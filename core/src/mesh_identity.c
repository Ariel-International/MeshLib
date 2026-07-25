/*
 * mesh_identity.c — L0 identity: P-256 keypair, PeerId, sign/verify.
 *
 * C port of the Java PeerIdentity + PeerId classes. Desktop path only: the
 * crypto backend is OpenSSL (>= 3.0) via the EVP high-level API. The ESP-IDF
 * (mbedTLS) path is intentionally NOT implemented here — see ../README.md and
 * the ESP-IDF note in ../CMakeLists.txt.
 *
 * Interop contract (WIRE_FORMAT.md, repo root):
 *   - Key: P-256 / secp256r1 (prime256v1) EC keypair.
 *   - PeerId: the X.509 SubjectPublicKeyInfo DER of the public key
 *     (i2d_PUBKEY). On the wire this is hex-encoded.
 *   - Signatures: SHA256withECDSA, DER-encoded (the ASN.1 SEQUENCE of r,s that
 *     java.security.Signature "SHA256withECDSA" produces/consumes).
 *
 * The opaque struct is defined here so OpenSSL types stay out of the public
 * header. It caches the DER PeerId so mesh_identity_peer_id is a pure copy.
 */
#include "mesh_identity.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/x509.h>   /* i2d_PUBKEY / d2i_PUBKEY */
#include <openssl/err.h>

struct mesh_identity {
    EVP_PKEY *pkey;      /* owned; holds the private (and public) key material */
    uint8_t  *peer_id;   /* owned; cached X.509 DER SubjectPublicKeyInfo */
    size_t    peer_id_len;
};

/* ---- internal helpers --------------------------------------------------- */

/* Cache i2d_PUBKEY(pkey) into id->peer_id / id->peer_id_len. */
static mesh_result_t cache_peer_id(struct mesh_identity *id) {
    unsigned char *der = NULL;
    int n = i2d_PUBKEY(id->pkey, &der);
    if (n <= 0 || der == NULL) {
        if (der) OPENSSL_free(der);
        return MESH_ERR_CRYPTO;
    }
    /* Copy out of OpenSSL's allocation into a plain malloc block so the caller
     * side (mesh_buf/free) never has to know about OPENSSL_free. */
    uint8_t *copy = (uint8_t *)malloc((size_t)n);
    if (!copy) {
        OPENSSL_free(der);
        return MESH_ERR_NOBUF;
    }
    memcpy(copy, der, (size_t)n);
    OPENSSL_free(der);
    id->peer_id = copy;
    id->peer_id_len = (size_t)n;
    return MESH_OK;
}

/* ---- public API --------------------------------------------------------- */

mesh_result_t mesh_identity_create(mesh_bytes_t seed_or_null, mesh_identity_t **out) {
    if (!out) return MESH_ERR_INVALID_ARG;
    *out = NULL;

    struct mesh_identity *id = (struct mesh_identity *)calloc(1, sizeof(*id));
    if (!id) return MESH_ERR_NOBUF;

    if (seed_or_null.data == NULL) {
        /* Fresh keypair from the platform RNG. EVP_PKEY_Q_keygen seeds from
         * OpenSSL's DRBG, which is backed by the OS CSPRNG. */
        id->pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
        if (!id->pkey) {
            free(id);
            return MESH_ERR_CRYPTO;
        }
    } else {
        /* Load an existing private keypair from DER. d2i_AutoPrivateKey accepts
         * both PKCS8 (SubjectPublicKeyInfo-style wrapping) and the traditional
         * SEC1 EC private-key encodings, so the embedder is not pinned to one. */
        if (seed_or_null.len == 0) {
            free(id);
            return MESH_ERR_INVALID_ARG;
        }
        const unsigned char *p = seed_or_null.data;
        id->pkey = d2i_AutoPrivateKey(NULL, &p, (long)seed_or_null.len);
        if (!id->pkey) {
            free(id);
            return MESH_ERR_MALFORMED;
        }
    }

    mesh_result_t rc = cache_peer_id(id);
    if (rc != MESH_OK) {
        EVP_PKEY_free(id->pkey);
        free(id);
        return rc;
    }

    *out = id;
    return MESH_OK;
}

void mesh_identity_free(mesh_identity_t *id) {
    if (!id) return;
    if (id->pkey) EVP_PKEY_free(id->pkey);
    if (id->peer_id) free(id->peer_id);
    free(id);
}

mesh_result_t mesh_identity_peer_id(const mesh_identity_t *id, mesh_buf_t *out) {
    if (!id || !out) return MESH_ERR_INVALID_ARG;
    if (!id->peer_id || id->peer_id_len == 0) return MESH_ERR_CRYPTO;

    mesh_result_t rc = mesh_buf_reserve(out, id->peer_id_len);
    if (rc != MESH_OK) return rc;

    memcpy(out->data + out->len, id->peer_id, id->peer_id_len);
    out->len += id->peer_id_len;
    return MESH_OK;
}

mesh_result_t mesh_identity_sign(const mesh_identity_t *id,
                                 mesh_bytes_t payload, mesh_buf_t *out) {
    if (!id || !out) return MESH_ERR_INVALID_ARG;
    if (payload.len > 0 && !payload.data) return MESH_ERR_INVALID_ARG;
    if (!id->pkey) return MESH_ERR_CRYPTO;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return MESH_ERR_NOBUF;

    mesh_result_t rc = MESH_ERR_CRYPTO;
    size_t siglen = 0;

    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, id->pkey) != 1)
        goto done;

    /* Two-pass: first NULL sig buffer to learn the max DER length, then sign. */
    if (EVP_DigestSign(ctx, NULL, &siglen, payload.data, payload.len) != 1)
        goto done;
    if (siglen == 0) goto done;

    rc = mesh_buf_reserve(out, siglen);
    if (rc != MESH_OK) goto done;

    /* siglen is updated to the actual DER length (<= the reserved bound). */
    if (EVP_DigestSign(ctx, out->data + out->len, &siglen,
                       payload.data, payload.len) != 1) {
        rc = MESH_ERR_CRYPTO;
        goto done;
    }
    out->len += siglen;
    rc = MESH_OK;

done:
    EVP_MD_CTX_free(ctx);
    return rc;
}

mesh_result_t mesh_identity_verify(mesh_bytes_t peer_id_der,
                                   mesh_bytes_t payload,
                                   mesh_bytes_t signature) {
    if (!peer_id_der.data || peer_id_der.len == 0) return MESH_ERR_INVALID_ARG;
    if (!signature.data || signature.len == 0) return MESH_ERR_INVALID_ARG;
    if (payload.len > 0 && !payload.data) return MESH_ERR_INVALID_ARG;

    /* Recover the public key from the claimed PeerId's X.509 DER. */
    const unsigned char *p = peer_id_der.data;
    EVP_PKEY *pub = d2i_PUBKEY(NULL, &p, (long)peer_id_der.len);
    if (!pub) return MESH_ERR_MALFORMED;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pub);
        return MESH_ERR_NOBUF;
    }

    mesh_result_t rc = MESH_ERR_CRYPTO;
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pub) == 1) {
        int v = EVP_DigestVerify(ctx, signature.data, signature.len,
                                 payload.data, payload.len);
        /* 1 = good, 0 = bad signature, <0 = error. Only 1 is MESH_OK; every
         * other case is a verification failure (MESH_ERR_CRYPTO). */
        if (v == 1) rc = MESH_OK;
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pub);
    return rc;
}
