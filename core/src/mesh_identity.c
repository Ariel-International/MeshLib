/*
 * mesh_identity.c — L0 identity. SKELETON: no real logic yet.
 *
 * Port target: Java PeerIdentity + PeerId. Crypto backend is intentionally not
 * chosen here (OpenSSL on desktop JNI, mbedTLS on ESP-IDF — see ../README.md).
 * The opaque struct is defined here so the backend stays out of the header.
 */
#include "mesh_identity.h"

struct mesh_identity {
    /* TODO: backend keypair handle (e.g. EVP_PKEY* / mbedtls_pk_context) plus
     * cached DER PeerId bytes. Empty for now so the type is complete. */
    int placeholder;
};

mesh_result_t mesh_identity_create(mesh_bytes_t seed_or_null, mesh_identity_t **out) {
    (void)seed_or_null;
    (void)out;
    /* TODO: NULL seed => generate P-256; else load X.509/PKCS8 DER. */
    return MESH_ERR_UNIMPLEMENTED;
}

void mesh_identity_free(mesh_identity_t *id) {
    (void)id;
    /* TODO: free backend key + cached DER, then free(id). */
}

mesh_result_t mesh_identity_peer_id(const mesh_identity_t *id, mesh_buf_t *out) {
    (void)id;
    (void)out;
    /* TODO: copy X.509 DER public key bytes. */
    return MESH_ERR_UNIMPLEMENTED;
}

mesh_result_t mesh_identity_sign(const mesh_identity_t *id,
                                 mesh_bytes_t payload, mesh_buf_t *out) {
    (void)id;
    (void)payload;
    (void)out;
    /* TODO: SHA256withECDSA over payload as-given (caller supplies nonce STRING
     * bytes for the handshake — WIRE_FORMAT.md:139-142). */
    return MESH_ERR_UNIMPLEMENTED;
}

mesh_result_t mesh_identity_verify(mesh_bytes_t peer_id_der,
                                   mesh_bytes_t payload,
                                   mesh_bytes_t signature) {
    (void)peer_id_der;
    (void)payload;
    (void)signature;
    /* TODO: recover pubkey from DER, verify ECDSA signature. */
    return MESH_ERR_UNIMPLEMENTED;
}
