/*
 * mesh_link.c — L2 framing + handshake (desktop path).
 *
 * Port target: Java MeshFrame + MeshLink (framing/handshake only; the core owns
 * no socket, heartbeat thread, or timers — those stay with the embedder, see
 * ../README.md). Normative rules: ../../WIRE_FORMAT.md "Framing" (:12-43) and
 * "L2 handshake" (:125-150).
 *
 * Crypto (nonce RNG, sign/verify) is OpenSSL via mesh_identity.c + RAND_bytes;
 * meshcore links OpenSSL::Crypto PRIVATE, so this TU may use it directly.
 */
#include "mesh_link.h"
#include "mesh_codec.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>

/* ===================================================================== */
/*  Frame codec — WIRE_FORMAT.md:12-43                                    */
/* ===================================================================== */

mesh_result_t mesh_frame_encode(mesh_bytes_t payload, mesh_buf_t *out) {
    if (!out) return MESH_ERR_INVALID_ARG;
    if (payload.len > 0 && !payload.data) return MESH_ERR_INVALID_ARG;

    /* Stricter than the Java sender: refuse to emit an oversized frame rather
     * than relying on the receiver to reject it (WIRE_FORMAT.md:40-43). The
     * lower bound (len >= 1) is implied — an empty payload would frame a length
     * of 0, which every receiver rejects, so we forbid it here too. */
    if (payload.len == 0) return MESH_ERR_INVALID_ARG;
    if (payload.len > (size_t)MESH_MAX_FRAME_BYTES) return MESH_ERR_TOO_LARGE;

    mesh_result_t rc = mesh_buf_reserve(out, MESH_FRAME_PREFIX_BYTES + payload.len);
    if (rc != MESH_OK) return rc;

    uint8_t *o = out->data + out->len;
    /* 4-byte big-endian signed length (== Java DataOutputStream.writeInt). The
     * value fits in a positive int32 because it is <= 262144. */
    uint32_t n = (uint32_t)payload.len;
    o[0] = (uint8_t)((n >> 24) & 0xFF);
    o[1] = (uint8_t)((n >> 16) & 0xFF);
    o[2] = (uint8_t)((n >> 8) & 0xFF);
    o[3] = (uint8_t)(n & 0xFF);
    memcpy(o + 4, payload.data, payload.len);
    out->len += MESH_FRAME_PREFIX_BYTES + payload.len;
    return MESH_OK;
}

mesh_result_t mesh_frame_decode(mesh_bytes_t in,
                                mesh_bytes_t *payload,
                                size_t       *consumed,
                                int          *need_more) {
    if (!payload || !consumed || !need_more) return MESH_ERR_INVALID_ARG;
    *need_more = 0;
    *consumed = 0;
    payload->data = NULL;
    payload->len = 0;

    if (in.len > 0 && !in.data) return MESH_ERR_INVALID_ARG;

    /* Not enough bytes for the length prefix yet. */
    if (in.len < MESH_FRAME_PREFIX_BYTES) {
        *need_more = 1;
        return MESH_OK;
    }

    /* Read the signed big-endian prefix. Assemble as int32_t so a negative
     * value (stream desync) is caught by the <= 0 check, exactly as the Java
     * receiver's signed readInt does (WIRE_FORMAT.md:34-38). */
    const uint8_t *d = in.data;
    int32_t len = (int32_t)(((uint32_t)d[0] << 24) |
                            ((uint32_t)d[1] << 16) |
                            ((uint32_t)d[2] << 8)  |
                            ((uint32_t)d[3]));

    if (len <= 0 || len > MESH_MAX_FRAME_BYTES) return MESH_ERR_MALFORMED;

    size_t frame_len = MESH_FRAME_PREFIX_BYTES + (size_t)len;
    if (in.len < frame_len) {
        /* Prefix is valid but the payload has not fully arrived. */
        *need_more = 1;
        return MESH_OK;
    }

    payload->data = d + MESH_FRAME_PREFIX_BYTES;
    payload->len  = (size_t)len;
    *consumed = frame_len;
    return MESH_OK;
}

/* ===================================================================== */
/*  Minimal JSON helpers (handshake frames only)                         */
/*                                                                       */
/*  We never need a general JSON parser: handshake frames are flat string */
/*  objects. We extract a named top-level string value, honouring JSON    */
/*  escapes, and emit flat objects with proper escaping. Order-           */
/*  independent parsing — a conforming peer may order fields any way.     */
/* ===================================================================== */

/* Append a JSON-escaped copy of the C string `s` (bytes, len) to `out`,
 * wrapped in double quotes. Escapes ", \\, and control chars < 0x20. */
static mesh_result_t json_append_quoted(mesh_buf_t *out, const char *s, size_t len) {
    /* Worst case every byte becomes \uXXXX (6 chars), plus the two quotes. */
    mesh_result_t rc = mesh_buf_reserve(out, len * 6 + 2);
    if (rc != MESH_OK) return rc;
    uint8_t *o = out->data + out->len;
    size_t w = 0;
    o[w++] = '"';
    static const char HEX[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
            case '"':  o[w++] = '\\'; o[w++] = '"';  break;
            case '\\': o[w++] = '\\'; o[w++] = '\\'; break;
            case '\b': o[w++] = '\\'; o[w++] = 'b';  break;
            case '\f': o[w++] = '\\'; o[w++] = 'f';  break;
            case '\n': o[w++] = '\\'; o[w++] = 'n';  break;
            case '\r': o[w++] = '\\'; o[w++] = 'r';  break;
            case '\t': o[w++] = '\\'; o[w++] = 't';  break;
            default:
                if (c < 0x20) {
                    o[w++] = '\\'; o[w++] = 'u'; o[w++] = '0'; o[w++] = '0';
                    o[w++] = HEX[(c >> 4) & 0xF];
                    o[w++] = HEX[c & 0xF];
                } else {
                    o[w++] = (char)c;
                }
                break;
        }
    }
    o[w++] = '"';
    out->len += w;
    return MESH_OK;
}

/* Append a raw literal (no escaping) — for keys and structural characters. */
static mesh_result_t json_append_raw(mesh_buf_t *out, const char *s) {
    size_t len = strlen(s);
    mesh_result_t rc = mesh_buf_reserve(out, len);
    if (rc != MESH_OK) return rc;
    memcpy(out->data + out->len, s, len);
    out->len += len;
    return MESH_OK;
}

/*
 * Extract the string value of top-level key `key` from a flat JSON object.
 * Writes an unescaped, NUL-terminated copy into `out` (a mesh_buf; the NUL is
 * written but NOT counted in out->len). Returns:
 *   MESH_OK           value found and copied
 *   MESH_ERR_MALFORMED key present but value is not a well-formed JSON string,
 *                      or the object is not parseable as we need
 *   MESH_ERR_INVALID_ARG on null args
 * A key that is simply absent yields MESH_ERR_MALFORMED with *found = 0, so the
 * caller can distinguish "absent" (e.g. optional appId) from "malformed".
 */
static mesh_result_t json_get_string(mesh_bytes_t json, const char *key,
                                     mesh_buf_t *out, int *found) {
    if (!json.data || !key || !out || !found) return MESH_ERR_INVALID_ARG;
    *found = 0;

    size_t keylen = strlen(key);
    const uint8_t *p = json.data;
    const uint8_t *end = json.data + json.len;

    /* Scan for  "key"  at a position where it is a key: preceded by '{' or ','
     * (skipping whitespace) and followed by optional whitespace then ':'. This
     * is deliberately simple but robust for the flat, string-only handshake
     * objects — it never treats a substring inside a value as a key because a
     * value string is consumed whole when we walk past it. */
    while (p < end) {
        if (*p != '"') { p++; continue; }
        /* p is at an opening quote of some string. Determine if it is a KEY:
         * find the previous non-space char. */
        const uint8_t *q = p;
        /* Match the key literal. */
        const uint8_t *k = p + 1;
        int is_key_match = ((size_t)(end - k) >= keylen) &&
                           memcmp(k, key, keylen) == 0 &&
                           (k + keylen < end) && k[keylen] == '"';
        /* Look back for the character that precedes this string token. */
        const uint8_t *b = p;
        while (b > json.data) {
            unsigned char pc = *(b - 1);
            if (pc == ' ' || pc == '\t' || pc == '\n' || pc == '\r') { b--; continue; }
            break;
        }
        int in_key_pos = (b == json.data) ? 0 : (*(b - 1) == '{' || *(b - 1) == ',');

        if (is_key_match && in_key_pos) {
            /* Advance past  "key"  then whitespace, expect ':'. */
            const uint8_t *r = k + keylen + 1; /* past closing quote of key */
            while (r < end && (*r == ' ' || *r == '\t' || *r == '\n' || *r == '\r')) r++;
            if (r >= end || *r != ':') return MESH_ERR_MALFORMED;
            r++;
            while (r < end && (*r == ' ' || *r == '\t' || *r == '\n' || *r == '\r')) r++;
            if (r >= end || *r != '"') return MESH_ERR_MALFORMED; /* not a string value */
            r++; /* first char of value */

            /* Decode the JSON string into out, handling escapes, until the
             * unescaped closing quote. */
            out->len = 0;
            while (r < end) {
                unsigned char c = *r;
                if (c == '"') {
                    /* End of value. NUL-terminate (uncounted). */
                    mesh_result_t rc = mesh_buf_reserve(out, 1);
                    if (rc != MESH_OK) return rc;
                    out->data[out->len] = '\0';
                    *found = 1;
                    return MESH_OK;
                }
                if (c == '\\') {
                    r++;
                    if (r >= end) return MESH_ERR_MALFORMED;
                    unsigned char e = *r;
                    uint8_t decoded;
                    switch (e) {
                        case '"':  decoded = '"';  break;
                        case '\\': decoded = '\\'; break;
                        case '/':  decoded = '/';  break;
                        case 'b':  decoded = '\b'; break;
                        case 'f':  decoded = '\f'; break;
                        case 'n':  decoded = '\n'; break;
                        case 'r':  decoded = '\r'; break;
                        case 't':  decoded = '\t'; break;
                        case 'u': {
                            /* \uXXXX — accept and emit only the BMP-ASCII range
                             * we could ever see in these fields; reject the rest
                             * rather than silently mangling (handshake fields are
                             * base64/hex/appId, all ASCII). */
                            if ((size_t)(end - r) < 5) return MESH_ERR_MALFORMED;
                            int hv = 0;
                            for (int i = 1; i <= 4; i++) {
                                unsigned char hc = r[i];
                                int v;
                                if (hc >= '0' && hc <= '9') v = hc - '0';
                                else if (hc >= 'a' && hc <= 'f') v = hc - 'a' + 10;
                                else if (hc >= 'A' && hc <= 'F') v = hc - 'A' + 10;
                                else return MESH_ERR_MALFORMED;
                                hv = (hv << 4) | v;
                            }
                            if (hv > 0x7F) return MESH_ERR_MALFORMED; /* non-ASCII unsupported */
                            decoded = (uint8_t)hv;
                            r += 4; /* consume the 4 hex digits (loop ++ eats 'u') */
                            break;
                        }
                        default: return MESH_ERR_MALFORMED;
                    }
                    mesh_result_t rc = mesh_buf_reserve(out, 1);
                    if (rc != MESH_OK) return rc;
                    out->data[out->len++] = decoded;
                    r++;
                } else if (c < 0x20) {
                    /* Raw control char inside a JSON string is illegal. */
                    return MESH_ERR_MALFORMED;
                } else {
                    mesh_result_t rc = mesh_buf_reserve(out, 1);
                    if (rc != MESH_OK) return rc;
                    out->data[out->len++] = c;
                    r++;
                }
            }
            return MESH_ERR_MALFORMED; /* unterminated string value */
        }

        /* Not our key at a key position: skip this whole string token (whether
         * it is some other key or a value) so its contents can't be re-scanned
         * as a key. Walk to its unescaped closing quote. */
        p = q + 1;
        while (p < end) {
            if (*p == '\\') { p += 2; continue; }
            if (*p == '"') { p++; break; }
            p++;
        }
    }

    /* Key not present. */
    return MESH_ERR_MALFORMED;
}

/* ===================================================================== */
/*  Handshake state machine — WIRE_FORMAT.md:125-150                     */
/* ===================================================================== */

struct mesh_handshake {
    const mesh_identity_t *id;   /* borrowed; not owned */
    mesh_hs_state_t state;

    char  *app_id;               /* owned copy or NULL (wildcard) */

    char  *our_nonce;            /* owned; base64 string we emitted */
    char  *peer_nonce;           /* owned; base64 string peer sent (signed as-is) */

    uint8_t *peer_der;           /* owned; claimed peer PeerId (raw DER) */
    size_t   peer_der_len;
};

mesh_result_t mesh_handshake_begin(const mesh_identity_t *id,
                                   const char *app_id_or_null,
                                   mesh_handshake_t **out) {
    if (!id || !out) return MESH_ERR_INVALID_ARG;
    *out = NULL;

    struct mesh_handshake *hs = (struct mesh_handshake *)calloc(1, sizeof(*hs));
    if (!hs) return MESH_ERR_NOBUF;

    hs->id = id;
    hs->state = MESH_HS_INIT;

    if (app_id_or_null) {
        size_t n = strlen(app_id_or_null);
        hs->app_id = (char *)malloc(n + 1);
        if (!hs->app_id) { free(hs); return MESH_ERR_NOBUF; }
        memcpy(hs->app_id, app_id_or_null, n + 1);
    }

    *out = hs;
    return MESH_OK;
}

void mesh_handshake_free(mesh_handshake_t *hs) {
    if (!hs) return;
    free(hs->app_id);
    free(hs->our_nonce);
    free(hs->peer_nonce);
    free(hs->peer_der);
    free(hs);
}

/* Copy a mesh_buf's bytes into a fresh NUL-terminated C string. */
static char *dup_cstr(const uint8_t *data, size_t len) {
    char *s = (char *)malloc(len + 1);
    if (!s) return NULL;
    if (len) memcpy(s, data, len);
    s[len] = '\0';
    return s;
}

mesh_result_t mesh_handshake_write_hello(mesh_handshake_t *hs, mesh_buf_t *out) {
    if (!hs || !out) return MESH_ERR_INVALID_ARG;
    if (hs->state != MESH_HS_INIT) return MESH_ERR_INVALID_ARG;

    /* 16 random bytes -> canonical base64 nonce. */
    uint8_t nonce[MESH_NONCE_BYTES];
    if (RAND_bytes(nonce, (int)sizeof(nonce)) != 1) { hs->state = MESH_HS_FAILED; return MESH_ERR_CRYPTO; }

    mesh_buf_t nb;
    mesh_buf_init(&nb);
    mesh_bytes_t nbytes = { nonce, sizeof(nonce) };
    mesh_result_t rc = mesh_base64_encode(nbytes, &nb);
    if (rc != MESH_OK) { mesh_buf_free(&nb); hs->state = MESH_HS_FAILED; return rc; }
    hs->our_nonce = dup_cstr(nb.data, nb.len);
    mesh_buf_free(&nb);
    if (!hs->our_nonce) { hs->state = MESH_HS_FAILED; return MESH_ERR_NOBUF; }

    /* peerId hex from our identity's cached DER. */
    mesh_buf_t der;
    mesh_buf_init(&der);
    rc = mesh_identity_peer_id(hs->id, &der);
    if (rc != MESH_OK) { mesh_buf_free(&der); hs->state = MESH_HS_FAILED; return rc; }
    mesh_buf_t hex;
    mesh_buf_init(&hex);
    mesh_bytes_t derb = { der.data, der.len };
    rc = mesh_hex_encode(derb, &hex);
    mesh_buf_free(&der);
    if (rc != MESH_OK) { mesh_buf_free(&hex); hs->state = MESH_HS_FAILED; return rc; }

    /* Emit  {"type":"hello","peerId":"<hex>","nonce":"<b64>"[,"appId":"<...>"]} */
    #define TRY(expr) do { rc = (expr); if (rc != MESH_OK) { mesh_buf_free(&hex); hs->state = MESH_HS_FAILED; return rc; } } while (0)
    TRY(json_append_raw(out, "{\"type\":\"hello\",\"peerId\":"));
    TRY(json_append_quoted(out, (const char *)hex.data, hex.len));
    TRY(json_append_raw(out, ",\"nonce\":"));
    TRY(json_append_quoted(out, hs->our_nonce, strlen(hs->our_nonce)));
    if (hs->app_id) {
        TRY(json_append_raw(out, ",\"appId\":"));
        TRY(json_append_quoted(out, hs->app_id, strlen(hs->app_id)));
    }
    TRY(json_append_raw(out, "}"));
    #undef TRY
    mesh_buf_free(&hex);

    hs->state = MESH_HS_HELLO_SENT;
    return MESH_OK;
}

mesh_result_t mesh_handshake_read_hello(mesh_handshake_t *hs, mesh_bytes_t hello_json) {
    if (!hs) return MESH_ERR_INVALID_ARG;
    if (hs->state == MESH_HS_FAILED) return MESH_ERR_INVALID_ARG;

    mesh_result_t rc;
    int found;
    mesh_buf_t field;
    mesh_buf_init(&field);

    /* type must be "hello". */
    rc = json_get_string(hello_json, "type", &field, &found);
    if (rc != MESH_OK || !found || strcmp((const char *)field.data, "hello") != 0) {
        mesh_buf_free(&field); hs->state = MESH_HS_FAILED; return MESH_ERR_MALFORMED;
    }

    /* appId filter: reject only if BOTH sides declare one and they differ. A
     * missing appId on either side is a wildcard (WIRE_FORMAT.md:143-145). */
    rc = json_get_string(hello_json, "appId", &field, &found);
    if (rc != MESH_OK && found) { mesh_buf_free(&field); hs->state = MESH_HS_FAILED; return MESH_ERR_MALFORMED; }
    if (found && hs->app_id && field.len > 0 && strlen(hs->app_id) > 0) {
        if (strcmp((const char *)field.data, hs->app_id) != 0) {
            mesh_buf_free(&field); hs->state = MESH_HS_FAILED; return MESH_ERR_MALFORMED;
        }
    }

    /* peerId — hex of the claimed X.509 DER. Strict decode binds identity to
     * key material (WIRE_FORMAT.md:146-147); a malformed hex fails the link. */
    rc = json_get_string(hello_json, "peerId", &field, &found);
    if (rc != MESH_OK || !found) { mesh_buf_free(&field); hs->state = MESH_HS_FAILED; return MESH_ERR_MALFORMED; }
    {
        mesh_buf_t der;
        mesh_buf_init(&der);
        rc = mesh_hex_decode((const char *)field.data, &der);
        if (rc != MESH_OK) { mesh_buf_free(&der); mesh_buf_free(&field); hs->state = MESH_HS_FAILED; return MESH_ERR_MALFORMED; }
        free(hs->peer_der);
        hs->peer_der = (uint8_t *)malloc(der.len ? der.len : 1);
        if (!hs->peer_der) { mesh_buf_free(&der); mesh_buf_free(&field); hs->state = MESH_HS_FAILED; return MESH_ERR_NOBUF; }
        memcpy(hs->peer_der, der.data, der.len);
        hs->peer_der_len = der.len;
        mesh_buf_free(&der);
    }

    /* nonce — kept as the raw base64 STRING; it is signed as-is, never decoded
     * (WIRE_FORMAT.md:139-142). We still sanity-decode nothing here on purpose:
     * the receiver does not validate nonce encoding (WIRE_FORMAT.md:81-84). */
    rc = json_get_string(hello_json, "nonce", &field, &found);
    if (rc != MESH_OK || !found) { mesh_buf_free(&field); hs->state = MESH_HS_FAILED; return MESH_ERR_MALFORMED; }
    free(hs->peer_nonce);
    hs->peer_nonce = dup_cstr(field.data, field.len);
    mesh_buf_free(&field);
    if (!hs->peer_nonce) { hs->state = MESH_HS_FAILED; return MESH_ERR_NOBUF; }

    return MESH_OK;
}

mesh_result_t mesh_handshake_write_proof(mesh_handshake_t *hs, mesh_buf_t *out) {
    if (!hs || !out) return MESH_ERR_INVALID_ARG;
    /* Must have both sent our hello and received the peer's (we need their
     * nonce to sign). */
    if (hs->state != MESH_HS_HELLO_SENT || !hs->peer_nonce) return MESH_ERR_INVALID_ARG;

    /* Sign the peer's nonce STRING bytes exactly as received. */
    mesh_bytes_t to_sign = { (const uint8_t *)hs->peer_nonce, strlen(hs->peer_nonce) };
    mesh_buf_t sig;
    mesh_buf_init(&sig);
    mesh_result_t rc = mesh_identity_sign(hs->id, to_sign, &sig);
    if (rc != MESH_OK) { mesh_buf_free(&sig); hs->state = MESH_HS_FAILED; return rc; }

    mesh_buf_t b64;
    mesh_buf_init(&b64);
    mesh_bytes_t sigb = { sig.data, sig.len };
    rc = mesh_base64_encode(sigb, &b64);
    mesh_buf_free(&sig);
    if (rc != MESH_OK) { mesh_buf_free(&b64); hs->state = MESH_HS_FAILED; return rc; }

    #define TRY(expr) do { rc = (expr); if (rc != MESH_OK) { mesh_buf_free(&b64); hs->state = MESH_HS_FAILED; return rc; } } while (0)
    TRY(json_append_raw(out, "{\"type\":\"proof\",\"signature\":"));
    TRY(json_append_quoted(out, (const char *)b64.data, b64.len));
    TRY(json_append_raw(out, "}"));
    #undef TRY
    mesh_buf_free(&b64);

    hs->state = MESH_HS_PROOF_SENT;
    return MESH_OK;
}

mesh_result_t mesh_handshake_read_proof(mesh_handshake_t *hs, mesh_bytes_t proof_json) {
    if (!hs) return MESH_ERR_INVALID_ARG;
    /* We must have already produced our proof (so our_nonce exists and the peer
     * signed it) and have the claimed peer DER from read_hello. */
    if (hs->state != MESH_HS_PROOF_SENT || !hs->our_nonce || !hs->peer_der) {
        if (hs) hs->state = MESH_HS_FAILED;
        return MESH_ERR_INVALID_ARG;
    }

    mesh_result_t rc;
    int found;
    mesh_buf_t field;
    mesh_buf_init(&field);

    rc = json_get_string(proof_json, "type", &field, &found);
    if (rc != MESH_OK || !found || strcmp((const char *)field.data, "proof") != 0) {
        mesh_buf_free(&field); hs->state = MESH_HS_FAILED; return MESH_ERR_MALFORMED;
    }

    rc = json_get_string(proof_json, "signature", &field, &found);
    if (rc != MESH_OK || !found) { mesh_buf_free(&field); hs->state = MESH_HS_FAILED; return MESH_ERR_MALFORMED; }

    /* signature is base64 of the DER ECDSA signature — strictly decoded. */
    mesh_buf_t sig;
    mesh_buf_init(&sig);
    rc = mesh_base64_decode((const char *)field.data, &sig);
    mesh_buf_free(&field);
    if (rc != MESH_OK) { mesh_buf_free(&sig); hs->state = MESH_HS_FAILED; return MESH_ERR_MALFORMED; }

    /* Verify: peer's signature must cover OUR nonce string, under the pubkey
     * recovered from their CLAIMED peerId DER. */
    mesh_bytes_t peer_der = { hs->peer_der, hs->peer_der_len };
    mesh_bytes_t our_nonce_bytes = { (const uint8_t *)hs->our_nonce, strlen(hs->our_nonce) };
    mesh_bytes_t sig_bytes = { sig.data, sig.len };
    rc = mesh_identity_verify(peer_der, our_nonce_bytes, sig_bytes);
    mesh_buf_free(&sig);
    if (rc != MESH_OK) { hs->state = MESH_HS_FAILED; return MESH_ERR_CRYPTO; }

    hs->state = MESH_HS_DONE;
    return MESH_OK;
}

mesh_hs_state_t mesh_handshake_state(const mesh_handshake_t *hs) {
    return hs ? hs->state : MESH_HS_FAILED;
}

mesh_result_t mesh_handshake_remote_peer_id(const mesh_handshake_t *hs, mesh_buf_t *out) {
    if (!hs || !out) return MESH_ERR_INVALID_ARG;
    if (hs->state != MESH_HS_DONE || !hs->peer_der) return MESH_ERR_INVALID_ARG;

    mesh_result_t rc = mesh_buf_reserve(out, hs->peer_der_len);
    if (rc != MESH_OK) return rc;
    memcpy(out->data + out->len, hs->peer_der, hs->peer_der_len);
    out->len += hs->peer_der_len;
    return MESH_OK;
}
