/*
 * mesh_link.c — L2 framing + handshake. SKELETON: no real logic yet.
 *
 * Port target: Java MeshFrame + MeshLink (framing/handshake only; the core
 * owns no socket, heartbeat thread, or timers — see ../README.md ambiguities).
 * Rules: ../../WIRE_FORMAT.md:12-43 (framing), :125-162 (handshake/heartbeat).
 */
#include "mesh_link.h"

struct mesh_handshake {
    /* TODO: our nonce string, peer nonce string, peer peerId (DER), appId,
     * identity ptr, current state. Placeholder keeps the type complete. */
    mesh_hs_state_t state;
};

mesh_result_t mesh_frame_encode(mesh_bytes_t payload, mesh_buf_t *out) {
    (void)payload;
    (void)out;
    /* TODO: 4-byte big-endian length prefix + payload. Enforce 256 KiB cap on
     * write (stricter than Java reference — WIRE_FORMAT.md:40-43). */
    return MESH_ERR_UNIMPLEMENTED;
}

mesh_result_t mesh_frame_decode(mesh_bytes_t in,
                                mesh_bytes_t *payload,
                                size_t       *consumed,
                                int          *need_more) {
    (void)in;
    (void)payload;
    (void)consumed;
    (void)need_more;
    /* TODO: read signed BE prefix; reject <=0 or >256 KiB (MESH_ERR_MALFORMED);
     * set need_more when short; else return payload view + consumed. */
    return MESH_ERR_UNIMPLEMENTED;
}

mesh_result_t mesh_handshake_begin(const mesh_identity_t *id,
                                   const char *app_id_or_null,
                                   mesh_handshake_t **out) {
    (void)id;
    (void)app_id_or_null;
    (void)out;
    /* TODO: alloc, state = MESH_HS_INIT. */
    return MESH_ERR_UNIMPLEMENTED;
}

void mesh_handshake_free(mesh_handshake_t *hs) {
    (void)hs;
    /* TODO: free nonces/peerId/appId then free(hs). */
}

mesh_result_t mesh_handshake_write_hello(mesh_handshake_t *hs, mesh_buf_t *out) {
    (void)hs;
    (void)out;
    /* TODO: 16 random bytes -> base64 nonce; emit hello JSON. */
    return MESH_ERR_UNIMPLEMENTED;
}

mesh_result_t mesh_handshake_read_hello(mesh_handshake_t *hs, mesh_bytes_t hello_json) {
    (void)hs;
    (void)hello_json;
    /* TODO: parse peerId/nonce/appId; appId-mismatch => MESH_HS_FAILED. */
    return MESH_ERR_UNIMPLEMENTED;
}

mesh_result_t mesh_handshake_write_proof(mesh_handshake_t *hs, mesh_buf_t *out) {
    (void)hs;
    (void)out;
    /* TODO: sign peer nonce STRING bytes; emit proof JSON. */
    return MESH_ERR_UNIMPLEMENTED;
}

mesh_result_t mesh_handshake_read_proof(mesh_handshake_t *hs, mesh_bytes_t proof_json) {
    (void)hs;
    (void)proof_json;
    /* TODO: verify peer signature over OUR nonce string; set DONE/FAILED. */
    return MESH_ERR_UNIMPLEMENTED;
}

mesh_hs_state_t mesh_handshake_state(const mesh_handshake_t *hs) {
    /* TODO: return hs->state once begin() allocates. */
    return hs ? hs->state : MESH_HS_FAILED;
}

mesh_result_t mesh_handshake_remote_peer_id(const mesh_handshake_t *hs, mesh_buf_t *out) {
    (void)hs;
    (void)out;
    /* TODO: copy verified remote DER after MESH_HS_DONE. */
    return MESH_ERR_UNIMPLEMENTED;
}
