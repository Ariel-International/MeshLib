/*
 * mesh_link.h — L2 framing and handshake.
 *
 * C counterpart of the Java MeshFrame + MeshLink. Framing rules are in
 * WIRE_FORMAT.md "Framing" (../../WIRE_FORMAT.md:12-43); the handshake and
 * heartbeat in "L2 handshake"/"Heartbeat" (:125-162).
 *
 * The core is transport-agnostic: it never owns a socket. The embedder reads
 * and writes bytes; these functions only encode/decode/validate frames. (The
 * Java MeshLink additionally owns the socket, heartbeat thread, and timers —
 * intentionally NOT modelled here; see report/ambiguity notes.)
 */
#ifndef MESH_LINK_H
#define MESH_LINK_H

#include "mesh_common.h"
#include "mesh_identity.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Frame codec (WIRE_FORMAT.md:12-43) -------------------------------- */

/*
 * Prepend the 4-byte big-endian length prefix to `payload` and append the
 * result to `out`. Returns MESH_ERR_TOO_LARGE if payload.len > MESH_MAX_FRAME_
 * BYTES.
 *
 * NOTE (ambiguity, see report): the Java sender does NOT enforce the 256 KiB
 * cap on write (WIRE_FORMAT.md:40-43) — it relies on the receiver rejecting
 * oversized frames. This C signature enforces it on write instead, which is
 * stricter than the reference. Flagged as a deliberate, documented divergence
 * to resolve before wire-compat fixtures are frozen.
 */
mesh_result_t mesh_frame_encode(mesh_bytes_t payload, mesh_buf_t *out);

/*
 * Given a buffer that may hold one or more frames, validate the leading length
 * prefix and report the framed payload.
 *   - If fewer than 4 bytes are available, sets *need_more = 1, returns MESH_OK.
 *   - If the prefix is <= 0 or > MESH_MAX_FRAME_BYTES, returns MESH_ERR_MALFORMED
 *     (link must be torn down — WIRE_FORMAT.md:34-38).
 *   - If the full payload has not yet arrived, sets *need_more = 1, returns MESH_OK.
 *   - On a complete frame, points *payload at the JSON bytes (a view INTO `in`,
 *     not a copy), sets *consumed to prefix+payload length, *need_more = 0.
 */
mesh_result_t mesh_frame_decode(mesh_bytes_t in,
                                mesh_bytes_t *payload,
                                size_t       *consumed,
                                int          *need_more);

/* ---- Handshake (WIRE_FORMAT.md:125-150) -------------------------------- */

/*
 * Handshake is a small state machine driven by the embedder, since the core
 * does no I/O. Typical flow: build our hello -> feed peer hello -> build our
 * proof -> feed peer proof -> query result.
 */
typedef enum mesh_hs_state {
    MESH_HS_INIT = 0,
    MESH_HS_HELLO_SENT,
    MESH_HS_PROOF_SENT,
    MESH_HS_DONE,        /* peer signature verified — link usable */
    MESH_HS_FAILED       /* appId mismatch, bad signature, or malformed frame */
} mesh_hs_state_t;

typedef struct mesh_handshake mesh_handshake_t;

/*
 * Begin a handshake for `id`. `app_id_or_null` is the optional appId filter
 * (WIRE_FORMAT.md:143-145); NULL means wildcard. Frees with mesh_handshake_free().
 */
mesh_result_t mesh_handshake_begin(const mesh_identity_t *id,
                                   const char *app_id_or_null,
                                   mesh_handshake_t **out);

void mesh_handshake_free(mesh_handshake_t *hs);

/* Produce the JSON payload for our outgoing "hello" (16-byte random nonce). */
mesh_result_t mesh_handshake_write_hello(mesh_handshake_t *hs, mesh_buf_t *out);

/* Feed the peer's decoded "hello" JSON payload. May transition to FAILED on
 * appId mismatch or malformed peerId/nonce. */
mesh_result_t mesh_handshake_read_hello(mesh_handshake_t *hs, mesh_bytes_t hello_json);

/* Produce our "proof" — signs the peer's nonce STRING bytes (the quirk in
 * WIRE_FORMAT.md:139-142). Requires read_hello to have succeeded first. */
mesh_result_t mesh_handshake_write_proof(mesh_handshake_t *hs, mesh_buf_t *out);

/* Feed the peer's "proof"; verifies their signature over OUR nonce string. */
mesh_result_t mesh_handshake_read_proof(mesh_handshake_t *hs, mesh_bytes_t proof_json);

mesh_hs_state_t mesh_handshake_state(const mesh_handshake_t *hs);

/* After MESH_HS_DONE, copy the verified remote PeerId (raw DER) into `out`. */
mesh_result_t mesh_handshake_remote_peer_id(const mesh_handshake_t *hs, mesh_buf_t *out);

#ifdef __cplusplus
}
#endif

#endif /* MESH_LINK_H */
