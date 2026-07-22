/*
 * mesh_common.h — shared types and result codes for the MeshLib C core.
 *
 * This is the portable L0–L3 core extracted from the reference Java
 * implementation (see ../../ARCHITECTURE.md, "Portable core"). The wire format
 * these declarations must produce and accept is specified normatively in
 * ../../WIRE_FORMAT.md — that document, not this header, is the interop
 * contract. Every struct layout and function signature here exists to serve a
 * rule stated there.
 *
 * SKELETON: declarations only. No function in this core is implemented yet.
 */
#ifndef MESH_COMMON_H
#define MESH_COMMON_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Uniform result code. Functions that can fail return mesh_result_t; output
 * values are returned through pointer parameters. MESH_OK is zero so callers
 * may branch on `if (rc)`.
 */
typedef enum mesh_result {
    MESH_OK = 0,
    MESH_ERR_INVALID_ARG,   /* null pointer or out-of-range scalar */
    MESH_ERR_MALFORMED,     /* input violated a WIRE_FORMAT.md rule  */
    MESH_ERR_TOO_LARGE,     /* frame/field exceeded a hard cap       */
    MESH_ERR_NOBUF,         /* caller-provided buffer too small      */
    MESH_ERR_CRYPTO,        /* sign/verify/keygen failure            */
    MESH_ERR_IO,            /* transport read/write failure          */
    MESH_ERR_UNIMPLEMENTED  /* stub — every function returns this today */
} mesh_result_t;

/*
 * Framing limits — WIRE_FORMAT.md "Length constraints".
 *
 * The length prefix is a big-endian SIGNED 32-bit integer. A conforming
 * receiver rejects len <= 0 or len > MESH_MAX_FRAME_BYTES. Because the Java
 * reference reads it signed, a desync producing a negative int is rejected
 * naturally; a C implementation reading it unsigned MUST add the explicit
 * upper-bound check to match (WIRE_FORMAT.md:34-38).
 */
#define MESH_FRAME_PREFIX_BYTES 4
#define MESH_MAX_FRAME_BYTES    (256 * 1024)   /* 262144 */

/*
 * L0 identity is a P-256 (secp256r1) EC keypair. The PeerId is the X.509
 * DER-encoded public key — variable length, so it is NOT a fixed array here.
 * WIRE_FORMAT.md:94-110.
 */
#define MESH_NONCE_BYTES 16   /* WIRE_FORMAT.md:138 — hello nonce is 16 bytes */

/*
 * Borrowed (non-owning) view of a byte range. Neither creating nor destroying
 * a mesh_bytes_t frees anything; ownership stays with whoever allocated `data`.
 * Used for wire buffers the caller supplies.
 */
typedef struct mesh_bytes {
    const uint8_t *data;
    size_t         len;
} mesh_bytes_t;

/*
 * Owned, growable output buffer the core writes into. Caller initialises with
 * mesh_buf_init(), passes it to producing functions, and releases with
 * mesh_buf_free(). SKELETON: these two helpers are the only "utility" surface;
 * their bodies are still TODO.
 */
typedef struct mesh_buf {
    uint8_t *data;
    size_t   len;       /* bytes currently used   */
    size_t   cap;       /* bytes allocated        */
} mesh_buf_t;

void          mesh_buf_init(mesh_buf_t *buf);
mesh_result_t mesh_buf_reserve(mesh_buf_t *buf, size_t additional);
void          mesh_buf_free(mesh_buf_t *buf);

/*
 * Human-readable name for a result code, for logging. Never NULL.
 */
const char *mesh_result_str(mesh_result_t rc);

#ifdef __cplusplus
}
#endif

#endif /* MESH_COMMON_H */
