/*
 * mesh_codec.h — strict Base64 and hex codecs.
 *
 * Direct C counterpart of the Java MeshBase64 and PeerId.fromHex hardening
 * (repo commit 4cc1e64). The strict-reject rules these functions MUST enforce
 * are enumerated in WIRE_FORMAT.md "Encoding of binary fields"
 * (../../WIRE_FORMAT.md:47-121). Decoders reject malformed input with
 * MESH_ERR_MALFORMED — they never repair, skip, or truncate.
 *
 * SKELETON: signatures only; every function returns MESH_ERR_UNIMPLEMENTED.
 */
#ifndef MESH_CODEC_H
#define MESH_CODEC_H

#include "mesh_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Base64 (WIRE_FORMAT.md:60-92) ------------------------------------- */

/*
 * Exact encoded length for `n` input bytes, EXCLUDING a NUL terminator:
 * ((n + 2) / 3) * 4, or 0 when n == 0. Provided so callers can size buffers
 * without a trial encode.
 */
size_t mesh_base64_encoded_len(size_t n);

/*
 * Encode `in` as canonical RFC 4648 Base64 (alphabet A-Za-z0-9+/, '=' pad).
 * Output MUST be byte-identical to java.util.Base64.getEncoder()
 * (WIRE_FORMAT.md:63-64). Writes into `out` (an owned mesh_buf_t); does not
 * NUL-terminate.
 */
mesh_result_t mesh_base64_encode(mesh_bytes_t in, mesh_buf_t *out);

/*
 * Decode canonical Base64. STRICT — returns MESH_ERR_MALFORMED for any input
 * rejected by WIRE_FORMAT.md:66-92: length not a multiple of 4, non-alphabet
 * character (including whitespace and URL-safe -/_), '=' outside the final
 * quantum, >2 padding chars, or non-zero discarded bits in the final quantum
 * (e.g. "AB==" is rejected). Empty input decodes to zero bytes and returns
 * MESH_OK. `s` is a NUL-terminated C string.
 */
mesh_result_t mesh_base64_decode(const char *s, mesh_buf_t *out);

/* ---- Hex (WIRE_FORMAT.md:94-110) --------------------------------------- */

/*
 * Encode `in` as LOWERCASE hex (WIRE_FORMAT.md:96-98). No separators, no
 * prefix. Writes 2*in.len bytes into `out`; does not NUL-terminate.
 */
mesh_result_t mesh_hex_encode(mesh_bytes_t in, mesh_buf_t *out);

/*
 * Decode hex. STRICT — returns MESH_ERR_MALFORMED for null/empty, odd length,
 * or any character outside [0-9a-fA-F] including embedded whitespace or
 * separators (WIRE_FORMAT.md:100-110). Accepts both upper and lower case.
 * `s` is a NUL-terminated C string.
 */
mesh_result_t mesh_hex_decode(const char *s, mesh_buf_t *out);

#ifdef __cplusplus
}
#endif

#endif /* MESH_CODEC_H */
