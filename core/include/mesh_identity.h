/*
 * mesh_identity.h — L0 identity: P-256 keypair, PeerId, sign/verify.
 *
 * C counterpart of the Java PeerIdentity + PeerId classes. WIRE_FORMAT.md
 * "L2 handshake" (../../WIRE_FORMAT.md:125-150) defines how these values cross
 * the wire; ARCHITECTURE.md line 11 defines the layer.
 */
#ifndef MESH_IDENTITY_H
#define MESH_IDENTITY_H

#include "mesh_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Opaque handle to a node's keypair. The public half is the PeerId (X.509 DER
 * of the P-256 public key). Definition lives in mesh_identity.c so the crypto
 * backend (OpenSSL on desktop, mbedTLS on ESP32 — see core/README.md) stays
 * out of the public header.
 */
typedef struct mesh_identity mesh_identity_t;

/*
 * Create an in-memory keypair. `seed_or_null` selects the source:
 *   - NULL  → generate a fresh keypair from the platform RNG.
 *   - non-NULL → load an existing X.509/PKCS8 keypair (DER) the caller holds.
 * On success writes an owned handle to *out; free with mesh_identity_free().
 *
 * NOTE (ambiguity, see report): the Java side persists the keypair to
 * mesh-identity.pub/.key files. This C core deliberately does NOT do file I/O
 * — persistence is the embedder's job (Android KeyStore, ESP32 NVS, a desktop
 * file). So there is no storageDir analogue here; the caller owns storage.
 */
mesh_result_t mesh_identity_create(mesh_bytes_t seed_or_null, mesh_identity_t **out);

void mesh_identity_free(mesh_identity_t *id);

/*
 * Copy this identity's PeerId (raw X.509 DER public-key bytes) into `out`.
 * To put a PeerId on the wire, hex-encode these bytes (mesh_hex_encode).
 */
mesh_result_t mesh_identity_peer_id(const mesh_identity_t *id, mesh_buf_t *out);

/*
 * Sign `payload` with SHA256withECDSA, writing the DER signature into `out`.
 *
 * HANDSHAKE QUIRK (WIRE_FORMAT.md:139-142): during the handshake the signed
 * payload is the raw UTF-8 bytes of the peer's nonce *string as transmitted*,
 * NOT the decoded nonce bytes. This function signs whatever bytes it is given;
 * mesh_link is responsible for passing the string bytes, not decoded bytes.
 */
mesh_result_t mesh_identity_sign(const mesh_identity_t *id,
                                 mesh_bytes_t payload, mesh_buf_t *out);

/*
 * Verify `signature` over `payload` against the public key recovered from
 * `peer_id_der` (the claimed PeerId's raw DER bytes — WIRE_FORMAT.md:146-147).
 * Returns MESH_OK iff the signature verifies, MESH_ERR_CRYPTO otherwise.
 * Static: verification needs no local keypair.
 */
mesh_result_t mesh_identity_verify(mesh_bytes_t peer_id_der,
                                   mesh_bytes_t payload,
                                   mesh_bytes_t signature);

#ifdef __cplusplus
}
#endif

#endif /* MESH_IDENTITY_H */
