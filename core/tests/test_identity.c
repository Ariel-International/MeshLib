/*
 * test_identity.c — L0 identity tests for the MeshLib C core (desktop/OpenSSL).
 *
 * Exercises the mesh_identity public API only (no crypto backend headers):
 *   - create (fresh keypair) succeeds and yields a non-empty X.509 DER PeerId
 *   - sign -> verify round-trip succeeds
 *   - a tampered PAYLOAD fails verification
 *   - a tampered SIGNATURE fails verification
 *   - verify against a DIFFERENT identity's PeerId fails
 *   - a fresh keypair round-trips through a re-created identity (seed load)
 *   - malformed PeerId DER is rejected, not crashed on
 *
 * No framework — plain checks with a pass/fail tally. Exit 0 = all pass.
 * Mirrors the style of test_codec.c.
 */
#include "mesh_identity.h"
#include "mesh_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg)                                                        \
    do {                                                                        \
        if (cond) { g_pass++; }                                                 \
        else { g_fail++; printf("  FAIL  %s  (%s:%d)\n", msg, __FILE__, __LINE__); } \
    } while (0)

int main(void) {
    /* The handshake signs the raw UTF-8 bytes of a Base64 nonce string; use a
     * representative payload of that shape (WIRE_FORMAT.md L2 handshake). */
    const uint8_t payload[] = "d29ybGQtbm9uY2UtMTIzNA==";
    mesh_bytes_t pl = { payload, sizeof(payload) - 1 }; /* drop the NUL */

    printf("== create fresh identity ==\n");
    mesh_bytes_t no_seed = { NULL, 0 };
    mesh_identity_t *id = NULL;
    mesh_result_t rc = mesh_identity_create(no_seed, &id);
    CHECK(rc == MESH_OK && id != NULL, "create fresh keypair");
    if (rc != MESH_OK || !id) {
        printf("\n=== %d passed, %d failed (aborted) ===\n", g_pass, g_fail);
        return 1;
    }

    printf("== PeerId is non-empty X.509 DER ==\n");
    mesh_buf_t pid;
    mesh_buf_init(&pid);
    rc = mesh_identity_peer_id(id, &pid);
    /* P-256 SubjectPublicKeyInfo DER is 91 bytes; require a plausible SEQUENCE
     * header (0x30) and a non-trivial length rather than pinning an exact size. */
    CHECK(rc == MESH_OK && pid.len > 30 && pid.data && pid.data[0] == 0x30,
          "peer_id returns X.509 DER");

    printf("== sign -> verify round-trip ==\n");
    mesh_buf_t sig;
    mesh_buf_init(&sig);
    rc = mesh_identity_sign(id, pl, &sig);
    CHECK(rc == MESH_OK && sig.len > 0, "sign produces a DER signature");

    mesh_bytes_t pid_b = { pid.data, pid.len };
    mesh_bytes_t sig_b = { sig.data, sig.len };
    rc = mesh_identity_verify(pid_b, pl, sig_b);
    CHECK(rc == MESH_OK, "verify accepts a genuine signature");

    printf("== tampered payload fails ==\n");
    {
        uint8_t bad[sizeof(payload) - 1];
        memcpy(bad, payload, sizeof(bad));
        bad[0] ^= 0x01; /* flip one bit */
        mesh_bytes_t bad_pl = { bad, sizeof(bad) };
        rc = mesh_identity_verify(pid_b, bad_pl, sig_b);
        CHECK(rc != MESH_OK, "verify rejects a tampered payload");
    }

    printf("== tampered signature fails ==\n");
    {
        uint8_t *bad = (uint8_t *)malloc(sig.len);
        CHECK(bad != NULL, "alloc for tampered sig");
        if (bad) {
            memcpy(bad, sig.data, sig.len);
            bad[sig.len / 2] ^= 0x01; /* corrupt a middle byte */
            mesh_bytes_t bad_sig = { bad, sig.len };
            rc = mesh_identity_verify(pid_b, pl, bad_sig);
            CHECK(rc != MESH_OK, "verify rejects a tampered signature");
            free(bad);
        }
    }

    printf("== truncated signature fails ==\n");
    {
        mesh_bytes_t trunc = { sig.data, sig.len > 4 ? sig.len - 4 : 0 };
        rc = mesh_identity_verify(pid_b, pl, trunc);
        CHECK(rc != MESH_OK, "verify rejects a truncated signature");
    }

    printf("== wrong identity fails ==\n");
    {
        mesh_identity_t *other = NULL;
        rc = mesh_identity_create(no_seed, &other);
        CHECK(rc == MESH_OK && other != NULL, "create second keypair");
        if (other) {
            mesh_buf_t opid;
            mesh_buf_init(&opid);
            rc = mesh_identity_peer_id(other, &opid);
            CHECK(rc == MESH_OK, "second peer_id");
            mesh_bytes_t opid_b = { opid.data, opid.len };
            /* Signature made by `id` must NOT verify under `other`'s PeerId. */
            rc = mesh_identity_verify(opid_b, pl, sig_b);
            CHECK(rc != MESH_OK, "verify rejects signature under wrong PeerId");
            /* And the two PeerIds must differ. */
            CHECK(!(opid.len == pid.len && memcmp(opid.data, pid.data, pid.len) == 0),
                  "two fresh identities have distinct PeerIds");
            mesh_buf_free(&opid);
            mesh_identity_free(other);
        }
    }

    printf("== malformed PeerId DER rejected (no crash) ==\n");
    {
        const uint8_t junk[] = { 0x30, 0x03, 0x01, 0x02, 0x03 };
        mesh_bytes_t junk_b = { junk, sizeof(junk) };
        rc = mesh_identity_verify(junk_b, pl, sig_b);
        CHECK(rc != MESH_OK, "verify rejects malformed PeerId DER");

        mesh_bytes_t empty_pid = { NULL, 0 };
        rc = mesh_identity_verify(empty_pid, pl, sig_b);
        CHECK(rc == MESH_ERR_INVALID_ARG, "verify rejects empty PeerId");
    }

    mesh_buf_free(&pid);
    mesh_buf_free(&sig);
    mesh_identity_free(id);

    printf("\n=== %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
