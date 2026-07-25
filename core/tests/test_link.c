/*
 * test_link.c — L2 framing + handshake tests for the MeshLib C core.
 *
 * Framing: round-trip encode/decode plus the reject cases (zero length,
 * negative length, oversized, truncated-buffer need_more).
 * Handshake: a full two-party happy path, plus appId-mismatch rejection,
 * tampered-nonce (signature no longer verifies), and malformed hex/base64
 * fields in hello wired through to a link failure.
 *
 * Rules under test: ../../WIRE_FORMAT.md "Framing" (:12-43) and
 * "L2 handshake" (:125-150).
 *
 * No framework — plain checks with a pass/fail tally. Exit 0 = all pass.
 */
#include "mesh_link.h"
#include "mesh_identity.h"
#include "mesh_codec.h"
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

/* ---- framing ------------------------------------------------------------ */

static void test_framing(void) {
    printf("== frame encode/decode round-trip ==\n");
    const char *msg = "{\"type\":\"heartbeat\"}";
    mesh_bytes_t pl = { (const uint8_t *)msg, strlen(msg) };

    mesh_buf_t frame;
    mesh_buf_init(&frame);
    mesh_result_t rc = mesh_frame_encode(pl, &frame);
    CHECK(rc == MESH_OK && frame.len == 4 + strlen(msg), "encode produces prefix+payload");
    /* Prefix is big-endian length. */
    CHECK(frame.data[0] == 0 && frame.data[1] == 0 &&
          frame.data[2] == ((strlen(msg) >> 8) & 0xFF) &&
          frame.data[3] == (strlen(msg) & 0xFF), "encode big-endian length prefix");

    mesh_bytes_t in = { frame.data, frame.len };
    mesh_bytes_t out_pl; size_t consumed; int need_more;
    rc = mesh_frame_decode(in, &out_pl, &consumed, &need_more);
    CHECK(rc == MESH_OK && !need_more && consumed == frame.len
          && out_pl.len == strlen(msg)
          && memcmp(out_pl.data, msg, out_pl.len) == 0, "decode recovers payload");
    mesh_buf_free(&frame);

    printf("== frame decode: need_more on short prefix / short payload ==\n");
    {
        uint8_t two[2] = { 0x00, 0x01 };
        mesh_bytes_t b = { two, 2 };
        mesh_bytes_t p; size_t c; int nm;
        rc = mesh_frame_decode(b, &p, &c, &nm);
        CHECK(rc == MESH_OK && nm == 1 && c == 0, "short prefix -> need_more");
    }
    {
        /* Valid prefix says 10 bytes, but only 4 present. */
        uint8_t hdr[8] = { 0x00, 0x00, 0x00, 0x0A, 'x', 'y', 'z', 'w' };
        mesh_bytes_t b = { hdr, 8 };
        mesh_bytes_t p; size_t c; int nm;
        rc = mesh_frame_decode(b, &p, &c, &nm);
        CHECK(rc == MESH_OK && nm == 1 && c == 0, "short payload -> need_more");
    }

    printf("== frame decode: reject zero / negative / oversized length ==\n");
    {
        uint8_t zero[4] = { 0, 0, 0, 0 };
        mesh_bytes_t b = { zero, 4 };
        mesh_bytes_t p; size_t c; int nm;
        rc = mesh_frame_decode(b, &p, &c, &nm);
        CHECK(rc == MESH_ERR_MALFORMED, "zero length rejected");
    }
    {
        /* 0xFFFFFFFF as signed int32 is -1. */
        uint8_t neg[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
        mesh_bytes_t b = { neg, 4 };
        mesh_bytes_t p; size_t c; int nm;
        rc = mesh_frame_decode(b, &p, &c, &nm);
        CHECK(rc == MESH_ERR_MALFORMED, "negative length rejected");
    }
    {
        /* 0x00040001 = 262145 = MAX + 1. */
        uint8_t big[4] = { 0x00, 0x04, 0x00, 0x01 };
        mesh_bytes_t b = { big, 4 };
        mesh_bytes_t p; size_t c; int nm;
        rc = mesh_frame_decode(b, &p, &c, &nm);
        CHECK(rc == MESH_ERR_MALFORMED, "oversized length rejected");
    }

    printf("== frame encode: reject empty and oversized payloads ==\n");
    {
        mesh_bytes_t empty = { (const uint8_t *)"", 0 };
        mesh_buf_t o; mesh_buf_init(&o);
        rc = mesh_frame_encode(empty, &o);
        CHECK(rc == MESH_ERR_INVALID_ARG, "encode rejects empty payload");
        mesh_buf_free(&o);
    }
    {
        /* One byte over the cap. Allocate, fill, encode -> TOO_LARGE. */
        size_t n = (size_t)MESH_MAX_FRAME_BYTES + 1;
        uint8_t *big = (uint8_t *)malloc(n);
        CHECK(big != NULL, "alloc oversized payload");
        if (big) {
            memset(big, 'A', n);
            mesh_bytes_t b = { big, n };
            mesh_buf_t o; mesh_buf_init(&o);
            rc = mesh_frame_encode(b, &o);
            CHECK(rc == MESH_ERR_TOO_LARGE, "encode rejects payload > 256 KiB");
            mesh_buf_free(&o);
            free(big);
        }
    }
    {
        /* Exactly the cap is allowed. */
        size_t n = (size_t)MESH_MAX_FRAME_BYTES;
        uint8_t *max = (uint8_t *)malloc(n);
        if (max) {
            memset(max, 'B', n);
            mesh_bytes_t b = { max, n };
            mesh_buf_t o; mesh_buf_init(&o);
            rc = mesh_frame_encode(b, &o);
            CHECK(rc == MESH_OK && o.len == 4 + n, "encode accepts exactly 256 KiB");
            mesh_buf_free(&o);
            free(max);
        }
    }
}

/* ---- handshake helpers -------------------------------------------------- */

/* Run hello+proof exchange between two handshakes. Returns 1 if both reach
 * DONE, 0 otherwise. Frames flow directly (no socket). */
static int run_handshake(mesh_handshake_t *a, mesh_handshake_t *b) {
    mesh_buf_t a_hello, b_hello, a_proof, b_proof;
    mesh_buf_init(&a_hello); mesh_buf_init(&b_hello);
    mesh_buf_init(&a_proof); mesh_buf_init(&b_proof);
    int ok = 0;

    if (mesh_handshake_write_hello(a, &a_hello) != MESH_OK) goto done;
    if (mesh_handshake_write_hello(b, &b_hello) != MESH_OK) goto done;

    mesh_bytes_t bh = { b_hello.data, b_hello.len };
    mesh_bytes_t ah = { a_hello.data, a_hello.len };
    if (mesh_handshake_read_hello(a, bh) != MESH_OK) goto done;
    if (mesh_handshake_read_hello(b, ah) != MESH_OK) goto done;

    if (mesh_handshake_write_proof(a, &a_proof) != MESH_OK) goto done;
    if (mesh_handshake_write_proof(b, &b_proof) != MESH_OK) goto done;

    mesh_bytes_t bp = { b_proof.data, b_proof.len };
    mesh_bytes_t ap = { a_proof.data, a_proof.len };
    if (mesh_handshake_read_proof(a, bp) != MESH_OK) goto done;
    if (mesh_handshake_read_proof(b, ap) != MESH_OK) goto done;

    ok = (mesh_handshake_state(a) == MESH_HS_DONE)
      && (mesh_handshake_state(b) == MESH_HS_DONE);

done:
    mesh_buf_free(&a_hello); mesh_buf_free(&b_hello);
    mesh_buf_free(&a_proof); mesh_buf_free(&b_proof);
    return ok;
}

/* ---- handshake tests ---------------------------------------------------- */

static void test_handshake(void) {
    mesh_bytes_t no_seed = { NULL, 0 };
    mesh_identity_t *id_a = NULL, *id_b = NULL;
    if (mesh_identity_create(no_seed, &id_a) != MESH_OK ||
        mesh_identity_create(no_seed, &id_b) != MESH_OK) {
        CHECK(0, "create identities for handshake");
        return;
    }

    printf("== handshake happy path (no appId) ==\n");
    {
        mesh_handshake_t *a = NULL, *b = NULL;
        mesh_handshake_begin(id_a, NULL, &a);
        mesh_handshake_begin(id_b, NULL, &b);
        CHECK(run_handshake(a, b), "both sides reach DONE");

        /* Each side's verified remote PeerId must equal the OTHER's real PeerId. */
        mesh_buf_t a_remote, b_pid;
        mesh_buf_init(&a_remote); mesh_buf_init(&b_pid);
        mesh_result_t r1 = mesh_handshake_remote_peer_id(a, &a_remote);
        mesh_result_t r2 = mesh_identity_peer_id(id_b, &b_pid);
        CHECK(r1 == MESH_OK && r2 == MESH_OK && a_remote.len == b_pid.len
              && memcmp(a_remote.data, b_pid.data, a_remote.len) == 0,
              "A's verified remote PeerId == B's real PeerId");
        mesh_buf_free(&a_remote); mesh_buf_free(&b_pid);

        mesh_handshake_free(a); mesh_handshake_free(b);
    }

    printf("== handshake happy path (matching appId) ==\n");
    {
        mesh_handshake_t *a = NULL, *b = NULL;
        mesh_handshake_begin(id_a, "popcoin", &a);
        mesh_handshake_begin(id_b, "popcoin", &b);
        CHECK(run_handshake(a, b), "matching appId reaches DONE");
        mesh_handshake_free(a); mesh_handshake_free(b);
    }

    printf("== handshake: one side wildcard appId still matches ==\n");
    {
        mesh_handshake_t *a = NULL, *b = NULL;
        mesh_handshake_begin(id_a, "popcoin", &a);
        mesh_handshake_begin(id_b, NULL, &b); /* wildcard */
        CHECK(run_handshake(a, b), "wildcard appId matches anything");
        mesh_handshake_free(a); mesh_handshake_free(b);
    }

    printf("== handshake: appId mismatch rejected ==\n");
    {
        mesh_handshake_t *a = NULL, *b = NULL;
        mesh_handshake_begin(id_a, "popcoin", &a);
        mesh_handshake_begin(id_b, "astrolabius", &b);
        int done = run_handshake(a, b);
        CHECK(!done, "appId mismatch does not reach DONE");
        /* The side that read the mismatching hello must be FAILED. */
        CHECK(mesh_handshake_state(a) == MESH_HS_FAILED ||
              mesh_handshake_state(b) == MESH_HS_FAILED,
              "appId mismatch marks a side FAILED");
        mesh_handshake_free(a); mesh_handshake_free(b);
    }

    printf("== handshake: tampered nonce breaks signature ==\n");
    {
        /* Drive manually so we can corrupt B's hello (its nonce) before A signs
         * it. A then signs the corrupted nonce; B verifies over its OWN real
         * nonce and must reject. */
        mesh_handshake_t *a = NULL, *b = NULL;
        mesh_handshake_begin(id_a, NULL, &a);
        mesh_handshake_begin(id_b, NULL, &b);

        mesh_buf_t a_hello, b_hello;
        mesh_buf_init(&a_hello); mesh_buf_init(&b_hello);
        mesh_handshake_write_hello(a, &a_hello);
        mesh_handshake_write_hello(b, &b_hello);

        /* Corrupt one character inside B's hello nonce value. Find "nonce":" and
         * flip a char just after it. */
        char *hay = (char *)malloc(b_hello.len + 1);
        memcpy(hay, b_hello.data, b_hello.len);
        hay[b_hello.len] = '\0';
        char *np = strstr(hay, "\"nonce\":\"");
        int tampered = 0;
        if (np) {
            char *val = np + strlen("\"nonce\":\"");
            /* Flip to a different valid base64 char so the string stays
             * well-formed but the bytes differ. */
            *val = (*val == 'A') ? 'B' : 'A';
            tampered = 1;
        }
        CHECK(tampered, "located nonce to tamper");

        mesh_bytes_t bh_bad = { (const uint8_t *)hay, b_hello.len };
        mesh_bytes_t ah = { a_hello.data, a_hello.len };
        /* A reads B's TAMPERED hello (accepts it — nonce isn't validated on
         * read), B reads A's clean hello. */
        mesh_result_t ra = mesh_handshake_read_hello(a, bh_bad);
        mesh_result_t rb = mesh_handshake_read_hello(b, ah);
        CHECK(ra == MESH_OK && rb == MESH_OK, "both read hello (tampered nonce not rejected on read)");

        mesh_buf_t a_proof, b_proof;
        mesh_buf_init(&a_proof); mesh_buf_init(&b_proof);
        mesh_handshake_write_proof(a, &a_proof); /* A signs the tampered nonce */
        mesh_handshake_write_proof(b, &b_proof); /* B signs A's real nonce */

        /* B verifies A's proof over B's OWN (real) nonce -> mismatch -> fail. */
        mesh_bytes_t ap = { a_proof.data, a_proof.len };
        mesh_result_t rp = mesh_handshake_read_proof(b, ap);
        CHECK(rp != MESH_OK && mesh_handshake_state(b) == MESH_HS_FAILED,
              "tampered nonce => B rejects A's proof");

        free(hay);
        mesh_buf_free(&a_hello); mesh_buf_free(&b_hello);
        mesh_buf_free(&a_proof); mesh_buf_free(&b_proof);
        mesh_handshake_free(a); mesh_handshake_free(b);
    }

    printf("== handshake: malformed hex peerId in hello rejected ==\n");
    {
        mesh_handshake_t *a = NULL;
        mesh_handshake_begin(id_a, NULL, &a);
        mesh_buf_t a_hello; mesh_buf_init(&a_hello);
        mesh_handshake_write_hello(a, &a_hello);
        (void)a_hello;
        /* Feed A a hello whose peerId is not valid hex (odd length + 'g'). */
        const char *bad = "{\"type\":\"hello\",\"peerId\":\"abcg\",\"nonce\":\"AAAAAAAAAAAAAAAAAAAAAA==\"}";
        mesh_bytes_t bh = { (const uint8_t *)bad, strlen(bad) };
        mesh_result_t rc = mesh_handshake_read_hello(a, bh);
        CHECK(rc == MESH_ERR_MALFORMED && mesh_handshake_state(a) == MESH_HS_FAILED,
              "malformed peerId hex fails the handshake");
        mesh_buf_free(&a_hello);
        mesh_handshake_free(a);
    }

    printf("== handshake: malformed base64 signature in proof rejected ==\n");
    {
        /* Full valid hello exchange, then feed a proof with a bad signature. */
        mesh_handshake_t *a = NULL, *b = NULL;
        mesh_handshake_begin(id_a, NULL, &a);
        mesh_handshake_begin(id_b, NULL, &b);
        mesh_buf_t a_hello, b_hello;
        mesh_buf_init(&a_hello); mesh_buf_init(&b_hello);
        mesh_handshake_write_hello(a, &a_hello);
        mesh_handshake_write_hello(b, &b_hello);
        mesh_bytes_t bh = { b_hello.data, b_hello.len };
        mesh_handshake_read_hello(a, bh);
        mesh_buf_t a_proof; mesh_buf_init(&a_proof);
        mesh_handshake_write_proof(a, &a_proof);
        (void)a_proof;
        /* "!!!!" is not valid base64 -> strict decode rejects. */
        const char *bad = "{\"type\":\"proof\",\"signature\":\"!!!!\"}";
        mesh_bytes_t bp = { (const uint8_t *)bad, strlen(bad) };
        mesh_result_t rc = mesh_handshake_read_proof(a, bp);
        CHECK(rc == MESH_ERR_MALFORMED && mesh_handshake_state(a) == MESH_HS_FAILED,
              "malformed base64 signature fails the handshake");
        mesh_buf_free(&a_hello); mesh_buf_free(&b_hello); mesh_buf_free(&a_proof);
        mesh_handshake_free(a); mesh_handshake_free(b);
    }

    printf("== handshake: hello with missing field rejected ==\n");
    {
        mesh_handshake_t *a = NULL;
        mesh_handshake_begin(id_a, NULL, &a);
        mesh_buf_t a_hello; mesh_buf_init(&a_hello);
        mesh_handshake_write_hello(a, &a_hello);
        /* No nonce field. */
        const char *bad = "{\"type\":\"hello\",\"peerId\":\"30\"}";
        mesh_bytes_t bh = { (const uint8_t *)bad, strlen(bad) };
        mesh_result_t rc = mesh_handshake_read_hello(a, bh);
        CHECK(rc == MESH_ERR_MALFORMED && mesh_handshake_state(a) == MESH_HS_FAILED,
              "hello missing nonce fails");
        mesh_buf_free(&a_hello);
        mesh_handshake_free(a);
    }

    mesh_identity_free(id_a);
    mesh_identity_free(id_b);
}

int main(void) {
    test_framing();
    test_handshake();
    printf("\n=== %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
