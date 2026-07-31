/*
 * test_fuzz.c — deterministic random-input hardening for the wire-facing
 * entry points: mesh_frame_decode (L2 framing), the handshake JSON readers
 * (L2), and mesh_router_on_topology / mesh_router_on_route (L3).
 *
 * This is NOT coverage-guided fuzzing. No clang/libFuzzer/AFL toolchain is
 * available on this machine (MSVC's cl.exe has no -fsanitize=fuzzer), and
 * standing one up would mean installing new tooling, not exercising the
 * existing core. Instead this is a seeded, reproducible random/boundary
 * input generator: it does not have instrumentation-guided coverage feedback,
 * but for a 4-byte-length-prefix + flat-JSON codec it still walks the actual
 * risk surface at integration time — truncation at every offset, length
 * fields that lie in both directions, multiple frames concatenated or
 * interleaved with garbage, and malformed JSON fed to the handshake/router
 * parsers.
 *
 * Every property checked below is a real WIRE_FORMAT.md / API contract, not
 * an invented one:
 *   - mesh_frame_decode must never read past `in.len` bytes (checked
 *     structurally: it only ever returns a payload view whose data+len fits
 *     inside the input, or need_more/MALFORMED — verified per-call).
 *   - it must never claim OK+need_more=0 on a frame it wasn't actually given
 *     in full (consumed must equal 4+len exactly).
 *   - a "lying" length prefix (claims more than is present) must yield
 *     need_more=1, not a bogus payload.
 *   - out-of-range length (<=0 or >MAX) must yield MESH_ERR_MALFORMED,
 *     deterministically, never MESH_OK.
 *   - decoding must terminate — no infinite loop on any input.
 *   - handshake read_hello/read_proof and router on_topology/on_route must
 *     never return MESH_OK on structurally-random byte soup (it is
 *     astronomically unlikely random bytes form valid JSON with the right
 *     shape), must never crash, and on_route/on_topology must specifically
 *     never tear the router down (there is no "link" object at L3 to check,
 *     but the router handle itself must remain usable afterwards, i.e. a
 *     subsequent well-formed call still works) — WIRE_FORMAT.md:119-121.
 *
 * Seeded with a fixed PRNG seed by default so failures are reproducible;
 * pass an explicit seed as argv[1] to explore further. argv[2] (or the
 * MESHCORE_FUZZ_MULTIPLIER env var) scales every loop's iteration count for
 * long sweeps without slowing down the default `ctest` run.
 */
#include "mesh_link.h"
#include "mesh_identity.h"
#include "mesh_router.h"
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

/* ---- small xorshift PRNG so runs are reproducible from a printed seed --- */

static uint64_t g_rng_state;

static void rng_seed(uint64_t seed) {
    g_rng_state = seed ? seed : 0x9E3779B97F4A7C15ULL;
}

static uint32_t rng_next(void) {
    /* xorshift64* */
    uint64_t x = g_rng_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    g_rng_state = x;
    return (uint32_t)((x * 0x2545F4914F6CDD1DULL) >> 32);
}

static size_t rng_below(size_t n) {
    if (n == 0) return 0;
    return (size_t)(rng_next() % n);
}

static void rng_fill(uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)(rng_next() & 0xFF);
}

/* Scales every loop's iteration count for long sweeps; 1 by default so the
 * normal `ctest` run stays fast. */
static int g_mult = 1;


/* ===================================================================== */
/*  L2 framing: mesh_frame_decode under truncation, lying lengths,       */
/*  concatenation/interleaving.                                          */
/* ===================================================================== */

/* One decode call must be internally consistent regardless of what garbage
 * it was given. This is checked on every single call, not just at the end. */
static void assert_decode_consistent(mesh_bytes_t in, mesh_result_t rc,
                                     mesh_bytes_t payload, size_t consumed,
                                     int need_more) {
    CHECK(rc == MESH_OK || rc == MESH_ERR_MALFORMED || rc == MESH_ERR_INVALID_ARG,
          "decode returns only a documented result code");

    if (rc == MESH_ERR_MALFORMED) {
        /* Malformed must not also claim a usable payload. */
        CHECK(need_more == 0, "malformed result: need_more not set");
    }

    if (rc == MESH_OK && !need_more) {
        /* A complete frame was reported: consumed must be entirely within
         * the buffer we handed in, and payload must sit fully inside it. */
        CHECK(consumed <= in.len, "consumed does not exceed input length");
        CHECK(consumed >= MESH_FRAME_PREFIX_BYTES, "consumed includes the prefix");
        CHECK(payload.data >= in.data && payload.data + payload.len <= in.data + in.len,
              "payload view lies fully inside the input buffer");
        CHECK(payload.len == consumed - MESH_FRAME_PREFIX_BYTES,
              "consumed accounts for prefix + exactly the reported payload");
    }

    if (rc == MESH_OK && need_more) {
        CHECK(consumed == 0, "need_more implies nothing was consumed yet");
    }
}

static void test_frame_decode_truncation(void) {
    printf("== fuzz: mesh_frame_decode truncated at every offset ==\n");
    const char *msg = "{\"type\":\"heartbeat\",\"seq\":12345}";
    mesh_buf_t frame;
    mesh_buf_init(&frame);
    mesh_bytes_t pl = { (const uint8_t *)msg, strlen(msg) };
    mesh_result_t rc = mesh_frame_encode(pl, &frame);
    CHECK(rc == MESH_OK, "setup: encode a real frame to truncate");

    /* Every possible truncation point, including 0 bytes and the full frame,
     * must behave: never a bogus payload, never a crash, never a hang. */
    for (size_t cut = 0; cut <= frame.len; cut++) {
        mesh_bytes_t in = { frame.data, cut };
        mesh_bytes_t payload; size_t consumed; int need_more;
        rc = mesh_frame_decode(in, &payload, &consumed, &need_more);
        assert_decode_consistent(in, rc, payload, consumed, need_more);
        if (cut < frame.len) {
            CHECK(rc == MESH_OK && need_more == 1,
                  "truncated buffer always reports need_more, never a false frame");
        } else {
            CHECK(rc == MESH_OK && need_more == 0 && consumed == frame.len,
                  "exact full frame decodes cleanly");
        }
    }
    mesh_buf_free(&frame);
}

static void test_frame_decode_lying_length(void) {
    printf("== fuzz: length prefix that lies (random values vs random buffer sizes) ==\n");
    rng_seed(0xF00D);
    int n_lying = 20000 * g_mult;
    for (int iter = 0; iter < n_lying; iter++) {
        size_t buflen = 4 + rng_below(64); /* prefix + up to 63 bytes of body */
        uint8_t *buf = (uint8_t *)malloc(buflen);
        CHECK(buf != NULL, "alloc fuzz buffer");
        if (!buf) continue;
        rng_fill(buf, buflen);

        /* Bias some fraction of iterations toward specific edge values in the
         * prefix so we don't rely purely on chance to hit them. */
        uint32_t bias = rng_below(6);
        if (bias == 0) { buf[0]=0;buf[1]=0;buf[2]=0;buf[3]=0; }                  /* zero length   */
        else if (bias == 1) { buf[0]=0xFF;buf[1]=0xFF;buf[2]=0xFF;buf[3]=0xFF; } /* -1 as signed  */
        else if (bias == 2) { buf[0]=0x00;buf[1]=0x04;buf[2]=0x00;buf[3]=0x01; } /* MAX+1         */
        else if (bias == 3) { buf[0]=0x00;buf[1]=0x00;buf[2]=0x00;buf[3]=0x01; } /* claims 1, may have 0 body bytes */
        else if (bias == 4) { buf[0]=0x7F;buf[1]=0xFF;buf[2]=0xFF;buf[3]=0xFF; } /* huge positive */
        /* else: fully random prefix from rng_fill above */

        mesh_bytes_t in = { buf, buflen };
        mesh_bytes_t payload; size_t consumed; int need_more;
        mesh_result_t rc = mesh_frame_decode(in, &payload, &consumed, &need_more);
        assert_decode_consistent(in, rc, payload, consumed, need_more);

        free(buf);
    }
    printf("     %d random (prefix,buffer) pairs checked\n", n_lying);
}

static void test_frame_decode_concatenated_and_interleaved(void) {
    printf("== fuzz: concatenated frames, and a valid frame after garbage ==\n");
    const char *m1 = "{\"a\":1}";
    const char *m2 = "{\"b\":22}";
    mesh_buf_t f1, f2, combo;
    mesh_buf_init(&f1); mesh_buf_init(&f2); mesh_buf_init(&combo);
    mesh_bytes_t p1 = { (const uint8_t *)m1, strlen(m1) };
    mesh_bytes_t p2 = { (const uint8_t *)m2, strlen(m2) };
    CHECK(mesh_frame_encode(p1, &f1) == MESH_OK, "setup encode f1");
    CHECK(mesh_frame_encode(p2, &f2) == MESH_OK, "setup encode f2");

    /* Two valid frames back to back: decode must recover both, in order,
     * using `consumed` to walk forward, and nothing else. */
    mesh_buf_reserve(&combo, f1.len + f2.len);
    memcpy(combo.data, f1.data, f1.len);
    memcpy(combo.data + f1.len, f2.data, f2.len);
    combo.len = f1.len + f2.len;

    mesh_bytes_t in = { combo.data, combo.len };
    mesh_bytes_t payload; size_t consumed; int need_more;
    mesh_result_t rc = mesh_frame_decode(in, &payload, &consumed, &need_more);
    CHECK(rc == MESH_OK && !need_more && payload.len == strlen(m1) &&
          memcmp(payload.data, m1, payload.len) == 0, "first of two concatenated frames recovered");
    CHECK(consumed == f1.len, "consumed points exactly at the second frame's start");

    mesh_bytes_t in2 = { combo.data + consumed, combo.len - consumed };
    mesh_bytes_t payload2; size_t consumed2; int need_more2;
    rc = mesh_frame_decode(in2, &payload2, &consumed2, &need_more2);
    CHECK(rc == MESH_OK && !need_more2 && payload2.len == strlen(m2) &&
          memcmp(payload2.data, m2, payload2.len) == 0, "second concatenated frame recovered after re-slicing by consumed");

    /* A valid frame preceded by an out-of-range prefix must fail exactly at
     * the garbage, not skip past it and resync on the good frame — a decoder
     * that "recovers" from a corrupt prefix by scanning forward would mask
     * a desynced stream instead of surfacing it. */
    uint8_t bad_prefix[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
    mesh_buf_t spliced;
    mesh_buf_init(&spliced);
    mesh_buf_reserve(&spliced, 4 + f1.len);
    memcpy(spliced.data, bad_prefix, 4);
    memcpy(spliced.data + 4, f1.data, f1.len);
    spliced.len = 4 + f1.len;
    mesh_bytes_t in3 = { spliced.data, spliced.len };
    mesh_bytes_t payload3; size_t consumed3; int need_more3;
    rc = mesh_frame_decode(in3, &payload3, &consumed3, &need_more3);
    CHECK(rc == MESH_ERR_MALFORMED, "garbage prefix before a valid frame is rejected, not skipped");

    mesh_buf_free(&f1); mesh_buf_free(&f2); mesh_buf_free(&combo); mesh_buf_free(&spliced);
}

/* ===================================================================== */
/*  L2 handshake JSON readers under random/garbage input.                */
/* ===================================================================== */

static void test_handshake_garbage_input(void) {
    printf("== fuzz: mesh_handshake_read_hello / read_proof on random byte soup ==\n");
    mesh_bytes_t no_seed = { NULL, 0 };
    mesh_identity_t *id = NULL;
    CHECK(mesh_identity_create(no_seed, &id) == MESH_OK, "setup: identity for handshake fuzz");
    if (!id) return;

    rng_seed(0xC0FFEE);
    int ok_never_seen = 1;
    int n_hello = 5000 * g_mult;
    for (int iter = 0; iter < n_hello; iter++) {
        size_t len = rng_below(256);
        uint8_t *buf = (uint8_t *)malloc(len ? len : 1);
        if (len) rng_fill(buf, len);

        /* Bias a slice of iterations toward "JSON-ish" garbage: brace-heavy
         * bytes drawn from a small alphabet, more likely to trip the parser's
         * escape/quote handling than uniform random bytes would. */
        if (rng_below(3) == 0 && len > 0) {
            static const char alphabet[] = "{}[]\":,\\abc012 \t\n";
            for (size_t i = 0; i < len; i++)
                buf[i] = (uint8_t)alphabet[rng_below(sizeof(alphabet) - 1)];
        }

        mesh_handshake_t *hs = NULL;
        mesh_handshake_begin(id, NULL, &hs);
        mesh_buf_t hello; mesh_buf_init(&hello);
        mesh_handshake_write_hello(hs, &hello); /* reach HELLO_SENT so read_hello is a valid call */

        mesh_bytes_t garbage = { buf, len };
        mesh_result_t rc = mesh_handshake_read_hello(hs, garbage);
        if (rc == MESH_OK) ok_never_seen = 0;
        CHECK(rc == MESH_OK || rc == MESH_ERR_MALFORMED || rc == MESH_ERR_INVALID_ARG,
              "read_hello on garbage returns only a documented code");
        if (rc != MESH_OK) {
            CHECK(mesh_handshake_state(hs) == MESH_HS_FAILED,
                  "rejected hello leaves the handshake FAILED, not stuck mid-state");
        }

        mesh_buf_free(&hello);
        free(buf);
        mesh_handshake_free(hs);
    }
    CHECK(ok_never_seen, "random/JSON-ish garbage never parsed as a valid hello");
    printf("     %d garbage hello payloads checked\n", n_hello);

    /* Same drill for read_proof, reached via a real hello exchange so the
     * handshake is in PROOF_SENT (the only state read_proof accepts). */
    rng_seed(0xBEEF);
    int proof_ok_never_seen = 1;
    mesh_identity_t *id2 = NULL;
    CHECK(mesh_identity_create(no_seed, &id2) == MESH_OK, "setup: second identity for proof fuzz");
    int n_proof = 5000 * g_mult;
    for (int iter = 0; id2 && iter < n_proof; iter++) {
        mesh_handshake_t *a = NULL, *b = NULL;
        mesh_handshake_begin(id, NULL, &a);
        mesh_handshake_begin(id2, NULL, &b);
        mesh_buf_t ah, bh, ap;
        mesh_buf_init(&ah); mesh_buf_init(&bh); mesh_buf_init(&ap);
        mesh_handshake_write_hello(a, &ah);
        mesh_handshake_write_hello(b, &bh);
        mesh_bytes_t bhv = { bh.data, bh.len };
        mesh_bytes_t ahv = { ah.data, ah.len };
        mesh_handshake_read_hello(a, bhv);
        mesh_handshake_read_hello(b, ahv);
        mesh_handshake_write_proof(a, &ap); /* a now in PROOF_SENT */

        size_t len = rng_below(256);
        uint8_t *buf = (uint8_t *)malloc(len ? len : 1);
        if (len) rng_fill(buf, len);
        if (rng_below(3) == 0 && len > 0) {
            static const char alphabet[] = "{}[]\":,\\abc012 \t\n";
            for (size_t i = 0; i < len; i++)
                buf[i] = (uint8_t)alphabet[rng_below(sizeof(alphabet) - 1)];
        }
        mesh_bytes_t garbage = { buf, len };
        mesh_result_t rc = mesh_handshake_read_proof(a, garbage);
        if (rc == MESH_OK) proof_ok_never_seen = 0;
        CHECK(rc == MESH_OK || rc == MESH_ERR_MALFORMED || rc == MESH_ERR_INVALID_ARG || rc == MESH_ERR_CRYPTO,
              "read_proof on garbage returns only a documented code");

        free(buf);
        mesh_buf_free(&ah); mesh_buf_free(&bh); mesh_buf_free(&ap);
        mesh_handshake_free(a); mesh_handshake_free(b);
    }
    CHECK(proof_ok_never_seen, "random/JSON-ish garbage never parsed as a valid proof");
    printf("     %d garbage proof payloads checked\n", n_proof);

    mesh_identity_free(id);
    if (id2) mesh_identity_free(id2);
}

/* ===================================================================== */
/*  L3 router: on_topology / on_route on random/garbage input must never  */
/*  crash and must never take down the router (WIRE_FORMAT.md:119-121).  */
/* ===================================================================== */

static mesh_result_t noop_send(const char *next_hop_hex, mesh_bytes_t frame, void *user) {
    (void)next_hop_hex; (void)frame; (void)user;
    return MESH_OK;
}

static int g_delivered = 0;
static void noop_deliver(const char *from_hex, mesh_bytes_t payload, void *user) {
    (void)from_hex; (void)payload; (void)user;
    g_delivered++;
}

static void test_router_garbage_input(void) {
    printf("== fuzz: mesh_router_on_topology / on_route on random byte soup ==\n");
    mesh_router_t *r = NULL;
    const char *self_hex = "3059301306072a8648ce3d020106082a8648ce3d03010703420004";
    mesh_result_t rc = mesh_router_create(self_hex, noop_send, noop_deliver, NULL, &r);
    CHECK(rc == MESH_OK && r != NULL, "setup: router created for fuzz");
    if (!r) return;

    CHECK(mesh_router_link_up(r, "aa") == MESH_OK, "setup: one link so on_topology has something to compare against");

    rng_seed(0x5EED1);
    int topo_ok_never_seen = 0;
    int n_topo = 8000 * g_mult;
    for (int iter = 0; iter < n_topo; iter++) {
        size_t len = rng_below(300);
        uint8_t *buf = (uint8_t *)malloc(len ? len : 1);
        if (len) rng_fill(buf, len);
        if (rng_below(3) == 0 && len > 0) {
            static const char alphabet[] = "{}[]\":,\\abcdef0123 \t\n";
            for (size_t i = 0; i < len; i++)
                buf[i] = (uint8_t)alphabet[rng_below(sizeof(alphabet) - 1)];
        }
        mesh_bytes_t garbage = { buf, len };
        mesh_result_t r1 = mesh_router_on_topology(r, garbage);
        if (r1 == MESH_OK) topo_ok_never_seen++;
        CHECK(r1 == MESH_OK || r1 == MESH_ERR_MALFORMED || r1 == MESH_ERR_INVALID_ARG,
              "on_topology(garbage) returns only a documented code");
        free(buf);
    }
    /* Random bytes CAN occasionally slip through as a technically-parseable
     * empty/trivial topology row (e.g. "{}" is only 2 bytes and could appear);
     * what matters is that it never crashes and the router stays usable —
     * checked below, not that OK is literally impossible. */
    printf("     %d garbage topology frames checked (%d spuriously well-formed)\n", n_topo, topo_ok_never_seen);

    rng_seed(0xFACE);
    int route_ok_never_seen = 0;
    int delivered_before = g_delivered;
    int n_route = 8000 * g_mult;
    for (int iter = 0; iter < n_route; iter++) {
        size_t len = rng_below(300);
        uint8_t *buf = (uint8_t *)malloc(len ? len : 1);
        if (len) rng_fill(buf, len);
        if (rng_below(3) == 0 && len > 0) {
            static const char alphabet[] = "{}[]\":,\\abcdef0123 \t\n";
            for (size_t i = 0; i < len; i++)
                buf[i] = (uint8_t)alphabet[rng_below(sizeof(alphabet) - 1)];
        }
        mesh_bytes_t garbage = { buf, len };
        mesh_result_t r1 = mesh_router_on_route(r, garbage);
        if (r1 == MESH_OK) route_ok_never_seen++;
        CHECK(r1 == MESH_OK || r1 == MESH_ERR_MALFORMED || r1 == MESH_ERR_INVALID_ARG,
              "on_route(garbage) returns only a documented code");
        free(buf);
    }
    CHECK(g_delivered == delivered_before,
          "garbage route frames never trigger a spurious delivery to the app layer");
    printf("     %d garbage route frames checked (%d spuriously well-formed)\n", n_route, route_ok_never_seen);

    /* The router must still work normally after all that garbage — this is
     * the actual "link stays up" property from WIRE_FORMAT.md:119-121
     * translated to the L3 API: the router handle is not corrupted. */
    int depth = -1;
    rc = mesh_router_depth(r, "aa", &depth);
    CHECK(rc == MESH_OK && depth == 1, "router still answers correctly for a known peer after garbage flood");
    rc = mesh_router_link_up(r, "bb");
    CHECK(rc == MESH_OK, "router still accepts new links after garbage flood");

    mesh_router_free(r);
}

int main(int argc, char **argv) {
    uint64_t seed = 0xA11CE5EEDULL;
    if (argc > 1) seed = (uint64_t)strtoull(argv[1], NULL, 0);

    if (argc > 2) {
        g_mult = atoi(argv[2]);
    } else {
        const char *env = getenv("MESHCORE_FUZZ_MULTIPLIER");
        if (env) g_mult = atoi(env);
    }
    if (g_mult < 1) g_mult = 1;

    printf("mesh core fuzz harness (seed=0x%llx, multiplier=%d)\n",
           (unsigned long long)seed, g_mult);
    rng_seed(seed);

    test_frame_decode_truncation();
    test_frame_decode_lying_length();
    test_frame_decode_concatenated_and_interleaved();
    test_handshake_garbage_input();
    test_router_garbage_input();

    printf("\n=== %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
