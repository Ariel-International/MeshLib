/*
 * test_codec.c — strict Base64/hex codec tests for the MeshLib C core.
 *
 * Mirrors the Java StrictTest bar: round-trips PLUS deliberately-malformed
 * inputs that MUST be rejected (MESH_ERR_MALFORMED), never silently corrected.
 * Rules under test: ../../WIRE_FORMAT.md:47-121.
 *
 * No framework — plain asserts with a pass/fail tally. Exit code 0 = all pass.
 */
#include "mesh_codec.h"

#include <stdio.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg)                                                    \
    do {                                                                    \
        if (cond) { g_pass++; }                                             \
        else { g_fail++; printf("  FAIL  %s  (%s:%d)\n", msg, __FILE__, __LINE__); } \
    } while (0)

/* Encode `in` (len bytes) and compare the result string to `expect`. */
static void expect_b64(const uint8_t *in, size_t len, const char *expect) {
    mesh_buf_t out;
    mesh_buf_init(&out);
    mesh_bytes_t b = { in, len };
    mesh_result_t rc = mesh_base64_encode(b, &out);
    int ok = (rc == MESH_OK)
             && out.len == strlen(expect)
             && (out.len == 0 || memcmp(out.data, expect, out.len) == 0);
    if (!ok) {
        g_fail++;
        printf("  FAIL  b64 encode: got rc=%s len=%zu, want \"%s\"\n",
               mesh_result_str(rc), out.len, expect);
    } else {
        g_pass++;
    }
    mesh_buf_free(&out);
}

/* Decode `s`; expect success and exact byte match against expect[expect_len]. */
static void expect_b64_decode_ok(const char *s, const uint8_t *expect, size_t expect_len) {
    mesh_buf_t out;
    mesh_buf_init(&out);
    mesh_result_t rc = mesh_base64_decode(s, &out);
    int ok = (rc == MESH_OK)
             && out.len == expect_len
             && (expect_len == 0 || memcmp(out.data, expect, expect_len) == 0);
    if (!ok) {
        g_fail++;
        printf("  FAIL  b64 decode ok \"%s\": rc=%s len=%zu want %zu\n",
               s, mesh_result_str(rc), out.len, expect_len);
    } else {
        g_pass++;
    }
    mesh_buf_free(&out);
}

/* Decode `s`; expect strict rejection. */
static void expect_b64_reject(const char *s, const char *label) {
    mesh_buf_t out;
    mesh_buf_init(&out);
    mesh_result_t rc = mesh_base64_decode(s, &out);
    CHECK(rc == MESH_ERR_MALFORMED, label);
    mesh_buf_free(&out);
}

static void expect_hex_reject(const char *s, const char *label) {
    mesh_buf_t out;
    mesh_buf_init(&out);
    mesh_result_t rc = mesh_hex_decode(s, &out);
    CHECK(rc == MESH_ERR_MALFORMED, label);
    mesh_buf_free(&out);
}

/* Round-trip: bytes -> encode -> decode -> same bytes. */
static void roundtrip_b64(const uint8_t *in, size_t len) {
    mesh_buf_t enc, dec;
    mesh_buf_init(&enc);
    mesh_buf_init(&dec);
    mesh_bytes_t b = { in, len };
    mesh_result_t r1 = mesh_base64_encode(b, &enc);

    /* Decode needs a NUL-terminated string. */
    char tmp[512];
    size_t n = enc.len < sizeof(tmp) - 1 ? enc.len : 0;
    if (enc.len > 0) memcpy(tmp, enc.data, n);
    tmp[n] = '\0';

    mesh_result_t r2 = mesh_base64_decode(tmp, &dec);
    int ok = (r1 == MESH_OK) && (r2 == MESH_OK)
             && dec.len == len
             && (len == 0 || memcmp(dec.data, in, len) == 0);
    CHECK(ok, "b64 round-trip");
    mesh_buf_free(&enc);
    mesh_buf_free(&dec);
}

static void roundtrip_hex(const uint8_t *in, size_t len) {
    mesh_buf_t enc, dec;
    mesh_buf_init(&enc);
    mesh_buf_init(&dec);
    mesh_bytes_t b = { in, len };
    mesh_result_t r1 = mesh_hex_encode(b, &enc);

    char tmp[512];
    size_t n = enc.len < sizeof(tmp) - 1 ? enc.len : 0;
    if (enc.len > 0) memcpy(tmp, enc.data, n);
    tmp[n] = '\0';

    mesh_result_t r2 = mesh_hex_decode(tmp, &dec);
    int ok = (r1 == MESH_OK) && (r2 == MESH_OK)
             && dec.len == len
             && (len == 0 || memcmp(dec.data, in, len) == 0);
    CHECK(ok, "hex round-trip");
    mesh_buf_free(&enc);
    mesh_buf_free(&dec);
}

int main(void) {
    printf("== Base64 encode (canonical, must match java.util.Base64) ==\n");
    /* Known-answer vectors (RFC 4648 §10 + wire cases). */
    expect_b64((const uint8_t *)"", 0, "");
    expect_b64((const uint8_t *)"f", 1, "Zg==");
    expect_b64((const uint8_t *)"fo", 2, "Zm8=");
    expect_b64((const uint8_t *)"foo", 3, "Zm9v");
    expect_b64((const uint8_t *)"foob", 4, "Zm9vYg==");
    expect_b64((const uint8_t *)"fooba", 5, "Zm9vYmE=");
    expect_b64((const uint8_t *)"foobar", 6, "Zm9vYmFy");

    printf("== Base64 decode (canonical accepted) ==\n");
    expect_b64_decode_ok("", NULL, 0);
    expect_b64_decode_ok("Zg==", (const uint8_t *)"f", 1);
    expect_b64_decode_ok("Zm8=", (const uint8_t *)"fo", 2);
    expect_b64_decode_ok("Zm9v", (const uint8_t *)"foo", 3);
    expect_b64_decode_ok("AA==", (const uint8_t *)"\0", 1);
    expect_b64_decode_ok("AAA=", (const uint8_t *)"\0\0", 2);

    printf("== Base64 STRICT rejections (must not be silently corrected) ==\n");
    expect_b64_reject("abc",      "b64 len not multiple of 4");
    expect_b64_reject("ab!d",     "b64 invalid char '!'");
    expect_b64_reject("ab\ncd",   "b64 embedded newline");
    expect_b64_reject("ab-d",     "b64 URL-safe '-'");
    expect_b64_reject("ab_d",     "b64 URL-safe '_'");
    expect_b64_reject("ab=cdefg", "b64 '=' in interior + bad len");
    expect_b64_reject("A===",     "b64 too much padding");
    expect_b64_reject("=AAA",     "b64 '=' at start");
    expect_b64_reject("AB==",     "b64 non-canonical final-quantum bits");
    expect_b64_reject("Zm9=Yg==", "b64 '=' mid-string");

    printf("== Hex encode (lowercase) ==\n");
    {
        const uint8_t v[] = { 0x00, 0xFF, 0x12, 0xAB };
        mesh_buf_t out; mesh_buf_init(&out);
        mesh_bytes_t b = { v, sizeof(v) };
        mesh_result_t rc = mesh_hex_encode(b, &out);
        int ok = rc == MESH_OK && out.len == 8 && memcmp(out.data, "00ff12ab", 8) == 0;
        CHECK(ok, "hex encode lowercase");
        mesh_buf_free(&out);
    }

    printf("== Hex decode (both cases accepted) ==\n");
    {
        mesh_buf_t out; mesh_buf_init(&out);
        mesh_result_t rc = mesh_hex_decode("00FF12ab", &out);
        const uint8_t want[] = { 0x00, 0xFF, 0x12, 0xAB };
        int ok = rc == MESH_OK && out.len == 4 && memcmp(out.data, want, 4) == 0;
        CHECK(ok, "hex decode mixed case");
        mesh_buf_free(&out);
    }

    printf("== Hex STRICT rejections ==\n");
    expect_hex_reject("",     "hex empty rejected");
    expect_hex_reject("abc",  "hex odd length");
    expect_hex_reject("abcg", "hex non-hex char 'g'");
    expect_hex_reject("ab cd","hex embedded space");
    expect_hex_reject("ab:cd","hex separator ':'");

    printf("== Round-trips (0..64 bytes, incl. wire sizes) ==\n");
    {
        uint8_t buf[64];
        for (size_t i = 0; i < sizeof(buf); i++) buf[i] = (uint8_t)(i * 7 + 1);
        for (size_t len = 0; len <= sizeof(buf); len++) {
            roundtrip_b64(buf, len);
            /* Empty hex is NOT a valid round-trip: encode("")="" but hex decode
             * rejects the empty string (WIRE_FORMAT.md:104, matches Java
             * PeerId.fromHex). Base64 differs — empty decodes to zero bytes. */
            if (len > 0) roundtrip_hex(buf, len);
        }
    }
    /* 16-byte nonce and a 71-byte-ish signature are the real handshake sizes. */
    {
        uint8_t nonce[16], sig[71];
        for (size_t i = 0; i < sizeof(nonce); i++) nonce[i] = (uint8_t)(i * 11 + 3);
        for (size_t i = 0; i < sizeof(sig); i++)   sig[i]   = (uint8_t)(i * 5 + 9);
        roundtrip_b64(nonce, sizeof(nonce));
        roundtrip_b64(sig,   sizeof(sig));
        roundtrip_hex(nonce, sizeof(nonce));
    }

    printf("\n=== %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
