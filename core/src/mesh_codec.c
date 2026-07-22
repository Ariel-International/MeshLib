/*
 * mesh_codec.c — strict Base64 and hex codecs.
 *
 * Faithful C port of the Java MeshBase64 + PeerId hex logic (commit 4cc1e64).
 * The strict-reject rules are normative in ../../WIRE_FORMAT.md:47-121; the
 * behaviour here is intended to be byte-for-byte identical to the Java side,
 * including which malformed inputs are rejected rather than repaired.
 */
#include "mesh_codec.h"

#include <string.h>

/* Standard RFC 4648 alphabet. Index = 6-bit value (0..63). Left unsized so the
 * literal's NUL terminator is included without a too-small-array warning; only
 * indices 0..63 are ever read. */
static const char B64_ENCODE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
 * Reverse table: ASCII char -> 6-bit value, or -1 if not in the alphabet.
 * '=' is deliberately NOT a data value (mirrors the Java DECODE_TABLE, which
 * dropped the '=' => 0 entry during hardening).
 */
static int b64_val(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* ---- Base64 ------------------------------------------------------------- */

size_t mesh_base64_encoded_len(size_t n) {
    if (n == 0) return 0;
    return ((n + 2) / 3) * 4;
}

mesh_result_t mesh_base64_encode(mesh_bytes_t in, mesh_buf_t *out) {
    if (!out) return MESH_ERR_INVALID_ARG;
    if (in.len > 0 && !in.data) return MESH_ERR_INVALID_ARG;

    size_t outlen = mesh_base64_encoded_len(in.len);
    if (outlen == 0) return MESH_OK; /* empty input -> empty output */

    mesh_result_t rc = mesh_buf_reserve(out, outlen);
    if (rc != MESH_OK) return rc;

    const uint8_t *d = in.data;
    uint8_t *o = out->data + out->len;
    size_t i = 0;

    /* Full 3-byte groups -> 4 chars. */
    while (i + 3 <= in.len) {
        unsigned b0 = d[i], b1 = d[i + 1], b2 = d[i + 2];
        *o++ = (uint8_t)B64_ENCODE[b0 >> 2];
        *o++ = (uint8_t)B64_ENCODE[((b0 & 0x03) << 4) | (b1 >> 4)];
        *o++ = (uint8_t)B64_ENCODE[((b1 & 0x0F) << 2) | (b2 >> 6)];
        *o++ = (uint8_t)B64_ENCODE[b2 & 0x3F];
        i += 3;
    }

    size_t rem = in.len - i;
    if (rem == 1) {
        unsigned b0 = d[i];
        *o++ = (uint8_t)B64_ENCODE[b0 >> 2];
        *o++ = (uint8_t)B64_ENCODE[(b0 & 0x03) << 4];
        *o++ = '=';
        *o++ = '=';
    } else if (rem == 2) {
        unsigned b0 = d[i], b1 = d[i + 1];
        *o++ = (uint8_t)B64_ENCODE[b0 >> 2];
        *o++ = (uint8_t)B64_ENCODE[((b0 & 0x03) << 4) | (b1 >> 4)];
        *o++ = (uint8_t)B64_ENCODE[(b1 & 0x0F) << 2];
        *o++ = '=';
    }

    out->len += outlen;
    return MESH_OK;
}

mesh_result_t mesh_base64_decode(const char *s, mesh_buf_t *out) {
    if (!out) return MESH_ERR_INVALID_ARG;
    if (!s || s[0] == '\0') return MESH_OK; /* null/empty -> zero bytes */

    size_t len = strlen(s);
    if ((len & 3u) != 0) return MESH_ERR_MALFORMED; /* not a multiple of 4 */

    /* Padding is only recognised at the very end. */
    int padding = 0;
    if (s[len - 1] == '=') {
        padding = (s[len - 2] == '=') ? 2 : 1;
    }

    size_t out_len = (len / 4) * 3 - (size_t)padding;
    if (out_len > 0) {
        mesh_result_t rc = mesh_buf_reserve(out, out_len);
        if (rc != MESH_OK) return rc;
    }

    uint8_t *o = out->data ? out->data + out->len : NULL;
    size_t produced = 0;
    unsigned buf = 0;
    int bits = 0;

    /* Everything before the final quantum must be pure alphabet — any '='
     * here (or in the interior) is caught because b64_val('=') == -1. */
    size_t data_chars = len - (size_t)padding;
    for (size_t i = 0; i < data_chars; i++) {
        int v = b64_val((unsigned char)s[i]);
        if (v < 0) return MESH_ERR_MALFORMED;
        buf = (buf << 6) | (unsigned)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            o[produced++] = (uint8_t)((buf >> bits) & 0xFF);
        }
    }

    /* Reject non-canonical encodings: leftover bits must be zero (e.g. "AB=="
     * has non-zero discarded bits and is rejected). */
    if (bits > 0 && (buf & ((1u << bits) - 1u)) != 0)
        return MESH_ERR_MALFORMED;

    out->len += produced;
    return MESH_OK;
}

/* ---- Hex ---------------------------------------------------------------- */

static const char HEX_LOWER[] = "0123456789abcdef"; /* indices 0..15 read */

/* char -> nibble value, or -1 if not [0-9a-fA-F]. */
static int hex_val(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

mesh_result_t mesh_hex_encode(mesh_bytes_t in, mesh_buf_t *out) {
    if (!out) return MESH_ERR_INVALID_ARG;
    if (in.len > 0 && !in.data) return MESH_ERR_INVALID_ARG;
    if (in.len == 0) return MESH_OK;

    if (in.len > ((size_t)-1) / 2) return MESH_ERR_TOO_LARGE;
    size_t outlen = in.len * 2;

    mesh_result_t rc = mesh_buf_reserve(out, outlen);
    if (rc != MESH_OK) return rc;

    uint8_t *o = out->data + out->len;
    for (size_t i = 0; i < in.len; i++) {
        o[2 * i]     = (uint8_t)HEX_LOWER[in.data[i] >> 4];
        o[2 * i + 1] = (uint8_t)HEX_LOWER[in.data[i] & 0x0F];
    }
    out->len += outlen;
    return MESH_OK;
}

mesh_result_t mesh_hex_decode(const char *s, mesh_buf_t *out) {
    if (!out) return MESH_ERR_INVALID_ARG;
    if (!s || s[0] == '\0') return MESH_ERR_MALFORMED; /* null/empty rejected */

    size_t len = strlen(s);
    if ((len & 1u) != 0) return MESH_ERR_MALFORMED; /* odd length */

    size_t out_len = len / 2;
    mesh_result_t rc = mesh_buf_reserve(out, out_len);
    if (rc != MESH_OK) return rc;

    uint8_t *o = out->data + out->len;
    for (size_t i = 0; i < len; i += 2) {
        int hi = hex_val((unsigned char)s[i]);
        int lo = hex_val((unsigned char)s[i + 1]);
        if (hi < 0 || lo < 0) return MESH_ERR_MALFORMED;
        o[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    out->len += out_len;
    return MESH_OK;
}
