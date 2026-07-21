package com.mesh;

/**
 * Minimal RFC 4648 Base64 encoder/decoder — works on Java 6+ and Android API 1+.
 * Exists because java.util.Base64 requires API 26 (Android 8.0).
 *
 * <p><strong>Decoding is strict.</strong> {@link #decode} rejects malformed input
 * with {@link IllegalArgumentException} rather than silently skipping bad
 * characters or truncating output. This is deliberate: Base64 fields cross the
 * wire on the security-critical handshake path ({@code nonce}, {@code signature}),
 * where a lenient decoder turns corrupt or hostile input into silently-wrong
 * bytes that only surface later as an opaque signature-verify failure.
 *
 * <p>Rejected inputs: any character outside the standard alphabet (including
 * whitespace, newlines, and URL-safe {@code -}/{@code _}), lengths that are not
 * a multiple of 4, {@code =} anywhere but the final quantum, more than two
 * padding characters, and non-zero discarded bits in the final quantum
 * (non-canonical encodings).
 */
public final class MeshBase64 {

    private static final char[] ENCODE_TABLE =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();

    /** Alphabet values only; {@code '='} is deliberately NOT a data value. */
    private static final int[] DECODE_TABLE = new int[128];
    static {
        for (int i = 0; i < DECODE_TABLE.length; i++) DECODE_TABLE[i] = -1;
        for (int i = 0; i < ENCODE_TABLE.length; i++) DECODE_TABLE[ENCODE_TABLE[i]] = i;
    }

    private MeshBase64() {}

    public static String encode(byte[] data) {
        if (data == null || data.length == 0) return "";
        StringBuilder sb = new StringBuilder(((data.length + 2) / 3) * 4);
        int i = 0;
        while (i < data.length - 2) {
            int b0 = data[i++] & 0xFF, b1 = data[i++] & 0xFF, b2 = data[i++] & 0xFF;
            sb.append(ENCODE_TABLE[b0 >> 2]);
            sb.append(ENCODE_TABLE[((b0 & 3) << 4) | (b1 >> 4)]);
            sb.append(ENCODE_TABLE[((b1 & 0xF) << 2) | (b2 >> 6)]);
            sb.append(ENCODE_TABLE[b2 & 0x3F]);
        }
        int remaining = data.length - i;
        if (remaining == 1) {
            int b0 = data[i] & 0xFF;
            sb.append(ENCODE_TABLE[b0 >> 2]);
            sb.append(ENCODE_TABLE[(b0 & 3) << 4]);
            sb.append("==");
        } else if (remaining == 2) {
            int b0 = data[i] & 0xFF, b1 = data[i + 1] & 0xFF;
            sb.append(ENCODE_TABLE[b0 >> 2]);
            sb.append(ENCODE_TABLE[((b0 & 3) << 4) | (b1 >> 4)]);
            sb.append(ENCODE_TABLE[(b1 & 0xF) << 2]);
            sb.append('=');
        }
        return sb.toString();
    }

    /**
     * Decodes standard RFC 4648 Base64. Strict: see class javadoc for the exact
     * set of rejected inputs.
     *
     * @param s encoded text; null or empty decodes to a zero-length array
     * @return the decoded bytes
     * @throws IllegalArgumentException if {@code s} is not canonical Base64
     */
    public static byte[] decode(String s) {
        if (s == null || s.isEmpty()) return new byte[0];

        int len = s.length();
        if ((len & 3) != 0)
            throw new IllegalArgumentException("Base64 length not a multiple of 4: " + len);

        int padding = 0;
        if (s.charAt(len - 1) == '=') {
            padding = s.charAt(len - 2) == '=' ? 2 : 1;
        }

        int outLen = (len / 4) * 3 - padding;
        byte[] out = new byte[outLen];
        int outIdx = 0;
        int buf = 0, bits = 0;

        // Everything before the final quantum must be pure alphabet — no padding.
        int dataChars = len - padding;
        for (int i = 0; i < dataChars; i++) {
            char c = s.charAt(i);
            if (c >= DECODE_TABLE.length || DECODE_TABLE[c] == -1)
                throw new IllegalArgumentException(
                        "Invalid Base64 character '" + c + "' at index " + i);
            buf = (buf << 6) | DECODE_TABLE[c];
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out[outIdx++] = (byte) ((buf >> bits) & 0xFF);
            }
        }

        // Reject non-canonical encodings: leftover bits must be zero.
        if (bits > 0 && (buf & ((1 << bits) - 1)) != 0)
            throw new IllegalArgumentException("Non-canonical Base64: non-zero padding bits");

        return out;
    }
}
