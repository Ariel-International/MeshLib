package com.mesh;

import java.util.Arrays;

/**
 * A peer's stable identity token — the X.509 DER-encoded public key of its
 * P-256 EC keypair.
 *
 * <p>A PeerId is generated once by {@link PeerIdentity} and never changes for
 * the lifetime of a node's key material. It is the only addressing primitive
 * in the mesh: routing, session membership, and message deduplication all key
 * on PeerId hex strings.
 *
 * <p>Equality and hashing are by value (byte-by-byte comparison of the
 * encoded key). {@link #toString()} returns a truncated hex string for log
 * readability; use {@link #toHex()} for the full value.
 */
public final class PeerId {

    private final byte[] mBytes;

    /** Constructs a PeerId from a raw X.509 DER-encoded EC public key. */
    public PeerId(byte[] encoded) {
        mBytes = Arrays.copyOf(encoded, encoded.length);
    }

    /** Returns the raw X.509 DER-encoded bytes (defensive copy). */
    public byte[] toBytes() { return Arrays.copyOf(mBytes, mBytes.length); }

    /** Returns the full hex-encoded PeerId string. */
    public String toHex() {
        StringBuilder sb = new StringBuilder(mBytes.length * 2);
        for (byte b : mBytes) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }

    /**
     * Reconstructs a PeerId from its hex representation.
     *
     * <p>Strict: input must be non-null, non-empty, of even length, and contain
     * only {@code [0-9a-fA-F]}. Malformed input is rejected with
     * {@link IllegalArgumentException} rather than propagating a
     * {@code StringIndexOutOfBoundsException} or {@code NumberFormatException}
     * from the parse internals. PeerId hex arrives straight off the wire in the
     * L2 {@code hello} frame, so this is untrusted input.
     *
     * @throws IllegalArgumentException if {@code hex} is not valid hex
     */
    public static PeerId fromHex(String hex) {
        if (hex == null || hex.isEmpty())
            throw new IllegalArgumentException("PeerId hex is null or empty");

        int len = hex.length();
        if ((len & 1) != 0)
            throw new IllegalArgumentException("PeerId hex has odd length: " + len);

        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            int hi = mHexVal(hex.charAt(i), i);
            int lo = mHexVal(hex.charAt(i + 1), i + 1);
            data[i / 2] = (byte) ((hi << 4) | lo);
        }
        return new PeerId(data);
    }

    private static int mHexVal(char c, int idx) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        throw new IllegalArgumentException(
                "Invalid hex character '" + c + "' at index " + idx);
    }

    @Override public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof PeerId)) return false;
        return Arrays.equals(mBytes, ((PeerId) o).mBytes);
    }

    @Override public int hashCode() { return Arrays.hashCode(mBytes); }

    /** Returns the first 16 hex chars followed by "…" for compact log output. */
    @Override public String toString() {
        String h = toHex();
        return h.length() > 16 ? h.substring(0, 16) + "…" : h;
    }
}
