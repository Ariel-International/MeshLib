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

    /** Reconstructs a PeerId from its hex representation. */
    public static PeerId fromHex(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
            data[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        return new PeerId(data);
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
