package com.mesh;

import java.util.Arrays;
import java.util.HexFormat;

/**
 * A peer's identity token: the X.509-encoded public key of an EC P-256 keypair.
 * Equality and hash are by value.
 */
public final class PeerId {

    private final byte[] mBytes;

    public PeerId(byte[] encoded) {
        mBytes = Arrays.copyOf(encoded, encoded.length);
    }

    public byte[] toBytes() { return Arrays.copyOf(mBytes, mBytes.length); }

    public String toHex() {
        return HexFormat.of().formatHex(mBytes);
    }

    public static PeerId fromHex(String hex) {
        return new PeerId(HexFormat.of().parseHex(hex));
    }

    @Override public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof PeerId)) return false;
        return Arrays.equals(mBytes, ((PeerId) o).mBytes);
    }

    @Override public int hashCode() { return Arrays.hashCode(mBytes); }

    @Override public String toString() {
        String h = toHex();
        return h.length() > 16 ? h.substring(0, 16) + "…" : h;
    }
}
