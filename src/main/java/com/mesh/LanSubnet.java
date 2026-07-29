package com.mesh;

/**
 * An IPv4 LAN interface address together with its real network prefix length.
 *
 * <p>Discovery used to assume every interface was a {@code /24} and sweep
 * {@code x.y.z.1-254}. That silently fails on a wider network: on a
 * {@code /16}, two peers at {@code 172.16.4.9} and {@code 172.16.7.22} are
 * mutually reachable but never probe each other, and the scan completes with
 * an empty list and no error. Carrying the mask lets {@link MeshFinder}
 * compute the true host range and report when it is too large to sweep.
 *
 * <p>Prefix length comes from {@link java.net.InterfaceAddress#getNetworkPrefixLength()}
 * (API 9 — safe on the API 23 floor).
 */
public final class LanSubnet {

    /** Interface IPv4 address, dotted-quad. */
    public final String ip;
    /** Network prefix length in bits, 0–32. */
    public final int    prefixLen;
    /** True for hotspot interfaces (ap*, swlan*), which sort first. */
    public final boolean isHotspot;

    public LanSubnet(String ip, int prefixLen, boolean isHotspot) {
        this.ip        = ip;
        this.prefixLen = prefixLen;
        this.isHotspot = isHotspot;
    }

    /** Number of probeable hosts in this subnet (excludes network + broadcast). */
    public long hostCount() {
        if (prefixLen >= 31) return 0;          // /31 and /32 have no host range
        return (1L << (32 - prefixLen)) - 2;
    }

    /** This address as a 32-bit unsigned value packed into a long. */
    public long ipAsLong() { return mParse(ip); }

    /** Lowest host address in the subnet (network address + 1). */
    public long networkBase() {
        long mask = mMask(prefixLen);
        return ipAsLong() & mask;
    }

    /** True if {@code other} lies inside this subnet. */
    public boolean contains(String other) {
        long mask = mMask(prefixLen);
        return (mParse(other) & mask) == networkBase();
    }

    /** Dotted-quad rendering of a packed address. */
    public static String toIp(long v) {
        return ((v >> 24) & 0xFF) + "." + ((v >> 16) & 0xFF)
                + "." + ((v >> 8) & 0xFF) + "." + (v & 0xFF);
    }

    private static long mMask(int prefixLen) {
        if (prefixLen <= 0)  return 0L;
        if (prefixLen >= 32) return 0xFFFFFFFFL;
        return (0xFFFFFFFFL << (32 - prefixLen)) & 0xFFFFFFFFL;
    }

    private static long mParse(String ip) {
        String[] p = ip.split("\\.");
        if (p.length != 4) return 0L;
        long v = 0;
        for (String s : p) v = (v << 8) | (Long.parseLong(s) & 0xFF);
        return v;
    }

    @Override public String toString() {
        return ip + "/" + prefixLen + (isHotspot ? " (hotspot)" : "");
    }
}
