package com.mesh;

/**
 * Well-known port numbers for MeshLib networks.
 *
 * <p>A MeshLib deployment picks one port from this list (or any other
 * unregistered port). All nodes in the same network must agree on the port.
 * Different applications can run independent MeshLib networks simultaneously
 * by using different ports.
 *
 * <p><b>Recommended ports for different use cases:</b>
 *
 * <pre>
 * Port   Name              Use case
 * ─────  ────────────────  ──────────────────────────────────────────────────
 * 47820  MESH_GENERAL      General-purpose mesh / default when no other fits
 * 47821  MESH_CHAT         Chat applications (this library's default)
 * 47822  MESH_WALLET       Wallet / payment traffic (Sovrana)
 * 47823  MESH_MONITOR      LAN monitoring, device presence, router health
 * 47824  MESH_SYNC         File / data sync between trusted peers
 * 47825  MESH_IOT          IoT sensor data, embedded devices
 * 47826  MESH_RELAY        Relay / bridge nodes that forward to other networks
 * 47827  MESH_ADMIN        Admin / management plane (separate from data plane)
 * 47828  MESH_MEDIA        Audio/video metadata signalling
 * 47829  MESH_CUSTOM       Application-defined; use with an appId filter
 * </pre>
 *
 * <p>All ports in the range 47820–47829 are unregistered with IANA as of
 * 2024. They are above the ephemeral range on most OS defaults (32768–60999
 * on Linux) and do not collide with common services. The range is narrow
 * enough that a full-range probe adds only 9 extra TCP connects per host
 * during discovery.
 *
 * <p>If you need to co-host multiple MeshLib applications on the same device,
 * assign each one a distinct port from this list. If you need further
 * isolation within a single port (e.g. wallet vs chat traffic on port 47821),
 * use the {@code appId} field in {@link MeshConfig} — the handshake will
 * reject connections from nodes with a different appId.
 *
 * <p>For traffic isolation within a single connected mesh (e.g. routing wallet
 * frames separately from chat frames without running two networks), use
 * {@link MeshSession} IDs and the {@code layer} field in the frame protocol.
 * No separate port is needed.
 */
public final class MeshPort {

    /** Default port — used when no port is specified in {@link MeshConfig}. */
    public static final int DEFAULT   = 47821;

    public static final int GENERAL   = 47820;
    public static final int CHAT      = 47821;
    public static final int WALLET    = 47822;
    public static final int MONITOR   = 47823;
    public static final int SYNC      = 47824;
    public static final int IOT       = 47825;
    public static final int RELAY     = 47826;
    public static final int ADMIN     = 47827;
    public static final int MEDIA     = 47828;
    public static final int CUSTOM    = 47829;

    /** The full range — pass to {@link MeshFinder} to probe all known mesh ports. */
    public static final int[] ALL = { GENERAL, CHAT, WALLET, MONITOR, SYNC, IOT, RELAY, ADMIN, MEDIA, CUSTOM };

    private MeshPort() {}
}
