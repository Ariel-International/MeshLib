package com.mesh;

/**
 * Immutable configuration for a {@link MeshNode}.
 *
 * <p>Build with the inner {@link Builder}:
 * <pre>
 *   MeshConfig cfg = new MeshConfig.Builder()
 *       .port(MeshPort.WALLET)
 *       .appId("sovrana-wallet-v1")
 *       .rescanIntervalMs(60_000)
 *       .build();
 *   MeshNode node = new MeshNode(storageDir, "Alice", cfg);
 * </pre>
 *
 * <p><b>appId</b> — an arbitrary string embedded in the handshake hello frame.
 * Nodes with different appIds refuse each other's connections. Use this when
 * multiple applications share the same port (e.g. two programs both on
 * {@link MeshPort#CUSTOM}) and must not cross-connect. Leave null (the
 * default) to accept connections from any MeshLib node on the same port,
 * regardless of which application sent them.
 *
 * <p><b>port</b> — the TCP port this node listens on and scans for peers.
 * See {@link MeshPort} for a list of recommended per-use-case ports.
 *
 * <p><b>bindIp</b> — explicit bind address for the server socket. Normally
 * null (auto-detects the LAN interface). Override in tests or when a specific
 * interface must be used.
 */
public final class MeshConfig {

    /** Default rescan period: 30 seconds. */
    public static final long DEFAULT_RESCAN_MS       = 30_000;
    /** Default gateway probe timeout: 1 second. */
    public static final int  DEFAULT_GATEWAY_TIMEOUT = 1_000;
    /** Default per-host sweep timeout: 300 ms. */
    public static final int  DEFAULT_SWEEP_TIMEOUT   = 300;

    public final int    port;
    public final String appId;
    public final String bindIp;
    public final long   rescanIntervalMs;
    public final int    gatewayTimeoutMs;
    public final int    sweepTimeoutMs;

    private MeshConfig(Builder b) {
        port             = b.port;
        appId            = b.appId;
        bindIp           = b.bindIp;
        rescanIntervalMs = b.rescanIntervalMs;
        gatewayTimeoutMs = b.gatewayTimeoutMs;
        sweepTimeoutMs   = b.sweepTimeoutMs;
    }

    /** Returns a default config (port={@link MeshPort#DEFAULT}, no appId filter). */
    public static MeshConfig defaults() { return new Builder().build(); }

    public static final class Builder {
        private int    port             = MeshPort.DEFAULT;
        private String appId            = null;
        private String bindIp           = null;
        private long   rescanIntervalMs = DEFAULT_RESCAN_MS;
        private int    gatewayTimeoutMs = DEFAULT_GATEWAY_TIMEOUT;
        private int    sweepTimeoutMs   = DEFAULT_SWEEP_TIMEOUT;

        /** TCP port to listen on and scan. Default: {@link MeshPort#DEFAULT}. */
        public Builder port(int port)                       { this.port = port; return this; }
        /** appId filter string. Null = accept all. */
        public Builder appId(String appId)                  { this.appId = appId; return this; }
        /** Explicit server bind IP. Null = auto-detect LAN interface. */
        public Builder bindIp(String bindIp)                { this.bindIp = bindIp; return this; }
        /** How often to re-scan for new peers (ms). */
        public Builder rescanIntervalMs(long ms)            { this.rescanIntervalMs = ms; return this; }
        /** TCP connect timeout for the gateway probe (ms). */
        public Builder gatewayTimeoutMs(int ms)             { this.gatewayTimeoutMs = ms; return this; }
        /** TCP connect timeout for each /24 host during sweep (ms). */
        public Builder sweepTimeoutMs(int ms)               { this.sweepTimeoutMs = ms; return this; }

        public MeshConfig build()                           { return new MeshConfig(this); }
    }
}
