package com.mesh;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * L1 Discovery — scans the local subnet for responsive hosts.
 *
 * <p>The scan range is derived from each interface's real netmask (see
 * {@link LanSubnet}), not an assumed {@code /24}. Subnets wider than
 * {@link #MAX_SWEEP_PREFIX} are reported as unscannable rather than
 * partially scanned, so a wide network fails loudly instead of returning
 * an empty peer list.
 *
 * <p>Two scan modes:
 * <ol>
 *   <li><b>Mesh scan</b> (default via {@link MeshClient}) — probes a single
 *       configured port. {@link Listener#onPeerFound} fires for each host
 *       that responds; the caller then initiates an L2 handshake to confirm
 *       it is a MeshLib peer.
 *   <li><b>Port scan</b> (via {@link #scanPorts}) — probes an arbitrary list
 *       of ports per host and reports every open port found, whether or not
 *       it belongs to a MeshLib node. Useful for monitoring: routers,
 *       printers, cameras, IoT devices, anything reachable on the LAN.
 * </ol>
 *
 * <h3>Gateway detection order</h3>
 * <ol>
 *   <li>{@code /proc/net/route} default-route entry (Linux / Android).
 *   <li>Subnet {@code .1} fallback (hotspot-host path where there is no
 *       default route to the upstream network).
 * </ol>
 *
 * <p>Interface selection prefers {@code wlan*}, {@code ap*}, {@code swlan*},
 * {@code eth*} — the same priority order as {@link MeshServer}.
 *
 * <p>All probe callbacks fire from pool threads. {@link Listener#onScanComplete}
 * fires on the calling thread after all futures are resolved.
 */
public class MeshFinder {

    /**
     * Callback interface for mesh-mode scans.
     * Callbacks may arrive from multiple threads concurrently.
     */
    public interface Listener {
        /**
         * A host at {@code address} responded on the configured mesh port.
         *
         * @param address   the responding host
         * @param isGateway true if this is the subnet gateway (probed first and
         *                  with a longer timeout than the general sweep)
         */
        void onPeerFound(InetAddress address, boolean isGateway);

        /**
         * A LAN interface was skipped because its subnet is too wide to sweep
         * (prefix narrower than {@link #MAX_SWEEP_PREFIX}). Peers on that
         * interface will not be discovered — surface this to the user rather
         * than showing an empty node list with no explanation.
         *
         * <p>Default is a no-op so existing listeners keep compiling.
         *
         * @param subnet the interface address and its real prefix length
         */
        default void onSubnetTooLarge(LanSubnet subnet) {}

        /** All probe futures have resolved — scan is complete. */
        void onScanComplete();
    }

    /**
     * Callback interface for multi-port scans (monitoring mode).
     * Callbacks may arrive from multiple threads concurrently.
     */
    public interface PortScanListener {
        /**
         * A TCP port responded on a host.
         *
         * @param address the responding host
         * @param port    the port that accepted a connection
         */
        void onPortOpen(InetAddress address, int port);

        /** All probe futures have resolved. */
        void onScanComplete();
    }

    private static final int SWEEP_THREADS = 32;

    /**
     * Narrowest prefix this scanner will sweep: {@code /22} (1022 hosts).
     * Anything wider is reported via {@link Listener#onSubnetTooLarge} instead
     * of scanned — a {@code /16} is 65534 probes, and a {@code /8} is 16.7M.
     */
    public static final int MAX_SWEEP_PREFIX = 22;

    private final MeshConfig mConfig;
    private MeshLogger       mLog       = MeshLogger.DEFAULT;
    private volatile boolean mCancelled = false;

    public MeshFinder(MeshConfig config) { mConfig = config; }

    public void setLogger(MeshLogger log) { mLog = log; }

    /** Cancels an in-progress scan. Safe to call from any thread. */
    public void cancel() { mCancelled = true; }

    // -------------------------------------------------------------------------
    // Mesh scan (single port)
    // -------------------------------------------------------------------------

    /**
     * Probes the gateway and sweeps every eligible LAN interface's real
     * subnet in parallel. All results feed the same listener.
     * Blocks until all subnets are complete — call from a background thread.
     *
     * <p>The host range comes from the interface's actual netmask, not an
     * assumed {@code /24}. Subnets wider than {@link #MAX_SWEEP_PREFIX} have
     * too many hosts to probe in reasonable time; those report
     * {@link Listener#onSubnetTooLarge} and are skipped rather than silently
     * scanning a wrong (assumed-/24) range.
     */
    public void start(Listener listener) {
        mCancelled = false;

        List<LanSubnet> subnets = MeshServer.mLanSubnets();
        if (subnets.isEmpty()) {
            mLog.d("NET", "L1 scan: no suitable interface found");
            listener.onScanComplete();
            return;
        }

        String routeGw = mRouteGateway();
        ExecutorService pool = Executors.newFixedThreadPool(SWEEP_THREADS);
        try {
            List<Future<?>> futures = new ArrayList<>();
            for (LanSubnet sub : subnets) {
                if (sub.prefixLen < MAX_SWEEP_PREFIX) {
                    mLog.w("NET", "L1 scan skipped: " + sub + " has " + sub.hostCount()
                            + " hosts, wider than /" + MAX_SWEEP_PREFIX);
                    listener.onSubnetTooLarge(sub);
                    continue;
                }
                // Gateway: route-table entry if it falls inside this subnet, else base+1
                String gwIp = (routeGw != null && sub.contains(routeGw))
                        ? routeGw : LanSubnet.toIp(sub.networkBase() + 1);
                mLog.d("NET", "L1 scan subnet=" + LanSubnet.toIp(sub.networkBase())
                        + "/" + sub.prefixLen + " hosts=" + sub.hostCount()
                        + " gw=" + gwIp + " local=" + sub.ip);
                final String fGw = gwIp;
                futures.add(pool.submit(() -> mSweepSubnet(sub, fGw, listener)));
            }
            for (Future<?> f : futures) {
                if (mCancelled) break;
                try { f.get(); } catch (Exception ignored) {}
            }
        } finally {
            pool.shutdownNow();
            try { pool.awaitTermination(1, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}
            listener.onScanComplete();
        }
    }

    private void mSweepSubnet(LanSubnet sub, String gwIp, Listener listener) {
        // Probe gateway first with longer timeout
        if (!mCancelled) {
            try {
                if (mProbe(gwIp, mConfig.port, mConfig.gatewayTimeoutMs))
                    listener.onPeerFound(InetAddress.getByName(gwIp), true);
            } catch (Exception ignored) {}
        }

        // Sweep the real host range in parallel using a dedicated pool
        // — submit sub-tasks inline so we don't nest pools
        long base  = sub.networkBase();
        long count = sub.hostCount();
        ExecutorService sweep = Executors.newFixedThreadPool(SWEEP_THREADS);
        try {
            List<Future<?>> futures = new ArrayList<>();
            for (long i = 1; i <= count; i++) {
                final String ip = LanSubnet.toIp(base + i);
                if (ip.equals(gwIp) || ip.equals(sub.ip)) continue;
                futures.add(sweep.submit(() -> {
                    if (mCancelled) return;
                    try {
                        if (mProbe(ip, mConfig.port, mConfig.sweepTimeoutMs))
                            listener.onPeerFound(InetAddress.getByName(ip), false);
                    } catch (Exception ignored) {}
                }));
            }
            for (Future<?> f : futures) {
                if (mCancelled) break;
                try { f.get(); } catch (Exception ignored) {}
            }
        } finally {
            sweep.shutdownNow();
            try { sweep.awaitTermination(1, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}
        }
    }

    // -------------------------------------------------------------------------
    // Multi-port scan (monitoring mode)
    // -------------------------------------------------------------------------

    /**
     * Probes every host in the local subnet against every port in {@code ports}.
     * Reports any host+port combination that accepts a TCP connection,
     * regardless of whether it speaks the MeshLib protocol.
     *
     * <p>Useful for LAN monitoring: discover routers (port 80/443/22),
     * cameras, printers, IoT devices, or any other reachable service.
     * Pass {@link MeshPort#ALL} to scan all known mesh ports.
     *
     * <p>Range comes from the interface's real netmask. Returns immediately
     * without scanning if the subnet is wider than {@link #MAX_SWEEP_PREFIX}.
     *
     * <p>Blocks until complete — call from a background thread.
     *
     * @param ports    ports to probe on each host
     * @param timeout  TCP connect timeout per probe in milliseconds
     * @param listener result callbacks
     */
    public void scanPorts(int[] ports, int timeout, PortScanListener listener) {
        mCancelled = false;

        List<LanSubnet> subnets = MeshServer.mLanSubnets();
        if (subnets.isEmpty()) { listener.onScanComplete(); return; }
        LanSubnet sub = subnets.get(0);
        if (sub.prefixLen < MAX_SWEEP_PREFIX) {
            mLog.w("NET", "port scan skipped: " + sub + " too wide");
            listener.onScanComplete();
            return;
        }

        final long base   = sub.networkBase();
        final long count  = sub.hostCount();
        final String selfIp = sub.ip;

        ExecutorService pool = Executors.newFixedThreadPool(SWEEP_THREADS);
        try {
            List<Future<?>> futures = new ArrayList<>();
            for (long h = 1; h <= count; h++) {
                final String ip = LanSubnet.toIp(base + h);
                if (ip.equals(selfIp)) continue;
                for (int port : ports) {
                    final int p = port;
                    futures.add(pool.submit(() -> {
                        if (mCancelled) return;
                        try {
                            if (mProbe(ip, p, timeout))
                                listener.onPortOpen(InetAddress.getByName(ip), p);
                        } catch (Exception ignored) {}
                    }));
                }
            }
            for (Future<?> f : futures) {
                if (mCancelled) break;
                try { f.get(); } catch (Exception ignored) {}
            }
        } finally {
            pool.shutdownNow();
            try { pool.awaitTermination(1, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}
            listener.onScanComplete();
        }
    }

    // -------------------------------------------------------------------------
    // Internal
    // -------------------------------------------------------------------------

    /**
     * Returns the IPv4 address of the best LAN interface.
     * Delegates to {@link MeshServer#mLanInterfaceIp()} for consistent
     * interface selection (whitelist-only, hotspot preferred).
     */
    static String mLanInterfaceIp() {
        return MeshServer.mLanInterfaceIp();
    }

    /**
     * Reads the Linux kernel routing table from {@code /proc/net/route} and
     * returns the gateway for the default route (destination 00000000).
     * Returns null on Windows/Mac or if no default route is found.
     */
    static String mRouteGateway() {
        try (java.io.BufferedReader br = new java.io.BufferedReader(
                new java.io.FileReader("/proc/net/route"))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] f = line.trim().split("\\s+");
                if (f.length < 4 || !"00000000".equals(f[1]) || "00000000".equals(f[2])) continue;
                long gw = Long.parseLong(f[2], 16);
                return (gw & 0xFF) + "." + ((gw >> 8) & 0xFF)
                        + "." + ((gw >> 16) & 0xFF) + "." + ((gw >> 24) & 0xFF);
            }
        } catch (Exception ignored) {}
        return null;
    }

    private boolean mProbe(String ip, int port, int timeoutMs) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(ip, port), timeoutMs);
            return true;
        } catch (IOException e) { return false; }
    }
}
