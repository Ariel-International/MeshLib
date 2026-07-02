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
 * L1 Discovery — scans the local /24 subnet for responsive hosts.
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
     * Probes the gateway and then sweeps the /24 on the configured port.
     * Blocks until complete — call from a background thread.
     */
    public void start(Listener listener) {
        mCancelled = false;

        String localIp   = mLanInterfaceIp();
        String gatewayIp = mRouteGateway();

        if (gatewayIp == null && localIp != null) {
            int dot = localIp.lastIndexOf('.');
            gatewayIp = localIp.substring(0, dot + 1) + "1";
            mLog.d("NET", "L1 fallback: local=" + localIp + " gw=" + gatewayIp);
        } else if (gatewayIp != null) {
            mLog.d("NET", "L1 route: local=" + localIp + " gw=" + gatewayIp);
        }

        if (gatewayIp == null) {
            mLog.d("NET", "L1 scan: no suitable interface found");
            listener.onScanComplete();
            return;
        }

        final String subnet = gatewayIp.substring(0, gatewayIp.lastIndexOf('.') + 1);
        final String gwIp   = gatewayIp;
        final String selfIp = localIp;

        ExecutorService pool = Executors.newFixedThreadPool(SWEEP_THREADS);
        try {
            if (mProbe(gwIp, mConfig.port, mConfig.gatewayTimeoutMs))
                listener.onPeerFound(InetAddress.getByName(gwIp), true);
            if (mCancelled) return;

            List<Future<?>> futures = new ArrayList<>();
            for (int host = 1; host < 255; host++) {
                final String ip = subnet + host;
                if (ip.equals(gwIp) || ip.equals(selfIp)) continue;
                futures.add(pool.submit(() -> {
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
        } catch (Exception e) {
            mLog.e("MESH", "L1 scan failed: " + e.getMessage());
        } finally {
            pool.shutdownNow();
            try { pool.awaitTermination(1, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}
            listener.onScanComplete();
        }
    }

    // -------------------------------------------------------------------------
    // Multi-port scan (monitoring mode)
    // -------------------------------------------------------------------------

    /**
     * Probes every host in the local /24 against every port in {@code ports}.
     * Reports any host+port combination that accepts a TCP connection,
     * regardless of whether it speaks the MeshLib protocol.
     *
     * <p>Useful for LAN monitoring: discover routers (port 80/443/22),
     * cameras, printers, IoT devices, or any other reachable service.
     * Pass {@link MeshPort#ALL} to scan all known mesh ports.
     *
     * <p>Blocks until complete — call from a background thread.
     *
     * @param ports    ports to probe on each host
     * @param timeout  TCP connect timeout per probe in milliseconds
     * @param listener result callbacks
     */
    public void scanPorts(int[] ports, int timeout, PortScanListener listener) {
        mCancelled = false;

        String localIp = mLanInterfaceIp();
        if (localIp == null) { listener.onScanComplete(); return; }

        String gatewayIp = mRouteGateway();
        if (gatewayIp == null) {
            int dot = localIp.lastIndexOf('.');
            gatewayIp = localIp.substring(0, dot + 1) + "1";
        }
        final String subnet = gatewayIp.substring(0, gatewayIp.lastIndexOf('.') + 1);
        final String selfIp = localIp;

        ExecutorService pool = Executors.newFixedThreadPool(SWEEP_THREADS);
        try {
            List<Future<?>> futures = new ArrayList<>();
            for (int host = 1; host < 255; host++) {
                final String ip = subnet + host;
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
