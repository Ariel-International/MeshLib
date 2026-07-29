package com.mesh;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * L2 listening side — accepts inbound TCP connections.
 *
 * <p>Binds one {@link ServerSocket} per eligible LAN interface so the node
 * is reachable on every subnet it participates in (e.g. both the hotspot
 * {@code ap0} interface and a upstream {@code wlan0} at the same time).
 * This makes a multi-homed device a natural mesh bridge.
 *
 * <p>Each interface runs its own accept loop on a daemon thread. All accepted
 * connections feed the same {@link MeshLink.Listener}, so the router above
 * sees a single stream of peer events regardless of which interface they
 * arrived on.
 *
 * <p>If {@link MeshConfig#bindIp} is set, only that address is bound
 * (single-interface override, useful for tests).
 *
 * <p>The restart loop per interface handles transient bind failures
 * (interface not yet up, hotspot bounce, etc.) with a 2-second back-off.
 */
public class MeshServer {

    private final PeerIdentity      mSelfIdentity;
    private final MeshLink.Listener mListener;
    private final MeshConfig        mConfig;
    private MeshLogger              mLog = MeshLogger.DEFAULT;

    private volatile boolean                  mRunning = false;
    private final CopyOnWriteArrayList<ServerSocket> mSockets = new CopyOnWriteArrayList<>();
    private final List<Thread>                mThreads = new ArrayList<>();

    public MeshServer(PeerIdentity selfIdentity, MeshLink.Listener listener) {
        this(selfIdentity, listener, MeshConfig.defaults());
    }

    public MeshServer(PeerIdentity selfIdentity, MeshLink.Listener listener, MeshConfig config) {
        mSelfIdentity = selfIdentity;
        mListener     = listener;
        mConfig       = config;
    }

    public void setLogger(MeshLogger log) { mLog = log; }

    /** Starts accept loops on all eligible interfaces. Idempotent. */
    public void start() {
        if (mRunning) return;
        mRunning = true;

        if (mConfig.bindIp != null) {
            // Single-interface override
            mStartAcceptor(mConfig.bindIp);
        } else {
            List<String> ips = mLanInterfaceIps();
            if (ips.isEmpty()) {
                // No LAN interface yet — start one loop on 0.0.0.0 as fallback
                mStartAcceptor("0.0.0.0");
            } else {
                for (String ip : ips) mStartAcceptor(ip);
            }
        }
    }

    /** Stops all accept loops and closes all server sockets. */
    public void stop() {
        mRunning = false;
        for (ServerSocket ss : mSockets) {
            try { ss.close(); } catch (Exception ignored) {}
        }
        mSockets.clear();
        mThreads.clear();
    }

    public boolean isRunning() { return mRunning; }

    private void mStartAcceptor(String bindIp) {
        Thread t = new Thread(() -> mAcceptLoop(bindIp), "mesh-l2-accept-" + bindIp);
        t.setDaemon(true);
        mThreads.add(t);
        t.start();
    }

    private void mAcceptLoop(String bindIp) {
        while (mRunning) {
            ServerSocket ss = null;
            try {
                InetAddress addr = InetAddress.getByName(bindIp);
                ss = new ServerSocket();
                ss.setReuseAddress(true);
                ss.bind(new InetSocketAddress(addr, mConfig.port));
                mSockets.add(ss);
                mLog.d("MESH", "L2 listening on " + bindIp + ":" + mConfig.port);

                while (mRunning) {
                    Socket socket = ss.accept();
                    mHandleInbound(socket);
                }
            } catch (Exception e) {
                if (ss != null) {
                    mSockets.remove(ss);
                    try { ss.close(); } catch (Exception ignored) {}
                }
                if (mRunning) {
                    mLog.w("MESH", "L2 accept loop [" + bindIp + "] restarting: " + e.getMessage());
                    try { Thread.sleep(2000); } catch (InterruptedException ignored) {}
                }
            }
        }
    }

    private void mHandleInbound(Socket socket) {
        MeshLink link = new MeshLink(socket, mSelfIdentity, false, mConfig.appId, mListener);
        link.setLogger(mLog);
        new Thread(link::start, "mesh-link-inbound").start();
    }

    /**
     * Returns the first IPv4 address of the best available LAN interface.
     * Prefers hotspot (ap/swlan) then wlan/eth over other interfaces.
     * Used by the test harness and gateway prefill to display the local IP.
     */
    public static String mLanInterfaceIp() {
        List<String> ips = mLanInterfaceIps();
        return ips.isEmpty() ? null : ips.get(0);
    }

    /**
     * Returns IPv4 addresses for all eligible LAN interfaces, hotspot
     * interfaces first, then wlan/eth, then anything else non-loopback.
     */
    public static List<String> mLanInterfaceIps() {
        List<String> result = new ArrayList<>();
        for (LanSubnet s : mLanSubnets()) result.add(s.ip);
        return result;
    }

    /**
     * Returns all eligible LAN interfaces with their real network prefix
     * length, hotspot interfaces first, then wlan/eth.
     *
     * <p>Discovery needs the mask, not just the address: assuming {@code /24}
     * makes {@link MeshFinder} skip peers that are reachable but outside the
     * assumed range (e.g. two hosts in different third octets of a {@code /16}).
     * Reads the prefix from {@link java.net.InterfaceAddress} (API 9).
     */
    public static List<LanSubnet> mLanSubnets() {
        List<LanSubnet> hotspot = new ArrayList<>();
        List<LanSubnet> wlan    = new ArrayList<>();
        try {
            Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();
            while (ifaces.hasMoreElements()) {
                NetworkInterface iface = ifaces.nextElement();
                if (iface.isLoopback() || !iface.isUp()) continue;
                String name = iface.getName();
                // Whitelist: only known LAN/WiFi/hotspot interface prefixes
                boolean isHotspot = name.startsWith("ap") || name.startsWith("swlan");
                boolean isLan     = name.startsWith("wlan") || name.startsWith("eth")
                        || name.startsWith("lan") || name.startsWith("usb")
                        || name.startsWith("rndis") || name.startsWith("br");
                if (!isHotspot && !isLan) continue;
                for (java.net.InterfaceAddress ia : iface.getInterfaceAddresses()) {
                    InetAddress addr = ia.getAddress();
                    if (!(addr instanceof Inet4Address) || addr.isLoopbackAddress()) continue;
                    int prefix = ia.getNetworkPrefixLength();
                    // Some Android builds report 0 or a nonsense prefix; fall
                    // back to /24 rather than treating the whole space as local.
                    if (prefix <= 0 || prefix > 32) prefix = 24;
                    LanSubnet sub = new LanSubnet(addr.getHostAddress(), prefix, isHotspot);
                    if (isHotspot) hotspot.add(sub);
                    else           wlan.add(sub);
                }
            }
        } catch (Exception ignored) {}

        List<LanSubnet> result = new ArrayList<>();
        result.addAll(hotspot);
        result.addAll(wlan);
        return result;
    }
}
