package com.mesh;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Enumeration;

/**
 * L2 listening side — accepts inbound TCP connections.
 *
 * <p>Binds to the LAN interface IP (not {@code 0.0.0.0} by default) so the
 * socket is reachable on the correct interface even on a device that also has
 * mobile data active. Uses {@link MeshConfig#bindIp} if set.
 *
 * <p>Runs a restart loop: if the server socket dies (interface IP change,
 * hotspot bounce, etc.), it waits 2 seconds and rebinds. The loop exits only
 * when {@link #stop()} is called.
 *
 * <p>Each accepted connection is handed off to a new {@link MeshLink} on its
 * own thread, which runs the handshake and the read loop.
 */
public class MeshServer {

    private final PeerIdentity      mSelfIdentity;
    private final MeshLink.Listener mListener;
    private final MeshConfig        mConfig;
    private MeshLogger              mLog = MeshLogger.DEFAULT;

    private ServerSocket     mServerSocket;
    private Thread           mAcceptThread;
    private volatile boolean mRunning = false;

    public MeshServer(PeerIdentity selfIdentity, MeshLink.Listener listener) {
        this(selfIdentity, listener, MeshConfig.defaults());
    }

    public MeshServer(PeerIdentity selfIdentity, MeshLink.Listener listener, MeshConfig config) {
        mSelfIdentity = selfIdentity;
        mListener     = listener;
        mConfig       = config;
    }

    public void setLogger(MeshLogger log) { mLog = log; }

    /** Starts the accept loop on a background thread. Idempotent. */
    public void start() {
        if (mRunning) return;
        mRunning = true;
        mAcceptThread = new Thread(this::mAcceptLoop, "mesh-l2-accept");
        mAcceptThread.start();
    }

    /** Stops the accept loop and closes the server socket. */
    public void stop() {
        mRunning = false;
        if (mServerSocket != null) {
            try { mServerSocket.close(); } catch (Exception ignored) {}
        }
        mServerSocket = null;
    }

    public boolean isRunning() { return mRunning; }

    private void mAcceptLoop() {
        while (mRunning) {
            try {
                String localIp = mConfig.bindIp != null ? mConfig.bindIp : mLanInterfaceIp();
                InetAddress bindAddr = localIp != null
                        ? InetAddress.getByName(localIp)
                        : InetAddress.getByName("0.0.0.0");

                mServerSocket = new ServerSocket();
                mServerSocket.setReuseAddress(true);
                mServerSocket.bind(new InetSocketAddress(bindAddr, mConfig.port));
                mLog.d("MESH", "L2 listening on " + bindAddr.getHostAddress() + ":" + mConfig.port);

                while (mRunning) {
                    Socket socket = mServerSocket.accept();
                    mHandleInbound(socket);
                }
            } catch (Exception e) {
                if (mRunning) {
                    mLog.w("MESH", "L2 accept loop restarting: " + e.getMessage());
                    try { if (mServerSocket != null) mServerSocket.close(); } catch (Exception ignored) {}
                    mServerSocket = null;
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
     * Returns the IPv4 address of the best LAN interface.
     * Prefers wlan/ap/swlan/eth interfaces; falls back to any non-loopback IPv4.
     */
    public static String mLanInterfaceIp() {
        try {
            Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();
            String fallback = null;
            while (ifaces.hasMoreElements()) {
                NetworkInterface iface = ifaces.nextElement();
                if (iface.isLoopback() || !iface.isUp()) continue;
                String name = iface.getName();
                Enumeration<InetAddress> addrs = iface.getInetAddresses();
                while (addrs.hasMoreElements()) {
                    InetAddress addr = addrs.nextElement();
                    if (!(addr instanceof Inet4Address) || addr.isLoopbackAddress()) continue;
                    String ip = addr.getHostAddress();
                    if (name.startsWith("wlan") || name.startsWith("ap")
                            || name.startsWith("swlan") || name.startsWith("eth"))
                        return ip;
                    if (fallback == null) fallback = ip;
                }
            }
            return fallback;
        } catch (Exception e) { return null; }
    }
}
