package com.mesh;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;

/**
 * L1/L2 client side — runs {@link MeshFinder} on a periodic loop and
 * initiates outbound connections to discovered peers.
 *
 * <p>On Android the caller should subclass and override {@link #bindSocket}
 * to bind the socket to the Wi-Fi network object before connecting, ensuring
 * Android routes the connection through the LAN interface rather than mobile
 * data.
 *
 * <pre>
 * // Android subclass example:
 * new MeshClient(config, listener) {
 *     {@literal @}Override protected void bindSocket(Socket s) throws Exception {
 *         Network wifi = getWifiNetwork(context);
 *         if (wifi != null) wifi.bindSocket(s);
 *     }
 * };
 * </pre>
 */
public class MeshClient {

    /**
     * Callbacks fired when the finder reports results.
     * Called on finder pool threads — do not block.
     */
    public interface Listener {
        /**
         * A host at {@code address} responded on the mesh port.
         * The caller should call {@link MeshClient#connect} to establish the link.
         */
        void onPeerFound(InetAddress address, boolean isGateway);

        /** One full scan cycle completed. */
        void onScanComplete();
    }

    private final MeshConfig mConfig;
    private final Listener   mListener;
    private MeshLogger       mLog = MeshLogger.DEFAULT;

    private MeshFinder       mFinder;
    private Thread           mScanThread;
    private volatile boolean mRunning = false;

    public MeshClient(MeshConfig config, Listener listener) {
        mConfig   = config;
        mListener = listener;
    }

    public void setLogger(MeshLogger log) { mLog = log; }

    /** Starts the scan loop on a background thread. Idempotent. */
    public void start() {
        if (mRunning) return;
        mRunning = true;
        mScanThread = new Thread(this::mScanLoop, "mesh-l1-scan");
        mScanThread.start();
    }

    /** Interrupts the current sleep and triggers an immediate rescan. */
    public void rescan() {
        if (!mRunning) return;
        if (mFinder != null) mFinder.cancel();
        if (mScanThread != null) mScanThread.interrupt();
    }

    /** Stops the scan loop. */
    public void stop() {
        mRunning = false;
        if (mFinder != null) mFinder.cancel();
        mFinder = null;
        if (mScanThread != null) mScanThread.interrupt();
        mScanThread = null;
    }

    private void mScanLoop() {
        while (mRunning) {
            mFinder = new MeshFinder(mConfig);
            mFinder.setLogger(mLog);
            mFinder.start(new MeshFinder.Listener() {
                @Override public void onPeerFound(InetAddress address, boolean isGateway) {
                    if (mRunning) mListener.onPeerFound(address, isGateway);
                }
                @Override public void onScanComplete() {
                    if (mRunning) mListener.onScanComplete();
                }
            });
            if (!mRunning) break;
            try { Thread.sleep(mConfig.rescanIntervalMs); } catch (InterruptedException ignored) {}
        }
    }

    /**
     * Opens a TCP socket to a discovered peer and runs the L2 handshake.
     * Fires {@link MeshLink.Listener} callbacks when the link is ready or fails.
     * The link's read loop blocks the spawned thread until the link dies.
     *
     * @param address      peer's IP address
     * @param selfIdentity this node's keypair
     * @param listener     link lifecycle callbacks
     */
    public void connect(InetAddress address, PeerIdentity selfIdentity,
                        MeshLink.Listener listener) {
        new Thread(() -> {
            try {
                Socket socket = new Socket();
                bindSocket(socket);
                socket.connect(new InetSocketAddress(address, mConfig.port),
                        mConfig.gatewayTimeoutMs);
                MeshLink link = new MeshLink(socket, selfIdentity, true, mConfig.appId, listener);
                link.setLogger(mLog);
                link.start();
            } catch (Exception e) {
                mLog.e("NET", "L2 connect to " + address.getHostAddress() + " failed: " + e.getMessage());
                try { listener.onClosed(null, e.getMessage()); } catch (Exception ignored) {}
            }
        }, "mesh-l2-connect-" + address.getHostAddress()).start();
    }

    /**
     * Called before {@link Socket#connect} on every outbound socket.
     * Override on Android to bind to the Wi-Fi {@code Network} object.
     * Default implementation does nothing.
     */
    protected void bindSocket(Socket socket) throws Exception {}
}
