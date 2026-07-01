package com.mesh;

import org.json.JSONObject;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * L2 Channel — one TCP socket per direct peer.
 *
 * <p>Owns the handshake (nonce/signature identity verification), periodic
 * heartbeat, and the framed read loop. L3 ({@link MeshRouter}) sits on top
 * and never touches the socket directly.
 *
 * <h3>Handshake protocol</h3>
 * <ol>
 *   <li>Both sides send {@code {type:"hello", peerId:"<hex>", nonce:"<b64>", appId:"<str>"}}.
 *   <li>Each side signs the <em>other's</em> nonce with its private key and sends
 *       {@code {type:"proof", signature:"<b64>"}}.
 *   <li>Each side verifies the received signature against the claimed PeerId.
 * </ol>
 * The link is handed to {@link Listener#onReady} only after signature
 * verification succeeds. If {@code appId} is configured on both ends and they
 * differ, the handshake is rejected before signature exchange.
 */
public class MeshLink {

    /** Callbacks fired on background threads — do not block them. */
    public interface Listener {
        /** Handshake complete and signature verified — link is usable. */
        void onReady(MeshLink link, PeerId remotePeerId);
        /** Application frame received (heartbeats are consumed silently). */
        void onMessage(MeshLink link, JSONObject json);
        /** Link closed — heartbeat timeout, socket error, or explicit {@link #close()}. */
        void onClosed(MeshLink link, String reason);
    }

    private static final int  HEARTBEAT_INTERVAL_MS = 5_000;
    private static final int  DEAD_LINK_TIMEOUT_MS  = 30_000;
    private static final long HANDSHAKE_TIMEOUT_MS  = 5_000;

    private final Socket       mSocket;
    private final PeerIdentity mSelfIdentity;
    private final Listener     mListener;
    private final boolean      mIsInitiator;
    private final String       mAppId; // null = wildcard
    private MeshLogger         mLog = MeshLogger.DEFAULT;

    private DataInputStream  mIn;
    private DataOutputStream mOut;
    private PeerId mRemotePeerId;

    private final AtomicBoolean mClosed    = new AtomicBoolean(false);
    private final Object        mWriteLock = new Object();

    private volatile long mLastReceivedAt = 0;
    private Thread        mHeartbeatThread;

    /**
     * @param socket       connected (or accepted) TCP socket
     * @param selfIdentity this node's keypair
     * @param isInitiator  true if we dialled out; false if we accepted inbound
     * @param appId        application identifier sent in hello; null = no filter
     * @param listener     lifecycle callbacks
     */
    public MeshLink(Socket socket, PeerIdentity selfIdentity, boolean isInitiator,
                    String appId, Listener listener) {
        mSocket       = socket;
        mSelfIdentity = selfIdentity;
        mIsInitiator  = isInitiator;
        mAppId        = appId;
        mListener     = listener;
    }

    public void setLogger(MeshLogger log) { mLog = log; }

    /**
     * Runs the handshake, then the read loop — blocks until the link dies.
     * Call from a dedicated background thread.
     */
    public void start() {
        try {
            mSocket.setSoTimeout((int) HANDSHAKE_TIMEOUT_MS);
            mIn  = new DataInputStream(mSocket.getInputStream());
            mOut = new DataOutputStream(mSocket.getOutputStream());

            if (!mHandshake()) { mFail("Handshake failed"); return; }

            mSocket.setSoTimeout(0);
            mLastReceivedAt = System.currentTimeMillis();
            mListener.onReady(this, mRemotePeerId);

            mHeartbeatThread = new Thread(this::mHeartbeatLoop, "mesh-link-hb");
            mHeartbeatThread.start();

            mReadLoop();
        } catch (Exception e) {
            mFail("start() error: " + e.getMessage());
        }
    }

    private boolean mHandshake() throws Exception {
        byte[] nonceBytes = new byte[16];
        new SecureRandom().nextBytes(nonceBytes);
        String ourNonce = Base64.getEncoder().encodeToString(nonceBytes);

        JSONObject hello = new JSONObject();
        hello.put("type",   "hello");
        hello.put("peerId", mSelfIdentity.getPeerId().toHex());
        hello.put("nonce",  ourNonce);
        if (mAppId != null) hello.put("appId", mAppId);
        MeshFrame.write(mOut, hello);

        JSONObject theirHello = MeshFrame.read(mIn);
        if (!"hello".equals(theirHello.optString("type"))) return false;

        // appId filter — reject if both sides declare an appId and they differ
        String theirAppId = theirHello.optString("appId", null);
        if (mAppId != null && theirAppId != null && !mAppId.equals(theirAppId)) {
            mLog.w("MESH", "L2 handshake: appId mismatch — ours=" + mAppId + " theirs=" + theirAppId);
            return false;
        }

        PeerId claimedPeer = PeerId.fromHex(theirHello.getString("peerId"));
        String theirNonce  = theirHello.getString("nonce");

        byte[] sig = mSelfIdentity.sign(theirNonce.getBytes("UTF-8"));
        if (sig == null) { mLog.e("MESH", "L2 handshake: sign() returned null"); return false; }

        JSONObject proof = new JSONObject();
        proof.put("type",      "proof");
        proof.put("signature", Base64.getEncoder().encodeToString(sig));
        MeshFrame.write(mOut, proof);

        JSONObject theirProof = MeshFrame.read(mIn);
        if (!"proof".equals(theirProof.optString("type"))) return false;
        byte[] theirSig = Base64.getDecoder().decode(theirProof.getString("signature"));

        if (!PeerIdentity.verify(claimedPeer, ourNonce.getBytes("UTF-8"), theirSig)) {
            mLog.e("MESH", "L2 handshake: signature verify failed for " + claimedPeer);
            return false;
        }
        mRemotePeerId = claimedPeer;
        return true;
    }

    private void mReadLoop() {
        try {
            while (!mClosed.get()) {
                JSONObject json = MeshFrame.read(mIn);
                mLastReceivedAt = System.currentTimeMillis();
                if ("heartbeat".equals(json.optString("type"))) continue;
                mListener.onMessage(this, json);
            }
        } catch (Exception e) {
            mFail("Read loop ended: " + e.getMessage());
        }
    }

    private void mHeartbeatLoop() {
        try {
            while (!mClosed.get()) {
                Thread.sleep(HEARTBEAT_INTERVAL_MS);
                if (mClosed.get()) return;
                long since = System.currentTimeMillis() - mLastReceivedAt;
                if (since > DEAD_LINK_TIMEOUT_MS) {
                    mFail("Dead link — no data for " + since + "ms"); return;
                }
                try {
                    JSONObject hb = new JSONObject();
                    hb.put("type", "heartbeat");
                    send(hb);
                    mLog.d("MESH", "Heartbeat → " + (mRemotePeerId != null ? mRemotePeerId : "?"));
                } catch (Exception e) {
                    mFail("Heartbeat send failed: " + e.getMessage()); return;
                }
            }
        } catch (InterruptedException ignored) {}
    }

    /**
     * Sends a JSON frame. Thread-safe; may be called from any thread.
     *
     * @throws IllegalStateException if the link is already closed
     */
    public void send(JSONObject json) throws Exception {
        if (mClosed.get()) throw new IllegalStateException("Link closed");
        synchronized (mWriteLock) { MeshFrame.write(mOut, json); }
    }

    /** The verified remote peer identity, available after {@link Listener#onReady}. */
    public PeerId  getRemotePeerId() { return mRemotePeerId; }
    /** True if this link was dialled out (we connected to the remote). */
    public boolean isInitiator()     { return mIsInitiator; }
    /** True after the link has been closed for any reason. */
    public boolean isClosed()        { return mClosed.get(); }
    /** Closes the link and fires {@link Listener#onClosed}. Idempotent. */
    public void    close()           { mFail("Closed by caller"); }

    private void mFail(String reason) {
        if (!mClosed.compareAndSet(false, true)) return;
        try { mSocket.close(); } catch (Exception ignored) {}
        if (mHeartbeatThread != null) mHeartbeatThread.interrupt();
        mLog.d("MESH", "Link to " + (mRemotePeerId != null ? mRemotePeerId : "?") + " closed: " + reason);
        mListener.onClosed(this, reason);
    }
}
