package com.mesh;

import org.json.JSONObject;

import java.io.File;
import java.net.InetAddress;
import java.util.List;
import java.util.Map;

/**
 * Public API facade for the MeshLib stack.
 *
 * <p>Wires together L0 (identity), L1 (discovery), L2 (links), L3 (routing),
 * L4 (sessions), and L5 (message log). Callers interact with this class only.
 *
 * <h3>Minimal usage</h3>
 * <pre>
 * MeshNode node = new MeshNode(storageDir, "Alice");
 * node.setLogger(MeshLogger.STDOUT);
 * node.setChatListener(myListener);
 * node.start();
 * node.createSession("room-1", "Main Room", true);
 * node.sendMessage("room-1", "Alice", "Hello!");
 * // ...
 * node.stop();
 * </pre>
 *
 * <h3>Custom port / appId</h3>
 * <pre>
 * MeshConfig cfg = new MeshConfig.Builder()
 *     .port(MeshPort.WALLET)
 *     .appId("sovrana-wallet-v1")
 *     .build();
 * MeshNode node = new MeshNode(storageDir, "Alice", cfg);
 * </pre>
 *
 * <h3>Traffic isolation within one mesh</h3>
 * <p>Multiple logical channels (e.g. wallet traffic and chat) can coexist on
 * a single MeshNode by using distinct {@link MeshSession} IDs. The session ID
 * and the {@code layer} field in the frame protocol keep traffic separate at
 * L4/L5. No separate port or node is needed for this.
 *
 * <h3>Thread safety</h3>
 * <p>All public methods are safe to call from any thread. Callbacks fire on
 * background threads — do not perform long blocking operations inside them.
 *
 * <h3>Android notes</h3>
 * <p>On Android, subclass {@link MeshClient} and override
 * {@link MeshClient#bindSocket} to bind outbound sockets to the Wi-Fi
 * {@code Network} object. Pass the subclass instance to
 * {@link #MeshNode(File, String, MeshConfig, MeshClient)}.
 */
public class MeshNode {

    /**
     * Application-level event callbacks.
     * All methods are called on background threads.
     */
    public interface ChatListener {
        /**
         * A chat message arrived in a session.
         *
         * @param sessionId   the session it belongs to
         * @param fromNickname the sender's display name
         * @param text        message text
         * @param timestampMs wall-clock send time (ms since epoch)
         */
        void onMessage(String sessionId, String fromNickname, String text, long timestampMs);

        /** A new peer completed the L2 handshake and joined the mesh. */
        void onPeerConnected(String peerIdHex);

        /** A peer's link closed (heartbeat timeout, disconnect, or error). */
        void onPeerDisconnected(String peerIdHex);

        /**
         * A session's membership changed (peer joined, left, or session created).
         *
         * @param members map of peerIdHex → nickname for all current members
         */
        void onSessionUpdated(String sessionId, String name, Map<String, String> members);
    }

    // Package-visible so the test harness can wire things directly
    final PeerIdentity      mIdentity;
    final MeshRouter        mRouter;
    final MeshSession       mSession;
    final MeshLog           mMsgLog;
    final MeshServer        mServer;
    MeshClient              mClient;
    MeshLogger              mLog = MeshLogger.DEFAULT;
    ChatListener            mChatListener;
    final MeshLink.Listener mLinkListener;

    /** Creates a node with default config (port {@link MeshPort#DEFAULT}, no appId filter). */
    public MeshNode(File storageDir, String nickname) {
        this(storageDir, nickname, MeshConfig.defaults(), null);
    }

    /** Creates a node with a custom config. */
    public MeshNode(File storageDir, String nickname, MeshConfig config) {
        this(storageDir, nickname, config, null);
    }

    /**
     * Full constructor — supply a custom {@link MeshClient} (e.g. an Android
     * subclass that binds sockets to a Wi-Fi network). Pass {@code null} to
     * use the default client.
     */
    public MeshNode(File storageDir, String nickname, MeshConfig config, MeshClient customClient) {
        mIdentity = new PeerIdentity(storageDir);

        mRouter = new MeshRouter(mIdentity.getPeerId(), new MeshRouter.Listener() {
            @Override public void onDelivered(PeerId from, JSONObject payload) { mDispatch(from, payload); }
            @Override public void onTopologyChanged() {}
        });

        mSession = new MeshSession(mIdentity.getPeerId(), mRouter, new MeshSession.Listener() {
            @Override public void onSessionUpdated(String id, String name, Map<String, String> m) {
                if (mChatListener != null) mChatListener.onSessionUpdated(id, name, m);
            }
            @Override public void onSessionGone(String id) {}
            @Override public void onPresence(String id, String h, String nick, boolean on) {}
        });
        mSession.setNickname(nickname);

        mMsgLog = new MeshLog(mIdentity.getPeerId(), mRouter, (sid, fromHex, nick, text, ts) -> {
            if (mChatListener != null) mChatListener.onMessage(sid, nick, text, ts);
        });

        mLinkListener = new MeshLink.Listener() {
            @Override public void onReady(MeshLink link, PeerId remote) {
                mRouter.onLinkReady(link, remote);
                if (mChatListener != null) mChatListener.onPeerConnected(remote.toHex());
            }
            @Override public void onMessage(MeshLink link, JSONObject json) {
                mRouter.onLinkMessage(link, json);
            }
            @Override public void onClosed(MeshLink link, String reason) {
                if (link == null) return;
                PeerId remote = link.getRemotePeerId();
                if (remote != null) {
                    mRouter.onLinkClosed(link, remote);
                    if (mChatListener != null) mChatListener.onPeerDisconnected(remote.toHex());
                }
            }
        };

        mServer = new MeshServer(mIdentity, mLinkListener, config);

        if (customClient != null) {
            mClient = customClient;
        } else {
            mClient = new MeshClient(config, new MeshClient.Listener() {
                @Override public void onPeerFound(InetAddress address, boolean isGateway) {
                    mClient.connect(address, mIdentity, mLinkListener);
                }
                @Override public void onScanComplete() {}
            });
        }
    }

    /**
     * Sets the log backend for all internal components.
     * Use {@link MeshLogger#STDOUT} for console output during development.
     */
    public void setLogger(MeshLogger log) {
        mLog = log;
        mIdentity.setLogger(log);
        mRouter.setLogger(log);
        mSession.setLogger(log);
        mMsgLog.setLogger(log);
        mServer.setLogger(log);
        mClient.setLogger(log);
    }

    /** Sets the application-level event listener. */
    public void setChatListener(ChatListener listener) { mChatListener = listener; }

    /**
     * Starts the mesh: L3 router, L2 server socket, and L1 scanner.
     * Returns immediately; all network activity runs on background threads.
     */
    public void start() {
        mRouter.start();
        mServer.start();
        mClient.start();
    }

    /**
     * Stops the mesh: scanner, server, router (in that order).
     * Leaves the active session gracefully before closing.
     */
    public void stop() {
        mClient.stop();
        mServer.stop();
        mRouter.stop();
        mSession.leave();
    }

    /**
     * Creates a new session on this node and floods the announcement to all
     * connected peers. This node becomes the first member.
     *
     * @param sessionId unique slug, e.g. {@code "wallet-abc123"} or {@code "chat-main"}
     * @param name      human-readable display name
     * @param isPublic  whether other nodes should list this session
     */
    public void createSession(String sessionId, String name, boolean isPublic) {
        mSession.create(sessionId, name, isPublic);
    }

    /**
     * Joins an existing session. The session must have been announced by a
     * connected peer (i.e. appear in {@link MeshSession#getSessions()}).
     */
    public void joinSession(String sessionId) { mSession.join(sessionId); }

    /** Leaves the active session and notifies all peers. */
    public void leaveSession() { mSession.leave(); }

    /**
     * Sends a chat message into a session.
     *
     * @param sessionId the target session
     * @param nickname  display name to attach to this message
     * @param text      message text
     */
    public void sendMessage(String sessionId, String nickname, String text) {
        mMsgLog.send(sessionId, nickname, text);
    }

    /**
     * Returns the in-memory message log for a session, sorted by timestamp.
     * Up to 500 messages are retained per session.
     */
    public List<MeshLog.Msg> getMessages(String sessionId) {
        return mMsgLog.getMessages(sessionId);
    }

    /** Returns this node's stable identity token (the public key of its EC keypair). */
    public PeerId getPeerId() { return mIdentity.getPeerId(); }

    /**
     * Triggers an immediate rescan without waiting for the next scheduled
     * interval. Useful after the network interface changes.
     */
    public void rescan() { mClient.rescan(); }

    /** Exposes the session layer for advanced use (e.g. presence announcements). */
    public MeshSession getSession() { return mSession; }

    /** Exposes the finder for general-purpose port scans. */
    public MeshFinder newFinder() { return new MeshFinder(MeshConfig.defaults()); }

    /** Exposes the finder with custom config for general-purpose port scans. */
    public MeshFinder newFinder(MeshConfig config) { return new MeshFinder(config); }

    private void mDispatch(PeerId from, JSONObject payload) {
        String layer = payload.optString("layer");
        switch (layer) {
            case "session": {
                JSONObject inner = payload.optJSONObject("payload");
                if (inner != null) mSession.handle(from, inner);
                break;
            }
            case "message":
                mMsgLog.handle(from, payload);
                break;
            default:
                mLog.w("MESH", "Unknown layer: " + layer);
        }
    }

    // -------------------------------------------------------------------------
    // Standalone entry point
    // -------------------------------------------------------------------------

    /**
     * When run as a standalone jar, prints this node's PeerId and usage info.
     * Run {@code ./gradlew test} to execute the in-process test suite.
     */
    public static void main(String[] args) throws Exception {
        MeshConfig cfg = new MeshConfig.Builder()
                .port(MeshPort.DEFAULT)
                .bindIp("0.0.0.0")
                .build();
        MeshNode node = new MeshNode(null, "PC-Server", cfg);
        node.setLogger(MeshLogger.STDOUT);
        node.start();
        node.createSession("test-session", "Test Room", true);
        System.out.println("MeshLib server running on port " + cfg.port);
        System.out.println("PeerId: " + node.getPeerId().toHex());
        System.out.println("Waiting for connections… (Ctrl+C to stop)");

        // Wire chat: print received messages and auto-reply
        node.setChatListener(new MeshNode.ChatListener() {
            @Override public void onMessage(String sid, String nick, String text, long ts) {
                System.out.println("[" + nick + "] " + text);
                try { node.sendMessage(sid, "PC-Server", "Hello back from PC, " + nick + "!"); }
                catch (Exception ignored) {}
            }
            @Override public void onPeerConnected(String hex) {
                System.out.println("Peer connected: " + hex.substring(0, 16) + "…");
            }
            @Override public void onPeerDisconnected(String hex) {
                System.out.println("Peer disconnected: " + hex.substring(0, 16) + "…");
            }
            @Override public void onSessionUpdated(String id, String name,
                    java.util.Map<String, String> members) {
                System.out.println("Session " + name + ": " + members.size() + " members");
            }
        });

        // Block forever
        Thread.currentThread().join();
    }
}
