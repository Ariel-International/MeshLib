package com.mesh.test;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.method.ScrollingMovementMethod;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import com.mesh.MeshConfig;
import com.mesh.MeshLink;
import com.mesh.MeshLog;
import com.mesh.MeshLogger;
import com.mesh.MeshNode;
import com.mesh.MeshPort;
import com.mesh.MeshRouter;
import com.mesh.MeshServer;
import com.mesh.MeshSession;
import com.mesh.PeerId;
import com.mesh.PeerIdentity;

import org.json.JSONObject;

import java.io.File;
import java.net.InetAddress;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * On-device harness for meshlib.jar.
 *
 * Run as SERVER on BV9500 (hotspot host), CLIENT on BISON (connected to hotspot).
 * Both devices must be on the same Wi-Fi network.
 *
 * Tests run through:
 *   L0  PeerIdentity sign/verify
 *   L1  TCP probe (client connects to server)
 *   L2  MeshLink handshake
 *   L3  MeshRouter delivery
 *   L4  MeshSession join
 *   L5  MeshLog chat round-trip
 */
public class MainActivity extends Activity {

    private static final int PORT    = MeshPort.DEFAULT;
    private static final String SID  = "test-session";
    private static final int TIMEOUT = 10;

    private TextView  mLog;
    private ScrollView mScroll;
    private final Handler mUi = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(32, 48, 32, 32);
        root.setBackgroundColor(0xFF0D0D0D);

        TextView title = new TextView(this);
        title.setText("MeshLib On-Device Test");
        title.setTextSize(18);
        title.setTextColor(0xFFFFFFFF);
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        // IP input for client mode
        EditText etIp = new EditText(this);
        etIp.setHint("Server IP (client mode only)");
        etIp.setTextColor(0xFFFFFFFF);
        etIp.setHintTextColor(0xFF666666);
        etIp.setBackgroundColor(0xFF1A1A1A);
        etIp.setPadding(16, 16, 16, 16);
        LinearLayout.LayoutParams ipParams = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        ipParams.setMargins(0, 24, 0, 8);
        root.addView(etIp, ipParams);

        // Buttons
        LinearLayout btnRow = new LinearLayout(this);
        btnRow.setOrientation(LinearLayout.HORIZONTAL);

        Button btnServer = new Button(this);
        btnServer.setText("▶ SERVER");
        btnServer.setBackgroundColor(0xFF1E5C3A);
        btnServer.setTextColor(0xFFFFFFFF);
        LinearLayout.LayoutParams bp = new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        bp.setMargins(0, 0, 8, 0);
        btnRow.addView(btnServer, bp);

        Button btnClient = new Button(this);
        btnClient.setText("▶ CLIENT");
        btnClient.setBackgroundColor(0xFF1A3D5C);
        btnClient.setTextColor(0xFFFFFFFF);
        LinearLayout.LayoutParams bp2 = new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        btnRow.addView(btnClient, bp2);

        LinearLayout.LayoutParams rowParams = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        rowParams.setMargins(0, 0, 0, 16);
        root.addView(btnRow, rowParams);

        // Log output
        mScroll = new ScrollView(this);
        mLog = new TextView(this);
        mLog.setTextColor(0xFFCCCCCC);
        mLog.setTextSize(12);
        mLog.setTypeface(android.graphics.Typeface.MONOSPACE);
        mLog.setMovementMethod(new ScrollingMovementMethod());
        mLog.setPadding(8, 8, 8, 8);
        mScroll.addView(mLog);
        LinearLayout.LayoutParams scrollParams = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f);
        root.addView(mScroll, scrollParams);

        setContentView(root);

        btnServer.setOnClickListener(v -> {
            btnServer.setEnabled(false);
            btnClient.setEnabled(false);
            mLog.setText("");
            new Thread(() -> runServer(), "mesh-test-server").start();
        });

        btnClient.setOnClickListener(v -> {
            String ip = etIp.getText().toString().trim();
            if (ip.isEmpty()) { log("⚠ Enter server IP first"); return; }
            btnServer.setEnabled(false);
            btnClient.setEnabled(false);
            mLog.setText("");
            new Thread(() -> runClient(ip), "mesh-test-client").start();
        });

        // Show local IP on screen
        new Thread(() -> {
            String ip = MeshServer.mLanInterfaceIp();
            log("Local IP: " + (ip != null ? ip : "unknown"));
            log("Port: " + PORT);
            log("");
            log("Run SERVER on one device, CLIENT on the other.");
            log("Enter server's IP in the field before pressing CLIENT.");
        }).start();
    }

    // -------------------------------------------------------------------------
    // Server mode
    // -------------------------------------------------------------------------

    private void runServer() {
        log("\n=== SERVER MODE ===");

        // L0 — identity
        PeerIdentity identity = step("L0 PeerIdentity", () -> {
            File dir = getFilesDir();
            PeerIdentity id = new PeerIdentity(dir);
            byte[] sig = id.sign("nonce".getBytes());
            if (!PeerIdentity.verify(id.getPeerId(), "nonce".getBytes(), sig))
                throw new Exception("sign/verify failed");
            return id;
        });
        if (identity == null) return;

        log("PeerId: " + identity.getPeerId().toHex().substring(0, 24) + "…");

        // L3 router
        MeshRouter router = new MeshRouter(identity.getPeerId(), new MeshRouter.Listener() {
            @Override public void onDelivered(PeerId from, JSONObject payload) {
                String layer = payload.optString("layer");
                log("L3 delivered layer=" + layer + " from=" + from);
            }
            @Override public void onTopologyChanged() { log("L3 topology changed"); }
        });
        router.setLogger(meshLogger());
        router.start();

        // L4 session
        MeshSession session = new MeshSession(identity.getPeerId(), router, new MeshSession.Listener() {
            @Override public void onSessionUpdated(String id, String name, Map<String, String> m) {
                log("L4 session updated: " + name + " members=" + m.size());
            }
            @Override public void onSessionGone(String id) { log("L4 session gone: " + id); }
            @Override public void onPresence(String id, String hex, String nick, boolean online) {
                log("L4 presence: " + nick + (online ? " online" : " offline"));
            }
        });
        session.setNickname("Server");

        // L5 log
        CountDownLatch gotMsg = new CountDownLatch(1);
        AtomicReference<String> recv = new AtomicReference<>();
        MeshLog meshLog = new MeshLog(identity.getPeerId(), router,
                (sid, fromHex, nick, text, ts) -> {
                    log("L5 received from " + nick + ": " + text);
                    recv.set(text);
                    gotMsg.countDown();
                });

        // L2 server
        MeshConfig cfg = new MeshConfig.Builder().port(PORT).bindIp("0.0.0.0").build();
        MeshServer server = new MeshServer(identity, new MeshLink.Listener() {
            @Override public void onReady(MeshLink link, PeerId remote) {
                log("L2 link ready — peer: " + remote);
                router.onLinkReady(link, remote);
                session.create(SID, "Test Room", true);
                meshLog.sendSyncSummary(SID, link);
            }
            @Override public void onMessage(MeshLink link, JSONObject json) {
                router.onLinkMessage(link, json);
            }
            @Override public void onClosed(MeshLink link, String reason) {
                PeerId r = link.getRemotePeerId();
                if (r != null) router.onLinkClosed(link, r);
                log("L2 link closed: " + reason);
            }
        }, cfg);
        server.setLogger(meshLogger());
        server.start();
        log("L2 server listening on port " + PORT);
        log("Waiting for client to connect…");

        // Wait for a message from client (up to 60s)
        try {
            if (gotMsg.await(60, TimeUnit.SECONDS)) {
                // Send reply
                meshLog.send(SID, "Server", "Hello back, Client!");
                log("\n✅ L5 round-trip PASS — received: \"" + recv.get() + "\"");
            } else {
                log("\n❌ TIMEOUT — no message received from client in 60s");
            }
        } catch (InterruptedException e) {
            log("Interrupted");
        }

        server.stop();
        router.stop();
        log("\nServer done.");
    }

    // -------------------------------------------------------------------------
    // Client mode
    // -------------------------------------------------------------------------

    private void runClient(String serverIp) {
        log("\n=== CLIENT MODE ===");
        log("Connecting to " + serverIp + ":" + PORT);

        // L0 — identity
        PeerIdentity identity = step("L0 PeerIdentity", () -> {
            File dir = getFilesDir();
            PeerIdentity id = new PeerIdentity(dir);
            byte[] sig = id.sign("nonce".getBytes());
            if (!PeerIdentity.verify(id.getPeerId(), "nonce".getBytes(), sig))
                throw new Exception("sign/verify failed");
            return id;
        });
        if (identity == null) return;
        log("PeerId: " + identity.getPeerId().toHex().substring(0, 24) + "…");

        // L3 router
        MeshRouter router = new MeshRouter(identity.getPeerId(), new MeshRouter.Listener() {
            @Override public void onDelivered(PeerId from, JSONObject payload) {
                String layer = payload.optString("layer");
                log("L3 delivered layer=" + layer);
            }
            @Override public void onTopologyChanged() { log("L3 topology changed"); }
        });
        router.setLogger(meshLogger());
        router.start();

        // L4 session
        MeshSession session = new MeshSession(identity.getPeerId(), router, new MeshSession.Listener() {
            @Override public void onSessionUpdated(String id, String name, Map<String, String> m) {
                log("L4 session: " + name + " members=" + m.size());
            }
            @Override public void onSessionGone(String id) {}
            @Override public void onPresence(String id, String hex, String nick, boolean online) {
                log("L4 presence: " + nick + (online ? " online" : " offline"));
            }
        });
        session.setNickname("Client");

        // L5 log
        CountDownLatch gotReply = new CountDownLatch(1);
        AtomicReference<String> recv = new AtomicReference<>();
        MeshLog meshLog = new MeshLog(identity.getPeerId(), router,
                (sid, fromHex, nick, text, ts) -> {
                    if (!"Client".equals(nick)) {
                        log("L5 reply from " + nick + ": " + text);
                        recv.set(text);
                        gotReply.countDown();
                    }
                });

        // L2 — direct TCP connect
        CountDownLatch linked = new CountDownLatch(1);
        MeshConfig cfg = new MeshConfig.Builder().port(PORT).build();

        com.mesh.MeshClient client = new com.mesh.MeshClient(cfg, new com.mesh.MeshClient.Listener() {
            @Override public void onPeerFound(InetAddress a, boolean gw) {}
            @Override public void onScanComplete() {}
        });

        client.connect(mResolve(serverIp), identity, new MeshLink.Listener() {
            @Override public void onReady(MeshLink link, PeerId remote) {
                log("L2 handshake OK — server peer: " + remote);
                router.onLinkReady(link, remote);
                linked.countDown();
                session.join(SID);
                meshLog.send(SID, "Client", "Hello from Client!");
                log("L5 sent: \"Hello from Client!\"");
            }
            @Override public void onMessage(MeshLink link, JSONObject json) {
                router.onLinkMessage(link, json);
            }
            @Override public void onClosed(MeshLink link, String reason) {
                if (link != null) {
                    PeerId r = link.getRemotePeerId();
                    if (r != null) router.onLinkClosed(link, r);
                }
                log("L2 link closed: " + reason);
                linked.countDown();
            }
        });

        try {
            if (!linked.await(TIMEOUT, TimeUnit.SECONDS)) {
                log("❌ L2 TIMEOUT — could not connect to " + serverIp + ":" + PORT);
                router.stop();
                return;
            }

            if (gotReply.await(TIMEOUT, TimeUnit.SECONDS)) {
                log("\n✅ FULL ROUND-TRIP PASS");
                log("  Sent:     \"Hello from Client!\"");
                log("  Received: \"" + recv.get() + "\"");
            } else {
                log("\n❌ L5 TIMEOUT — no reply from server");
            }
        } catch (InterruptedException e) {
            log("Interrupted");
        }

        router.stop();
        log("\nClient done.");
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private <T> T step(String name, ThrowingSupplier<T> fn) {
        try {
            T result = fn.get();
            log("✅ " + name);
            return result;
        } catch (Exception e) {
            log("❌ " + name + ": " + e.getMessage());
            return null;
        }
    }

    private InetAddress mResolve(String ip) {
        try { return InetAddress.getByName(ip); }
        catch (Exception e) { throw new RuntimeException(e); }
    }

    private MeshLogger meshLogger() {
        return new MeshLogger() {
            @Override public void d(String tag, String msg) { log("[" + tag + "] " + msg); }
            @Override public void w(String tag, String msg) { log("[" + tag + "] ⚠ " + msg); }
            @Override public void e(String tag, String msg) { log("[" + tag + "] ✗ " + msg); }
        };
    }

    private void log(String msg) {
        mUi.post(() -> {
            mLog.append(msg + "\n");
            mScroll.post(() -> mScroll.fullScroll(View.FOCUS_DOWN));
        });
    }

    @FunctionalInterface
    interface ThrowingSupplier<T> {
        T get() throws Exception;
    }
}
