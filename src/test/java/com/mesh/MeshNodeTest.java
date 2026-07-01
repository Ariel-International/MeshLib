package com.mesh;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import org.json.JSONObject;

import java.io.File;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * In-process two-node integration tests over loopback.
 *
 * Node A = server (MeshServer on 0.0.0.0 so loopback connects work).
 * Node B = direct connect to 127.0.0.1 — no subnet scan.
 *
 * Verifies: L0 identity, L2 handshake, L3 topology, L4 session, L5 chat delivery.
 */
class MeshNodeTest {

    @TempDir File tmpA;
    @TempDir File tmpB;
    @TempDir File tmpC;

    private static final MeshConfig TEST_CFG = new MeshConfig.Builder()
            .port(MeshPort.DEFAULT)
            .bindIp("0.0.0.0")
            .build();

    // -------------------------------------------------------------------------
    // Identity tests
    // -------------------------------------------------------------------------

    @Test @Timeout(5)
    void peerIdentitySignVerify() {
        PeerIdentity id = new PeerIdentity(tmpA);
        byte[] payload = "test-nonce-12345".getBytes();
        byte[] sig = id.sign(payload);
        assertNotNull(sig, "sign() should not return null");
        assertTrue(PeerIdentity.verify(id.getPeerId(), payload, sig), "verify() should pass");

        PeerIdentity id2 = new PeerIdentity(tmpB);
        assertFalse(PeerIdentity.verify(id2.getPeerId(), payload, sig),
                "sig from id1 should not verify against id2's pubkey");
    }

    @Test @Timeout(5)
    void identityPersistsAcrossLoad() {
        PeerIdentity id1 = new PeerIdentity(tmpA);
        PeerIdentity id2 = new PeerIdentity(tmpA);
        assertEquals(id1.getPeerId(), id2.getPeerId(), "PeerId should be stable across reload");
    }

    @Test @Timeout(5)
    void transientIdentityNoPersistence() {
        // null storageDir = in-memory only, must not throw
        PeerIdentity id = new PeerIdentity((java.io.File) null);
        assertNotNull(id.getPeerId());
        byte[] sig = id.sign("data".getBytes());
        assertNotNull(sig);
        assertTrue(PeerIdentity.verify(id.getPeerId(), "data".getBytes(), sig));
    }

    // -------------------------------------------------------------------------
    // Config tests
    // -------------------------------------------------------------------------

    @Test @Timeout(5)
    void meshConfigDefaults() {
        MeshConfig cfg = MeshConfig.defaults();
        assertEquals(MeshPort.DEFAULT, cfg.port);
        assertNull(cfg.appId);
        assertNull(cfg.bindIp);
        assertEquals(MeshConfig.DEFAULT_RESCAN_MS, cfg.rescanIntervalMs);
    }

    @Test @Timeout(5)
    void meshConfigBuilder() {
        MeshConfig cfg = new MeshConfig.Builder()
                .port(MeshPort.WALLET)
                .appId("sovrana-wallet-v1")
                .bindIp("0.0.0.0")
                .rescanIntervalMs(60_000)
                .build();
        assertEquals(MeshPort.WALLET, cfg.port);
        assertEquals("sovrana-wallet-v1", cfg.appId);
        assertEquals("0.0.0.0", cfg.bindIp);
        assertEquals(60_000, cfg.rescanIntervalMs);
    }

    // -------------------------------------------------------------------------
    // appId filter test
    // -------------------------------------------------------------------------

    @Test @Timeout(10)
    void appIdMismatchRejectsHandshake() throws Exception {
        MeshConfig cfgA = new MeshConfig.Builder()
                .port(MeshPort.DEFAULT).bindIp("0.0.0.0").appId("app-A").build();
        MeshConfig cfgB = new MeshConfig.Builder()
                .port(MeshPort.DEFAULT).appId("app-B").build();

        PeerIdentity idA = new PeerIdentity(tmpA);
        PeerIdentity idB = new PeerIdentity(tmpB);

        CountDownLatch rejected = new CountDownLatch(1);

        MeshLink.Listener serverListener = new MeshLink.Listener() {
            @Override public void onReady(MeshLink link, PeerId remote) {
                fail("Should not reach onReady — appId mismatch should reject");
            }
            @Override public void onMessage(MeshLink link, JSONObject json) {}
            @Override public void onClosed(MeshLink link, String reason) { rejected.countDown(); }
        };

        MeshServer server = new MeshServer(idA, serverListener, cfgA);
        server.setLogger(MeshLogger.STDOUT);
        server.start();
        waitForPort(MeshPort.DEFAULT, 3000);

        MeshClient client = new MeshClient(cfgB, new MeshClient.Listener() {
            @Override public void onPeerFound(InetAddress a, boolean gw) {}
            @Override public void onScanComplete() {}
        });
        client.connect(InetAddress.getByName("127.0.0.1"), idB, new MeshLink.Listener() {
            @Override public void onReady(MeshLink link, PeerId remote) {
                fail("Should not reach onReady");
            }
            @Override public void onMessage(MeshLink link, JSONObject json) {}
            @Override public void onClosed(MeshLink link, String reason) { rejected.countDown(); }
        });

        assertTrue(rejected.await(5, TimeUnit.SECONDS),
                "Handshake with mismatched appId should be rejected");
        server.stop();
    }

    // -------------------------------------------------------------------------
    // Two-node chat round-trip
    // -------------------------------------------------------------------------

    @Test @Timeout(15)
    void twoNodeChatRoundTrip() throws Exception {
        MeshNode nodeA = new MeshNode(tmpA, "Alice", TEST_CFG);
        MeshNode nodeB = new MeshNode(tmpB, "Bob",   TEST_CFG);
        nodeA.setLogger(MeshLogger.STDOUT);
        nodeB.setLogger(MeshLogger.STDOUT);

        CountDownLatch aGotMsg = new CountDownLatch(1);
        CountDownLatch bGotMsg = new CountDownLatch(1);
        AtomicReference<String> aRecv = new AtomicReference<>();
        AtomicReference<String> bRecv = new AtomicReference<>();

        nodeA.setChatListener(new MeshNode.ChatListener() {
            @Override public void onMessage(String sid, String nick, String text, long ts) {
                if ("Bob".equals(nick)) { aRecv.set(nick + ": " + text); aGotMsg.countDown(); }
            }
            @Override public void onPeerConnected(String h) {}
            @Override public void onPeerDisconnected(String h) {}
            @Override public void onSessionUpdated(String id, String name, Map<String, String> m) {}
        });
        nodeB.setChatListener(new MeshNode.ChatListener() {
            @Override public void onMessage(String sid, String nick, String text, long ts) {
                if ("Alice".equals(nick)) { bRecv.set(nick + ": " + text); bGotMsg.countDown(); }
            }
            @Override public void onPeerConnected(String h) {}
            @Override public void onPeerDisconnected(String h) {}
            @Override public void onSessionUpdated(String id, String name, Map<String, String> m) {}
        });

        // Start A's server and router (no client scan — loopback)
        nodeA.mRouter.start();
        nodeA.mServer.start();
        waitForPort(MeshPort.DEFAULT, 3000);

        nodeA.createSession("chat", "Chat Room", true);

        // B's router + direct connect
        nodeB.mRouter.start();
        CountDownLatch bLinked = new CountDownLatch(1);
        MeshLink.Listener bLinkListener = new MeshLink.Listener() {
            @Override public void onReady(MeshLink link, PeerId remote) {
                nodeB.mRouter.onLinkReady(link, remote);
                bLinked.countDown();
                nodeB.mSession.join("chat");
                nodeB.sendMessage("chat", "Bob", "Hello Alice!");
            }
            @Override public void onMessage(MeshLink link, JSONObject json) {
                nodeB.mRouter.onLinkMessage(link, json);
            }
            @Override public void onClosed(MeshLink link, String reason) {
                if (link == null) return;
                PeerId r = link.getRemotePeerId();
                if (r != null) nodeB.mRouter.onLinkClosed(link, r);
            }
        };

        MeshClient clientB = new MeshClient(TEST_CFG, new MeshClient.Listener() {
            @Override public void onPeerFound(InetAddress a, boolean gw) {}
            @Override public void onScanComplete() {}
        });
        clientB.connect(InetAddress.getByName("127.0.0.1"), nodeB.mIdentity, bLinkListener);

        assertTrue(bLinked.await(5, TimeUnit.SECONDS), "B should complete L2 handshake");

        nodeA.sendMessage("chat", "Alice", "Hello Bob!");

        assertTrue(aGotMsg.await(5, TimeUnit.SECONDS), "A should receive Bob's message");
        assertTrue(bGotMsg.await(5, TimeUnit.SECONDS), "B should receive Alice's message");

        assertTrue(aRecv.get().contains("Hello Alice!"), "A received: " + aRecv.get());
        assertTrue(bRecv.get().contains("Hello Bob!"),   "B received: " + bRecv.get());

        assertFalse(nodeA.getMessages("chat").isEmpty(), "A's log should not be empty");
        assertFalse(nodeB.getMessages("chat").isEmpty(), "B's log should not be empty");

        nodeA.mServer.stop();
        nodeA.mRouter.stop();
        nodeB.mRouter.stop();
    }

    // -------------------------------------------------------------------------
    // Port constants
    // -------------------------------------------------------------------------

    @Test @Timeout(1)
    void portConstantsAreUnique() {
        int[] all = MeshPort.ALL;
        for (int i = 0; i < all.length; i++)
            for (int j = i + 1; j < all.length; j++)
                assertNotEquals(all[i], all[j],
                        "Duplicate port value: " + all[i] + " at indices " + i + " and " + j);
    }

    @Test @Timeout(1)
    void portConstantsInRange() {
        for (int p : MeshPort.ALL) {
            assertTrue(p >= 47820 && p <= 47829,
                    "Port " + p + " is outside the 47820-47829 range");
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static void waitForPort(int port, long timeoutMs) throws Exception {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress("127.0.0.1", port), 100);
                return;
            } catch (Exception e) {
                Thread.sleep(100);
            }
        }
        throw new Exception("Port " + port + " did not open within " + timeoutMs + "ms");
    }
}
