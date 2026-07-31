package com.mesh;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import org.json.JSONObject;

import java.io.File;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

/**
 * MeshLog.send()'s "handed off to the mesh" signal (DOCS chat-UI work: ties
 * into the chat bubble's tick). Two honest states only — queued locally, or
 * reached >=1 live link. There is no receiver-side ack anywhere in this
 * stack, so onHandedOff is deliberately the last state MeshLog ever reports;
 * these tests exist to keep that contract from silently growing a third,
 * unearned state later.
 */
class MeshLogHandedOffTest {

    @TempDir File tmpA;
    @TempDir File tmpB;

    private static final MeshConfig TEST_CFG = new MeshConfig.Builder()
            .port(MeshPort.CHAT)
            .bindIp("0.0.0.0")
            .build();

    /** No links at all: floodAll reaches nobody, so onHandedOff must never fire. */
    @Test @Timeout(5)
    void noLiveLinksNeverFiresHandedOff() throws Exception {
        PeerIdentity self = new PeerIdentity(tmpA);
        MeshRouter router = new MeshRouter(self.getPeerId(), new MeshRouter.Listener() {
            @Override public void onDelivered(PeerId from, JSONObject payload) { }
            @Override public void onTopologyChanged() { }
        });

        java.util.concurrent.atomic.AtomicBoolean handedOff = new java.util.concurrent.atomic.AtomicBoolean(false);
        MeshLog log = new MeshLog(self.getPeerId(), router, new MeshLog.Listener() {
            @Override public void onMessage(String sid, String from, String nick, String text, long ts) { }
            @Override public void onHandedOff(String sid, long seq) { handedOff.set(true); }
        });

        long seq = log.send("room-1", "Alice", "hello, nobody");
        assertEquals(0, seq, "first seq for a fresh MeshLog should be 0");

        // floodAll's callback runs on a background thread; give it a moment,
        // then assert it never flipped the flag — this is a negative check,
        // not a race, since there are zero links for it to ever reach.
        Thread.sleep(300);
        assertFalse(handedOff.get(), "no live links exist — onHandedOff must not fire");
    }

    /** A real live link: floodAll reaches it, so onHandedOff must fire with the
     *  exact seq send() returned — the pairing the chat UI keys its tick on. */
    @Test @Timeout(15)
    void liveLinkFiresHandedOffWithMatchingSeq() throws Exception {
        PeerIdentity idA = new PeerIdentity(tmpA);
        PeerIdentity idB = new PeerIdentity(tmpB);

        MeshRouter routerA = new MeshRouter(idA.getPeerId(), new MeshRouter.Listener() {
            @Override public void onDelivered(PeerId from, JSONObject payload) { }
            @Override public void onTopologyChanged() { }
        });
        MeshRouter routerB = new MeshRouter(idB.getPeerId(), new MeshRouter.Listener() {
            @Override public void onDelivered(PeerId from, JSONObject payload) { }
            @Override public void onTopologyChanged() { }
        });

        CountDownLatch handedOffLatch = new CountDownLatch(1);
        AtomicLong handedOffSeq = new AtomicLong(-1);
        MeshLog logA = new MeshLog(idA.getPeerId(), routerA, new MeshLog.Listener() {
            @Override public void onMessage(String sid, String from, String nick, String text, long ts) { }
            @Override public void onHandedOff(String sid, long seq) {
                handedOffSeq.set(seq);
                handedOffLatch.countDown();
            }
        });

        // B just needs to be a live, accepted link — its own MeshLog/session
        // handling is irrelevant to what's under test (A's handed-off signal).
        CountDownLatch bReady = new CountDownLatch(1);
        MeshServer serverB = new MeshServer(idB, new MeshLink.Listener() {
            @Override public void onReady(MeshLink link, PeerId remote) {
                routerB.onLinkReady(link, remote);
                bReady.countDown();
            }
            @Override public void onMessage(MeshLink link, JSONObject json) {
                routerB.onLinkMessage(link, json);
            }
            @Override public void onClosed(MeshLink link, String reason) { }
        }, TEST_CFG);
        serverB.setLogger(MeshLogger.DEFAULT);
        int portB = MeshPort.CHAT;
        // Bind B on an ephemeral-safe fixed test port; retry not needed — CI/dev
        // machines don't otherwise hold this mesh port open.
        serverB.start();
        mWaitForPort(portB, 3000);

        CountDownLatch aLinked = new CountDownLatch(1);
        MeshClient clientA = new MeshClient(TEST_CFG, new MeshClient.Listener() {
            @Override public void onPeerFound(InetAddress a, boolean gw) { }
            @Override public void onScanComplete() { }
        });
        clientA.connect(InetAddress.getByName("127.0.0.1"), idA, new MeshLink.Listener() {
            @Override public void onReady(MeshLink link, PeerId remote) {
                routerA.onLinkReady(link, remote);
                aLinked.countDown();
            }
            @Override public void onMessage(MeshLink link, JSONObject json) {
                routerA.onLinkMessage(link, json);
            }
            @Override public void onClosed(MeshLink link, String reason) { }
        });

        assertTrue(aLinked.await(5, TimeUnit.SECONDS), "A should complete L2 handshake to B");
        assertTrue(bReady.await(5, TimeUnit.SECONDS), "B should accept the inbound link");

        long seq = logA.send("room-1", "Alice", "hello, Bob");

        assertTrue(handedOffLatch.await(5, TimeUnit.SECONDS),
                "onHandedOff must fire once the flood reaches B's live link");
        assertEquals(seq, handedOffSeq.get(),
                "onHandedOff's seq must match the seq send() returned — this is the pairing the chat UI's tick relies on");

        serverB.stop();
        routerA.stop();
        routerB.stop();
    }

    private static void mWaitForPort(int port, long timeoutMs) throws Exception {
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
