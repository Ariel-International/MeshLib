package com.mesh;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Trigger condition for "host/peer steps away from a live session mid-use"
 * (DOCS/MESH_ROADMAP.md "Still open" — warn, don't block).
 *
 * <p>{@link MeshSession#announcePresence(boolean)} is the wire signal the app
 * fires from {@code ChatFragment.pause()}/{@code resume()}. These tests check
 * the trigger condition in isolation: it fires only while a session is
 * actively joined, and is a no-op otherwise — so pausing the Chat pillar with
 * no live session never spams a flood that has nothing to say.
 */
class MeshSessionPresenceTest {

    @TempDir File tmp;

    private static final class CountingListener implements MeshSession.Listener {
        final AtomicInteger updates = new AtomicInteger();
        @Override public void onSessionUpdated(String id, String name, Map<String, String> members) { updates.incrementAndGet(); }
        @Override public void onSessionGone(String id) { }
        @Override public void onPresence(String id, String peerIdHex, String nickname, boolean online) { }
    }

    private MeshSession mSession() {
        PeerIdentity identity = new PeerIdentity(tmp);
        MeshRouter router = new MeshRouter(identity.getPeerId(), new MeshRouter.Listener() {
            @Override public void onDelivered(PeerId from, org.json.JSONObject payload) { }
            @Override public void onTopologyChanged() { }
        });
        return new MeshSession(identity.getPeerId(), router, new CountingListener());
    }

    /** Given an active session, stepping away must not throw and must not clear it — this is presence, not leave(). */
    @Test @Timeout(5)
    void announcePresenceFalseWhileJoinedIsSafeAndKeepsMembership() {
        MeshSession session = mSession();
        session.create("room-1", "Room One", true);
        assertEquals("room-1", session.getActiveSessionId());

        assertDoesNotThrow(() -> session.announcePresence(false));

        // Warn, don't block/leave: still the active session, still a member.
        assertEquals("room-1", session.getActiveSessionId());
        assertTrue(session.getSessions().get("room-1").members.size() >= 1);
    }

    /** Coming back re-announces online — the paired resume() call. */
    @Test @Timeout(5)
    void announcePresenceTrueAfterFalseIsSafe() {
        MeshSession session = mSession();
        session.create("room-1", "Room One", true);

        session.announcePresence(false);
        assertDoesNotThrow(() -> session.announcePresence(true));
        assertEquals("room-1", session.getActiveSessionId());
    }

    /** No active session (never joined, or already left) — announcePresence is a no-op, not an error. */
    @Test @Timeout(5)
    void announcePresenceWithNoActiveSessionIsNoOp() {
        MeshSession session = mSession();
        assertNull(session.getActiveSessionId());

        assertDoesNotThrow(() -> session.announcePresence(false));

        assertNull(session.getActiveSessionId());
        assertTrue(session.getSessions().isEmpty());
    }

    /** After leave(), the session is no longer active — pausing afterward must stay a no-op. */
    @Test @Timeout(5)
    void announcePresenceAfterLeaveIsNoOp() {
        MeshSession session = mSession();
        session.create("room-1", "Room One", true);
        session.leave();
        assertNull(session.getActiveSessionId());

        assertDoesNotThrow(() -> session.announcePresence(false));
        assertNull(session.getActiveSessionId());
    }
}
