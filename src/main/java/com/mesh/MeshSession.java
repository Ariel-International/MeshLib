package com.mesh;

import org.json.JSONObject;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * L4 Session — named group of PeerIds. Membership is replicated via L3 flood.
 * Session ID is a human-readable slug, independent of physical addresses.
 */
public class MeshSession {

    public interface Listener {
        void onSessionUpdated(String sessionId, String name, Map<String, String> members);
        void onSessionGone(String sessionId);
        void onPresence(String sessionId, String peerIdHex, String nickname, boolean online);
    }

    private static final String T_ANNOUNCE = "session_announce";
    private static final String T_JOIN     = "session_join";
    private static final String T_LEAVE    = "session_leave";
    private static final String T_PRESENCE = "session_presence";

    static class SessionState {
        final String id;
        String name;
        boolean isPublic;
        final Map<String, String> members = new LinkedHashMap<>();

        SessionState(String id, String name, boolean isPublic) {
            this.id = id; this.name = name; this.isPublic = isPublic;
        }
    }

    private final PeerId     mSelf;
    private final MeshRouter mRouter;
    private final Listener   mListener;
    private MeshLogger       mLog = MeshLogger.DEFAULT;

    private final Map<String, SessionState> mSessions = new ConcurrentHashMap<>();
    private String mActiveSessionId = null;
    private String mNickname = "";

    public MeshSession(PeerId self, MeshRouter router, Listener listener) {
        mSelf = self; mRouter = router; mListener = listener;
    }

    public void setLogger(MeshLogger log) { mLog = log; }

    public String getActiveSessionId() { return mActiveSessionId; }
    public void   setNickname(String nickname) { mNickname = nickname; }

    public void create(String sessionId, String name, boolean isPublic) {
        SessionState s = new SessionState(sessionId, name, isPublic);
        s.members.put(mSelf.toHex(), mNickname);
        mSessions.put(sessionId, s);
        mActiveSessionId = sessionId;
        mFloodAnnounce(s);
    }

    public void join(String sessionId) {
        SessionState s = mSessions.computeIfAbsent(sessionId,
                k -> new SessionState(sessionId, sessionId, true));
        s.members.put(mSelf.toHex(), mNickname);
        mActiveSessionId = sessionId;
        mFloodJoin(sessionId);
    }

    public void leave() {
        if (mActiveSessionId == null) return;
        String leaving = mActiveSessionId;
        mActiveSessionId = null;
        SessionState s = mSessions.get(leaving);
        if (s != null) s.members.remove(mSelf.toHex());
        mFloodLeave(leaving);
    }

    public void announcePresence(boolean online) {
        if (mActiveSessionId == null) return;
        try {
            JSONObject p = new JSONObject();
            p.put("type", T_PRESENCE);
            p.put("session", mActiveSessionId);
            p.put("peerId", mSelf.toHex());
            p.put("nickname", mNickname);
            p.put("online", online);
            mRouter.floodAll(mWrap(p));
        } catch (Exception e) { mLog.e("MESH", "L4 presence: " + e.getMessage()); }
    }

    public boolean handle(PeerId from, JSONObject payload) {
        String type = payload.optString("type");
        switch (type) {
            case T_ANNOUNCE: mHandleAnnounce(from, payload); return true;
            case T_JOIN:     mHandleJoin(from, payload);     return true;
            case T_LEAVE:    mHandleLeave(from, payload);    return true;
            case T_PRESENCE: mHandlePresence(from, payload); return true;
            default:         return false;
        }
    }

    public Map<String, SessionState> getSessions() {
        return Collections.unmodifiableMap(mSessions);
    }

    private void mHandleAnnounce(PeerId from, JSONObject p) {
        try {
            String id = p.getString("session");
            String name = p.optString("name", id);
            boolean pub = p.optBoolean("public", true);
            SessionState s = mSessions.computeIfAbsent(id, k -> new SessionState(id, name, pub));
            s.name = name; s.isPublic = pub;
            s.members.put(from.toHex(), p.optString("nickname", ""));
            mListener.onSessionUpdated(id, name, Collections.unmodifiableMap(s.members));
        } catch (Exception e) { mLog.e("MESH", "L4 announce: " + e.getMessage()); }
    }

    private void mHandleJoin(PeerId from, JSONObject p) {
        try {
            String id = p.getString("session");
            SessionState s = mSessions.get(id);
            if (s == null) return;
            s.members.put(from.toHex(), p.optString("nickname", ""));
            mListener.onSessionUpdated(id, s.name, Collections.unmodifiableMap(s.members));
        } catch (Exception e) { mLog.e("MESH", "L4 join: " + e.getMessage()); }
    }

    private void mHandleLeave(PeerId from, JSONObject p) {
        try {
            String id = p.getString("session");
            SessionState s = mSessions.get(id);
            if (s == null) return;
            s.members.remove(from.toHex());
            if (s.members.isEmpty()) { mSessions.remove(id); mListener.onSessionGone(id); }
            else mListener.onSessionUpdated(id, s.name, Collections.unmodifiableMap(s.members));
        } catch (Exception e) { mLog.e("MESH", "L4 leave: " + e.getMessage()); }
    }

    private void mHandlePresence(PeerId from, JSONObject p) {
        try {
            String id = p.getString("session");
            String nick = p.optString("nickname", "");
            boolean on = p.optBoolean("online", true);
            SessionState s = mSessions.get(id);
            if (s != null && on) s.members.put(from.toHex(), nick);
            mListener.onPresence(id, from.toHex(), nick, on);
        } catch (Exception e) { mLog.e("MESH", "L4 presence: " + e.getMessage()); }
    }

    private void mFloodAnnounce(SessionState s) {
        try {
            JSONObject p = new JSONObject();
            p.put("type", T_ANNOUNCE);
            p.put("session", s.id);
            p.put("name", s.name);
            p.put("public", s.isPublic);
            p.put("peerId", mSelf.toHex());
            p.put("nickname", mNickname);
            mRouter.floodAll(mWrap(p));
        } catch (Exception e) { mLog.e("MESH", "L4 announce flood: " + e.getMessage()); }
    }

    private void mFloodJoin(String sessionId) {
        try {
            JSONObject p = new JSONObject();
            p.put("type", T_JOIN);
            p.put("session", sessionId);
            p.put("peerId", mSelf.toHex());
            p.put("nickname", mNickname);
            mRouter.floodAll(mWrap(p));
        } catch (Exception e) { mLog.e("MESH", "L4 join flood: " + e.getMessage()); }
    }

    private void mFloodLeave(String sessionId) {
        try {
            JSONObject p = new JSONObject();
            p.put("type", T_LEAVE);
            p.put("session", sessionId);
            p.put("peerId", mSelf.toHex());
            mRouter.floodAll(mWrap(p));
        } catch (Exception e) { mLog.e("MESH", "L4 leave flood: " + e.getMessage()); }
    }

    private static JSONObject mWrap(JSONObject payload) throws Exception {
        JSONObject frame = new JSONObject();
        frame.put("layer", "session");
        frame.put("payload", payload);
        return frame;
    }
}
