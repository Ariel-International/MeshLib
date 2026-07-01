package com.mesh;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * L5 Message log / sync.
 * Message ID = (senderHex, seq). Seq is per-sender monotonic.
 * Reconciliation: peers exchange {peerId: lastSeenSeq} on reconnect and replay gaps.
 * Retention: 500 messages per session, in-memory only.
 */
public class MeshLog {

    public interface Listener {
        void onMessage(String sessionId, String fromPeerIdHex,
                String nickname, String text, long timestampMs);
    }

    private static final int MAX_MESSAGES = 500;

    public static final class Msg {
        public final String senderHex;
        public final long   seq;
        public final String nickname;
        public final String text;
        public final long   timestampMs;
        public final String sessionId;

        Msg(String senderHex, long seq, String nickname,
                String text, long timestampMs, String sessionId) {
            this.senderHex = senderHex; this.seq = seq; this.nickname = nickname;
            this.text = text; this.timestampMs = timestampMs; this.sessionId = sessionId;
        }
    }

    private final PeerId     mSelf;
    private final MeshRouter mRouter;
    private final Listener   mListener;
    private MeshLogger       mLog = MeshLogger.DEFAULT;

    private final Map<String, List<Msg>>          mLog2    = new ConcurrentHashMap<>();
    private final Map<String, Map<String, Long>>  mSeenSeqs = new ConcurrentHashMap<>();
    private long mNextSeq = 0;

    public MeshLog(PeerId self, MeshRouter router, Listener listener) {
        mSelf = self; mRouter = router; mListener = listener;
    }

    public void setLogger(MeshLogger log) { mLog = log; }

    public void send(String sessionId, String nickname, String text) {
        long seq = mNextSeq++;
        long ts  = System.currentTimeMillis();
        Msg msg  = new Msg(mSelf.toHex(), seq, nickname, text, ts, sessionId);
        mStore(sessionId, msg);
        mListener.onMessage(sessionId, mSelf.toHex(), nickname, text, ts);
        try {
            JSONObject payload = new JSONObject();
            payload.put("type", "chat");
            payload.put("session", sessionId);
            payload.put("sender", mSelf.toHex());
            payload.put("seq", seq);
            payload.put("nickname", nickname);
            payload.put("text", text);
            payload.put("ts", ts);
            mRouter.floodAll(mWrap(payload));
        } catch (Exception e) { mLog.e("MESH", "L5 send: " + e.getMessage()); }
    }

    public void sendSyncSummary(String sessionId, MeshLink link) {
        try {
            JSONObject payload = new JSONObject();
            payload.put("type", "sync_summary");
            payload.put("session", sessionId);
            JSONObject seqs = new JSONObject();
            for (Map.Entry<String, Long> e :
                    mSeenSeqs.getOrDefault(sessionId, Collections.emptyMap()).entrySet())
                seqs.put(e.getKey(), e.getValue());
            payload.put("seqs", seqs);
            link.send(mWrap(payload));
        } catch (Exception e) { mLog.e("MESH", "L5 sync summary: " + e.getMessage()); }
    }

    public void handle(PeerId from, JSONObject frame) {
        try {
            JSONObject payload = frame.optJSONObject("payload");
            if (payload == null) return;
            switch (payload.optString("type")) {
                case "chat":         mHandleChat(payload);              break;
                case "sync_summary": mHandleSyncSummary(from, payload); break;
                case "sync_replay":  mHandleSyncReplay(payload);        break;
                default: mLog.w("MESH", "L5 unknown: " + payload.optString("type"));
            }
        } catch (Exception e) { mLog.e("MESH", "L5 handle: " + e.getMessage()); }
    }

    public List<Msg> getMessages(String sessionId) {
        List<Msg> list = mLog2.get(sessionId);
        return list != null ? Collections.unmodifiableList(list) : Collections.emptyList();
    }

    private void mHandleChat(JSONObject p) throws Exception {
        String session  = p.getString("session");
        String sender   = p.getString("sender");
        long   seq      = p.getLong("seq");
        String nickname = p.optString("nickname", "");
        String text     = p.getString("text");
        long   ts       = p.optLong("ts", System.currentTimeMillis());

        Map<String, Long> seen = mSeenSeqs.computeIfAbsent(session, k -> new ConcurrentHashMap<>());
        Long lastSeen = seen.get(sender);
        if (lastSeen != null && seq <= lastSeen) return;
        seen.put(sender, Math.max(seq, lastSeen != null ? lastSeen : -1));

        mStore(session, new Msg(sender, seq, nickname, text, ts, session));
        mListener.onMessage(session, sender, nickname, text, ts);
    }

    private void mHandleSyncSummary(PeerId from, JSONObject p) throws Exception {
        String session = p.getString("session");
        JSONObject theirSeqs = p.getJSONObject("seqs");
        List<Msg> log = mLog2.getOrDefault(session, Collections.emptyList());
        JSONArray replay = new JSONArray();
        for (Msg msg : log) {
            if (msg.seq > theirSeqs.optLong(msg.senderHex, -1)) {
                JSONObject m = new JSONObject();
                m.put("sender", msg.senderHex);
                m.put("seq", msg.seq);
                m.put("nickname", msg.nickname);
                m.put("text", msg.text);
                m.put("ts", msg.timestampMs);
                replay.put(m);
            }
        }
        if (replay.length() == 0) return;
        JSONObject payload = new JSONObject();
        payload.put("type", "sync_replay");
        payload.put("session", session);
        payload.put("messages", replay);
        mRouter.send(from, mWrap(payload));
    }

    private void mHandleSyncReplay(JSONObject p) throws Exception {
        String session = p.getString("session");
        JSONArray msgs = p.getJSONArray("messages");
        for (int i = 0; i < msgs.length(); i++) {
            JSONObject m = msgs.getJSONObject(i);
            m.put("session", session);
            mHandleChat(m);
        }
    }

    private void mStore(String sessionId, Msg msg) {
        List<Msg> list = mLog2.computeIfAbsent(sessionId, k -> new ArrayList<>());
        list.add(msg);
        list.sort((a, b) -> Long.compare(a.timestampMs, b.timestampMs));
        while (list.size() > MAX_MESSAGES) list.remove(0);
    }

    private static JSONObject mWrap(JSONObject payload) throws Exception {
        JSONObject frame = new JSONObject();
        frame.put("layer", "message");
        frame.put("payload", payload);
        return frame;
    }
}
