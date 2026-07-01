package com.mesh;

import org.json.JSONObject;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * L3 Routing — topology tracking + hop-by-hop delivery.
 *
 * Frame type "route":    { type:"route", from:"<hex>", to:"<hex>", payload:{} }
 * Frame type "topology": full adjacency list, flooded on change + periodic tick.
 * Frames with a "layer" field are L4+ and get flooded/delivered directly.
 */
public class MeshRouter {

    public interface Listener {
        void onDelivered(PeerId from, JSONObject payload);
        void onTopologyChanged();
    }

    private static final long SYNC_INTERVAL_MS = 3_000;

    private final PeerId       mSelf;
    private final MeshTopology mTopology;
    private final Listener     mListener;
    private MeshLogger         mLog = MeshLogger.DEFAULT;

    private final Map<String, MeshLink> mLinks = new ConcurrentHashMap<>();

    private volatile boolean mRunning = false;
    private Thread mSyncThread;

    public MeshRouter(PeerId self, Listener listener) {
        mSelf     = self;
        mTopology = new MeshTopology(self);
        mListener = listener;
    }

    public void setLogger(MeshLogger log) {
        mLog = log;
    }

    public void start() {
        mRunning = true;
        mSyncThread = new Thread(this::mSyncLoop, "mesh-l3-sync");
        mSyncThread.start();
    }

    public void stop() {
        mRunning = false;
        if (mSyncThread != null) mSyncThread.interrupt();
    }

    public void onLinkReady(MeshLink link, PeerId remotePeerId) {
        mLinks.put(remotePeerId.toHex(), link);
        mTopology.addLink(remotePeerId);
        mLog.d("MESH", "L3: link up → " + remotePeerId);
        mFloodTopology(null);
        mListener.onTopologyChanged();
    }

    public void onLinkClosed(MeshLink link, PeerId remotePeerId) {
        if (remotePeerId == null) return;
        mLinks.remove(remotePeerId.toHex(), link);
        mTopology.removeLink(remotePeerId);
        mLog.d("MESH", "L3: link down → " + remotePeerId);
        mFloodTopology(null);
        mListener.onTopologyChanged();
    }

    public void onLinkMessage(MeshLink link, JSONObject json) {
        if (json.has("layer")) {
            try {
                PeerId remotePeerId = mPeerForLink(link);
                PeerId from = remotePeerId != null ? remotePeerId : mSelf;
                mListener.onDelivered(from, json);
                for (Map.Entry<String, MeshLink> entry : mLinks.entrySet()) {
                    if (entry.getValue() == link || entry.getValue().isClosed()) continue;
                    try { entry.getValue().send(json); } catch (Exception ignored) {}
                }
            } catch (Exception e) {
                mLog.e("MESH", "L3 layer dispatch failed: " + e.getMessage());
            }
            return;
        }
        String type = json.optString("type");
        switch (type) {
            case "topology":
                boolean changed = mTopology.merge(json);
                mFloodTopology(link);
                if (changed) mListener.onTopologyChanged();
                break;
            case "route":
                mHandleRoute(json);
                break;
            default:
                mLog.w("MESH", "L3: unknown frame type: " + type);
        }
    }

    public boolean send(PeerId to, JSONObject payload) {
        if (to.equals(mSelf)) { mListener.onDelivered(mSelf, payload); return true; }
        String nextHopHex = mTopology.nextHop(to);
        if (nextHopHex == null) { mLog.w("MESH", "L3: no route to " + to); return false; }
        MeshLink link = mLinks.get(nextHopHex);
        if (link == null || link.isClosed()) { mLog.w("MESH", "L3: next-hop gone for " + to); return false; }
        try {
            JSONObject frame = new JSONObject();
            frame.put("type", "route");
            frame.put("from", mSelf.toHex());
            frame.put("to", to.toHex());
            frame.put("payload", payload);
            link.send(frame);
            return true;
        } catch (Exception e) {
            mLog.e("MESH", "L3 send failed: " + e.getMessage());
            return false;
        }
    }

    public void floodAll(JSONObject payload) {
        new Thread(() -> {
            for (MeshLink link : mLinks.values()) {
                if (link.isClosed()) continue;
                try { link.send(payload); } catch (Exception e) {
                    mLog.w("MESH", "L3 flood failed: " + e.getMessage());
                }
            }
        }, "mesh-flood").start();
    }

    public Set<String> allKnownPeerHexIds() { return mTopology.allPeers(); }

    private PeerId mPeerForLink(MeshLink link) {
        for (Map.Entry<String, MeshLink> entry : mLinks.entrySet()) {
            if (entry.getValue() == link) {
                try { return PeerId.fromHex(entry.getKey()); } catch (Exception ignored) {}
            }
        }
        return null;
    }

    private void mHandleRoute(JSONObject frame) {
        try {
            String toHex = frame.getString("to");
            if (mSelf.toHex().equals(toHex)) {
                mListener.onDelivered(PeerId.fromHex(frame.getString("from")),
                        frame.getJSONObject("payload"));
            } else {
                PeerId to = PeerId.fromHex(toHex);
                String nextHopHex = mTopology.nextHop(to);
                if (nextHopHex == null) { mLog.w("MESH", "L3: no route (fwd) to " + toHex); return; }
                MeshLink link = mLinks.get(nextHopHex);
                if (link != null && !link.isClosed()) link.send(frame);
            }
        } catch (Exception e) {
            mLog.e("MESH", "L3 route failed: " + e.getMessage());
        }
    }

    private void mFloodTopology(MeshLink exclude) {
        JSONObject frame = mTopology.toFrame();
        for (Map.Entry<String, MeshLink> entry : mLinks.entrySet()) {
            MeshLink link = entry.getValue();
            if (link == exclude || link.isClosed()) continue;
            try { link.send(frame); } catch (Exception e) {
                mLog.e("MESH", "L3 topology flood failed: " + e.getMessage());
            }
        }
    }

    private void mSyncLoop() {
        try {
            while (mRunning) {
                Thread.sleep(SYNC_INTERVAL_MS);
                if (!mRunning) return;
                mFloodTopology(null);
            }
        } catch (InterruptedException ignored) {}
    }
}
