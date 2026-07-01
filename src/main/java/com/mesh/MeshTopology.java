package com.mesh;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayDeque;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Per-node adjacency view. Each node floods its own neighbor list; we merge
 * all received views into a global graph and do BFS for next-hop routing.
 *
 * This is eventually consistent: stale entries age out when a link-down
 * event removes the direct neighbor and the corresponding topology re-flood
 * removes it from other nodes' views.
 */
public class MeshTopology {

    private final PeerId mSelf;
    // peerHex → set of its neighbor hexes (as reported by that peer)
    private final Map<String, Set<String>> mGraph = new ConcurrentHashMap<>();

    public MeshTopology(PeerId self) {
        mSelf = self;
        mGraph.put(self.toHex(), ConcurrentHashMap.newKeySet());
    }

    public void addLink(PeerId remote) {
        mGraph.computeIfAbsent(mSelf.toHex(), k -> ConcurrentHashMap.newKeySet()).add(remote.toHex());
        mGraph.computeIfAbsent(remote.toHex(), k -> ConcurrentHashMap.newKeySet()).add(mSelf.toHex());
    }

    public void removeLink(PeerId remote) {
        Set<String> myNeighbors = mGraph.get(mSelf.toHex());
        if (myNeighbors != null) myNeighbors.remove(remote.toHex());
        Set<String> theirNeighbors = mGraph.get(remote.toHex());
        if (theirNeighbors != null) theirNeighbors.remove(mSelf.toHex());
    }

    /** Merge a topology frame received from a peer; returns true if the graph changed. */
    public boolean merge(JSONObject frame) {
        try {
            String peer = frame.getString("peer");
            JSONArray neighbors = frame.getJSONArray("neighbors");
            Set<String> newSet = new HashSet<>();
            for (int i = 0; i < neighbors.length(); i++) newSet.add(neighbors.getString(i));

            Set<String> existing = mGraph.computeIfAbsent(peer, k -> ConcurrentHashMap.newKeySet());
            if (existing.equals(newSet)) return false;
            existing.clear();
            existing.addAll(newSet);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /** Build the topology frame for this node's own adjacency list. */
    public JSONObject toFrame() {
        try {
            JSONObject frame = new JSONObject();
            frame.put("type", "topology");
            frame.put("peer", mSelf.toHex());
            JSONArray arr = new JSONArray();
            Set<String> myNeighbors = mGraph.getOrDefault(mSelf.toHex(), Collections.emptySet());
            for (String n : myNeighbors) arr.put(n);
            frame.put("neighbors", arr);
            return frame;
        } catch (Exception e) {
            return new JSONObject();
        }
    }

    /** BFS from self toward target; returns the hex of the next-hop neighbor, or null. */
    public String nextHop(PeerId target) {
        String targetHex = target.toHex();
        String selfHex   = mSelf.toHex();
        if (selfHex.equals(targetHex)) return selfHex;

        Set<String> visited = new HashSet<>();
        Queue<String[]> queue = new ArrayDeque<>();
        Set<String> direct = mGraph.getOrDefault(selfHex, Collections.emptySet());
        for (String n : direct) queue.add(new String[]{n, n});
        visited.add(selfHex);

        while (!queue.isEmpty()) {
            String[] entry = queue.poll();
            String cur  = entry[0];
            String via  = entry[1];
            if (visited.contains(cur)) continue;
            visited.add(cur);
            if (cur.equals(targetHex)) return via;
            for (String n : mGraph.getOrDefault(cur, Collections.emptySet())) {
                if (!visited.contains(n)) queue.add(new String[]{n, via});
            }
        }
        return null;
    }

    public Set<String> allPeers() {
        return Collections.unmodifiableSet(mGraph.keySet());
    }
}
