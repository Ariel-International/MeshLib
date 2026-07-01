package com.mesh;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayDeque;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * L3 topology graph — maintains a per-node adjacency view built from flooded
 * {@code topology} frames and provides BFS next-hop lookup.
 *
 * <p>Each node floods its own neighbour list whenever it changes. This class
 * merges all received views into a global graph. The graph is eventually
 * consistent: stale entries age out when a link-down event triggers a
 * re-flood that overwrites the old entry.
 *
 * <p>Thread-safe: the graph is backed by {@link ConcurrentHashMap}.
 */
public class MeshTopology {

    private final PeerId mSelf;

    // peerHex → set of that peer's direct neighbour hexes (as last reported by that peer)
    private final Map<String, Set<String>> mGraph = new ConcurrentHashMap<>();

    public MeshTopology(PeerId self) {
        mSelf = self;
        mGraph.put(self.toHex(), ConcurrentHashMap.newKeySet());
    }

    /** Records a new direct link to {@code remote} in the local adjacency list. */
    public void addLink(PeerId remote) {
        mGraph.computeIfAbsent(mSelf.toHex(),   k -> ConcurrentHashMap.newKeySet()).add(remote.toHex());
        mGraph.computeIfAbsent(remote.toHex(), k -> ConcurrentHashMap.newKeySet()).add(mSelf.toHex());
    }

    /** Removes a direct link to {@code remote} from the local adjacency list. */
    public void removeLink(PeerId remote) {
        Set<String> mine   = mGraph.get(mSelf.toHex());
        Set<String> theirs = mGraph.get(remote.toHex());
        if (mine   != null) mine.remove(remote.toHex());
        if (theirs != null) theirs.remove(mSelf.toHex());
    }

    /**
     * Merges a {@code topology} frame received from a peer into the graph.
     *
     * @return true if the graph changed (caller should re-flood if so)
     */
    public boolean merge(JSONObject frame) {
        try {
            String peer = frame.getString("peer");
            JSONArray neighbors = frame.getJSONArray("neighbors");
            Set<String> incoming = new HashSet<>();
            for (int i = 0; i < neighbors.length(); i++) incoming.add(neighbors.getString(i));

            Set<String> existing = mGraph.computeIfAbsent(peer, k -> ConcurrentHashMap.newKeySet());
            if (existing.equals(incoming)) return false;
            existing.clear();
            existing.addAll(incoming);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Builds a {@code topology} frame advertising this node's current adjacency list.
     * Used by {@link MeshRouter} for the periodic sync flood.
     */
    public JSONObject toFrame() {
        try {
            JSONObject frame = new JSONObject();
            frame.put("type", "topology");
            frame.put("peer", mSelf.toHex());
            JSONArray arr = new JSONArray();
            for (String n : mGraph.getOrDefault(mSelf.toHex(), Collections.emptySet())) arr.put(n);
            frame.put("neighbors", arr);
            return frame;
        } catch (Exception e) {
            return new JSONObject();
        }
    }

    /**
     * BFS from this node toward {@code target}.
     *
     * @return hex string of the direct neighbour to send through (first hop),
     *         or {@code null} if no path exists
     */
    public String nextHop(PeerId target) {
        String targetHex = target.toHex();
        String selfHex   = mSelf.toHex();
        if (selfHex.equals(targetHex)) return selfHex;

        Set<String>     visited = new HashSet<>();
        Queue<String[]> queue   = new ArrayDeque<>();
        visited.add(selfHex);
        for (String n : mGraph.getOrDefault(selfHex, Collections.emptySet()))
            queue.add(new String[]{n, n}); // {current, first-hop}

        while (!queue.isEmpty()) {
            String[] entry = queue.poll();
            String cur = entry[0], via = entry[1];
            if (visited.contains(cur)) continue;
            visited.add(cur);
            if (cur.equals(targetHex)) return via;
            for (String n : mGraph.getOrDefault(cur, Collections.emptySet()))
                if (!visited.contains(n)) queue.add(new String[]{n, via});
        }
        return null;
    }

    /** Returns an unmodifiable view of all known peer hex IDs (including self). */
    public Set<String> allPeers() {
        return Collections.unmodifiableSet(mGraph.keySet());
    }
}
