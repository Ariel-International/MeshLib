# MeshLib

A zero-dependency Java library for peer-to-peer mesh networking over local Wi-Fi.

Runs on any JVM (Java 11+) — Android, PC, Raspberry Pi, embedded Linux router.
No central server, no internet access required, no Android-specific APIs in the core.

---

## What it does

MeshLib builds a self-healing mesh network across devices on the same LAN or Wi-Fi hotspot.

- **Discovery** — sweeps the local /24 by TCP probe. No UDP broadcast, no mDNS. Every responding host is a candidate; identity is confirmed during the handshake.
- **Identity** — each node generates a P-256 EC keypair on first run. The public key *is* the node's address (PeerId). Handshakes are mutually authenticated with nonce-signing.
- **Routing** — BFS hop-by-hop over a topology built from flooded adjacency lists. Any node can reach any other node through intermediaries.
- **Sessions** — named logical groups (e.g. `"chat-room-1"`, `"wallet-abc"`). Membership is replicated to all peers via flood. Multiple sessions can coexist on one mesh without port separation.
- **Messages** — per-sender sequence numbers, timestamp ordering, and gap-replay sync on reconnect.

---

## Quick start

```java
MeshNode node = new MeshNode(new File("/data/mesh"), "Alice");
node.setLogger(MeshLogger.STDOUT);
node.setChatListener(new MeshNode.ChatListener() {
    public void onMessage(String session, String from, String text, long ts) {
        System.out.println(from + ": " + text);
    }
    public void onPeerConnected(String peerId)    { System.out.println("+ " + peerId); }
    public void onPeerDisconnected(String peerId) { System.out.println("- " + peerId); }
    public void onSessionUpdated(String id, String name, Map<String,String> members) {}
});

node.start();
node.createSession("my-room", "My Room", true);
node.sendMessage("my-room", "Alice", "Hello world!");

// later
node.stop();
```

---

## Custom port and appId

```java
MeshConfig cfg = new MeshConfig.Builder()
    .port(MeshPort.WALLET)          // each application picks its own port
    .appId("sovrana-wallet-v1")     // optional: reject nodes with a different appId
    .rescanIntervalMs(60_000)       // how often to sweep for new peers
    .build();

MeshNode node = new MeshNode(storageDir, "Alice", cfg);
```

---

## Port allocation

All ports live in the unregistered range **47820–47829**. Assign one port per application so that multiple MeshLib instances can run on the same device without interfering.

| Port  | Constant            | Suggested use                              |
|-------|---------------------|--------------------------------------------|
| 47820 | `MeshPort.GENERAL`  | General-purpose / default when nothing else fits |
| 47821 | `MeshPort.CHAT`     | Chat applications **(library default)**   |
| 47822 | `MeshPort.WALLET`   | Wallet / payment traffic                  |
| 47823 | `MeshPort.MONITOR`  | LAN monitoring, device presence, router health |
| 47824 | `MeshPort.SYNC`     | File / data synchronisation               |
| 47825 | `MeshPort.IOT`      | IoT sensors, embedded devices             |
| 47826 | `MeshPort.RELAY`    | Bridge / relay nodes                      |
| 47827 | `MeshPort.ADMIN`    | Management / admin plane                  |
| 47828 | `MeshPort.MEDIA`    | Audio/video metadata signalling           |
| 47829 | `MeshPort.CUSTOM`   | Application-defined; pair with `appId`    |

The range is narrow enough that a full `MeshPort.ALL` probe adds only 9 extra TCP connects per host during a subnet scan.

---

## Traffic isolation within one mesh

Separate logical channels (e.g. wallet traffic vs chat) do **not** need separate ports or nodes.
Use distinct session IDs — `"wallet-<peerId>"`, `"chat-main"` — and they stay isolated at L4.
The `layer` field in the frame protocol routes each frame to the correct handler.

---

## LAN scanner / monitoring mode

`MeshFinder` can probe any set of ports on the subnet and report every open port, not just MeshLib nodes. Useful for monitoring routers, printers, cameras, and other embedded hardware:

```java
MeshFinder finder = new MeshFinder(MeshConfig.defaults());
finder.setLogger(MeshLogger.STDOUT);

// Probe all known mesh ports
finder.scanPorts(MeshPort.ALL, 300, new MeshFinder.PortScanListener() {
    public void onPortOpen(InetAddress address, int port) {
        System.out.println(address.getHostAddress() + ":" + port + " is open");
    }
    public void onScanComplete() { System.out.println("done"); }
});

// Or probe arbitrary ports (HTTP, SSH, etc.)
finder.scanPorts(new int[]{22, 80, 443, 8080}, 300, listener);
```

The more devices that run MeshLib on a given network, the richer the mesh — including non-MeshLib hosts that simply appear as monitored endpoints during the scan.

---

## Android integration

Subclass `MeshClient` and override `bindSocket` to ensure Android routes connections through Wi-Fi rather than mobile data:

```java
MeshClient client = new MeshClient(config, listener) {
    @Override protected void bindSocket(Socket s) throws Exception {
        ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(CONNECTIVITY_SERVICE);
        for (Network net : cm.getAllNetworks()) {
            NetworkCapabilities caps = cm.getNetworkCapabilities(net);
            if (caps != null && caps.hasTransport(TRANSPORT_WIFI)) {
                net.bindSocket(s);
                return;
            }
        }
    }
};
MeshNode node = new MeshNode(storageDir, "Alice", config, client);
```

---

## Architecture

```
L5  MeshLog      — message log, per-sender dedup, gap-replay sync
L4  MeshSession  — named peer groups, membership flood
L3  MeshRouter   — BFS routing, topology sync
L2  MeshLink     — per-socket handshake, heartbeat, framed I/O
L1  MeshFinder   — /24 TCP probe scan
L0  PeerIdentity — P-256 EC keypair, persisted as DER files
```

`MeshConfig` tunes port, appId, timeouts.  
`MeshLogger` is a pluggable interface — swap in your own backend.  
`MeshNode` is the single entry point that wires all layers together.

---

## Build

```bash
# Compile and test
./gradlew test

# Build fat jar (bundles org.json)
./gradlew jar
# → build/libs/meshlib.jar  (~125 KB)
```

Requires Java 11+. No other toolchain dependencies.

---

## License

MIT
