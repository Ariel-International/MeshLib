# MeshLib Architecture

## Layers

```
L5  MeshLog      — message log, sync, dedup (IDs + reconciliation)
L4  MeshSession  — named peer groups, presence, membership
L3  MeshRouter   — tree topology, shortest-path routing, flood/unicast
L2  MeshLink     — TCP socket, length-prefix framing, handshake
L1  MeshFinder   — subnet sweep, seed peer dial, periodic rescan
L0  PeerIdentity — P-256 EC keypair, stable PeerId, sign/verify
```

Each layer is independent. The router does not know what a session is.
The session does not know what a socket is.

---

## Peer model

Every node is simultaneously a TCP listener and a scanner. "Server" and
"client" are TCP implementation details (someone has to call accept()),
not mesh roles. Once the L2 handshake completes both sides are equal
peers. There is no privileged node.

---

## Network toggle (local)

- **OFF** — zero network activity. No sockets, no scanning, no listening,
  no responding. This is a security control: network presence = wallet
  presence, so the user can go dark completely.
- **ON** — node listens on all eligible LAN interfaces and scans
  periodically for new peers.

Retains last state across restarts. Default OFF on first launch.

---

## Beacon toggle

- Advertises services/pillars to connected peers.
- Structurally gated by network toggle: beacon cannot be ON when network
  is OFF.
- Being on the network does not imply beacon is on. A node can
  participate in routing without advertising any service.

---

## Globe toggle (internet visibility) — planned

- A third toggle, separate from local network.
- Connects to one or more seed peers at known public addresses.
- Gated by network toggle (network must be ON).
- Independent of beacon — you can be globally reachable without
  advertising local services.
- UI: globe icon, same visual language as beacon.
- Security implication: with globe ON the node is reachable from the
  internet, not just the local subnet. User must opt in explicitly.

---

## Transport layer

`MeshLink` wraps any `Socket`. The router does not care what produced
the socket. Planned transports:

| Transport       | Interface prefix | Notes                          |
|-----------------|-----------------|--------------------------------|
| Wi-Fi (TCP)     | wlan, ap, eth…  | Primary, already implemented   |
| Wi-Fi Direct    | p2p             | No router needed, ~250m range  |
| Bluetooth       | bt              | Works when Wi-Fi off, ~10m     |
| Cloud relay     | (TCP to seed)   | Public IP, stable, opt-in      |

Android subclasses (`AndroidMeshClient`, `AndroidMeshServer`) handle
transport-specific socket binding.

---

## Interface classification (MeshServer / MeshFinder)

Whitelist-only. Interfaces not in the list are ignored (excludes mobile
data: ccmni, rmnet, pdp, ppp, clat).

| Priority | Prefix                           | Role              |
|----------|----------------------------------|-------------------|
| 1        | ap, swlan                        | Hotspot (gateway) |
| 2        | wlan, eth, lan, usb, rndis, br   | LAN / uplink      |

A node with both ap0 and wlan0 active listens on both and bridges
traffic between subnets naturally.

---

## Discovery

### Local (L1 — MeshFinder)

1. Enumerate all mesh interfaces (whitelist above).
2. Per interface: probe gateway first (longer timeout), then sweep /24
   in parallel (32 threads, 300ms timeout each).
3. `onPeerFound` fires for each host responding on the mesh port.
4. `MeshClient.connect()` initiates L2 handshake.
5. Already-connected peers are skipped (dedup by PeerId).

Scan schedule:
- Immediate on network-on.
- Repeat at 5s (catch slow-starting peers).
- Then periodic every 30s.
- Triggered rescan on interface change (hotspot toggle, Wi-Fi connect).

### Cloud (seed peers — planned)

- `MeshConfig.seedPeers` — list of `host:port` to dial at startup.
- Tried before local scan, retried on disconnect with backoff.
- Same L2 handshake as local peers — no special protocol.
- A seed peer is just a stable long-running `MeshNode` on a VPS
  (`java -jar meshlib.jar`).

---

## Topology

`MeshRouter` maintains a tree rooted at the gateway. Topology is flooded
on every link change. `onTopologyChanged()` fires reactively — not on a
timer. The UI renders peers by hop depth:

- Depth 1 — directly connected peers
- Depth 2 — peers-of-peers
- etc.

Shortest-path routing: a message to a local peer never bounces through
a cloud relay if a direct route exists.

Planned limits (to prevent abuse / runaway trees):
- Max peers per node (configurable, default TBD)
- Max routing depth (configurable, default TBD)

---

## Peer lists (planned)

Two lists exposed to the UI:

- **Local peers** — reachable via LAN/BT/Wi-Fi Direct
- **Remote peers** — reachable via cloud relay

Separate display, separate trust level. Remote peers require more
friction to interact with (contact request, etc.) because scam risk is
real for international money transfer.

---

## Cloud peer / analytics (planned)

A seed peer can optionally collect:
- Peer count over time (growth metric)
- Session creation rate (usage metric)
- No message content (privacy preserved if E2E encryption is on)

This is opt-in and disclosed. The seed operator controls what is
collected. First-party seed (operated by Sovrana) would publish
aggregates only.

---

## Security model

| Layer       | Mechanism                                      |
|-------------|------------------------------------------------|
| L0 identity | P-256 EC keypair, hardware-backed on Android   |
| L2 handshake| Mutual PeerId exchange + signature verify      |
| L5 messages | Plaintext today; E2E encryption planned        |
| Network off | Zero activity — structural, not a flag         |
| Beacon off  | No service advertisement — gated by network    |
| Globe off   | No internet exposure — gated by network        |

E2E encryption at L5 means a cloud relay sees only ciphertext. The
relay cannot read messages even if compromised.

---

## What is implemented today

- [x] L0–L5 full stack
- [x] Multi-interface server (binds all LAN interfaces)
- [x] Android hardware-backed identity (AndroidKeyStore)
- [x] Android Wi-Fi network binding (AndroidMeshClient)
- [x] android-test harness with SERVER / CLIENT / SCAN buttons
- [x] Tested on physical devices over direct Wi-Fi (no tunnel)
- [x] MeshNode.main() — standalone PC node

## Planned next

- [ ] Multi-subnet scanning (MeshFinder scans all interfaces in parallel)
- [ ] Dedup guard in MeshClient (skip already-connected peers)
- [ ] Aggressive scan schedule on startup (immediate → 5s → 30s)
- [ ] Seed peers in MeshConfig (cloud entry point)
- [ ] Globe toggle in wallet UI
- [ ] Peer list UI (local vs remote, depth display)
- [ ] Wi-Fi Direct transport
- [ ] Bluetooth transport
- [ ] E2E encryption at L5
- [ ] Contact request flow for remote peers
