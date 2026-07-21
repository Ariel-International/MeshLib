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

---

## Portable core — multi-platform (decided 20 Jul)

MeshLib now has two confirmed consumers beyond PopCoin's own JVM app:
**AstroLabius/ALOS** (needs L0–L3 on ESP32 — see `AstroLabius/CONCEPT.md`,
"MeshLib reuse spotted" log entry), and a third deployment shape Ariel
flagged directly: a **bare relay/"PoP" node** — no wallet, no IoT logic,
just a MeshLib node instance sitting next to whatever device is actually
publishing a PopCoin proof-of-presence, decoupling "the thing with a mesh
identity" from "the thing generating the payload."

That third case is what settled the design question. Two independent
implementations (Java here, hand-written C/C++ for ESP32) kept in sync only
by a shared spec document would drift over time, and doesn't serve the
bare-relay case at all — there'd be no app to embed a from-scratch port
into. So instead of a spec-only approach:

**Decision: extract L0–L3 (PeerIdentity, MeshFinder, MeshLink, MeshRouter —
the wire-format-critical layers) into a portable core written in C.**
L4–L5 (MeshSession, MeshLog) stay JVM/PopCoin-specific — AstroLabius and
bare relay nodes don't need named sessions or message-log sync, they only
need to exist on the mesh and route.

Why C specifically: ESP32 firmware (AstroLabius) is native C/C++ via
ESP-IDF — there's no JVM there to target instead. C binds cleanly into the
existing JVM code via JNI, so PopCoin's Java app layer (wallet UI, L4/L5)
doesn't need to be rewritten, only its L0–L3 internals swapped for calls
into the shared core over time.

**General pattern (sharpened 20 Jul): every endpoint implements its own
L4/L5 above the shared L0–L3 core.** Not "PopCoin has L4/L5, other
consumers have some separate unrelated thing" — the same architectural
slot, filled with domain-appropriate content, no code shared at that level
because the domains don't need to interoperate with each other there (a
PopCoin peer never needs to parse an AstroLabius event log or vice versa —
only L0–L3 needs to be byte-compatible across consumers). A node that
relays but never originates or reads at the application level needs
nothing in that slot at all.

**Per-target shape:**
- **PopCoin** — JNI binding wraps the C core; Java L4 (`MeshSession` —
  named peer groups, presence) / L5 (`MeshLog` — message log, sync, dedup)
  sit on top unchanged, calling into the core for identity/discovery/
  link/routing instead of running today's pure-Java L0–L3.
- **AstroLabius/ALOS** — native build of the same C core on ESP32, running
  its own L4/L5 embedded on-device: L4-equivalent = device/node membership
  for that deployment, L5-equivalent = event/command history, replacing
  PopCoin's session/log semantics with ALOS's own (per the existing
  "MeshLib reuse spotted" scoping — this was already decided independently
  of today's ownership question, still holds).
- **Bare relay/PoP node** — same native core, no layer above L3 at all —
  the clearest case of the slot being genuinely optional.
  Confirms the L0–L3/L4–L5 split is the right cut line: everything above
  it is "what kind of thing is running the node," everything at or below
  it is "is this a MeshLib node at all."

**Phasing** (doesn't block PopCoin's wallet finish line): build the C core
against AstroLabius's build first — nothing exists there yet, so no
migration cost. Migrate PopCoin's JVM L0–L3 onto the same core afterward,
once the core has proven itself against a real second target, rather than
rewriting working Java code up front.

**Not yet decided / open:**
- Build system for a C core that needs to target desktop JNI, Android JNI,
  and ESP-IDF from one source tree (CMake is the likely default, not
  confirmed).
- How wire compatibility gets *tested*, not just designed — a shared fixture
  suite (recorded handshake/routing byte sequences) that both the JNI
  binding and the ESP32 build run against is the obvious shape, not yet
  built.
- Versioning scheme for the core independent of PopCoin's and ALOS's own
  app-level versions.
- Whether this repo becomes the home for the C core too, or the core gets
  its own repo with this one becoming the JNI-binding-plus-L4/L5 consumer —
  leaning toward core-gets-its-own-repo given it now serves three consumers,
  not decided.
