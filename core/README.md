# MeshLib C core (L0–L3) — skeleton

Portable C implementation of MeshLib's wire-format-critical layers, extracted
from the reference Java implementation so that PopCoin (desktop/Android JNI),
AstroLabius/ALOS (ESP32), and bare relay nodes share one byte-compatible core.
Rationale and scope: [`../ARCHITECTURE.md`](../ARCHITECTURE.md), "Portable
core — multi-platform".

**Status: skeleton.** Header signatures and struct layouts only. Every function
compiles and links but returns `MESH_ERR_UNIMPLEMENTED` (or is an empty stub).
No crypto backend, no JSON parser, no JNI, no ESP-IDF toolchain is wired up yet.

## The interop contract lives at the repo root

The normative wire format these functions must produce and accept is
**[`../WIRE_FORMAT.md`](../WIRE_FORMAT.md)** — kept at the repo root because it
is shared by both this C core and the Java reference, not owned by either. Do
not treat these headers as the spec; they are an implementation *of* the spec,
and the doc comments cite specific `WIRE_FORMAT.md` line ranges so the two stay
in sync. If a signature here and a rule there ever disagree, the doc wins and
the header is a bug.

## Layout

```
core/
  CMakeLists.txt        desktop static-library build (skeleton)
  include/
    mesh_common.h       result codes, buffers, framing limits
    mesh_codec.h        strict Base64 + hex  (WIRE_FORMAT.md "Encoding")
    mesh_identity.h     L0 — P-256 keypair, PeerId, sign/verify
    mesh_link.h         L2 — length-prefix framing + handshake
    mesh_router.h       L3 — topology + BFS routing
  src/
    mesh_*.c            matching stub translation units
```

L4/L5 (sessions, message log) are intentionally absent — they are per-consumer
and stay in each embedder (`ARCHITECTURE.md`). This core is "is this a MeshLib
node at all"; everything above L3 is "what kind of node."

## Building

Desktop, plain CMake (what this skeleton targets):

```
cmake -S . -B build
cmake --build build
```

Produces a static library (`libmeshcore.a` on Unix, `meshcore.lib` with MSVC)
full of stub symbols. Warnings are on (`-Wall -Wextra -Wpedantic` / `/W4`); the
skeleton builds clean.

### Where an ESP-IDF build differs (flagged, not implemented)

The ESP-IDF toolchain is **not** set up here. When it is, these are the known
divergences from the desktop path — collected so nothing is lost:

- **Component registration.** ESP-IDF discovers code via components, not a
  standalone `project()`. This directory would gain (or its `CMakeLists.txt`
  would branch to) an `idf_component_register(SRCS … INCLUDE_DIRS include
  REQUIRES mbedtls)` call. `CMakeLists.txt` already `FATAL_ERROR`s if it detects
  `ESP_PLATFORM` so the wrong path can't be taken silently.
- **Crypto backend.** Desktop will link **OpenSSL** (`OpenSSL::Crypto`) for
  P-256 ECDSA in `mesh_identity.c`; ESP-IDF ships **mbedTLS**, so the same
  layer compiles against a different API. This is the main place the L0 `.c`
  file will need conditional compilation.
- **RNG.** The 16-byte handshake nonce (`WIRE_FORMAT.md` "L2 handshake") uses
  the platform RNG: OS CSPRNG on desktop vs. `esp_random()` / mbedTLS CTR-DRBG
  on ESP32.
- **No file persistence anywhere.** Unlike the Java `PeerIdentity` (which writes
  `mesh-identity.pub/.key`), this core never touches the filesystem — the
  embedder owns key storage (a desktop file, Android KeyStore, ESP32 NVS). This
  is a deliberate portability cut, not an ESP-only concern, but it matters most
  on ESP32 where there is no filesystem by default.
- **Integer width / endianness.** The length prefix is explicitly big-endian
  (`WIRE_FORMAT.md` "Framing"); ESP32 (Xtensa) is little-endian, so byte-swap on
  the prefix is mandatory there. The desktop x86 build is also little-endian, so
  this is already exercised — but it's called out because a from-scratch reader
  is the classic place to get it wrong.

## Not resolved in this skeleton

Open questions that surfaced while writing the signatures — see the accompanying
report for detail. Two worth recording here because they are contract-level, not
just implementation:

- **Frame size cap on write.** `mesh_frame_encode` enforces the 256 KiB cap on
  the sending side; the Java reference does *not* (`WIRE_FORMAT.md:40-43`). This
  skeleton is deliberately stricter. Reconcile before wire-compat fixtures are
  frozen.
- **Wire versioning.** Still unversioned (`WIRE_FORMAT.md` "Versioning"). Must be
  settled before this core ships against a second independent implementation.
