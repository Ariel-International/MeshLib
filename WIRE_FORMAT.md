# MeshLib Wire Format

Normative description of what MeshLib puts on the socket. This is the interop
contract: any independent implementation (the planned C core, the ESP32/ALOS
build, a bare relay node) must match this byte-for-byte to join a mesh.

Layers L0–L3 are wire-format-critical. L4–L5 are per-consumer and are not
specified here — see `ARCHITECTURE.md`.

---

## Framing

Every frame on every MeshLib socket is:

```
+------------------+-------------------------------+
| length (4 bytes) | UTF-8 JSON payload (N bytes)  |
+------------------+-------------------------------+
```

- **length** — big-endian **signed** 32-bit integer (Java `DataOutputStream.writeInt`),
  counting only the payload bytes that follow, not the prefix itself.
- **payload** — exactly `length` bytes of UTF-8 encoded JSON. No trailing
  newline, no delimiter, no compression.

### Length constraints

| Rule | Value |
|------|-------|
| Minimum accepted length | 1 (`len <= 0` is rejected) |
| Maximum accepted length | 262144 (256 KiB) |

A receiver MUST reject a frame whose length prefix is `<= 0` or `> 262144` and
tear down the link. Because the field is signed, a stream desync that yields a
negative integer surfaces here as a rejected frame rather than an allocation
attempt — implementations that read the prefix as *unsigned* must add an
explicit upper-bound check to get equivalent behaviour.

**No fragmentation exists.** A payload exceeding 256 KiB is unsendable; there is
no continuation mechanism. Note that the sender does not currently enforce this
cap — an oversized frame is written successfully and rejected by the receiver,
which closes the link.

---

## Encoding of binary fields

JSON carries no binary type, so binary values cross the wire as text. Two
encodings are used, and **both are validated strictly on decode.** A conforming
implementation MUST reject malformed input rather than repairing, skipping, or
truncating it.

This strictness is part of the interop contract, not an internal detail. These
fields appear on the authenticated handshake path, where a lenient decoder turns
corrupt or hostile input into silently-wrong bytes whose only symptom is an
opaque signature-verification failure — indistinguishable from a genuine
identity mismatch.

### Base64 (`signature`, and `nonce` on emission)

Standard RFC 4648 Base64 with the alphabet
`A–Z a–z 0–9 + /` and `=` padding. Encoders MUST emit canonical output; the
reference encoder is byte-identical to `java.util.Base64.getEncoder()`.

Decoders MUST reject:

| Rejected input | Example |
|----------------|---------|
| Length not a multiple of 4 | `"abc"` |
| Any character outside the alphabet | `"ab!d"` |
| Whitespace, newlines, or any embedded formatting | `"ab\ncd"` |
| URL-safe alphabet characters `-` and `_` | `"ab-d"`, `"ab_d"` |
| `=` anywhere other than the final quantum | `"ab=cdefg"` |
| More than two padding characters | `"A==="` |
| Non-canonical encodings — non-zero discarded bits in the final quantum | `"AB=="` |

Accepted edge cases: an empty or null string decodes to a zero-length array.
`"AA=="` (1 byte) and `"AAA="` (2 bytes) are canonical and valid.

**Scope note:** only `signature` is actually passed through the decoder during
the handshake. The `nonce` is signed and verified as its raw Base64 *string*
(see "L2 handshake" below) and never decoded, so the rules above constrain it
only on emission — a receiver does not validate an incoming nonce's encoding.
Implementations MUST still emit canonical Base64 for `nonce`, because the
signature is computed over the exact transmitted characters and any divergence
in encoding between two implementations breaks verification.

Note the last rejection rule: `"AB=="` is *not* valid even though every
character is in the alphabet and the length and padding are correct. The two
low bits of `B` are discarded by the 1-byte output length, and a canonical
encoder would never set them. Lenient decoders accept it; MeshLib does not.

### Hex (`peerId`, and every `from` / `to` / `peer` / `sender` field)

A PeerId on the wire is the lowercase hex encoding of the node's X.509
DER-encoded P-256 public key. Encoders MUST emit lowercase; decoders MUST accept
both cases.

Decoders MUST reject:

| Rejected input | Example |
|----------------|---------|
| Null or empty string | `""` |
| Odd length | `"abc"` |
| Any character outside `[0-9a-fA-F]` | `"abcg"` |
| Embedded whitespace or separators | `"ab cd"`, `"ab:cd"` |

There is no fixed length requirement — PeerId length follows the DER encoding of
the public key — but the string MUST be even-length and fully hex.

### Failure handling

A decode failure MUST NOT be silently absorbed:

- **During the L2 handshake** — the handshake fails and the link is closed. A
  peer that cannot present a well-formed nonce, signature, or PeerId is not
  admitted to the mesh.
- **On the L3 routing path** — the offending frame is dropped and the error
  logged. The link stays up: one malformed frame from one peer must not tear
  down a route that other peers depend on.

---

## L2 handshake

Both sides send `hello` simultaneously, then both send `proof`. The link is
usable only after signature verification succeeds on both ends.

```
1. →  {"type":"hello","peerId":"<hex>","nonce":"<base64>","appId":"<string>"}
   ←  {"type":"hello","peerId":"<hex>","nonce":"<base64>","appId":"<string>"}

2. →  {"type":"proof","signature":"<base64>"}
   ←  {"type":"proof","signature":"<base64>"}
```

- `nonce` — 16 random bytes, Base64 encoded.
- `signature` — `SHA256withECDSA` over the **other side's** nonce bytes, taken as
  the raw UTF-8 bytes of the received Base64 *string* (not the decoded nonce).
  This is a quirk worth calling out explicitly: implementations must sign the
  string as transmitted, not the bytes it decodes to.
- `appId` — optional. If **both** sides declare one and they differ, the
  handshake is rejected before signature exchange. A missing `appId` on either
  side acts as a wildcard and matches anything.
- Signature verification is against the public key recovered from the *claimed*
  `peerId`, which is what binds the PeerId to the key material.

Handshake timeout is 5000 ms (socket `SO_TIMEOUT`), cleared to infinite once the
handshake completes.

---

## Heartbeat

```
{"type":"heartbeat"}
```

Sent every 5000 ms. A link with no inbound data for 30000 ms is declared dead
and closed. Heartbeat frames are consumed by L2 and never surface to L3 or
above — but any inbound frame, heartbeat or not, resets the liveness timer.

---

## Versioning

The wire format is currently unversioned — no version field appears in any
frame. A version negotiation scheme is an open question (see `ARCHITECTURE.md`,
"Not yet decided / open") and must be settled before a second independent
implementation ships, since there is presently no in-band way for two nodes to
discover that they disagree about the format.
