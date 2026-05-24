# Vulos Peering Protocol — Versions

This document is the authoritative declaration of the **current** Vulos peering
wire-protocol version and the rules governing version changes. The protocol
itself is specified in [`PEERING.md`](PEERING.md).

---

## Current version

```
VULOS-PEER/1
```

- **Wire identifier:** the ASCII string `VULOS-PEER/1` (the `proto` field of the
  envelope header, see [`PEERING.md`](PEERING.md) §4).
- **Status:** STABLE. Implementations claiming peering support MUST implement
  `VULOS-PEER/1` exactly as specified.
- **Cipher suite:** `X25519-AESGCM-ED25519` (the only suite defined for v1; see
  [`PEERING.md`](PEERING.md) §5). The suite name is carried in the envelope so
  future versions can negotiate alternatives without ambiguity.

A peer advertises the protocol versions it supports in its peer descriptor
(see [`PEERING.md`](PEERING.md) §3). The sender selects the highest version both
sides support; if there is no overlap, the message MUST fall back to public SMTP
(or defer per local policy) — it is NEVER sent over peering with a guessed or
downgraded version.

---

## Versioning model

The peering protocol uses a single monotonic **major** integer carried in the
wire identifier (`VULOS-PEER/<N>`). There is no minor version on the wire: any
change that two independent implementations could observe differently is a major
bump. This keeps interoperation unambiguous — a node either speaks `VULOS-PEER/2`
or it does not.

Forward- and backward-compatibility is achieved by **negotiation**, not by
silently tolerating unknown fields:

- A receiver MUST reject an envelope whose `proto` it does not recognize.
- A receiver MUST reject an envelope whose `suite` it does not implement.
- Unknown fields in an otherwise-known version are NOT permitted; the canonical
  serialization (see [`PEERING.md`](PEERING.md) §6) is closed, so an extra field
  changes the signed bytes and fails verification. New fields require a version
  bump.

### When to bump the major version

Bump `VULOS-PEER/<N>` → `<N+1>` for ANY of:

1. A change to the envelope header fields, their order, or their canonical
   encoding.
2. A change to the cipher suite set, the AEAD construction, the KDF, or the
   signature algorithm.
3. A change to what bytes are covered by the sender signature, or to the
   transcript that binds the handshake.
4. A change to replay-protection semantics (nonce construction, timestamp
   window meaning, or the dedup contract).
5. A change to the abuse-prevention checks a conformant receiver MUST perform.

A new version MAY be introduced alongside the old one; nodes advertise the set
they support and negotiate per §3. Old versions are retired only after a
deprecation window announced here.

### What does NOT require a bump

- New peer-descriptor transport mechanisms (e.g. a new discovery method, such as
  the same-LAN multicast beacon of [`PEERING.md`](PEERING.md) §11.5) as long as
  the resolved descriptor shape is unchanged.
- New **payload sub-protocols** carried inside the envelope (e.g. the
  `VULOS-SYNC/1` box-to-box CRDT + blob sync of [`PEERING.md`](PEERING.md) §11):
  the envelope wire format is unchanged, so `VULOS-PEER` is unaffected. Sub-protocols
  carry their own independent version string (see below).
- Operational parameters that are local policy and never appear on the wire
  (timestamp skew tolerance bounds, dedup cache retention, retry backoff).
- Editorial clarifications to the spec that do not change conformant bytes or
  required behavior.

---

## Payload sub-protocol versions

Sub-protocols ride the §4 envelope payload and version **independently** of the
envelope `VULOS-PEER/<N>`. A receiver MUST reject a frame whose sub-protocol it
does not implement. Bumping a sub-protocol does not require bumping
`VULOS-PEER`, and vice versa.

| Sub-protocol | Status | Notes |
|---|---|---|
| `VULOS-SYNC/1` | STABLE | Box-to-box CRDT delta + content-addressed blob sync ([`PEERING.md`](PEERING.md) §11). Store-agnostic; same-LAN offline capable. |

---

## Version history

| Version | Status | Suite | Notes |
|---|---|---|---|
| `VULOS-PEER/1` | STABLE | `X25519-AESGCM-ED25519` | Initial published version. |

---

## Cross-references

- [`PEERING.md`](PEERING.md) — the full wire-protocol specification.
- [vulos-mail](https://github.com/vul-os/vulos-mail) — the receiving server side:
  a Vulos peer's inbound endpoint is fronted by the `vulos-mail` server, which
  injects a peered message into the recipient's mailbox after this protocol's
  receiver-side checks pass.
- The broader **Vulos fabric** (bucket transport) is the default carrier of v1
  envelopes between cloud-operated peers; the wire format is carrier-independent
  (see [`PEERING.md`](PEERING.md) §2).
