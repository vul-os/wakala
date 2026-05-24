# Vulos Peering Wire Protocol — `VULOS-PEER/1`

**Status:** STABLE · **Current version:** see [`VERSIONS.md`](VERSIONS.md)

This document specifies the Vulos-to-Vulos peering wire protocol: the format and
rules by which one Vulos relay hands a message directly to another Vulos relay
instead of delivering it over public SMTP. When both the sender and the
recipient are Vulos peers, the message travels over an authenticated, encrypted
transport that touches **no public DNS MX lookup and no blocklist surface** — it
is end-to-end between the two relays. Any recipient that is not a known Vulos
peer falls back to standard SMTP (see [the relay's sending path](../internal/sending/)).

> **Design intent — open federation.** This is a *published* protocol. Its
> security rests entirely on cryptography (public-key identity, AEAD, signed
> transcripts, replay windows), **never** on the protocol being secret or on a
> shared password. Any independent implementation that follows this document can
> stand up a node that peers with Vulos nodes. Interoperating against this spec is
> a supported goal, not an attack.

---

## 1. Roles and terminology

- **Peer** — a relay node identified by a long-term **Ed25519 identity key**.
  A peer is addressed by one or more mail **domains** it is authoritative for.
- **Sender peer** — the peer originating the handoff (this relay).
- **Receiver peer** — the peer authoritative for the recipient's domain.
- **Peer descriptor** — the resolved record describing how to reach a peer:
  endpoint, identity public key, supported protocol versions and cipher suites.
- **Envelope** — the on-wire unit: a header, an encrypted payload, and a sender
  signature. One envelope carries exactly one RFC 822 message for one or more
  recipients at the *same* receiver peer.
- **Carrier / transport** — the byte-moving substrate that conveys an envelope
  from sender to receiver (the Vulos fabric/bucket transport, a direct TLS
  stream, or, in tests, an in-memory loopback). The wire format is
  **carrier-independent**; this spec defines the envelope, not the socket.

MUST / SHOULD / MAY are used per RFC 2119.

---

## 2. Transport independence

The envelope (§4) is a self-contained, authenticated, encrypted blob. Its
security does NOT depend on the carrier providing confidentiality or
authentication. The same envelope bytes are valid whether delivered over:

- the **Vulos fabric/bucket transport** (the default for cloud-operated peers —
  the sender writes the envelope to a per-receiver bucket lease the receiver
  drains), or
- a direct connection, or
- an in-memory loopback (used by the reference implementation's tests).

Because the envelope is independently authenticated and encrypted, a hostile or
merely curious carrier can neither read the message nor forge, reorder-to-replay
(see §7), or alter an envelope without detection. This is what lets peering
**bypass** public SMTP, DNS, and blocklists: trust is established by keys, not by
the network path.

---

## 3. Peer resolution and discovery

Before a handoff, the sender must learn whether the recipient's domain is a
Vulos peer and, if so, obtain its **peer descriptor**.

A peer descriptor contains:

| Field | Meaning |
|---|---|
| `domains` | the mail domains this peer is authoritative for |
| `identity_pub` | the peer's long-term Ed25519 public key (32 bytes, base64url) |
| `kex_pub` | the peer's long-term X25519 key-agreement public key (32 bytes, base64url) |
| `versions` | the set of `VULOS-PEER/<N>` protocol versions supported |
| `suites` | the cipher suites supported (v1: `X25519-AESGCM-ED25519`) |
| `endpoint` | the carrier address (opaque to this spec; e.g. a fabric bucket id or a `host:port`) |

### 3.1 Resolution sources (in precedence order)

1. **Local peer registry.** An operator- or control-plane-provided mapping from
   domain → descriptor. This is the authoritative, fastest source and the one
   the Vulos cloud uses to wire its tenants together. The reference
   implementation ships a `StaticResolver` over an in-memory registry.

2. **DNS-published descriptor (open-federation path).** A domain advertises
   peering via a DNS `TXT` record at `_vulos-peer.<domain>`:

   ```
   _vulos-peer.example.org.  IN TXT  "v=vulos-peer1; k=<base64url ed25519 pub>; ep=<endpoint>; suites=X25519-AESGCM-ED25519"
   ```

   The `k=` identity key is the trust anchor. DNS is used only for *discovery*;
   it is **not** a security boundary. A descriptor learned over DNS is only
   trusted up to its identity key, and that key is then **pinned** (see §3.2). An
   attacker who forges the DNS record can cause a fallback or a denial of
   handoff but cannot impersonate an already-pinned peer, and cannot read or
   forge messages, because every envelope is signed by and encrypted to the
   pinned identity key.

A domain that resolves to no descriptor in any source is **not a peer**; mail to
it takes the SMTP fallback path. Resolution results (including negative results)
are cached with a TTL by the caller (the router), so the per-message decision is
cheap.

### 3.2 Key pinning and rotation

The first time a peer's identity key is seen for a domain, it is **pinned**
(trust-on-first-use, anchored by the local registry where present). Subsequent
resolutions for that domain MUST present the pinned key, or be signed in a way
that chains to it. Key rotation is performed by the receiver publishing a new
identity key **signed by the outgoing key** (a rotation attestation); a sender
that holds the old pinned key can verify the rotation and re-pin. Unsigned key
changes MUST be treated as a resolution failure (defer / fall back per policy),
never silently accepted. The registry path lets the control plane rotate keys
out-of-band without TOFU concerns.

---

## 4. Envelope format

An envelope is a single byte string with three top-level parts, in this order:

```
envelope := header || payload || signature
```

The exact framing on the wire is the **canonical serialization** of §6. All
multi-byte integers are big-endian. All keys/nonces/tags are raw bytes in the
serialization (the table below shows base64url only for human/DNS contexts).

### 4.1 Header (signed, cleartext)

The header is authenticated by the sender signature (§5.4) but NOT encrypted —
the receiver needs it to route, identify the sender, and derive the decryption
key before it can open the payload.

| # | Field | Type | Description |
|---|---|---|---|
| 1 | `proto` | string | protocol id, exactly `VULOS-PEER/1` |
| 2 | `suite` | string | cipher suite, exactly `X25519-AESGCM-ED25519` |
| 3 | `sender_domain` | string | the MAIL FROM domain the sender claims authority for |
| 4 | `sender_identity_pub` | 32 bytes | sender peer's Ed25519 identity public key |
| 5 | `receiver_kex_pub` | 32 bytes | receiver peer's X25519 key-agreement public key (from the resolved descriptor) |
| 6 | `ephemeral_pub` | 32 bytes | sender's per-envelope X25519 ephemeral public key |
| 7 | `nonce` | 12 bytes | per-envelope AEAD nonce (also the replay key, §7) |
| 8 | `timestamp` | int64 | sender's Unix-seconds UTC clock at envelope creation |
| 9 | `mail_from` | string | RFC 5321 envelope sender |
| 10 | `rcpt_to` | []string | RFC 5321 envelope recipients (all at the receiver peer) |

### 4.2 Payload (encrypted)

The payload is the AEAD ciphertext (AES-256-GCM) of the raw RFC 822 message
(`payload = AEAD-Seal(key, nonce, raw_rfc822, aad=header_bytes)`; see §5). The
GCM authentication tag is appended to the ciphertext, so the payload also binds
the entire header as associated data — the header cannot be altered without
breaking decryption.

### 4.3 Signature

A 64-byte Ed25519 signature by the sender's identity key over the canonical
**header bytes concatenated with the payload** (§5.4). This proves the envelope
was produced by the holder of `sender_identity_pub` and binds the encrypted
payload to that identity.

---

## 5. Cryptography — suite `X25519-AESGCM-ED25519`

All primitives are standard, public, and available in the Go standard library
(no CGO):

- **Identity / authentication:** Ed25519 (`crypto/ed25519`).
- **Key agreement:** X25519 ECDH (`crypto/ecdh`), ephemeral-static for forward
  secrecy.
- **KDF:** HKDF-SHA-256 (HMAC-SHA-256 extract/expand, `crypto/hmac` + `crypto/sha256`).
- **AEAD:** AES-256-GCM (`crypto/aes` + `crypto/cipher`), 96-bit nonce, 128-bit tag.

### 5.1 Key agreement

The sender generates a fresh X25519 ephemeral keypair per envelope. The shared
secret is:

```
ss = X25519(ephemeral_priv_sender, receiver_kex_pub)
```

`receiver_kex_pub` is the receiver's long-term X25519 key-agreement key,
published in its peer descriptor (§3) alongside the Ed25519 identity key. A peer
therefore holds two long-term keys: Ed25519 for *identity/signing* and X25519
for *key agreement*. Keeping the two algorithms in distinct keys avoids any
Edwards→Montgomery conversion and keeps the construction within widely-available
standard primitives. The receiver recomputes the same `ss` with
`X25519(receiver_kex_priv, ephemeral_pub)`.

> Using an ephemeral sender key against the receiver's static key gives **forward
> secrecy for the sender's compromise**: capturing the sender's long-term key
> later does not decrypt past envelopes, because the ephemeral private key is
> discarded after sealing.

### 5.2 Key derivation

```
key = HKDF-SHA256(
        ikm  = ss,
        salt = nonce,
        info = "VULOS-PEER/1 X25519-AESGCM-ED25519" ||
               sender_identity_pub || receiver_kex_pub,
        len  = 32)
```

Binding both identity keys and the protocol/suite label into `info` makes the
derived key a **transcript** of who is talking to whom under which version —
preventing cross-protocol and identity-substitution attacks. Using the envelope
`nonce` as the HKDF salt domain-separates every envelope's key.

### 5.3 AEAD

```
payload = AES-256-GCM-Seal(key, nonce, raw_rfc822, aad = canonical(header))
```

The header is the AEAD associated data, so any tampering with routing fields,
timestamp, or keys is detected on open.

### 5.4 Signature

```
signature = Ed25519-Sign(sender_identity_priv,
                         canonical(header) || payload)
```

The receiver verifies with `sender_identity_pub` from the header. Signing covers
both the cleartext header and the ciphertext payload, binding all envelope parts
to the sender identity.

---

## 6. Canonical serialization

To make the signed and AAD-covered bytes unambiguous across implementations, the
header has exactly one canonical encoding:

- Fields are emitted in the numeric order of the §4.1 table, with no extra
  fields and none omitted.
- Each `string` and each byte field is length-prefixed with a big-endian
  `uint16` length followed by the raw bytes (UTF-8 for strings).
- `rcpt_to` is encoded as a `uint16` count followed by each recipient as a
  length-prefixed string, in the order supplied.
- `timestamp` is a big-endian `int64`.
- Fixed-width keys/nonces (32 / 12 bytes) are length-prefixed too, so the parser
  is uniform; a receiver MUST reject a field whose length is not the value
  required for that field.

Because the encoding is closed and order-fixed, an envelope with an unknown or
extra field cannot round-trip — which is exactly why new fields force a version
bump (see [`VERSIONS.md`](VERSIONS.md)). The full envelope on the carrier is:

```
canonical(header) || uint32(len payload) || payload || signature(64 bytes)
```

---

## 7. Replay protection

Each envelope carries a unique 96-bit `nonce` (§4.1 field 7) and a `timestamp`
(field 8). The receiver MUST enforce **both**:

1. **Timestamp window.** Reject any envelope whose `timestamp` is outside an
   acceptance window of the receiver's clock (default ±300 s; an operational
   parameter, not a wire field). This bounds how long a captured envelope is
   replayable and bounds the size of the dedup cache.

2. **Nonce dedup.** Within the acceptance window, the receiver keeps a cache of
   `(sender_identity_pub, nonce)` pairs it has already accepted and MUST reject a
   second envelope with the same pair. Entries are retained for at least the
   width of the acceptance window, after which the timestamp check alone rejects
   any re-presentation. Keying the cache by sender identity prevents one peer's
   nonce choices from colliding with another's.

A replayed envelope (same sender + same nonce, or a too-old timestamp) MUST be
rejected with a permanent `replay` outcome and MUST NOT be re-injected into the
recipient's mailbox. The nonce doubling as the AEAD nonce (§5.3) and the HKDF
salt (§5.2) means nonce reuse also breaks the cryptographic construction, so the
two protections reinforce each other.

#### §7 note — single `ReplayGuard` per receiver box (operator guidance)

The Go reference implementation exposes the §7 dedup window as
`peering.ReplayGuard` (one instance backs the `(sender_identity_pub, nonce)`
cache). Operators wiring multiple inbound handlers on one box (e.g. the sync
sub-protocol `SyncTransport.HandleEnvelope`, the stream sub-protocol
`StreamRelay.HandleEnvelope`, the reputation receiver, and any future
sub-protocol) MUST share a **single `ReplayGuard` instance** across every
handler that opens envelopes addressed to that box's identity — including the
handler that opens replies to envelopes this box originally sent.

For store-and-forward carriers (the fabric/bucket), a request and its eventual
reply arrive as two independent inbound envelopes on the asker's box. If the
reply-open path is wired to a separately-constructed `ReplayGuard`, the box
runs two independent §7 windows; a replayed envelope rejected by one window
can still pass the other, silently weakening replay protection. The in-process
`LoopbackSyncTransport` opens the reply with the asker's own guard for exactly
this reason — but that is a test/loopback property, not a license to wire two
guards in production.

This applies symmetrically to the responder: the SAME guard the responder uses
to open inbound requests must also be the guard used by any other handler on
the same box that opens envelopes from the same peer fleet.

---

## 8. Open-relay / abuse prevention at the peer boundary

The relay's global rule is that it NEVER forwards mail for an unknown sender.
Peering adds these receiver-side checks, all of which a conformant receiver MUST
perform **before** injecting a peered message:

1. **Sender authentication.** The Ed25519 signature (§5.4) MUST verify against
   `sender_identity_pub`. A failed signature → reject (`unauthenticated`).

2. **Sender-domain authority.** `sender_identity_pub` MUST be the pinned/resolved
   identity key for `sender_domain` (§3.2), and the `mail_from` address's domain
   MUST equal `sender_domain`. This binds the message to a peer that is
   demonstrably authoritative for the claimed origin domain — a peer cannot
   originate mail for a domain it does not own. Mismatch → reject (`unauthorized`).

3. **Receiver targeting.** `receiver_kex_pub` MUST equal the receiver's own
   key-agreement key, and every `rcpt_to` domain MUST be one this receiver is
   authoritative for. This stops a third party from using one peer as an open
   relay to another. Mismatch → reject (`misrouted`).

4. **Replay window.** §7 MUST pass.

5. **Decryption integrity.** The AEAD open MUST succeed (which also re-verifies
   the header as AAD). Failure → reject (`corrupt`).

Only after ALL checks pass is the message handed to the receiver's mailbox
(via [vulos-mail](https://github.com/vul-os/vulos-mail)). Because authority is
proved by signature over a pinned key — not by IP, not by a shared secret, not by
the protocol being private — an open federation of independent peers can apply
these exact checks and remain mutually safe.

---

## 9. Version negotiation

1. The sender resolves the receiver's descriptor (§3) and reads its `versions`
   and `suites`.
2. The sender selects the **highest** `VULOS-PEER/<N>` both support, and a suite
   both support. For v1 the only suite is `X25519-AESGCM-ED25519`.
3. The selected `proto` and `suite` are written into the envelope header and are
   covered by the signature, so a downgrade cannot be injected by the carrier
   without breaking verification.
4. If there is **no** common version or suite, the message MUST NOT be sent over
   peering. It falls back to public SMTP, or defers, per local routing policy
   (see [the router](../internal/relay/)) — it is never sent with a guessed
   version.
5. A receiver MUST reject an envelope whose `proto` or `suite` it does not
   implement (`unsupported`), rather than attempt a best-effort parse.

---

## 10. Failure handling and SMTP fallback

Peering is one branch of the send pipeline. The fallback contract:

- **Recipient is not a peer** (no descriptor resolved) → route to SMTP. This is
  the normal, seamless fallback for the whole non-Vulos internet.
- **Mixed recipients** (some peers, some not) → the message is split per
  receiver peer / SMTP domain and each part takes its own path.
- **A peer handoff fails** after the recipient *was* resolved as a peer (carrier
  error, handshake/version mismatch, transient receiver rejection) → the message
  **defers/retries on the peer path** by default. It MUST NOT silently downgrade
  onto public SMTP without explicit policy, because doing so would leak a
  peer-internal message onto the public, blocklist-exposed path.
- **A permanent receiver rejection** (`unauthorized`, `misrouted`, `replay`,
  `unsupported`) → classified as bounced; no SMTP retry.

---

## 11. Sync sub-protocol — `VULOS-SYNC/1` (box-to-box CRDT + blob sync)

This section specifies an **opt-in payload sub-protocol** that rides the envelope
of §4 to converge two Vulos boxes' CRDT index and content-addressed blobs
directly over the fabric — including two boxes on the **same LAN with the internet
down**. It is a *payload* format: it does **not** change the envelope wire format
of §4–§6, so `VULOS-PEER/1` is unchanged. A sync message is marshaled into a
`VULOS-SYNC/1` frame and placed in the envelope payload slot (where a mail
message would otherwise go); the envelope's existing AEAD, Ed25519 signature, and
§7 replay window protect it. This mirrors the reputation side-channel
(`internal/peering/reputation.go`): a new message type carried over the existing
transport, with no new crypto and no envelope-format change.

### 11.1 Versioning

`VULOS-SYNC/<N>` is a **payload-level** version, independent of the envelope
`VULOS-PEER/<N>`. It is the first string field of every sync frame. A receiver
MUST reject a frame whose sub-protocol it does not implement. Bumping
`VULOS-SYNC` does NOT require bumping `VULOS-PEER` and vice versa — they evolve
separately. The current sync version is `VULOS-SYNC/1`.

### 11.2 Store-agnostic model

The transport is **store-agnostic**. The CRDT merge logic and the content store
live in the application (vulos-mail / vulos-office); this layer only moves bytes
between two stores via a small interface (`relay.SyncStore`):

| Concept | Wire shape | Meaning |
|---|---|---|
| **Version vector** | opaque bytes | a store-defined summary of history held. The transport never interprets it. |
| **Delta range** | `from` (opaque VV) + opaque bytes | one store-encoded chunk of CRDT history advancing a peer past `from`. |
| **Blob** | `hash` + `content` | a content-addressed object; `hash` is the store's addressing scheme (e.g. SHA-256). |

### 11.3 Message types and frame format

A frame is `len16(proto="VULOS-SYNC/1") || type(1 byte) || body`, where every
sub-field is length-prefixed big-endian, matching §6's codec style:

| Type | Name | Direction | Body |
|---|---|---|---|
| 1 | `pull` | A→B | the asker's opaque version vector |
| 2 | `deltas` | B→A | count + (`from`, delta-bytes)\* the asker is missing |
| 3 | `blob_req` | A→B | count + content-addressed hashes the asker lacks |
| 4 | `blob_resp` | B→A | count + (hash, content)\* |

One convergence leg is: A sends `pull(VV_A)`; B replies `deltas`; A applies them
(idempotently) and learns which referenced blob hashes it lacks; A sends
`blob_req`; B replies `blob_resp`. Leaderless convergence runs this leg in both
directions (or on a timer).

### 11.4 Idempotency and rendezvous compatibility

`ApplyDeltas` MUST be idempotent: applying the same delta(s) more than once leaves
the store unchanged beyond the first application. Because deltas are requested
relative to a version vector and applied idempotently, re-sync, retries, and a
separate **central-rendezvous** path (a node draining the same deltas from a
shared bucket) all compose without double-apply. The peering §7 replay window
still rejects a replayed *envelope*; idempotent apply additionally guarantees a
replayed *delta* (arriving via a different envelope or carrier) is a no-op.

### 11.5 Same-LAN discovery (offline)

Two boxes on one LAN find each other with an mDNS-style **UDP multicast beacon**
(admin-scoped, link-local), so they sync with no internet and no central
rendezvous. A beacon advertises enough to build a peer descriptor (§3): domain,
Ed25519 identity key, X25519 kex key, and an endpoint. As with the DNS path
(§3.1), the beacon's **identity key is the only trust anchor and is pinned**
(§3.2): a forged beacon can deny sync but can never impersonate a pinned peer or
read/forge a frame, because the handshake remains the pinned-key peering crypto.
Discovery only learns descriptors; per [`VERSIONS.md`](VERSIONS.md) a new
discovery method does **not** change the wire format.

---

## 12. Cross-references

- [`VERSIONS.md`](VERSIONS.md) — current version + version-bump rules.
- [`../internal/peering/`](../internal/peering/) — the Go reference
  implementation of this protocol (envelope sealing/opening, resolver, transport,
  and the `Sender` peer branch).
- [vulos-mail](https://github.com/vul-os/vulos-mail) — the receiving Vulos mail
  server that injects a successfully-peered message into the recipient mailbox
  after the §8 checks pass.
- The broader **Vulos fabric** provides the default bucket carrier (§2); the
  envelope format here is deliberately carrier-independent so the same protocol
  works over the fabric, a direct stream, or test loopback.
