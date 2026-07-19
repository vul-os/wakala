# Pinning — durable retention of public objects

Pinning is the **durability half** of the cache/pin substrate role: a node
**retains** public, content-addressed objects on disk, deliberately and
indefinitely, instead of holding them only as long as they happen to be popular.

`vulos-relayd` is a **reference implementation** (`tunnel/pubcache`), but this
document is the *role*, not the product. It is part of the DMTAP substrate's
[infrastructure roles](https://github.com/vul-os/dmtap) (`substrate/ROLES.md` § 6)
over the DMTAP-PUB public-object profile (§ 22.2, § 22.5.1, § 5.5.2). **Any node
may serve it.** A Vulos-operated pin service is just a well-run instance of this
code; a self-hoster runs the identical binary with the identical guarantees and
no billing in it at all.

> **Why the role exists:** availability in a decentralised network is
> **emergent**. A content address is *a name, not a promise* (§ 5.5.1) — an
> object is available exactly as long as some holder serves it, and an object
> nobody holds is **gone**. Durability is not a property of the address; it is
> **bought** by pinning, an explicit act with a real storage cost (§ 5.5.2). A
> pin-capable holder is what makes "your data survives" a true sentence.

---

## 1. A pin is not a cache entry

The [cache](PUBCACHE.md) answers *"did someone ask for this recently?"* and is
free to forget — eviction there is not a loss, it is this node ceasing to be one
of the holders (§ 22.6.2). A pin answers *"did an operator promise to keep
this?"* and must not forget.

|  | Cache | Pin |
|---|---|---|
| Storage | memory | disk |
| Lifetime | LRU + TTL | until explicitly unpinned |
| Under memory/disk pressure | evicted | **never evicted** |
| Survives restart | no | **yes** |
| Budget | `-pubcache-max-bytes` | `-pubcache-pin-max-bytes` (separate) |
| When full | evicts something | **refuses, with a typed error** |
| Written by | reads passing through | an explicit, **signed** request |

These are two separate stores that share **no bytes, no byte cap, and no code**.
That is the whole reason *"cache pressure can never evict a pin"* is trustworthy:
it is not a policy someone has to remember to honour, it is that pinned objects
are not in the cache's data structure at all, so nothing in its eviction path can
reach them.

**Pins take precedence on reads.** A pinned copy is served from disk before the
cache — and before any upstream — is consulted. Falling through to the cache
first would mean a TTL expiry could send a request to the swarm for an object
this node is holding on its own disk.

---

## 2. What gets pinned

You pin a **root object**, and the node pins everything that root needs:

- **`announce`** — a `PubAnnounce` (§ 22.3). One object.
- **`manifest`** — a `PubManifest` (§ 22.2.1) **plus every chunk it names.**

Recursive chunk pinning is not a convenience. A manifest without its chunks is a
list of hashes for bytes nobody holds, which is exactly the situation pinning
exists to prevent. It is **all-or-nothing**: if any chunk cannot be retrieved and
verified, the whole pin fails and every byte already written is rolled back.

Chunks **cannot be pinned on their own** (`bad_kind`). A chunk is pinned as part
of the manifest that gives it meaning, so a pin is always a complete,
self-contained, servable object.

**Deduplication is free and automatic.** Objects are content-addressed, so two
pins sharing chunks share the bytes on disk, and the budget counts **unique**
stored bytes. Retention is *derived* from the pin index on every mutation rather
than tracked as a refcount — derived state cannot drift the way a hand-maintained
counter can. Unpinning one of two pins that share a chunk keeps the chunk.

---

## 3. Verification — the same mandatory gate, and it matters more here

Nothing reaches the pin store without passing the [verification
gate](PUBCACHE.md#3-verification--the-mandatory-gate): announces and chunks by
their BLAKE3-256 anchor hash, manifests by the recomputed **DS-tagged RFC 6962
Merkle root** over their plaintext chunk hashes, plus the key-5 trap and self-`id`
agreement.

It matters more here than in the cache for a simple reason: **a cached lie dies
at restart; a persisted one does not.**

### Restart strategy: verify lazily, on first serve

On start the node reads its index and **stats** the object files. It does **not**
rehash them. The content check happens on the **first serve of each object in a
process lifetime**, and the result is remembered for that lifetime.

Rehashing everything at boot was considered and rejected. It would make startup
time proportional to pinned volume — a node holding a few hundred GB would spend
minutes of disk I/O before it could answer *any* request, including for the roles
that have nothing to do with pinning — and it would pay that cost on every
restart, to detect corruption slightly earlier than the path that actually
matters.

Lazy verification gives up nothing, because the invariant is not *"the disk is
known-good"*. It is:

> **Nothing is ever served unverified.**

That holds either way: an object is hashed before its first byte reaches a
client. Bitrot, a truncated write, or tampering by someone with disk access is
caught at exactly the moment it would otherwise do harm. When it is caught:

1. the object file is **deleted**;
2. **every pin that referenced it is dropped** — this node can no longer honour
   those pins, and saying so is the honest answer;
3. the index is rewritten so the damage is not rediscovered every restart;
4. the client gets the ordinary `404` refusal (`ERR_PUB_NOT_SERVED`, `0x090C`)
   and rotates to another holder;
5. the operator gets a loud `ERROR` log line and a `corrupted` counter.

**A pin whose objects are not all present at startup is dropped**, and its
orphaned bytes reclaimed. A pin that cannot be served in full is not a pin, and
honouring it would mean claiming durability the node cannot deliver.

### Durability of the writes themselves

Objects and the index are both written **temp file → `fsync` → atomic rename**
(and the directory is `fsync`ed after the index rename). A crash mid-write leaves
either the old state or the new one — never a partial file under a content
address, and never a half-parsed index.

---

## 4. Budget — refusal, never eviction

This is the part that kept the role unimplemented until it could be done
honestly. A pin store with a soft budget is not a pin store.

Three hard bounds, all operator-configured:

| Bound | Flag | Default | Purpose |
|---|---|---|---|
| Total unique bytes | `-pubcache-pin-max-bytes` | 1 GiB | the disk you are willing to spend |
| One pin | `-pubcache-pin-max-pin-bytes` | 256 MiB | one blob cannot take the whole budget |
| Pin count | `-pubcache-pin-max-pins` | 10000 | bounds index size and startup cost independently of bytes |

A per-object cap also applies, defaulting to the cache's `-pubcache-max-object-bytes`.

When a bound would be exceeded the request is **refused**:

```
HTTP/1.1 507 Insufficient Storage
{"error":"pin_budget_exceeded","message":"pubcache: pin budget exceeded: 1073741824 of 1073741824 bytes used, this pin needs 4096 more"}
```

`507` is the honest status: the request was valid and the node simply has no
room. **Nothing was evicted to make some.** Silently dropping an existing pin to
admit a new one is the one failure mode that would make the whole durability
claim a lie, so it is not implementable here — there is no eviction code in the
pin store to call.

Budget is checked **incrementally as each object is written**, so an oversized
pin is refused after one object rather than after buffering a multi-gigabyte blob
in memory, and everything already written is rolled back.

---

## 5. The wire protocol

Mounted under the cache's prefix (default `/.well-known/dmtap-pub`).

| Method | Path | Auth | Meaning |
|---|---|---|---|
| `POST` | `{p}/pin` | **signed** | durably retain a root object and its chunk set |
| `POST` | `{p}/unpin` | **signed** | release a pin; reclaim unreferenced bytes |
| `GET` | `{p}/pins` | public | what this holder durably retains |
| `GET` | `{p}/pins/status` | public | usage vs budget, and the counters |
| `GET` | `{p}/announce/{id}`, `{p}/manifest/{id}`, `{p}/chunk/{h}` | public | **unchanged** — pinned objects serve through the ordinary § 22.5.1 read surface |

Pinned objects need no new read endpoint and get no special headers: they are
served by the same content-addressed reads, with the same `immutable` caching and
the same strong `ETag`, and the § 5.3 **range-proof endpoint works over them**
identically. A reader cannot tell — and should not care — whether a holder's copy
is pinned or cached. That is the point of content addressing.

### 5.1 Why writes are signed and reads are not

§ 22 reads are **anonymous by protocol requirement**: a public object is public,
and a holder demanding identity to serve one would be adding a gate the spec does
not have. Reads of pinned content are therefore exactly as open as before.

A write is different in kind. `pin` spends the operator's **disk, durably**, and
disk is the scarce thing this role costs. An unauthenticated pin endpoint is a
remote *"fill this disk"* primitive. So writes carry the same signed-request
discipline as the [rendezvous role's](RENDEZVOUS.md) writes, via the shared
`tunnel/internal/keyauth` — one implementation, so the two surfaces cannot drift
apart.

### 5.2 Request format

```jsonc
POST /.well-known/dmtap-pub/pin
{
  "key":  "<base64url Ed25519 public key>",
  "kind": "manifest",              // or "announce"
  "addr": "<base64url content address>",
  "nonce": "<base64url random, >= 16 bytes recommended>",
  "ts":   1784500000,              // unix seconds
  "sig":  "<base64url Ed25519 signature>"
}
```

`unpin` is byte-identical in shape, under a different domain tag.

### 5.3 Canonical signing message

The signature covers a **domain-separated, length-prefixed** byte string. For the
domain tag and then each field in order, write `uint32be(len(utf8(s)))` followed
by `utf8(s)`:

```
domain  = "vulos-pub/pin/1"      (pin)
        | "vulos-pub/unpin/1"    (unpin)

message = seg(domain) ‖ seg(key) ‖ seg(decimal(ts)) ‖ seg(nonce) ‖ seg(kind) ‖ seg(addr)
where seg(s) = uint32be(len(s)) ‖ s
```

Length-prefixing means no delimiter can be forged across field boundaries. The
**domain tag** means a signature minted for `pin` can never be replayed as
`unpin` — without it, a captured pin request would be a deletion primitive.

### 5.4 Freshness and replay

A request is accepted only if its `ts` is within **±5 minutes** of the node's
clock (configurable via the `PinClockSkew` config field) **and** its `(key, nonce)`
pair has not been seen inside that window. A stale or replayed request is `409`.
The nonce set is bounded and self-expiring.

### 5.5 Authorisation

A valid signature proves *who* is asking, never that they *may*. Authorisation is
an operator-configured **allowlist** of pinner keys:

```bash
-pubcache-pin-keys <base64url-key>,<base64url-key>
```

It is **empty by default**, so a node that turns on durable pinning without naming
anyone still refuses every write (`403 pin_not_authorized`) while continuing to
serve the pins it already holds. Enabling storage must never imply enabling
anyone to fill it. A malformed key in the list is a **startup error**, not a
silently dropped entry — an operator must never believe a key is authorised when
it is not.

**Ownership:** any authorised key may pin, but **only the key that created a pin
may remove it** (`403 pin_not_owned`). Otherwise one tenant's authorisation would
be a delete button on another tenant's durability.

### 5.6 Error codes

| HTTP | `error` | Meaning |
|---|---|---|
| `400` | `bad_request` / `bad_key` / `bad_kind` / `bad_addr` | malformed input |
| `401` | `bad_signature` | signature did not verify |
| `409` | `stale_or_replayed` | timestamp outside the window, or nonce reused |
| `403` | `pin_not_authorized` | key is not on the operator's allowlist |
| `403` | `pin_not_owned` | pin belongs to another key |
| `404` | `pin_not_found` | no such pin |
| `404` | `object_not_retrievable` | the object could not be obtained verifiably |
| `422` | `object_failed_verification` | bytes do not match the content address |
| `507` | `pin_budget_exceeded` | out of budget — **nothing was evicted** |
| `501` | `pin_disabled` | this holder does not offer durable pinning |

---

## 6. Usage counters (what a billing layer reads)

```bash
curl https://relay.example.com/.well-known/dmtap-pub/pins/status
```

```jsonc
{
  "role": "dmtap-pub-pin",
  "authorized_keys": 3,
  "usage": {
    "pins": 42, "objects": 918,
    "bytes": 4204951552, "max_bytes": 10737418240,
    "available_bytes": 6532466688,
    "pinned": 51, "unpinned": 9, "refused": 2,
    "hits": 88213, "corrupted": 0, "dropped": 0
  }
}
```

These counters are **all** this daemon does about cost. Metering, pricing, and
charging live in the control plane; putting any of them here would make
self-hosting the same code impossible, and the role is only credible if the
self-hosted binary is the identical one. The `-pubcache-pin-keys` allowlist is
the seam a billing layer drives: a control plane adds a key when storage is
bought and removes it when it is not. Nothing in this package knows what any of
that costs.

The `/healthz` endpoint reports the pin block **separately** from the cache
totals, never folded into one number — an operator must be able to tell how much
of their disk is a durability promise and how much is scratch they may lose at
any moment.

---

## 7. Honest limits

1. **Pinning is not a takedown mechanism, in either direction** (§ 22.6.2). There
   is no protocol way to compel a holder to serve, or to compel one to stop. Each
   holder applies its own serve policy and may decline any object.
2. **A pin is one holder's promise, not the network's.** Durability across holder
   failure is **replication** — pin the same object at several independent
   holders. This node can guarantee only its own copy.
3. **Pinned public objects are plaintext the operator can read** (§ 22.6.1), the
   same liability posture as the cache, and the reason the whole role is opt-in.
   Unlike the tunnel, mailbox, and rendezvous roles, this one is **not
   content-blind**.
4. **The budget is bytes, not time.** This node makes no promise about *how long*
   it will keep a pin; an operator may unpin, and § 22.6.2 makes that always a
   holder's right. Nothing here is a contract.
5. **Publication is irrevocable.** Unpinning removes *this* holder's copy. It does
   not un-publish anything: a public object persists as long as *any* holder
   serves it (`substrate/FEEDS.md` § 8).

---

## 8. Configuration reference

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `-pubcache-pin-dir` | `VULOS_RELAY_PUBCACHE_PIN_DIR` | *(none)* | enable durable pinning rooted here |
| `-pubcache-pin-keys` | `VULOS_RELAY_PUBCACHE_PIN_KEYS` | *(none)* | keys allowed to pin/unpin |
| `-pubcache-pin-max-bytes` | `VULOS_RELAY_PUBCACHE_PIN_MAX_BYTES` | 1 GiB | hard total budget |
| `-pubcache-pin-max-pin-bytes` | `VULOS_RELAY_PUBCACHE_PIN_MAX_PIN_BYTES` | 256 MiB | per-pin cap |
| `-pubcache-pin-max-pins` | `VULOS_RELAY_PUBCACHE_PIN_MAX_PINS` | 10000 | maximum distinct pins |

Pinning requires `-pubcache` (the role) and is off until `-pubcache-pin-dir` is
set. Example:

```bash
vulos-relayd -domain relay.example.com \
  -pubcache \
  -pubcache-upstreams https://gw1.example.org,https://gw2.example.org \
  -pubcache-pin-dir /var/lib/vulos-relayd/pins \
  -pubcache-pin-keys tHqZ...,9fKp... \
  -pubcache-pin-max-bytes 107374182400
```

### On-disk layout

```
/var/lib/vulos-relayd/pins/
  index.json                      # the pin index (atomically rewritten)
  objects/
    manifest/Ht/HtelWGjHhGwe...   # content-addressed, sharded by address prefix
    chunk/Hn/HnuthoGzCJ8a...
    announce/Hj/Hj0TGflGbGuw...
```

Object files are named by their **canonical content address** (unpadded
base64url, which contains no `/` and no path component), sharded two characters
deep so no directory grows to millions of entries. The index is authoritative for
what is retained; anything on disk it does not name is swept at startup.

---

## 9. Related

- **[docs/PUBCACHE.md](PUBCACHE.md)** — the caching half of this role, the
  verification gate, and the § 22.5.1 read surface pinned objects are served
  through.
- **[docs/RENDEZVOUS.md](RENDEZVOUS.md)** — the sibling reachability role, whose
  signed-write discipline this shares.
- **[docs/SECURITY.md](SECURITY.md)** — what a relay operator can and cannot see.
- DMTAP `substrate/ROLES.md` § 6 (the role), `22-public-objects.md` § 22.2 / § 22.5
  / § 22.6 (the objects, their verification, and the serve-policy posture),
  § 5.5.1–5.5.2 (a name is not a promise; durability is bought).
