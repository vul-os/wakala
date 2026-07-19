package pubcache

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// pin.go — the PIN half of the cache/pin role (substrate/ROLES.md § 6):
// DURABLE retention of DMTAP-PUB public objects.
//
// ── Why this is a separate store, not a cache mode ──────────────────────────
//
// A cache and a pin answer different questions. The cache answers "did someone
// ask for this recently?" and is free to forget — eviction there is not a loss,
// it is this node ceasing to be one of the holders (§ 22.6.2). A pin answers
// "did an operator promise to keep this?" and MUST NOT forget: availability in
// a decentralised network is emergent, so an object no holder retains is simply
// gone (§ 5.5.1 — a content address is a name, not a promise; § 5.5.2 —
// durability is BOUGHT by pinning, an explicit act with a real storage cost).
//
// So the two live in different stores with different accounting, and that
// separation is structural rather than a policy flag:
//
//   - the LRU (store.go) holds soft state in memory, evicts under pressure, and
//     never sees a pinned object;
//   - the pin store (here) holds bytes on disk, has its OWN byte budget, and has
//     NO eviction path at all. Cache pressure cannot reach it, because the two
//     stores share no bytes, no cap, and no code.
//
// A pin is therefore refused when the budget is full (ErrPinBudget, a typed
// refusal the caller can act on) rather than silently making room. Silently
// dropping a pin to admit another would be the one failure mode that makes the
// whole durability claim a lie, so it is not implementable here.
//
// ── The verification discipline is unchanged ────────────────────────────────
//
// Nothing reaches this store without passing Verify (verify.go) — the same
// mandatory gate the cache uses, including DS-tagged Merkle-root recomputation
// for manifests. Persisting bytes that do not match their content address would
// be strictly worse than caching them, because the lie would survive a restart.
//
// ── Restart strategy: verify LAZILY, on first serve ─────────────────────────
//
// On start the node reads its index and STATS the object files; it does not
// rehash them. The content check happens on the first serve of each object in a
// process lifetime, and the result is remembered for that lifetime.
//
// The alternative — rehash everything at boot — was rejected deliberately.
// Startup time would become proportional to pinned volume: a node holding a few
// hundred GB would spend minutes of disk I/O before it could answer ANY request,
// including for the roles that have nothing to do with pinning. That is a real
// availability cost paid on every restart, in exchange for detecting corruption
// slightly earlier than the path that actually matters.
//
// Lazy verification gives up nothing that matters, because the invariant is not
// "the disk is known-good" — it is "NOTHING IS EVER SERVED UNVERIFIED", and that
// holds either way: an object is hashed before its first byte reaches a client.
// Bitrot, a truncated write, or tampering by someone with disk access is caught
// at exactly the moment it would otherwise do harm. When it is caught the object
// is deleted and every pin that referenced it is dropped, so a corrupted pin
// becomes an honest "this holder does not serve that" (0x090C) and the operator
// gets a loud log line — never a silently wrong answer.
//
// ── Deduplication ───────────────────────────────────────────────────────────
//
// Objects are content-addressed, so two pins that share chunks share the bytes
// on disk, and the budget counts UNIQUE stored bytes. Retention is derived from
// the index rather than tracked as a refcount: an object survives exactly as
// long as some pin references it, recomputed at unpin time. Derived state cannot
// drift the way a hand-maintained counter can.

// ErrPinBudget is the typed refusal when a pin would exceed a configured
// budget — the whole-store byte cap, the per-pin cap, or the pin count. It is a
// REFUSAL, never a trigger for eviction: a pinned object is never dropped to
// make room for another (that is the difference between a pin and a cache).
var ErrPinBudget = errors.New("pubcache: pin budget exceeded")

// ErrPinNotFound is returned when unpinning something this node does not hold.
var ErrPinNotFound = errors.New("pubcache: no such pin")

// ErrPinForbidden is returned when a key tries to unpin a pin it does not own.
var ErrPinForbidden = errors.New("pubcache: pin is owned by another key")

// ErrPinDisabled is returned when the pin role is not configured.
var ErrPinDisabled = errors.New("pubcache: pin role is not enabled on this node")

// pinIndexVersion is the on-disk index schema version. A future change bumps it
// and an unrecognised version is refused rather than guessed at.
const pinIndexVersion = 1

const (
	pinIndexFile = "index.json"
	pinObjectDir = "objects"
	// pinTmpSuffix marks a partial write. A .tmp file is never readable as an
	// object because objects are only ever named by their content address.
	pinTmpSuffix = ".tmp"
)

// PinRecord is one pin: a root object (announce or manifest) plus, for a
// manifest, the full chunk set it names. It is the unit an operator pins,
// unpins, and is billed for.
type PinRecord struct {
	// Kind and Addr identify the ROOT object of the pin.
	Kind string `json:"kind"`
	Addr string `json:"addr"`
	// Owner is the base64url Ed25519 key that created the pin. Only that key may
	// remove it.
	Owner string `json:"owner"`
	// Objects is every object this pin retains, as "kind:addr" store keys — the
	// root plus, for a manifest, each chunk. Recursive pinning is the point: a
	// manifest whose chunks are not held is not a durable copy of anything.
	Objects []string `json:"objects"`
	// Bytes is the total size of this pin's objects. Because objects are
	// content-addressed and shared, the SUM of every pin's Bytes may exceed the
	// store's actual usage — that is dedup working, not an accounting error.
	Bytes     int64 `json:"bytes"`
	CreatedAt int64 `json:"created_at"`
}

// pinIndex is the on-disk index document.
type pinIndex struct {
	Version int          `json:"version"`
	Pins    []*PinRecord `json:"pins"`
}

// PinStats is the usage view: what a billing layer would read. This package
// EXPOSES the counters and does nothing else with them — metering and charging
// live in the control plane, never in the daemon that serves the role.
type PinStats struct {
	Pins      int   `json:"pins"`
	Objects   int   `json:"objects"`
	Bytes     int64 `json:"bytes"`
	MaxBytes  int64 `json:"max_bytes"`
	MaxPins   int   `json:"max_pins"`
	Available int64 `json:"available_bytes"`

	Pinned    uint64 `json:"pinned"`
	Unpinned  uint64 `json:"unpinned"`
	Refused   uint64 `json:"refused"`
	Hits      uint64 `json:"hits"`
	Corrupted uint64 `json:"corrupted"`
	Dropped   uint64 `json:"dropped"`
}

// pinStore is the durable, content-addressed, budgeted object store.
type pinStore struct {
	dir         string
	maxBytes    int64
	maxPinBytes int64
	maxObjBytes int64
	maxPins     int
	log         *slog.Logger
	now         func() time.Time

	// opMu serialises whole pin/unpin operations. Writes are rare and
	// operator-gated, so one lock over the entire mutation keeps budget
	// accounting exact without a reservation protocol: an operation sees a
	// consistent store from its first budget check to its commit.
	opMu sync.Mutex

	// mu guards the maps below for the (frequent, concurrent) read path.
	mu       sync.RWMutex
	pins     map[string]*PinRecord // "kind:addr" of the ROOT -> pin
	objects  map[string]int64      // "kind:addr" -> size on disk
	verified map[string]bool       // "kind:addr" -> hashed OK in this process
	bytes    int64                 // sum of unique object sizes
	// pending holds objects an in-flight pin has written but not yet committed
	// to the index. Reclamation treats them as live: without this, a quarantine
	// running concurrently with a pin would see freshly-written objects as
	// unreferenced (their pin record does not exist yet) and delete them out
	// from under it.
	pending map[string]int

	pinned, unpinned, refused, hits, corrupted, dropped atomic.Uint64
}

// newPinStore opens (and creates) a pin store rooted at dir, loading any index
// left by a previous process.
func newPinStore(dir string, maxBytes, maxPinBytes, maxObjBytes int64, maxPins int, log *slog.Logger, now func() time.Time) (*pinStore, error) {
	if now == nil {
		now = time.Now
	}
	if log == nil {
		log = slog.Default()
	}
	p := &pinStore{
		dir:         dir,
		maxBytes:    maxBytes,
		maxPinBytes: maxPinBytes,
		maxObjBytes: maxObjBytes,
		maxPins:     maxPins,
		log:         log,
		now:         now,
		pins:        make(map[string]*PinRecord),
		objects:     make(map[string]int64),
		verified:    make(map[string]bool),
		pending:     make(map[string]int),
	}
	if err := os.MkdirAll(filepath.Join(dir, pinObjectDir), 0o700); err != nil {
		return nil, fmt.Errorf("pubcache: pin dir: %w", err)
	}
	if err := p.load(); err != nil {
		return nil, err
	}
	return p, nil
}

// load reads the index and reconciles it against what is actually on disk.
//
// A pin whose objects are not ALL present is not a pin — it is the debris of an
// interrupted write or a hand-edited directory, and honouring it would mean
// claiming durability this node cannot deliver. Such a pin is dropped and its
// orphaned bytes reclaimed, loudly. Fail closed: an incomplete pin is no pin.
func (p *pinStore) load() error {
	raw, err := os.ReadFile(filepath.Join(p.dir, pinIndexFile))
	if errors.Is(err, os.ErrNotExist) {
		return p.sweepOrphans()
	}
	if err != nil {
		return fmt.Errorf("pubcache: read pin index: %w", err)
	}
	var idx pinIndex
	if err := json.Unmarshal(raw, &idx); err != nil {
		return fmt.Errorf("pubcache: parse pin index: %w", err)
	}
	if idx.Version != pinIndexVersion {
		return fmt.Errorf("pubcache: pin index version %d is not supported (want %d)", idx.Version, pinIndexVersion)
	}

	for _, rec := range idx.Pins {
		if rec == nil || rec.Kind == "" || rec.Addr == "" || len(rec.Objects) == 0 {
			continue
		}
		sizes := make(map[string]int64, len(rec.Objects))
		complete := true
		for _, obj := range rec.Objects {
			kind, addr, ok := splitStoreKey(obj)
			// A kind is one of three fixed names and an address is canonical
			// base64url. Both are re-validated rather than trusted: the index is
			// a local file, and a hand-edited or corrupted one must not be able
			// to steer a path outside the object directory.
			if ok {
				if _, valid := parseObjectKind(kind); !valid {
					ok = false
				} else if _, err := ParseAddr(addr); err != nil {
					ok = false
				}
			}
			if !ok {
				complete = false
				break
			}
			fi, err := os.Stat(p.objectPath(kind, addr))
			if err != nil {
				complete = false
				break
			}
			sizes[obj] = fi.Size()
		}
		if !complete {
			p.dropped.Add(1)
			p.log.Warn("pubcache: dropping incomplete pin at startup — not every object it names is on disk, so it is not a durable copy",
				"kind", rec.Kind, "addr", rec.Addr)
			continue
		}
		p.pins[storeKeyStr(rec.Kind, rec.Addr)] = rec
		for obj, sz := range sizes {
			if _, seen := p.objects[obj]; !seen {
				p.objects[obj] = sz
				p.bytes += sz
			}
		}
	}
	// The index is authoritative for what is RETAINED; anything on disk it does
	// not name is unreferenced and must not consume budget.
	if err := p.sweepOrphans(); err != nil {
		return err
	}
	// Reconciliation may have dropped pins, so persist the truth immediately
	// rather than leaving a stale index for the next restart to re-reconcile.
	return p.writeIndexLocked()
}

// sweepOrphans deletes object files no pin references. It runs at startup only:
// during normal operation unpin reclaims eagerly, so an orphan can only be the
// residue of a crash mid-write or a dropped incomplete pin.
func (p *pinStore) sweepOrphans() error {
	root := filepath.Join(p.dir, pinObjectDir)
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // an unreadable entry is skipped, never fatal
		}
		kindDir := filepath.Base(filepath.Dir(filepath.Dir(path)))
		key := storeKeyStr(kindDir, d.Name())
		if _, ok := p.objects[key]; ok {
			return nil
		}
		_ = os.Remove(path)
		return nil
	})
}

// ── paths & keys ────────────────────────────────────────────────────────────

// storeKeyStr is the "kind:addr" store key. It matches cacheKey's shape so the
// two stores are addressable by the same string, but they never share entries.
func storeKeyStr(kind, addr string) string { return kind + ":" + addr }

// parseObjectKind maps a stored kind name back onto a Kind, rejecting anything
// that is not one of the three the addressing rules cover.
func parseObjectKind(s string) (Kind, bool) {
	switch s {
	case "announce":
		return KindAnnounce, true
	case "manifest":
		return KindManifest, true
	case "chunk":
		return KindChunk, true
	}
	return 0, false
}

func splitStoreKey(k string) (kind, addr string, ok bool) {
	for i := 0; i < len(k); i++ {
		if k[i] == ':' {
			kind, addr = k[:i], k[i+1:]
			return kind, addr, kind != "" && addr != ""
		}
	}
	return "", "", false
}

// objectPath is <dir>/objects/<kind>/<xx>/<addr>, where xx is the first two
// characters of the address. The fan-out keeps any single directory from
// growing to millions of entries, which several filesystems handle badly.
//
// The address is always canonical unpadded base64url (ParseAddr enforces it
// before anything gets here), which contains no '/', no '.', and no path
// component — so a content address can never escape this directory.
func (p *pinStore) objectPath(kind, addr string) string {
	shard := addr
	if len(shard) > 2 {
		shard = shard[:2]
	}
	return filepath.Join(p.dir, pinObjectDir, kind, shard, addr)
}

// ── reads ───────────────────────────────────────────────────────────────────

// has reports whether a pinned copy exists, without reading it.
func (p *pinStore) has(key string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.objects[key]
	return ok
}

// get returns a pinned object's bytes, verifying it on first read in this
// process (see the file header for why verification is lazy).
//
// A verification failure here means the bytes on disk are not the object they
// are filed as: bitrot, a truncated write, or tampering. The response is to
// delete the object and drop every pin that referenced it — this node can no
// longer honour those pins, and saying so is the honest answer. The caller then
// serves the ordinary 0x090C refusal and the fetcher rotates to another holder.
func (p *pinStore) get(kind Kind, addr Addr) ([]byte, bool) {
	key := storeKeyStr(kind.String(), addr.String())

	p.mu.RLock()
	_, held := p.objects[key]
	alreadyVerified := p.verified[key]
	p.mu.RUnlock()
	if !held {
		return nil, false
	}

	body, err := os.ReadFile(p.objectPath(kind.String(), addr.String()))
	if err != nil {
		p.log.Warn("pubcache: pinned object unreadable", "key", key, "err", err)
		p.quarantine(key)
		return nil, false
	}
	if !alreadyVerified {
		if err := Verify(kind, addr, body); err != nil {
			p.corrupted.Add(1)
			p.log.Error("pubcache: PINNED OBJECT FAILED VERIFICATION — the bytes on disk are not the object they are filed as; deleting it and dropping every pin that referenced it",
				"key", key, "err", err)
			p.quarantine(key)
			return nil, false
		}
		p.mu.Lock()
		p.verified[key] = true
		p.mu.Unlock()
	}
	p.hits.Add(1)
	return body, true
}

// quarantine removes a bad object and every pin that depended on it, then
// persists the reduced index so the damage is not rediscovered every restart.
//
// It deliberately takes ONLY p.mu, never p.opMu. Quarantine is reached from the
// read path, and the read path is reached from INSIDE a pin operation (a pin
// resolves its objects through the ordinary verified lookup, which consults the
// pin store first). Taking opMu here would therefore deadlock a pin against
// itself the moment it touched an object that had rotted on disk. All the state
// quarantine mutates is guarded by p.mu, and p.pending keeps a concurrent pin's
// uncommitted objects safe from reclamation, so opMu buys nothing.
func (p *pinStore) quarantine(badKey string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for root, rec := range p.pins {
		if !recordReferences(rec, badKey) {
			continue
		}
		delete(p.pins, root)
		p.dropped.Add(1)
	}
	if sz, ok := p.objects[badKey]; ok {
		delete(p.objects, badKey)
		delete(p.verified, badKey)
		p.bytes -= sz
	}
	if kind, addr, ok := splitStoreKey(badKey); ok {
		_ = os.Remove(p.objectPath(kind, addr))
	}
	p.reclaimUnreferencedLocked()
	if err := p.writeIndexLocked(); err != nil {
		p.log.Error("pubcache: failed to persist pin index after quarantine", "err", err)
	}
}

func recordReferences(rec *PinRecord, key string) bool {
	for _, o := range rec.Objects {
		if o == key {
			return true
		}
	}
	return false
}

// ── writes ──────────────────────────────────────────────────────────────────

// objectSource fetches and VERIFIES one object for a pin. The Service supplies
// it (backed by the pinned store, the cache, then upstream), so pinning reuses
// exactly one verified-retrieval path and cannot acquire bytes any other way.
type objectSource func(kind Kind, addr Addr) ([]byte, error)

// pin durably retains root and, when root is a manifest, every chunk it names.
//
// Recursive chunk pinning is not a convenience — a manifest without its chunks
// is a list of hashes for bytes nobody holds, which is precisely the thing
// pinning exists to prevent. Either the whole set lands or none of it does.
//
// Budget is checked incrementally as each object is written, so an oversized pin
// is refused after one object rather than after buffering the whole blob in
// memory, and anything already written is rolled back. Objects already present
// (shared with another pin) cost nothing — content addressing means dedup is
// free and the budget counts unique bytes.
func (p *pinStore) pin(kind Kind, addr Addr, owner string, src objectSource) (*PinRecord, error) {
	p.opMu.Lock()
	defer p.opMu.Unlock()

	rootKey := storeKeyStr(kind.String(), addr.String())

	p.mu.RLock()
	existing, already := p.pins[rootKey]
	pinCount := len(p.pins)
	p.mu.RUnlock()
	if already {
		// Idempotent: re-pinning what is already pinned is a no-op success, not
		// a second charge against the budget.
		return existing, nil
	}
	if p.maxPins > 0 && pinCount >= p.maxPins {
		p.refused.Add(1)
		return nil, fmt.Errorf("%w: already holding %d pins (max %d)", ErrPinBudget, pinCount, p.maxPins)
	}

	// Resolve the root first, through the verified path.
	rootBody, err := src(kind, addr)
	if err != nil {
		return nil, err
	}

	// Build the full object set. For a manifest this re-derives the chunk list
	// from bytes that have ALREADY passed the Merkle-root check, so a pin can
	// never be built over an unverified list.
	type want struct {
		kind Kind
		addr Addr
		body []byte // non-nil only for the root, which is already in hand
	}
	set := []want{{kind: kind, addr: addr, body: rootBody}}
	if kind == KindManifest {
		chunks, err := verifiedManifestChunks(addr, rootBody)
		if err != nil {
			return nil, err
		}
		seen := map[Addr]bool{}
		for _, c := range chunks {
			// A manifest may legitimately name the same chunk twice (repeated
			// content); it is one object on disk and one budget charge.
			if seen[c] {
				continue
			}
			seen[c] = true
			set = append(set, want{kind: KindChunk, addr: c})
		}
	}

	var (
		wrote    []string // newly-written object keys, for rollback
		objects  = make([]string, 0, len(set))
		pinBytes int64
	)
	// releasePending drops this operation's claim on the objects it wrote, once
	// they are either committed to the index or rolled back.
	releasePending := func() {
		p.mu.Lock()
		for _, k := range wrote {
			if n := p.pending[k]; n <= 1 {
				delete(p.pending, k)
			} else {
				p.pending[k] = n - 1
			}
		}
		p.mu.Unlock()
	}
	defer releasePending()

	rollback := func() {
		p.mu.Lock()
		for _, k := range wrote {
			if sz, ok := p.objects[k]; ok {
				delete(p.objects, k)
				delete(p.verified, k)
				p.bytes -= sz
			}
			if ki, ad, ok := splitStoreKey(k); ok {
				_ = os.Remove(p.objectPath(ki, ad))
			}
		}
		p.mu.Unlock()
	}

	for _, w := range set {
		key := storeKeyStr(w.kind.String(), w.addr.String())
		objects = append(objects, key)

		p.mu.RLock()
		sz, present := p.objects[key]
		p.mu.RUnlock()
		if present {
			// Already held for another pin: shared bytes, no new cost.
			pinBytes += sz
			continue
		}

		body := w.body
		if body == nil {
			if body, err = src(w.kind, w.addr); err != nil {
				rollback()
				return nil, fmt.Errorf("pubcache: pin %s: chunk %s: %w", addr, w.addr, err)
			}
		}
		// THE GATE, again and unconditionally. src verifies, but persisting is
		// the one operation whose mistakes outlive the process, so it re-proves
		// rather than trusting its caller.
		if err := Verify(w.kind, w.addr, body); err != nil {
			rollback()
			return nil, fmt.Errorf("pubcache: refusing to persist unverified object %s: %w", w.addr, err)
		}

		n := int64(len(body))
		if p.maxObjBytes > 0 && n > p.maxObjBytes {
			p.refused.Add(1)
			rollback()
			return nil, fmt.Errorf("%w: object %s is %d bytes (per-object max %d)", ErrPinBudget, w.addr, n, p.maxObjBytes)
		}
		if p.maxPinBytes > 0 && pinBytes+n > p.maxPinBytes {
			p.refused.Add(1)
			rollback()
			return nil, fmt.Errorf("%w: pin exceeds the per-pin max of %d bytes", ErrPinBudget, p.maxPinBytes)
		}

		p.mu.RLock()
		total := p.bytes
		p.mu.RUnlock()
		if p.maxBytes > 0 && total+n > p.maxBytes {
			p.refused.Add(1)
			rollback()
			return nil, fmt.Errorf("%w: %d of %d bytes used, this pin needs %d more", ErrPinBudget, total, p.maxBytes, n)
		}

		if err := p.writeObject(w.kind, w.addr, body); err != nil {
			rollback()
			return nil, err
		}
		p.mu.Lock()
		p.objects[key] = n
		// Just hashed above, so it is known-good for this process — no need to
		// re-hash it on the first serve.
		p.verified[key] = true
		p.bytes += n
		// Claim it until this operation commits or rolls back.
		p.pending[key]++
		p.mu.Unlock()

		wrote = append(wrote, key)
		pinBytes += n
	}

	rec := &PinRecord{
		Kind:      kind.String(),
		Addr:      addr.String(),
		Owner:     owner,
		Objects:   objects,
		Bytes:     pinBytes,
		CreatedAt: p.now().Unix(),
	}

	p.mu.Lock()
	p.pins[rootKey] = rec
	err = p.writeIndexLocked()
	p.mu.Unlock()
	if err != nil {
		// The index is the record of what is retained. If it cannot be written,
		// the pin would not survive a restart, so it is not a pin — undo it.
		p.mu.Lock()
		delete(p.pins, rootKey)
		p.mu.Unlock()
		rollback()
		return nil, fmt.Errorf("pubcache: persist pin index: %w", err)
	}
	p.pinned.Add(1)
	return rec, nil
}

// unpin removes a pin and reclaims every object no remaining pin references.
func (p *pinStore) unpin(kind Kind, addr Addr, owner string) (*PinRecord, error) {
	p.opMu.Lock()
	defer p.opMu.Unlock()

	rootKey := storeKeyStr(kind.String(), addr.String())

	p.mu.Lock()
	defer p.mu.Unlock()

	rec, ok := p.pins[rootKey]
	if !ok {
		return nil, ErrPinNotFound
	}
	// A pin is owned by the key that created it. Any authorised key may pin,
	// but only the owner may remove one — otherwise one tenant's authorisation
	// would be a delete button on another tenant's durability.
	if rec.Owner != "" && !keyEq(rec.Owner, owner) {
		return nil, ErrPinForbidden
	}
	delete(p.pins, rootKey)
	p.reclaimUnreferencedLocked()
	if err := p.writeIndexLocked(); err != nil {
		return nil, fmt.Errorf("pubcache: persist pin index: %w", err)
	}
	p.unpinned.Add(1)
	return rec, nil
}

// reclaimUnreferencedLocked deletes every object no surviving pin names, and is
// how unpinned bytes return to the budget. Retention is DERIVED from the index
// on each mutation rather than tracked as a per-object refcount, so it cannot
// drift out of step with the pins that are actually held. Caller holds p.mu.
func (p *pinStore) reclaimUnreferencedLocked() {
	live := make(map[string]struct{}, len(p.objects))
	for _, rec := range p.pins {
		for _, o := range rec.Objects {
			live[o] = struct{}{}
		}
	}
	// An in-flight pin's objects are live even though no record names them yet.
	for k := range p.pending {
		live[k] = struct{}{}
	}
	for key, sz := range p.objects {
		if _, ok := live[key]; ok {
			continue
		}
		delete(p.objects, key)
		delete(p.verified, key)
		p.bytes -= sz
		if kind, addr, ok := splitStoreKey(key); ok {
			_ = os.Remove(p.objectPath(kind, addr))
		}
	}
}

// writeObject persists one object durably: write to a temp name, fsync the
// file, then rename into place. The rename is atomic, so a reader (including
// this node after a crash) only ever sees a complete file under a content
// address — never a partial one it would then have to detect.
func (p *pinStore) writeObject(kind Kind, addr Addr, body []byte) error {
	path := p.objectPath(kind.String(), addr.String())
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("pubcache: pin object dir: %w", err)
	}
	tmp := path + pinTmpSuffix
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("pubcache: pin object: %w", err)
	}
	if _, err := f.Write(body); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("pubcache: pin object write: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("pubcache: pin object fsync: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("pubcache: pin object close: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("pubcache: pin object rename: %w", err)
	}
	return nil
}

// writeIndexLocked persists the pin index with the same temp-write + fsync +
// atomic-rename discipline as an object, so a crash mid-write leaves either the
// old index or the new one, never a half-parsed document. Caller holds p.mu.
func (p *pinStore) writeIndexLocked() error {
	idx := pinIndex{Version: pinIndexVersion, Pins: make([]*PinRecord, 0, len(p.pins))}
	for _, rec := range p.pins {
		idx.Pins = append(idx.Pins, rec)
	}
	// Deterministic order: an index that differs only by map iteration would
	// make on-disk state impossible to diff or reason about.
	sort.Slice(idx.Pins, func(i, j int) bool {
		if idx.Pins[i].Kind != idx.Pins[j].Kind {
			return idx.Pins[i].Kind < idx.Pins[j].Kind
		}
		return idx.Pins[i].Addr < idx.Pins[j].Addr
	})

	raw, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(p.dir, pinIndexFile)
	tmp := path + pinTmpSuffix
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// fsync the directory so the rename itself is durable, not just the bytes.
	if d, err := os.Open(p.dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// ── views ───────────────────────────────────────────────────────────────────

// list returns every pin, newest first. Pinned objects are PUBLIC by definition
// (§ 22), and this lists only their content addresses, sizes, and owner keys —
// all of which are public facts about public objects — so the view is not
// authenticated. What a holder serves is observable by fetching it anyway.
func (p *pinStore) list() []*PinRecord {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*PinRecord, 0, len(p.pins))
	for _, rec := range p.pins {
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt != out[j].CreatedAt {
			return out[i].CreatedAt > out[j].CreatedAt
		}
		return out[i].Addr < out[j].Addr
	})
	return out
}

// stats is the usage view a billing layer reads. Counters only — this daemon
// meters nothing and charges nobody.
func (p *pinStore) stats() PinStats {
	p.mu.RLock()
	pins, objects, bytes := len(p.pins), len(p.objects), p.bytes
	p.mu.RUnlock()

	avail := int64(0)
	if p.maxBytes > 0 {
		if avail = p.maxBytes - bytes; avail < 0 {
			avail = 0
		}
	}
	return PinStats{
		Pins:      pins,
		Objects:   objects,
		Bytes:     bytes,
		MaxBytes:  p.maxBytes,
		MaxPins:   p.maxPins,
		Available: avail,
		Pinned:    p.pinned.Load(),
		Unpinned:  p.unpinned.Load(),
		Refused:   p.refused.Load(),
		Hits:      p.hits.Load(),
		Corrupted: p.corrupted.Load(),
		Dropped:   p.dropped.Load(),
	}
}
