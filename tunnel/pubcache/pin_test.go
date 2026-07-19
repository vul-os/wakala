package pubcache

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/tunnel/internal/keyauth"
)

// pin_test.go — the durability contract.
//
// A pin makes a promise a cache does not: these bytes are still here after a
// restart, still here under cache pressure, and still verified before they are
// served. Each test below pins one of those claims down, plus the two things
// that keep the promise from becoming a liability: the signed-write gate on who
// may spend the operator's disk, and the hard budget that refuses rather than
// quietly evicting.

// ── harness ─────────────────────────────────────────────────────────────────

type pinHarness struct {
	svc  *Service
	up   *fakeUpstream
	dir  string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	key  string
	seq  int
	// clock supplies the timestamp signed requests carry. It must agree with the
	// service's clock, or every signed write fails the freshness check.
	clock func() time.Time
}

// newPinHarness builds a service with durable pinning enabled, an authorised
// key, and a fake upstream to pin from.
func newPinHarness(t *testing.T, mutate func(*Config)) *pinHarness {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	key := keyauth.B64.EncodeToString(pub)
	dir := t.TempDir()

	up := newFakeUpstream()
	svc := newTestService(t, up, func(c *Config) {
		c.PinDir = dir
		c.PinKeys = []string{key}
		if mutate != nil {
			mutate(c)
		}
	})
	h := &pinHarness{svc: svc, up: up, dir: dir, pub: pub, priv: priv, key: key, clock: time.Now}
	if svc.cfg.now != nil {
		h.clock = svc.cfg.now
	}
	return h
}

// reopen simulates a process restart: a brand-new Service over the SAME pin
// directory, with an upstream that has nothing in it. Anything served after this
// can only have come off disk.
func (h *pinHarness) reopen(t *testing.T, mutate func(*Config)) *Service {
	t.Helper()
	empty := newFakeUpstream()
	svc := newTestService(t, empty, func(c *Config) {
		c.PinDir = h.dir
		c.PinKeys = []string{h.key}
		if mutate != nil {
			mutate(c)
		}
	})
	h.up = empty
	h.svc = svc
	return svc
}

func (h *pinHarness) nonce() string {
	h.seq++
	return keyauth.B64.EncodeToString([]byte("nonce-pad-" + strconv.Itoa(h.seq)))
}

// signed builds a fully-valid signed pin/unpin request.
func (h *pinHarness) signed(domain, kind string, addr Addr) *pinRequest {
	req := &pinRequest{
		Key:       h.key,
		Kind:      kind,
		Addr:      addr.String(),
		Nonce:     h.nonce(),
		Timestamp: h.clock().Unix(),
	}
	req.Sig = keyauth.B64.EncodeToString(ed25519.Sign(h.priv, pinSigningMessage(domain, req)))
	return req
}

// post sends a management request and returns the status plus decoded body.
func (h *pinHarness) post(t *testing.T, path string, req *pinRequest) (int, map[string]any) {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", defaultPrefix+path, strings.NewReader(string(body)))
	r.RemoteAddr = "192.0.2.10:1234"
	rec := httptest.NewRecorder()
	h.svc.ServeHTTP(rec, r)

	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func (h *pinHarness) pin(t *testing.T, kind string, addr Addr) (int, map[string]any) {
	t.Helper()
	return h.post(t, "/pin", h.signed(domainPin, kind, addr))
}

func (h *pinHarness) unpin(t *testing.T, kind string, addr Addr) (int, map[string]any) {
	t.Helper()
	return h.post(t, "/unpin", h.signed(domainUnpin, kind, addr))
}

// seedManifest puts a manifest and its chunks on the upstream.
func (h *pinHarness) seedManifest(t *testing.T, chunks ...[]byte) Addr {
	t.Helper()
	id, body := buildManifest(t, chunks...)
	h.up.put("/manifest/"+id.String(), body)
	for _, c := range chunks {
		h.up.put("/chunk/"+HashBytes(c).String(), c)
	}
	return id
}

func (h *pinHarness) seedAnnounce(t *testing.T, body []byte) Addr {
	t.Helper()
	a := HashBytes(body)
	h.up.put("/announce/"+a.String(), body)
	return a
}

// ── persistence across restart ──────────────────────────────────────────────

// TestPinSurvivesRestart is the headline claim. A pinned manifest and every one
// of its chunks are served by a FRESH service over the same directory whose
// upstream holds nothing — so the bytes provably came off disk, not from memory
// and not from the network.
func TestPinSurvivesRestart(t *testing.T) {
	h := newPinHarness(t, nil)
	chunks := [][]byte{[]byte("chunk-zero"), []byte("chunk-one"), []byte("chunk-two")}
	id := h.seedManifest(t, chunks...)

	if code, _ := h.pin(t, "manifest", id); code != http.StatusOK {
		t.Fatalf("pin: got %d", code)
	}

	svc := h.reopen(t, nil)

	resp := get(t, svc, defaultPrefix+"/manifest/"+id.String(), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("manifest after restart: got %d, want 200 (pin did not survive)", resp.StatusCode)
	}
	for i, c := range chunks {
		resp := get(t, svc, chunkPath(HashBytes(c)), nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("chunk %d after restart: got %d, want 200", i, resp.StatusCode)
		}
	}
	if h.up.hits.Load() != 0 {
		t.Fatalf("restarted node hit the upstream %d times; pinned bytes must be served from disk", h.up.hits.Load())
	}
}

// TestPinListAndStatusSurviveRestart checks the INDEX round-trips, not just the
// objects: a holder that serves the bytes but has forgotten it promised to keep
// them would silently reclaim them on the next unpin sweep.
func TestPinListAndStatusSurviveRestart(t *testing.T) {
	h := newPinHarness(t, nil)
	id := h.seedManifest(t, []byte("a"), []byte("b"))
	if code, _ := h.pin(t, "manifest", id); code != http.StatusOK {
		t.Fatal("pin failed")
	}
	before := h.svc.pins.stats()

	svc := h.reopen(t, nil)
	after := svc.pins.stats()

	if after.Pins != before.Pins || after.Objects != before.Objects || after.Bytes != before.Bytes {
		t.Fatalf("index did not round-trip: before %+v after %+v", before, after)
	}
	if len(svc.pins.list()) != 1 {
		t.Fatalf("expected 1 pin after restart, got %d", len(svc.pins.list()))
	}
}

// ── verification on store ───────────────────────────────────────────────────

// TestPinRefusesUnverifiableObject: an upstream that answers a valid address
// with the wrong bytes cannot get them onto this node's DISK. This matters more
// than the cache equivalent — a cached lie dies at restart, a persisted one does
// not.
func TestPinRefusesUnverifiableObject(t *testing.T) {
	h := newPinHarness(t, nil)
	honest := []byte("the object the address names")
	addr := HashBytes(honest)
	h.up.put("/announce/"+addr.String(), []byte("something else entirely"))

	code, body := h.pin(t, "announce", addr)
	if code == http.StatusOK {
		t.Fatal("pinned an object that does not match its content address")
	}
	if body["error"] != "object_not_retrievable" && body["error"] != "object_failed_verification" {
		t.Fatalf("unexpected error code %v", body["error"])
	}
	if st := h.svc.pins.stats(); st.Objects != 0 || st.Bytes != 0 {
		t.Fatalf("unverified bytes reached the pin store: %+v", st)
	}
	// And nothing was written to disk.
	assertNoObjectFiles(t, h.dir)
}

// TestPinRefusesManifestWithMissingChunk: a manifest whose chunks cannot all be
// retrieved is not a durable copy of anything, so the whole pin fails and no
// partial state is left behind (all-or-nothing, with rollback).
func TestPinRefusesManifestWithMissingChunk(t *testing.T) {
	h := newPinHarness(t, nil)
	chunks := [][]byte{[]byte("present-one"), []byte("missing-one")}
	id, body := buildManifest(t, chunks...)
	h.up.put("/manifest/"+id.String(), body)
	h.up.put("/chunk/"+HashBytes(chunks[0]).String(), chunks[0])
	// chunks[1] is deliberately absent upstream.

	if code, _ := h.pin(t, "manifest", id); code == http.StatusOK {
		t.Fatal("pinned a manifest whose chunk set is incomplete")
	}
	if st := h.svc.pins.stats(); st.Pins != 0 || st.Objects != 0 || st.Bytes != 0 {
		t.Fatalf("partial pin left behind: %+v", st)
	}
	assertNoObjectFiles(t, h.dir)
}

// TestCorruptedPinnedObjectIsCaughtOnServe is the justification for verifying
// lazily rather than at boot. Bytes tampered with on disk between restarts are
// caught at the moment they would be served, the object is deleted, the pin that
// depended on it is dropped, and the client gets an honest refusal — never a
// wrong answer.
func TestCorruptedPinnedObjectIsCaughtOnServe(t *testing.T) {
	h := newPinHarness(t, nil)
	body := []byte("an announce worth keeping")
	addr := h.seedAnnounce(t, body)
	if code, _ := h.pin(t, "announce", addr); code != http.StatusOK {
		t.Fatal("pin failed")
	}

	// Tamper with the file on disk, as bitrot or an intruder would.
	path := h.svc.pins.objectPath("announce", addr.String())
	if err := os.WriteFile(path, []byte("tampered bytes of the same-ish size"), 0o600); err != nil {
		t.Fatal(err)
	}

	svc := h.reopen(t, nil)
	resp := get(t, svc, defaultPrefix+"/announce/"+addr.String(), nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("corrupted pinned object served with %d; must be refused", resp.StatusCode)
	}
	st := svc.pins.stats()
	if st.Corrupted != 1 {
		t.Fatalf("corruption not counted: %+v", st)
	}
	if st.Pins != 0 || st.Objects != 0 {
		t.Fatalf("corrupted object and its pin were not dropped: %+v", st)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("corrupted object file was not deleted")
	}
}

// TestIncompletePinIsDroppedAtStartup: if an object file goes missing while the
// node is down, the pin it belonged to is not honoured. A pin that cannot be
// served in full is not a pin, and claiming otherwise would be the dishonest
// failure mode.
func TestIncompletePinIsDroppedAtStartup(t *testing.T) {
	h := newPinHarness(t, nil)
	chunks := [][]byte{[]byte("keep-a"), []byte("keep-b")}
	id := h.seedManifest(t, chunks...)
	if code, _ := h.pin(t, "manifest", id); code != http.StatusOK {
		t.Fatal("pin failed")
	}
	if err := os.Remove(h.svc.pins.objectPath("chunk", HashBytes(chunks[1]).String())); err != nil {
		t.Fatal(err)
	}

	svc := h.reopen(t, nil)
	if st := svc.pins.stats(); st.Pins != 0 {
		t.Fatalf("incomplete pin was honoured after restart: %+v", st)
	}
	// The surviving orphan bytes were reclaimed, not left to consume budget.
	if st := svc.pins.stats(); st.Bytes != 0 || st.Objects != 0 {
		t.Fatalf("orphaned objects not reclaimed: %+v", st)
	}
	assertNoObjectFiles(t, h.dir)
}

// ── recursive chunk pinning ─────────────────────────────────────────────────

// TestPinManifestPinsEveryChunk: pinning a manifest retains the manifest plus
// each distinct chunk — n+1 objects for n chunks.
func TestPinManifestPinsEveryChunk(t *testing.T) {
	h := newPinHarness(t, nil)
	chunks := [][]byte{[]byte("c0"), []byte("c1"), []byte("c2"), []byte("c3"), []byte("c4")}
	id := h.seedManifest(t, chunks...)

	code, body := h.pin(t, "manifest", id)
	if code != http.StatusOK {
		t.Fatalf("pin: got %d (%v)", code, body)
	}
	if n := int(body["objects"].(float64)); n != len(chunks)+1 {
		t.Fatalf("pinned %d objects, want %d (manifest + every chunk)", n, len(chunks)+1)
	}
	for _, c := range chunks {
		if !h.svc.pins.has(storeKeyStr("chunk", HashBytes(c).String())) {
			t.Fatalf("chunk %q was not pinned; a manifest without its chunks is not durable", c)
		}
	}
}

// TestPinDeduplicatesSharedChunks: two manifests sharing chunks store those
// bytes once. Content addressing makes dedup free, and the budget counts unique
// bytes — otherwise a customer would be charged twice for one copy.
func TestPinDeduplicatesSharedChunks(t *testing.T) {
	h := newPinHarness(t, nil)
	shared := []byte("the shared chunk")
	idA := h.seedManifest(t, shared, []byte("only-in-a"))
	idB := h.seedManifest(t, shared, []byte("only-in-b"))

	if code, _ := h.pin(t, "manifest", idA); code != http.StatusOK {
		t.Fatal("pin A failed")
	}
	afterA := h.svc.pins.stats()
	if code, _ := h.pin(t, "manifest", idB); code != http.StatusOK {
		t.Fatal("pin B failed")
	}
	afterB := h.svc.pins.stats()

	// B adds its own manifest and its unique chunk — but NOT a second copy of
	// the shared one: 3 new objects would mean no dedup, 2 is correct.
	if got := afterB.Objects - afterA.Objects; got != 2 {
		t.Fatalf("pin B added %d objects, want 2 (shared chunk must not be stored twice)", got)
	}
	if afterB.Bytes-afterA.Bytes >= afterA.Bytes {
		t.Fatal("shared bytes appear to have been double-counted against the budget")
	}
}

// TestPinIsIdempotent: re-pinning what is already pinned succeeds without
// charging the budget a second time.
func TestPinIsIdempotent(t *testing.T) {
	h := newPinHarness(t, nil)
	id := h.seedManifest(t, []byte("x"), []byte("y"))
	if code, _ := h.pin(t, "manifest", id); code != http.StatusOK {
		t.Fatal("first pin failed")
	}
	first := h.svc.pins.stats()
	if code, _ := h.pin(t, "manifest", id); code != http.StatusOK {
		t.Fatal("re-pin failed")
	}
	second := h.svc.pins.stats()
	if first.Bytes != second.Bytes || first.Objects != second.Objects || second.Pins != 1 {
		t.Fatalf("re-pin was not idempotent: %+v then %+v", first, second)
	}
}

// ── budget ──────────────────────────────────────────────────────────────────

// TestPinRefusedWhenBudgetFull is the reason pinning was deferred until it could
// be done honestly. When the store is full the request is REFUSED with a typed,
// machine-readable error and a 507 — and, critically, the pin already held is
// still there. Nothing is evicted to make room.
func TestPinRefusedWhenBudgetFull(t *testing.T) {
	big := make([]byte, 4096)
	for i := range big {
		big[i] = byte(i)
	}
	h := newPinHarness(t, func(c *Config) { c.PinMaxBytes = 5000 })

	first := h.seedAnnounce(t, big)
	if code, _ := h.pin(t, "announce", first); code != http.StatusOK {
		t.Fatal("first pin should fit")
	}

	second := h.seedAnnounce(t, append([]byte("different"), big...))
	code, body := h.pin(t, "announce", second)
	if code != http.StatusInsufficientStorage {
		t.Fatalf("over-budget pin returned %d, want 507", code)
	}
	if body["error"] != "pin_budget_exceeded" {
		t.Fatalf("want typed budget error, got %v", body["error"])
	}
	// THE INVARIANT: the existing pin was not sacrificed to admit the new one.
	if !h.svc.pins.has(storeKeyStr("announce", first.String())) {
		t.Fatal("an existing pin was evicted to make room — pins must never be evicted")
	}
	if st := h.svc.pins.stats(); st.Pins != 1 || st.Refused != 1 {
		t.Fatalf("unexpected stats after refusal: %+v", st)
	}
	assertNoStrayTmpFiles(t, h.dir)
}

// TestPerPinCapRefusesOversizedPin: one blob cannot swallow the whole budget.
func TestPerPinCapRefusesOversizedPin(t *testing.T) {
	h := newPinHarness(t, func(c *Config) {
		c.PinMaxBytes = 1 << 20
		c.PinMaxPinBytes = 64 // far below one manifest + chunks
	})
	id := h.seedManifest(t, []byte("chunk-a"), []byte("chunk-b"), []byte("chunk-c"))

	code, body := h.pin(t, "manifest", id)
	if code != http.StatusInsufficientStorage {
		t.Fatalf("got %d, want 507 for a pin over the per-pin cap", code)
	}
	if body["error"] != "pin_budget_exceeded" {
		t.Fatalf("want typed budget error, got %v", body["error"])
	}
	if st := h.svc.pins.stats(); st.Bytes != 0 || st.Objects != 0 {
		t.Fatalf("refused pin left bytes behind (rollback failed): %+v", st)
	}
	assertNoObjectFiles(t, h.dir)
}

// TestPinCountCapRefuses bounds pins independently of bytes.
func TestPinCountCapRefuses(t *testing.T) {
	h := newPinHarness(t, func(c *Config) { c.PinMaxPins = 1 })
	a := h.seedAnnounce(t, []byte("first"))
	b := h.seedAnnounce(t, []byte("second"))

	if code, _ := h.pin(t, "announce", a); code != http.StatusOK {
		t.Fatal("first pin failed")
	}
	code, body := h.pin(t, "announce", b)
	if code != http.StatusInsufficientStorage || body["error"] != "pin_budget_exceeded" {
		t.Fatalf("got %d/%v, want 507 pin_budget_exceeded", code, body["error"])
	}
}

// TestUnpinReclaimsBudget: released bytes come back, and the freed room is
// genuinely usable.
func TestUnpinReclaimsBudget(t *testing.T) {
	big := make([]byte, 3000)
	h := newPinHarness(t, func(c *Config) { c.PinMaxBytes = 4000 })

	a := h.seedAnnounce(t, big)
	if code, _ := h.pin(t, "announce", a); code != http.StatusOK {
		t.Fatal("pin A failed")
	}
	b := h.seedAnnounce(t, append([]byte("b"), big...))
	if code, _ := h.pin(t, "announce", b); code != http.StatusInsufficientStorage {
		t.Fatal("B should not fit before A is released")
	}

	if code, _ := h.unpin(t, "announce", a); code != http.StatusOK {
		t.Fatal("unpin A failed")
	}
	if st := h.svc.pins.stats(); st.Bytes != 0 || st.Objects != 0 {
		t.Fatalf("unpin did not reclaim: %+v", st)
	}
	if _, err := os.Stat(h.svc.pins.objectPath("announce", a.String())); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unpinned object file was not deleted from disk")
	}
	// The reclaimed room is real.
	if code, _ := h.pin(t, "announce", b); code != http.StatusOK {
		t.Fatal("B should fit once A's bytes were reclaimed")
	}
}

// TestUnpinKeepsObjectsSharedWithAnotherPin: reclaiming is by REFERENCE, not by
// pin — releasing one of two pins that share a chunk must not break the other.
func TestUnpinKeepsObjectsSharedWithAnotherPin(t *testing.T) {
	h := newPinHarness(t, nil)
	shared := []byte("shared between both manifests")
	idA := h.seedManifest(t, shared, []byte("a-only"))
	idB := h.seedManifest(t, shared, []byte("b-only"))
	for _, id := range []Addr{idA, idB} {
		if code, _ := h.pin(t, "manifest", id); code != http.StatusOK {
			t.Fatal("pin failed")
		}
	}
	if code, _ := h.unpin(t, "manifest", idA); code != http.StatusOK {
		t.Fatal("unpin A failed")
	}

	sharedKey := storeKeyStr("chunk", HashBytes(shared).String())
	if !h.svc.pins.has(sharedKey) {
		t.Fatal("a chunk still referenced by pin B was reclaimed with pin A")
	}
	if h.svc.pins.has(storeKeyStr("chunk", HashBytes([]byte("a-only")).String())) {
		t.Fatal("a chunk referenced by nothing was not reclaimed")
	}
	// B is still fully servable.
	if code, _ := h.svc.pins.get(KindChunk, HashBytes(shared)); code == nil {
		t.Fatal("shared chunk unreadable after unpinning A")
	}
}

// ── pins vs the cache ───────────────────────────────────────────────────────

// TestPinNotEvictedByCachePressure: the cache is driven far past its cap while a
// pin is held. Because the two stores share no bytes and no budget, the pin is
// untouched — and it is served after the cache has churned completely.
func TestPinNotEvictedByCachePressure(t *testing.T) {
	pinned := []byte("this object was paid for and must not disappear")
	h := newPinHarness(t, func(c *Config) {
		// A cache so small that almost anything evicts almost everything.
		c.MaxCacheBytes = 512
	})
	addr := h.seedAnnounce(t, pinned)
	if code, _ := h.pin(t, "announce", addr); code != http.StatusOK {
		t.Fatal("pin failed")
	}

	// Flood the cache with unrelated objects, far past its cap.
	for i := 0; i < 200; i++ {
		body := []byte("cache-filler-object-number-" + strconv.Itoa(i) + strings.Repeat("x", 100))
		a := HashBytes(body)
		h.up.put("/chunk/"+a.String(), body)
		if resp := get(t, h.svc, chunkPath(a), nil); resp.StatusCode != http.StatusOK {
			t.Fatalf("filler %d: %d", i, resp.StatusCode)
		}
	}
	if ev := h.svc.store.stats().Evictions; ev == 0 {
		t.Fatal("test is not exercising cache pressure: nothing was evicted")
	}

	// The pin is intact, in the store and on disk.
	if st := h.svc.pins.stats(); st.Pins != 1 || st.Objects != 1 {
		t.Fatalf("cache pressure disturbed the pin store: %+v", st)
	}
	resp := get(t, h.svc, defaultPrefix+"/announce/"+addr.String(), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pinned object gone after cache churn: %d", resp.StatusCode)
	}
}

// TestPinnedObjectServedWithoutUpstream demonstrates precedence: a pinned object
// is answered from the pin store even when the cache has expired it and the
// upstream would have been consulted.
func TestPinnedObjectServedWithoutUpstream(t *testing.T) {
	clk := newFakeClock()
	h := newPinHarness(t, func(c *Config) {
		c.TTL = time.Minute
		c.now = clk.now
	})
	body := []byte("pinned and precedent")
	addr := h.seedAnnounce(t, body)
	if code, _ := h.pin(t, "announce", addr); code != http.StatusOK {
		t.Fatal("pin failed")
	}

	// Blow past any cache TTL and make the upstream hostile: if the read path
	// ever falls through to it, the answer would be a refusal.
	clk.advance(time.Hour)
	h.up.status = http.StatusInternalServerError
	hitsBefore := h.up.hits.Load()

	resp := get(t, h.svc, defaultPrefix+"/announce/"+addr.String(), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pinned read fell through to the cache/upstream path: %d", resp.StatusCode)
	}
	if h.up.hits.Load() != hitsBefore {
		t.Fatal("a pinned object must be served without consulting the upstream")
	}
}

// TestProofsServedOverPinnedManifest: the § 5.3 proof endpoint runs through the
// same read path, so it works over pinned manifests with no upstream at all.
func TestProofsServedOverPinnedManifest(t *testing.T) {
	h := newPinHarness(t, func(c *Config) { c.ServeProofs = true })
	chunks := [][]byte{[]byte("p0"), []byte("p1"), []byte("p2"), []byte("p3")}
	id := h.seedManifest(t, chunks...)
	if code, _ := h.pin(t, "manifest", id); code != http.StatusOK {
		t.Fatal("pin failed")
	}

	svc := h.reopen(t, func(c *Config) { c.ServeProofs = true })
	resp, raw := getProof(t, svc, proofURL(svc, id, 2), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("proof over a pinned manifest: got %d", resp.StatusCode)
	}
	idx, path, err := DecodeChunkProof(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyChunkProof(id, len(chunks), idx, chunks[2], path); err != nil {
		t.Fatalf("proof served from a pinned manifest did not verify: %v", err)
	}
}

// ── authentication & authorisation ──────────────────────────────────────────

// TestPinRequiresSignature: an unsigned request is refused. Without this the pin
// endpoint would be a remote "fill this operator's disk" primitive.
func TestPinRequiresSignature(t *testing.T) {
	h := newPinHarness(t, nil)
	addr := h.seedAnnounce(t, []byte("unauthenticated"))

	req := &pinRequest{Key: h.key, Kind: "announce", Addr: addr.String(), Nonce: h.nonce(), Timestamp: time.Now().Unix()}
	// No Sig at all.
	if code, _ := h.post(t, "/pin", req); code != http.StatusUnauthorized {
		t.Fatalf("unsigned pin returned %d, want 401", code)
	}
	// A syntactically valid signature over the WRONG message.
	req.Sig = keyauth.B64.EncodeToString(ed25519.Sign(h.priv, []byte("some other message")))
	if code, _ := h.post(t, "/pin", req); code != http.StatusUnauthorized {
		t.Fatalf("bad-signature pin returned %d, want 401", code)
	}
	if st := h.svc.pins.stats(); st.Pins != 0 {
		t.Fatal("an unauthenticated request pinned something")
	}
}

// TestPinRejectsReplay: a captured request cannot be re-sent. Replay of a pin is
// harmless-looking but replay of an unpin would let a network observer delete
// someone's durability.
func TestPinRejectsReplay(t *testing.T) {
	h := newPinHarness(t, nil)
	addr := h.seedAnnounce(t, []byte("replay target"))
	req := h.signed(domainPin, "announce", addr)

	if code, _ := h.post(t, "/pin", req); code != http.StatusOK {
		t.Fatal("first pin failed")
	}
	if code, _ := h.post(t, "/pin", req); code != http.StatusConflict {
		t.Fatalf("replayed pin returned %d, want 409", code)
	}
}

// TestPinRejectsStaleTimestamp bounds how long a captured request stays useful.
func TestPinRejectsStaleTimestamp(t *testing.T) {
	h := newPinHarness(t, nil)
	addr := h.seedAnnounce(t, []byte("stale"))
	req := &pinRequest{
		Key: h.key, Kind: "announce", Addr: addr.String(), Nonce: h.nonce(),
		Timestamp: time.Now().Add(-2 * time.Hour).Unix(),
	}
	req.Sig = keyauth.B64.EncodeToString(ed25519.Sign(h.priv, pinSigningMessage(domainPin, req)))
	if code, _ := h.post(t, "/pin", req); code != http.StatusConflict {
		t.Fatalf("stale-timestamp pin returned %d, want 409", code)
	}
}

// TestPinRejectsUnauthorizedKey: a valid signature from a key the operator did
// not authorise is refused. Signature proves who is asking, never that they may.
func TestPinRejectsUnauthorizedKey(t *testing.T) {
	h := newPinHarness(t, nil)
	addr := h.seedAnnounce(t, []byte("not yours"))

	_, otherPriv, _ := ed25519.GenerateKey(nil)
	otherPub := otherPriv.Public().(ed25519.PublicKey)
	req := &pinRequest{
		Key:   keyauth.B64.EncodeToString(otherPub),
		Kind:  "announce",
		Addr:  addr.String(),
		Nonce: h.nonce(), Timestamp: time.Now().Unix(),
	}
	req.Sig = keyauth.B64.EncodeToString(ed25519.Sign(otherPriv, pinSigningMessage(domainPin, req)))

	code, body := h.post(t, "/pin", req)
	if code != http.StatusForbidden {
		t.Fatalf("unauthorized key returned %d, want 403", code)
	}
	if body["error"] != "pin_not_authorized" {
		t.Fatalf("want pin_not_authorized, got %v", body["error"])
	}
}

// TestSignatureFromWrongKeyRejected: signing with key B while claiming key A.
func TestSignatureFromWrongKeyRejected(t *testing.T) {
	h := newPinHarness(t, nil)
	addr := h.seedAnnounce(t, []byte("impersonation"))
	_, otherPriv, _ := ed25519.GenerateKey(nil)

	req := &pinRequest{Key: h.key, Kind: "announce", Addr: addr.String(), Nonce: h.nonce(), Timestamp: time.Now().Unix()}
	req.Sig = keyauth.B64.EncodeToString(ed25519.Sign(otherPriv, pinSigningMessage(domainPin, req)))
	if code, _ := h.post(t, "/pin", req); code != http.StatusUnauthorized {
		t.Fatalf("wrong-key signature returned %d, want 401", code)
	}
}

// TestPinSignatureIsDomainSeparated: a signature minted for `pin` must not be
// replayable as `unpin`. This is what the domain tag in the canonical message
// buys, and it is worth a test because getting it wrong would let a captured pin
// request be turned into a deletion.
func TestPinSignatureIsDomainSeparated(t *testing.T) {
	h := newPinHarness(t, nil)
	addr := h.seedAnnounce(t, []byte("domain separation"))
	if code, _ := h.pin(t, "announce", addr); code != http.StatusOK {
		t.Fatal("pin failed")
	}

	// A request signed under the PIN domain, submitted to unpin.
	req := h.signed(domainPin, "announce", addr)
	if code, _ := h.post(t, "/unpin", req); code != http.StatusUnauthorized {
		t.Fatalf("pin-domain signature accepted at /unpin (got %d)", code)
	}
	if !h.svc.pins.has(storeKeyStr("announce", addr.String())) {
		t.Fatal("the pin was removed by a cross-domain signature")
	}
}

// TestUnpinRequiresOwnership: any authorised key may pin, but only the key that
// created a pin may remove it — otherwise one tenant's authorisation would be a
// delete button on another tenant's durability.
func TestUnpinRequiresOwnership(t *testing.T) {
	otherPub, otherPriv, _ := ed25519.GenerateKey(nil)
	otherKey := keyauth.B64.EncodeToString(otherPub)

	h := newPinHarness(t, func(c *Config) { c.PinKeys = append(c.PinKeys, otherKey) })
	// Re-add our own key, since the mutate above ran with the harness key first.
	addr := h.seedAnnounce(t, []byte("owned by the first key"))
	if code, _ := h.pin(t, "announce", addr); code != http.StatusOK {
		t.Fatal("pin failed")
	}

	req := &pinRequest{Key: otherKey, Kind: "announce", Addr: addr.String(), Nonce: h.nonce(), Timestamp: time.Now().Unix()}
	req.Sig = keyauth.B64.EncodeToString(ed25519.Sign(otherPriv, pinSigningMessage(domainUnpin, req)))

	code, body := h.post(t, "/unpin", req)
	if code != http.StatusForbidden {
		t.Fatalf("another authorised key unpinned someone else's pin (got %d)", code)
	}
	if body["error"] != "pin_not_owned" {
		t.Fatalf("want pin_not_owned, got %v", body["error"])
	}
	if !h.svc.pins.has(storeKeyStr("announce", addr.String())) {
		t.Fatal("pin was removed by a non-owner")
	}
}

// TestPinWritesRefusedWhenNoKeysAuthorized: enabling durable storage must never
// imply enabling anyone to fill it. With an empty allowlist the node still
// SERVES what it holds but accepts nothing new.
func TestPinWritesRefusedWhenNoKeysAuthorized(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	dir := t.TempDir()
	up := newFakeUpstream()
	body := []byte("nobody may pin this")
	addr := HashBytes(body)
	up.put("/announce/"+addr.String(), body)

	svc := newTestService(t, up, func(c *Config) {
		c.PinDir = dir
		c.PinKeys = nil // explicit: storage on, writes closed
	})

	req := &pinRequest{
		Key: keyauth.B64.EncodeToString(pub), Kind: "announce", Addr: addr.String(),
		Nonce: keyauth.B64.EncodeToString([]byte("nonce-padding-x")), Timestamp: time.Now().Unix(),
	}
	req.Sig = keyauth.B64.EncodeToString(ed25519.Sign(priv, pinSigningMessage(domainPin, req)))
	raw, _ := json.Marshal(req)
	r := httptest.NewRequest("POST", defaultPrefix+"/pin", strings.NewReader(string(raw)))
	r.RemoteAddr = "192.0.2.10:1234"
	rec := httptest.NewRecorder()
	svc.ServeHTTP(rec, r)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("pin with no authorised keys returned %d, want 403", rec.Code)
	}
	// The read/status surface still works.
	if resp := get(t, svc, defaultPrefix+"/pins/status", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("status should be served: %d", resp.StatusCode)
	}
}

// TestPinDisabledWhenNoDirConfigured: without PinDir the node is a pure cache
// and says so, rather than pretending to offer durability.
func TestPinDisabledWhenNoDirConfigured(t *testing.T) {
	up := newFakeUpstream()
	svc := newTestService(t, up, nil)

	for _, p := range []string{"/pins", "/pins/status"} {
		if resp := get(t, svc, defaultPrefix+p, nil); resp.StatusCode != http.StatusNotImplemented {
			t.Fatalf("%s returned %d, want 501", p, resp.StatusCode)
		}
	}
	r := httptest.NewRequest("POST", defaultPrefix+"/pin", strings.NewReader("{}"))
	r.RemoteAddr = "192.0.2.10:1234"
	rec := httptest.NewRecorder()
	svc.ServeHTTP(rec, r)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("pin on a cache-only node returned %d, want 501", rec.Code)
	}
}

// TestInvalidPinKeyIsAConfigError: a malformed allowlist entry fails at
// construction rather than being silently dropped, which would leave an operator
// believing a key is authorised when it is not.
func TestInvalidPinKeyIsAConfigError(t *testing.T) {
	_, err := New(Config{PinDir: t.TempDir(), PinKeys: []string{"not-a-key"}})
	if err == nil {
		t.Fatal("a malformed pin key must be a construction error")
	}
}

// ── views ───────────────────────────────────────────────────────────────────

// TestPinListAndStatusViews checks the shapes a billing layer and an operator
// read. This package exposes counters and nothing else — no pricing, no metering.
func TestPinListAndStatusViews(t *testing.T) {
	h := newPinHarness(t, func(c *Config) { c.PinMaxBytes = 1 << 20 })
	id := h.seedManifest(t, []byte("v0"), []byte("v1"))
	if code, _ := h.pin(t, "manifest", id); code != http.StatusOK {
		t.Fatal("pin failed")
	}

	var listed struct {
		Pins []PinRecord `json:"pins"`
	}
	decodeJSONBody(t, get(t, h.svc, defaultPrefix+"/pins", nil), &listed)
	if len(listed.Pins) != 1 || listed.Pins[0].Addr != id.String() || listed.Pins[0].Owner != h.key {
		t.Fatalf("unexpected pin listing: %+v", listed.Pins)
	}

	var status struct {
		Role  string   `json:"role"`
		Usage PinStats `json:"usage"`
		Keys  int      `json:"authorized_keys"`
	}
	decodeJSONBody(t, get(t, h.svc, defaultPrefix+"/pins/status", nil), &status)
	if status.Role != "dmtap-pub-pin" || status.Keys != 1 {
		t.Fatalf("unexpected status: %+v", status)
	}
	if status.Usage.Pins != 1 || status.Usage.Bytes <= 0 || status.Usage.MaxBytes != 1<<20 {
		t.Fatalf("unexpected usage: %+v", status.Usage)
	}
	if status.Usage.Available != status.Usage.MaxBytes-status.Usage.Bytes {
		t.Fatalf("available bytes inconsistent: %+v", status.Usage)
	}
}

// TestHealthzReportsPinSeparately: cache and pin totals are never folded into
// one number, because one is a promise and the other is scratch.
func TestHealthzReportsPinSeparately(t *testing.T) {
	h := newPinHarness(t, nil)
	addr := h.seedAnnounce(t, []byte("health"))
	if code, _ := h.pin(t, "announce", addr); code != http.StatusOK {
		t.Fatal("pin failed")
	}
	var health struct {
		Bytes    int64    `json:"bytes"`
		MaxBytes int64    `json:"maxBytes"`
		Pin      PinStats `json:"pin"`
	}
	decodeJSONBody(t, get(t, h.svc, defaultPrefix+"/healthz", nil), &health)
	if health.Pin.Pins != 1 || health.Pin.Bytes <= 0 {
		t.Fatalf("healthz did not report pin usage: %+v", health.Pin)
	}
	// The two are separate blocks with separate budgets. Reporting one number for
	// both would leave an operator unable to tell how much of their disk is a
	// durability promise and how much is scratch they may lose at any moment.
	if health.MaxBytes == health.Pin.MaxBytes {
		t.Fatal("cache and pin budgets must be reported as distinct numbers")
	}
	// Unpinning moves the pin total and leaves the cache total alone.
	if code, _ := h.unpin(t, "announce", addr); code != http.StatusOK {
		t.Fatal("unpin failed")
	}
	var after struct {
		Bytes int64    `json:"bytes"`
		Pin   PinStats `json:"pin"`
	}
	decodeJSONBody(t, get(t, h.svc, defaultPrefix+"/healthz", nil), &after)
	if after.Pin.Bytes != 0 {
		t.Fatalf("pin bytes not reclaimed in healthz: %+v", after.Pin)
	}
	if after.Bytes != health.Bytes {
		t.Fatalf("unpinning disturbed the cache total (%d -> %d); the stores are independent", health.Bytes, after.Bytes)
	}
}

// TestUnpinUnknownPinIsNotFound.
func TestUnpinUnknownPinIsNotFound(t *testing.T) {
	h := newPinHarness(t, nil)
	code, body := h.unpin(t, "announce", HashBytes([]byte("never pinned")))
	if code != http.StatusNotFound || body["error"] != "pin_not_found" {
		t.Fatalf("got %d/%v, want 404 pin_not_found", code, body["error"])
	}
}

// TestChunkCannotBePinnedDirectly: chunks are pinned as part of the manifest
// that gives them meaning, so a pin is always a complete object.
func TestChunkCannotBePinnedDirectly(t *testing.T) {
	h := newPinHarness(t, nil)
	body := []byte("a lone chunk")
	addr := HashBytes(body)
	h.up.put("/chunk/"+addr.String(), body)

	req := h.signed(domainPin, "chunk", addr)
	code, out := h.post(t, "/pin", req)
	if code != http.StatusBadRequest || out["error"] != "bad_kind" {
		t.Fatalf("got %d/%v, want 400 bad_kind", code, out["error"])
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

func decodeJSONBody(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status %d", resp.StatusCode)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatal(err)
	}
}

// assertNoObjectFiles fails if any object file exists under the pin directory.
func assertNoObjectFiles(t *testing.T, dir string) {
	t.Helper()
	root := filepath.Join(dir, pinObjectDir)
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr
		}
		t.Fatalf("unexpected object file left on disk: %s", path)
		return nil
	})
}

// assertNoStrayTmpFiles fails if a partial write was left behind.
func assertNoStrayTmpFiles(t *testing.T, dir string) {
	t.Helper()
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr
		}
		if strings.HasSuffix(path, pinTmpSuffix) {
			t.Fatalf("stray temp file: %s", path)
		}
		return nil
	})
}

// TestQuarantineConcurrentWithPinIsSafe is a regression test for two coupled
// hazards a review caught before they shipped.
//
// Quarantine runs from the READ path and reclaims every object no pin
// references. A pin operation writes its objects BEFORE its pin record exists.
// So the two hazards are:
//
//  1. LOCK ORDER. Quarantine must not take the operation lock a pin may already
//     hold — the read path is reachable from inside a pin (a pin resolves its
//     objects through the ordinary verified lookup, which consults the pin store
//     first), so sharing that lock would wedge the daemon on exactly the input it
//     most needs to survive: a disk that has gone bad.
//  2. IN-FLIGHT RECLAMATION. Quarantine must not mistake a concurrent pin's
//     freshly-written objects for garbage just because that pin has not committed
//     its record yet.
//
// This drives a serve of a corrupted pinned object concurrently with a stream of
// pins, and asserts both that nothing wedges and that every pin that reported
// success is actually complete and servable.
func TestQuarantineConcurrentWithPinIsSafe(t *testing.T) {
	h := newPinHarness(t, nil)

	// A pinned announce that we then rot on disk.
	rotten := []byte("this object will be corrupted on disk")
	rottenAddr := h.seedAnnounce(t, rotten)
	if code, _ := h.pin(t, "announce", rottenAddr); code != http.StatusOK {
		t.Fatal("pin of the soon-to-rot object failed")
	}

	// Seed a batch of manifests to pin concurrently with the quarantine.
	var ids []Addr
	for i := 0; i < 12; i++ {
		ids = append(ids, h.seedManifest(t,
			[]byte("c-"+strconv.Itoa(i)+"-0"),
			[]byte("c-"+strconv.Itoa(i)+"-1"),
		))
	}

	if err := os.WriteFile(h.svc.pins.objectPath("announce", rottenAddr.String()), []byte("rot"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Drop the in-process "already verified" memo so the next serve re-hashes,
	// exactly as it would after a restart.
	h.svc.pins.mu.Lock()
	h.svc.pins.verified = map[string]bool{}
	h.svc.pins.mu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Triggers verification failure -> quarantine -> reclaim sweep.
		get(t, h.svc, defaultPrefix+"/announce/"+rottenAddr.String(), nil)
	}()

	// Track which ORIGINAL index each success corresponds to, so the chunk-set
	// assertion below checks the right chunk names.
	pinned := map[int]Addr{}
	for i, id := range ids {
		if code, _ := h.pin(t, "manifest", id); code == http.StatusOK {
			pinned[i] = id
		}
	}

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("quarantine concurrent with pinning deadlocked")
	}

	if h.svc.pins.stats().Corrupted == 0 {
		t.Fatal("corruption was not detected")
	}
	if h.svc.pins.has(storeKeyStr("announce", rottenAddr.String())) {
		t.Fatal("the corrupted object was not removed")
	}
	if len(pinned) == 0 {
		t.Fatal("no pins succeeded; the test is not exercising the race")
	}
	// EVERY pin that reported success must still be whole: the quarantine sweep
	// must not have reclaimed objects belonging to an in-flight pin.
	for i, id := range pinned {
		resp := get(t, h.svc, defaultPrefix+"/manifest/"+id.String(), nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("manifest %s reported pinned but is not servable: %d", id, resp.StatusCode)
		}
		// And its whole chunk set survived the sweep.
		for _, suffix := range []string{"-0", "-1"} {
			c := []byte("c-" + strconv.Itoa(i) + suffix)
			if !h.svc.pins.has(storeKeyStr("chunk", HashBytes(c).String())) {
				t.Fatalf("chunk %q of a committed pin was reclaimed by the quarantine sweep", c)
			}
		}
	}
}
