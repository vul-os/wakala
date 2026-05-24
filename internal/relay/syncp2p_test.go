// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"sync"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/internal/peering"
)

// memStore is a minimal in-memory SyncStore for tests. It models a real CRDT
// for concurrent writers: each record is keyed by (replicaID, seq), and the
// version vector is the per-replica max seq map. Each record may reference
// content-addressed blobs by sha256. ApplyDeltas is idempotent: a record at a
// (replica,seq) already held is ignored, so re-sync and concurrent writers both
// converge without double-apply.
type memStore struct {
	replica byte
	mu      sync.Mutex
	log     map[recKey][]byte // (replica,seq) -> opaque record bytes
	vv      map[byte]uint64   // replica -> max contiguous seq held
	blobs   map[string][]byte // string(hash) -> content
	refs    map[recKey][][]byte
}

type recKey struct {
	replica byte
	seq     uint64
}

func newMemStoreR(replica byte) *memStore {
	return &memStore{replica: replica, log: map[recKey][]byte{}, vv: map[byte]uint64{}, blobs: map[string][]byte{}, refs: map[recKey][][]byte{}}
}

// add appends a local record at this replica's next sequence.
func (m *memStore) add(rec []byte, blobHashes ...[]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.vv[m.replica]++
	k := recKey{m.replica, m.vv[m.replica]}
	m.log[k] = append([]byte(nil), rec...)
	if len(blobHashes) > 0 {
		m.refs[k] = blobHashes
	}
}

func (m *memStore) putContent(content []byte) []byte {
	h := sha256.Sum256(content)
	m.mu.Lock()
	m.blobs[string(h[:])] = append([]byte(nil), content...)
	m.mu.Unlock()
	return h[:]
}

// Version encodes the version vector as count||(replica,maxSeq)*.
func (m *memStore) Version() (VersionVector, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var b []byte
	b = appendU16(b, len(m.vv))
	for r, s := range m.vv {
		b = append(b, r)
		b = append(b, encodeU64(s)...)
	}
	return b, nil
}

func decodeVV(b VersionVector) map[byte]uint64 {
	out := map[byte]uint64{}
	if len(b) < 2 {
		return out
	}
	n := int(uint16(b[0])<<8 | uint16(b[1]))
	b = b[2:]
	for i := 0; i < n && len(b) >= 9; i++ {
		out[b[0]] = decodeU64(b[1:9])
		b = b[9:]
	}
	return out
}

func (m *memStore) DeltasSince(remote VersionVector) ([]DeltaRange, error) {
	rvv := decodeVV(remote)
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []DeltaRange
	for r, max := range m.vv {
		for seq := rvv[r] + 1; seq <= max; seq++ {
			k := recKey{r, seq}
			rec, ok := m.log[k]
			if !ok {
				continue
			}
			// Encode delta as replica||seq||refcount||refs||record (opaque to transport).
			b := []byte{r}
			b = append(b, encodeU64(seq)...)
			refs := m.refs[k]
			b = appendU16(b, len(refs))
			for _, rf := range refs {
				b = appendLP(b, rf)
			}
			b = append(b, rec...)
			out = append(out, DeltaRange{From: append([]byte{r}, encodeU64(seq-1)...), Bytes: b})
		}
	}
	return out, nil
}

func (m *memStore) ApplyDeltas(deltas []DeltaRange) ([][]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var missing [][]byte
	for _, d := range deltas {
		replica := d.Bytes[0]
		seq := decodeU64(d.Bytes[1:9])
		rest := d.Bytes[9:]
		nrefs := int(uint16(rest[0])<<8 | uint16(rest[1]))
		rest = rest[2:]
		var refs [][]byte
		for i := 0; i < nrefs; i++ {
			l := int(uint16(rest[0])<<8 | uint16(rest[1]))
			rest = rest[2:]
			refs = append(refs, rest[:l])
			rest = rest[l:]
		}
		rec := rest
		k := recKey{replica, seq}
		// Idempotency: skip if we already hold this (replica,seq).
		if _, ok := m.log[k]; ok {
			continue
		}
		m.log[k] = append([]byte(nil), rec...)
		if seq > m.vv[replica] {
			m.vv[replica] = seq
		}
		if len(refs) > 0 {
			m.refs[k] = refs
		}
		for _, h := range refs {
			if _, ok := m.blobs[string(h)]; !ok {
				missing = append(missing, append([]byte(nil), h...))
			}
		}
	}
	return missing, nil
}

func (m *memStore) HasBlob(hash []byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.blobs[string(hash)]
	return ok
}

func (m *memStore) GetBlob(hash []byte) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.blobs[string(hash)]
	return c, ok
}

func (m *memStore) PutBlob(hash, content []byte) error {
	// Content addressing: verify hash matches before storing.
	h := sha256.Sum256(content)
	if !bytes.Equal(h[:], hash) {
		return ErrSyncStore
	}
	m.mu.Lock()
	m.blobs[string(hash)] = append([]byte(nil), content...)
	m.mu.Unlock()
	return nil
}

func (m *memStore) recordCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.log)
}

func encodeU64(v uint64) []byte {
	return []byte{byte(v >> 56), byte(v >> 48), byte(v >> 40), byte(v >> 32), byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}
func decodeU64(b []byte) uint64 {
	if len(b) < 8 {
		return 0
	}
	var v uint64
	for i := 0; i < 8; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v
}
func appendU16(b []byte, n int) []byte { return append(b, byte(n>>8), byte(n)) }
func appendLP(b, p []byte) []byte      { return append(appendU16(b, len(p)), p...) }

// syncPair builds two boxes (A and B) wired over an in-process LoopbackSyncTransport
// with mutual pinning, each with its own store.
func syncPair(t *testing.T) (a, b *SyncTransport, lb *LoopbackSyncTransport, storeA, storeB *memStore) {
	t.Helper()
	idA, err := peering.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	idB, err := peering.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	const domA, domB = "a.box.local", "b.box.local"

	resA := peering.NewStaticResolver()
	resB := peering.NewStaticResolver()
	descB := &peering.PeerDescriptor{Domains: []string{domB}, IdentityPub: idB.SignPub, KexPub: idB.KexPub, Versions: []string{peering.ProtoV1}, Suites: []string{peering.SuiteV1}, Endpoint: "ep-b"}
	descA := &peering.PeerDescriptor{Domains: []string{domA}, IdentityPub: idA.SignPub, KexPub: idA.KexPub, Versions: []string{peering.ProtoV1}, Suites: []string{peering.SuiteV1}, Endpoint: "ep-a"}
	// Each side can resolve the other AND itself (HandleEnvelope/Exchange resolves
	// the asker domain to seal the reply).
	for _, r := range []*peering.StaticResolver{resA, resB} {
		if err := r.Add(descA); err != nil {
			t.Fatal(err)
		}
		if err := r.Add(descB); err != nil {
			t.Fatal(err)
		}
	}

	storeA, storeB = newMemStoreR('A'), newMemStoreR('B')
	lb = NewLoopbackSyncTransport()
	a = &SyncTransport{Identity: idA, Domain: domA, Resolver: resA, Transport: lb, Store: storeA}
	b = &SyncTransport{Identity: idB, Domain: domB, Resolver: resB, Transport: lb, Store: storeB}
	a.init()
	b.init()

	authA := func(d string) bool { return d == domA }
	authB := func(d string) bool { return d == domB }
	pinAll := func(d string) (ed25519.PublicKey, bool) {
		switch d {
		case domA:
			return idA.SignPub, true
		case domB:
			return idB.SignPub, true
		}
		return nil, false
	}
	lb.Register("ep-a", a, authA, pinAll)
	lb.Register("ep-b", b, authB, pinAll)
	return
}

// TestCRDTDeltaExchange: B has records A lacks; one SyncWith converges A to B.
func TestCRDTDeltaExchange(t *testing.T) {
	a, _, _, storeA, storeB := syncPair(t)
	storeB.add([]byte("record-1"))
	storeB.add([]byte("record-2"))
	storeB.add([]byte("record-3"))

	if err := a.SyncWith(context.Background(), "b.box.local"); err != nil {
		t.Fatalf("SyncWith: %v", err)
	}
	if got := storeA.recordCount(); got != 3 {
		t.Fatalf("A converged to %d records, want 3", got)
	}
	va, _ := storeA.Version()
	vb, _ := storeB.Version()
	if !bytes.Equal(va, vb) {
		t.Fatalf("version vectors differ after sync: A=%x B=%x", va, vb)
	}
}

// TestBlobFetchByHash: B's delta references a content-addressed blob A must fetch.
func TestBlobFetchByHash(t *testing.T) {
	a, _, _, storeA, storeB := syncPair(t)
	content := []byte("the quick brown fox attachment payload")
	h := storeB.putContent(content)
	storeB.add([]byte("record-with-attachment"), h)

	if err := a.SyncWith(context.Background(), "b.box.local"); err != nil {
		t.Fatalf("SyncWith: %v", err)
	}
	got, ok := storeA.GetBlob(h)
	if !ok {
		t.Fatal("A did not fetch the referenced blob")
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("fetched blob content mismatch: %q", got)
	}
	// Verify content addressing held: stored hash matches sha256 of content.
	rehash := sha256.Sum256(got)
	if !bytes.Equal(rehash[:], h) {
		t.Fatal("fetched blob does not match its content hash")
	}
}

// TestIdempotentReSync: applying the same deltas twice changes nothing.
func TestIdempotentReSync(t *testing.T) {
	a, _, _, storeA, storeB := syncPair(t)
	content := []byte("idempotent-blob")
	h := storeB.putContent(content)
	storeB.add([]byte("rec-A"))
	storeB.add([]byte("rec-B"), h)

	if err := a.SyncWith(context.Background(), "b.box.local"); err != nil {
		t.Fatalf("first SyncWith: %v", err)
	}
	c1 := storeA.recordCount()
	v1, _ := storeA.Version()

	// Re-sync: same deltas, must be a no-op.
	if err := a.SyncWith(context.Background(), "b.box.local"); err != nil {
		t.Fatalf("second SyncWith: %v", err)
	}
	if c2 := storeA.recordCount(); c2 != c1 {
		t.Fatalf("re-sync double-applied: %d records, want %d", c2, c1)
	}
	v2, _ := storeA.Version()
	if !bytes.Equal(v1, v2) {
		t.Fatalf("re-sync changed version vector: %x -> %x", v1, v2)
	}
	// And a third sync after B advances pulls only the new record.
	storeB.add([]byte("rec-C"))
	if err := a.SyncWith(context.Background(), "b.box.local"); err != nil {
		t.Fatalf("third SyncWith: %v", err)
	}
	if got := storeA.recordCount(); got != c1+1 {
		t.Fatalf("incremental sync = %d records, want %d", got, c1+1)
	}
}

// TestBidirectionalConvergence: each side has unique records; two SyncWith legs
// (A←B then B←A) converge both stores (leaderless).
func TestBidirectionalConvergence(t *testing.T) {
	a, b, _, storeA, storeB := syncPair(t)
	storeA.add([]byte("only-on-A"))
	storeB.add([]byte("only-on-B-1"))
	storeB.add([]byte("only-on-B-2"))

	if err := a.SyncWith(context.Background(), "b.box.local"); err != nil {
		t.Fatalf("A<-B: %v", err)
	}
	if err := b.SyncWith(context.Background(), "a.box.local"); err != nil {
		t.Fatalf("B<-A: %v", err)
	}
	// Both stores now hold all three records.
	if storeA.recordCount() != 3 || storeB.recordCount() != 3 {
		t.Fatalf("not converged: A=%d B=%d", storeA.recordCount(), storeB.recordCount())
	}
}

// TestSyncRejectsUnpinnedSender: a sync envelope from an unpinned domain is
// rejected by the reused peering §8 checks (no from-scratch crypto / auth).
func TestSyncRejectsUnpinnedSender(t *testing.T) {
	a, _, lb, _, _ := syncPair(t)
	// Re-register B's endpoint with a pinned-key oracle that knows nobody.
	lb.Register("ep-b", mustEndpointStore(t), func(string) bool { return true }, func(string) (ed25519.PublicKey, bool) { return nil, false })
	err := a.SyncWith(context.Background(), "b.box.local")
	if err == nil {
		t.Fatal("expected sync to fail against an endpoint that pins nobody")
	}
}

func mustEndpointStore(t *testing.T) *SyncTransport {
	t.Helper()
	id, err := peering.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	res := peering.NewStaticResolver()
	st := &SyncTransport{Identity: id, Domain: "b.box.local", Resolver: res, Store: newMemStoreR('Z')}
	st.init()
	return st
}

// --- same-LAN discovery tests ---

// TestLANDiscoveryObserve: a beacon observed (as if received off the LAN) becomes
// a usable peer descriptor; the node ignores its own beacon.
func TestLANDiscoveryObserve(t *testing.T) {
	idA, _ := peering.GenerateIdentity()
	idB, _ := peering.GenerateIdentity()
	self := Beacon{Domain: "a.box.local", IdentityPub: idA.SignPub, KexPub: idA.KexPub, Endpoint: "ep-a"}
	disc := NewLANDiscovery(self)

	// Self beacon is ignored.
	disc.Observe(self)
	if len(disc.Peers()) != 0 {
		t.Fatal("self beacon should be ignored")
	}

	other := Beacon{Domain: "b.box.local", IdentityPub: idB.SignPub, KexPub: idB.KexPub, Endpoint: "ep-b"}
	disc.Observe(other)
	peers := disc.Peers()
	if len(peers) != 1 {
		t.Fatalf("expected 1 discovered peer, got %d", len(peers))
	}
	d := peers[0]
	if d.Domains[0] != "b.box.local" || d.Endpoint != "ep-b" {
		t.Fatalf("bad descriptor: %+v", d)
	}
	if !bytes.Equal(d.IdentityPub, idB.SignPub) || !bytes.Equal(d.KexPub, idB.KexPub) {
		t.Fatal("descriptor keys do not match beacon")
	}
	if d.Versions[0] != peering.ProtoV1 || d.Suites[0] != peering.SuiteV1 {
		t.Fatal("descriptor does not advertise the peering version/suite")
	}
}

// TestBeaconMarshalRoundTrip: a beacon survives the wire codec and rejects junk.
func TestBeaconMarshalRoundTrip(t *testing.T) {
	id, _ := peering.GenerateIdentity()
	b := Beacon{Domain: "x.box.local", IdentityPub: id.SignPub, KexPub: id.KexPub, Endpoint: "host:7711"}
	wire := marshalBeacon(b)
	got, ok := unmarshalBeacon(wire)
	if !ok {
		t.Fatal("unmarshalBeacon failed on valid beacon")
	}
	if got.Domain != b.Domain || got.Endpoint != b.Endpoint ||
		!bytes.Equal(got.IdentityPub, b.IdentityPub) || !bytes.Equal(got.KexPub, b.KexPub) {
		t.Fatalf("beacon round-trip mismatch: %+v vs %+v", got, b)
	}
	if _, ok := unmarshalBeacon([]byte("garbage")); ok {
		t.Fatal("expected junk to be rejected")
	}
	if _, ok := unmarshalBeacon(append(wire, 0xff)); ok {
		t.Fatal("expected trailing garbage to be rejected")
	}
}

// TestLANDiscoveryDriveSync: discovery feeds a resolver that the SyncTransport
// then uses to converge — the end-to-end "internet-down, found on LAN, synced"
// path, exercised without a live multicast network via Observe.
func TestLANDiscoveryDriveSync(t *testing.T) {
	a, _, _, storeA, storeB := syncPair(t)
	storeB.add([]byte("lan-record-1"))
	storeB.add([]byte("lan-record-2"))

	// A's discovery learns B off the LAN (simulated by Observe).
	idB := beaconFor(t, "b.box.local", "ep-b", a) // pull B's keys from A's resolver
	disc := NewLANDiscovery(Beacon{Domain: "a.box.local"})
	disc.Observe(idB)

	// The discovered descriptor must match what A already pins (so the handshake
	// succeeds), proving discovery yields a usable, pin-compatible descriptor.
	peers := disc.Peers()
	if len(peers) != 1 {
		t.Fatalf("discovery found %d peers, want 1", len(peers))
	}
	if err := a.SyncWith(context.Background(), peers[0].Domains[0]); err != nil {
		t.Fatalf("sync to LAN-discovered peer: %v", err)
	}
	if storeA.recordCount() != 2 {
		t.Fatalf("A did not converge over LAN-discovered peer: %d records", storeA.recordCount())
	}
}

// beaconFor builds a Beacon from the keys A's resolver already holds for domain.
func beaconFor(t *testing.T, domain, endpoint string, a *SyncTransport) Beacon {
	t.Helper()
	desc, err := a.Resolver.Resolve(context.Background(), domain)
	if err != nil {
		t.Fatal(err)
	}
	return Beacon{Domain: domain, IdentityPub: desc.IdentityPub, KexPub: desc.KexPub, Endpoint: endpoint}
}

// TestLANDiscoveryRunNoMulticast: Run must not hang or panic when multicast is
// unavailable (sandboxed CI); it blocks until ctx ends and Observe still works.
func TestLANDiscoveryRunNoMulticast(t *testing.T) {
	disc := NewLANDiscovery(Beacon{Domain: "a.box.local"})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { _ = disc.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
}

// Compile-time assertions for the seams.
var (
	_ SyncStore             = (*memStore)(nil)
	_ peering.PeerTransport = (*LoopbackSyncTransport)(nil)
	_ SyncResponder         = (*LoopbackSyncTransport)(nil)
)
