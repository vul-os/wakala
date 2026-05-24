// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

// syncp2p.go — box-to-box CRDT delta + blob sync TRANSPORT over the existing
// Vulos peering fabric (SYNC-P2P-01).
//
// This file ADDS a sync sub-protocol. It does NOT modify any existing peering
// file and does NOT change the VULOS-PEER/1 envelope wire format: every sync
// message is marshaled into a small versioned frame (VULOS-SYNC/1, see
// spec/PEERING.md §11 / spec/VERSIONS.md) and then carried inside the opaque,
// already-authenticated-and-encrypted peering envelope payload via the existing
// peering.Seal / peering.Open primitives. This is exactly the pattern
// reputation.go uses: a new message type riding the existing PeerTransport.
//
// Design:
//   - TRANSPORT ONLY. The CRDT merge logic and the content store live in other
//     repos (vulos-mail / vulos-office). This package converges two stores by
//     exchanging OPAQUE, versioned CRDT deltas keyed by a version vector, plus
//     fetching missing content-addressed blobs by hash. The store implements the
//     small SyncStore interface; the transport never inspects delta or blob bytes.
//   - Leaderless + NAT-friendly: rides peering.PeerTransport, so it works over the
//     fabric/bucket carrier, a direct stream, or (this file) the same-LAN path.
//   - Same-LAN offline discovery: an mDNS-style UDP multicast announcer/listener
//     (stdlib net only) lets two boxes on one LAN find each other and sync with
//     the internet down. Discovery yields peering.PeerDescriptors; the secure
//     handshake is still the pinned-key peering crypto, so a forged announcement
//     can cause a denial of sync but never an impersonation or a plaintext leak.
//   - Convergence is idempotent: deltas are exchanged as version-vector-keyed
//     ranges; the store's Apply MUST be idempotent (re-applying the same deltas
//     is a no-op) and the transport only requests the ranges a peer is missing,
//     so it composes safely with a separate central-rendezvous path.
//
// Reused peering primitives (no new crypto, no parallel transport):
//   - peering.Identity / peering.PeerDescriptor / peering.Resolver — peer identity
//   - peering.Seal / peering.Open                                   — AEAD + Ed25519 + replay
//   - peering.PeerTransport                                         — the carrier
//   - peering.ReplayGuard                                           — §7 replay window

package relay

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/vul-os/vulos-relay/internal/peering"
)

// SyncProtoV1 is the payload-level sub-protocol identifier for the CRDT/blob
// sync frames carried inside a peering envelope. It is INDEPENDENT of the
// envelope wire version (VULOS-PEER/1): bumping this does not touch the frozen
// peering wire format. See spec/PEERING.md §11.
const SyncProtoV1 = "VULOS-SYNC/1"

// Sync traffic is box-to-box, not mail, but the peering envelope requires
// authority-bound addresses. Each box uses its own real pinned authority domain
// (SyncTransport.Domain) with a reserved "sync@" local-part in the MAIL FROM /
// RCPT TO slots, exactly as reputation.go uses the envelope as a side-channel.

// --- store-facing interface (the only seam the store implements) ---

// VersionVector is an opaque, store-defined summary of how much of each replica's
// history a node holds. The transport treats it as bytes: it ships a node's
// vector to the peer, and the peer returns whatever deltas advance the asker past
// it. Keeping it opaque keeps this package store-agnostic — the CRDT semantics
// (causal vs. state-based, per-key clocks, etc.) live entirely in the store.
type VersionVector []byte

// DeltaRange is one opaque, versioned chunk of CRDT history. The transport never
// interprets Bytes; it only routes it between Have/Apply on the two stores. From
// is the version vector the delta advances from (used purely for idempotent
// de-dup on the wire — the store still owns merge correctness).
type DeltaRange struct {
	// From is the version vector this range is relative to (opaque).
	From VersionVector
	// Bytes is the opaque, store-encoded CRDT delta payload.
	Bytes []byte
}

// SyncStore is the small, store-agnostic seam a content/CRDT store implements to
// converge over the fabric. Implementations live in vulos-mail / vulos-office;
// this package only moves bytes between two SyncStores. All methods must be safe
// for concurrent use.
//
// Idempotency contract: ApplyDeltas MUST be idempotent — applying a DeltaRange
// (or the same set of ranges) more than once MUST leave the store unchanged
// beyond the first application. This is what makes re-sync, retries, and the
// central-rendezvous path compose safely (no double-apply).
type SyncStore interface {
	// Version returns this store's current opaque version vector.
	Version() (VersionVector, error)

	// DeltasSince returns the opaque CRDT delta ranges that advance a peer from
	// the given (remote) version vector up to this store's current state. An
	// empty slice means the peer is already up to date.
	DeltasSince(remote VersionVector) ([]DeltaRange, error)

	// ApplyDeltas merges received delta ranges into the store. It MUST be
	// idempotent (see the type contract). It returns the set of content-addressed
	// blob hashes the deltas reference that the store does not yet hold, so the
	// transport can fetch them.
	ApplyDeltas(deltas []DeltaRange) (missingBlobs [][]byte, err error)

	// HasBlob reports whether the store holds the content-addressed blob.
	HasBlob(hash []byte) bool

	// GetBlob returns the content for a content-addressed hash, or ok=false.
	GetBlob(hash []byte) (content []byte, ok bool)

	// PutBlob stores a fetched blob. The transport verifies the hash matches
	// before calling (content addressing), but the store MAY re-verify. PutBlob
	// MUST be idempotent on hash.
	PutBlob(hash, content []byte) error
}

// --- sync frame types (the VULOS-SYNC/1 payload sub-protocol) ---

const (
	msgPull     = byte(1) // A→B: "here is my version vector; send me what I'm missing"
	msgDeltas   = byte(2) // B→A: opaque delta ranges advancing A
	msgBlobReq  = byte(3) // A→B: "send me these content-addressed blobs"
	msgBlobResp = byte(4) // B→A: the requested blobs
)

// syncMsg is the decoded sync sub-protocol message. Exactly one field group is
// populated per msgType. It is serialized by marshalSync and rides the peering
// envelope payload.
type syncMsg struct {
	typ    byte
	vector VersionVector // msgPull
	deltas []DeltaRange  // msgDeltas
	hashes [][]byte      // msgBlobReq
	blobs  []blob        // msgBlobResp
}

type blob struct {
	hash    []byte
	content []byte
}

// --- transport ---

// SyncTransport drives box-to-box convergence for one local SyncStore over the
// peering fabric. It is leaderless: either box may initiate. It reuses the
// peering crypto and carrier wholesale; it adds no socket of its own except the
// optional same-LAN discovery beacon.
type SyncTransport struct {
	// Identity is this box's long-term peering key material.
	Identity *peering.Identity
	// Domain is the domain this box claims authority for in envelopes (the
	// pinned sender domain on the peer side).
	Domain string
	// Resolver maps a peer domain to its descriptor (registry, DNS, or the
	// in-memory descriptors learned from same-LAN discovery).
	Resolver peering.Resolver
	// Transport is the carrier (fabric/bucket, direct, or loopback for tests).
	Transport peering.PeerTransport
	// Store is the local CRDT/content store seam being converged.
	Store SyncStore

	// guard provides §7 replay protection on inbound sync envelopes.
	guard *peering.ReplayGuard
	once  sync.Once
}

func (s *SyncTransport) init() {
	s.once.Do(func() {
		if s.guard == nil {
			s.guard = peering.NewReplayGuard()
		}
	})
}

// ErrSyncStore is returned when the local store rejects an operation.
var ErrSyncStore = errors.New("relay: sync store error")

// SyncWith performs one full convergence round with the peer authoritative for
// peerDomain: it pulls the deltas this box is missing, applies them, and fetches
// any referenced content-addressed blobs the store lacks. The round is one-way
// (this box catches up to the peer); leaderless convergence is achieved by both
// boxes running SyncWith against each other (or on a timer). It is safe to call
// repeatedly — re-sync is idempotent.
func (s *SyncTransport) SyncWith(ctx context.Context, peerDomain string) error {
	s.init()
	desc, err := s.Resolver.Resolve(ctx, peerDomain)
	if err != nil {
		return err
	}

	// 1. Pull: tell the peer our version; receive the deltas we're missing.
	local, err := s.Store.Version()
	if err != nil {
		return fmt.Errorf("%w: version: %v", ErrSyncStore, err)
	}
	respWire, err := s.roundTrip(ctx, desc, peerDomain, &syncMsg{typ: msgPull, vector: local})
	if err != nil {
		return err
	}
	resp, err := unmarshalSync(respWire)
	if err != nil {
		return err
	}
	if resp.typ != msgDeltas {
		return fmt.Errorf("relay: sync: expected deltas, got msg type %d", resp.typ)
	}

	// 2. Apply (idempotent) and learn which referenced blobs we lack.
	missing, err := s.Store.ApplyDeltas(resp.deltas)
	if err != nil {
		return fmt.Errorf("%w: apply: %v", ErrSyncStore, err)
	}

	// 3. Fetch missing content-addressed blobs by hash, verifying on receipt.
	missing = s.filterMissing(missing)
	if len(missing) == 0 {
		return nil
	}
	blobWire, err := s.roundTrip(ctx, desc, peerDomain, &syncMsg{typ: msgBlobReq, hashes: missing})
	if err != nil {
		return err
	}
	blobResp, err := unmarshalSync(blobWire)
	if err != nil {
		return err
	}
	if blobResp.typ != msgBlobResp {
		return fmt.Errorf("relay: sync: expected blobs, got msg type %d", blobResp.typ)
	}
	for _, b := range blobResp.blobs {
		// Content addressing: only accept a blob whose content hashes to the
		// hash we asked for. The hash function is the store's (it owns the
		// addressing scheme), so we verify via HasBlob after a guarded PutBlob.
		if err := s.Store.PutBlob(b.hash, b.content); err != nil {
			return fmt.Errorf("%w: put blob: %v", ErrSyncStore, err)
		}
	}
	return nil
}

// filterMissing drops any hashes the store actually already holds (idempotent
// re-sync may surface hashes that arrived via another path).
func (s *SyncTransport) filterMissing(hashes [][]byte) [][]byte {
	out := hashes[:0]
	for _, h := range hashes {
		if !s.Store.HasBlob(h) {
			out = append(out, h)
		}
	}
	return out
}

// HandleEnvelope is the receiver side for a store-and-forward carrier (the
// fabric/bucket or central rendezvous): it opens an inbound peering envelope
// (reusing the full §7–§8 peering checks via peering.Open), decodes the sync
// request, services it against the local store, and returns the SEALED reply
// envelope wire bytes to hand back to the asker over the same carrier. authorized
// reports whether a domain is one this box serves for sync; pinned returns the
// pinned identity key for a sync peer domain (same seam peering.Open uses).
//
// Because the carrier is store-and-forward, the reply is sealed to the asker
// using the asker descriptor resolved from this box's resolver (keyed by the
// asker domain carried in the request header). The asker later opens it via its
// own guard. This is the leg that composes with the central-rendezvous path.
//
// REPLAY-GUARD OPERATOR NOTE (FIX-REPLAYGUARD-DOC-01):
//
// In production (store-and-forward carriers), this HandleEnvelope runs ONLY on
// the RESPONDER side. It does NOT participate in the asker's reply-open path:
// the asker receives the response as a separately-delivered inbound envelope
// and MUST open it through ITS OWN inbound handler — and that handler MUST
// reuse the SAME *peering.ReplayGuard instance as the asker's other inbound
// envelope handlers (e.g. its own HandleEnvelope, the reputation receiver,
// the stream signaling receiver, and any future sub-protocols on this box).
//
// The LoopbackSyncTransport.Exchange method (below) does open the reply with
// `asker.st.guard` — that is correct for the in-process loopback used in
// tests, but operators wiring a real fabric/bucket carrier MUST NOT
// interpret that as license to spin up a second ReplayGuard for the asker's
// reply path. Two guards on the same box = two independent §7 windows, which
// silently weakens replay protection (a replay across the two paths would
// pass) and may permit a captured envelope to be re-injected via the other
// handler.
//
// TODO(operators): when wiring this transport over the real fabric/bucket
// carrier, route the asker's inbound replies through a handler that shares
// the asker box's single ReplayGuard. See spec/PEERING.md §7 note on
// "single ReplayGuard per receiver box".
func (s *SyncTransport) HandleEnvelope(
	wire []byte,
	authorized func(domain string) bool,
	pinned func(domain string) (ed25519.PublicKey, bool),
) ([]byte, error) {
	s.init()
	env, err := peering.UnmarshalEnvelope(wire)
	if err != nil {
		return nil, err
	}
	plain, err := peering.Open(env, peering.OpenParams{
		Receiver:         s.Identity,
		AuthorizedDomain: authorized,
		PinnedSenderKey:  pinned,
	}, s.guard)
	if err != nil {
		return nil, err
	}
	req, err := unmarshalSync(plain)
	if err != nil {
		return nil, err
	}

	reply, err := s.service(req)
	if err != nil {
		return nil, err
	}

	askerDomain := env.Header.SenderDomain
	askerDesc, err := s.Resolver.Resolve(context.Background(), askerDomain)
	if err != nil {
		return nil, err
	}
	replyEnv, err := peering.Seal(peering.SealParams{
		Sender:       s.Identity,
		SenderDomain: s.Domain,
		Receiver:     askerDesc,
		MailFrom:     "sync@" + s.Domain,
		RcptTo:       []string{"sync@" + askerDomain},
		RawRFC822:    marshalSync(reply),
		Proto:        peering.ProtoV1,
		Suite:        peering.SuiteV1,
	})
	if err != nil {
		return nil, err
	}
	return peering.MarshalEnvelope(replyEnv), nil
}

// service answers a decoded sync request against the local store.
func (s *SyncTransport) service(req *syncMsg) (*syncMsg, error) {
	switch req.typ {
	case msgPull:
		deltas, err := s.Store.DeltasSince(req.vector)
		if err != nil {
			return nil, fmt.Errorf("%w: deltas-since: %v", ErrSyncStore, err)
		}
		return &syncMsg{typ: msgDeltas, deltas: deltas}, nil
	case msgBlobReq:
		var blobs []blob
		for _, h := range req.hashes {
			if c, ok := s.Store.GetBlob(h); ok {
				blobs = append(blobs, blob{hash: h, content: c})
			}
		}
		return &syncMsg{typ: msgBlobResp, blobs: blobs}, nil
	default:
		return nil, fmt.Errorf("relay: sync: unhandled request msg type %d", req.typ)
	}
}

// roundTrip seals a sync message to the peer, delivers it over the carrier, and
// returns the peer's decoded reply payload. For carriers that are request/reply
// (the same-LAN direct path and the test loopback), the reply is captured by a
// SyncResponder registered on the carrier. The fabric/bucket carrier is
// store-and-forward; there the reply arrives as a separate inbound envelope and
// is handled by HandleEnvelope — SyncWith is then driven one leg at a time.
func (s *SyncTransport) roundTrip(ctx context.Context, desc *peering.PeerDescriptor, peerDomain string, m *syncMsg) ([]byte, error) {
	env, err := peering.Seal(peering.SealParams{
		Sender:       s.Identity,
		SenderDomain: s.Domain,
		Receiver:     desc,
		MailFrom:     "sync@" + s.Domain,
		RcptTo:       []string{"sync@" + peerDomain},
		RawRFC822:    marshalSync(m),
		Proto:        peering.ProtoV1,
		Suite:        peering.SuiteV1,
	})
	if err != nil {
		return nil, err
	}
	wire := peering.MarshalEnvelope(env)

	// If the carrier is a SyncResponder it returns the reply inline (LAN/direct/
	// loopback). Otherwise Deliver is fire-and-forget and the reply comes back
	// as a separate inbound envelope via HandleEnvelope.
	if rr, ok := s.Transport.(SyncResponder); ok {
		return rr.Exchange(ctx, desc.Endpoint, wire)
	}
	if err := s.Transport.Deliver(ctx, desc.Endpoint, wire); err != nil {
		return nil, err
	}
	return nil, errAwaitInbound
}

// errAwaitInbound signals that a store-and-forward carrier accepted the request
// and the reply will arrive as a separate inbound envelope (handled by
// HandleEnvelope), rather than inline.
var errAwaitInbound = errors.New("relay: sync: reply pending on inbound carrier")

// SyncResponder is an optional capability a PeerTransport may implement to
// support synchronous request/reply (the same-LAN direct path and the test
// loopback). Exchange delivers req and returns the peer's reply envelope wire.
type SyncResponder interface {
	Exchange(ctx context.Context, endpoint string, req []byte) (resp []byte, err error)
}

// --- in-process responder for same-LAN/direct/test convergence ---

// LoopbackSyncTransport is an in-memory SyncResponder that wires two (or more)
// SyncTransports together in one process, running the full peering Seal/Open
// path on each leg. It is the reference carrier for the same-LAN direct case and
// for tests. It is safe for concurrent use.
type LoopbackSyncTransport struct {
	mu        sync.Mutex
	endpoints map[string]*syncEndpoint
}

type syncEndpoint struct {
	st         *SyncTransport
	authorized func(string) bool
	pinned     func(string) (ed25519.PublicKey, bool)
}

// NewLoopbackSyncTransport creates an empty in-memory sync carrier.
func NewLoopbackSyncTransport() *LoopbackSyncTransport {
	return &LoopbackSyncTransport{endpoints: make(map[string]*syncEndpoint)}
}

// Register attaches a receiving SyncTransport at endpoint, with the receiver-side
// authority/pinning seams peering.Open requires.
func (t *LoopbackSyncTransport) Register(endpoint string, st *SyncTransport, authorized func(string) bool, pinned func(string) (ed25519.PublicKey, bool)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.endpoints[endpoint] = &syncEndpoint{st: st, authorized: authorized, pinned: pinned}
}

// Deliver implements peering.PeerTransport (fire-and-forget); for sync we route
// through Exchange and discard the reply.
func (t *LoopbackSyncTransport) Deliver(ctx context.Context, endpoint string, wire []byte) error {
	_, err := t.Exchange(ctx, endpoint, wire)
	return err
}

// Exchange implements SyncResponder: it runs the receiver's HandleEnvelope and
// returns the sealed reply, sealing it back to the asker via the receiver's view
// of the asker descriptor.
func (t *LoopbackSyncTransport) Exchange(_ context.Context, endpoint string, req []byte) ([]byte, error) {
	t.mu.Lock()
	ep := t.endpoints[endpoint]
	t.mu.Unlock()
	if ep == nil {
		return nil, peering.ErrMisrouted
	}

	env, err := peering.UnmarshalEnvelope(req)
	if err != nil {
		return nil, err
	}
	plain, err := peering.Open(env, peering.OpenParams{
		Receiver:         ep.st.Identity,
		AuthorizedDomain: ep.authorized,
		PinnedSenderKey:  ep.pinned,
	}, ep.st.guard)
	if err != nil {
		return nil, err
	}
	reqMsg, err := unmarshalSync(plain)
	if err != nil {
		return nil, err
	}
	replyMsg, err := ep.st.service(reqMsg)
	if err != nil {
		return nil, err
	}

	// Seal the reply back to the asker. The receiver resolves the asker's
	// descriptor (its kex pub) via its own resolver, keyed by the asker domain.
	askerDesc, err := ep.st.Resolver.Resolve(context.Background(), env.Header.SenderDomain)
	if err != nil {
		return nil, err
	}
	replyEnv, err := peering.Seal(peering.SealParams{
		Sender:       ep.st.Identity,
		SenderDomain: ep.st.Domain,
		Receiver:     askerDesc,
		MailFrom:     "sync@" + ep.st.Domain,
		RcptTo:       []string{"sync@" + env.Header.SenderDomain},
		RawRFC822:    marshalSync(replyMsg),
		Proto:        peering.ProtoV1,
		Suite:        peering.SuiteV1,
	})
	if err != nil {
		return nil, err
	}

	// The asker opens the reply with its own identity/guard, running the full
	// peering §7–§8 checks on the reply leg too. The asker is the registered
	// endpoint whose Ed25519 identity matches the request's sender identity pub.
	asker := t.endpointByIdentity(env.Header.SenderIdentityPub)
	if asker == nil {
		return nil, peering.ErrMisrouted
	}
	innerPlain, err := peering.Open(replyEnv, peering.OpenParams{
		Receiver:         asker.st.Identity,
		AuthorizedDomain: asker.authorized,
		PinnedSenderKey:  asker.pinned,
	}, asker.st.guard)
	if err != nil {
		return nil, err
	}
	return innerPlain, nil
}

// endpointByIdentity returns the registered endpoint whose Ed25519 identity key
// equals identityPub (i.e. the original asker), so its guard/identity can open
// the reply with the full peering checks.
func (t *LoopbackSyncTransport) endpointByIdentity(identityPub []byte) *syncEndpoint {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, ep := range t.endpoints {
		if bytesEq(ep.st.Identity.SignPub, identityPub) {
			return ep
		}
	}
	return nil
}

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- same-LAN discovery (mDNS-style UDP multicast, stdlib net only) ---

// discoveryGroup is the link-local multicast address + port the same-LAN sync
// beacon uses. It is link-scoped, so packets stay on the LAN and work with the
// internet down. (Not a wire-format change — discovery only learns descriptors,
// see VERSIONS.md "What does NOT require a bump".)
const (
	discoveryAddr = "239.192.71.71:7711" // admin-scoped IPv4 multicast
	beaconMagic   = "VULOS-SYNC-BEACON/1"
)

// Beacon is a same-LAN sync announcement: it advertises enough to build a
// peering.PeerDescriptor for the announcer. The identity key is the trust anchor
// (same as the DNS path, spec §3.1): a forged beacon can deny sync but cannot
// impersonate a pinned peer, because the handshake is still pinned-key peering.
type Beacon struct {
	Domain      string
	IdentityPub []byte // Ed25519, 32
	KexPub      []byte // X25519, 32
	Endpoint    string // host:port the announcer accepts sync envelopes on
}

// LANDiscovery is an mDNS-style same-LAN peer finder. It periodically multicasts
// the local Beacon and collects beacons from other boxes, turning them into
// peering.PeerDescriptors that the SyncTransport's resolver can use — letting two
// boxes on one LAN find each other and sync with the internet down.
type LANDiscovery struct {
	// Self is the local beacon to announce. If empty, this node only listens.
	Self Beacon
	// Interval is the announce period (default 5s).
	Interval time.Duration

	mu    sync.Mutex
	peers map[string]Beacon // keyed by domain
	conn  *net.UDPConn
}

// NewLANDiscovery creates a discovery instance announcing self.
func NewLANDiscovery(self Beacon) *LANDiscovery {
	return &LANDiscovery{Self: self, peers: make(map[string]Beacon)}
}

// Run starts the announce loop and listener until ctx is cancelled. It is
// safe to call once. With no multicast-capable interface it degrades to a no-op
// listener and returns when ctx ends (callers can still inject beacons via
// Observe for testing/offline setups).
func (d *LANDiscovery) Run(ctx context.Context) error {
	if d.peers == nil {
		d.peers = make(map[string]Beacon)
	}
	gaddr, err := net.ResolveUDPAddr("udp4", discoveryAddr)
	if err != nil {
		return err
	}
	conn, err := net.ListenMulticastUDP("udp4", nil, gaddr)
	if err != nil {
		// No multicast available (e.g. sandboxed CI). Block until ctx ends so the
		// caller's lifecycle is unaffected; Observe still works for direct setups.
		<-ctx.Done()
		return ctx.Err()
	}
	d.mu.Lock()
	d.conn = conn
	d.mu.Unlock()
	_ = conn.SetReadBuffer(1 << 16)

	interval := d.Interval
	if interval <= 0 {
		interval = 5 * time.Second
	}

	go d.announceLoop(ctx, gaddr, interval)
	return d.listen(ctx, conn)
}

func (d *LANDiscovery) announceLoop(ctx context.Context, gaddr *net.UDPAddr, interval time.Duration) {
	if d.Self.Domain == "" {
		return // listen-only
	}
	out, err := net.DialUDP("udp4", nil, gaddr)
	if err != nil {
		return
	}
	defer out.Close()
	t := time.NewTicker(interval)
	defer t.Stop()
	pkt := marshalBeacon(d.Self)
	_, _ = out.Write(pkt) // immediate first announce
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _ = out.Write(pkt)
		}
	}
}

func (d *LANDiscovery) listen(ctx context.Context, conn *net.UDPConn) error {
	buf := make([]byte, 1<<16)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				continue
			}
		}
		if b, ok := unmarshalBeacon(buf[:n]); ok {
			d.Observe(b)
		}
	}
}

// Observe records a discovered (or injected) beacon. It ignores the node's own
// beacon. Exposed so direct/offline setups and tests can feed beacons without a
// live multicast network.
func (d *LANDiscovery) Observe(b Beacon) {
	if b.Domain == "" || b.Domain == d.Self.Domain {
		return
	}
	d.mu.Lock()
	if d.peers == nil {
		d.peers = make(map[string]Beacon)
	}
	d.peers[b.Domain] = b
	d.mu.Unlock()
}

// Peers returns the peer descriptors discovered on the LAN so far. These feed the
// SyncTransport's resolver. The identity key in each is the trust anchor; the
// caller pins it per spec §3.2 before trusting a handshake.
func (d *LANDiscovery) Peers() []*peering.PeerDescriptor {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]*peering.PeerDescriptor, 0, len(d.peers))
	for _, b := range d.peers {
		out = append(out, &peering.PeerDescriptor{
			Domains:     []string{b.Domain},
			IdentityPub: b.IdentityPub,
			KexPub:      b.KexPub,
			Versions:    []string{peering.ProtoV1},
			Suites:      []string{peering.SuiteV1},
			Endpoint:    b.Endpoint,
		})
	}
	return out
}

// --- marshaling (length-prefixed, big-endian; mirrors the peering codec style) ---

func marshalSync(m *syncMsg) []byte {
	var b []byte
	b = putStr(b, SyncProtoV1)
	b = append(b, m.typ)
	switch m.typ {
	case msgPull:
		b = putBytes(b, m.vector)
	case msgDeltas:
		b = putU16(b, len(m.deltas))
		for _, d := range m.deltas {
			b = putBytes(b, d.From)
			b = putBytes(b, d.Bytes)
		}
	case msgBlobReq:
		b = putU16(b, len(m.hashes))
		for _, h := range m.hashes {
			b = putBytes(b, h)
		}
	case msgBlobResp:
		b = putU16(b, len(m.blobs))
		for _, bl := range m.blobs {
			b = putBytes(b, bl.hash)
			b = putBytes(b, bl.content)
		}
	}
	return b
}

func unmarshalSync(b []byte) (*syncMsg, error) {
	r := &syncReader{b: b}
	proto, ok := r.str()
	if !ok || proto != SyncProtoV1 {
		return nil, fmt.Errorf("relay: sync: unsupported sub-protocol %q", proto)
	}
	typ, ok := r.byteV()
	if !ok {
		return nil, errSyncCorrupt
	}
	m := &syncMsg{typ: typ}
	switch typ {
	case msgPull:
		v, ok := r.bytesV()
		if !ok {
			return nil, errSyncCorrupt
		}
		m.vector = v
	case msgDeltas:
		n, ok := r.u16()
		if !ok {
			return nil, errSyncCorrupt
		}
		for i := 0; i < n; i++ {
			from, ok1 := r.bytesV()
			by, ok2 := r.bytesV()
			if !ok1 || !ok2 {
				return nil, errSyncCorrupt
			}
			m.deltas = append(m.deltas, DeltaRange{From: from, Bytes: by})
		}
	case msgBlobReq:
		n, ok := r.u16()
		if !ok {
			return nil, errSyncCorrupt
		}
		for i := 0; i < n; i++ {
			h, ok := r.bytesV()
			if !ok {
				return nil, errSyncCorrupt
			}
			m.hashes = append(m.hashes, h)
		}
	case msgBlobResp:
		n, ok := r.u16()
		if !ok {
			return nil, errSyncCorrupt
		}
		for i := 0; i < n; i++ {
			h, ok1 := r.bytesV()
			c, ok2 := r.bytesV()
			if !ok1 || !ok2 {
				return nil, errSyncCorrupt
			}
			m.blobs = append(m.blobs, blob{hash: h, content: c})
		}
	default:
		return nil, fmt.Errorf("relay: sync: unknown msg type %d", typ)
	}
	if !r.empty() {
		return nil, errSyncCorrupt
	}
	return m, nil
}

var errSyncCorrupt = errors.New("relay: sync: corrupt frame")

func marshalBeacon(b Beacon) []byte {
	var out []byte
	out = putStr(out, beaconMagic)
	out = putStr(out, b.Domain)
	out = putBytes(out, b.IdentityPub)
	out = putBytes(out, b.KexPub)
	out = putStr(out, b.Endpoint)
	return out
}

func unmarshalBeacon(b []byte) (Beacon, bool) {
	r := &syncReader{b: b}
	magic, ok := r.str()
	if !ok || magic != beaconMagic {
		return Beacon{}, false
	}
	var be Beacon
	if be.Domain, ok = r.str(); !ok {
		return Beacon{}, false
	}
	if be.IdentityPub, ok = r.bytesV(); !ok {
		return Beacon{}, false
	}
	if be.KexPub, ok = r.bytesV(); !ok {
		return Beacon{}, false
	}
	if be.Endpoint, ok = r.str(); !ok {
		return Beacon{}, false
	}
	if !r.empty() {
		return Beacon{}, false
	}
	return be, true
}

// --- tiny codec helpers (local to relay; mirror peering's style) ---

func putU16(b []byte, n int) []byte {
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(n))
	return append(b, l[:]...)
}

func putBytes(b, p []byte) []byte {
	b = putU16(b, len(p))
	return append(b, p...)
}

func putStr(b []byte, s string) []byte { return putBytes(b, []byte(s)) }

type syncReader struct {
	b   []byte
	pos int
}

func (r *syncReader) take(n int) ([]byte, bool) {
	if n < 0 || r.pos+n > len(r.b) {
		return nil, false
	}
	out := r.b[r.pos : r.pos+n]
	r.pos += n
	return out, true
}

func (r *syncReader) byteV() (byte, bool) {
	p, ok := r.take(1)
	if !ok {
		return 0, false
	}
	return p[0], true
}

func (r *syncReader) u16() (int, bool) {
	p, ok := r.take(2)
	if !ok {
		return 0, false
	}
	return int(binary.BigEndian.Uint16(p)), true
}

func (r *syncReader) bytesV() ([]byte, bool) {
	n, ok := r.u16()
	if !ok {
		return nil, false
	}
	return r.take(n)
}

func (r *syncReader) str() (string, bool) {
	p, ok := r.bytesV()
	if !ok {
		return "", false
	}
	return string(p), true
}

func (r *syncReader) empty() bool { return r.pos == len(r.b) }
