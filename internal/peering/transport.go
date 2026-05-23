// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package peering

import (
	"context"
	"crypto/ed25519"
	"sync"
)

// PeerTransport is the injectable carrier that moves a marshaled envelope from
// the sender peer to the receiver peer (spec/PEERING.md §2). Vulos plugs in its
// fabric/bucket transport; this package ships an in-memory loopback for tests
// and standalone use. Implementations must be safe for concurrent use.
//
// The envelope is independently authenticated and encrypted, so the transport
// need provide no confidentiality or authenticity of its own — and it does NO
// public DNS lookup and NO blocklist exposure.
type PeerTransport interface {
	// Deliver hands wire (a MarshalEnvelope blob) to the peer reachable at
	// endpoint. A nil error means the receiver accepted the envelope; a non-nil
	// error is a (possibly transient) handoff failure.
	Deliver(ctx context.Context, endpoint string, wire []byte) error
}

// LoopbackTransport is an in-memory PeerTransport: each registered endpoint is
// backed by a local receiver that opens the envelope through the full spec §7–§8
// checks and, on success, appends the recovered message to a delivered log. It
// is the reference transport for tests and single-process standalone setups.
type LoopbackTransport struct {
	mu        sync.Mutex
	endpoints map[string]*LoopbackEndpoint
}

// NewLoopbackTransport creates an empty LoopbackTransport.
func NewLoopbackTransport() *LoopbackTransport {
	return &LoopbackTransport{endpoints: make(map[string]*LoopbackEndpoint)}
}

// LoopbackEndpoint is a receiving peer attached to a LoopbackTransport.
type LoopbackEndpoint struct {
	Receiver   *Identity
	Authorized func(domain string) bool
	PinnedKey  func(domain string) (ed25519.PublicKey, bool)
	Guard      *ReplayGuard

	mu        sync.Mutex
	Delivered [][]byte // recovered raw RFC 822 messages, in arrival order
}

// Register attaches an endpoint to the transport under the given address.
func (t *LoopbackTransport) Register(endpoint string, ep *LoopbackEndpoint) {
	if ep.Guard == nil {
		ep.Guard = NewReplayGuard()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.endpoints[endpoint] = ep
}

// Deliver implements PeerTransport: it routes the envelope to the registered
// receiver and runs the full receiver-side validation (spec §7–§8).
func (t *LoopbackTransport) Deliver(_ context.Context, endpoint string, wire []byte) error {
	t.mu.Lock()
	ep := t.endpoints[endpoint]
	t.mu.Unlock()
	if ep == nil {
		return ErrMisrouted
	}

	env, err := UnmarshalEnvelope(wire)
	if err != nil {
		return err
	}
	plain, err := Open(env, OpenParams{
		Receiver:         ep.Receiver,
		AuthorizedDomain: ep.Authorized,
		PinnedSenderKey:  ep.PinnedKey,
	}, ep.Guard)
	if err != nil {
		return err
	}

	ep.mu.Lock()
	ep.Delivered = append(ep.Delivered, plain)
	ep.mu.Unlock()
	return nil
}

// Inbox returns a copy of the messages delivered to this endpoint so far.
func (ep *LoopbackEndpoint) Inbox() [][]byte {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	out := make([][]byte, len(ep.Delivered))
	copy(out, ep.Delivered)
	return out
}
