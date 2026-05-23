// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package peering

import (
	"context"
	"errors"

	"github.com/vul-os/vulos-relay/internal/sending"
)

// PeerSender is the sending.Sender for peer recipients (spec/PEERING.md). It
// resolves the receiver descriptor, negotiates the protocol version, builds the
// encrypted envelope, hands it off over a PeerTransport, and classifies the
// result into a sending.SendResult. It performs NO public DNS lookup and NO
// blocklist exposure.
//
// It is wired as the peer branch of the relay pipeline: Router.IsPeer → here.
type PeerSender struct {
	// Identity is this node's long-term key material.
	Identity *Identity
	// Resolver maps recipient domains to peer descriptors.
	Resolver Resolver
	// Transport is the carrier that moves envelopes to peers.
	Transport PeerTransport
}

// NewPeerSender constructs a PeerSender.
func NewPeerSender(id *Identity, r Resolver, t PeerTransport) *PeerSender {
	return &PeerSender{Identity: id, Resolver: r, Transport: t}
}

// Send implements sending.Sender. All recipients are expected to belong to a
// single peer (the router splits multi-peer messages upstream); if they span
// multiple resolved peers, Send returns a deferred result so the message is
// retried rather than partially delivered.
func (s *PeerSender) Send(ctx context.Context, msg sending.Message) (sending.SendResult, error) {
	if len(msg.Recipients) == 0 {
		return sending.SendResult{State: sending.StateBounced, Message: "no recipients"}, nil
	}

	// Resolve the peer for the first recipient; require all recipients to share it.
	desc, err := s.Resolver.Resolve(ctx, DomainOf(msg.Recipients[0]))
	if err != nil {
		// Not a peer (or resolution failure) — surface as deferred so the
		// router/pipeline decides fallback vs. retry (spec §10). The PeerSender
		// itself never silently downgrades to SMTP.
		return sending.SendResult{State: sending.StateDeferred, Message: err.Error()}, nil
	}
	for _, r := range msg.Recipients[1:] {
		d2, err2 := s.Resolver.Resolve(ctx, DomainOf(r))
		if err2 != nil || d2 != desc {
			return sending.SendResult{State: sending.StateDeferred, Message: "recipients span multiple peers"}, nil
		}
	}

	// §9 version negotiation: highest common proto + suite. v1 is all we speak.
	if !desc.supports(ProtoV1, SuiteV1) {
		return sending.SendResult{State: sending.StateBounced, Message: ErrNoCommonVersion.Error()}, ErrNoCommonVersion
	}

	env, err := Seal(SealParams{
		Sender:       s.Identity,
		SenderDomain: DomainOf(msg.Sender),
		Receiver:     desc,
		MailFrom:     msg.Sender,
		RcptTo:       msg.Recipients,
		RawRFC822:    msg.RawRFC822,
		Proto:        ProtoV1,
		Suite:        SuiteV1,
	})
	if err != nil {
		return sending.SendResult{State: sending.StateDeferred, Message: err.Error()}, err
	}

	wire := MarshalEnvelope(env)
	if err := s.Transport.Deliver(ctx, desc.Endpoint, wire); err != nil {
		return classifyHandoff(err), err
	}

	return sending.SendResult{State: sending.StateDelivered, Code: 250, Provider: "vulos-peer"}, nil
}

// classifyHandoff maps a transport / receiver error to a SendResult per
// spec §10. Permanent receiver rejections bounce (no SMTP retry); everything
// else defers on the peer path.
func classifyHandoff(err error) sending.SendResult {
	switch {
	case errors.Is(err, ErrUnauthorized),
		errors.Is(err, ErrMisrouted),
		errors.Is(err, ErrReplay),
		errors.Is(err, ErrUnsupported),
		errors.Is(err, ErrUnauthenticated),
		errors.Is(err, ErrCorrupt):
		return sending.SendResult{State: sending.StateBounced, Message: err.Error()}
	default:
		// Transient carrier error: defer/retry on the peer path.
		return sending.SendResult{State: sending.StateDeferred, Message: err.Error()}
	}
}
