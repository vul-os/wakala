// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package peering

import (
	"context"

	"github.com/vul-os/vulos-relay/internal/sending"
)

// RoutingSender is a sending.Sender that splits a message by recipient: peer
// recipients take the encrypted peering path (PeerSender), everything else
// falls back to the SMTP sender (spec/PEERING.md §10). It is the single
// drop-in Sender the pipeline can use for the combined peer+SMTP behavior.
//
// Failure contract (spec §10): a recipient that resolves to a peer is NEVER
// silently downgraded to SMTP on a peer-handoff failure — that part defers on
// the peer path. Only recipients that are not peers go to SMTP.
type RoutingSender struct {
	// Peer handles peer recipients.
	Peer *PeerSender
	// SMTP handles non-peer recipients (the existing sending.SMTPSender or any
	// sending.Sender). Consumed as a seam — peering does not reimplement SMTP.
	SMTP sending.Sender
	// Resolver detects peers; same instance the PeerSender uses.
	Resolver Resolver
}

// Send implements sending.Sender. It partitions recipients by their resolved
// peer (one PeerSender call per distinct peer) and one SMTP call for the rest,
// then returns the worst per-part outcome.
func (rs *RoutingSender) Send(ctx context.Context, msg sending.Message) (sending.SendResult, error) {
	if len(msg.Recipients) == 0 {
		return sending.SendResult{State: sending.StateBounced, Message: "no recipients"}, nil
	}

	// Partition recipients: each distinct peer descriptor gets its own group;
	// non-peers collect into the SMTP group.
	peerGroups := map[*PeerDescriptor][]string{}
	var smtpRcpts []string
	for _, r := range msg.Recipients {
		desc, err := rs.Resolver.Resolve(ctx, DomainOf(r))
		if err != nil {
			smtpRcpts = append(smtpRcpts, r) // not a peer → SMTP fallback
			continue
		}
		peerGroups[desc] = append(peerGroups[desc], r)
	}

	worst := sending.SendResult{State: sending.StateDelivered, Code: 250}
	var firstErr error

	for _, rcpts := range peerGroups {
		part := msg
		part.Recipients = rcpts
		res, err := rs.Peer.Send(ctx, part)
		if firstErr == nil {
			firstErr = err
		}
		worst = worseOf(worst, res)
	}

	if len(smtpRcpts) > 0 {
		part := msg
		part.Recipients = smtpRcpts
		res, err := rs.SMTP.Send(ctx, part)
		if err != nil {
			// Infra error from SMTP → deferred (mirrors pipeline semantics).
			res = sending.SendResult{State: sending.StateDeferred, Message: err.Error()}
		}
		if firstErr == nil {
			firstErr = err
		}
		worst = worseOf(worst, res)
	}

	return worst, firstErr
}

// worseOf returns the worse of two delivery states (bounced > deferred > delivered).
func worseOf(a, b sending.SendResult) sending.SendResult {
	rank := map[sending.SendState]int{
		sending.StateDelivered: 0,
		sending.StateDeferred:  1,
		sending.StateBounced:   2,
	}
	if rank[b.State] > rank[a.State] {
		return b
	}
	return a
}
