// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package peering

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/internal/sending"
)

// testPair builds a sender + receiver identity, a resolver pinning the
// receiver, and a pinned-key lookup for the sender domain.
func testPair(t *testing.T) (sender, receiver *Identity, res *StaticResolver) {
	t.Helper()
	var err error
	sender, err = GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	receiver, err = GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	res = NewStaticResolver()
	if err := res.Add(&PeerDescriptor{
		Domains:     []string{"recv.example"},
		IdentityPub: receiver.SignPub,
		KexPub:      receiver.KexPub,
		Versions:    []string{ProtoV1},
		Suites:      []string{SuiteV1},
		Endpoint:    "ep-recv",
	}); err != nil {
		t.Fatal(err)
	}
	return
}

func sealFixture(t *testing.T, sender, receiver *Identity, res *StaticResolver) *Envelope {
	t.Helper()
	desc, err := res.Resolve(context.Background(), "recv.example")
	if err != nil {
		t.Fatal(err)
	}
	env, err := Seal(SealParams{
		Sender:       sender,
		SenderDomain: "send.example",
		Receiver:     desc,
		MailFrom:     "alice@send.example",
		RcptTo:       []string{"bob@recv.example"},
		RawRFC822:    []byte("Subject: hi\r\n\r\nhello peer\r\n"),
		Proto:        ProtoV1,
		Suite:        SuiteV1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func openParams(receiver *Identity, senderID ed25519.PublicKey) OpenParams {
	return OpenParams{
		Receiver:         receiver,
		AuthorizedDomain: func(d string) bool { return d == "recv.example" },
		PinnedSenderKey: func(d string) (ed25519.PublicKey, bool) {
			if d == "send.example" {
				return senderID, true
			}
			return nil, false
		},
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	sender, receiver, res := testPair(t)
	env := sealFixture(t, sender, receiver, res)

	plain, err := Open(env, openParams(receiver, sender.SignPub), NewReplayGuard())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Contains(plain, []byte("hello peer")) {
		t.Fatalf("recovered plaintext = %q", plain)
	}
}

func TestWireRoundTrip(t *testing.T) {
	sender, receiver, res := testPair(t)
	env := sealFixture(t, sender, receiver, res)

	wire := MarshalEnvelope(env)
	got, err := UnmarshalEnvelope(wire)
	if err != nil {
		t.Fatalf("UnmarshalEnvelope: %v", err)
	}
	plain, err := Open(got, openParams(receiver, sender.SignPub), NewReplayGuard())
	if err != nil {
		t.Fatalf("Open after wire round-trip: %v", err)
	}
	if !bytes.Contains(plain, []byte("hello peer")) {
		t.Fatalf("recovered = %q", plain)
	}
}

func TestUnmarshalRejectsTrailingGarbage(t *testing.T) {
	sender, receiver, res := testPair(t)
	env := sealFixture(t, sender, receiver, res)
	wire := append(MarshalEnvelope(env), 0xff)
	if _, err := UnmarshalEnvelope(wire); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("expected ErrCorrupt, got %v", err)
	}
}

func TestTamperedPayloadFails(t *testing.T) {
	sender, receiver, res := testPair(t)
	env := sealFixture(t, sender, receiver, res)
	env.Payload[0] ^= 0xff // breaks both signature and AEAD tag
	if _, err := Open(env, openParams(receiver, sender.SignPub), NewReplayGuard()); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expected ErrUnauthenticated, got %v", err)
	}
}

func TestTamperedHeaderFails(t *testing.T) {
	sender, receiver, res := testPair(t)
	env := sealFixture(t, sender, receiver, res)
	// Change a header field after signing; signature must fail.
	env.Header.MailFrom = "mallory@send.example"
	if _, err := Open(env, openParams(receiver, sender.SignPub), NewReplayGuard()); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expected ErrUnauthenticated, got %v", err)
	}
}

func TestReplayRejected(t *testing.T) {
	sender, receiver, res := testPair(t)
	env := sealFixture(t, sender, receiver, res)
	guard := NewReplayGuard()

	if _, err := Open(env, openParams(receiver, sender.SignPub), guard); err != nil {
		t.Fatalf("first Open: %v", err)
	}
	// Replaying the exact same envelope must be rejected.
	if _, err := Open(env, openParams(receiver, sender.SignPub), guard); !errors.Is(err, ErrReplay) {
		t.Fatalf("expected ErrReplay on replay, got %v", err)
	}
}

func TestStaleTimestampRejected(t *testing.T) {
	sender, receiver, res := testPair(t)
	desc, _ := res.Resolve(context.Background(), "recv.example")
	old := time.Now().Add(-1 * time.Hour)
	env, err := Seal(SealParams{
		Sender: sender, SenderDomain: "send.example", Receiver: desc,
		MailFrom: "alice@send.example", RcptTo: []string{"bob@recv.example"},
		RawRFC822: []byte("x"), Proto: ProtoV1, Suite: SuiteV1,
		Now: func() time.Time { return old },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(env, openParams(receiver, sender.SignPub), NewReplayGuard()); !errors.Is(err, ErrReplay) {
		t.Fatalf("expected ErrReplay for stale timestamp, got %v", err)
	}
}

func TestSenderDomainAuthorityEnforced(t *testing.T) {
	sender, receiver, res := testPair(t)
	env := sealFixture(t, sender, receiver, res)

	// Receiver does not recognize the sender's domain pin → unauthorized.
	p := openParams(receiver, sender.SignPub)
	p.PinnedSenderKey = func(string) (ed25519.PublicKey, bool) { return nil, false }
	if _, err := Open(env, p, NewReplayGuard()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized (unknown domain), got %v", err)
	}

	// Pinned key for the domain belongs to a different peer → unauthorized.
	other, _ := GenerateIdentity()
	p2 := openParams(receiver, sender.SignPub)
	p2.PinnedSenderKey = func(string) (ed25519.PublicKey, bool) { return other.SignPub, true }
	if _, err := Open(env, p2, NewReplayGuard()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized (key mismatch), got %v", err)
	}
}

func TestMisroutedRecipientRejected(t *testing.T) {
	sender, receiver, res := testPair(t)
	env := sealFixture(t, sender, receiver, res)
	p := openParams(receiver, sender.SignPub)
	p.AuthorizedDomain = func(string) bool { return false } // not our domain
	if _, err := Open(env, p, NewReplayGuard()); !errors.Is(err, ErrMisrouted) {
		t.Fatalf("expected ErrMisrouted, got %v", err)
	}
}

func TestWrongReceiverKeyRejected(t *testing.T) {
	sender, receiver, res := testPair(t)
	env := sealFixture(t, sender, receiver, res)
	other, _ := GenerateIdentity()
	if _, err := Open(env, openParams(other, sender.SignPub), NewReplayGuard()); !errors.Is(err, ErrMisrouted) {
		t.Fatalf("expected ErrMisrouted for wrong receiver key, got %v", err)
	}
}

func TestKeyPinningRejectsConflict(t *testing.T) {
	res := NewStaticResolver()
	a, _ := GenerateIdentity()
	b, _ := GenerateIdentity()
	d := &PeerDescriptor{Domains: []string{"x.example"}, IdentityPub: a.SignPub, KexPub: a.KexPub, Versions: []string{ProtoV1}, Suites: []string{SuiteV1}}
	if err := res.Add(d); err != nil {
		t.Fatal(err)
	}
	// Re-adding the same key is fine.
	if err := res.Add(d); err != nil {
		t.Fatalf("re-add same key: %v", err)
	}
	// A different key for the same domain must be rejected (spec §3.2).
	if err := res.Add(&PeerDescriptor{Domains: []string{"x.example"}, IdentityPub: b.SignPub, KexPub: b.KexPub}); err == nil {
		t.Fatal("expected pin conflict error")
	}
}

// --- Sender / transport / fallback tests ---

func newReceiverEndpoint(receiver, sender *Identity) *LoopbackEndpoint {
	return &LoopbackEndpoint{
		Receiver:   receiver,
		Authorized: func(d string) bool { return d == "recv.example" },
		PinnedKey: func(d string) (ed25519.PublicKey, bool) {
			if d == "send.example" {
				return sender.SignPub, true
			}
			return nil, false
		},
	}
}

func TestPeerSenderHandoff(t *testing.T) {
	sender, receiver, res := testPair(t)
	tr := NewLoopbackTransport()
	ep := newReceiverEndpoint(receiver, sender)
	tr.Register("ep-recv", ep)

	ps := NewPeerSender(sender, res, tr)
	res2, err := ps.Send(context.Background(), sending.Message{
		Sender:     "alice@send.example",
		Recipients: []string{"bob@recv.example"},
		RawRFC822:  []byte("Subject: t\r\n\r\nbody\r\n"),
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if res2.State != sending.StateDelivered {
		t.Fatalf("state = %s, want delivered", res2.State)
	}
	if got := ep.Inbox(); len(got) != 1 || !bytes.Contains(got[0], []byte("body")) {
		t.Fatalf("inbox = %v", got)
	}
}

func TestPeerSenderNonPeerDefers(t *testing.T) {
	sender, _, res := testPair(t)
	ps := NewPeerSender(sender, res, NewLoopbackTransport())
	r, _ := ps.Send(context.Background(), sending.Message{
		Sender:     "alice@send.example",
		Recipients: []string{"bob@stranger.example"},
		RawRFC822:  []byte("x"),
	})
	if r.State != sending.StateDeferred {
		t.Fatalf("non-peer should defer, got %s", r.State)
	}
}

func TestPeerSenderReplayOnHandoffBounces(t *testing.T) {
	sender, receiver, res := testPair(t)
	tr := NewLoopbackTransport()
	ep := newReceiverEndpoint(receiver, sender)
	tr.Register("ep-recv", ep)
	ps := NewPeerSender(sender, res, tr)

	msg := sending.Message{Sender: "alice@send.example", Recipients: []string{"bob@recv.example"}, RawRFC822: []byte("body")}
	if _, err := ps.Send(context.Background(), msg); err != nil {
		t.Fatalf("first send: %v", err)
	}
	// Re-deliver the identical wire bytes through the same guarded endpoint.
	desc, _ := res.Resolve(context.Background(), "recv.example")
	env, _ := Seal(SealParams{Sender: sender, SenderDomain: "send.example", Receiver: desc, MailFrom: msg.Sender, RcptTo: msg.Recipients, RawRFC822: msg.RawRFC822, Proto: ProtoV1, Suite: SuiteV1})
	wire := MarshalEnvelope(env)
	// Deliver once (accepted), then replay the SAME bytes (rejected).
	_ = tr.Deliver(context.Background(), "ep-recv", wire)
	if err := tr.Deliver(context.Background(), "ep-recv", wire); !errors.Is(err, ErrReplay) {
		t.Fatalf("expected replay rejection on second identical delivery, got %v", err)
	}
}

func TestNoCommonVersionBounces(t *testing.T) {
	sender, receiver, _ := testPair(t)
	res := NewStaticResolver()
	_ = res.Add(&PeerDescriptor{
		Domains: []string{"recv.example"}, IdentityPub: receiver.SignPub, KexPub: receiver.KexPub,
		Versions: []string{"VULOS-PEER/99"}, Suites: []string{"SOME-OTHER-SUITE"}, Endpoint: "ep-recv",
	})
	ps := NewPeerSender(sender, res, NewLoopbackTransport())
	r, err := ps.Send(context.Background(), sending.Message{Sender: "alice@send.example", Recipients: []string{"bob@recv.example"}, RawRFC822: []byte("x")})
	if !errors.Is(err, ErrNoCommonVersion) || r.State != sending.StateBounced {
		t.Fatalf("expected no-common-version bounce, got state=%s err=%v", r.State, err)
	}
}

// stubSMTP records the recipients it was asked to deliver to.
type stubSMTP struct{ got []string }

func (s *stubSMTP) Send(_ context.Context, msg sending.Message) (sending.SendResult, error) {
	s.got = append(s.got, msg.Recipients...)
	return sending.SendResult{State: sending.StateDelivered, Code: 250}, nil
}

func TestRoutingSenderMixedRecipients(t *testing.T) {
	sender, receiver, res := testPair(t)
	tr := NewLoopbackTransport()
	ep := newReceiverEndpoint(receiver, sender)
	tr.Register("ep-recv", ep)

	smtp := &stubSMTP{}
	rs := &RoutingSender{
		Peer:     NewPeerSender(sender, res, tr),
		SMTP:     smtp,
		Resolver: res,
	}
	r, err := rs.Send(context.Background(), sending.Message{
		Sender:     "alice@send.example",
		Recipients: []string{"bob@recv.example", "carol@stranger.example"},
		RawRFC822:  []byte("Subject: m\r\n\r\nhi\r\n"),
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if r.State != sending.StateDelivered {
		t.Fatalf("state = %s, want delivered", r.State)
	}
	// Peer recipient delivered to the loopback inbox.
	if got := ep.Inbox(); len(got) != 1 {
		t.Fatalf("peer inbox = %d, want 1", len(got))
	}
	// Non-peer recipient routed to SMTP fallback only.
	if len(smtp.got) != 1 || smtp.got[0] != "carol@stranger.example" {
		t.Fatalf("smtp recipients = %v, want [carol@stranger.example]", smtp.got)
	}
}

func TestRoutingSenderAllSMTP(t *testing.T) {
	sender, _, res := testPair(t)
	smtp := &stubSMTP{}
	rs := &RoutingSender{Peer: NewPeerSender(sender, res, NewLoopbackTransport()), SMTP: smtp, Resolver: res}
	if _, err := rs.Send(context.Background(), sending.Message{
		Sender: "alice@send.example", Recipients: []string{"x@a.example", "y@b.example"}, RawRFC822: []byte("x"),
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(smtp.got) != 2 {
		t.Fatalf("expected both recipients on SMTP, got %v", smtp.got)
	}
}

// Compile-time assertions that the senders satisfy the sending.Sender seam.
var (
	_ sending.Sender = (*PeerSender)(nil)
	_ sending.Sender = (*RoutingSender)(nil)
)
