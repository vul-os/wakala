// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package peering

import (
	"context"
	"sync"
	"testing"

	"github.com/vul-os/vulos-relay/internal/sending"
)

// collectingSink records delivered (mailFrom, rcptTo, raw) tuples.
type collectingSink struct {
	mu        sync.Mutex
	delivered [][]byte
	failNext  bool // when true, the next Deliver returns a transient error
}

func (s *collectingSink) Deliver(_ context.Context, _ string, _ []string, raw []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failNext {
		s.failNext = false
		return context.DeadlineExceeded // any non-nil → transient
	}
	cp := make([]byte, len(raw))
	copy(cp, raw)
	s.delivered = append(s.delivered, cp)
	return nil
}

func (s *collectingSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.delivered)
}

// bucketReceiver builds a Receiver for recv.example wired to sink + resolver.
func bucketReceiver(receiver *Identity, res *StaticResolver, sink *collectingSink) *Receiver {
	return &Receiver{
		Identity:   receiver,
		Authorized: func(d string) bool { return d == "recv.example" },
		PinnedKey:  res.PinnedKey,
		Guard:      NewReplayGuard(),
		Sink:       sink,
	}
}

// TestBucketTransportRoundTrip proves Send→bucket→ingest delivers the message
// through the full §7–§8 receiver checks against an in-memory bucket.
func TestBucketTransportRoundTrip(t *testing.T) {
	sender, receiver, res := testPair(t)
	// Pin the sender domain so the receiver authorizes it (§8.2).
	if err := res.Add(&PeerDescriptor{
		Domains:     []string{"send.example"},
		IdentityPub: sender.SignPub,
		KexPub:      sender.KexPub,
		Versions:    []string{ProtoV1},
		Suites:      []string{SuiteV1},
		Endpoint:    "bucket:peers/inbox/sender",
	}); err != nil {
		t.Fatal(err)
	}

	bucket := NewMemBucket()

	// The receiver's descriptor endpoint designates its bucket inbox prefix.
	recvDesc, _ := res.Resolve(context.Background(), "recv.example")
	recvDesc.Endpoint = "bucket:peers/inbox/recv"

	// Sender side: PeerSender over the bucket transport.
	transport := NewBucketTransport(bucket)
	ps := NewPeerSender(sender, res, transport)

	msg := sending.Message{
		ID:         "b1",
		Sender:     "alice@send.example",
		Recipients: []string{"bob@recv.example"},
		RawRFC822:  []byte("Subject: hi\r\n\r\nhello over bucket\r\n"),
	}
	res1, err := ps.Send(context.Background(), msg)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if res1.State != sending.StateDelivered {
		t.Fatalf("Send state = %s (%s), want delivered (durably enqueued)", res1.State, res1.Message)
	}
	if bucket.Len() != 1 {
		t.Fatalf("want 1 object enqueued, got %d", bucket.Len())
	}

	// Receiver side: ingest the inbox.
	sink := &collectingSink{}
	in := &BucketIngestor{
		Client:   bucket,
		Prefix:   "peers/inbox/recv",
		Receiver: bucketReceiver(receiver, res, sink),
	}
	n := in.PollOnce(context.Background())
	if n != 1 {
		t.Fatalf("ingest delivered %d, want 1", n)
	}
	if sink.count() != 1 {
		t.Fatalf("sink got %d messages, want 1", sink.count())
	}
	// Object should be deleted after successful delivery.
	if bucket.Len() != 0 {
		t.Fatalf("want object deleted after delivery, %d remain", bucket.Len())
	}
}

// TestBucketIngestRejectsForgedEnvelope proves the receiver §8 checks still
// apply on the bucket path: an envelope whose signature does not verify is
// rejected and the object is dropped (never delivered).
func TestBucketIngestRejectsForgedEnvelope(t *testing.T) {
	sender, receiver, res := testPair(t)
	if err := res.Add(&PeerDescriptor{
		Domains:     []string{"send.example"},
		IdentityPub: sender.SignPub,
		KexPub:      sender.KexPub,
		Versions:    []string{ProtoV1},
		Suites:      []string{SuiteV1},
		Endpoint:    "bucket:peers/inbox/sender",
	}); err != nil {
		t.Fatal(err)
	}

	bucket := NewMemBucket()
	recvDesc, _ := res.Resolve(context.Background(), "recv.example")
	recvDesc.Endpoint = "bucket:peers/inbox/recv"

	// Build a valid envelope, then tamper the payload so the signature fails.
	env := sealFixture(t, sender, receiver, res)
	env.Payload = append([]byte{}, env.Payload...)
	env.Payload[0] ^= 0xFF
	wire := MarshalEnvelope(env)
	if err := bucket.Put(context.Background(), "peers/inbox/recv/000-forged.env", wire); err != nil {
		t.Fatal(err)
	}

	sink := &collectingSink{}
	in := &BucketIngestor{
		Client:   bucket,
		Prefix:   "peers/inbox/recv",
		Receiver: bucketReceiver(receiver, res, sink),
	}
	n := in.PollOnce(context.Background())
	if n != 0 {
		t.Fatalf("forged envelope must NOT be delivered, ingest reported %d delivered", n)
	}
	if sink.count() != 0 {
		t.Fatalf("forged envelope reached the sink (%d) — §8 checks bypassed", sink.count())
	}
	// Permanent rejection → object dropped so it does not accumulate.
	if bucket.Len() != 0 {
		t.Fatalf("permanently-rejected object should be deleted, %d remain", bucket.Len())
	}
}

// TestBucketIngestRetainsOnTransientFailure proves a transient local-delivery
// failure leaves the object in the bucket for a later poll (no data loss).
func TestBucketIngestRetainsOnTransientFailure(t *testing.T) {
	sender, receiver, res := testPair(t)
	if err := res.Add(&PeerDescriptor{
		Domains:     []string{"send.example"},
		IdentityPub: sender.SignPub,
		KexPub:      sender.KexPub,
		Versions:    []string{ProtoV1},
		Suites:      []string{SuiteV1},
		Endpoint:    "bucket:peers/inbox/sender",
	}); err != nil {
		t.Fatal(err)
	}

	bucket := NewMemBucket()
	env := sealFixture(t, sender, receiver, res)
	if err := bucket.Put(context.Background(), "peers/inbox/recv/000-ok.env", MarshalEnvelope(env)); err != nil {
		t.Fatal(err)
	}

	sink := &collectingSink{failNext: true}
	in := &BucketIngestor{
		Client:   bucket,
		Prefix:   "peers/inbox/recv",
		Receiver: bucketReceiver(receiver, res, sink),
	}

	// First poll: sink fails transiently → object retained.
	if n := in.PollOnce(context.Background()); n != 0 {
		t.Fatalf("transient failure: want 0 delivered, got %d", n)
	}
	if bucket.Len() != 1 {
		t.Fatalf("transient failure: object must be retained, %d remain", bucket.Len())
	}

	// Second poll: sink succeeds → delivered + object removed.
	if n := in.PollOnce(context.Background()); n != 1 {
		t.Fatalf("retry: want 1 delivered, got %d", n)
	}
	if bucket.Len() != 0 {
		t.Fatalf("retry: object should be deleted after delivery, %d remain", bucket.Len())
	}
}

// TestMultiTransportRoutesByScheme proves a single PeerSender can use the bucket
// carrier for a bucket: endpoint and a fallback for the rest.
func TestMultiTransportRoutesByScheme(t *testing.T) {
	bucket := NewMemBucket()
	bt := NewBucketTransport(bucket)
	loop := NewLoopbackTransport()
	mt := NewMultiTransport(loop, bt)

	if err := mt.Deliver(context.Background(), "bucket:peers/inbox/x", []byte("env")); err != nil {
		t.Fatalf("bucket route: %v", err)
	}
	if bucket.Len() != 1 {
		t.Fatalf("bucket route did not write object, len=%d", bucket.Len())
	}
	// A non-bucket endpoint routes to the loopback (unregistered → ErrMisrouted).
	if err := mt.Deliver(context.Background(), "https://peer.example", []byte("env")); err != ErrMisrouted {
		t.Fatalf("default route: want ErrMisrouted from empty loopback, got %v", err)
	}
}
