// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package peering

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Bucket-based peer transport (spec/PEERING.md §2 — an alternative carrier to
// the HTTP transport).
//
// Motivation: not every Vulos relay is reachable on an inbound HTTPS port (NAT,
// air-gapped-ish edge, intermittent connectivity). A shared S3/Tigris-compatible
// object store gives a store-and-forward rendezvous: the SENDER writes the
// already-encrypted, already-authenticated envelope as an object under a prefix
// the RECEIVER polls; the receiver's ingestor lists + fetches new objects and
// runs the EXACT same §7–§8 receiver checks (via Receiver.Accept) before local
// delivery, then deletes the object.
//
// The envelope is end-to-end encrypted + signed (envelope.go), so the bucket —
// like any other carrier — provides NO confidentiality or authenticity of its
// own and does NO public DNS lookup or blocklist exposure. A bucket operator who
// can read objects sees only opaque ciphertext bound to a receiver key; a bucket
// operator who can write objects cannot forge a valid envelope (no signing key)
// and any tampered/forged object is rejected by §8 + dropped. Replay across
// polls is handled by the receiver's shared ReplayGuard (§7), so re-reading the
// same object is idempotent.
//
// This transport is selectable alongside HTTPTransport via config (a peer whose
// descriptor Endpoint is a `bucket:<prefix>` address routes here).

// BucketClient is the minimal S3/Tigris/MinIO-compatible object-store surface
// the transport needs. A real client (aws-sdk-go-v2, minio-go, etc.) is wired by
// the operator/control plane; this package ships an in-memory fake for tests and
// single-process standalone use. Keeping it a seam means the relay build stays
// CGO_ENABLED=0 and does not pull a specific SDK into the OSS module.
//
// Implementations must be safe for concurrent use. Keys are opaque object names
// (the transport composes them under a prefix). Bodies are the raw envelope wire
// blobs (opaque bytes).
type BucketClient interface {
	// Put writes body at key, overwriting any existing object.
	Put(ctx context.Context, key string, body []byte) error
	// List returns the keys under prefix (no pagination contract beyond "all
	// current keys"; a real adapter may page internally).
	List(ctx context.Context, prefix string) ([]string, error)
	// Get returns the body at key. A missing key returns ErrObjectNotFound.
	Get(ctx context.Context, key string) ([]byte, error)
	// Delete removes key. Deleting a missing key is not an error.
	Delete(ctx context.Context, key string) error
}

// ErrObjectNotFound is returned by BucketClient.Get for a missing key.
var ErrObjectNotFound = errors.New("peering: bucket object not found")

// bucketEndpointScheme prefixes a descriptor Endpoint that designates the bucket
// carrier. The remainder is the receiver's inbox prefix within the shared
// bucket, e.g. "bucket:peers/inbox/peer-b". The transport writes envelopes under
// "<prefix>/<random>.env".
const bucketEndpointScheme = "bucket:"

// IsBucketEndpoint reports whether a descriptor endpoint designates the bucket
// carrier (so the routing layer / config can pick this transport for that peer).
func IsBucketEndpoint(endpoint string) bool {
	return strings.HasPrefix(strings.TrimSpace(endpoint), bucketEndpointScheme)
}

// bucketPrefixOf extracts the inbox prefix from a bucket endpoint, trimming the
// scheme and any surrounding slashes.
func bucketPrefixOf(endpoint string) (string, error) {
	e := strings.TrimSpace(endpoint)
	if !strings.HasPrefix(e, bucketEndpointScheme) {
		return "", fmt.Errorf("peering: not a bucket endpoint: %q", endpoint)
	}
	prefix := strings.Trim(strings.TrimPrefix(e, bucketEndpointScheme), "/")
	if prefix == "" {
		return "", fmt.Errorf("peering: bucket endpoint %q has empty prefix", endpoint)
	}
	return prefix, nil
}

// BucketTransport is a PeerTransport that hands an envelope off by writing it as
// an object under the receiver's inbox prefix in a shared bucket. The receiver's
// BucketIngestor polls that prefix. It is safe for concurrent use.
//
// Because the bucket is a one-way drop (no synchronous receiver response), a
// successful Put means the envelope is durably enqueued for the peer — NOT that
// the peer has accepted it. Permanent receiver rejections (bad signature, etc.)
// are therefore surfaced asynchronously on the INGEST side (logged + dropped),
// not back through Deliver. This matches the store-and-forward model and the
// spec §10 "defer on the peer path" failure contract: a Put failure is a
// transient carrier error and the sender retries.
type BucketTransport struct {
	// Client is the object-store client. Required.
	Client BucketClient
	// Now overrides the clock for object-key timestamps (tests). Optional.
	Now func() time.Time
}

// NewBucketTransport constructs a BucketTransport over client.
func NewBucketTransport(client BucketClient) *BucketTransport {
	return &BucketTransport{Client: client}
}

// Deliver implements PeerTransport: it writes wire as a new object under the
// receiver inbox prefix encoded in endpoint ("bucket:<prefix>"). A write failure
// is a transient carrier error (the caller defers + retries on the peer path).
func (t *BucketTransport) Deliver(ctx context.Context, endpoint string, wire []byte) error {
	if t.Client == nil {
		return errors.New("peering: bucket transport has no client")
	}
	prefix, err := bucketPrefixOf(endpoint)
	if err != nil {
		return err
	}
	key, err := t.objectKey(prefix)
	if err != nil {
		return err
	}
	if err := t.Client.Put(ctx, key, wire); err != nil {
		// Transient carrier failure; sender defers + retries (spec §10). Never a
		// silent SMTP downgrade.
		return fmt.Errorf("peering: bucket put %q: %w", key, err)
	}
	return nil
}

// objectKey composes a unique, sortable object key under prefix. The leading
// timestamp gives rough FIFO ordering on List; the random suffix avoids
// collisions between concurrent senders.
func (t *BucketTransport) objectKey(prefix string) (string, error) {
	now := time.Now
	if t.Now != nil {
		now = t.Now
	}
	var rnd [12]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return "", fmt.Errorf("peering: bucket key rand: %w", err)
	}
	// nanos for ordering + hex random for uniqueness; ".env" so non-envelope
	// objects (if the prefix is shared) are ignored by the ingestor.
	return fmt.Sprintf("%s/%020d-%s.env", prefix, now().UTC().UnixNano(), hex.EncodeToString(rnd[:])), nil
}

// BucketIngestor is the receiver side of the bucket carrier: it polls a bucket
// inbox prefix for new envelope objects, runs each through Receiver.Accept (the
// full §7–§8 checks), and deletes the object once it has been handled.
//
// Deletion policy:
//   - Accept returns nil (delivered) → delete the object (done).
//   - Accept returns a PERMANENT rejection (bad signature, unauthorized,
//     misrouted, replay, unsupported, corrupt) → delete the object: it can
//     never succeed and must not accumulate. The rejection is logged/observed.
//   - Accept returns a TRANSIENT error (local delivery failure) → LEAVE the
//     object so a later poll retries it.
type BucketIngestor struct {
	// Client is the object-store client. Required.
	Client BucketClient
	// Prefix is THIS node's inbox prefix (the bare prefix, no "bucket:" scheme).
	Prefix string
	// Receiver runs the §7–§8 checks + local delivery. Required.
	Receiver *Receiver
	// Interval is the poll interval. Zero defaults to 5s.
	Interval time.Duration
	// Logf, if non-nil, logs ingest activity. Optional.
	Logf func(format string, args ...any)
}

func (in *BucketIngestor) logf(format string, args ...any) {
	if in.Logf != nil {
		in.Logf(format, args...)
	}
}

// Run polls the inbox until ctx is cancelled. It is the long-running ingest loop
// wired by the daemon when the bucket carrier is enabled.
func (in *BucketIngestor) Run(ctx context.Context) {
	interval := in.Interval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	// Poll once immediately, then on each tick.
	in.PollOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			in.PollOnce(ctx)
		}
	}
}

// PollOnce processes all currently-pending objects in the inbox exactly once. It
// is exported so a test (or a one-shot drain) can drive ingest deterministically
// without the timer. It returns the number of objects DELIVERED (Accept==nil).
func (in *BucketIngestor) PollOnce(ctx context.Context) int {
	if in.Client == nil || in.Receiver == nil {
		return 0
	}
	prefix := strings.Trim(in.Prefix, "/")
	keys, err := in.Client.List(ctx, prefix+"/")
	if err != nil {
		in.logf("peering: bucket ingest list %q: %v", prefix, err)
		return 0
	}
	// Process in key order (timestamp-prefixed → rough FIFO).
	sort.Strings(keys)
	delivered := 0
	for _, key := range keys {
		if !strings.HasSuffix(key, ".env") {
			continue
		}
		body, gerr := in.Client.Get(ctx, key)
		if gerr != nil {
			if errors.Is(gerr, ErrObjectNotFound) {
				continue // another ingestor took it; fine
			}
			in.logf("peering: bucket ingest get %q: %v", key, gerr)
			continue
		}
		// Two-phase accept: the §7 replay pair is committed only on successful
		// delivery, so a transient local failure leaves the stored object
		// retryable without burning the nonce.
		aerr := in.Receiver.AcceptStored(ctx, body)
		switch {
		case aerr == nil:
			delivered++
			in.deleteObject(ctx, key)
		case isPermanentReject(aerr):
			// Can never succeed; drop so it does not accumulate.
			in.logf("peering: bucket ingest dropping permanently-rejected object %q: %v", key, aerr)
			in.deleteObject(ctx, key)
		default:
			// Transient (local delivery) failure: leave for the next poll.
			in.logf("peering: bucket ingest transient failure for %q (will retry): %v", key, aerr)
		}
	}
	return delivered
}

func (in *BucketIngestor) deleteObject(ctx context.Context, key string) {
	if err := in.Client.Delete(ctx, key); err != nil {
		in.logf("peering: bucket ingest delete %q: %v", key, err)
	}
}

// isPermanentReject reports whether an Accept error is one of the permanent §8
// receiver rejections (vs. a transient local-delivery failure).
func isPermanentReject(err error) bool {
	switch {
	case errors.Is(err, ErrUnauthenticated),
		errors.Is(err, ErrUnauthorized),
		errors.Is(err, ErrMisrouted),
		errors.Is(err, ErrReplay),
		errors.Is(err, ErrUnsupported),
		errors.Is(err, ErrCorrupt):
		return true
	default:
		return false
	}
}

// ── in-memory fake bucket ──────────────────────────────────────────────────

// MemBucket is an in-memory BucketClient for tests and single-process standalone
// use. It is safe for concurrent use.
type MemBucket struct {
	mu      sync.Mutex
	objects map[string][]byte
}

// NewMemBucket creates an empty in-memory bucket.
func NewMemBucket() *MemBucket {
	return &MemBucket{objects: make(map[string][]byte)}
}

// Put implements BucketClient.
func (b *MemBucket) Put(_ context.Context, key string, body []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	cp := make([]byte, len(body))
	copy(cp, body)
	b.objects[key] = cp
	return nil
}

// List implements BucketClient.
func (b *MemBucket) List(_ context.Context, prefix string) ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for k := range b.objects {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	return out, nil
}

// Get implements BucketClient.
func (b *MemBucket) Get(_ context.Context, key string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	body, ok := b.objects[key]
	if !ok {
		return nil, ErrObjectNotFound
	}
	cp := make([]byte, len(body))
	copy(cp, body)
	return cp, nil
}

// Delete implements BucketClient.
func (b *MemBucket) Delete(_ context.Context, key string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.objects, key)
	return nil
}

// Len reports the number of objects currently stored (test helper).
func (b *MemBucket) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.objects)
}

// Compile-time interface checks.
var (
	_ PeerTransport = (*BucketTransport)(nil)
	_ BucketClient  = (*MemBucket)(nil)
)
