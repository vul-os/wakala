// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package peering

import "context"

// MultiTransport dispatches a Deliver to the right carrier based on the peer's
// descriptor Endpoint, so a single PeerSender can reach some peers over HTTP and
// others over the shared bucket — selected per-peer by config (the Endpoint
// scheme). It is the seam that makes the bucket carrier selectable alongside
// HTTP without changing the PeerSender or the wire format.
//
//   - A "bucket:<prefix>" endpoint routes to Bucket.
//   - Anything else (http(s):// or a bare authority) routes to Default.
//
// MultiTransport is safe for concurrent use when its underlying transports are.
type MultiTransport struct {
	// Default handles non-bucket endpoints (typically an *HTTPTransport or, in
	// tests/standalone, a *LoopbackTransport).
	Default PeerTransport
	// Bucket handles "bucket:<prefix>" endpoints. May be nil if the bucket
	// carrier is not configured; a bucket endpoint then yields ErrUnsupported.
	Bucket PeerTransport
}

// NewMultiTransport builds a MultiTransport. Either carrier may be nil.
func NewMultiTransport(def, bucket PeerTransport) *MultiTransport {
	return &MultiTransport{Default: def, Bucket: bucket}
}

// Deliver implements PeerTransport by routing on the endpoint scheme.
func (m *MultiTransport) Deliver(ctx context.Context, endpoint string, wire []byte) error {
	if IsBucketEndpoint(endpoint) {
		if m.Bucket == nil {
			return ErrUnsupported
		}
		return m.Bucket.Deliver(ctx, endpoint, wire)
	}
	if m.Default == nil {
		return ErrUnsupported
	}
	return m.Default.Deliver(ctx, endpoint, wire)
}

var _ PeerTransport = (*MultiTransport)(nil)
