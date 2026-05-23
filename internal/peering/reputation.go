// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

// reputation.go — federated peering reputation extension for vulos-relay.
//
// This file ADDS the ReputationAttestation message type and the local
// reputation aggregator. It does NOT modify any existing peering file.
//
// Design:
//   - Each Vulos node periodically (daily) generates a ReputationAttestation
//     for every sender handle it has observed, signing it with its Ed25519
//     identity key.
//   - Attestations are delivered to trusted peers via the existing PeerTransport
//     (out-of-band; treated as a side-channel alongside normal mail envelopes).
//   - Receiving nodes store attestations in a local in-memory table and use them
//     to bias the combined spam score: combined = rspamd_score * (1 + (1 - rep) * 0.5)
//   - Privacy: attestations carry ONLY aggregate counts. No per-message metadata,
//     no message content, no recipient list. The sender handle is the only PII.
//   - Backwards-compatibility: peers without reputation support simply ignore
//     unknown message types; normal mail delivery is unaffected.

package peering

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// ReputationAttestation is a signed, aggregate reputation record for one sender
// handle over a time window. Sent daily over the existing PeerTransport.
//
// Privacy invariant: carries ONLY aggregate counts, never per-message data.
type ReputationAttestation struct {
	SenderHandle      string // canonicalised e-mail handle, e.g. "alice@example.com"
	PeerNodePubkey    []byte // Ed25519 public key of the attesting Vulos node (32 bytes)
	WindowStart       int64  // unix timestamp — start of observation window
	WindowEnd         int64  // unix timestamp — end of observation window
	MessagesSent      int64  // total messages seen from SenderHandle in window
	ReportedSpamCount int64  // messages reported as spam by recipients in window
	ReportedHamCount  int64  // messages confirmed ham by recipients in window
	Signature         []byte // Ed25519 signature over the canonical body (64 bytes)
}

// attestationCanonical returns the deterministic byte representation of the
// attestation fields that are covered by the signature (all except Signature).
func attestationCanonical(a *ReputationAttestation) []byte {
	var buf bytes.Buffer
	writeStr := func(s string) {
		b := []byte(s)
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(b)))
		buf.Write(l[:])
		buf.Write(b)
	}
	writeI64 := func(v int64) {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(v))
		buf.Write(b[:])
	}
	writeStr(a.SenderHandle)
	var klen [4]byte
	binary.BigEndian.PutUint32(klen[:], uint32(len(a.PeerNodePubkey)))
	buf.Write(klen[:])
	buf.Write(a.PeerNodePubkey)
	writeI64(a.WindowStart)
	writeI64(a.WindowEnd)
	writeI64(a.MessagesSent)
	writeI64(a.ReportedSpamCount)
	writeI64(a.ReportedHamCount)
	return buf.Bytes()
}

// SignAttestation signs the attestation with the given Ed25519 private key.
// The Signature field is set in-place.
func SignAttestation(a *ReputationAttestation, priv ed25519.PrivateKey) {
	msg := attestationCanonical(a)
	a.Signature = ed25519.Sign(priv, msg)
}

// VerifyAttestation verifies the attestation signature using the public key
// embedded in PeerNodePubkey. Returns an error if verification fails.
func VerifyAttestation(a *ReputationAttestation) error {
	if len(a.PeerNodePubkey) != ed25519.PublicKeySize {
		return fmt.Errorf("reputation: invalid pubkey length %d", len(a.PeerNodePubkey))
	}
	if len(a.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("reputation: invalid signature length %d", len(a.Signature))
	}
	msg := attestationCanonical(a)
	if !ed25519.Verify(a.PeerNodePubkey, msg, a.Signature) {
		return fmt.Errorf("reputation: signature verification failed for %q", a.SenderHandle)
	}
	return nil
}

// ReputationRecord is one row in the local peer_reputations table.
type ReputationRecord struct {
	SenderHandle  string
	AttestingNode []byte // Ed25519 pubkey of the attesting node
	WindowEnd     int64  // unix
	SpamCount     int64
	HamCount      int64
	TotalSent     int64
	ReceivedAt    time.Time
}

// ReputationStore maintains the local peer_reputations table in memory.
// In production this would be backed by SQLite; here it is memory-only for
// zero-dependency use within the peering package. It is safe for concurrent use.
type ReputationStore struct {
	mu      sync.RWMutex
	records []*ReputationRecord

	// trustedNodes is the set of attesting node public keys this node trusts.
	// Attestations from unknown nodes are ignored.
	trustedNodes map[string]bool // hex(pubkey) → trusted

	// staleCutoff: attestation WindowEnd must be within this duration of now.
	staleCutoff time.Duration

	// now is a clock override for tests.
	now func() time.Time
}

// NewReputationStore creates a ReputationStore.
// trustedPubkeys are the Ed25519 public keys (raw 32 bytes) of nodes whose
// attestations this node accepts.
// staleCutoff is the maximum age of a WindowEnd before an attestation is
// considered stale and ignored. Default: 48 hours.
func NewReputationStore(trustedPubkeys []ed25519.PublicKey, staleCutoff time.Duration) *ReputationStore {
	if staleCutoff == 0 {
		staleCutoff = 48 * time.Hour
	}
	trusted := make(map[string]bool, len(trustedPubkeys))
	for _, pk := range trustedPubkeys {
		trusted[pubkeyHex(pk)] = true
	}
	return &ReputationStore{
		trustedNodes: trusted,
		staleCutoff:  staleCutoff,
		now:          time.Now,
	}
}

// Receive validates and stores an incoming ReputationAttestation. It:
//  1. Verifies the Ed25519 signature.
//  2. Checks the attesting node is in the trusted set.
//  3. Discards stale attestations (WindowEnd too old).
//
// Returns nil on success; a descriptive error if the attestation is rejected.
// An unrecognised attestation is silently ignored for backwards compatibility
// (callers that receive arbitrary peer messages must handle this).
func (rs *ReputationStore) Receive(a *ReputationAttestation) error {
	if err := VerifyAttestation(a); err != nil {
		return fmt.Errorf("reputation: rejected: %w", err)
	}
	if !rs.trustedNodes[pubkeyHex(a.PeerNodePubkey)] {
		// Not in trust list — silently ignore (backwards-compat, no error surfaced to caller).
		return nil
	}
	now := rs.now()
	windowEndTime := time.Unix(a.WindowEnd, 0)
	if now.Sub(windowEndTime) > rs.staleCutoff {
		return nil // stale; silently ignore
	}

	rec := &ReputationRecord{
		SenderHandle:  a.SenderHandle,
		AttestingNode: a.PeerNodePubkey,
		WindowEnd:     a.WindowEnd,
		SpamCount:     a.ReportedSpamCount,
		HamCount:      a.ReportedHamCount,
		TotalSent:     a.MessagesSent,
		ReceivedAt:    now,
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.records = append(rs.records, rec)
	return nil
}

// ReputationScore is a 0..1 float: 0 = certain spammer, 1 = confirmed clean.
type ReputationScore float64

// AggregateReputation combines all trusted-peer attestations for senderHandle
// and returns a 0..1 score. Returns 0.5 (neutral) if no attestations exist.
//
// Scoring: weighted average of (hamCount / totalSent) across all attestations,
// penalised by spam rate. Attestations with TotalSent=0 are skipped.
func (rs *ReputationStore) AggregateReputation(senderHandle string) ReputationScore {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	var totalWeight float64
	var weightedScore float64

	for _, r := range rs.records {
		if r.SenderHandle != senderHandle {
			continue
		}
		if r.TotalSent == 0 {
			continue
		}
		// Stale check against current time.
		now := rs.now()
		if now.Sub(time.Unix(r.WindowEnd, 0)) > rs.staleCutoff {
			continue
		}

		spamRate := float64(r.SpamCount) / float64(r.TotalSent)
		hamRate := float64(r.HamCount) / float64(r.TotalSent)
		// Score: start at 0.5, add ham contribution, subtract spam penalty.
		score := 0.5 + (hamRate * 0.5) - (spamRate * 0.5)
		if score < 0 {
			score = 0
		}
		if score > 1 {
			score = 1
		}
		weight := float64(r.TotalSent) // weight by sample size
		weightedScore += score * weight
		totalWeight += weight
	}

	if totalWeight == 0 {
		return 0.5 // neutral: no data
	}
	return ReputationScore(weightedScore / totalWeight)
}

// CombineScore computes the combined spam score:
//
//	combined = rspamd_score * (1 + (1 - reputation_score) * 0.5)
//
// A perfect reputation (1.0) leaves the rspamd score unchanged.
// Zero reputation (0.0) inflates the score by 50%.
func CombineScore(rspamdScore float64, rep ReputationScore) float64 {
	return rspamdScore * (1 + (1-float64(rep))*0.5)
}

// MarshalAttestation serialises an attestation to JSON bytes for transport.
func MarshalAttestation(a *ReputationAttestation) ([]byte, error) {
	return json.Marshal(a)
}

// UnmarshalAttestation deserialises an attestation from JSON bytes.
func UnmarshalAttestation(b []byte) (*ReputationAttestation, error) {
	var a ReputationAttestation
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, fmt.Errorf("reputation: unmarshal: %w", err)
	}
	return &a, nil
}

// SendAttestation serialises and delivers a ReputationAttestation to a remote
// peer via the existing PeerTransport. The attestation is wrapped in a minimal
// reputation-specific message frame so receivers can distinguish it from mail
// envelopes without breaking existing wire parsing.
func SendAttestation(ctx context.Context, transport PeerTransport, endpoint string, a *ReputationAttestation) error {
	b, err := MarshalAttestation(a)
	if err != nil {
		return fmt.Errorf("reputation: marshal for send: %w", err)
	}
	// Frame: magic prefix + length + JSON payload.
	frame := makeReputationFrame(b)
	return transport.Deliver(ctx, endpoint, frame)
}

// reputationMagic is the 8-byte magic prefix identifying a reputation frame
// on the wire. It is chosen to not conflict with the VULOS-PEER/1 envelope
// magic (which starts with a length-prefixed string header).
const reputationMagic = "VLSREP1\x00"

// makeReputationFrame wraps JSON payload with the reputation magic + length.
func makeReputationFrame(payload []byte) []byte {
	frame := make([]byte, len(reputationMagic)+4+len(payload))
	copy(frame, []byte(reputationMagic))
	binary.BigEndian.PutUint32(frame[len(reputationMagic):], uint32(len(payload)))
	copy(frame[len(reputationMagic)+4:], payload)
	return frame
}

// IsReputationFrame returns true if wire starts with the reputation magic.
// Callers should check this before passing a received frame to UnmarshalEnvelope,
// so that legacy receivers do not choke on a reputation frame.
func IsReputationFrame(wire []byte) bool {
	return len(wire) >= len(reputationMagic) && string(wire[:len(reputationMagic)]) == reputationMagic
}

// ParseReputationFrame extracts the JSON payload from a reputation frame,
// returning an error if the magic or length is invalid.
func ParseReputationFrame(wire []byte) ([]byte, error) {
	if !IsReputationFrame(wire) {
		return nil, fmt.Errorf("reputation: not a reputation frame")
	}
	off := len(reputationMagic)
	if len(wire) < off+4 {
		return nil, fmt.Errorf("reputation: frame too short")
	}
	plen := binary.BigEndian.Uint32(wire[off:])
	off += 4
	if uint32(len(wire)-off) < plen {
		return nil, fmt.Errorf("reputation: frame payload truncated")
	}
	return wire[off : off+int(plen)], nil
}

// pubkeyHex returns the hex string of a raw public key, used as a map key.
func pubkeyHex(pub []byte) string {
	const hexChars = "0123456789abcdef"
	out := make([]byte, len(pub)*2)
	for i, b := range pub {
		out[i*2] = hexChars[b>>4]
		out[i*2+1] = hexChars[b&0xf]
	}
	return string(out)
}
