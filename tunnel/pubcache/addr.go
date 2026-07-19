// Package pubcache implements the DMTAP substrate's CACHE/PIN role
// (substrate/ROLES.md § 6) over the DMTAP-PUB public-object HTTP profile
// (dmtap § 22.5.1, substrate/FEEDS.md § 5).
//
// The role in one sentence: a node may cache and re-serve PUBLIC,
// content-addressed, self-verifying objects — announces, manifests, chunks —
// on behalf of upstream § 22 gateways, so readers get a nearby copy.
//
// Why this is safe to run on shared infrastructure: every object served here is
// authenticated by the address it is fetched by. A cache therefore CANNOT FORGE
// an object (that needs the publisher's key, or a BLAKE3 collision); the worst a
// broken or hostile cache can do is FAIL TO SERVE, and a fetcher rotates to
// another holder (ERR_PUB_NOT_SERVED, 0x090C). That asymmetry is the entire
// security argument for the role, and this package preserves it by refusing to
// STORE anything whose bytes do not match its content address (verify.go).
//
// This is an open protocol behaviour, not a Vulos service: any node may serve
// this role, and a Vulos-operated PoP is just a well-run instance of it. It is
// OFF by default — serving public objects means serving PLAINTEXT THE OPERATOR
// CAN READ, which shifts an operator's moderation and liability posture, so
// § 22.6.1 makes it explicit operator opt-in (the pub-1 capability). Unlike the
// relay, mailbox, and rendezvous roles, this one is NOT content-blind, and the
// package is written to make that trade visible rather than incidental.
package pubcache

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/zeebo/blake3"
)

// addr.go — DMTAP content addressing (§ 18.1.5 multihash-style prefix,
// § 22.2.2 plaintext addressing).
//
// A v0 address is the 33-byte value `0x1e ‖ BLAKE3-256(...)` and travels on the
// wire as unpadded base64url. The prefix is what preserves hash agility: a later
// suite is a different prefix, never a different address FORMAT. This node
// implements exactly one suite and rejects every other prefix fail-closed — an
// address it cannot verify is an address it MUST NOT cache.

const (
	// HashPrefixBLAKE3_256 is the § 18.1.5 multihash-style prefix for the v0
	// suite. It is the only prefix this implementation accepts.
	HashPrefixBLAKE3_256 = 0x1e

	digestLen     = 32            // BLAKE3-256
	addrLen       = 1 + digestLen // prefix ‖ digest
	maxAddrB64Len = 64            // 33 bytes base64url-encodes to 44 chars; cap the input hard
)

// Errors returned by address parsing and verification. They map onto the § 21
// DMTAP-PUB error block; the HTTP surface collapses them all to a refusal,
// because a cache that cannot verify simply does not serve (0x090C).
var (
	// ErrBadAddr is a syntactically invalid or unsupported content address.
	ErrBadAddr = errors.New("pubcache: malformed content address")
	// ErrAddrMismatch is the load-bearing one: the bytes do not hash to the
	// address they were fetched by (0x0905 / 0x0909 / 0x090A). It is why a
	// poisoned upstream can never become a poisoned cache.
	ErrAddrMismatch = errors.New("pubcache: content address mismatch")
	// ErrMalformedObject is a structurally invalid object (0x0901).
	ErrMalformedObject = errors.New("pubcache: malformed object")
	// ErrManifestKeyPresent is the § 22.2.1 key-5 trap: a PubManifest carrying a
	// key field is a leaked sealed manifest or a malformation, never valid
	// (ERR_PUB_MANIFEST_KEY_PRESENT, 0x0902).
	ErrManifestKeyPresent = errors.New("pubcache: PubManifest carries forbidden key field")
)

// Addr is a DMTAP content address: prefix ‖ digest.
type Addr [addrLen]byte

// String renders the address as unpadded base64url, the § 22.5.1 path form.
func (a Addr) String() string { return base64.RawURLEncoding.EncodeToString(a[:]) }

// ParseAddr parses the `{id}` / `{h}` path component of a § 22.5.1 read.
//
// It is strict on purpose: unpadded base64url only, exactly 33 bytes, prefix
// 0x1e only. A lenient parser here would let two spellings of one address
// occupy two cache entries (a cheap amplification), so canonicity is enforced
// rather than assumed.
func ParseAddr(s string) (Addr, error) {
	var a Addr
	if s == "" || len(s) > maxAddrB64Len {
		return a, ErrBadAddr
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return a, fmt.Errorf("%w: %v", ErrBadAddr, err)
	}
	if len(raw) != addrLen {
		return a, fmt.Errorf("%w: got %d bytes, want %d", ErrBadAddr, len(raw), addrLen)
	}
	if raw[0] != HashPrefixBLAKE3_256 {
		return a, fmt.Errorf("%w: unsupported hash prefix 0x%02x", ErrBadAddr, raw[0])
	}
	copy(a[:], raw)
	// Re-encoding must reproduce the input exactly: rejects any non-canonical
	// spelling that base64 would otherwise tolerate.
	if a.String() != s {
		return Addr{}, fmt.Errorf("%w: non-canonical encoding", ErrBadAddr)
	}
	return a, nil
}

// HashBytes computes the v0 content address of a byte string:
// `0x1e ‖ BLAKE3-256(b)`. This is the § 18.9.4 generic anchor rule, which is
// what addresses a PubAnnounce (§ 22.3.3 step 2) and a plaintext chunk
// (§ 22.2.2 step 1). A PubManifest is NOT addressed this way — its address is a
// Merkle root over its chunk list (see merkle.go).
func HashBytes(b []byte) Addr {
	sum := blake3.Sum256(b)
	var a Addr
	a[0] = HashPrefixBLAKE3_256
	copy(a[1:], sum[:])
	return a
}
