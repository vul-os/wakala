// Package rendezvous is the reference implementation of the open "rendezvous"
// infrastructure role: the key-addressed announce / resolve / signal / mailbox
// substrate that lets peers discover each other and exchange WebRTC signaling
// (and short-lived opaque blobs) through ANY conforming node — a self-hosted
// relayd or a Vulos-run one — with no Vulos OS required.
//
// It is deliberately standalone: it imports nothing from the OS repo and depends
// only on the Go standard library. The wire protocol it speaks is documented in
// docs/RENDEZVOUS.md so any implementer can build a compatible node or client.
//
// ── The role in one paragraph ───────────────────────────────────────────────
//
// Every participant is identified by an Ed25519 public key. A node ANNOUNCEs its
// presence (endpoints + TTL) under its key with a signed request; anyone RESOLVEs
// a key to its current presence with an unauthenticated read. Two peers negotiate
// a direct WebRTC connection by SIGNALing — depositing content-opaque offer /
// answer / ICE blobs addressed to each other's key, picked up by the holder of the
// matching private key. When a peer is offline, a short-TTL content-blind MAILBOX
// buffers opaque encrypted blobs addressed to its key until it comes back.
//
// ── Content-blind by construction ───────────────────────────────────────────
//
// The rendezvous node NEVER inspects, decrypts, or dials application payloads. It
// stores opaque bytes keyed by public key, gates writes with signatures, and hands
// them to the holder of the private key. It makes NO outbound connection on behalf
// of a request (announced endpoints are stored and echoed, never dialed), so it has
// no SSRF surface of its own.
package rendezvous

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
)

// keyB64 is the canonical URL-addressing of an Ed25519 public key: the 32 raw key
// bytes in unpadded base64url. It is the single key encoding used everywhere in the
// protocol — in URL path segments, in JSON fields, and inside the signed canonical
// message — so an implementer never has to guess an encoding.
//
// base64url (unpadded) is chosen over hex (shorter) and over multibase (no extra
// prefix byte to agree on); it is URL-safe so it can sit in a path segment without
// escaping.

// b64 is the unpadded base64url codec used for every binary field on the wire.
var b64 = base64.RawURLEncoding

// pubKeyLen is the Ed25519 public-key length in bytes.
const pubKeyLen = ed25519.PublicKeySize // 32

// sigLen is the Ed25519 signature length in bytes.
const sigLen = ed25519.SignatureSize // 64

var (
	errBadKey   = errors.New("invalid key")
	errBadSig   = errors.New("invalid signature encoding")
	errSigFail  = errors.New("signature verification failed")
	errBadNonce = errors.New("invalid nonce")
)

// decodeKey parses a base64url-encoded Ed25519 public key of the exact expected
// length. It fails closed on any malformed or wrong-length input rather than
// returning a truncated/padded key.
func decodeKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errBadKey
	}
	raw, err := b64.DecodeString(s)
	if err != nil || len(raw) != pubKeyLen {
		return nil, errBadKey
	}
	return ed25519.PublicKey(raw), nil
}

// normalizeKey validates a key string and returns its canonical encoding (the
// re-encoded form), so a stored/compared key is always in one form regardless of
// any incidental input variation. Returns "" on invalid input.
func normalizeKey(s string) string {
	pk, err := decodeKey(s)
	if err != nil {
		return ""
	}
	return b64.EncodeToString(pk)
}

// decodeSig parses a base64url Ed25519 signature of the exact expected length.
func decodeSig(s string) ([]byte, error) {
	raw, err := b64.DecodeString(strings.TrimSpace(s))
	if err != nil || len(raw) != sigLen {
		return nil, errBadSig
	}
	return raw, nil
}

// canonicalMessage builds the unambiguous byte string that a signature covers. It
// length-prefixes every segment (a 4-byte big-endian length followed by the
// segment's UTF-8 bytes), starting with a domain-separation tag. Length-prefixing
// means no delimiter can ever be forged across fields and two different message
// TYPES (different domain tags) can never collide, so a signature minted for one
// request can't be replayed as another.
//
// A reimplementer reproduces this exactly: for the domain tag and then each field
// in order, write uint32be(len(utf8(s))) followed by utf8(s). All binary fields
// (keys, nonces, payloads) are passed as their base64url string form and numbers as
// their base-10 decimal string, so every segment is plain text.
func canonicalMessage(domain string, fields ...string) []byte {
	total := 4 + len(domain)
	for _, f := range fields {
		total += 4 + len(f)
	}
	buf := make([]byte, 0, total)
	var lp [4]byte
	appendSeg := func(s string) {
		binary.BigEndian.PutUint32(lp[:], uint32(len(s)))
		buf = append(buf, lp[:]...)
		buf = append(buf, s...)
	}
	appendSeg(domain)
	for _, f := range fields {
		appendSeg(f)
	}
	return buf
}

// verifySig checks an Ed25519 signature (base64url) over the canonical message for
// the given key. It fails closed on any decode error or verification failure. The
// key argument is the already-decoded public key of the purported signer.
func verifySig(pub ed25519.PublicKey, sigB64 string, msg []byte) error {
	sig, err := decodeSig(sigB64)
	if err != nil {
		return err
	}
	if len(pub) != pubKeyLen {
		return errBadKey
	}
	if !ed25519.Verify(pub, msg, sig) {
		return errSigFail
	}
	return nil
}

// keyEqual is a constant-time equality check for two canonical key strings. Both
// are already-normalized base64url strings of equal length in the common case;
// subtle.ConstantTimeCompare tolerates differing lengths (returns 0) safely.
func keyEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
