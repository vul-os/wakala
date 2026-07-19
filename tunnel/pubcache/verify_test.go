package pubcache

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/zeebo/blake3"
)

// verify_test.go — the address/verification contract. These tests are the ones
// that matter most in this package: they pin the promise that a cache cannot be
// poisoned, only starved.

// ---------------------------------------------------------------------------
// tiny deterministic-CBOR encoder, test-only (the package itself never encodes)
// ---------------------------------------------------------------------------

func cborHead(major byte, arg uint64) []byte {
	switch {
	case arg < 24:
		return []byte{major<<5 | byte(arg)}
	case arg <= 0xff:
		return []byte{major<<5 | 24, byte(arg)}
	case arg <= 0xffff:
		b := []byte{major<<5 | 25, 0, 0}
		binary.BigEndian.PutUint16(b[1:], uint16(arg))
		return b
	case arg <= 0xffffffff:
		b := []byte{major<<5 | 26, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(b[1:], uint32(arg))
		return b
	default:
		b := []byte{major<<5 | 27, 0, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint64(b[1:], arg)
		return b
	}
}

func cborUint(v uint64) []byte  { return cborHead(0, v) }
func cborBytes(b []byte) []byte { return append(cborHead(2, uint64(len(b))), b...) }

func cborMap(pairs ...[]byte) []byte {
	out := cborHead(5, uint64(len(pairs)/2))
	for _, p := range pairs {
		out = append(out, p...)
	}
	return out
}

func cborArray(items ...[]byte) []byte {
	out := cborHead(4, uint64(len(items)))
	for _, it := range items {
		out = append(out, it...)
	}
	return out
}

// buildManifest encodes a well-formed PubManifest over the given plaintext
// chunks and returns (address, encoded bytes).
func buildManifest(t *testing.T, chunkData ...[]byte) (Addr, []byte) {
	t.Helper()
	hashes := make([]Addr, 0, len(chunkData))
	items := make([][]byte, 0, len(chunkData))
	total := 0
	for _, c := range chunkData {
		h := HashBytes(c)
		hashes = append(hashes, h)
		hc := h
		items = append(items, cborBytes(hc[:]))
		total += len(c)
	}
	id := ManifestRoot(hashes)
	idb := id
	body := cborMap(
		cborUint(1), cborBytes(idb[:]),
		cborUint(2), cborUint(uint64(total)),
		cborUint(3), cborUint(1<<20),
		cborUint(4), cborArray(items...),
		cborUint(6), cborUint(0),
	)
	return id, body
}

// ---------------------------------------------------------------------------
// addressing
// ---------------------------------------------------------------------------

// TestBlake3KnownAnswer pins the hash function itself: if the dependency ever
// changed algorithm under us, every address in the cache would silently become
// wrong, so the suite is nailed to a published vector.
func TestBlake3KnownAnswer(t *testing.T) {
	sum := blake3.Sum256([]byte("abc"))
	const want = "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("BLAKE3-256(\"abc\") = %s, want %s", got, want)
	}
}

func TestHashBytesCarriesMultihashPrefix(t *testing.T) {
	a := HashBytes([]byte("hello"))
	if a[0] != HashPrefixBLAKE3_256 {
		t.Fatalf("address prefix = 0x%02x, want 0x1e", a[0])
	}
	if len(a.String()) != 44 {
		t.Fatalf("base64url address length = %d, want 44", len(a.String()))
	}
}

func TestParseAddrRoundTrip(t *testing.T) {
	a := HashBytes([]byte("round trip"))
	got, err := ParseAddr(a.String())
	if err != nil {
		t.Fatal(err)
	}
	if got != a {
		t.Fatal("round-trip address mismatch")
	}
}

func TestParseAddrRejectsMalformed(t *testing.T) {
	good := HashBytes([]byte("x")).String()
	cases := map[string]string{
		"empty":           "",
		"padded base64":   good + "=",
		"standard base64": "+" + good[1:],
		"too short":       good[:20],
		"too long":        good + good,
		"not base64":      "!!!!",
		"wrong hash prefix": func() string {
			a := HashBytes([]byte("x"))
			a[0] = 0x12 // SHA2-256 — a suite this node does not implement
			return a.String()
		}(),
	}
	for name, in := range cases {
		if _, err := ParseAddr(in); err == nil {
			t.Fatalf("%s: expected rejection, got nil", name)
		}
	}
}

// ---------------------------------------------------------------------------
// verification: announces and chunks
// ---------------------------------------------------------------------------

func TestVerifyChunkAndAnnounceAcceptMatchingBytes(t *testing.T) {
	body := []byte("public plaintext chunk")
	a := HashBytes(body)
	for _, k := range []Kind{KindChunk, KindAnnounce} {
		if err := Verify(k, a, body); err != nil {
			t.Fatalf("%s: %v", k, err)
		}
	}
}

// TestVerifyRejectsPoisonedBytes is the core anti-poisoning assertion: an
// upstream that returns the WRONG bytes for a right address is refused, so the
// poisoning stops at this node instead of being amplified by it.
func TestVerifyRejectsPoisonedBytes(t *testing.T) {
	honest := []byte("the real object")
	a := HashBytes(honest)
	for _, k := range []Kind{KindChunk, KindAnnounce} {
		err := Verify(k, a, []byte("attacker substituted this"))
		if !errors.Is(err, ErrAddrMismatch) {
			t.Fatalf("%s: expected ErrAddrMismatch, got %v", k, err)
		}
	}
	// A single flipped bit must also fail.
	tampered := append([]byte(nil), honest...)
	tampered[0] ^= 0x01
	if err := Verify(KindChunk, a, tampered); !errors.Is(err, ErrAddrMismatch) {
		t.Fatalf("one-bit tamper accepted: %v", err)
	}
}

// ---------------------------------------------------------------------------
// verification: manifests
// ---------------------------------------------------------------------------

func TestVerifyManifestAcceptsWellFormed(t *testing.T) {
	// Exercise several chunk counts so the RFC 6962 split rule is covered for
	// both power-of-two and ragged trees.
	for _, n := range []int{1, 2, 3, 4, 5, 7, 8, 9, 16, 17} {
		chunks := make([][]byte, n)
		for i := range chunks {
			chunks[i] = []byte{byte(i), byte(i >> 8), 'c'}
		}
		id, body := buildManifest(t, chunks...)
		if err := Verify(KindManifest, id, body); err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
	}
}

func TestVerifyManifestRejectsAlteredChunkList(t *testing.T) {
	id, body := buildManifest(t, []byte("a"), []byte("b"), []byte("c"))
	// Swap two chunk hashes: same set, different order ⇒ different Merkle root.
	swapped := append([]byte(nil), body...)
	ha, hb := HashBytes([]byte("a")), HashBytes([]byte("b"))
	ia := bytes.Index(swapped, ha[:])
	ib := bytes.Index(swapped, hb[:])
	if ia < 0 || ib < 0 {
		t.Fatal("test setup: chunk hashes not found in encoding")
	}
	copy(swapped[ia:], hb[:])
	copy(swapped[ib:], ha[:])
	if err := Verify(KindManifest, id, swapped); !errors.Is(err, ErrAddrMismatch) {
		t.Fatalf("reordered chunk list accepted: %v", err)
	}
}

// TestVerifyManifestKeyFiveTrap: a manifest carrying the forbidden key field is
// either a leaked SEALED manifest or a malformation — never something to cache.
func TestVerifyManifestKeyFiveTrap(t *testing.T) {
	h := HashBytes([]byte("a"))
	hc := h
	id := ManifestRoot([]Addr{h})
	idb := id
	body := cborMap(
		cborUint(1), cborBytes(idb[:]),
		cborUint(2), cborUint(1),
		cborUint(3), cborUint(1<<20),
		cborUint(4), cborArray(cborBytes(hc[:])),
		cborUint(5), cborBytes(make([]byte, 32)), // FORBIDDEN
		cborUint(6), cborUint(0),
	)
	if err := Verify(KindManifest, id, body); !errors.Is(err, ErrManifestKeyPresent) {
		t.Fatalf("key-5 manifest accepted: %v", err)
	}
}

// TestVerifyManifestSelfIDMustAgree: an object that disagrees with itself is
// never stored, even if its chunk list happens to root correctly.
func TestVerifyManifestSelfIDMustAgree(t *testing.T) {
	id, body := buildManifest(t, []byte("a"), []byte("b"))
	wrong := HashBytes([]byte("not the id"))
	tampered := append([]byte(nil), body...)
	i := bytes.Index(tampered, id[:])
	if i < 0 {
		t.Fatal("test setup: id not found")
	}
	copy(tampered[i:], wrong[:])
	if err := Verify(KindManifest, id, tampered); !errors.Is(err, ErrAddrMismatch) {
		t.Fatalf("self-inconsistent manifest accepted: %v", err)
	}
}

// TestVerifyManifestRejectsSealedShapedInput: a sealed Manifest (§ 5.5) fed to
// the public verifier cannot pass — the DS-tagged tree and the plaintext chunk
// hashes make the two address spaces type-incompatible (§ 22.2.3), and the
// failure is a rejection, never a coercion.
func TestVerifyManifestRejectsSealedShapedInput(t *testing.T) {
	h := HashBytes([]byte("ciphertext chunk"))
	hc := h
	// Sealed-style root: plain RFC 6962 tags with NO DMTAP-PUB DS fold.
	d := blake3.New()
	_, _ = d.Write([]byte{0x00})
	_, _ = d.Write(hc[:])
	var sealedRoot Addr
	sealedRoot[0] = HashPrefixBLAKE3_256
	copy(sealedRoot[1:], d.Sum(nil))
	srb := sealedRoot
	body := cborMap(
		cborUint(1), cborBytes(srb[:]),
		cborUint(2), cborUint(16),
		cborUint(3), cborUint(1<<20),
		cborUint(4), cborArray(cborBytes(hc[:])),
		cborUint(6), cborUint(0),
	)
	if err := Verify(KindManifest, sealedRoot, body); !errors.Is(err, ErrAddrMismatch) {
		t.Fatalf("sealed-shaped manifest accepted as public: %v", err)
	}
}

func TestVerifyManifestRejectsMalformedEncodings(t *testing.T) {
	h := HashBytes([]byte("a"))
	hc := h
	id := ManifestRoot([]Addr{h})
	idb := id
	ok := func() []byte {
		return cborMap(
			cborUint(1), cborBytes(idb[:]),
			cborUint(2), cborUint(1),
			cborUint(3), cborUint(1<<20),
			cborUint(4), cborArray(cborBytes(hc[:])),
			cborUint(6), cborUint(0),
		)
	}
	cases := map[string][]byte{
		"empty":            {},
		"not a map":        cborArray(cborUint(1)),
		"trailing garbage": append(ok(), 0x00),
		"truncated":        ok()[:len(ok())-3],
		"missing required field": cborMap(
			cborUint(1), cborBytes(idb[:]),
			cborUint(4), cborArray(cborBytes(hc[:])),
		),
		"unknown low key": cborMap(
			cborUint(1), cborBytes(idb[:]),
			cborUint(2), cborUint(1),
			cborUint(3), cborUint(1<<20),
			cborUint(4), cborArray(cborBytes(hc[:])),
			cborUint(6), cborUint(0),
			cborUint(7), cborUint(1), // unknown, below the extension floor
		),
		"empty chunk list": cborMap(
			cborUint(1), cborBytes(idb[:]),
			cborUint(2), cborUint(0),
			cborUint(3), cborUint(1<<20),
			cborUint(4), cborArray(),
			cborUint(6), cborUint(0),
		),
		"indefinite-length map": append([]byte{0xbf}, append(ok()[1:], 0xff)...),
	}
	for name, body := range cases {
		if err := Verify(KindManifest, id, body); err == nil {
			t.Fatalf("%s: expected rejection, got nil", name)
		}
	}
}

// TestVerifyManifestToleratesExtensionKeys: keys >= 64 are reserved for future
// extension and MAY be ignored in an unsigned object (§ 18.1.2), so a manifest
// carrying one still verifies — forward compatibility without a flag day.
func TestVerifyManifestToleratesExtensionKeys(t *testing.T) {
	h := HashBytes([]byte("a"))
	hc := h
	id := ManifestRoot([]Addr{h})
	idb := id
	body := cborMap(
		cborUint(1), cborBytes(idb[:]),
		cborUint(2), cborUint(1),
		cborUint(3), cborUint(1<<20),
		cborUint(4), cborArray(cborBytes(hc[:])),
		cborUint(6), cborUint(0),
		cborUint(64), cborUint(7), // reserved extension range
	)
	if err := Verify(KindManifest, id, body); err != nil {
		t.Fatalf("extension key rejected: %v", err)
	}
}

func TestCBORRejectsNonDeterministicMapOrder(t *testing.T) {
	body := cborMap(
		cborUint(4), cborUint(1),
		cborUint(1), cborUint(1), // out of order
	)
	if _, err := parseUintKeyedMap(body); err == nil {
		t.Fatal("out-of-order cbor map keys accepted")
	}
	dup := cborMap(
		cborUint(1), cborUint(1),
		cborUint(1), cborUint(2), // duplicate
	)
	if _, err := parseUintKeyedMap(dup); err == nil {
		t.Fatal("duplicate cbor map key accepted")
	}
	nonMinimal := []byte{0xa1, 0x18, 0x01, 0x01} // key 1 encoded in two bytes
	if _, err := parseUintKeyedMap(nonMinimal); err == nil {
		t.Fatal("non-minimal cbor integer accepted")
	}
}
