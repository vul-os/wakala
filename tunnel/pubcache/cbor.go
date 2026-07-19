package pubcache

import (
	"encoding/binary"
	"fmt"
)

// cbor.go — a deliberately tiny, strict, read-only CBOR scanner.
//
// Scope: exactly enough to VERIFY a PubManifest (§ 22.2.1) — walk an
// integer-keyed map, detect the forbidden key 5, and read the ordered array of
// chunk hashes so the Merkle root can be recomputed. It decodes nothing into
// application structs and encodes nothing at all, because a cache never needs to
// understand an object beyond proving the bytes match the address.
//
// It is strict rather than tolerant, which is the correct posture for a
// verifier: indefinite-length items, non-minimal integer encodings, out-of-order
// map keys, duplicate keys, and trailing garbage are all REJECTED. DMTAP objects
// are deterministically encoded (§ 18.1.2), so anything else is either a
// malformation or an attempt to make two byte strings mean one object — and this
// package's whole guarantee rests on bytes and meaning being the same thing.

const (
	cborMajorUint    = 0
	cborMajorByteStr = 2
	cborMajorArray   = 4
	cborMajorMap     = 5

	// maxCBORDepth bounds recursion when skipping an unknown value, so a
	// hostile upstream cannot blow the stack with a deeply nested object.
	maxCBORDepth = 16
	// maxCBORItems bounds the element count of any single map or array.
	maxCBORItems = 1 << 20
)

// readHead decodes one CBOR head, returning the major type, the argument, and
// the number of bytes consumed. Non-minimal and indefinite-length heads are
// errors.
func readHead(b []byte) (major byte, arg uint64, n int, err error) {
	if len(b) == 0 {
		return 0, 0, 0, fmt.Errorf("%w: truncated cbor", ErrMalformedObject)
	}
	major = b[0] >> 5
	ai := b[0] & 0x1f
	switch {
	case ai < 24:
		return major, uint64(ai), 1, nil
	case ai == 24:
		if len(b) < 2 {
			return 0, 0, 0, fmt.Errorf("%w: truncated cbor head", ErrMalformedObject)
		}
		if b[1] < 24 { // non-minimal
			return 0, 0, 0, fmt.Errorf("%w: non-minimal cbor integer", ErrMalformedObject)
		}
		return major, uint64(b[1]), 2, nil
	case ai == 25:
		if len(b) < 3 {
			return 0, 0, 0, fmt.Errorf("%w: truncated cbor head", ErrMalformedObject)
		}
		v := uint64(binary.BigEndian.Uint16(b[1:3]))
		if v <= 0xff {
			return 0, 0, 0, fmt.Errorf("%w: non-minimal cbor integer", ErrMalformedObject)
		}
		return major, v, 3, nil
	case ai == 26:
		if len(b) < 5 {
			return 0, 0, 0, fmt.Errorf("%w: truncated cbor head", ErrMalformedObject)
		}
		v := uint64(binary.BigEndian.Uint32(b[1:5]))
		if v <= 0xffff {
			return 0, 0, 0, fmt.Errorf("%w: non-minimal cbor integer", ErrMalformedObject)
		}
		return major, v, 5, nil
	case ai == 27:
		if len(b) < 9 {
			return 0, 0, 0, fmt.Errorf("%w: truncated cbor head", ErrMalformedObject)
		}
		v := binary.BigEndian.Uint64(b[1:9])
		if v <= 0xffffffff {
			return 0, 0, 0, fmt.Errorf("%w: non-minimal cbor integer", ErrMalformedObject)
		}
		return major, v, 9, nil
	default: // 28..30 reserved, 31 indefinite-length
		return 0, 0, 0, fmt.Errorf("%w: reserved or indefinite-length cbor item", ErrMalformedObject)
	}
}

// skipValue consumes exactly one CBOR data item and returns its length in bytes.
func skipValue(b []byte, depth int) (int, error) {
	if depth > maxCBORDepth {
		return 0, fmt.Errorf("%w: cbor nesting too deep", ErrMalformedObject)
	}
	major, arg, n, err := readHead(b)
	if err != nil {
		return 0, err
	}
	switch major {
	case cborMajorUint, 1: // uint / negative int — head only
		return n, nil
	case cborMajorByteStr, 3: // byte string / text string — head + payload
		if arg > uint64(len(b)-n) {
			return 0, fmt.Errorf("%w: cbor string overruns buffer", ErrMalformedObject)
		}
		return n + int(arg), nil
	case cborMajorArray, cborMajorMap:
		items := arg
		if major == cborMajorMap {
			items *= 2
		}
		if items > maxCBORItems {
			return 0, fmt.Errorf("%w: cbor container too large", ErrMalformedObject)
		}
		off := n
		for i := uint64(0); i < items; i++ {
			m, err := skipValue(b[off:], depth+1)
			if err != nil {
				return 0, err
			}
			off += m
		}
		return off, nil
	case 6: // tag — one nested item
		m, err := skipValue(b[n:], depth+1)
		if err != nil {
			return 0, err
		}
		return n + m, nil
	case 7: // simple / float
		switch arg := b[0] & 0x1f; {
		case arg < 24:
			return 1, nil
		case arg == 24:
			return 2, nil
		case arg == 25:
			return 3, nil
		case arg == 26:
			return 5, nil
		case arg == 27:
			return 9, nil
		default:
			return 0, fmt.Errorf("%w: bad cbor simple value", ErrMalformedObject)
		}
	}
	return 0, fmt.Errorf("%w: unhandled cbor major type %d", ErrMalformedObject, major)
}

// cborEntry is one key/value pair of an integer-keyed map, with the value left
// as an unparsed byte span.
type cborEntry struct {
	key uint64
	val []byte
}

// parseUintKeyedMap parses a complete, deterministically-encoded CBOR map whose
// keys are all unsigned integers — the § 18.1.2 shape of every DMTAP object.
// Keys MUST be strictly increasing (which is deterministic order for uints, and
// which also rules out duplicates), and no trailing bytes may follow the map.
func parseUintKeyedMap(b []byte) ([]cborEntry, error) {
	major, arg, n, err := readHead(b)
	if err != nil {
		return nil, err
	}
	if major != cborMajorMap {
		return nil, fmt.Errorf("%w: expected a cbor map, got major type %d", ErrMalformedObject, major)
	}
	if arg > maxCBORItems {
		return nil, fmt.Errorf("%w: cbor map too large", ErrMalformedObject)
	}
	out := make([]cborEntry, 0, arg)
	off := n
	prev := uint64(0)
	for i := uint64(0); i < arg; i++ {
		kMajor, key, kn, err := readHead(b[off:])
		if err != nil {
			return nil, err
		}
		if kMajor != cborMajorUint {
			return nil, fmt.Errorf("%w: non-integer cbor map key", ErrMalformedObject)
		}
		if i > 0 && key <= prev {
			return nil, fmt.Errorf("%w: cbor map keys not in deterministic order", ErrMalformedObject)
		}
		prev = key
		off += kn
		vn, err := skipValue(b[off:], 1)
		if err != nil {
			return nil, err
		}
		out = append(out, cborEntry{key: key, val: b[off : off+vn]})
		off += vn
	}
	if off != len(b) {
		return nil, fmt.Errorf("%w: %d trailing bytes after cbor map", ErrMalformedObject, len(b)-off)
	}
	return out, nil
}

// parseAddrArray reads a non-empty CBOR array of byte strings, each of which
// MUST be a well-formed v0 content address (§ 18.1.5) — the shape of
// PubManifest.chunks (§ 22.2.1 key 4).
func parseAddrArray(b []byte) ([]Addr, error) {
	major, arg, n, err := readHead(b)
	if err != nil {
		return nil, err
	}
	if major != cborMajorArray {
		return nil, fmt.Errorf("%w: expected a cbor array of hashes", ErrMalformedObject)
	}
	if arg == 0 {
		return nil, fmt.Errorf("%w: PubManifest.chunks must hold at least one hash", ErrMalformedObject)
	}
	if arg > maxCBORItems {
		return nil, fmt.Errorf("%w: cbor array too large", ErrMalformedObject)
	}
	out := make([]Addr, 0, arg)
	off := n
	for i := uint64(0); i < arg; i++ {
		eMajor, eLen, en, err := readHead(b[off:])
		if err != nil {
			return nil, err
		}
		if eMajor != cborMajorByteStr {
			return nil, fmt.Errorf("%w: non-bytestring in chunk-hash array", ErrMalformedObject)
		}
		off += en
		if eLen != addrLen || uint64(len(b)-off) < eLen {
			return nil, fmt.Errorf("%w: chunk hash is not a %d-byte address", ErrMalformedObject, addrLen)
		}
		var a Addr
		copy(a[:], b[off:off+int(eLen)])
		if a[0] != HashPrefixBLAKE3_256 {
			return nil, fmt.Errorf("%w: unsupported hash prefix 0x%02x in chunk list", ErrBadAddr, a[0])
		}
		out = append(out, a)
		off += int(eLen)
	}
	if off != len(b) {
		return nil, fmt.Errorf("%w: trailing bytes after chunk-hash array", ErrMalformedObject)
	}
	return out, nil
}
