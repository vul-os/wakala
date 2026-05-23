// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package peering

import (
	"encoding/binary"
)

// MarshalEnvelope renders a full envelope to its on-carrier byte form
// (spec/PEERING.md §6):
//
//	canonical(header) || uint32(len payload) || payload || signature(64)
func MarshalEnvelope(env *Envelope) []byte {
	hdr := marshalHeader(env.Header)
	out := make([]byte, 0, len(hdr)+4+len(env.Payload)+sigLen)
	out = append(out, hdr...)
	var pl [4]byte
	binary.BigEndian.PutUint32(pl[:], uint32(len(env.Payload)))
	out = append(out, pl[:]...)
	out = append(out, env.Payload...)
	out = append(out, env.Signature...)
	return out
}

// UnmarshalEnvelope parses an on-carrier envelope. It enforces the closed
// canonical encoding: any short read, trailing garbage, or wrong fixed-width
// field length yields ErrCorrupt (spec §6).
func UnmarshalEnvelope(b []byte) (*Envelope, error) {
	r := &reader{b: b}
	h := Header{}
	var ok bool
	if h.Proto, ok = r.str(); !ok {
		return nil, ErrCorrupt
	}
	if h.Suite, ok = r.str(); !ok {
		return nil, ErrCorrupt
	}
	if h.SenderDomain, ok = r.str(); !ok {
		return nil, ErrCorrupt
	}
	if h.SenderIdentityPub, ok = r.fixed(ed25519PubLen); !ok {
		return nil, ErrCorrupt
	}
	if h.ReceiverKexPub, ok = r.fixed(x25519PubLen); !ok {
		return nil, ErrCorrupt
	}
	if h.EphemeralPub, ok = r.fixed(x25519PubLen); !ok {
		return nil, ErrCorrupt
	}
	if h.Nonce, ok = r.fixed(nonceLen); !ok {
		return nil, ErrCorrupt
	}
	if h.Timestamp, ok = r.i64(); !ok {
		return nil, ErrCorrupt
	}
	if h.MailFrom, ok = r.str(); !ok {
		return nil, ErrCorrupt
	}
	cnt, ok := r.u16()
	if !ok {
		return nil, ErrCorrupt
	}
	for i := 0; i < int(cnt); i++ {
		rcpt, ok := r.str()
		if !ok {
			return nil, ErrCorrupt
		}
		h.RcptTo = append(h.RcptTo, rcpt)
	}

	plLen, ok := r.u32()
	if !ok {
		return nil, ErrCorrupt
	}
	payload, ok := r.take(int(plLen))
	if !ok {
		return nil, ErrCorrupt
	}
	sig, ok := r.take(sigLen)
	if !ok {
		return nil, ErrCorrupt
	}
	if !r.empty() {
		return nil, ErrCorrupt
	}

	return &Envelope{Header: h, Payload: payload, Signature: sig}, nil
}

// reader is a bounds-checked byte cursor.
type reader struct {
	b   []byte
	pos int
}

func (r *reader) take(n int) ([]byte, bool) {
	if n < 0 || r.pos+n > len(r.b) {
		return nil, false
	}
	out := r.b[r.pos : r.pos+n]
	r.pos += n
	return out, true
}

func (r *reader) u16() (uint16, bool) {
	p, ok := r.take(2)
	if !ok {
		return 0, false
	}
	return binary.BigEndian.Uint16(p), true
}

func (r *reader) u32() (uint32, bool) {
	p, ok := r.take(4)
	if !ok {
		return 0, false
	}
	return binary.BigEndian.Uint32(p), true
}

func (r *reader) i64() (int64, bool) {
	p, ok := r.take(8)
	if !ok {
		return 0, false
	}
	return int64(binary.BigEndian.Uint64(p)), true
}

func (r *reader) str() (string, bool) {
	l, ok := r.u16()
	if !ok {
		return "", false
	}
	p, ok := r.take(int(l))
	if !ok {
		return "", false
	}
	return string(p), true
}

func (r *reader) fixed(n int) ([]byte, bool) {
	l, ok := r.u16()
	if !ok || int(l) != n {
		return nil, false
	}
	return r.take(n)
}

func (r *reader) empty() bool { return r.pos == len(r.b) }
