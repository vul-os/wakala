// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package peering

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

// freshKeys returns a base64url identity + kex pubkey pair from a new identity.
func freshKeys(t *testing.T) (idPub, kexPub string, id *Identity) {
	t.Helper()
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return EncodeKey(id.SignPub), EncodeKey(id.KexPub), id
}

func TestPeerStoreRegisterPinListRevoke(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.json")
	st, err := OpenPeerStore(path)
	if err != nil {
		t.Fatalf("OpenPeerStore: %v", err)
	}

	idPub, kexPub, _ := freshKeys(t)

	// Register a peer.
	entry, err := st.Register(RegisterRequest{
		Domains:     []string{"Peer.Example", "alias.example"},
		Endpoint:    "https://peer.example/peering/v1/deliver",
		IdentityPub: idPub,
		KexPub:      kexPub,
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if len(entry.Domains) != 2 || entry.Domains[0] != "peer.example" {
		t.Fatalf("domains not normalized: %v", entry.Domains)
	}

	// List shows it.
	peers := st.List()
	if len(peers) != 1 {
		t.Fatalf("List len = %d, want 1", len(peers))
	}

	// Re-register the SAME identity key with an updated endpoint: allowed (pin
	// unchanged), upserts in place.
	if _, err := st.Register(RegisterRequest{
		Domains:     []string{"peer.example"},
		Endpoint:    "https://peer.example:8443/peering/v1/deliver",
		IdentityPub: idPub,
		KexPub:      kexPub,
	}); err != nil {
		t.Fatalf("re-register same key: %v", err)
	}
	if got := st.List(); len(got) != 1 {
		t.Fatalf("re-register should upsert, List len = %d, want 1", len(got))
	}

	// Register a DIFFERENT identity key for a domain already pinned: REJECT.
	otherID, otherKex, _ := freshKeys(t)
	_, err = st.Register(RegisterRequest{
		Domains:     []string{"peer.example"},
		Endpoint:    "https://attacker.example",
		IdentityPub: otherID,
		KexPub:      otherKex,
	})
	if !errors.Is(err, ErrPeerKeyConflict) {
		t.Fatalf("conflicting re-pin: want ErrPeerKeyConflict, got %v", err)
	}

	// Persistence: reopen and confirm the entry survived.
	st2, err := OpenPeerStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got := st2.List(); len(got) != 1 || got[0].IdentityPub != idPub {
		t.Fatalf("persistence lost the peer: %+v", got)
	}

	// Revoke by an alias domain releases the whole entry.
	if err := st2.Revoke("alias.example"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if got := st2.List(); len(got) != 0 {
		t.Fatalf("after Revoke, List len = %d, want 0", len(got))
	}

	// After revoke, a DIFFERENT key can be registered (pin released).
	if _, err := st2.Register(RegisterRequest{
		Domains:     []string{"peer.example"},
		Endpoint:    "https://new.example",
		IdentityPub: otherID,
		KexPub:      otherKex,
	}); err != nil {
		t.Fatalf("re-register after revoke: %v", err)
	}

	// Revoking an unknown domain errors.
	if err := st2.Revoke("nope.example"); !errors.Is(err, ErrPeerNotFound) {
		t.Fatalf("Revoke unknown: want ErrPeerNotFound, got %v", err)
	}
}

// TestPeerStoreLoadIntoResolver proves a registered peer is usable by the
// resolver (the daemon path) — resolve + pinned-key lookup work.
func TestPeerStoreLoadIntoResolver(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.json")
	st, err := OpenPeerStore(path)
	if err != nil {
		t.Fatal(err)
	}
	idPub, kexPub, id := freshKeys(t)
	if _, err := st.Register(RegisterRequest{
		Domains:     []string{"recv.example"},
		Endpoint:    "https://recv.example",
		IdentityPub: idPub,
		KexPub:      kexPub,
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	r := NewStaticResolver()
	n, err := st.LoadInto(r)
	if err != nil || n != 1 {
		t.Fatalf("LoadInto: n=%d err=%v", n, err)
	}
	desc, err := r.Resolve(context.Background(), "recv.example")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !desc.IdentityPub.Equal(id.SignPub) {
		t.Fatalf("resolved descriptor has wrong identity key")
	}
	pinned, ok := r.PinnedKey("recv.example")
	if !ok || !pinned.Equal(id.SignPub) {
		t.Fatalf("pinned key lookup failed: ok=%v", ok)
	}
}

// TestLocalPeerEntryExchange proves whoami-style key exchange round-trips: this
// node's LocalPeerEntry can be registered verbatim by a remote store.
func TestLocalPeerEntryExchange(t *testing.T) {
	_, _, id := freshKeys(t)
	entry := LocalPeerEntry(id, []string{"me.example"}, "https://me.example/peering/v1/deliver")

	remote, err := OpenPeerStore(filepath.Join(t.TempDir(), "remote.json"))
	if err != nil {
		t.Fatal(err)
	}
	stored, err := remote.Register(RegisterRequest{
		Domains:     entry.Domains,
		Endpoint:    entry.Endpoint,
		IdentityPub: entry.IdentityPub,
		KexPub:      entry.KexPub,
		Versions:    entry.Versions,
		Suites:      entry.Suites,
	})
	if err != nil {
		t.Fatalf("remote Register of exchanged entry: %v", err)
	}
	if stored.IdentityPub != EncodeKey(id.SignPub) {
		t.Fatalf("exchanged identity key mismatch")
	}
}

// TestPeerStoreRejectsBadKey proves a wrong-length key is rejected before any
// write.
func TestPeerStoreRejectsBadKey(t *testing.T) {
	st, err := OpenPeerStore(filepath.Join(t.TempDir(), "peers.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.Register(RegisterRequest{
		Domains:     []string{"x.example"},
		Endpoint:    "https://x.example",
		IdentityPub: EncodeKey([]byte("too-short")),
		KexPub:      EncodeKey(make([]byte, KexKeyLen)),
	})
	if err == nil {
		t.Fatalf("want error for bad identity key length")
	}
}
