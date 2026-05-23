// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package sending_test

import (
	"strings"
	"testing"
	"time"

	"github.com/vul-os/vulos-relay/internal/sending"
)

// TestDKIMRotateGeneratesKey verifies that Rotate produces a key with a
// non-empty selector, DNS TXT record, and PEM material.
func TestDKIMRotateGeneratesKey(t *testing.T) {
	store := sending.NewMemKeyStore()
	rotator, err := sending.NewDKIMRotator("example.com", store, sending.DKIMRotatorConfig{
		KeyBits: 1024, // small key for test speed
	})
	if err != nil {
		t.Fatalf("NewDKIMRotator: %v", err)
	}

	key, err := rotator.Rotate()
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if key.Selector == "" {
		t.Error("expected non-empty selector")
	}
	if key.Domain != "example.com" {
		t.Errorf("expected domain example.com, got %s", key.Domain)
	}
	if len(key.PrivateKeyPEM) == 0 {
		t.Error("expected non-empty PrivateKeyPEM")
	}
	if !strings.HasPrefix(key.DNSTXTRecord, "v=DKIM1;") {
		t.Errorf("unexpected DNS TXT record: %s", key.DNSTXTRecord)
	}
}

// TestDKIMCurrentKeyAfterGrace verifies that CurrentKey returns the newly
// rotated key once the propagation grace period has elapsed.
func TestDKIMCurrentKeyAfterGrace(t *testing.T) {
	store := sending.NewMemKeyStore()
	// Zero propagation grace → key is immediately active.
	rotator, err := sending.NewDKIMRotator("example.com", store, sending.DKIMRotatorConfig{
		KeyBits:          1024,
		PropagationGrace: 0,
	})
	if err != nil {
		t.Fatalf("NewDKIMRotator: %v", err)
	}

	key, err := rotator.Rotate()
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	current, err := rotator.CurrentKey()
	if err != nil {
		t.Fatalf("CurrentKey: %v", err)
	}
	if current.Selector != key.Selector {
		t.Errorf("expected selector %s, got %s", key.Selector, current.Selector)
	}
}

// TestDKIMCurrentKeyWithGrace verifies that CurrentKey still returns a key
// (the newly created one) even when it's still in propagation grace — no gap.
func TestDKIMCurrentKeyWithGrace(t *testing.T) {
	store := sending.NewMemKeyStore()
	// Long propagation grace → key not yet "officially" active, but should
	// still be returned (no gap rule).
	rotator, err := sending.NewDKIMRotator("example.com", store, sending.DKIMRotatorConfig{
		KeyBits:          1024,
		PropagationGrace: 72 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewDKIMRotator: %v", err)
	}

	_, err = rotator.Rotate()
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	// CurrentKey must NOT return ErrKeyNotFound — the key-in-grace is the
	// fallback.
	_, err = rotator.CurrentKey()
	if err != nil {
		t.Fatalf("CurrentKey should not fail during grace period: %v", err)
	}
}

// TestDKIMRetiredKeyNotReturned verifies that RetireSelector stops the key
// from being returned by CurrentKey.
func TestDKIMRetiredKeyNotReturned(t *testing.T) {
	store := sending.NewMemKeyStore()
	rotator, err := sending.NewDKIMRotator("example.com", store, sending.DKIMRotatorConfig{
		KeyBits:          1024,
		PropagationGrace: 0,
	})
	if err != nil {
		t.Fatalf("NewDKIMRotator: %v", err)
	}

	// First key.
	k1, err := rotator.Rotate()
	if err != nil {
		t.Fatalf("Rotate k1: %v", err)
	}

	// Second key — should become current after retiring the first.
	k2, err := rotator.Rotate()
	if err != nil {
		t.Fatalf("Rotate k2: %v", err)
	}

	// Retire the first key.
	if err := rotator.RetireSelector(k1.Selector); err != nil {
		t.Fatalf("RetireSelector: %v", err)
	}

	current, err := rotator.CurrentKey()
	if err != nil {
		t.Fatalf("CurrentKey: %v", err)
	}
	if current.Selector == k1.Selector {
		t.Error("retired key should not be returned as current")
	}
	if current.Selector != k2.Selector {
		t.Errorf("expected k2 selector %s, got %s", k2.Selector, current.Selector)
	}
}

// TestDKIMPendingDNSRecords verifies that PendingDNSRecords returns entries
// for both the active and newly created (in-grace) keys.
func TestDKIMPendingDNSRecords(t *testing.T) {
	store := sending.NewMemKeyStore()
	rotator, err := sending.NewDKIMRotator("example.com", store, sending.DKIMRotatorConfig{
		KeyBits:          1024,
		PropagationGrace: 0,
		RetentionWindow:  7 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewDKIMRotator: %v", err)
	}

	_, _ = rotator.Rotate()
	_, _ = rotator.Rotate()

	records := rotator.PendingDNSRecords()
	if len(records) < 2 {
		t.Errorf("expected at least 2 pending DNS records (old + new), got %d", len(records))
	}
	for _, r := range records {
		if !strings.Contains(r.Name, "_domainkey.example.com") {
			t.Errorf("unexpected record name: %s", r.Name)
		}
		if !strings.HasPrefix(r.Value, "v=DKIM1;") {
			t.Errorf("unexpected record value: %s", r.Value)
		}
	}
}

// TestMemKeyStore verifies basic Save/Load/List/Delete round-trip.
func TestMemKeyStore(t *testing.T) {
	s := sending.NewMemKeyStore()

	key := sending.DKIMKey{Selector: "testsel", Domain: "example.com"}
	if err := s.Save(key); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := s.Load("testsel")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Selector != "testsel" {
		t.Errorf("expected testsel, got %s", loaded.Selector)
	}

	list, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0] != "testsel" {
		t.Errorf("unexpected list: %v", list)
	}

	if err := s.Delete("testsel"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = s.Load("testsel")
	if err == nil {
		t.Error("expected ErrKeyNotFound after delete")
	}
}
