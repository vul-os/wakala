// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package peering

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Federation onboarding (replacing hand-edited peer JSON).
//
// PeerStore is the durable, mutation-friendly home of the operator peer
// registry (spec §3.1 source 1). It reads/writes the SAME on-disk wire format as
// LoadPeersFile (PeersFile / PeerEntry — base64url keys), so existing configs
// keep working and a StaticResolver can still be loaded from the file. On top of
// that it adds the onboarding operations the CLI/API expose:
//
//   - Register: add a peer (domains + endpoint + identity/kex pubkeys), pinning
//     the identity key on first sight (TOFU, spec §3.2). A later Register for a
//     domain with a DIFFERENT identity key is REJECTED (the pin is the trust
//     anchor; rotation must go through the signed §3.2 rotation path, not a
//     hand-edit). Endpoint / kex / version / suite updates that keep the same
//     identity key are allowed (re-pin no-op).
//   - List: enumerate registered peers.
//   - Revoke: remove a peer by domain (drops its pin too, so a fresh Register
//     can re-establish trust deliberately).
//
// Writes are atomic (temp file + rename) so a crash mid-write never corrupts the
// registry. PeerStore is safe for concurrent use within one process; it does NOT
// coordinate across processes (one relay owns its peer file).
type PeerStore struct {
	mu   sync.Mutex
	path string
	// entries is keyed by a stable peer key (the base64url identity pubkey) so a
	// multi-domain peer is one entry. domains within an entry are lowercased.
	file PeersFile
}

// ErrPeerKeyConflict is returned when a Register would change a domain's pinned
// identity key (spec §3.2 — only the signed rotation path may do that).
var ErrPeerKeyConflict = errors.New("peering: identity key conflicts with the pinned key for a domain")

// ErrPeerNotFound is returned by Revoke/Get when no peer matches.
var ErrPeerNotFound = errors.New("peering: peer not found")

// OpenPeerStore opens (or initializes) the peer store at path. A missing file is
// treated as an empty registry; the file is created on the first successful
// mutation. A present-but-malformed file is an error (refuse to clobber it).
func OpenPeerStore(path string) (*PeerStore, error) {
	s := &PeerStore{path: path}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("peering: open peer store %q: %w", path, err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return s, nil
	}
	if err := json.Unmarshal(raw, &s.file); err != nil {
		return nil, fmt.Errorf("peering: parse peer store %q: %w", path, err)
	}
	return s, nil
}

// RegisterRequest is the input to Register (the CLI/API onboarding payload).
type RegisterRequest struct {
	// Domains the peer is authoritative for (at least one). Lowercased on store.
	Domains []string
	// Endpoint is the carrier address (https URL, host[:port], or bucket:<prefix>).
	Endpoint string
	// IdentityPub is the peer's Ed25519 identity public key, base64url (raw 32B).
	IdentityPub string
	// KexPub is the peer's X25519 key-agreement public key, base64url (raw 32B).
	KexPub string
	// Versions/Suites optionally override the VULOS-PEER/1 defaults.
	Versions []string
	Suites   []string
}

// Register adds or updates a peer, enforcing key pinning. It validates the wire
// fields (key lengths, non-empty endpoint/domains) by building a descriptor, and
// rejects a conflicting identity key for any already-pinned domain. On success
// it persists the registry atomically and returns the stored entry.
func (s *PeerStore) Register(req RegisterRequest) (PeerEntry, error) {
	entry := PeerEntry{
		Domains:     normDomains(req.Domains),
		Endpoint:    strings.TrimSpace(req.Endpoint),
		IdentityPub: strings.TrimSpace(req.IdentityPub),
		KexPub:      strings.TrimSpace(req.KexPub),
		Versions:    req.Versions,
		Suites:      req.Suites,
	}
	// Validate by decoding into a descriptor (reuses the same checks as load).
	if _, err := entry.descriptor(); err != nil {
		return PeerEntry{}, fmt.Errorf("peering: register: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Pin check: for each domain this entry claims, if another EXISTING entry
	// already pins that domain to a different identity key, reject.
	for _, dom := range entry.Domains {
		for i := range s.file.Peers {
			if s.file.Peers[i].IdentityPub == entry.IdentityPub {
				continue // same key — fine
			}
			if containsFold(s.file.Peers[i].Domains, dom) {
				return PeerEntry{}, fmt.Errorf("%w: domain %q pinned to a different identity key", ErrPeerKeyConflict, dom)
			}
		}
	}

	// Upsert by identity key (a peer is identified by its pinned identity key).
	idx := -1
	for i := range s.file.Peers {
		if s.file.Peers[i].IdentityPub == entry.IdentityPub {
			idx = i
			break
		}
	}
	if idx >= 0 {
		// Update: merge domains, refresh endpoint/kex/versions/suites. The
		// identity key is unchanged (that's how we found it), so no pin break.
		merged := mergeDomains(s.file.Peers[idx].Domains, entry.Domains)
		entry.Domains = merged
		s.file.Peers[idx] = entry
	} else {
		s.file.Peers = append(s.file.Peers, entry)
	}

	if err := s.persistLocked(); err != nil {
		return PeerEntry{}, err
	}
	return entry, nil
}

// List returns a copy of the registered peers, sorted by their first domain for
// stable output.
func (s *PeerStore) List() []PeerEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]PeerEntry, len(s.file.Peers))
	copy(out, s.file.Peers)
	sort.Slice(out, func(i, j int) bool {
		return firstDomain(out[i]) < firstDomain(out[j])
	})
	return out
}

// Revoke removes the peer authoritative for domain (matching any of its
// domains), dropping the entry entirely so its pin is released. It returns
// ErrPeerNotFound if no peer claims that domain.
func (s *PeerStore) Revoke(domain string) error {
	dom := strings.ToLower(strings.TrimSpace(domain))
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := -1
	for i := range s.file.Peers {
		if containsFold(s.file.Peers[i].Domains, dom) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return ErrPeerNotFound
	}
	s.file.Peers = append(s.file.Peers[:idx], s.file.Peers[idx+1:]...)
	return s.persistLocked()
}

// Get returns the entry authoritative for domain, or ErrPeerNotFound.
func (s *PeerStore) Get(domain string) (PeerEntry, error) {
	dom := strings.ToLower(strings.TrimSpace(domain))
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.file.Peers {
		if containsFold(s.file.Peers[i].Domains, dom) {
			return s.file.Peers[i], nil
		}
	}
	return PeerEntry{}, ErrPeerNotFound
}

// LoadInto registers every stored peer into a StaticResolver (re-using the
// pinning Add path). It is the bridge from the durable store to the in-memory
// resolver the daemon serves from. Returns the number of peers loaded.
func (s *PeerStore) LoadInto(r *StaticResolver) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for i, e := range s.file.Peers {
		desc, err := e.descriptor()
		if err != nil {
			return n, fmt.Errorf("peering: peer store entry %d: %w", i, err)
		}
		if err := r.Add(desc); err != nil {
			return n, fmt.Errorf("peering: peer store entry %d: %w", i, err)
		}
		n++
	}
	return n, nil
}

// persistLocked writes the registry atomically. Caller holds s.mu.
func (s *PeerStore) persistLocked() error {
	if s.path == "" {
		return errors.New("peering: peer store has no path")
	}
	data, err := json.MarshalIndent(&s.file, "", "  ")
	if err != nil {
		return fmt.Errorf("peering: marshal peer store: %w", err)
	}
	data = append(data, '\n')
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("peering: peer store dir %q: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".peers-*.tmp")
	if err != nil {
		return fmt.Errorf("peering: peer store temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("peering: peer store write: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("peering: peer store chmod: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("peering: peer store close: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("peering: peer store rename: %w", err)
	}
	return nil
}

// ── helpers ────────────────────────────────────────────────────────────────

// LocalPeerEntry renders THIS node's own descriptor as a PeerEntry that a remote
// operator can register on their side ("exchange keys"). It carries only public
// material (identity + kex pubkeys), the local domains, and the endpoint other
// peers should reach this node at.
func LocalPeerEntry(id *Identity, domains []string, endpoint string) PeerEntry {
	return PeerEntry{
		Domains:     normDomains(domains),
		Endpoint:    strings.TrimSpace(endpoint),
		IdentityPub: EncodeKey(id.SignPub),
		KexPub:      EncodeKey(id.KexPub),
		Versions:    []string{ProtoV1},
		Suites:      []string{SuiteV1},
	}
}

func normDomains(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(d, ".")))
		if d == "" {
			continue
		}
		if _, dup := seen[d]; dup {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out
}

func mergeDomains(a, b []string) []string {
	return normDomains(append(append([]string{}, a...), b...))
}

func containsFold(list []string, v string) bool {
	for _, e := range list {
		if strings.EqualFold(strings.TrimSuffix(e, "."), v) {
			return true
		}
	}
	return false
}

func firstDomain(e PeerEntry) string {
	if len(e.Domains) > 0 {
		return e.Domains[0]
	}
	return ""
}

// ValidatePubKey checks that a base64url key decodes to the expected raw length.
// It is exported so the CLI/API can give a precise error before Register.
func ValidatePubKey(b64 string, wantLen int) error {
	raw, err := DecodeKey(strings.TrimSpace(b64))
	if err != nil {
		return fmt.Errorf("decode key: %w", err)
	}
	if len(raw) != wantLen {
		return fmt.Errorf("key length %d, want %d", len(raw), wantLen)
	}
	return nil
}

// IdentityKeyLen / KexKeyLen expose the expected raw key lengths for callers.
const (
	IdentityKeyLen = ed25519.PublicKeySize // 32
	KexKeyLen      = x25519PubLen           // 32
)
