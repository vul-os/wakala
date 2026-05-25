// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package suppression

import (
	"strings"
	"sync"
	"time"
)

// Reason classifies why a recipient was suppressed.
type Reason string

const (
	// ReasonHardBounce is a permanent (5.x.x) delivery failure (RFC 3464 DSN).
	ReasonHardBounce Reason = "hard_bounce"

	// ReasonComplaint is an FBL/ARF abuse complaint (RFC 5965).
	ReasonComplaint Reason = "complaint"

	// ReasonManual is an operator-added suppression.
	ReasonManual Reason = "manual"
)

// Entry is a single suppression-list record.
type Entry struct {
	// Account is the account this suppression is scoped to. Suppression is
	// per-account: a hard-bounce/complaint for one account's mail NEVER blocks
	// delivery of another account's mail to the same recipient. This is the
	// fix for the "suppression poisoning" class — a forged or legitimate report
	// can only ever affect the account it pertains to.
	Account string
	// Address is the normalised (lowercased) recipient address.
	Address string
	// Reason is why the address was suppressed.
	Reason Reason
	// Detail is an optional human-readable detail (e.g. the DSN status/diag).
	Detail string
	// At is when the suppression was recorded.
	At time.Time
}

// Observer is notified whenever an address is suppressed (for metrics). It must
// be non-blocking and safe for concurrent use. Nil disables observation.
type Observer interface {
	// Suppressed reports that a recipient was added to the list (or refreshed)
	// for the given reason.
	Suppressed(reason Reason)
	// Hit reports that a send was blocked because the recipient is suppressed.
	Hit(reason Reason)
}

// Store is the durable (or in-memory) backend the suppression List persists
// entries in. Implementations MUST be safe for concurrent use and MUST key
// entries by (account, recipient): the same recipient may be suppressed for one
// account and deliverable for another.
//
// The default store is in-memory (NewMemStore). A durable, restart-surviving
// store backed by pure-Go modernc SQLite is provided by NewSQLiteStore so
// hard-bounce/complaint protection is not reset to empty on every deploy.
type Store interface {
	// Put inserts or refreshes e (keyed by e.Account + e.Address). It returns
	// true if the entry was newly added (false if it already existed).
	Put(e Entry) (added bool, err error)
	// Get returns the entry for (account, address) and whether it was found.
	Get(account, address string) (Entry, bool, error)
	// Delete removes (account, address). It returns true if an entry existed.
	Delete(account, address string) (removed bool, err error)
	// Len returns the number of stored entries (all accounts).
	Len() (int, error)
}

// List is the recipient suppression list. It is safe for concurrent use.
//
// Suppression is scoped per-account: every operation takes an account ID so a
// report submitted by (or pertaining to) one account can never suppress a
// recipient for a different account. The zero value is not usable; call NewList
// or NewListWithStore.
type List struct {
	mu       sync.RWMutex
	store    Store
	observer Observer
}

// NewList returns a suppression list backed by an in-memory store. Entries do
// not survive process restart; use NewListWithStore(NewSQLiteStore(...)) for
// durability.
func NewList() *List {
	return &List{store: NewMemStore()}
}

// NewListWithStore returns a suppression list backed by the given store. It
// panics if store is nil — wiring a list with no backend is a programmer error.
func NewListWithStore(store Store) *List {
	if store == nil {
		panic("suppression: NewListWithStore requires a non-nil Store")
	}
	return &List{store: store}
}

// SetObserver installs an Observer for metrics. Safe to call before use begins.
func (l *List) SetObserver(o Observer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.observer = o
}

// normalizeAddr lowercases and trims an address for stable matching. It strips a
// surrounding pair of angle brackets ("<a@b>") commonly seen in DSN reports.
func normalizeAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	addr = strings.TrimPrefix(addr, "<")
	addr = strings.TrimSuffix(addr, ">")
	return strings.ToLower(strings.TrimSpace(addr))
}

// normalizeAccount trims/lowercases an account key so scoping is stable.
func normalizeAccount(account string) string {
	return strings.ToLower(strings.TrimSpace(account))
}

// Suppress adds (or refreshes) addr on account's list with the given reason. An
// empty/malformed address or an empty account is ignored. It returns true if the
// address was newly added (false if it already existed for this account).
func (l *List) Suppress(account, addr string, reason Reason, detail string) bool {
	a := normalizeAccount(account)
	n := normalizeAddr(addr)
	if a == "" || n == "" || !strings.Contains(n, "@") {
		return false
	}
	added, err := l.store.Put(Entry{
		Account: a, Address: n, Reason: reason, Detail: detail, At: time.Now(),
	})
	if err != nil {
		return false
	}
	l.mu.RLock()
	obs := l.observer
	l.mu.RUnlock()
	if obs != nil {
		obs.Suppressed(reason)
	}
	return added
}

// IsSuppressed reports whether addr is on account's suppression list, and the
// matching entry if so. It records a metrics "hit" when a match is found. A
// suppression recorded for a DIFFERENT account never matches here.
func (l *List) IsSuppressed(account, addr string) (Entry, bool) {
	a := normalizeAccount(account)
	n := normalizeAddr(addr)
	if a == "" {
		return Entry{}, false
	}
	e, ok, err := l.store.Get(a, n)
	if err != nil || !ok {
		return Entry{}, false
	}
	l.mu.RLock()
	obs := l.observer
	l.mu.RUnlock()
	if obs != nil {
		obs.Hit(e.Reason)
	}
	return e, true
}

// Remove deletes addr from account's suppression list (e.g. operator re-enables
// a recipient after they confirm the address is valid again). Returns true if an
// entry was removed.
func (l *List) Remove(account, addr string) bool {
	removed, err := l.store.Delete(normalizeAccount(account), normalizeAddr(addr))
	if err != nil {
		return false
	}
	return removed
}

// Len returns the total number of suppressed (account, address) pairs.
func (l *List) Len() int {
	n, err := l.store.Len()
	if err != nil {
		return 0
	}
	return n
}

// FilterRecipients partitions rcpts into those allowed to receive (not
// suppressed for account) and those dropped (suppressed for account). The
// returned slices preserve input order. A metrics "hit" is recorded for each
// dropped recipient. Suppression is per-account: a recipient suppressed only for
// another account is allowed here.
func (l *List) FilterRecipients(account string, rcpts []string) (allowed, dropped []string) {
	for _, r := range rcpts {
		if _, ok := l.IsSuppressed(account, r); ok {
			dropped = append(dropped, r)
		} else {
			allowed = append(allowed, r)
		}
	}
	return allowed, dropped
}

// ─── In-memory Store ──────────────────────────────────────────────────────────

// MemStore is an in-memory, per-account-keyed Store. It is the default backend
// and is used in tests. Entries are lost on process restart.
type MemStore struct {
	mu      sync.RWMutex
	entries map[string]Entry // key = account + "\x00" + address
}

// NewMemStore returns an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{entries: make(map[string]Entry)}
}

func memKey(account, address string) string { return account + "\x00" + address }

// Put implements Store.
func (s *MemStore) Put(e Entry) (bool, error) {
	k := memKey(e.Account, e.Address)
	s.mu.Lock()
	defer s.mu.Unlock()
	_, existed := s.entries[k]
	s.entries[k] = e
	return !existed, nil
}

// Get implements Store.
func (s *MemStore) Get(account, address string) (Entry, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[memKey(account, address)]
	return e, ok, nil
}

// Delete implements Store.
func (s *MemStore) Delete(account, address string) (bool, error) {
	k := memKey(account, address)
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.entries[k]
	delete(s.entries, k)
	return ok, nil
}

// Len implements Store.
func (s *MemStore) Len() (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries), nil
}

var _ Store = (*MemStore)(nil)
