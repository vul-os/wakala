// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package suppression

import (
	"database/sql"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (CGO_ENABLED=0 friendly)
)

// SQLiteStore is a durable, restart-surviving suppression Store backed by
// pure-Go modernc SQLite. It keys entries by (account, address) so a report can
// only ever affect the account it pertains to, and it survives a deploy/restart
// — hard-bounce/complaint protection is no longer reset to empty on every
// restart (the in-memory MEDIUM finding).
//
// The driver is "modernc.org/sqlite", which compiles with CGO_ENABLED=0.
type SQLiteStore struct {
	db *sql.DB

	mu       sync.Mutex
	putStmt  *sql.Stmt
	getStmt  *sql.Stmt
	delStmt  *sql.Stmt
	lenStmt  *sql.Stmt
	existsQ  *sql.Stmt
	prepared bool
}

// NewSQLiteStore opens (creating if needed) a suppression database at path and
// returns a durable Store. Pass ":memory:" for an ephemeral DB (e.g. tests that
// want the SQLite code path without a file). Call Close when done.
func NewSQLiteStore(path string) (*SQLiteStore, error) {
	if path == "" {
		return nil, fmt.Errorf("suppression: NewSQLiteStore requires a non-empty path")
	}
	// busy_timeout avoids spurious "database is locked" under concurrent writers
	// (the relay has multiple ingress/send goroutines); journal_mode=WAL keeps
	// readers and the writer from blocking each other.
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(on)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("suppression: open sqlite %q: %w", path, err)
	}
	// A single writer connection avoids lock contention for SQLite; reads are
	// fast and serialised through the same handle.
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS suppression (
			account   TEXT NOT NULL,
			address   TEXT NOT NULL,
			reason    TEXT NOT NULL,
			detail    TEXT NOT NULL,
			at_unix   INTEGER NOT NULL,
			PRIMARY KEY (account, address)
		)
	`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("suppression: create schema: %w", err)
	}

	s := &SQLiteStore{db: db}
	if err := s.prepare(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *SQLiteStore) prepare() error {
	var err error
	if s.existsQ, err = s.db.Prepare(`SELECT 1 FROM suppression WHERE account = ? AND address = ?`); err != nil {
		return fmt.Errorf("suppression: prepare exists: %w", err)
	}
	if s.putStmt, err = s.db.Prepare(`
		INSERT INTO suppression (account, address, reason, detail, at_unix)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(account, address) DO UPDATE SET
			reason = excluded.reason, detail = excluded.detail, at_unix = excluded.at_unix
	`); err != nil {
		return fmt.Errorf("suppression: prepare put: %w", err)
	}
	if s.getStmt, err = s.db.Prepare(`SELECT reason, detail, at_unix FROM suppression WHERE account = ? AND address = ?`); err != nil {
		return fmt.Errorf("suppression: prepare get: %w", err)
	}
	if s.delStmt, err = s.db.Prepare(`DELETE FROM suppression WHERE account = ? AND address = ?`); err != nil {
		return fmt.Errorf("suppression: prepare delete: %w", err)
	}
	if s.lenStmt, err = s.db.Prepare(`SELECT COUNT(*) FROM suppression`); err != nil {
		return fmt.Errorf("suppression: prepare len: %w", err)
	}
	s.prepared = true
	return nil
}

// Put implements Store.
func (s *SQLiteStore) Put(e Entry) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Determine "newly added" by checking existence first; ON CONFLICT refreshes.
	var existed bool
	if err := s.existsQ.QueryRow(e.Account, e.Address).Scan(new(int)); err == nil {
		existed = true
	} else if err != sql.ErrNoRows {
		return false, fmt.Errorf("suppression: exists check: %w", err)
	}
	if _, err := s.putStmt.Exec(e.Account, e.Address, string(e.Reason), e.Detail, e.At.Unix()); err != nil {
		return false, fmt.Errorf("suppression: put: %w", err)
	}
	return !existed, nil
}

// Get implements Store.
func (s *SQLiteStore) Get(account, address string) (Entry, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var reason, detail string
	var atUnix int64
	err := s.getStmt.QueryRow(account, address).Scan(&reason, &detail, &atUnix)
	if err == sql.ErrNoRows {
		return Entry{}, false, nil
	}
	if err != nil {
		return Entry{}, false, fmt.Errorf("suppression: get: %w", err)
	}
	return Entry{
		Account: account,
		Address: address,
		Reason:  Reason(reason),
		Detail:  detail,
		At:      time.Unix(atUnix, 0),
	}, true, nil
}

// Delete implements Store.
func (s *SQLiteStore) Delete(account, address string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.delStmt.Exec(account, address)
	if err != nil {
		return false, fmt.Errorf("suppression: delete: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// Len implements Store.
func (s *SQLiteStore) Len() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var n int
	if err := s.lenStmt.QueryRow().Scan(&n); err != nil {
		return 0, fmt.Errorf("suppression: len: %w", err)
	}
	return n, nil
}

// Close releases the database handle.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

var _ Store = (*SQLiteStore)(nil)
