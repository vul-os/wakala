// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FSQueue is a filesystem-backed Queue implementation suitable for simple
// self-hosting.  Each message is stored as a JSON file under dir/active/.
// Dead-lettered messages are moved to dir/dead/.  Safe for concurrent use
// within a single process; for multi-process safety use a proper database.
type FSQueue struct {
	dir string
	mu  sync.Mutex

	leases map[string]time.Time // id → expiry (in-memory only; lost on restart)
}

// fsRecord is the on-disk representation of a queued message.
type fsRecord struct {
	OutboundMessage
	DeadReason string `json:"dead_reason,omitempty"`
}

// NewFSQueue creates (or reopens) a filesystem queue rooted at dir.
func NewFSQueue(dir string) (*FSQueue, error) {
	for _, sub := range []string{"active", "dead"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return nil, fmt.Errorf("queue: mkdir %s: %w", sub, err)
		}
	}
	return &FSQueue{
		dir:    dir,
		leases: make(map[string]time.Time),
	}, nil
}

func (q *FSQueue) activePath(id string) string {
	return filepath.Join(q.dir, "active", id+".json")
}

func (q *FSQueue) deadPath(id string) string {
	return filepath.Join(q.dir, "dead", id+".json")
}

// Enqueue writes a message to the active directory.
func (q *FSQueue) Enqueue(msg OutboundMessage) error {
	if msg.NextAttemptAt.IsZero() {
		msg.NextAttemptAt = time.Now()
	}
	if msg.Metadata == nil {
		msg.Metadata = make(map[string]string)
	}
	return q.writeRecord(q.activePath(msg.ID), fsRecord{OutboundMessage: msg})
}

func (q *FSQueue) writeRecord(path string, r fsRecord) error {
	data, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("queue: marshal: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("queue: write: %w", err)
	}
	return os.Rename(tmp, path)
}

func (q *FSQueue) readRecord(path string) (fsRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return fsRecord{}, err
	}
	var r fsRecord
	if err := json.Unmarshal(data, &r); err != nil {
		return fsRecord{}, fmt.Errorf("queue: unmarshal %s: %w", path, err)
	}
	return r, nil
}

// Lease implements Queue.
func (q *FSQueue) Lease(ctx context.Context, n int) ([]LeasedMessage, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	now := time.Now()

	// Expire stale in-memory leases.
	for id, exp := range q.leases {
		if now.After(exp) {
			delete(q.leases, id)
		}
	}

	entries, err := os.ReadDir(filepath.Join(q.dir, "active"))
	if err != nil {
		return nil, fmt.Errorf("queue: readdir: %w", err)
	}

	var leased []LeasedMessage
	for _, entry := range entries {
		if len(leased) >= n {
			break
		}
		if entry.IsDir() {
			continue
		}
		id := entry.Name()
		if len(id) <= 5 || id[len(id)-5:] != ".json" {
			continue
		}
		id = id[:len(id)-5]

		if _, held := q.leases[id]; held {
			continue
		}

		r, err := q.readRecord(q.activePath(id))
		if err != nil {
			continue
		}
		if r.NextAttemptAt.After(now) {
			continue
		}

		expiry := now.Add(30 * time.Second)
		q.leases[id] = expiry
		leased = append(leased, LeasedMessage{
			OutboundMessage: r.OutboundMessage,
			LeaseExpiry:     expiry,
		})
	}
	if len(leased) == 0 {
		return nil, ErrEmpty
	}
	return leased, nil
}

// Ack implements Queue.
func (q *FSQueue) Ack(_ context.Context, id string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	p := q.activePath(id)
	if _, err := os.Stat(p); os.IsNotExist(err) {
		return ErrUnknownMessage
	}
	delete(q.leases, id)
	return os.Remove(p)
}

// Nack implements Queue.
func (q *FSQueue) Nack(_ context.Context, id string, retryAfter time.Time) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	p := q.activePath(id)
	r, err := q.readRecord(p)
	if os.IsNotExist(err) {
		return ErrUnknownMessage
	}
	if err != nil {
		return err
	}
	r.Attempts++
	r.NextAttemptAt = retryAfter
	delete(q.leases, id)
	return q.writeRecord(p, r)
}

// Fail implements Queue.
func (q *FSQueue) Fail(_ context.Context, id string, reason string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	p := q.activePath(id)
	r, err := q.readRecord(p)
	if os.IsNotExist(err) {
		return ErrUnknownMessage
	}
	if err != nil {
		return err
	}
	r.DeadReason = reason
	delete(q.leases, id)
	if err := q.writeRecord(q.deadPath(id), r); err != nil {
		return err
	}
	return os.Remove(p)
}

var _ Queue = (*FSQueue)(nil)
