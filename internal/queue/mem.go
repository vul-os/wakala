// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package queue

import (
	"context"
	"sync"
	"time"
)

// MemQueue is an in-process, in-memory Queue implementation intended for
// tests and standalone/single-binary deployments.  Messages are lost when the
// process exits.  Safe for concurrent use.
type MemQueue struct {
	mu          sync.Mutex
	messages    map[string]*memEntry // id → entry
	leaseExpiry map[string]time.Time // id → lease expiry (zero = not leased)
	deadLetters map[string]string    // id → reason
}

type memEntry struct {
	msg OutboundMessage
}

// NewMemQueue creates an empty MemQueue.
func NewMemQueue() *MemQueue {
	return &MemQueue{
		messages:    make(map[string]*memEntry),
		leaseExpiry: make(map[string]time.Time),
		deadLetters: make(map[string]string),
	}
}

// Enqueue adds a message to the queue.  NextAttemptAt defaults to now if zero.
func (q *MemQueue) Enqueue(msg OutboundMessage) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if msg.NextAttemptAt.IsZero() {
		msg.NextAttemptAt = time.Now()
	}
	if msg.Metadata == nil {
		msg.Metadata = make(map[string]string)
	}
	q.messages[msg.ID] = &memEntry{msg: msg}
}

// Lease implements Queue.
func (q *MemQueue) Lease(ctx context.Context, n int) ([]LeasedMessage, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	now := time.Now()

	// Expire old leases so messages are returned to the available pool.
	for id, exp := range q.leaseExpiry {
		if now.After(exp) {
			delete(q.leaseExpiry, id)
		}
	}

	var leased []LeasedMessage
	for id, e := range q.messages {
		if len(leased) >= n {
			break
		}
		if _, dead := q.deadLetters[id]; dead {
			continue
		}
		if _, held := q.leaseExpiry[id]; held {
			continue
		}
		if e.msg.NextAttemptAt.After(now) {
			continue
		}
		expiry := now.Add(30 * time.Second)
		q.leaseExpiry[id] = expiry
		leased = append(leased, LeasedMessage{
			OutboundMessage: e.msg,
			LeaseExpiry:     expiry,
		})
	}
	if len(leased) == 0 {
		return nil, ErrEmpty
	}
	return leased, nil
}

// Ack implements Queue.
func (q *MemQueue) Ack(_ context.Context, id string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, ok := q.messages[id]; !ok {
		return ErrUnknownMessage
	}
	delete(q.messages, id)
	delete(q.leaseExpiry, id)
	return nil
}

// Nack implements Queue.
func (q *MemQueue) Nack(_ context.Context, id string, retryAfter time.Time) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	e, ok := q.messages[id]
	if !ok {
		return ErrUnknownMessage
	}
	e.msg.Attempts++
	e.msg.NextAttemptAt = retryAfter
	delete(q.leaseExpiry, id)
	return nil
}

// Fail implements Queue.
func (q *MemQueue) Fail(_ context.Context, id string, reason string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, ok := q.messages[id]; !ok {
		return ErrUnknownMessage
	}
	q.deadLetters[id] = reason
	delete(q.leaseExpiry, id)
	return nil
}

// DeadLetters returns a snapshot of dead-lettered messages and their reasons.
func (q *MemQueue) DeadLetters() map[string]string {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make(map[string]string, len(q.deadLetters))
	for k, v := range q.deadLetters {
		out[k] = v
	}
	return out
}

var _ Queue = (*MemQueue)(nil)
