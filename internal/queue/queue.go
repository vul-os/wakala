// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package queue

import (
	"context"
	"errors"
	"time"
)

// Sentinel errors returned by Queue implementations.
var (
	// ErrEmpty is returned by Lease when no messages are available.
	ErrEmpty = errors.New("queue: empty")

	// ErrUnknownMessage is returned when the given message ID is not known.
	ErrUnknownMessage = errors.New("queue: unknown message")

	// ErrLeaseExpired is returned when a lease has already timed out and the
	// message has been re-queued.
	ErrLeaseExpired = errors.New("queue: lease expired")
)

// OutboundMessage is a message waiting to be delivered.
type OutboundMessage struct {
	// ID is a unique, stable identifier for this message.
	ID string

	// AccountID identifies the sending account.
	AccountID string

	// Sender is the RFC-5321 envelope sender (MAIL FROM address).
	Sender string

	// Recipients are the RFC-5321 envelope recipients (RCPT TO addresses).
	Recipients []string

	// RawRFC822 is the raw wire-format message (headers + body).
	RawRFC822 []byte

	// Attempts is the number of delivery attempts made so far.
	Attempts int

	// NextAttemptAt is the earliest time the message should be leased again.
	NextAttemptAt time.Time

	// Metadata holds arbitrary key-value pairs for use by callers.
	Metadata map[string]string
}

// LeasedMessage is an OutboundMessage that has been claimed for delivery.
// The caller must Ack, Nack, or Fail it before the visibility timeout expires;
// an unacknowledged message will be returned by a subsequent Lease call.
type LeasedMessage struct {
	OutboundMessage

	// LeaseExpiry is the absolute time at which this lease expires.
	LeaseExpiry time.Time
}

// Queue is the pluggable seam for "where do I get mail to send."
//
// Implementations must be safe for concurrent use. The canonical external
// implementation (Vulos's bucket-backed queue) lives outside this repository
// and is NOT included here.
type Queue interface {
	// Lease claims up to n messages whose NextAttemptAt is in the past,
	// granting each a visibility timeout during which they will not be
	// returned to other callers. If no messages are available it returns
	// ErrEmpty.
	Lease(ctx context.Context, n int) ([]LeasedMessage, error)

	// Ack acknowledges successful delivery of the message with the given ID,
	// removing it permanently from the queue.
	Ack(ctx context.Context, id string) error

	// Nack requeues the message for a future retry. retryAfter specifies
	// the earliest time the message should be leased again.
	Nack(ctx context.Context, id string, retryAfter time.Time) error

	// Fail dead-letters the message with the given reason. Dead-lettered
	// messages are not returned by Lease.
	Fail(ctx context.Context, id string, reason string) error
}
