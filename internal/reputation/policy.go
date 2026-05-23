// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package reputation

import (
	"context"
	"errors"
	"time"
)

// Sentinel errors returned by Policy implementations.
var (
	// ErrSuspended is returned when an account has been suspended due to abuse
	// or a reputation threshold crossing.
	ErrSuspended = errors.New("reputation: account suspended")

	// ErrRateLimited is returned when the account has exceeded its send quota.
	ErrRateLimited = errors.New("reputation: rate limited")
)

// SendState classifies the outcome of a delivery attempt.
type SendState string

const (
	SendDelivered SendState = "delivered"
	SendBounced   SendState = "bounced"
	SendDeferred  SendState = "deferred"
	SendComplaint SendState = "complaint"
)

// SendResult carries the outcome of one delivery attempt for use by
// RecordResult.
type SendResult struct {
	// State is the delivery outcome.
	State SendState

	// Provider is an optional identifier for the receiving provider
	// (e.g. "gmail", "outlook").
	Provider string

	// Code is the SMTP reply code, if applicable.
	Code int

	// EnhancedCode is the RFC-3463 enhanced status code, if applicable.
	EnhancedCode string
}

// Decision is the verdict returned by CheckSend.
type Decision struct {
	// Allow indicates whether the message may be sent.
	Allow bool

	// Reason is a human-readable explanation (informational; may be empty).
	Reason string

	// DelayUntil, when set, indicates the earliest time at which a retry is
	// permitted.  Only meaningful when Allow is false.
	DelayUntil *time.Time

	// PoolHint is an optional hint to the send pipeline about which IP pool
	// segment to prefer.
	PoolHint string
}

// Message is the minimal view of an outbound message that a Policy needs to
// make its decision.
type Message struct {
	// ID is the queue message ID.
	ID string

	// Sender is the RFC-5321 envelope sender address.
	Sender string

	// Recipients are the RFC-5321 envelope recipient addresses.
	Recipients []string

	// Size is the byte size of the raw message.
	Size int
}

// Policy is the pluggable seam for "may this account send right now, and at
// what rate."
//
// Implementations must be safe for concurrent use. The canonical external
// implementation (Vulos's tenant-aware policy) lives outside this repository
// and is NOT included here.
type Policy interface {
	// CheckSend decides whether accountID may send msg right now.
	// It returns ErrSuspended if the account has been suspended and
	// ErrRateLimited if the account's quota is exhausted.
	CheckSend(ctx context.Context, accountID string, msg Message) (Decision, error)

	// RecordResult feeds the outcome of a delivery attempt back into the
	// policy's scoring model so that subsequent CheckSend calls reflect
	// up-to-date reputation data.
	RecordResult(ctx context.Context, accountID string, result SendResult) error
}
