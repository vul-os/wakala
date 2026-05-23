// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package sending

import (
	"context"
	"net"
)

// SourceBinding describes the local IP and HELO name to use when establishing
// an outbound SMTP connection. If nil or zero-valued, the OS routing table
// selects the source address and the system hostname is used as HELO.
type SourceBinding struct {
	// LocalIP is the source IP address to bind for the outbound connection.
	// If nil, the OS default is used.
	LocalIP net.IP

	// HELOName is the hostname to announce in the SMTP EHLO/HELO command.
	// If empty, the system hostname is used.
	HELOName string
}

// SendState classifies the outcome of an outbound delivery attempt.
type SendState string

const (
	// StateDelivered means the remote MX accepted the message with a 2xx reply.
	StateDelivered SendState = "delivered"

	// StateDeferred means the remote MX returned a 4xx transient failure.
	StateDeferred SendState = "deferred"

	// StateBounced means the remote MX returned a 5xx permanent failure.
	StateBounced SendState = "bounced"
)

// SendResult is the outcome of one delivery attempt returned by a Sender.
type SendResult struct {
	// State is the delivery classification.
	State SendState

	// Code is the SMTP reply code (e.g. 250, 421, 550).
	Code int

	// EnhancedCode is the RFC-3463 enhanced status code (e.g. "2.0.0").
	EnhancedCode string

	// Message is the human-readable SMTP reply text.
	Message string

	// Provider is an optional identifier for the receiving provider inferred
	// from the MX hostname (e.g. "gmail", "outlook").
	Provider string
}

// Sender delivers a single outbound message via some transport (SMTP or
// peer). Implementations must be safe for concurrent use.
type Sender interface {
	// Send attempts to deliver msg. It returns a SendResult classifying the
	// outcome. A non-nil error indicates an infrastructure failure (network
	// error, DNS failure) distinct from an SMTP-level rejection; callers
	// should treat infrastructure errors as transient (deferred).
	Send(ctx context.Context, msg Message) (SendResult, error)
}

// Message is the outbound message view consumed by a Sender.
type Message struct {
	// ID is the queue message ID.
	ID string

	// AccountID is the sending account identifier.
	AccountID string

	// Sender is the RFC-5321 envelope sender (MAIL FROM address).
	Sender string

	// Recipients are the RFC-5321 envelope recipients (RCPT TO addresses).
	Recipients []string

	// RawRFC822 is the raw wire-format message.
	RawRFC822 []byte

	// Binding optionally specifies the local IP and HELO name.
	Binding *SourceBinding
}
