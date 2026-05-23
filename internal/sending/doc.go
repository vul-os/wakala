// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

// Package sending implements outbound SMTP delivery using Mox smtpclient,
// the warmed-IP pool, DKIM key rotation, IP warm-up scheduling, and outbound
// Rspamd content scanning. It provides the Sender implementation for
// standard (non-peer) recipients.
package sending
