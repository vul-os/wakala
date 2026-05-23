// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

// Package peering implements the Vulos-to-Vulos encrypted peer transport.
// It resolves peer endpoints, performs the cryptographic handshake defined in
// spec/PEERING.md, enforces replay protection, and delivers messages to known
// Vulos peers without traversing public SMTP or blocklist paths. It is one
// branch of the pipeline router; non-peer recipients fall back to the sending
// package.
package peering
