// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

// Package queue defines the Queue interface — the pluggable seam that decouples
// the relay's send pipeline from the source of outbound messages. Reference
// implementations (in-memory and filesystem-backed) live here; Vulos's
// bucket-backed queue is an external implementation of this interface and is
// NOT part of this repository.
package queue
