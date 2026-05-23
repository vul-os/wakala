// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

// Package reputation defines the Policy interface — the pluggable seam for
// send authorization and rate control. It provides reference implementations
// (permissive and per-account-capped) and types for provider reputation
// signals. Vulos's tenant-aware policy is an external implementation of this
// interface and is NOT part of this repository.
package reputation
