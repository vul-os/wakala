// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

// Package relay contains the core types and send pipeline for vulos-relay.
// It orchestrates message flow from the queue through the reputation policy,
// router, and sender, and defines the central abstractions that all other
// internal packages depend upon.
package relay
