// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

// Command relay is the Vulos outbound mail relay and Vulos-to-Vulos peering
// transport. It provides a warmed-IP SMTP relay and an encrypted peer
// delivery path, with pluggable queue and reputation-policy seams so the core
// is never hardwired to Vulos's infrastructure.
package main

import "fmt"

const version = "0.0.1-dev"

func main() {
	fmt.Printf("vulos-relay %s\n", version)
}
