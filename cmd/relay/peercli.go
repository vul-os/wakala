// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/vul-os/vulos-relay/internal/peering"
)

// Federation onboarding CLI: `relay peer <subcommand>`. It replaces hand-editing
// the peer JSON with explicit register / list / revoke / whoami operations
// against a durable peering.PeerStore that reads + writes the SAME spec wire
// format (PeersFile). It is dispatched from main() before the daemon path.
//
// Subcommands:
//
//	relay peer register --store FILE --domains a.com,b.com --endpoint URL \
//	      --identity-pub B64 --kex-pub B64 [--versions ...] [--suites ...]
//	relay peer list     --store FILE [--json]
//	relay peer revoke   --store FILE --domain a.com
//	relay peer whoami   --key-dir DIR --domains a.com --endpoint URL  (prints THIS
//	      node's PeerEntry JSON for a remote operator to register — key exchange)
//
// The store path defaults to RELAY_PEER_CONFIG so the CLI and the daemon share
// one registry by default.

// runPeerCLI handles `relay peer ...`. args is os.Args[2:] (after "peer").
// It returns the process exit code.
func runPeerCLI(args []string) int {
	if len(args) == 0 {
		peerUsage(os.Stderr)
		return 2
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "register":
		return peerRegisterCmd(rest)
	case "list":
		return peerListCmd(rest)
	case "revoke":
		return peerRevokeCmd(rest)
	case "whoami":
		return peerWhoamiCmd(rest)
	case "-h", "--help", "help":
		peerUsage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "relay peer: unknown subcommand %q\n\n", sub)
		peerUsage(os.Stderr)
		return 2
	}
}

func peerUsage(w io.Writer) {
	fmt.Fprintf(w, `Usage: relay peer <subcommand> [flags]

Federation onboarding — register, list, and revoke Vulos peers in the peer
store (the spec PeersFile registry). Default --store is $RELAY_PEER_CONFIG.

Subcommands:
  register  Add/update a peer (domains + endpoint + identity/kex pubkeys; pins
            the identity key on first sight, rejects a conflicting re-pin)
  list      List registered peers
  revoke    Remove a peer by domain (releases its pin)
  whoami    Print THIS node's PeerEntry JSON to hand to a remote operator
            (key exchange) — requires --key-dir, --domains, --endpoint

Run "relay peer <subcommand> -h" for subcommand flags.
`)
}

// storeFlag adds the shared --store flag (defaults to RELAY_PEER_CONFIG).
func storeFlag(fs *flag.FlagSet) *string {
	return fs.String("store", os.Getenv("RELAY_PEER_CONFIG"), "peer store file (default: $RELAY_PEER_CONFIG)")
}

func peerRegisterCmd(args []string) int {
	fs := flag.NewFlagSet("peer register", flag.ContinueOnError)
	store := storeFlag(fs)
	domains := fs.String("domains", "", "comma-separated mail domains the peer is authoritative for (required)")
	endpoint := fs.String("endpoint", "", "peer carrier address: https URL, host[:port], or bucket:<prefix> (required)")
	identityPub := fs.String("identity-pub", "", "peer Ed25519 identity public key, base64url (required)")
	kexPub := fs.String("kex-pub", "", "peer X25519 key-agreement public key, base64url (required)")
	versions := fs.String("versions", "", "comma-separated protocol versions (default: VULOS-PEER/1)")
	suites := fs.String("suites", "", "comma-separated cipher suites (default: the v1 suite)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *store == "" {
		fmt.Fprintln(os.Stderr, "relay peer register: --store (or RELAY_PEER_CONFIG) is required")
		return 2
	}
	if *domains == "" || *endpoint == "" || *identityPub == "" || *kexPub == "" {
		fmt.Fprintln(os.Stderr, "relay peer register: --domains, --endpoint, --identity-pub and --kex-pub are all required")
		return 2
	}
	// Validate keys with a precise message before touching the store.
	if err := peering.ValidatePubKey(*identityPub, peering.IdentityKeyLen); err != nil {
		fmt.Fprintf(os.Stderr, "relay peer register: invalid --identity-pub: %v\n", err)
		return 1
	}
	if err := peering.ValidatePubKey(*kexPub, peering.KexKeyLen); err != nil {
		fmt.Fprintf(os.Stderr, "relay peer register: invalid --kex-pub: %v\n", err)
		return 1
	}

	st, err := peering.OpenPeerStore(*store)
	if err != nil {
		fmt.Fprintf(os.Stderr, "relay peer register: %v\n", err)
		return 1
	}
	entry, err := st.Register(peering.RegisterRequest{
		Domains:     splitComma(*domains),
		Endpoint:    *endpoint,
		IdentityPub: *identityPub,
		KexPub:      *kexPub,
		Versions:    splitComma(*versions),
		Suites:      splitComma(*suites),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "relay peer register: %v\n", err)
		return 1
	}
	fmt.Printf("registered peer: domains=%v endpoint=%s identity_pub=%s (pinned)\n",
		entry.Domains, entry.Endpoint, entry.IdentityPub)
	return 0
}

func peerListCmd(args []string) int {
	fs := flag.NewFlagSet("peer list", flag.ContinueOnError)
	store := storeFlag(fs)
	asJSON := fs.Bool("json", false, "emit JSON instead of a table")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *store == "" {
		fmt.Fprintln(os.Stderr, "relay peer list: --store (or RELAY_PEER_CONFIG) is required")
		return 2
	}
	st, err := peering.OpenPeerStore(*store)
	if err != nil {
		fmt.Fprintf(os.Stderr, "relay peer list: %v\n", err)
		return 1
	}
	peers := st.List()
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(peering.PeersFile{Peers: peers}); err != nil {
			fmt.Fprintf(os.Stderr, "relay peer list: %v\n", err)
			return 1
		}
		return 0
	}
	if len(peers) == 0 {
		fmt.Println("no peers registered")
		return 0
	}
	for _, p := range peers {
		fmt.Printf("%-40s %-30s %s\n", strings.Join(p.Domains, ","), p.Endpoint, p.IdentityPub)
	}
	return 0
}

func peerRevokeCmd(args []string) int {
	fs := flag.NewFlagSet("peer revoke", flag.ContinueOnError)
	store := storeFlag(fs)
	domain := fs.String("domain", "", "domain of the peer to revoke (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *store == "" {
		fmt.Fprintln(os.Stderr, "relay peer revoke: --store (or RELAY_PEER_CONFIG) is required")
		return 2
	}
	if *domain == "" {
		fmt.Fprintln(os.Stderr, "relay peer revoke: --domain is required")
		return 2
	}
	st, err := peering.OpenPeerStore(*store)
	if err != nil {
		fmt.Fprintf(os.Stderr, "relay peer revoke: %v\n", err)
		return 1
	}
	if err := st.Revoke(*domain); err != nil {
		fmt.Fprintf(os.Stderr, "relay peer revoke: %v\n", err)
		return 1
	}
	fmt.Printf("revoked peer for domain %s\n", *domain)
	return 0
}

func peerWhoamiCmd(args []string) int {
	fs := flag.NewFlagSet("peer whoami", flag.ContinueOnError)
	keyDir := fs.String("key-dir", os.Getenv("RELAY_PEERING_KEY_DIR"), "this node's peer key dir (default: $RELAY_PEERING_KEY_DIR)")
	domains := fs.String("domains", os.Getenv("RELAY_PEERING_DOMAINS"), "this node's authoritative domains (default: $RELAY_PEERING_DOMAINS)")
	endpoint := fs.String("endpoint", "", "the endpoint remote peers should reach this node at (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *keyDir == "" {
		fmt.Fprintln(os.Stderr, "relay peer whoami: --key-dir (or RELAY_PEERING_KEY_DIR) is required to load this node's identity")
		return 2
	}
	if *domains == "" || *endpoint == "" {
		fmt.Fprintln(os.Stderr, "relay peer whoami: --domains and --endpoint are required")
		return 2
	}
	id, err := loadOrCreatePeerIdentity(*keyDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "relay peer whoami: %v\n", err)
		return 1
	}
	entry := peering.LocalPeerEntry(id, splitComma(*domains), *endpoint)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(entry); err != nil {
		fmt.Fprintf(os.Stderr, "relay peer whoami: %v\n", err)
		return 1
	}
	return 0
}

func splitComma(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
