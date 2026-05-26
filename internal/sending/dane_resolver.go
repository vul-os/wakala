// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package sending

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// MiekgDNSSECResolver is the production DNSSECResolver: it queries a *validating
// upstream* DNS resolver for TLSA records with the DNSSEC OK (DO) bit set, and
// trusts the answer only when the upstream returns the Authenticated Data (AD)
// bit — i.e. the upstream did the DNSSEC validation and vouches for it.
//
// IMPORTANT TRUST-ANCHOR FLAG: this resolver does NOT perform local DNSSEC chain
// validation against a baked IANA trust anchor. It relies on the configured
// upstream being a validating resolver AND the path to it being trusted (RFC
// 7672 §2.1: the validating resolver is in the trusted computing base). On an
// untrusted network this MUST point at a localhost validating resolver
// (unbound/knot/systemd-resolved with DNSSEC=yes). When RequireAD is true (the
// default) a missing AD bit is treated as "no DANE" — fail safe, never trust
// unvalidated TLSA data. This is the documented foundation+flag boundary; a
// future self-contained validator can replace this type behind DNSSECResolver
// without touching the matching core (dane.go).
type MiekgDNSSECResolver struct {
	// Server is the validating upstream resolver address (host:port). If empty,
	// the first nameserver from /etc/resolv.conf is used, falling back to
	// 127.0.0.1:53. For DANE on an untrusted network this SHOULD be a localhost
	// validating resolver.
	Server string

	// RequireAD, when true (recommended/default via NewMiekgDNSSECResolver),
	// treats an answer WITHOUT the AD bit as not-secure (no DANE). When false,
	// the AD requirement is relaxed — UNSAFE, for closed test networks only.
	RequireAD bool

	// Net is the transport ("udp" or "tcp"). TLSA answers can be large; we use
	// TCP by default to avoid truncation games. Empty defaults to "tcp".
	Net string

	// Timeout bounds each query. Zero defaults to 5s.
	Timeout time.Duration

	// client, if set, overrides the dns.Client (tests). Production builds one.
	client dnsExchanger
}

// dnsExchanger is the minimal miekg/dns client surface used, for test injection.
type dnsExchanger interface {
	ExchangeContext(ctx context.Context, m *dns.Msg, addr string) (*dns.Msg, time.Duration, error)
}

// NewMiekgDNSSECResolver builds the production resolver with AD enforcement on.
// server may be empty to auto-detect from resolv.conf.
func NewMiekgDNSSECResolver(server string) *MiekgDNSSECResolver {
	return &MiekgDNSSECResolver{
		Server:    server,
		RequireAD: true,
		Net:       "tcp",
		Timeout:   5 * time.Second,
	}
}

func (r *MiekgDNSSECResolver) resolverAddr() string {
	if r.Server != "" {
		return ensurePort(r.Server)
	}
	if cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil && len(cfg.Servers) > 0 {
		return net.JoinHostPort(cfg.Servers[0], cfg.Port)
	}
	return "127.0.0.1:53"
}

func ensurePort(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(addr, "53")
}

func (r *MiekgDNSSECResolver) exchanger() dnsExchanger {
	if r.client != nil {
		return r.client
	}
	netw := r.Net
	if netw == "" {
		netw = "tcp"
	}
	to := r.Timeout
	if to == 0 {
		to = 5 * time.Second
	}
	return &dns.Client{Net: netw, Timeout: to}
}

// LookupTLSA implements DNSSECResolver. It builds `_25._tcp.<host>`, queries the
// validating upstream with DO=1, and returns Secure=true only when AD=1 (unless
// RequireAD is disabled). NXDOMAIN / empty answer is a non-error "no DANE".
func (r *MiekgDNSSECResolver) LookupTLSA(ctx context.Context, mxHost string) (TLSAResult, error) {
	host := dns.Fqdn(strings.TrimSuffix(mxHost, "."))
	qname, err := dns.TLSAName(host, "25", "tcp")
	if err != nil {
		return TLSAResult{}, fmt.Errorf("dane: build TLSA name for %q: %w", mxHost, err)
	}

	m := new(dns.Msg)
	m.SetQuestion(qname, dns.TypeTLSA)
	m.RecursionDesired = true
	// Request DNSSEC records + signal we want validation (DO bit).
	m.SetEdns0(4096, true)
	// Ask the upstream to set AD if it validated.
	m.AuthenticatedData = true

	resp, _, err := r.exchanger().ExchangeContext(ctx, m, r.resolverAddr())
	if err != nil {
		return TLSAResult{}, fmt.Errorf("dane: TLSA query %q: %w", qname, err)
	}
	if resp == nil {
		return TLSAResult{}, fmt.Errorf("dane: nil TLSA response for %q", qname)
	}
	switch resp.Rcode {
	case dns.RcodeSuccess:
		// proceed
	case dns.RcodeNameError:
		// NXDOMAIN: no TLSA, no DANE. (Note: an NXDOMAIN ought itself be
		// DNSSEC-authenticated to be sure DANE is truly absent; we treat absence
		// as "no DANE" which is the standard opportunistic-DANE posture.)
		return TLSAResult{Secure: resp.AuthenticatedData}, nil
	case dns.RcodeServerFailure:
		// SERVFAIL from a validating resolver typically signals a DNSSEC
		// validation failure (bogus). Surface as an error so the caller does NOT
		// silently downgrade.
		return TLSAResult{}, fmt.Errorf("dane: SERVFAIL for %q (possible DNSSEC validation failure)", qname)
	default:
		return TLSAResult{}, fmt.Errorf("dane: TLSA query %q rcode %s", qname, dns.RcodeToString[resp.Rcode])
	}

	var recs []TLSARecord
	for _, rr := range resp.Answer {
		t, ok := rr.(*dns.TLSA)
		if !ok {
			continue
		}
		recs = append(recs, TLSARecord{
			Usage:        t.Usage,
			Selector:     t.Selector,
			MatchingType: t.MatchingType,
			Cert:         strings.ToLower(t.Certificate),
		})
	}

	secure := resp.AuthenticatedData
	if r.RequireAD && !secure {
		// We have records but the upstream did not vouch for them via AD. Per RFC
		// 7672 §2.1, unauthenticated TLSA records MUST NOT be used. Treat as no
		// DANE (Secure=false) rather than erroring, so delivery can fall back to
		// MTA-STS / TLS policy. The matching core checks Secure before acting.
		return TLSAResult{Records: recs, Secure: false}, nil
	}
	return TLSAResult{Records: recs, Secure: secure}, nil
}
