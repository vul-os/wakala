// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package sending

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// stubExchanger returns a fixed response for any query.
type stubExchanger struct {
	resp *dns.Msg
	err  error
}

func (s stubExchanger) ExchangeContext(_ context.Context, _ *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
	return s.resp, 0, s.err
}

func tlsaMsg(t *testing.T, ad bool, rcode int) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.Rcode = rcode
	m.AuthenticatedData = ad
	rr, err := dns.NewRR("_25._tcp.mx.test. 3600 IN TLSA 3 1 1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}
	m.Answer = []dns.RR{rr}
	return m
}

// TestMiekgResolverADBitRequired proves that without the AD bit, the resolver
// reports the answer as NOT secure (so DANE is treated as absent — fail safe).
func TestMiekgResolverADBitRequired(t *testing.T) {
	r := NewMiekgDNSSECResolver("127.0.0.1:53")
	r.client = stubExchanger{resp: tlsaMsg(t, false, dns.RcodeSuccess)}

	res, err := r.LookupTLSA(context.Background(), "mx.test")
	if err != nil {
		t.Fatalf("LookupTLSA: %v", err)
	}
	if res.Secure {
		t.Fatalf("want Secure=false when AD bit absent, got true")
	}
	if len(res.Records) != 1 {
		t.Fatalf("want 1 record parsed, got %d", len(res.Records))
	}
}

// TestMiekgResolverADBitTrusts proves that with the AD bit, the answer is
// reported secure and the TLSA record is parsed.
func TestMiekgResolverADBitTrusts(t *testing.T) {
	r := NewMiekgDNSSECResolver("127.0.0.1:53")
	r.client = stubExchanger{resp: tlsaMsg(t, true, dns.RcodeSuccess)}

	res, err := r.LookupTLSA(context.Background(), "mx.test")
	if err != nil {
		t.Fatalf("LookupTLSA: %v", err)
	}
	if !res.Secure {
		t.Fatalf("want Secure=true when AD bit set, got false")
	}
	if len(res.Records) != 1 || res.Records[0].Usage != 3 {
		t.Fatalf("want 1 DANE-EE record, got %+v", res.Records)
	}
}

// TestMiekgResolverServfailErrors proves a SERVFAIL (likely a DNSSEC bogus
// answer) surfaces as an error so the caller does not silently downgrade.
func TestMiekgResolverServfailErrors(t *testing.T) {
	r := NewMiekgDNSSECResolver("127.0.0.1:53")
	r.client = stubExchanger{resp: tlsaMsg(t, false, dns.RcodeServerFailure)}

	if _, err := r.LookupTLSA(context.Background(), "mx.test"); err == nil {
		t.Fatalf("want error on SERVFAIL, got nil")
	}
}

// TestMiekgResolverNXDOMAINNoDANE proves NXDOMAIN is a clean "no DANE".
func TestMiekgResolverNXDOMAINNoDANE(t *testing.T) {
	r := NewMiekgDNSSECResolver("127.0.0.1:53")
	m := new(dns.Msg)
	m.Rcode = dns.RcodeNameError
	r.client = stubExchanger{resp: m}

	res, err := r.LookupTLSA(context.Background(), "mx.test")
	if err != nil {
		t.Fatalf("LookupTLSA: %v", err)
	}
	if len(res.Records) != 0 {
		t.Fatalf("want no records on NXDOMAIN, got %d", len(res.Records))
	}
}
