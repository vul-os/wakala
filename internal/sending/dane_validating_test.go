// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package sending

import (
	"context"
	"crypto"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// ── synthetic DNSSEC chain test harness ────────────────────────────────────
//
// These tests build a REAL (if minimal) DNSSEC chain in memory:
//
//	root (.) ──DS──▶ test. ──DS──▶ mx zone ──signs──▶ TLSA
//
// Each zone has an ECDSA-P256 KSK (DNSKEY). The parent's DS records hash the
// child's KSK; every RRset (DNSKEY, DS, TLSA) is signed with a real RRSIG. The
// resolver under test is given the ROOT zone's DS as its baked anchor and a stub
// exchanger that serves the chain, so it exercises the genuine chain-verify path
// (RRSIG.Verify against keys proven to chain to the anchor), not the AD bit.

// signedZone is a DNSSEC-signed test zone.
type signedZone struct {
	name    string
	key     *dns.DNSKEY
	priv    crypto.Signer
	incept  uint32
	expire  uint32
}

func newSignedZone(t *testing.T, name string, incept, expire time.Time) *signedZone {
	t.Helper()
	name = dns.Fqdn(name)
	k := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257, // KSK (ZONE|SEP)
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	priv, err := k.Generate(256)
	if err != nil {
		t.Fatalf("generate key for %s: %v", name, err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatalf("private key for %s is not a crypto.Signer", name)
	}
	return &signedZone{
		name:   name,
		key:    k,
		priv:   signer,
		incept: uint32(incept.Unix()),
		expire: uint32(expire.Unix()),
	}
}

// sign produces an RRSIG over rrset using this zone's key.
func (z *signedZone) sign(t *testing.T, rrset []dns.RR) *dns.RRSIG {
	t.Helper()
	if len(rrset) == 0 {
		t.Fatal("sign: empty rrset")
	}
	sig := &dns.RRSIG{
		Hdr:        dns.RR_Header{Name: rrset[0].Header().Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		TypeCovered: rrset[0].Header().Rrtype,
		Algorithm:  z.key.Algorithm,
		Labels:     uint8(dns.CountLabel(rrset[0].Header().Name)),
		OrigTtl:    rrset[0].Header().Ttl,
		Expiration: z.expire,
		Inception:  z.incept,
		KeyTag:     z.key.KeyTag(),
		SignerName: z.name,
	}
	if err := sig.Sign(z.priv, rrset); err != nil {
		t.Fatalf("sign %s for %s: %v", dns.TypeToString[sig.TypeCovered], z.name, err)
	}
	return sig
}

// ds returns this zone's KSK as a DS record (SHA-256) owned at name.
func (z *signedZone) ds() *dns.DS {
	ds := z.key.ToDS(dns.SHA256)
	return ds
}

// chainExchanger answers DNSKEY/DS/TLSA queries from a fixed map of signed
// RRsets, simulating a recursive (non-validating) upstream.
type chainExchanger struct {
	// answers maps "qname|qtype" → answer RRs (records + their RRSIGs).
	answers map[string][]dns.RR
	// servfail/nxdomain by key, optional.
	rcode map[string]int
}

func key(qname string, qtype uint16) string {
	return dns.Fqdn(qname) + "|" + dns.TypeToString[qtype]
}

func (c *chainExchanger) ExchangeContext(_ context.Context, m *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
	q := m.Question[0]
	k := key(q.Name, q.Qtype)
	resp := new(dns.Msg)
	resp.SetReply(m)
	if rc, ok := c.rcode[k]; ok {
		resp.Rcode = rc
		return resp, 0, nil
	}
	if ans, ok := c.answers[k]; ok {
		resp.Answer = ans
		resp.Rcode = dns.RcodeSuccess
		return resp, 0, nil
	}
	// Default: NOERROR/empty (no such record).
	resp.Rcode = dns.RcodeSuccess
	return resp, 0, nil
}

// buildChain constructs a full root→test→mx chain and returns the resolver
// (anchored on the root DS), the exchanger, and the mx host name.
func buildChain(t *testing.T, incept, expire time.Time) (*ValidatingDNSSECResolver, *chainExchanger, string, *dns.TLSA) {
	t.Helper()
	root := newSignedZone(t, ".", incept, expire)
	tld := newSignedZone(t, "test.", incept, expire)
	mxZone := newSignedZone(t, "mx.test.", incept, expire)

	mxHost := "mx.test."
	tlsaName, _ := dns.TLSAName(mxHost, "25", "tcp")
	tlsa := &dns.TLSA{
		Hdr:          dns.RR_Header{Name: tlsaName, Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 3600},
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		Certificate:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}

	ex := &chainExchanger{answers: map[string][]dns.RR{}, rcode: map[string]int{}}

	// Root DNSKEY, self-signed.
	rootKeyset := []dns.RR{root.key}
	ex.answers[key(".", dns.TypeDNSKEY)] = append(rootKeyset, root.sign(t, rootKeyset))

	// test. DS at the root, signed by root; test. DNSKEY self-signed.
	tldDS := tld.ds()
	tldDS.Hdr.Name = "test."
	ex.answers[key("test.", dns.TypeDS)] = []dns.RR{tldDS, root.sign(t, []dns.RR{tldDS})}
	tldKeyset := []dns.RR{tld.key}
	ex.answers[key("test.", dns.TypeDNSKEY)] = append(tldKeyset, tld.sign(t, tldKeyset))

	// mx.test. DS at test., signed by test.; mx.test. DNSKEY self-signed.
	mxDS := mxZone.ds()
	mxDS.Hdr.Name = "mx.test."
	ex.answers[key("mx.test.", dns.TypeDS)] = []dns.RR{mxDS, tld.sign(t, []dns.RR{mxDS})}
	mxKeyset := []dns.RR{mxZone.key}
	ex.answers[key("mx.test.", dns.TypeDNSKEY)] = append(mxKeyset, mxZone.sign(t, mxKeyset))

	// TLSA in the mx zone, signed by mx zone.
	ex.answers[key(tlsaName, dns.TypeTLSA)] = []dns.RR{tlsa, mxZone.sign(t, []dns.RR{tlsa})}

	r := &ValidatingDNSSECResolver{
		anchors: []*dns.DS{root.ds()}, // baked anchor = root KSK DS
		client:  ex,
		Now:     func() time.Time { return incept.Add(time.Hour) },
	}
	return r, ex, mxHost, tlsa
}

// TestValidatingResolverChainValidates proves the validator verifies the full
// chain root-DS → root-DNSKEY → test.DS → test.DNSKEY → mx.DS → mx.DNSKEY →
// TLSA-RRSIG against the baked anchor and reports Secure=true with the record.
func TestValidatingResolverChainValidates(t *testing.T) {
	now := time.Now()
	r, _, mxHost, want := buildChain(t, now.Add(-time.Hour), now.Add(24*time.Hour))

	res, err := r.LookupTLSA(context.Background(), mxHost)
	if err != nil {
		t.Fatalf("LookupTLSA: %v", err)
	}
	if !res.Secure {
		t.Fatalf("want Secure=true after full chain validation, got false")
	}
	if len(res.Records) != 1 {
		t.Fatalf("want 1 TLSA record, got %d", len(res.Records))
	}
	if res.Records[0].Usage != want.Usage || !strings.EqualFold(res.Records[0].Cert, want.Certificate) {
		t.Fatalf("TLSA record mismatch: got %+v", res.Records[0])
	}
}

// TestValidatingResolverRejectsExpiredSig proves an expired TLSA RRSIG is
// rejected (validity-period check) — surfaced as an error so no downgrade.
func TestValidatingResolverRejectsExpiredSig(t *testing.T) {
	// Build a chain whose signatures expired yesterday, and evaluate "now".
	past := time.Now().Add(-72 * time.Hour)
	r, _, mxHost, _ := buildChain(t, past, past.Add(time.Hour)) // expired
	r.Now = func() time.Time { return time.Now() }              // evaluate in the present

	if _, err := r.LookupTLSA(context.Background(), mxHost); err == nil {
		t.Fatalf("want error on expired RRSIG chain, got nil")
	}
}

// TestValidatingResolverRejectsForgedTLSASig proves a forged TLSA signature
// (signed by a key NOT in the validated zone) is rejected: an attacker who
// publishes a TLSA + a self-made RRSIG cannot get it trusted.
func TestValidatingResolverRejectsForgedTLSASig(t *testing.T) {
	now := time.Now()
	r, ex, mxHost, tlsa := buildChain(t, now.Add(-time.Hour), now.Add(24*time.Hour))

	// Forge: replace the TLSA RRSIG with one signed by an UNTRUSTED key whose
	// name claims to be the mx zone (so the signer-name passes) but which does
	// not chain to the anchor.
	tlsaName, _ := dns.TLSAName(mxHost, "25", "tcp")
	attacker := newSignedZone(t, "mx.test.", now.Add(-time.Hour), now.Add(24*time.Hour))
	forgedSig := attacker.sign(t, []dns.RR{tlsa})
	ex.answers[key(tlsaName, dns.TypeTLSA)] = []dns.RR{tlsa, forgedSig}

	if _, err := r.LookupTLSA(context.Background(), mxHost); err == nil {
		t.Fatalf("want error on forged TLSA RRSIG (untrusted key), got nil")
	}
}

// TestValidatingResolverRejectsBrokenChain proves that if a zone's KSK does not
// hash to the parent's DS (a broken/forged delegation), validation fails.
func TestValidatingResolverRejectsBrokenChain(t *testing.T) {
	now := time.Now()
	r, ex, mxHost, _ := buildChain(t, now.Add(-time.Hour), now.Add(24*time.Hour))

	// Replace test.'s DNSKEY with a DIFFERENT key (self-signed) that does NOT
	// match the DS published at the root for test.
	rogue := newSignedZone(t, "test.", now.Add(-time.Hour), now.Add(24*time.Hour))
	rogueKeyset := []dns.RR{rogue.key}
	ex.answers[key("test.", dns.TypeDNSKEY)] = append(rogueKeyset, rogue.sign(t, rogueKeyset))

	if _, err := r.LookupTLSA(context.Background(), mxHost); err == nil {
		t.Fatalf("want error when zone KSK does not match parent DS, got nil")
	}
}

// TestValidatingResolverServfailErrors proves SERVFAIL on the TLSA query is an
// error (no silent downgrade).
func TestValidatingResolverServfailErrors(t *testing.T) {
	now := time.Now()
	r, ex, mxHost, _ := buildChain(t, now.Add(-time.Hour), now.Add(24*time.Hour))
	tlsaName, _ := dns.TLSAName(mxHost, "25", "tcp")
	ex.rcode[key(tlsaName, dns.TypeTLSA)] = dns.RcodeServerFailure

	if _, err := r.LookupTLSA(context.Background(), mxHost); err == nil {
		t.Fatalf("want error on SERVFAIL, got nil")
	}
}

// TestValidatingResolverNoTLSANoDANE proves NXDOMAIN/no-TLSA is a clean "no
// DANE" (not an error, Secure=false).
func TestValidatingResolverNoTLSANoDANE(t *testing.T) {
	now := time.Now()
	r, ex, mxHost, _ := buildChain(t, now.Add(-time.Hour), now.Add(24*time.Hour))
	tlsaName, _ := dns.TLSAName(mxHost, "25", "tcp")
	ex.rcode[key(tlsaName, dns.TypeTLSA)] = dns.RcodeNameError

	res, err := r.LookupTLSA(context.Background(), mxHost)
	if err != nil {
		t.Fatalf("LookupTLSA: %v", err)
	}
	if res.Secure || len(res.Records) != 0 {
		t.Fatalf("want no-DANE (Secure=false, 0 records), got %+v", res)
	}
}

// TestValidatingResolverUnsignedTLSAIgnored proves a TLSA present but with NO
// RRSIG is treated as not-secure (attacker-forgeable; never acted on).
func TestValidatingResolverUnsignedTLSAIgnored(t *testing.T) {
	now := time.Now()
	r, ex, mxHost, tlsa := buildChain(t, now.Add(-time.Hour), now.Add(24*time.Hour))
	tlsaName, _ := dns.TLSAName(mxHost, "25", "tcp")
	// Strip the RRSIG: just the bare TLSA.
	ex.answers[key(tlsaName, dns.TypeTLSA)] = []dns.RR{tlsa}

	res, err := r.LookupTLSA(context.Background(), mxHost)
	if err != nil {
		t.Fatalf("LookupTLSA: %v", err)
	}
	if res.Secure {
		t.Fatalf("unsigned TLSA must NOT be Secure, got Secure=true")
	}
}

// TestRootAnchorsParse proves the baked IANA root anchors parse as DS records.
func TestRootAnchorsParse(t *testing.T) {
	anchors, err := parseRootAnchors(rootTrustAnchorsDS)
	if err != nil {
		t.Fatalf("parseRootAnchors: %v", err)
	}
	if len(anchors) != len(rootTrustAnchorsDS) {
		t.Fatalf("want %d anchors, got %d", len(rootTrustAnchorsDS), len(anchors))
	}
	for _, a := range anchors {
		if a.Hdr.Name != "." {
			t.Fatalf("anchor owner = %q, want root .", a.Hdr.Name)
		}
		if a.DigestType != dns.SHA256 {
			t.Fatalf("anchor digest type = %d, want SHA256", a.DigestType)
		}
	}
	// Sanity: the well-known KSK-2017 key tag must be present.
	found := false
	for _, a := range anchors {
		if a.KeyTag == 20326 {
			found = true
		}
	}
	if !found {
		t.Fatalf("KSK-2017 (key tag 20326) not present in baked anchors")
	}
}
