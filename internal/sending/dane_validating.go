// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package sending

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ValidatingDNSSECResolver is a self-contained DNSSEC-validating DNSSECResolver
// that verifies the FULL chain of trust from the baked IANA root trust anchor
// (dane_anchor.go) down to the TLSA record, rather than blindly trusting an
// upstream resolver's AD bit.
//
// It is a *minimal* validator: it queries any (non-validating is fine) recursive
// resolver with DO=1 for the DNSKEY/DS/TLSA RRsets and their RRSIGs, then locally
// verifies, for every zone from the root down to the TLSA owner:
//
//  1. the parent's DS RRset is signed by a parent-zone DNSKEY (and the root DS is
//     the baked anchor — no signature needed for the anchor itself);
//  2. the child zone's DNSKEY RRset contains a KSK whose hash matches a validated
//     DS, and the DNSKEY RRset is self-signed by that KSK;
//  3. the TLSA RRset is signed by a DNSKEY of its owner zone;
//  4. every RRSIG used is within its validity period (expired/forged → reject).
//
// What this DOES validate: the cryptographic chain root-DS → root-DNSKEY →
// (delegation DS → zone-DNSKEY)* → TLSA-RRSIG. A forged or expired signature, a
// DNSKEY that does not hash to the parent's DS, or a TLSA RRset with no valid
// RRSIG all cause the answer to be reported NOT Secure (DANE treated as absent)
// or, for a hard validation failure on a delegated/secure zone, an error so the
// caller does not silently downgrade.
//
// What this does NOT do (honest scope): it does not validate NSEC/NSEC3 to prove
// authenticated DENIAL OF EXISTENCE. Consequently a *missing* TLSA record or a
// *missing* DS (an insecure delegation / opt-out) is taken at face value as "no
// DANE" rather than being cryptographically proven absent — this is the standard
// opportunistic-DANE posture (the same one the AD-bit path takes; see the
// NXDOMAIN note in MiekgDNSSECResolver). The PRESENCE of a TLSA record, by
// contrast, is fully chain-verified before it is ever acted on, which is the
// property RFC 7672 §2.1 actually requires before mandating TLS. CNAME chasing
// for the TLSA owner is not implemented (SMTP DANE base names are not CNAMEs in
// practice; RFC 7672 §7).
type ValidatingDNSSECResolver struct {
	// Server is the recursive resolver address (host[:port]) used purely as a
	// TRANSPORT to fetch signed RRsets — it need NOT itself validate, because we
	// validate locally against the baked anchor. Empty → resolv.conf → 127.0.0.1.
	Server string

	// Net is the transport ("tcp" default — TLSA/DNSKEY answers are large).
	Net string

	// Timeout bounds each query (default 5s).
	Timeout time.Duration

	// Now overrides the clock for RRSIG validity checks (tests). nil → time.Now.
	Now func() time.Time

	// anchors are the parsed baked root DS records. Populated by
	// NewValidatingDNSSECResolver; tests may override.
	anchors []*dns.DS

	// client overrides the dns exchanger (tests). Production builds a dns.Client.
	client dnsExchanger
}

// NewValidatingDNSSECResolver builds the validator with the baked IANA root
// trust anchors. server may be empty to auto-detect a recursive resolver.
func NewValidatingDNSSECResolver(server string) (*ValidatingDNSSECResolver, error) {
	anchors, err := parseRootAnchors(rootTrustAnchorsDS)
	if err != nil {
		return nil, err
	}
	return &ValidatingDNSSECResolver{
		Server:  server,
		Net:     "tcp",
		Timeout: 5 * time.Second,
		anchors: anchors,
	}, nil
}

// parseRootAnchors parses the baked DS presentation records into *dns.DS.
func parseRootAnchors(lines []string) ([]*dns.DS, error) {
	out := make([]*dns.DS, 0, len(lines))
	for _, l := range lines {
		rr, err := dns.NewRR(l)
		if err != nil {
			return nil, fmt.Errorf("dane: parse root trust anchor %q: %w", l, err)
		}
		ds, ok := rr.(*dns.DS)
		if !ok {
			return nil, fmt.Errorf("dane: root trust anchor %q is not a DS record", l)
		}
		out = append(out, ds)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("dane: no root trust anchors configured")
	}
	return out, nil
}

func (r *ValidatingDNSSECResolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *ValidatingDNSSECResolver) resolverAddr() string {
	mr := &MiekgDNSSECResolver{Server: r.Server}
	return mr.resolverAddr()
}

func (r *ValidatingDNSSECResolver) exchanger() dnsExchanger {
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

// query sends one DO=1 question and returns the response (RRSIGs included).
func (r *ValidatingDNSSECResolver) query(ctx context.Context, qname string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	m.RecursionDesired = true
	m.SetEdns0(4096, true) // DO=1: ask for DNSSEC records
	resp, _, err := r.exchanger().ExchangeContext(ctx, m, r.resolverAddr())
	if err != nil {
		return nil, fmt.Errorf("dane: %s %s query: %w", dns.TypeToString[qtype], qname, err)
	}
	if resp == nil {
		return nil, fmt.Errorf("dane: nil response for %s %s", dns.TypeToString[qtype], qname)
	}
	return resp, nil
}

// LookupTLSA implements DNSSECResolver via a real chain validation.
func (r *ValidatingDNSSECResolver) LookupTLSA(ctx context.Context, mxHost string) (TLSAResult, error) {
	host := dns.Fqdn(strings.TrimSuffix(mxHost, "."))
	qname, err := dns.TLSAName(host, "25", "tcp")
	if err != nil {
		return TLSAResult{}, fmt.Errorf("dane: build TLSA name for %q: %w", mxHost, err)
	}

	// 1) Establish the validated DNSKEY set for the TLSA owner zone by walking
	//    the chain from the root anchor. The TLSA owner zone is the zone that
	//    actually holds the record; we use the zone apex discovered from the
	//    TLSA RRSIG's signer name (set after fetching), so first fetch the TLSA.
	tlsaResp, err := r.query(ctx, qname, dns.TypeTLSA)
	if err != nil {
		return TLSAResult{}, err
	}
	switch tlsaResp.Rcode {
	case dns.RcodeSuccess:
		// proceed
	case dns.RcodeNameError:
		// NXDOMAIN: no TLSA. We do not prove this with NSEC/NSEC3 (see type doc);
		// treat as "no DANE" — opportunistic posture.
		return TLSAResult{}, nil
	case dns.RcodeServerFailure:
		return TLSAResult{}, fmt.Errorf("dane: SERVFAIL for %q (possible DNSSEC validation failure)", qname)
	default:
		return TLSAResult{}, fmt.Errorf("dane: TLSA query %q rcode %s", qname, dns.RcodeToString[tlsaResp.Rcode])
	}

	tlsaRRs, tlsaSigs := splitRRset(tlsaResp.Answer, dns.TypeTLSA)
	if len(tlsaRRs) == 0 {
		// No TLSA in a NOERROR answer → no DANE (insecure / no record). Not proven
		// via NSEC; opportunistic posture.
		return TLSAResult{}, nil
	}
	if len(tlsaSigs) == 0 {
		// TLSA present but UNSIGNED — attacker-forgeable. MUST NOT be trusted.
		// Treat as not-secure (no DANE), fail safe (RFC 7672 §2.1).
		return TLSAResult{Records: parseTLSARecords(tlsaRRs), Secure: false}, nil
	}

	// The TLSA owner zone apex is the RRSIG signer name.
	zone := dns.CanonicalName(tlsaSigs[0].SignerName)

	// 2) Validate the chain to that zone's DNSKEY set against the baked anchor.
	zoneKeys, err := r.validateChainTo(ctx, zone)
	if err != nil {
		return TLSAResult{}, err
	}
	if len(zoneKeys) == 0 {
		// Could not establish a secure zone (insecure delegation). The TLSA is not
		// validatable → treat as no DANE (fail safe).
		return TLSAResult{Records: parseTLSARecords(tlsaRRs), Secure: false}, nil
	}

	// 3) Verify a TLSA RRSIG against the validated zone keys (validity + crypto).
	if err := r.verifyRRSIG(tlsaSigs, tlsaRRs, zoneKeys); err != nil {
		// A present TLSA whose signature does not verify is a HARD failure: an
		// attacker may be stripping/forging. Surface as an error so the sender
		// defers rather than silently downgrading.
		return TLSAResult{}, fmt.Errorf("dane: TLSA RRSIG verify for %q: %w", qname, err)
	}

	return TLSAResult{Records: parseTLSARecords(tlsaRRs), Secure: true}, nil
}

// validateChainTo walks delegations from the root down to zone, returning the
// validated DNSKEY RRset of zone (keys proven to chain to the baked anchor). A
// nil (len 0) result with nil error means an insecure delegation was hit (no DS),
// i.e. the zone is not DNSSEC-secured.
func (r *ValidatingDNSSECResolver) validateChainTo(ctx context.Context, zone string) ([]*dns.DNSKEY, error) {
	zone = dns.CanonicalName(zone)
	labels := zoneChain(zone) // ["." , "org.", "example.org.", ...]

	// Root: validate root DNSKEY against the baked DS anchor.
	parentKeys, err := r.validateZoneKeysAgainstDS(ctx, ".", r.anchors)
	if err != nil {
		return nil, fmt.Errorf("dane: root anchor validation: %w", err)
	}

	for i := 1; i < len(labels); i++ {
		child := labels[i]
		// Fetch + verify the child's DS RRset using the parent's validated keys.
		dsRRs, secure, err := r.fetchValidatedDS(ctx, child, parentKeys)
		if err != nil {
			return nil, err
		}
		if !secure || len(dsRRs) == 0 {
			// Insecure delegation (no DS, opt-out, or unsigned) → chain stops here.
			// The target zone is not DNSSEC-secured.
			return nil, nil
		}
		// Validate the child DNSKEY set against its (now-validated) DS records.
		childKeys, err := r.validateZoneKeysAgainstDS(ctx, child, dsRRs)
		if err != nil {
			return nil, err
		}
		parentKeys = childKeys
	}
	return parentKeys, nil
}

// validateZoneKeysAgainstDS fetches the DNSKEY RRset for zone, requires at least
// one DNSKEY whose hash matches one of dsSet, and requires the DNSKEY RRset to be
// self-signed by such a key. Returns the validated DNSKEY RRset.
func (r *ValidatingDNSSECResolver) validateZoneKeysAgainstDS(ctx context.Context, zone string, dsSet []*dns.DS) ([]*dns.DNSKEY, error) {
	resp, err := r.query(ctx, zone, dns.TypeDNSKEY)
	if err != nil {
		return nil, err
	}
	if resp.Rcode == dns.RcodeServerFailure {
		return nil, fmt.Errorf("dane: SERVFAIL fetching DNSKEY for %q", zone)
	}
	keyRRs, keySigs := splitDNSKEY(resp.Answer)
	if len(keyRRs) == 0 {
		return nil, fmt.Errorf("dane: no DNSKEY records for zone %q", zone)
	}
	if len(keySigs) == 0 {
		return nil, fmt.Errorf("dane: DNSKEY RRset for %q has no RRSIG", zone)
	}

	// Find at least one DNSKEY (the KSK) that hashes to a trusted DS.
	var validKSKs []*dns.DNSKEY
	for _, k := range keyRRs {
		for _, ds := range dsSet {
			computed := k.ToDS(ds.DigestType)
			if computed == nil {
				continue
			}
			if computed.KeyTag == ds.KeyTag &&
				strings.EqualFold(computed.Digest, ds.Digest) &&
				computed.Algorithm == ds.Algorithm {
				validKSKs = append(validKSKs, k)
				break
			}
		}
	}
	if len(validKSKs) == 0 {
		return nil, fmt.Errorf("dane: no DNSKEY for %q matches a trusted DS (broken chain)", zone)
	}

	// The DNSKEY RRset MUST be self-signed by one of the validated KSKs, within
	// its validity period.
	keyRRGeneric := dnskeysToRR(keyRRs)
	if err := r.verifyRRSIGWithKeys(keySigs, keyRRGeneric, validKSKs); err != nil {
		return nil, fmt.Errorf("dane: DNSKEY self-signature for %q: %w", zone, err)
	}
	return keyRRs, nil
}

// fetchValidatedDS fetches the DS RRset for child and verifies its RRSIG using
// the parent's validated DNSKEYs. A NOERROR answer with no DS (and no proof) is
// reported secure=false (insecure delegation). Returns (ds, secure, err).
func (r *ValidatingDNSSECResolver) fetchValidatedDS(ctx context.Context, child string, parentKeys []*dns.DNSKEY) ([]*dns.DS, bool, error) {
	resp, err := r.query(ctx, child, dns.TypeDS)
	if err != nil {
		return nil, false, err
	}
	switch resp.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
		// proceed; absence handled below
	case dns.RcodeServerFailure:
		return nil, false, fmt.Errorf("dane: SERVFAIL fetching DS for %q", child)
	default:
		return nil, false, fmt.Errorf("dane: DS query %q rcode %s", child, dns.RcodeToString[resp.Rcode])
	}

	dsRRs, dsSigs := splitDS(resp.Answer)
	if len(dsRRs) == 0 {
		// No DS → insecure delegation (we do not prove this via NSEC; opportunistic).
		return nil, false, nil
	}
	if len(dsSigs) == 0 {
		return nil, false, fmt.Errorf("dane: DS RRset for %q has no RRSIG", child)
	}
	if err := r.verifyRRSIGWithKeys(dsSigs, dsToRR(dsRRs), parentKeys); err != nil {
		return nil, false, fmt.Errorf("dane: DS RRSIG verify for %q: %w", child, err)
	}
	return dsRRs, true, nil
}

// verifyRRSIG verifies at least one sig in sigs over rrset using one of keys.
func (r *ValidatingDNSSECResolver) verifyRRSIG(sigs []*dns.RRSIG, rrset []dns.RR, keys []*dns.DNSKEY) error {
	return r.verifyRRSIGWithKeys(sigs, rrset, keys)
}

func (r *ValidatingDNSSECResolver) verifyRRSIGWithKeys(sigs []*dns.RRSIG, rrset []dns.RR, keys []*dns.DNSKEY) error {
	now := r.now()
	var lastErr error
	for _, sig := range sigs {
		if !sig.ValidityPeriod(now) {
			lastErr = fmt.Errorf("RRSIG (keytag %d) outside validity period", sig.KeyTag)
			continue
		}
		for _, k := range keys {
			if sig.KeyTag != k.KeyTag() {
				continue
			}
			if err := sig.Verify(k, rrset); err != nil {
				lastErr = err
				continue
			}
			return nil // a valid, in-period signature by a trusted key
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no RRSIG matched a trusted key")
	}
	return lastErr
}

// ── RRset helpers ──────────────────────────────────────────────────────────

// zoneChain returns the apex chain from root to zone, e.g.
// "mx.example.org." → [".","org.","example.org.","mx.example.org."]. (Used only
// to walk delegations; the actual signed zone apex is taken from RRSIG signer
// names, so an over-long chain that hits an insecure delegation simply stops.)
func zoneChain(zone string) []string {
	zone = dns.CanonicalName(zone)
	if zone == "." {
		return []string{"."}
	}
	labels := dns.SplitDomainName(zone) // ["mx","example","org"]
	out := []string{"."}
	for i := len(labels) - 1; i >= 0; i-- {
		out = append(out, dns.Fqdn(strings.Join(labels[i:], ".")))
	}
	return out
}

// splitRRset partitions answers into the RRs of the requested type and the
// RRSIGs that cover that type.
func splitRRset(answers []dns.RR, t uint16) ([]dns.RR, []*dns.RRSIG) {
	var rrs []dns.RR
	var sigs []*dns.RRSIG
	for _, rr := range answers {
		if rr.Header().Rrtype == t {
			rrs = append(rrs, rr)
			continue
		}
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == t {
			sigs = append(sigs, sig)
		}
	}
	return rrs, sigs
}

func splitDNSKEY(answers []dns.RR) ([]*dns.DNSKEY, []*dns.RRSIG) {
	var keys []*dns.DNSKEY
	var sigs []*dns.RRSIG
	for _, rr := range answers {
		switch v := rr.(type) {
		case *dns.DNSKEY:
			keys = append(keys, v)
		case *dns.RRSIG:
			if v.TypeCovered == dns.TypeDNSKEY {
				sigs = append(sigs, v)
			}
		}
	}
	return keys, sigs
}

func splitDS(answers []dns.RR) ([]*dns.DS, []*dns.RRSIG) {
	var ds []*dns.DS
	var sigs []*dns.RRSIG
	for _, rr := range answers {
		switch v := rr.(type) {
		case *dns.DS:
			ds = append(ds, v)
		case *dns.RRSIG:
			if v.TypeCovered == dns.TypeDS {
				sigs = append(sigs, v)
			}
		}
	}
	return ds, sigs
}

func dnskeysToRR(keys []*dns.DNSKEY) []dns.RR {
	out := make([]dns.RR, len(keys))
	for i, k := range keys {
		out[i] = k
	}
	return out
}

func dsToRR(ds []*dns.DS) []dns.RR {
	out := make([]dns.RR, len(ds))
	for i, d := range ds {
		out[i] = d
	}
	return out
}

func parseTLSARecords(rrs []dns.RR) []TLSARecord {
	var recs []TLSARecord
	for _, rr := range rrs {
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
	return recs
}

// Compile-time interface check.
var _ DNSSECResolver = (*ValidatingDNSSECResolver)(nil)
