// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package sending

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// DANE / TLSA outbound enforcement (RFC 7672, building on RFC 6698).
//
// DANE lets a recipient domain bind its MX TLS certificate to a TLSA record
// published in DNSSEC-signed DNS at `_25._tcp.<mx-host>`. When such a record
// is present (and DNSSEC-validated), TLS to that MX is MANDATORY and the
// presented certificate chain MUST match the TLSA association. A mismatch — or
// a STARTTLS failure / a plaintext-only MX — MUST cause the message to be
// DEFERRED, never delivered in the clear (RFC 7672 §2.2, §6).
//
// DANE precedence vs MTA-STS: RFC 7672 and the MTA-STS RFC (8461 §2) both close
// the STARTTLS-downgrade hole; where a DANE-secured TLSA record exists it is the
// stronger, DNSSEC-rooted statement, so this implementation lets DANE TAKE
// PRECEDENCE over an MTA-STS policy for the same MX (the sender enforces the
// TLSA match instead of, or in addition to, the WebPKI name check). When no
// usable TLSA record exists for an MX, the MTA-STS decision still applies.
//
// ── DNSSEC dependency (FLAGGED) ─────────────────────────────────────────────
// DANE's security rests ENTIRELY on the TLSA lookup being DNSSEC-validated: an
// unauthenticated TLSA record is attacker-forgeable and MUST NOT be trusted
// (RFC 7672 §2.1). We do NOT ship a full local validating resolver with a baked
// IANA trust anchor in this build. Instead:
//
//   - TLSA lookup + RFC 7672 certificate matching are implemented for real
//     (matchTLSA, against a fake resolver in tests and a real resolver in prod).
//   - The DNSSEC validation itself is delegated to a *validating upstream
//     resolver* (e.g. a local unbound/knot-resolver, or 1.1.1.1/8.8.8.8 reached
//     over a trusted channel) via the AD (Authenticated Data) bit: the real
//     resolver sets DO=1, and treats a TLSA answer as usable ONLY when the
//     upstream returns AD=1. If AD is not set, the records are treated as
//     ABSENT (no DANE) rather than trusted — fail safe.
//
// OPERATOR-VISIBLE LIMITATION / TRUST-ANCHOR DEPTH: relying on the upstream AD
// bit means the path to the validating resolver must itself be trusted (RFC
// 7672 §2.1 "the validating resolver is part of the trusted computing base").
// On an untrusted network this should be a localhost validating resolver. A
// future hardening is a fully self-contained validating resolver with a baked,
// rotatable IANA KSK trust anchor; that is intentionally deferred here and the
// dependency is surfaced via MiekgDNSSECResolver.RequireAD + the start-up log.
// This seam (DNSSECResolver) lets that stronger validator drop in without
// touching the matching core.

// TLSA usage values (RFC 6698 §2.1.1). DANE-EE and DANE-TA are the only modes
// permitted for SMTP by RFC 7672 §3.1.3; the PKIX-* usages (0/1) are explicitly
// NOT usable for SMTP and are ignored.
const (
	tlsaUsagePKIXTA = 0 // CA constraint   — not usable for SMTP (RFC 7672 §3.1.3)
	tlsaUsagePKIXEE = 1 // service cert     — not usable for SMTP
	tlsaUsageDANETA = 2 // trust anchor assertion
	tlsaUsageDANEEE = 3 // domain-issued / end-entity assertion
)

// TLSARecord is a parsed TLSA resource record (RFC 6698 §2). Certificate is the
// raw association data (hex-decoded by the resolver into bytes for matching).
type TLSARecord struct {
	Usage        uint8
	Selector     uint8
	MatchingType uint8
	// Cert is the association data as a lowercase hex string (the wire form of
	// the TLSA RDATA Certificate Association Data field).
	Cert string
}

// usable reports whether this TLSA record is a usage SMTP/DANE may act on.
// Per RFC 7672 §3.1.3 only DANE-EE(3) and DANE-TA(2) are usable for SMTP.
func (r TLSARecord) usable() bool {
	return r.Usage == tlsaUsageDANEEE || r.Usage == tlsaUsageDANETA
}

// TLSAResult is the outcome of a DNSSEC-validated TLSA lookup for one MX host.
type TLSAResult struct {
	// Records are the usable TLSA records found. Empty when no DANE applies.
	Records []TLSARecord
	// Secure is true only when the answer was DNSSEC-validated (AD bit / local
	// validation). A non-secure answer MUST be treated as "no DANE".
	Secure bool
}

// DNSSECResolver is the seam over the DNSSEC-validated TLSA lookup. Production
// wires MiekgDNSSECResolver (a real validating-upstream client that checks the
// AD bit). Tests wire a fake. Implementations MUST NOT return Secure=true for an
// unvalidated answer.
type DNSSECResolver interface {
	// LookupTLSA resolves the TLSA records at `_<port>._<proto>.<host>` for the
	// MX host (port 25, tcp for SMTP). A nil error with an empty/!Secure result
	// means "no DANE" (opportunistic / MTA-STS path). A non-nil error is a
	// lookup failure the caller treats as "DANE state unknown".
	LookupTLSA(ctx context.Context, mxHost string) (TLSAResult, error)
}

// daneError distinguishes a DANE-mandated defer (TLS required / mismatch) from
// an ordinary delivery error so the SMTP sender can classify it.
var (
	// ErrDANEMismatch indicates the MX certificate chain did not match any usable
	// TLSA record; under DANE this MUST defer (never plaintext).
	ErrDANEMismatch = errors.New("dane: certificate chain does not match any TLSA record")
	// ErrDANENoTLS indicates a DANE-secured MX did not allow TLS (no STARTTLS),
	// which MUST defer.
	ErrDANENoTLS = errors.New("dane: TLS required for DANE-secured MX but not available")
)

// daneDecision is the per-MX DANE decision computed before/at connect time.
type daneDecision struct {
	// secured is true when a usable, DNSSEC-validated TLSA record set exists for
	// this MX. When true, TLS is mandatory and the chain MUST match.
	secured bool
	// records are the usable TLSA records to match the presented chain against.
	records []TLSARecord
}

// decideDANE resolves the DANE decision for an MX host. On a lookup error it
// returns an unsecured decision (DANE state unknown → fall through to MTA-STS /
// TLS policy) but the caller logs it. A resolver that returns Secure=false (no
// DNSSEC validation, or AD bit absent) yields an unsecured decision — we never
// act on unauthenticated TLSA data (RFC 7672 §2.1).
func decideDANE(ctx context.Context, resolver DNSSECResolver, mxHost string) (daneDecision, error) {
	if resolver == nil {
		return daneDecision{}, nil
	}
	res, err := resolver.LookupTLSA(ctx, mxHost)
	if err != nil {
		return daneDecision{}, err
	}
	if !res.Secure {
		// Records present but not DNSSEC-validated → treat as absent (fail safe).
		return daneDecision{}, nil
	}
	usable := make([]TLSARecord, 0, len(res.Records))
	for _, r := range res.Records {
		if r.usable() {
			usable = append(usable, r)
		}
	}
	if len(usable) == 0 {
		return daneDecision{}, nil
	}
	return daneDecision{secured: true, records: usable}, nil
}

// matchTLSA implements the RFC 7672 §2.1 certificate-matching core. It returns
// nil when the presented chain satisfies at least one usable TLSA record, or
// ErrDANEMismatch otherwise.
//
//   - chain[0] is the MX's end-entity (leaf) certificate; chain[1:] are the
//     intermediates the server presented.
//   - DANE-EE(3): match the association against the leaf certificate only
//     (RFC 7672 §2.1 — the TLSA record directly names the end-entity cert/SPKI;
//     name checks and chain validity are NOT required).
//   - DANE-TA(2): match the association against any certificate the server
//     presented (a trust-anchor cert that must appear in the chain); the leaf
//     must then chain to that anchor. We require the matched anchor to be one of
//     the presented certs (RFC 7672 §2.1 / §3.1.3).
func matchTLSA(chain []*x509.Certificate, records []TLSARecord) error {
	if len(chain) == 0 {
		return ErrDANEMismatch
	}
	leaf := chain[0]
	for _, rec := range records {
		switch rec.Usage {
		case tlsaUsageDANEEE:
			if tlsaMatchesCert(rec, leaf) {
				return nil
			}
		case tlsaUsageDANETA:
			// The trust anchor may be any presented cert (leaf included for a
			// self-issued TA). RFC 7672 §3.1.3: the matched TA must be in the
			// server's presented chain.
			for _, c := range chain {
				if tlsaMatchesCert(rec, c) {
					return nil
				}
			}
		default:
			// PKIX-* usages are not usable for SMTP; skip.
			continue
		}
	}
	return ErrDANEMismatch
}

// tlsaMatchesCert reports whether one TLSA record's association data matches the
// given certificate under the record's selector + matching type. It uses
// miekg/dns CertificateToDANE to compute the association, then compares
// case-insensitively against the record's stored hex.
func tlsaMatchesCert(rec TLSARecord, cert *x509.Certificate) bool {
	assoc, err := dns.CertificateToDANE(rec.Selector, rec.MatchingType, cert)
	if err != nil {
		return false
	}
	return strings.EqualFold(assoc, rec.Cert)
}

// fmtTLSA renders a TLSA record for logs.
func fmtTLSA(r TLSARecord) string {
	return fmt.Sprintf("%d %d %d %s", r.Usage, r.Selector, r.MatchingType, r.Cert)
}
