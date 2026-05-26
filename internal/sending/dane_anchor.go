// Copyright (c) 2024 Vulos contributors
// SPDX-License-Identifier: MIT

package sending

// Baked IANA DNS root trust anchor (the root-zone KSK DS records).
//
// DNSSEC validation is only as trustworthy as the anchor it roots in. RFC 7672
// §2.1 requires DANE's TLSA lookup to be DNSSEC-validated against a trust anchor
// the verifier holds independently — NOT merely trusting an upstream resolver's
// AD bit. We therefore bake the IANA root KSK DS set here so the validating
// resolver (dane_validating.go) verifies a real chain to the root.
//
// These are the published, well-known IANA root-zone KSK DS records (the same
// values served as `. IN DS` and distributed in IANA's root-anchors.xml). Both
// the long-standing KSK-2017 (tag 20326) and the rolled-in KSK-2024 (tag 38696)
// are included so validation keeps working across the key roll; either matching
// is sufficient to anchor the root DNSKEY RRset.
//
// SECURITY / ROTATION NOTE: the root KSK rolls roughly every several years
// (RFC 5011 automated rollover at the resolver, or a code/data update here).
// When IANA publishes a new KSK, add its DS line below and ship a release; the
// validator accepts ANY anchor whose DS matches a self-signing root DNSKEY, so
// adding a new anchor before the old is retired makes the roll seamless. The
// values are presentation-format DS records parsed at init via miekg/dns.
//
// Source of truth (verify against these when updating):
//   https://data.iana.org/root-anchors/root-anchors.xml
//   https://www.iana.org/dnssec/files
//
//	KSK-2017: . IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
//	KSK-2024: . IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16
var rootTrustAnchorsDS = []string{
	".\t86400\tIN\tDS\t20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
	".\t86400\tIN\tDS\t38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
}
