// Package cost projects the relay's data-plane egress cost from bytes relayed.
//
// The relay is the ONLY bandwidth-bound service in the Vulos suite: every other
// service is compute/storage-bound, but the relay's marginal running cost is a direct
// function of the bytes it moves. That makes "does it scale gracefully AND stay cost-
// managed" a single arithmetic question — bytes → euros — rather than a hand-wave. This
// package turns a metered byte total (the same monotonic counter the billing meter and
// the autoscaler read, see server.Load().TotalBytes / vulos_relay_proxied_bytes_total)
// into a projected euro cost against a provider/region egress rate.
//
// Units: a "TB" here is the DECIMAL terabyte (1e12 bytes) — the unit bandwidth is
// actually billed in by Hetzner/Vultr/Fly — not the binary TiB (2^40). Mixing the two
// silently under- or over-states cost by ~10%, so the constant is explicit.
package cost

// BytesPerTB is one decimal terabyte, the unit egress is billed in.
const BytesPerTB = 1_000_000_000_000

// Per-provider/region egress rates, in euros per TB. These are the grounded numbers
// behind the topology decision that the relay runs on Hetzner EU as the cheap default
// and on Fly only for gap regions:
//
//   - Hetzner EU: ~€1 / TB — the primary data plane.
//   - Fly Africa: ~$0.12 / GB ≈ €110 / TB — ~100× Hetzner, which is exactly why the
//     relay does NOT run general traffic there; it is a fallback for regions Hetzner
//     does not serve.
//
// The CP prices relay GB per-region from the `region` tag stamped on each usage report
// (see docs/METERING-BILLING.md); these constants are the reference rates that pricing
// is derived from.
const (
	HetznerEUEURPerTB = 1.0
	FlyAfricaEURPerTB = 110.0
)

// ProjectEUR returns the projected data-plane cost, in euros, of relaying `bytes` at
// the given €/TB egress rate. Zero or negative inputs project zero cost (a relay that
// moved nothing, or an unpriced region, costs nothing to project).
func ProjectEUR(bytes int64, eurPerTB float64) float64 {
	if bytes <= 0 || eurPerTB <= 0 {
		return 0
	}
	return float64(bytes) / float64(BytesPerTB) * eurPerTB
}

// TBFor returns how many decimal TB a euro budget buys at the given €/TB rate. It is
// the inverse of ProjectEUR and answers the capacity-planning question directly: "what
// monthly transfer does a €N/mo relay node's bandwidth allowance cover?"
func TBFor(budgetEUR, eurPerTB float64) float64 {
	if budgetEUR <= 0 || eurPerTB <= 0 {
		return 0
	}
	return budgetEUR / eurPerTB
}
