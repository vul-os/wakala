//! USD-recommended pricing — a cost-plus `HostingProfile` model and
//! [`recommended_tariff`], turning an operator's real infra costs into a starting-point
//! [`TariffSchedule`] per coordinator kind.
//!
//! # THESE ARE RECOMMENDATIONS, NOT PROTOCOL NUMBERS
//!
//! CONTRACT §6 is explicit: "the numbers are operator policy" — quotas, rate limits, and prices
//! are never something this crate (or KOTVA) mandates. Everything in this module exists only to
//! give an operator a defensible, cost-plus **starting point** instead of a blank page. An
//! operator SHOULD look at their own invoice and override every number here; nothing downstream
//! of [`recommended_tariff`] treats its output as anything but an ordinary, editable
//! [`TariffSchedule`] the operator still has to sign themselves ([`TariffSchedule::sign`]).
//!
//! ## Source assumptions (illustrative, not fetched live)
//!
//! The [`HostingProfile`] constants below are **illustrative approximations** of low/mid-tier VPS
//! pricing as commonly advertised (rough figures in the 2024-2026 window; a *shape* to copy, not
//! a quote):
//! - **Hetzner-like** ([`HostingProfile::HETZNER_CX`]): a small (2 vCPU / 4-8 GB) Cloud VPS around
//!   $5/mo, with a large included bandwidth allowance and cheap (~$0.01/GB) overage.
//! - **Vultr-like** ([`HostingProfile::VULTR_GENERIC`]): a comparable small Cloud Compute
//!   instance around $6/mo with similar bandwidth-overage pricing.
//! - **Generic conservative** ([`HostingProfile::GENERIC_VPS`]): a deliberately padded baseline
//!   (higher base cost, higher bandwidth, higher reachability premium) for an operator who wants
//!   a safety margin over either named provider without picking one.
//!
//! Every profile also carries a `reachability_premium_usd_cents_per_month`: the extra monthly
//! cost of a **reputable, port-25-unblocked / publicly-reachable-ingress IP** — CONTRACT §2.3's
//! one disclosed scarce-reachability exception class (the `gateway` and `reachability-adapter`
//! kinds), priced as a real line item rather than left implicit. An operator MUST replace these
//! numbers with their actual invoice before relying on them for real billing.
//!
//! ## Why prices are per-batch, not per-byte/per-message
//!
//! [`crate::meter::ResourceKind`]'s own docs are explicit that "what counts as a unit... is
//! entirely [`crate::tariff::TariffSchedule`] (operator policy) — this module only counts." Real
//! bandwidth/message costs (fractions of a cent per byte or per message) cannot be represented as
//! a non-zero integer price in whole cents at that granularity. So the recommended schedules
//! here price in **batches**:
//! - [`ResourceKind::BytesForwarded`] — priced **per GiB** ([`BYTES_FORWARDED_BATCH_BYTES`]).
//! - [`ResourceKind::Messages`] — priced **per 1,000 messages** ([`MESSAGES_BATCH`]).
//! - [`ResourceKind::ComputeSeconds`] — priced **per 1,000 compute-seconds**
//!   ([`COMPUTE_SECONDS_BATCH`]).
//!
//! An operator adopting a recommended schedule as-is MUST record usage in matching batch units
//! (round usage up into the batch before calling [`crate::meter::Meter::record`]) — the
//! [`gib_billing_units`]/[`messages_billing_units`]/[`compute_seconds_billing_units`] helpers do
//! that rounding. This is the same convention real bandwidth/API billing already uses ("$X per
//! GB", "$X per 1K requests"); it is not a departure from how [`TariffSchedule`] works, just a
//! documented choice of what "one unit" means for these particular recommended schedules.
//!
//! ## The cost-plus formula
//!
//! For a bandwidth-priced kind:
//! ```text
//! fixed_monthly     = base_vps + (reachability_premium if the kind is in the scarce class)
//! amortized_per_gib = ceil(fixed_monthly / ASSUMED_MONTHLY_GIB)
//! cost_per_gib      = bandwidth_per_gib + amortized_per_gib
//! recommended       = ceil(cost_per_gib * RECOMMENDED_MARKUP_X100 / 100)
//! ```
//! `gateway` (per-1000-messages) and `compute` (per-1000-compute-seconds) follow the same shape,
//! substituting the relevant assumed monthly batch count. All arithmetic is integer (`u64`,
//! saturating), rounding fixed-cost amortization UP (never under-recovering fixed costs) — no
//! floats anywhere, matching kotva-core's wire-level no-float rule (tariff.rs module doc).

use std::collections::BTreeMap;

use crate::meter::ResourceKind;
use crate::tariff::TariffSchedule;

/// The recommended display/pricing currency for every schedule this module produces: plain
/// "USD" at its ordinary ISO 4217 minor unit (cents) — CONTRACT §6/DIRECTION §5's settlement
/// currency remains entirely a rail concern ([`crate::settlement::SettlementRail`]); this is only
/// the *pricing* currency shown to an operator/payer (task: "USD recommended pricing... USD is
/// the pricing/display currency; settlement is stablecoin or fiat via the rail").
pub const RECOMMENDED_CURRENCY: &str = "USD";

/// Cost-plus markup applied on top of raw infra cost, as an integer percent-times-100
/// (`200` = 2.00x = a 100% margin over cost). Deliberately a **recommendation**, not a mandate —
/// see the module doc.
pub const RECOMMENDED_MARKUP_X100: u64 = 200;

/// Assumed baseline monthly bandwidth volume (GiB) used only to amortize a bandwidth-priced
/// kind's fixed VPS cost into a per-GiB recommendation. A documented assumption, not a forecast —
/// an operator's real traffic will differ; this exists so the fixed VPS cost isn't simply ignored
/// by the formula.
pub const ASSUMED_MONTHLY_GIB: u64 = 500;

/// Assumed baseline monthly message volume the `gateway` kind's fixed cost is amortized over.
pub const ASSUMED_MONTHLY_MESSAGES: u64 = 200_000;

/// Assumed baseline monthly compute-second volume the `compute` kind's fixed cost is amortized
/// over.
pub const ASSUMED_MONTHLY_COMPUTE_SECONDS: u64 = 500_000;

/// One [`ResourceKind::BytesForwarded`] billed unit, in raw bytes: 1 GiB. See the module doc's
/// "why prices are per-batch" section.
pub const BYTES_FORWARDED_BATCH_BYTES: u64 = 1024 * 1024 * 1024;

/// One [`ResourceKind::Messages`] billed unit: 1,000 messages.
pub const MESSAGES_BATCH: u64 = 1_000;

/// One [`ResourceKind::ComputeSeconds`] billed unit: 1,000 compute-seconds.
pub const COMPUTE_SECONDS_BATCH: u64 = 1_000;

/// Round `raw_bytes` up into whole [`BYTES_FORWARDED_BATCH_BYTES`] (GiB) billing units — the
/// conversion an operator applies before [`crate::meter::Meter::record`]ing
/// [`ResourceKind::BytesForwarded`] usage against a recommended schedule.
pub fn gib_billing_units(raw_bytes: u64) -> u64 {
    ceil_div(raw_bytes, BYTES_FORWARDED_BATCH_BYTES)
}

/// Round `raw_messages` up into whole [`MESSAGES_BATCH`] billing units.
pub fn messages_billing_units(raw_messages: u64) -> u64 {
    ceil_div(raw_messages, MESSAGES_BATCH)
}

/// Round `raw_compute_seconds` up into whole [`COMPUTE_SECONDS_BATCH`] billing units.
pub fn compute_seconds_billing_units(raw_compute_seconds: u64) -> u64 {
    ceil_div(raw_compute_seconds, COMPUTE_SECONDS_BATCH)
}

fn ceil_div(a: u64, b: u64) -> u64 {
    if b == 0 {
        return 0;
    }
    a.saturating_add(b - 1) / b
}

/// An operator's real per-unit infra costs for the VPS a coordinator kind runs on — the input to
/// [`recommended_tariff`]. See the module doc for the illustrative constants below and their
/// sourcing caveat.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostingProfile {
    /// A short, human-readable label for this profile (never parsed, informational only).
    pub name: &'static str,
    /// Baseline monthly VPS cost, in whole USD cents, excluding bandwidth overage and any
    /// reachability premium.
    pub base_vps_usd_cents_per_month: u64,
    /// Marginal bandwidth cost, in whole USD cents per GiB, above whatever allowance is included
    /// in the base VPS cost.
    pub bandwidth_usd_cents_per_gib: u64,
    /// Extra monthly USD cents for a reputable, port-25-unblocked / publicly-reachable-ingress
    /// IP — CONTRACT §2.3's scarce-reachability exception class, priced. Applied only to kinds
    /// that actually need it ([`CoordinatorPricingKind::Gateway`],
    /// [`CoordinatorPricingKind::ReachabilityAdapter`]).
    pub reachability_premium_usd_cents_per_month: u64,
}

impl HostingProfile {
    /// Illustrative Hetzner-Cloud-like small VPS: ~$5/mo base, cheap (~$0.01/GB) bandwidth
    /// overage, a modest reachability premium. See the module doc's sourcing caveat.
    pub const HETZNER_CX: HostingProfile = HostingProfile {
        name: "hetzner-cx-illustrative",
        base_vps_usd_cents_per_month: 500,
        bandwidth_usd_cents_per_gib: 1,
        reachability_premium_usd_cents_per_month: 500,
    };

    /// Illustrative Vultr-Cloud-Compute-like small VPS: ~$6/mo base, similarly cheap bandwidth
    /// overage. See the module doc's sourcing caveat.
    pub const VULTR_GENERIC: HostingProfile = HostingProfile {
        name: "vultr-generic-illustrative",
        base_vps_usd_cents_per_month: 600,
        bandwidth_usd_cents_per_gib: 1,
        reachability_premium_usd_cents_per_month: 500,
    };

    /// A deliberately padded, provider-agnostic baseline for an operator who wants a safety
    /// margin over either named provider without picking one.
    pub const GENERIC_VPS: HostingProfile = HostingProfile {
        name: "generic-vps-conservative",
        base_vps_usd_cents_per_month: 1_000,
        bandwidth_usd_cents_per_gib: 2,
        reachability_premium_usd_cents_per_month: 1_000,
    };
}

/// Which coordinator kind a [`recommended_tariff`] is being computed for — deliberately a small,
/// closed set mirroring the kinds CONTRACT §6 calls out by pricing shape (bandwidth vs.
/// per-message vs. per-compute-second), not a copy of every Wakala coordinator kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoordinatorPricingKind {
    /// Mesh Circuit-Relay-style forwarding — bandwidth-priced, not in the scarce-reachability
    /// class.
    Relay,
    /// SFU/media forwarding — bandwidth-priced, not in the scarce-reachability class.
    MediaRelay,
    /// SNI-passthrough ingress — bandwidth-priced, AND in the scarce-reachability class (a
    /// publicly reachable ingress is the resource CONTRACT §2.3 discloses as not
    /// always self-provisionable).
    ReachabilityAdapter,
    /// Legacy mail adapter — per-message-priced, AND in the scarce-reachability class (a
    /// reputable, port-25-unblocked IP, CONTRACT §2.3).
    Gateway,
    /// Hosted compute/inference — per-compute-second-priced, not in the scarce-reachability
    /// class.
    Compute,
}

/// Compute a **recommended** cost-plus [`TariffSchedule`] for `kind` given `profile`'s real infra
/// costs. See the module doc for the formula, the batching convention, and the loud disclaimer
/// that this is a starting point, never a mandate — CONTRACT §6 keeps the actual numbers
/// operator policy; the caller still calls [`TariffSchedule::sign`] themselves.
pub fn recommended_tariff(kind: CoordinatorPricingKind, profile: &HostingProfile) -> TariffSchedule {
    match kind {
        CoordinatorPricingKind::Relay | CoordinatorPricingKind::MediaRelay => {
            bandwidth_schedule(profile, false)
        }
        CoordinatorPricingKind::ReachabilityAdapter => bandwidth_schedule(profile, true),
        CoordinatorPricingKind::Gateway => gateway_schedule(profile),
        CoordinatorPricingKind::Compute => compute_schedule(profile),
    }
}

const NOMINAL_PERIOD_SECONDS: u64 = 30 * 24 * 3600;

fn bandwidth_schedule(profile: &HostingProfile, include_reachability_premium: bool) -> TariffSchedule {
    let fixed = profile.base_vps_usd_cents_per_month.saturating_add(if include_reachability_premium {
        profile.reachability_premium_usd_cents_per_month
    } else {
        0
    });
    let amortized_per_gib = ceil_div(fixed, ASSUMED_MONTHLY_GIB);
    let cost_per_gib = profile.bandwidth_usd_cents_per_gib.saturating_add(amortized_per_gib);
    let recommended_per_gib = markup(cost_per_gib);

    let mut prices = BTreeMap::new();
    prices.insert(ResourceKind::BytesForwarded, recommended_per_gib.max(1));
    TariffSchedule {
        currency: RECOMMENDED_CURRENCY.to_string(),
        prices,
        free_allowance: BTreeMap::new(),
        period_seconds: Some(NOMINAL_PERIOD_SECONDS),
    }
}

fn gateway_schedule(profile: &HostingProfile) -> TariffSchedule {
    // The gateway is always in the scarce-reachability class (CONTRACT §2.3) — its reachability
    // premium is unconditionally amortized in, unlike the bandwidth-priced kinds above.
    let fixed = profile
        .base_vps_usd_cents_per_month
        .saturating_add(profile.reachability_premium_usd_cents_per_month);
    let amortized_per_1k_messages = ceil_div(fixed, ASSUMED_MONTHLY_MESSAGES / MESSAGES_BATCH);
    let recommended_per_1k = markup(amortized_per_1k_messages);

    let mut prices = BTreeMap::new();
    prices.insert(ResourceKind::Messages, recommended_per_1k.max(1));
    TariffSchedule {
        currency: RECOMMENDED_CURRENCY.to_string(),
        prices,
        free_allowance: BTreeMap::new(),
        period_seconds: Some(NOMINAL_PERIOD_SECONDS),
    }
}

fn compute_schedule(profile: &HostingProfile) -> TariffSchedule {
    let fixed = profile.base_vps_usd_cents_per_month;
    let amortized_per_1k_seconds = ceil_div(fixed, ASSUMED_MONTHLY_COMPUTE_SECONDS / COMPUTE_SECONDS_BATCH);
    let recommended_per_1k = markup(amortized_per_1k_seconds);

    let mut prices = BTreeMap::new();
    prices.insert(ResourceKind::ComputeSeconds, recommended_per_1k.max(1));
    TariffSchedule {
        currency: RECOMMENDED_CURRENCY.to_string(),
        prices,
        free_allowance: BTreeMap::new(),
        period_seconds: Some(NOMINAL_PERIOD_SECONDS),
    }
}

fn markup(cost: u64) -> u64 {
    ceil_div(cost.saturating_mul(RECOMMENDED_MARKUP_X100), 100)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batching_helpers_round_up() {
        assert_eq!(gib_billing_units(0), 0);
        assert_eq!(gib_billing_units(1), 1);
        assert_eq!(gib_billing_units(BYTES_FORWARDED_BATCH_BYTES), 1);
        assert_eq!(gib_billing_units(BYTES_FORWARDED_BATCH_BYTES + 1), 2);
        assert_eq!(messages_billing_units(1_500), 2);
        assert_eq!(compute_seconds_billing_units(1_000), 1);
        assert_eq!(compute_seconds_billing_units(1_001), 2);
    }

    #[test]
    fn every_kind_and_profile_produces_a_nonzero_priced_schedule() {
        let kinds = [
            CoordinatorPricingKind::Relay,
            CoordinatorPricingKind::MediaRelay,
            CoordinatorPricingKind::ReachabilityAdapter,
            CoordinatorPricingKind::Gateway,
            CoordinatorPricingKind::Compute,
        ];
        let profiles = [
            HostingProfile::HETZNER_CX,
            HostingProfile::VULTR_GENERIC,
            HostingProfile::GENERIC_VPS,
        ];
        for kind in kinds {
            for profile in profiles {
                let schedule = recommended_tariff(kind, &profile);
                assert_eq!(schedule.currency, "USD");
                assert_eq!(schedule.prices.len(), 1, "one priced resource kind per profile");
                let (_, &price) = schedule.prices.iter().next().unwrap();
                assert!(price > 0, "{:?}/{} priced at zero", kind, profile.name);
            }
        }
    }

    #[test]
    fn reachability_adapter_costs_more_than_relay_for_the_same_profile() {
        // Same bandwidth-priced shape, but the reachability-adapter carries the scarce-class
        // premium the plain relay does not (CONTRACT §2.3).
        for profile in [HostingProfile::HETZNER_CX, HostingProfile::VULTR_GENERIC, HostingProfile::GENERIC_VPS] {
            let relay = recommended_tariff(CoordinatorPricingKind::Relay, &profile);
            let reach = recommended_tariff(CoordinatorPricingKind::ReachabilityAdapter, &profile);
            let relay_price = relay.prices[&ResourceKind::BytesForwarded];
            let reach_price = reach.prices[&ResourceKind::BytesForwarded];
            assert!(
                reach_price > relay_price,
                "{}: reachability-adapter ({reach_price}) should cost more per GiB than relay ({relay_price})",
                profile.name
            );
        }
    }

    #[test]
    fn recommended_schedule_signs_and_evaluates_like_any_other_schedule() {
        // Proves this module's output is an ordinary TariffSchedule — no special-casing
        // downstream: it signs (real IdentityKey) and evaluates real metered usage exactly like
        // a hand-authored schedule (tariff.rs tests).
        let key = broker_economics::IdentityKey::from_seed(&[0x33; 32]);
        let schedule = recommended_tariff(CoordinatorPricingKind::Relay, &HostingProfile::HETZNER_CX);
        let tariff = schedule.sign(&key);
        assert!(tariff.verify().is_ok());

        let mut usage = BTreeMap::new();
        usage.insert(ResourceKind::BytesForwarded, gib_billing_units(3 * BYTES_FORWARDED_BATCH_BYTES));
        let bill = schedule.evaluate(&usage).unwrap();
        assert_eq!(bill.amount, 3 * schedule.prices[&ResourceKind::BytesForwarded]);
    }

    #[test]
    fn gateway_schedule_prices_messages_not_bytes() {
        let schedule = recommended_tariff(CoordinatorPricingKind::Gateway, &HostingProfile::HETZNER_CX);
        assert!(schedule.prices.contains_key(&ResourceKind::Messages));
        assert!(!schedule.prices.contains_key(&ResourceKind::BytesForwarded));
    }
}
