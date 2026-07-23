//! Monthly postpaid — an OPTIONAL, operator-offered policy, secondary to [`crate::prepaid`]
//! (founder decision, see `DECISIONS.md`: prepaid is the primary model). A [`Subscription`] is
//! deliberately thin: a fixed monthly amount charged through the exact same
//! [`crate::settlement::SettlementRail`] seam every other charge in this crate rides — there is
//! no second money path, no separate invoicing engine, and this type carries no billing logic
//! beyond "charge this fixed amount." An operator who wants proration, multiple tiers, or
//! usage-capped plans layers that on top; it is out of scope here on purpose, exactly as §6 keeps
//! "the numbers" operator policy.
//!
//! Why this stays optional/secondary: a monthly card-on-file relationship binds a real-world
//! billing identity to the payer in a way prepaid credit does not (CONTRACT §4/SEC-7's
//! anonymous-but-accountable anti-abuse list explicitly favors postage-style credit), and a
//! standing subscription is a small but real form of lock-in a payer has to actively cancel
//! (CONTRACT §2.2) — prepaid credit simply runs out. An operator MAY still offer this (e.g. for
//! payers who prefer predictable monthly invoicing over topping up), which is exactly why the
//! seam exists rather than being refused outright.

use crate::settlement::{SettlementReceipt, SettlementRail};

/// A fixed monthly postpaid charge for one payer. Construct with [`Subscription::new`]; charge a
/// period with [`Subscription::charge`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subscription {
    pub payer: Vec<u8>,
    /// The fixed amount charged per period, in `currency`'s minor unit.
    pub monthly_amount: u64,
    pub currency: String,
    /// Whether this subscription is currently active — a simple on/off flag; this crate does not
    /// model trial periods, proration, or cancellation timing.
    pub active: bool,
}

impl Subscription {
    /// A new, active subscription for `payer` at `monthly_amount`/`currency` per period.
    pub fn new(payer: impl Into<Vec<u8>>, monthly_amount: u64, currency: impl Into<String>) -> Self {
        Subscription { payer: payer.into(), monthly_amount, currency: currency.into(), active: true }
    }

    /// Charge one period's `monthly_amount` through `rail` — thin sugar over
    /// [`SettlementRail::charge`]; this type adds no logic beyond passing the fixed amount
    /// through. Returns the rail's own error type on failure (e.g. a declined card, an
    /// insufficient-balance mock ledger) — this function does not interpret or retry it.
    ///
    /// Charging an inactive subscription is still permitted (this type does not gate on
    /// `active`) — a caller that wants to skip inactive subscriptions checks `self.active` before
    /// calling, keeping the policy decision at the call site rather than hidden in here.
    pub fn charge<R: SettlementRail>(&self, rail: &R) -> Result<SettlementReceipt, R::Error> {
        rail.charge(&self.payer, self.monthly_amount, &self.currency)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settlement::InMemoryLedger;

    #[test]
    fn charge_rides_the_settlement_rail() {
        let ledger = InMemoryLedger::new();
        ledger.deposit(b"payer", 5_000, "USD");
        let sub = Subscription::new(b"payer".to_vec(), 999, "USD");
        let receipt = sub.charge(&ledger).unwrap();
        assert_eq!(receipt.amount, 999);
        assert_eq!(ledger.balance(b"payer", "USD").unwrap(), 5_000 - 999);
    }

    #[test]
    fn charge_fails_closed_without_funds_on_the_rail() {
        let ledger = InMemoryLedger::new();
        let sub = Subscription::new(b"payer".to_vec(), 999, "USD");
        assert!(sub.charge(&ledger).is_err());
    }

    #[test]
    fn new_subscription_defaults_active() {
        let sub = Subscription::new(b"payer".to_vec(), 100, "USD");
        assert!(sub.active);
    }
}
