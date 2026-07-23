//! Simulated billing events — a deterministic event stream driving the real prepaid pipeline
//! ([`crate::meter`] → [`crate::tariff`] → [`crate::prepaid`] → [`crate::receipt`], with
//! [`crate::subscription`] riding a [`crate::settlement::SettlementRail`] for the optional
//! postpaid path), so a full billing lifecycle can be replayed and asserted on in tests without
//! any network or wall-clock dependency.
//!
//! [`BillingEvent`] is the input stream; [`SimEngine::replay`] processes each event through the
//! **real** crate types (no test-only stand-ins: the same [`crate::meter::Meter`],
//! [`crate::tariff::TariffSchedule`], [`crate::prepaid::PrepaidLedger`],
//! [`crate::receipt::ReceiptLog`], and a caller-supplied real
//! [`crate::settlement::SettlementRail`]) and returns one [`BillingOutcome`] per event **plus**
//! any derived [`BillingOutcome::LowBalance`]/[`BillingOutcome::Exhausted`] notifications the
//! engine raises after a debit — so the output trace covers exactly the six event kinds this
//! module is scoped to (`TopUp`, `MeteredUsage`, `TariffChange`, `LowBalance`, `Refund`,
//! `MonthlyCharge`): the first five plus `MonthlyCharge` are things the caller feeds in;
//! `LowBalance` is what the engine reports back once a debit crosses the ledger's threshold.

use broker_economics::IdentityKey;

use crate::meter::{InMemoryMeter, Meter, ResourceKind};
use crate::prepaid::{BillingState, DebitRecord, PrepaidError, PrepaidLedger, RefundRecord, TopUpRecord};
use crate::receipt::ReceiptLog;
use crate::settlement::{SettlementReceipt, SettlementRail};
use crate::tariff::TariffSchedule;
use broker_economics::UsageReceipt;

/// One simulated billing event, fed into [`SimEngine::replay`] in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BillingEvent {
    /// A prepaid top-up lands (see [`crate::prepaid::PrepaidLedger::top_up`]).
    TopUp { payer: Vec<u8>, amount: u64, funding_ref: String },
    /// `units` of `kind` were metered for `payer` since their last billed usage. The engine
    /// immediately evaluates and debits this event's usage against the engine's current tariff
    /// (see the module doc) — each `MeteredUsage` event is its own billed increment, deterministic
    /// and order-sensitive.
    MeteredUsage { payer: Vec<u8>, kind: ResourceKind, units: u64 },
    /// The operator republishes a new tariff — every subsequent `MeteredUsage` event evaluates
    /// against `schedule` instead of whatever was active before.
    TariffChange { schedule: TariffSchedule },
    /// The operator refunds part of a payer's remaining prepaid balance (see
    /// [`crate::prepaid::PrepaidLedger::refund`]).
    Refund { payer: Vec<u8>, amount: u64 },
    /// An optional postpaid monthly charge rides the engine's [`crate::settlement::SettlementRail`]
    /// directly (see [`crate::subscription::Subscription`]) — independent of the prepaid ledger.
    MonthlyCharge { payer: Vec<u8>, amount: u64, currency: String },
}

/// One outcome of processing a [`BillingEvent`] (or a derived notification the engine raises on
/// its own after a debit) — the full record [`SimEngine::replay`] returns.
///
/// Not `PartialEq`: [`broker_economics::UsageReceipt`] (carried by [`BillingOutcome::Debited`])
/// does not implement it — tests match on `matches!`/field access instead.
#[derive(Clone, Debug)]
pub enum BillingOutcome {
    ToppedUp(TopUpRecord),
    /// A `MeteredUsage` event was evaluated and successfully debited, with the receipts issued
    /// for it.
    Debited { record: DebitRecord, receipts: Vec<UsageReceipt> },
    /// A `MeteredUsage` event was metered but could NOT be debited (insufficient prepaid credit)
    /// — fail-closed: no receipt is issued for unpaid usage (see
    /// [`crate::prepaid::PrepaidLedger::debit_and_receipt`]).
    DebitFailed { payer: Vec<u8>, error: PrepaidError },
    TariffChanged,
    Refunded(RefundRecord),
    /// Derived: raised immediately after a debit/refund left `payer` at
    /// [`BillingState::LowBalance`].
    LowBalance { payer: Vec<u8>, balance: u64 },
    /// Derived: raised immediately after a debit/refund left `payer` at
    /// [`BillingState::Exhausted`].
    Exhausted { payer: Vec<u8> },
    MonthlyCharged(SettlementReceipt),
    /// A `MonthlyCharge` event's settlement-rail charge failed (e.g. no funds on the rail) — the
    /// error is rail-specific, so this variant carries its `Debug` rendering rather than the
    /// generic type (kept engine-generic over `R::Error`, which is not necessarily `Clone`).
    MonthlyChargeFailed { payer: Vec<u8>, error: String },
}

/// Drives [`crate::prepaid::PrepaidLedger`], a [`crate::meter::Meter`], a
/// [`crate::tariff::TariffSchedule`], a [`crate::receipt::ReceiptLog`], and a caller-supplied
/// [`crate::settlement::SettlementRail`] through a [`BillingEvent`] stream deterministically. See
/// the module doc.
pub struct SimEngine<'a, R: SettlementRail> {
    meter: InMemoryMeter,
    ledger: PrepaidLedger,
    schedule: TariffSchedule,
    log: ReceiptLog,
    ik: IdentityKey,
    rail: &'a R,
}

impl<'a, R: SettlementRail> SimEngine<'a, R>
where
    R::Error: std::fmt::Debug,
{
    /// A fresh engine: `ledger` and `schedule` MUST share the same currency (an evaluated bill in
    /// a different currency than `ledger` tracks is refused per-event, surfaced as
    /// [`BillingOutcome::DebitFailed`], never silently converted). `rail` backs any
    /// `MonthlyCharge` events; `ik` signs every issued [`broker_economics::UsageReceipt`].
    pub fn new(ledger: PrepaidLedger, schedule: TariffSchedule, ik: IdentityKey, rail: &'a R) -> Self {
        SimEngine { meter: InMemoryMeter::new(), ledger, schedule, log: ReceiptLog::new(), ik, rail }
    }

    /// The underlying [`crate::prepaid::PrepaidLedger`] — for asserting on balances after a
    /// replay.
    pub fn ledger(&self) -> &PrepaidLedger {
        &self.ledger
    }

    /// The underlying [`crate::receipt::ReceiptLog`] — for verifying every issued receipt after a
    /// replay (see [`crate::receipt::ReceiptLog::verify_all`]).
    pub fn receipt_log(&self) -> &ReceiptLog {
        &self.log
    }

    /// The tariff currently in effect (after any `TariffChange` events processed so far).
    pub fn current_schedule(&self) -> &TariffSchedule {
        &self.schedule
    }

    /// Process `events` in order, returning one (or more, for a debit's derived low-balance/
    /// exhausted notifications) [`BillingOutcome`] per event, in the same order.
    pub fn replay(&mut self, events: &[BillingEvent]) -> Vec<BillingOutcome> {
        let mut out = Vec::new();
        for event in events {
            self.apply(event, &mut out);
        }
        out
    }

    fn apply(&mut self, event: &BillingEvent, out: &mut Vec<BillingOutcome>) {
        match event {
            BillingEvent::TopUp { payer, amount, funding_ref } => {
                let record = self.ledger.top_up(payer, *amount, funding_ref.clone());
                out.push(BillingOutcome::ToppedUp(record));
            }
            BillingEvent::MeteredUsage { payer, kind, units } => {
                self.meter.record(payer, *kind, *units);
                let usage = self.meter.reset(payer);
                match self.schedule.evaluate(&usage) {
                    Ok(bill) => match self.ledger.debit_and_receipt(payer, &bill, &mut self.log, &self.ik) {
                        Ok((record, receipts)) => {
                            out.push(BillingOutcome::Debited { record, receipts });
                            self.push_state_notification(payer, out);
                        }
                        Err(error) => out.push(BillingOutcome::DebitFailed { payer: payer.clone(), error }),
                    },
                    Err(_) => out.push(BillingOutcome::DebitFailed {
                        payer: payer.clone(),
                        error: PrepaidError::CurrencyMismatch {
                            bill_currency: "unpriced-kind".to_string(),
                            ledger_currency: self.ledger.currency().to_string(),
                        },
                    }),
                }
            }
            BillingEvent::TariffChange { schedule } => {
                self.schedule = schedule.clone();
                out.push(BillingOutcome::TariffChanged);
            }
            BillingEvent::Refund { payer, amount } => match self.ledger.refund(payer, *amount) {
                Ok(record) => {
                    out.push(BillingOutcome::Refunded(record));
                    self.push_state_notification(payer, out);
                }
                Err(error) => out.push(BillingOutcome::DebitFailed { payer: payer.clone(), error }),
            },
            BillingEvent::MonthlyCharge { payer, amount, currency } => {
                match self.rail.charge(payer, *amount, currency) {
                    Ok(receipt) => out.push(BillingOutcome::MonthlyCharged(receipt)),
                    Err(e) => out.push(BillingOutcome::MonthlyChargeFailed {
                        payer: payer.clone(),
                        error: format!("{e:?}"),
                    }),
                }
            }
        }
    }

    fn push_state_notification(&self, payer: &[u8], out: &mut Vec<BillingOutcome>) {
        match self.ledger.state(payer) {
            BillingState::LowBalance => {
                out.push(BillingOutcome::LowBalance { payer: payer.to_vec(), balance: self.ledger.balance(payer) })
            }
            BillingState::Exhausted => out.push(BillingOutcome::Exhausted { payer: payer.to_vec() }),
            BillingState::Ok => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settlement::InMemoryLedger;
    use std::collections::BTreeMap;

    fn schedule(price: u64) -> TariffSchedule {
        let mut prices = BTreeMap::new();
        prices.insert(ResourceKind::BytesForwarded, price);
        TariffSchedule { currency: "USD".to_string(), prices, free_allowance: BTreeMap::new(), period_seconds: None }
    }

    #[test]
    fn full_lifecycle_replays_deterministically() {
        let rail = InMemoryLedger::new();
        let ledger = PrepaidLedger::new("USD", 50);
        let ik = IdentityKey::from_seed(&[0x55; 32]);
        let mut engine = SimEngine::new(ledger, schedule(1), ik, &rail);

        let events = vec![
            BillingEvent::TopUp { payer: b"payer".to_vec(), amount: 1_000, funding_ref: "f1".into() },
            BillingEvent::MeteredUsage { payer: b"payer".to_vec(), kind: ResourceKind::BytesForwarded, units: 500 },
            BillingEvent::MeteredUsage { payer: b"payer".to_vec(), kind: ResourceKind::BytesForwarded, units: 450 },
            BillingEvent::Refund { payer: b"payer".to_vec(), amount: 20 },
        ];
        let outcomes = engine.replay(&events);

        assert!(matches!(outcomes[0], BillingOutcome::ToppedUp(_)));
        assert!(matches!(outcomes[1], BillingOutcome::Debited { .. })); // balance 1000 -> 500
        // Second debit of 450 brings balance to 50, at the threshold -> LowBalance follows.
        assert!(matches!(outcomes[2], BillingOutcome::Debited { .. }));
        assert!(matches!(outcomes[3], BillingOutcome::LowBalance { .. }));
        assert!(matches!(outcomes[4], BillingOutcome::Refunded(_)));

        assert_eq!(engine.ledger().balance(b"payer"), 30); // 1000 - 500 - 450 - 20
    }

    #[test]
    fn tariff_change_affects_subsequent_usage_only() {
        let rail = InMemoryLedger::new();
        let ledger = PrepaidLedger::new("USD", 0);
        let ik = IdentityKey::from_seed(&[0x56; 32]);
        let mut engine = SimEngine::new(ledger, schedule(1), ik, &rail);

        engine.replay(&[BillingEvent::TopUp { payer: b"payer".to_vec(), amount: 1_000, funding_ref: "f1".into() }]);
        engine.replay(&[BillingEvent::MeteredUsage {
            payer: b"payer".to_vec(),
            kind: ResourceKind::BytesForwarded,
            units: 100,
        }]);
        assert_eq!(engine.ledger().balance(b"payer"), 900); // 1 usd/unit * 100

        engine.replay(&[BillingEvent::TariffChange { schedule: schedule(5) }]);
        engine.replay(&[BillingEvent::MeteredUsage {
            payer: b"payer".to_vec(),
            kind: ResourceKind::BytesForwarded,
            units: 100,
        }]);
        assert_eq!(engine.ledger().balance(b"payer"), 400); // 900 - (5 usd/unit * 100)
    }

    #[test]
    fn exhausted_payer_gets_debit_failed_and_no_receipt() {
        let rail = InMemoryLedger::new();
        let ledger = PrepaidLedger::new("USD", 0);
        let ik = IdentityKey::from_seed(&[0x57; 32]);
        let mut engine = SimEngine::new(ledger, schedule(1), ik, &rail);

        let outcomes = engine.replay(&[BillingEvent::MeteredUsage {
            payer: b"payer".to_vec(),
            kind: ResourceKind::BytesForwarded,
            units: 1,
        }]);
        assert!(matches!(outcomes[0], BillingOutcome::DebitFailed { .. }));
        assert!(engine.receipt_log().receipts().is_empty());
    }

    #[test]
    fn monthly_charge_rides_the_settlement_rail_independent_of_prepaid_ledger() {
        let rail = InMemoryLedger::new();
        rail.deposit(b"payer", 10_000, "USD");
        let ledger = PrepaidLedger::new("USD", 0);
        let ik = IdentityKey::from_seed(&[0x58; 32]);
        let mut engine = SimEngine::new(ledger, schedule(1), ik, &rail);

        let outcomes = engine.replay(&[BillingEvent::MonthlyCharge {
            payer: b"payer".to_vec(),
            amount: 999,
            currency: "USD".to_string(),
        }]);
        assert!(matches!(outcomes[0], BillingOutcome::MonthlyCharged(_)));
        assert_eq!(rail.balance(b"payer", "USD").unwrap(), 10_000 - 999);
        // The prepaid ledger is untouched by a monthly (postpaid) charge.
        assert_eq!(engine.ledger().balance(b"payer"), 0);
    }

    #[test]
    fn monthly_charge_failure_is_reported_not_panicked() {
        let rail = InMemoryLedger::new(); // no deposit -> insufficient balance
        let ledger = PrepaidLedger::new("USD", 0);
        let ik = IdentityKey::from_seed(&[0x59; 32]);
        let mut engine = SimEngine::new(ledger, schedule(1), ik, &rail);

        let outcomes = engine.replay(&[BillingEvent::MonthlyCharge {
            payer: b"payer".to_vec(),
            amount: 999,
            currency: "USD".to_string(),
        }]);
        assert!(matches!(outcomes[0], BillingOutcome::MonthlyChargeFailed { .. }));
    }
}
