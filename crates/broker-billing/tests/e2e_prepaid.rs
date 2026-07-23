//! End-to-end test: the real prepaid pipeline, start to finish.
//!
//! top-up → meter usage → evaluate the (recommended-or-custom) tariff → debit prepaid → issue a
//! signed receipt → verify the receipt → settle an optional monthly charge via a MOCK
//! `SettlementRail` — using ONLY the crate's real, public types (no test-only stand-ins for
//! meter/tariff/prepaid/receipt/settlement). Also demonstrates, end-to-end, the documented
//! CONTRACT §6 R-6 one-directional-audit residual: a fabricated operation's receipt verifies
//! exactly like a real one's.

use std::collections::BTreeMap;

use broker_economics::IdentityKey;

use broker_billing::pricing::{recommended_tariff, CoordinatorPricingKind, HostingProfile};
use broker_billing::receipt::{BilledOperation, ReceiptLog};
use broker_billing::sim::{BillingEvent, BillingOutcome, SimEngine};
use broker_billing::{InMemoryLedger, PrepaidLedger, ResourceKind, SettlementRail, Subscription};

/// The full happy-path lifecycle, driven through [`SimEngine`] against a **recommended** (not
/// hand-authored) USD tariff: sign the recommended schedule as a real
/// `broker_economics::Tariff`, verify it, decode it back, then run it through top-up → metered
/// usage → tariff evaluation → prepaid debit → signed receipt issuance → receipt verification →
/// an optional monthly settlement charge on a mock rail.
#[test]
fn e2e_full_prepaid_lifecycle_through_a_recommended_tariff() {
    // 1. USD recommended pricing: a cost-plus starting point for a bandwidth-priced kind.
    let schedule = recommended_tariff(CoordinatorPricingKind::Relay, &HostingProfile::HETZNER_CX);
    assert_eq!(schedule.currency, "USD");
    let price_per_gib = *schedule.prices.get(&ResourceKind::BytesForwarded).unwrap();
    assert!(price_per_gib > 0, "a recommended tariff must never silently price at zero");

    // The operator signs the recommended schedule with their real coordinator identity — proves
    // it rides the same signed-Tariff mechanism as any hand-authored schedule (CONTRACT §6: the
    // mechanism is normative, the numbers are policy).
    let operator_key = IdentityKey::from_seed(&[0xA0; 32]);
    let signed_tariff = schedule.sign(&operator_key);
    assert!(signed_tariff.verify().is_ok());
    let schedule = broker_billing::TariffSchedule::from_tariff(&signed_tariff).unwrap();

    // 2. The prepaid rail: a payer tops up, custody-free (Wakala holds no funds — see
    // `prepaid`'s module doc); a mock settlement rail stands in for a real on-chain/patala rail
    // only for the OPTIONAL monthly-postpaid leg exercised at the end of this test.
    let mock_rail = InMemoryLedger::new();
    let ledger = PrepaidLedger::new("USD", price_per_gib * 2); // low-balance at < 2 GiB left
    let ik = IdentityKey::from_seed(&[0xA1; 32]);
    let payer = b"relay-payer-1".to_vec();

    let mut engine = SimEngine::new(ledger, schedule.clone(), ik, &mock_rail);

    // 3. Simulated billing events driving the real pipeline deterministically.
    let events = vec![
        BillingEvent::TopUp { payer: payer.clone(), amount: price_per_gib * 10, funding_ref: "patala-topup-ref-1".into() },
        BillingEvent::MeteredUsage {
            payer: payer.clone(),
            kind: ResourceKind::BytesForwarded,
            units: 3, // 3 GiB metered (already batched — see pricing module doc)
        },
    ];
    let outcomes = engine.replay(&events);

    // top-up, then a successful debit with receipts issued.
    assert!(matches!(outcomes[0], BillingOutcome::ToppedUp(ref r) if r.amount == price_per_gib * 10));
    let (debit_amount, receipts) = match &outcomes[1] {
        BillingOutcome::Debited { record, receipts } => (record.amount, receipts.clone()),
        other => panic!("expected a successful debit, got {other:?}"),
    };
    assert_eq!(debit_amount, price_per_gib * 3);
    assert_eq!(receipts.len(), 1);

    // 4. Verify every receipt the payer was handed — a real, payer-side check against the real
    // signed UsageReceipt/IdentityKey machinery.
    assert!(engine.receipt_log().verify_all().is_ok());
    for r in &receipts {
        assert!(r.verify().is_ok());
        let decoded = BilledOperation::from_receipt(r).unwrap();
        assert_eq!(decoded.payer, payer);
        assert_eq!(decoded.amount, price_per_gib * 3);
        assert_eq!(decoded.currency, "USD");
    }

    // 5. Balance conservation: top-up minus debit equals the current balance.
    let expected_balance = price_per_gib * 10 - price_per_gib * 3;
    assert_eq!(engine.ledger().balance(&payer), expected_balance);

    // 6. The OPTIONAL monthly postpaid leg — an operator-offered `Subscription`, riding the exact
    // same `SettlementRail` (a *different* rail instance here, standing in for a real
    // card/fiat processor — never the prepaid ledger).
    let card_rail = InMemoryLedger::new();
    card_rail.deposit(&payer, 5_000, "USD");
    let subscription = Subscription::new(payer.clone(), 999, "USD");
    let settlement_receipt = subscription.charge(&card_rail).expect("mock rail has funds");
    assert_eq!(settlement_receipt.amount, 999);
    assert_eq!(card_rail.balance(&payer, "USD").unwrap(), 5_000 - 999);
    // Wholly independent of the prepaid ledger's own balance.
    assert_eq!(engine.ledger().balance(&payer), expected_balance);
}

/// Low-balance and exhausted transitions, driven end-to-end by the sim engine against a custom
/// (non-recommended) tariff, then a top-up recovering the account back to `Ok`.
#[test]
fn e2e_low_balance_and_exhausted_transitions() {
    let mut prices = BTreeMap::new();
    prices.insert(ResourceKind::Messages, 10u64);
    let schedule = broker_billing::TariffSchedule {
        currency: "USD".to_string(),
        prices,
        free_allowance: BTreeMap::new(),
        period_seconds: None,
    };

    let rail = InMemoryLedger::new();
    let ledger = PrepaidLedger::new("USD", 50);
    let ik = IdentityKey::from_seed(&[0xB0; 32]);
    let payer = b"gateway-payer-1".to_vec();
    let mut engine = SimEngine::new(ledger, schedule, ik, &rail);

    let outcomes = engine.replay(&[
        BillingEvent::TopUp { payer: payer.clone(), amount: 200, funding_ref: "ref-a".into() },
        BillingEvent::MeteredUsage { payer: payer.clone(), kind: ResourceKind::Messages, units: 14 }, // -140 -> insufficient? balance 200
    ]);
    // 14 messages * 10 = 140; balance 200 -> 60, still Ok (> 50 threshold).
    assert!(matches!(outcomes[1], BillingOutcome::Debited { .. }));
    assert_eq!(engine.ledger().balance(&payer), 60);

    let outcomes = engine.replay(&[BillingEvent::MeteredUsage {
        payer: payer.clone(),
        kind: ResourceKind::Messages,
        units: 1, // -10 -> balance 50, at threshold
    }]);
    assert!(matches!(outcomes[0], BillingOutcome::Debited { .. }));
    assert!(matches!(outcomes[1], BillingOutcome::LowBalance { .. }));
    assert_eq!(engine.ledger().balance(&payer), 50);

    // Attempting more usage than the remaining balance covers fails closed — no receipt issued,
    // balance untouched.
    let before_receipts = engine.receipt_log().receipts().len();
    let outcomes = engine.replay(&[BillingEvent::MeteredUsage {
        payer: payer.clone(),
        kind: ResourceKind::Messages,
        units: 6, // 60 needed, only 50 available
    }]);
    assert!(matches!(outcomes[0], BillingOutcome::DebitFailed { .. }));
    assert_eq!(engine.ledger().balance(&payer), 50, "a failed debit must not change the balance");
    assert_eq!(engine.receipt_log().receipts().len(), before_receipts);

    // Drain to exactly zero -> Exhausted.
    let outcomes = engine.replay(&[BillingEvent::MeteredUsage { payer: payer.clone(), kind: ResourceKind::Messages, units: 5 }]);
    assert!(matches!(outcomes[0], BillingOutcome::Debited { .. }));
    assert!(matches!(outcomes[1], BillingOutcome::Exhausted { .. }));
    assert_eq!(engine.ledger().balance(&payer), 0);

    // A top-up recovers the account.
    engine.replay(&[BillingEvent::TopUp { payer: payer.clone(), amount: 1_000, funding_ref: "ref-b".into() }]);
    assert_eq!(engine.ledger().balance(&payer), 1_000);
}

/// Refund conservation: top-up, partial debit, partial refund — the ledger's own bookkeeping
/// (top-ups minus debits minus refunds) must always equal the live balance, end-to-end through
/// the sim engine's event stream (not just the unit-level ledger test in `prepaid.rs`).
#[test]
fn e2e_refund_conservation_through_the_event_stream() {
    let mut prices = BTreeMap::new();
    prices.insert(ResourceKind::ComputeSeconds, 3u64);
    let schedule = broker_billing::TariffSchedule {
        currency: "USD".to_string(),
        prices,
        free_allowance: BTreeMap::new(),
        period_seconds: None,
    };

    let rail = InMemoryLedger::new();
    let ledger = PrepaidLedger::new("USD", 0);
    let ik = IdentityKey::from_seed(&[0xC0; 32]);
    let payer = b"compute-payer-1".to_vec();
    let mut engine = SimEngine::new(ledger, schedule, ik, &rail);

    engine.replay(&[
        BillingEvent::TopUp { payer: payer.clone(), amount: 900, funding_ref: "ref-1".into() },
        BillingEvent::MeteredUsage { payer: payer.clone(), kind: ResourceKind::ComputeSeconds, units: 100 }, // -300
        BillingEvent::Refund { payer: payer.clone(), amount: 150 },
    ]);

    let total_topped_up: u64 = engine.ledger().top_ups().iter().map(|r| r.amount).sum();
    let total_debited: u64 = engine.ledger().debits().iter().map(|r| r.amount).sum();
    let total_refunded: u64 = engine.ledger().refunds().iter().map(|r| r.amount).sum();
    assert_eq!(total_topped_up, 900);
    assert_eq!(total_debited, 300);
    assert_eq!(total_refunded, 150);
    assert_eq!(engine.ledger().balance(&payer), total_topped_up - total_debited - total_refunded);
    assert_eq!(engine.ledger().balance(&payer), 450);
}

/// The one-directional-audit residual (CONTRACT §6, R-6), demonstrated at THIS crate's prepaid
/// e2e layer, not just in `lib.rs`'s dedicated unit-test module: a signed
/// `broker_economics::UsageReceipt` for an operation the prepaid ledger never actually debited
/// verifies exactly like a receipt for a real, debited operation. Verification proves the
/// coordinator's key signed the claim; it does not and cannot prove the claim corresponds to a
/// real debit.
#[test]
fn e2e_fabricated_operations_receipt_still_verifies() {
    let ik = IdentityKey::from_seed(&[0xD0; 32]);
    let payer = b"audited-payer".to_vec();

    // A REAL debit, with a real receipt, for comparison.
    let mut prices = BTreeMap::new();
    prices.insert(ResourceKind::BytesForwarded, 1u64);
    let schedule = broker_billing::TariffSchedule {
        currency: "USD".to_string(),
        prices,
        free_allowance: BTreeMap::new(),
        period_seconds: None,
    };
    let ledger = PrepaidLedger::new("USD", 0);
    ledger.top_up(&payer, 1_000, "ref-real");
    let bill = schedule
        .evaluate(&BTreeMap::from([(ResourceKind::BytesForwarded, 100u64)]))
        .unwrap();
    let mut log = ReceiptLog::new();
    let (real_debit, real_receipts) = ledger.debit_and_receipt(&payer, &bill, &mut log, &ik).unwrap();
    assert_eq!(real_debit.amount, 100);
    assert!(real_receipts[0].verify().is_ok());
    assert_eq!(ledger.balance(&payer), 900);

    // A FABRICATED operation: no corresponding debit against `ledger` at all — the balance is
    // untouched by this. The coordinator's key can still sign a receipt claiming it happened.
    let fabricated = BilledOperation {
        payer: payer.clone(),
        kind: ResourceKind::BytesForwarded,
        metered_units: 5_000_000,
        billed_units: 5_000_000,
        amount: 5_000_000, // wildly more than the payer's balance could ever cover
        currency: "USD".to_string(),
        sequence: 999,
    };
    let fabricated_receipt = log.issue(&fabricated, &ik);

    // The honest residual: verification alone cannot tell the two apart.
    assert!(
        fabricated_receipt.verify().is_ok(),
        "a fabricated operation's receipt verifies exactly like a real one's — CONTRACT §6, R-6"
    );
    // And the ledger itself proves the fabrication independently, from the *ledger's* side (which
    // a payer holding only the receipt cannot do): the balance never moved for it.
    assert_eq!(
        ledger.balance(&payer),
        900,
        "the prepaid ledger's real balance is unaffected by a receipt with no matching debit"
    );
}
