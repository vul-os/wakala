//! # broker-billing-patala
//!
//! An OPTIONAL, isolated reference implementation of
//! [`broker_billing::settlement::SettlementRail`] (CONTRACT §6) backed by
//! [`patala`](../../../patala/PATALA.md) — a separate, sibling, non-custodial payment-rail
//! substrate. This crate exists to prove the seam is usable end-to-end with a real payment rail;
//! it is **never** a dependency of `broker-billing` itself, and an operator who wants a different
//! provider (a card processor, a bank rail, their own ledger) writes their own small
//! `SettlementRail` impl and never looks at this crate at all — see
//! `broker_billing::settlement` module docs.
//!
//! ## Prepaid, not per-charge network calls — and why `charge` stays synchronous
//!
//! [`broker_billing::settlement::SettlementRail::charge`] is a **synchronous** trait method.
//! Patala's [`patala_core::PaymentRail`] is `async`, and — more fundamentally — a non-custodial
//! rail (`patala-stellar`) requires the *sender's own* signer to submit a payment; this adapter
//! has no access to that key and must not invent one, so it structurally cannot turn a `charge`
//! call into "submit a new on-chain payment right now" even if the trait were async. The honest
//! resolution (matching this crate's own DECISIONS.md call: **prepaid is the primary model**) is
//! the same split `dmtap-postage-patala` uses for `PostageProvider::top_up`:
//!
//! 1. [`PatalaSettlement::top_up_pay_request`] (sync): builds the [`patala_core::PayRequest`] a
//!    payer's own wallet would submit to top up — an intent, never a credit.
//! 2. [`PatalaSettlement::credit_from_receipt`] (async, NOT part of `SettlementRail`): given a
//!    [`patala_core::Receipt`] for a payment that already happened, calls
//!    [`patala_core::PaymentRail::verify`] and, only on success, credits a local prepaid balance.
//!    This is the ONLY place this crate ever trusts a payment happened.
//! 3. [`SettlementRail::charge`]/[`SettlementRail::balance`] (sync, the actual trait impl):
//!    operate purely on that local, already-verified balance — no further patala/network call on
//!    the hot billing path, exactly the "prepaid, not per-message" rule
//!    `crate::prepaid`/`dmtap-postage-patala` both already follow.
//!
//! ## Non-custodial, by construction; Ephor takes no cut
//!
//! This adapter never holds a payer's funds and never signs a payment on a payer's behalf.
//! Patala's rails are non-custodial (`patala-stellar` settles wallet-to-wallet); this crate only
//! ever **verifies** a payment the payer's own wallet already made, then credits a local ledger
//! it owns — mirroring `broker_billing::prepaid`'s own "credit claims, not custody" framing
//! exactly. No fee, spread, or cut is taken anywhere in this crate (DIRECTION §5: "KOTVA brokers
//! none and takes no cut").
//!
//! ## Reference rail: patala-stellar; noted alternative: patala-hyperswitch
//!
//! [`StellarSettlement`] wires this adapter to `patala-stellar` (Ed25519-native, so a
//! coordinator's own substrate identity key can double as the receiving wallet with no separate
//! mapping table — `PATALA.md` §6) as the one reference **crypto** top-up rail this crate ships.
//! For the OPTIONAL monthly-postpaid leg (`broker_billing::subscription::Subscription`), an
//! operator wanting a card/fiat rail instead would wire `patala-hyperswitch` (a thin HTTP client
//! to a self-hosted Hyperswitch instance) the same way — noted here, not shipped as a dependency
//! of this crate, to keep it minimal; `PatalaSettlement<R>` is generic over any
//! `patala_core::PaymentRail`, so swapping rails needs no code change in this crate.
//!
//! ## UNVERIFIED AGAINST LIVE STELLAR
//!
//! **This crate has not been run against a live Stellar network (testnet or mainnet) from this
//! environment.** All tests here run fully offline against a fake [`patala_core::PaymentRail`]
//! (mirroring `dmtap-postage-patala`'s own test approach); a real top-up flow additionally
//! depends on `patala-stellar`'s own live path, which that crate's README already discloses as
//! unverified against live Horizon. Treat the end-to-end real-money path as **UNVERIFIED** until
//! someone runs it against a real (or at least testnet) Stellar network and confirms it.

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use patala_core::{PayRequest, PaymentRail, Receipt};

use broker_billing::settlement::{SettlementReceipt, SettlementRail};

/// Everything that can go wrong against a [`PatalaSettlement`]. Every variant is a refusal: none
/// of them ever result in a balance changing.
#[derive(Debug, thiserror::Error)]
pub enum PatalaSettlementError {
    /// The requested currency does not match this adapter's configured currency — refused rather
    /// than silently cross-charged.
    #[error("currency {requested} does not match this settlement rail's currency {configured}")]
    CurrencyMismatch { requested: String, configured: String },
    /// The payer's local prepaid balance is insufficient to cover the charge — fail-closed, the
    /// same shape as [`broker_billing::prepaid::PrepaidError::Exhausted`].
    #[error("insufficient prepaid credit on the patala rail: payer has {balance} {currency}, charge was {amount}")]
    InsufficientCredit { balance: u64, amount: u64, currency: String },
    /// [`PaymentRail::verify`] itself failed (an operational failure to even check — RPC down,
    /// etc. — never implies the receipt is valid; see that method's own fail-closed contract).
    #[error("payment rail verification failed: {0}")]
    Rail(String),
    /// [`PaymentRail::verify`] returned `Ok(false)`: the receipt does not hold up.
    #[error("receipt did not verify")]
    NotVerified,
    /// A [`patala_core::Receipt`] presented to [`PatalaSettlement::credit_from_receipt`] named a
    /// currency other than this adapter's configured one.
    #[error("receipt currency {receipt} does not match this settlement rail's currency {expected}")]
    ReceiptCurrencyMismatch { receipt: String, expected: String },
}

/// A [`broker_billing::settlement::SettlementRail`] backed by ANY `patala_core::PaymentRail` (a
/// generic Stellar/Solana/mock rail, or your own) — see the module docs for the two-phase
/// top-up/credit split and why [`SettlementRail::charge`] itself never touches the network.
///
/// Like every `broker-billing` settlement adapter, this struct owns its own storage: a plain
/// in-memory `Mutex<HashMap<...>>` local prepaid ledger here, for reference — a real operator
/// deployment would likely back this with a database instead, which is exactly why
/// `broker_billing::settlement::SettlementRail` never prescribes storage.
pub struct PatalaSettlement<R: PaymentRail> {
    rail: R,
    /// The operator's own receiving address/account payers pay into to top up. Opaque to this
    /// crate beyond carrying it through to the payer as part of the payment intent.
    destination: String,
    currency: String,
    ledger: Mutex<HashMap<Vec<u8>, u64>>,
    /// Dedup: a receipt reference already credited is never credited twice, even if presented
    /// again (e.g. a retried caller).
    credited_references: Mutex<HashSet<String>>,
    next_tx_seq: Mutex<u64>,
}

impl<R: PaymentRail> PatalaSettlement<R> {
    /// Wrap `rail` (any `patala_core::PaymentRail` — real or a fake for tests/offline use) as a
    /// [`SettlementRail`]. `destination` is the operator's own receiving address/account;
    /// `currency` is the asset/ISO code this adapter tracks balances in (must match what `rail`
    /// actually settles, e.g. `"USDC"` for `patala-stellar`).
    pub fn new(rail: R, destination: impl Into<String>, currency: impl Into<String>) -> Self {
        PatalaSettlement {
            rail,
            destination: destination.into(),
            currency: currency.into(),
            ledger: Mutex::new(HashMap::new()),
            credited_references: Mutex::new(HashSet::new()),
            next_tx_seq: Mutex::new(0),
        }
    }

    /// The address/account payers should pay to top up (surfaced alongside
    /// [`Self::top_up_pay_request`]).
    pub fn destination(&self) -> &str {
        &self.destination
    }

    /// The currency/asset code this adapter tracks balances in.
    pub fn currency(&self) -> &str {
        &self.currency
    }

    /// This adapter's locally credited balance for `payer` — the same number
    /// [`SettlementRail::balance`] reports, exposed without the `Result`/currency-check wrapper
    /// for callers that already know they are asking about this adapter's own currency.
    pub fn local_balance(&self, payer: &[u8]) -> u64 {
        self.ledger.lock().expect("patala settlement ledger mutex poisoned").get(payer).copied().unwrap_or(0)
    }

    fn next_seq(&self) -> u64 {
        let mut seq = self.next_tx_seq.lock().expect("patala settlement ledger mutex poisoned");
        let v = *seq;
        *seq += 1;
        v
    }

    /// Build the [`patala_core::PayRequest`] a payer's own wallet would submit to top up
    /// `amount_minor` — a convenience for constructing the intent a caller surfaces to a payer;
    /// never submitted or signed by this crate itself (non-custodial, see module docs).
    pub fn top_up_pay_request(&self, amount_minor: u64, reference: impl Into<String>) -> PayRequest {
        PayRequest {
            amount_minor,
            currency: self.currency.clone(),
            destination: self.destination.clone(),
            reference: reference.into(),
        }
    }

    /// The real credit path (see module docs). Verifies `receipt` against the configured
    /// [`patala_core::PaymentRail`] and, only on success, credits `payer`'s local prepaid balance
    /// by `receipt.amount_minor`. Idempotent on `receipt.reference`: a receipt whose reference has
    /// already been credited is accepted (returns the current balance) without crediting again —
    /// so a caller may safely retry this call.
    pub async fn credit_from_receipt(&self, payer: &[u8], receipt: Receipt) -> Result<u64, PatalaSettlementError> {
        if receipt.currency != self.currency {
            return Err(PatalaSettlementError::ReceiptCurrencyMismatch {
                receipt: receipt.currency.clone(),
                expected: self.currency.clone(),
            });
        }

        // Idempotency check BEFORE re-verifying: a repeated call with an already-credited
        // reference just reports the current balance, never re-credits.
        if self.credited_references.lock().expect("mutex poisoned").contains(&receipt.reference) {
            return Ok(self.local_balance(payer));
        }

        // The ONLY place this crate trusts a payment happened. Fail closed per
        // `PaymentRail::verify`'s own contract: `Err` is an operational failure to check (never
        // "valid"), `Ok(false)` is a receipt that does not hold up.
        let verified = self
            .rail
            .verify(&receipt)
            .await
            .map_err(|e| PatalaSettlementError::Rail(e.to_string()))?;
        if !verified {
            return Err(PatalaSettlementError::NotVerified);
        }

        let new_balance = {
            let mut ledger = self.ledger.lock().expect("mutex poisoned");
            let entry = ledger.entry(payer.to_vec()).or_insert(0);
            *entry = entry.saturating_add(receipt.amount_minor);
            *entry
        };
        self.credited_references.lock().expect("mutex poisoned").insert(receipt.reference.clone());

        Ok(new_balance)
    }
}

/// A [`PatalaSettlement`] wired to `patala-stellar`'s real rail — the one reference rail this
/// crate ships (Stellar: ~$0.0001/tx fees suit prepaid micropayment top-ups, 3-5s finality,
/// Ed25519 StrKey so the operator's receiving identity key doubles as its wallet with no separate
/// mapping table; see `patala-stellar`'s own docs and `PATALA.md` §6).
pub type StellarSettlement = PatalaSettlement<patala_stellar::StellarRail>;

impl StellarSettlement {
    /// Construct a settlement rail that verifies USDC-on-Stellar top-ups against `horizon_url`,
    /// tracking balances for `usdc_issuer` on `network`, with payers paying into `destination` (a
    /// StrKey Stellar address, `G...`). Verify-only (no signer attached) — this crate never signs
    /// a payment on a payer's behalf; see the module docs' non-custodial section.
    ///
    /// **UNVERIFIED AGAINST LIVE STELLAR** — see this crate's module docs. Every test here runs
    /// against a fake `PaymentRail`, never this constructor's real `HorizonRpc`.
    pub fn stellar(
        network: patala_stellar::Network,
        usdc_issuer: impl Into<String>,
        base_fee_stroops: u32,
        horizon_url: impl Into<String>,
        destination: impl Into<String>,
    ) -> Self {
        let cfg = patala_stellar::StellarConfig {
            network,
            usdc_issuer: usdc_issuer.into(),
            base_fee_stroops,
        };
        let rpc: std::sync::Arc<dyn patala_stellar::rpc::StellarRpc> =
            std::sync::Arc::new(patala_stellar::rpc::HorizonRpc::new(horizon_url));
        let rail = patala_stellar::StellarRail::new(cfg, rpc);
        PatalaSettlement::new(rail, destination, "USDC")
    }
}

impl<R: PaymentRail> SettlementRail for PatalaSettlement<R> {
    type Error = PatalaSettlementError;

    /// Charge `payer` `amount` of `currency` against their **already-credited local balance**
    /// (see the module doc's three-step split) — never a live network/rail call on this path.
    /// Fails closed on a currency mismatch or insufficient local balance, leaving the balance
    /// unchanged.
    fn charge(&self, payer: &[u8], amount: u64, currency: &str) -> Result<SettlementReceipt, Self::Error> {
        if currency != self.currency {
            return Err(PatalaSettlementError::CurrencyMismatch {
                requested: currency.to_string(),
                configured: self.currency.clone(),
            });
        }
        let mut ledger = self.ledger.lock().expect("mutex poisoned");
        let balance = ledger.get(payer).copied().unwrap_or(0);
        if balance < amount {
            return Err(PatalaSettlementError::InsufficientCredit {
                balance,
                amount,
                currency: currency.to_string(),
            });
        }
        ledger.insert(payer.to_vec(), balance - amount);
        drop(ledger);

        Ok(SettlementReceipt {
            payer: payer.to_vec(),
            amount,
            currency: currency.to_string(),
            tx_seq: self.next_seq(),
        })
    }

    /// `payer`'s locally credited balance in `currency` — `0` for any currency other than this
    /// adapter's configured one (never an error: `SettlementRail::balance` is documented as
    /// returning a plain non-applicable `0` rather than erroring for a rail that only tracks one
    /// currency).
    fn balance(&self, payer: &[u8], currency: &str) -> Result<i64, Self::Error> {
        if currency != self.currency {
            return Ok(0);
        }
        Ok(self.local_balance(payer) as i64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use patala_core::{Error as PatalaError, Quote, RailCapabilities, RailClass, Settlement};

    /// A minimal, deterministic offline fake `PaymentRail` (this crate's own equivalent of
    /// `patala_core::MockRail`, written locally so this crate's dev-deps stay minimal and its
    /// tests never depend on `patala_core`'s internal mock digest scheme) — always verifies a
    /// receipt it itself issued via [`FakeRail::charge`], and can be configured to reject
    /// tampered/mismatched receipts, exactly like a real rail would.
    struct FakeRail {
        id: String,
        caps: RailCapabilities,
    }

    impl FakeRail {
        fn new(id: &str) -> Self {
            FakeRail {
                id: id.to_string(),
                caps: RailCapabilities {
                    class: RailClass::NonCustodialFinal,
                    reversible: false,
                    requires_kyc: false,
                    holds_funds: false,
                    currencies: vec!["USDC".to_string()],
                    settlement: Settlement::Instant,
                },
            }
        }
    }

    #[async_trait]
    impl PaymentRail for FakeRail {
        fn id(&self) -> &str {
            &self.id
        }
        fn capabilities(&self) -> &RailCapabilities {
            &self.caps
        }
        async fn quote(&self, req: &PayRequest) -> patala_core::Result<Quote> {
            Ok(Quote {
                rail_id: self.id.clone(),
                amount_minor: req.amount_minor,
                currency: req.currency.clone(),
                fee_minor: 0,
                total_minor: req.amount_minor,
                settlement: Settlement::Instant,
                expires_at_unix: 0,
            })
        }
        async fn charge(&self, req: &PayRequest) -> patala_core::Result<Receipt> {
            req.validate().map_err(|e| PatalaError::InvalidRequest(e.to_string()))?;
            Ok(Receipt {
                rail_id: self.id.clone(),
                amount_minor: req.amount_minor,
                currency: req.currency.clone(),
                reference: req.reference.clone(),
                proof: req.reference.clone().into_bytes(),
                settled_at_unix: 0,
            })
        }
        async fn verify(&self, receipt: &Receipt) -> patala_core::Result<bool> {
            // A tampered receipt (proof no longer matching `reference`) fails to verify — enough
            // to exercise this crate's fail-closed handling without depending on
            // `patala_core::MockRail`'s internal digest scheme.
            Ok(receipt.rail_id == self.id && receipt.proof == receipt.reference.clone().into_bytes())
        }
    }

    /// A rail that always errors on `verify` — an operational-failure double, proving this
    /// crate's `Rail` error variant is distinct from `NotVerified`.
    struct AlwaysErrorsOnVerify(FakeRail);

    #[async_trait]
    impl PaymentRail for AlwaysErrorsOnVerify {
        fn id(&self) -> &str {
            self.0.id()
        }
        fn capabilities(&self) -> &RailCapabilities {
            self.0.capabilities()
        }
        async fn quote(&self, req: &PayRequest) -> patala_core::Result<Quote> {
            self.0.quote(req).await
        }
        async fn charge(&self, req: &PayRequest) -> patala_core::Result<Receipt> {
            self.0.charge(req).await
        }
        async fn verify(&self, _receipt: &Receipt) -> patala_core::Result<bool> {
            Err(PatalaError::Rail("rpc unreachable".into()))
        }
    }

    #[tokio::test]
    async fn top_up_pay_request_is_an_intent_never_a_credit() {
        let adapter = PatalaSettlement::new(FakeRail::new("fake"), "operator-address", "USDC");
        let intent = adapter.top_up_pay_request(500, "ref-1");
        assert_eq!(intent.amount_minor, 500);
        assert_eq!(intent.destination, "operator-address");
        assert_eq!(adapter.local_balance(b"payer"), 0, "building the intent credits nothing");
    }

    #[tokio::test]
    async fn credit_from_receipt_verifies_before_crediting() {
        let rail = FakeRail::new("fake");
        let req = PayRequest {
            amount_minor: 1_000,
            currency: "USDC".into(),
            destination: "operator-address".into(),
            reference: "ref-1".into(),
        };
        let receipt = rail.charge(&req).await.unwrap();

        let adapter = PatalaSettlement::new(rail, "operator-address", "USDC");
        let new_balance = adapter.credit_from_receipt(b"payer", receipt).await.unwrap();
        assert_eq!(new_balance, 1_000);
        assert_eq!(adapter.local_balance(b"payer"), 1_000);
    }

    #[tokio::test]
    async fn credit_from_receipt_rejects_a_tampered_receipt() {
        let rail = FakeRail::new("fake");
        let req = PayRequest {
            amount_minor: 1_000,
            currency: "USDC".into(),
            destination: "operator-address".into(),
            reference: "ref-1".into(),
        };
        let mut receipt = rail.charge(&req).await.unwrap();
        receipt.amount_minor = 999_999; // tamper with the amount after the fact (proof no longer matches)
        receipt.proof = b"not-the-real-proof".to_vec();

        let adapter = PatalaSettlement::new(rail, "operator-address", "USDC");
        let err = adapter.credit_from_receipt(b"payer", receipt).await.unwrap_err();
        assert!(matches!(err, PatalaSettlementError::NotVerified));
        assert_eq!(adapter.local_balance(b"payer"), 0, "a rejected receipt credits nothing");
    }

    #[tokio::test]
    async fn credit_from_receipt_rejects_currency_mismatch() {
        let rail = FakeRail::new("fake");
        let adapter = PatalaSettlement::new(rail, "operator-address", "USDC");
        let receipt = Receipt {
            rail_id: "fake".into(),
            amount_minor: 1_000,
            currency: "EUR".into(), // adapter tracks USDC
            reference: "ref-1".into(),
            proof: b"ref-1".to_vec(),
            settled_at_unix: 0,
        };
        let err = adapter.credit_from_receipt(b"payer", receipt).await.unwrap_err();
        assert!(matches!(err, PatalaSettlementError::ReceiptCurrencyMismatch { .. }));
    }

    #[tokio::test]
    async fn credit_from_receipt_is_idempotent_on_reference() {
        let rail = FakeRail::new("fake");
        let req = PayRequest {
            amount_minor: 1_000,
            currency: "USDC".into(),
            destination: "operator-address".into(),
            reference: "ref-1".into(),
        };
        let receipt = rail.charge(&req).await.unwrap();

        let adapter = PatalaSettlement::new(rail, "operator-address", "USDC");
        adapter.credit_from_receipt(b"payer", receipt.clone()).await.unwrap();
        // Presenting the exact same receipt again must not double-credit.
        adapter.credit_from_receipt(b"payer", receipt).await.unwrap();
        assert_eq!(adapter.local_balance(b"payer"), 1_000);
    }

    #[tokio::test]
    async fn rail_operational_failure_surfaces_as_rail_error_not_a_false_verify() {
        let inner = FakeRail::new("fake");
        let req = PayRequest {
            amount_minor: 100,
            currency: "USDC".into(),
            destination: "operator-address".into(),
            reference: "ref-1".into(),
        };
        let receipt = inner.charge(&req).await.unwrap();
        let rail = AlwaysErrorsOnVerify(FakeRail::new("fake"));
        let adapter = PatalaSettlement::new(rail, "operator-address", "USDC");
        let err = adapter.credit_from_receipt(b"payer", receipt).await.unwrap_err();
        assert!(matches!(err, PatalaSettlementError::Rail(_)));
    }

    #[tokio::test]
    async fn settlement_rail_charge_spends_the_locally_credited_balance() {
        let rail = FakeRail::new("fake");
        let req = PayRequest {
            amount_minor: 1_000,
            currency: "USDC".into(),
            destination: "operator-address".into(),
            reference: "ref-1".into(),
        };
        let receipt = rail.charge(&req).await.unwrap();
        let adapter = PatalaSettlement::new(rail, "operator-address", "USDC");
        adapter.credit_from_receipt(b"payer", receipt).await.unwrap();

        let settlement_receipt = adapter.charge(b"payer", 300, "USDC").unwrap();
        assert_eq!(settlement_receipt.amount, 300);
        assert_eq!(SettlementRail::balance(&adapter, b"payer", "USDC").unwrap(), 700);
    }

    #[tokio::test]
    async fn charge_beyond_local_balance_is_rejected_and_balance_unchanged() {
        let rail = FakeRail::new("fake");
        let adapter = PatalaSettlement::new(rail, "operator-address", "USDC");
        let err = adapter.charge(b"payer", 100, "USDC").unwrap_err();
        assert!(matches!(err, PatalaSettlementError::InsufficientCredit { .. }));
    }

    #[tokio::test]
    async fn charge_rejects_a_currency_this_adapter_does_not_track() {
        let rail = FakeRail::new("fake");
        let adapter = PatalaSettlement::new(rail, "operator-address", "USDC");
        let err = adapter.charge(b"payer", 100, "EUR").unwrap_err();
        assert!(matches!(err, PatalaSettlementError::CurrencyMismatch { .. }));
    }

    #[tokio::test]
    async fn balance_for_an_untracked_currency_is_zero_not_an_error() {
        let rail = FakeRail::new("fake");
        let adapter = PatalaSettlement::new(rail, "operator-address", "USDC");
        assert_eq!(SettlementRail::balance(&adapter, b"payer", "EUR").unwrap(), 0);
    }

    #[tokio::test]
    async fn composes_with_broker_billing_subscription_exactly_like_any_other_rail() {
        // Proves this real, patala-backed adapter is a drop-in `SettlementRail` — no
        // patala-specific code needed in `broker_billing::subscription` itself.
        let rail = FakeRail::new("fake");
        let req = PayRequest {
            amount_minor: 2_000,
            currency: "USDC".into(),
            destination: "operator-address".into(),
            reference: "ref-1".into(),
        };
        let receipt = rail.charge(&req).await.unwrap();
        let adapter = PatalaSettlement::new(rail, "operator-address", "USDC");
        adapter.credit_from_receipt(b"payer", receipt).await.unwrap();

        let subscription = broker_billing::Subscription::new(b"payer".to_vec(), 999, "USDC");
        let receipt = subscription.charge(&adapter).unwrap();
        assert_eq!(receipt.amount, 999);
        assert_eq!(adapter.local_balance(b"payer"), 2_000 - 999);
    }
}
