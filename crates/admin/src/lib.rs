//! # admin
//!
//! The operator admin API for an Ephor coordinator (BUILD-PLAN.md W7) — a kind-agnostic HTTP
//! control plane an operator runs alongside any `crates/*` coordinator-kind crate (gateway,
//! relay, reachability-adapter, ...). It composes, and never reimplements:
//!
//! - **`broker-economics`** — the signed [`broker_economics::Descriptor`]/[`broker_economics::Tariff`]
//!   types and the real `kotva-core` Ed25519 signing (CONTRACT §2.1, §6).
//! - **`broker-billing`** — [`broker_billing::Meter`]/[`broker_billing::TariffSchedule`]/
//!   [`broker_billing::ReceiptLog`] (CONTRACT §6, made concrete).
//! - **`broker-conformance`** — the COORD-1..8 checklist (CONTRACT §7).
//!
//! ## What an operator can do here
//! 1. **Descriptor** (`descriptor.rs`) — GET the current signed descriptor; PUT the policy +
//!    declared content-visibility + kind, sign it, serve it. A visibility change that weakens
//!    the declared class/level is rejected unless explicitly disclosed (`confirm_downgrade`,
//!    CONTRACT §3.2), and every PUT response carries the COORD-1..8 findings for what was just
//!    published.
//! 2. **Tariff** (`tariff.rs`) — GET/PUT the price schedule, signed into the descriptor's tariff.
//!    No token, ever (DIRECTION §5) — an attempt to configure one is rejected.
//! 3. **Metering + receipts** (`billing.rs`) — GET usage per payer and issued receipts, with the
//!    one-directional-audit caveat (CONTRACT §6, R-6) surfaced in every response.
//! 4. **Quota / rate policy** (`quota.rs`) — GET/PUT operator numbers, in-memory.
//! 5. **Keys** (`keys.rs`) — inspect the operator's public key; rotate it (re-signs the
//!    descriptor; the old public key is kept, never dropped — CONTRACT §2.1).
//! 6. **Conformance self-check** (`conformance.rs`) — GET the COORD-1..8 report for the current
//!    posture.
//!
//! ## Admin auth (SEC-1 fail-closed)
//! Every route in [`router`] requires a bearer token ([`auth::AdminAuth`]), compared in constant
//! time. **No token configured → every request is `401`** — this API manages the operator's
//! signing key, so it must default to inert, not merely undocumented. See `auth.rs`.
//!
//! ## Deployment posture — operator-local, not a delivery-path surface
//! This is the operator's own control plane, analogous to a database admin console: it is meant
//! to be reachable only by the operator (the reference binary, `bin/ephor-admin`, binds loopback
//! by default — `config.rs`), and the bearer token is operator config, not a credential any end
//! user ever holds or needs. It sits on **no** user delivery/authoritative path — the descriptor,
//! tariff, and receipts it produces are exactly the discovery-only, self-asserted artifacts
//! CONTRACT §2.1/§6 already make public by design; this crate only adds the operator-side surface
//! that produces/signs them, plus quota/key management that was never content-visible to begin
//! with.
//!
//! ## Deliberate seams (left for a real deployment to fill in)
//! - **In-memory stores.** [`broker_billing::InMemoryMeter`]/[`broker_billing::ReceiptLog`] and
//!   this crate's [`descriptor::DescriptorStore`]/quota lock are process-memory only — a restart
//!   loses unbilled usage and any in-flight (unpersisted) config change. [`broker_billing::Meter`]
//!   is already a trait for exactly this reason; a real deployment backs it (and the descriptor/
//!   quota state, which this crate does not abstract behind a trait) with a durable store.
//! - **Ephemeral key by default.** With no seed configured, `main.rs` generates a fresh key at
//!   startup (loudly, to the log) rather than refusing to start — convenient for a first run, but
//!   an operator MUST configure `EPHOR_ADMIN_KEY_SEED_HEX`/`EPHOR_ADMIN_KEY_FILE` for anything
//!   that needs to keep the same accountable identity across restarts.
//! - **Rotate re-signs the descriptor only**, per the wave's own scope — a tariff already
//!   attached to the descriptor keeps its *own* (still self-certifying, still valid) signature
//!   under the *previous* key; re-signing it too under the new key on rotation is not done here.
//! - **Quota/rate numbers are declared, not enforced.** This crate stores the operator's numbers;
//!   wiring them into an actual rate limiter is the coordinator-kind data plane's job.

#![forbid(unsafe_code)]

pub mod auth;
pub mod billing;
pub mod config;
pub mod conformance;
pub mod descriptor;
pub mod error;
pub mod keys;
pub mod policy;
pub mod quota;
pub mod tariff;

use std::sync::{Arc, RwLock};

use axum::middleware;
use axum::routing::{get, post};
use axum::Router;

use broker_billing::{InMemoryMeter, Meter, ReceiptLog};
use broker_economics::Tariff;
use broker_economics::{ContentVisibility, CoordinatorKind};

pub use auth::AdminAuth;
pub use error::AdminError;
pub use keys::KeyState;

use descriptor::{DescriptorState, DescriptorStore};
use quota::QuotaPolicy;

/// The admin API's full mutable state. Everything here is either a real, composed type from
/// `broker-economics`/`broker-billing` (`keys`, `tariff`, `meter`, `receipts`) or this crate's
/// own in-memory reference store for operator config (`descriptor`, `quota`) — see the crate doc
/// "Deliberate seams" for what a durable deployment needs to replace.
pub struct AdminState {
    pub keys: KeyState,
    pub descriptor: DescriptorStore,
    /// The signed tariff currently attached to the descriptor, if any (`None` = not metered).
    pub tariff: RwLock<Option<Tariff>>,
    /// Shared with whatever data-plane code this admin surface is deployed alongside — that code
    /// calls `record`/`usage`/`reset` directly; this crate only reads it (`billing.rs`).
    pub meter: Arc<dyn Meter + Send + Sync>,
    pub receipts: RwLock<ReceiptLog>,
    pub quota: RwLock<QuotaPolicy>,
    pub auth: AdminAuth,
}

impl AdminState {
    /// Construct fresh admin state: a brand-new (in-memory) meter/receipt log/quota, and the
    /// descriptor seeded from `kind`/`visibility` with an empty operator policy.
    pub fn new(
        kind: CoordinatorKind,
        visibility: ContentVisibility,
        keys: KeyState,
        auth: AdminAuth,
    ) -> Self {
        AdminState {
            keys,
            descriptor: DescriptorStore::new(DescriptorState {
                kind,
                visibility,
                policy: policy::OperatorPolicy::default(),
            }),
            tariff: RwLock::new(None),
            meter: Arc::new(InMemoryMeter::new()),
            receipts: RwLock::new(ReceiptLog::new()),
            quota: RwLock::new(QuotaPolicy::default()),
            auth,
        }
    }
}

/// Build the admin HTTP API. Every route is behind [`auth::require_auth`] — there is no
/// unauthenticated route in this router at all (see the crate doc's auth section).
pub fn router(state: Arc<AdminState>) -> Router {
    Router::new()
        .route(
            "/descriptor",
            get(descriptor::get_descriptor).put(descriptor::put_descriptor),
        )
        .route("/tariff", get(tariff::get_tariff).put(tariff::put_tariff))
        .route("/usage/{payer_hex}", get(billing::get_usage))
        .route("/receipts", get(billing::get_receipts))
        .route(
            "/receipts/{payer_hex}",
            get(billing::get_receipts_for_payer),
        )
        .route("/billing/run/{payer_hex}", post(billing::run_billing))
        .route("/quota", get(quota::get_quota).put(quota::put_quota))
        .route("/keys", get(keys::get_keys))
        .route("/keys/rotate", post(keys::rotate_keys))
        .route("/conformance", get(conformance::get_conformance))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_auth,
        ))
        .with_state(state)
}
