//! Conformance self-check: run `broker_conformance::check` over the operator's current posture
//! and return the COORD-1..8 report, so an operator can see their own conformance — including
//! which clauses the harness can only mark [`broker_conformance::Outcome::Behavioral`] pending a
//! runtime test (CONTRACT §7, `broker-conformance`'s own honesty rule).
//!
//! **Honest scope note:** this admin crate is a control plane, not the coordinator's data plane —
//! it does not itself forward/terminate any traffic. `lock_in`, `self_host`, and
//! `delivery_path_gate` below are therefore this crate's best *declared* inference from the
//! descriptor's kind (the same table `broker_economics::kinds` documents), not an independent
//! runtime observation of the actual coordinator-kind crate's behavior. A kind whose real
//! behavior diverges from this inference (e.g. a `gateway` that secretly classifies mail on the
//! delivery path) is exactly the gap `broker-conformance`'s `Behavioral` outcomes and W10's
//! per-kind runtime tests exist to close — not something this admin surface can observe.

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde::Serialize;

use broker_conformance::{
    check, Coordinator, Gate, LockIn, Metering, Outcome, Report, SelfHost, Settlement,
};
use broker_economics::{CoordinatorKind, Descriptor};

use crate::AdminState;

struct Posture {
    descriptor: Descriptor,
    metered: bool,
}

impl Coordinator for Posture {
    fn kind(&self) -> CoordinatorKind {
        self.descriptor.kind
    }

    fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }

    fn lock_in(&self) -> LockIn {
        // This admin API persists no user data — only rebuildable operator config (descriptor
        // fields, tariff, quota) — and a rotated key keeps the accountable-identity trail
        // (`keys.rs`). Switching/dropping this operator is config-only by construction.
        LockIn::None
    }

    fn self_host(&self) -> SelfHost {
        if self.descriptor.kind.is_scarce_reachability() {
            SelfHost::ScarceReachabilityException
        } else {
            SelfHost::Backstop
        }
    }

    fn delivery_path_gate(&self) -> Gate {
        use CoordinatorKind::*;
        match self.descriptor.kind {
            // Ciphertext-only kinds: no content on the delivery path to gate on at all.
            Relay | MediaRelay => Gate::NoDeliveryPath,
            // The §4 derived-view carve-out: these kinds classify/rank their own opt-in corpus.
            Indexer | Labeler | Matcher => Gate::DerivedViewOnly,
            // Everything else: the declared default is authorize-from-identity-only.
            _ => Gate::Authorization,
        }
    }

    fn metering(&self) -> Metering {
        if self.metered {
            Metering::SignedReceiptsToPayer
        } else {
            Metering::NotMetered
        }
    }

    fn settlement(&self) -> Settlement {
        // Structural: this crate has no code path that mints or accepts a protocol token
        // (DIRECTION §5) — `broker-billing`'s settlement seam is existing-assets-only throughout.
        Settlement::ExistingAssetsOnly
    }
}

pub(crate) fn run_conformance(state: &AdminState) -> Report {
    let descriptor = crate::descriptor::build_descriptor(state);
    let metered = state.tariff.read().expect("tariff lock poisoned").is_some();
    check(&Posture {
        descriptor,
        metered,
    })
}

#[derive(Serialize)]
pub struct FindingDto {
    pub id: &'static str,
    pub clause: &'static str,
    pub outcome: &'static str,
    pub detail: Option<String>,
}

#[derive(Serialize)]
pub struct ReportDto {
    pub kind: String,
    pub is_conformant: bool,
    pub findings: Vec<FindingDto>,
}

pub(crate) fn report_dto(r: &Report) -> ReportDto {
    ReportDto {
        kind: r.kind.as_str().to_string(),
        is_conformant: r.is_conformant(),
        findings: r
            .findings
            .iter()
            .map(|f| {
                let (outcome, detail) = match &f.outcome {
                    Outcome::Pass => ("pass", None),
                    Outcome::Violation(s) => ("violation", Some(s.clone())),
                    Outcome::Behavioral(s) => ("behavioral", Some(s.clone())),
                };
                FindingDto {
                    id: f.id,
                    clause: f.clause,
                    outcome,
                    detail,
                }
            })
            .collect(),
    }
}

pub async fn get_conformance(State(state): State<Arc<AdminState>>) -> Json<ReportDto> {
    Json(report_dto(&run_conformance(&state)))
}
