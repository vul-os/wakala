//! Descriptor management: GET the current signed descriptor; PUT the operator policy + declared
//! content-visibility + kind, sign it, and serve the result (CONTRACT §2.1's discovery-only
//! descriptor).
//!
//! The descriptor is always (re-)signed **fresh**, from whatever the operator's current signing
//! key is ([`crate::keys::KeyState`]) — so a `GET` right after a key rotation always verifies,
//! and the wire `identity` field never silently drifts from the key that actually produced `sig`.

use std::sync::{Arc, RwLock};

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};

use broker_economics::{
    AssuranceLevel, ContentVisibility, CoordinatorKind, Descriptor, SignedDescriptor,
    VisibilityClass,
};

use crate::conformance::{report_dto, run_conformance, ReportDto};
use crate::error::AdminError;
use crate::policy::OperatorPolicy;
use crate::tariff::{tariff_to_dto, TariffDto};
use crate::AdminState;

/// The mutable descriptor fields an operator controls (everything but `identity`, which always
/// tracks [`crate::keys::KeyState`], and `tariff`, which is configured separately at `/tariff`
/// but folded in when the descriptor is built/signed).
#[derive(Clone, Debug)]
pub struct DescriptorState {
    pub kind: CoordinatorKind,
    pub visibility: ContentVisibility,
    pub policy: OperatorPolicy,
}

/// A lock around [`DescriptorState`] — the admin API's one piece of mutable descriptor config.
pub struct DescriptorStore {
    inner: RwLock<DescriptorState>,
}

impl DescriptorStore {
    pub fn new(initial: DescriptorState) -> Self {
        DescriptorStore {
            inner: RwLock::new(initial),
        }
    }

    pub fn get(&self) -> DescriptorState {
        self.inner.read().expect("descriptor lock poisoned").clone()
    }

    pub fn set(&self, next: DescriptorState) {
        *self.inner.write().expect("descriptor lock poisoned") = next;
    }
}

// --- Visibility downgrade detection (CONTRACT §3.2: "no silent downgrade") ---------------------

/// Ranks a visibility class from most- to least-blind (§3.1). Lower is more protective. This is
/// only used to detect a *silent* downgrade attempt (§3.2) — it is not a judgement about which
/// class an operator SHOULD run (that stays the operator's call, made explicitly).
fn class_rank(c: VisibilityClass) -> u8 {
    match c {
        VisibilityClass::Blind => 0,
        VisibilityClass::BlindRouting => 1,
        VisibilityClass::Terminating => 2,
    }
}

fn level_rank(l: AssuranceLevel) -> u8 {
    match l {
        AssuranceLevel::Structural => 0,
        AssuranceLevel::Attested => 1,
        AssuranceLevel::Declared => 2,
    }
}

/// Whether moving from `from` to `to` weakens the declared visibility: a less-blind class, or the
/// same class at a weaker assurance level (§3.2/§3.3).
pub fn is_downgrade(from: ContentVisibility, to: ContentVisibility) -> bool {
    class_rank(to.class) > class_rank(from.class)
        || (to.class == from.class && level_rank(to.level) > level_rank(from.level))
}

// --- Building / signing --------------------------------------------------------------------

/// Assemble the current unsigned [`Descriptor`] from state: identity always tracks the live
/// signing key, visibility/policy/kind come from [`DescriptorStore`], tariff from `/tariff`.
pub(crate) fn build_descriptor(state: &AdminState) -> Descriptor {
    let d = state.descriptor.get();
    Descriptor {
        identity: state.keys.public(),
        kind: d.kind,
        visibility: d.visibility,
        policy: d.policy.to_cbor(),
        tariff: state.tariff.read().expect("tariff lock poisoned").clone(),
    }
}

/// Sign the current descriptor under the current key (fresh every call — see module doc).
pub(crate) fn sign_descriptor(state: &AdminState) -> SignedDescriptor {
    let descriptor = build_descriptor(state);
    state.keys.with_current(|ik| descriptor.sign(ik))
}

// --- Wire DTOs -------------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VisibilityDto {
    pub class: String,
    pub level: String,
}

impl VisibilityDto {
    fn to_domain(&self) -> Result<ContentVisibility, AdminError> {
        let class = match self.class.as_str() {
            "blind" => VisibilityClass::Blind,
            "blind-routing" => VisibilityClass::BlindRouting,
            "terminating" => VisibilityClass::Terminating,
            other => {
                return Err(AdminError::BadRequest(format!(
                    "unknown visibility class {other:?} (want blind|blind-routing|terminating)"
                )))
            }
        };
        let level = match self.level.as_str() {
            "structural" => AssuranceLevel::Structural,
            "attested" => AssuranceLevel::Attested,
            "declared" => AssuranceLevel::Declared,
            other => {
                return Err(AdminError::BadRequest(format!(
                    "unknown assurance level {other:?} (want structural|attested|declared)"
                )))
            }
        };
        Ok(ContentVisibility::new(class, level))
    }

    fn from_domain(v: ContentVisibility) -> Self {
        VisibilityDto {
            class: v.class.to_string(),
            level: v.level.to_string(),
        }
    }
}

/// CONTRACT §2.1: the descriptor carries no global score, price rank, or stake field — that is
/// structural (the `Descriptor` type has no such field), not a runtime check; this note just
/// says so where a client reads the response.
const DISCOVERY_ONLY_NOTE: &str = "discovery-only, self-asserted (CONTRACT §2.1): carries no \
global reputation score, no price ranking, and no stake field by construction";

#[derive(Serialize)]
pub struct SignedDescriptorDto {
    pub kind: String,
    pub identity_hex: String,
    pub visibility: VisibilityDto,
    pub policy: OperatorPolicy,
    pub tariff: Option<TariffDto>,
    pub sig_hex: String,
    /// The full wire bytes (`SignedDescriptor::det_cbor`), hex — a relying party can store/verify
    /// this directly without going back through this admin API's JSON shape.
    pub det_cbor_hex: String,
    pub note: &'static str,
}

pub(crate) fn to_dto(signed: &SignedDescriptor) -> SignedDescriptorDto {
    SignedDescriptorDto {
        kind: signed.descriptor.kind.as_str().to_string(),
        identity_hex: hex::encode(&signed.descriptor.identity),
        visibility: VisibilityDto::from_domain(signed.descriptor.visibility),
        policy: OperatorPolicy::from_cbor(&signed.descriptor.policy).unwrap_or_default(),
        tariff: signed
            .descriptor
            .tariff
            .as_ref()
            .and_then(|t| tariff_to_dto(t).ok()),
        sig_hex: hex::encode(&signed.sig),
        det_cbor_hex: hex::encode(signed.det_cbor()),
        note: DISCOVERY_ONLY_NOTE,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescriptorPutRequest {
    pub kind: String,
    pub visibility: VisibilityDto,
    #[serde(default)]
    pub policy: OperatorPolicy,
    /// Explicit operator disclosure required to accept a weaker visibility than the one
    /// currently declared (CONTRACT §3.2 "no *silent* downgrade") — a real, intentional switch
    /// to `terminating` is legitimate as long as it is disclosed; omitting this on a weakening
    /// change is treated as an accidental/silent one and rejected (409).
    #[serde(default)]
    pub confirm_downgrade: bool,
}

#[derive(Serialize)]
pub struct DescriptorPutResponse {
    pub descriptor: SignedDescriptorDto,
    /// COORD-1..8 findings for the posture that was just published, so a downgrade (or any other
    /// COORD-4/5-relevant change) is visible in the same response that accepted it, not only via
    /// a separate `/conformance` lookup.
    pub conformance: ReportDto,
}

pub async fn get_descriptor(State(state): State<Arc<AdminState>>) -> Json<SignedDescriptorDto> {
    Json(to_dto(&sign_descriptor(&state)))
}

pub async fn put_descriptor(
    State(state): State<Arc<AdminState>>,
    Json(body): Json<DescriptorPutRequest>,
) -> Result<Json<DescriptorPutResponse>, AdminError> {
    let kind = CoordinatorKind::from_wire_str(&body.kind).ok_or_else(|| {
        AdminError::BadRequest(format!("unknown coordinator kind {:?}", body.kind))
    })?;
    let new_visibility = body.visibility.to_domain()?;
    let current = state.descriptor.get();

    if is_downgrade(current.visibility, new_visibility) && !body.confirm_downgrade {
        return Err(AdminError::Conflict(format!(
            "declaring {new_visibility} after {} is a visibility downgrade (CONTRACT §3.2: no \
             silent downgrade); resubmit with \"confirm_downgrade\": true to disclose it \
             explicitly",
            current.visibility
        )));
    }

    state.descriptor.set(DescriptorState {
        kind,
        visibility: new_visibility,
        policy: body.policy,
    });

    let signed = sign_descriptor(&state);
    let report = run_conformance(&state);
    Ok(Json(DescriptorPutResponse {
        descriptor: to_dto(&signed),
        conformance: report_dto(&report),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_class_stronger_level_is_not_a_downgrade() {
        let from = ContentVisibility::new(VisibilityClass::BlindRouting, AssuranceLevel::Declared);
        let to = ContentVisibility::new(VisibilityClass::BlindRouting, AssuranceLevel::Structural);
        assert!(!is_downgrade(from, to));
    }

    #[test]
    fn blind_to_terminating_is_a_downgrade() {
        let from = ContentVisibility::new(VisibilityClass::Blind, AssuranceLevel::Structural);
        let to = ContentVisibility::new(VisibilityClass::Terminating, AssuranceLevel::Declared);
        assert!(is_downgrade(from, to));
    }

    #[test]
    fn same_class_weaker_level_is_a_downgrade() {
        let from = ContentVisibility::new(VisibilityClass::Blind, AssuranceLevel::Structural);
        let to = ContentVisibility::new(VisibilityClass::Blind, AssuranceLevel::Declared);
        assert!(is_downgrade(from, to));
    }

    #[test]
    fn identical_visibility_is_not_a_downgrade() {
        let v = ContentVisibility::new(VisibilityClass::Blind, AssuranceLevel::Structural);
        assert!(!is_downgrade(v, v));
    }

    #[test]
    fn terminating_to_blind_is_an_upgrade_not_a_downgrade() {
        let from = ContentVisibility::new(VisibilityClass::Terminating, AssuranceLevel::Declared);
        let to = ContentVisibility::new(VisibilityClass::Blind, AssuranceLevel::Structural);
        assert!(!is_downgrade(from, to));
    }
}
