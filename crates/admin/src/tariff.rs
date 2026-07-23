//! Tariff configuration: GET/PUT the operator's [`TariffSchedule`] (currency, per-`ResourceKind`
//! price, free allowance — operator *numbers*, CONTRACT §6), sign it into a
//! [`broker_economics::Tariff`], and attach it to the descriptor.
//!
//! **No token.** CONTRACT §6 / DIRECTION §5: KOTVA mints no protocol token, ever. The PUT request
//! DTO carries an explicit `token` field for exactly one reason — so a client that tries to
//! configure one gets a clear, on-purpose rejection (`400`) instead of a generic
//! "unknown field" error indistinguishable from a typo.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};

use broker_billing::{ResourceKind, TariffSchedule};
use broker_economics::Tariff;

use crate::error::AdminError;
use crate::AdminState;

pub(crate) fn resource_kind_name(k: ResourceKind) -> &'static str {
    match k {
        ResourceKind::BytesForwarded => "bytes_forwarded",
        ResourceKind::Connections => "connections",
        ResourceKind::Messages => "messages",
        ResourceKind::ComputeSeconds => "compute_seconds",
    }
}

fn resource_kind_from_name(s: &str) -> Result<ResourceKind, AdminError> {
    Ok(match s {
        "bytes_forwarded" => ResourceKind::BytesForwarded,
        "connections" => ResourceKind::Connections,
        "messages" => ResourceKind::Messages,
        "compute_seconds" => ResourceKind::ComputeSeconds,
        other => {
            return Err(AdminError::BadRequest(format!(
                "unknown resource kind {other:?} (want bytes_forwarded|connections|messages|compute_seconds)"
            )))
        }
    })
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TariffScheduleDto {
    pub currency: String,
    #[serde(default)]
    pub prices: BTreeMap<String, u64>,
    #[serde(default)]
    pub free_allowance: BTreeMap<String, u64>,
    #[serde(default)]
    pub period_seconds: Option<u64>,
    /// MUST be absent/null — see the module doc. Present only to give a misdirected "configure a
    /// token" attempt an explicit rejection.
    #[serde(default)]
    pub token: Option<serde_json::Value>,
}

fn schedule_from_dto(dto: TariffScheduleDto) -> Result<TariffSchedule, AdminError> {
    if dto.token.is_some() {
        return Err(AdminError::BadRequest(
            "no protocol token: KOTVA mints none, ever (CONTRACT §6, DIRECTION §5) — price in \
             an existing currency/asset (\"currency\") instead, and drop the \"token\" field"
                .into(),
        ));
    }
    let mut prices = BTreeMap::new();
    for (name, price) in dto.prices {
        prices.insert(resource_kind_from_name(&name)?, price);
    }
    let mut free_allowance = BTreeMap::new();
    for (name, units) in dto.free_allowance {
        free_allowance.insert(resource_kind_from_name(&name)?, units);
    }
    Ok(TariffSchedule {
        currency: dto.currency,
        prices,
        free_allowance,
        period_seconds: dto.period_seconds,
    })
}

fn schedule_to_dto(s: &TariffSchedule) -> TariffScheduleDto {
    TariffScheduleDto {
        currency: s.currency.clone(),
        prices: s
            .prices
            .iter()
            .map(|(k, v)| (resource_kind_name(*k).to_string(), *v))
            .collect(),
        free_allowance: s
            .free_allowance
            .iter()
            .map(|(k, v)| (resource_kind_name(*k).to_string(), *v))
            .collect(),
        period_seconds: s.period_seconds,
        token: None,
    }
}

#[derive(Serialize)]
pub struct TariffDto {
    pub identity_hex: String,
    pub schedule: TariffScheduleDto,
    pub sig_hex: String,
}

/// Decode a signed [`Tariff`] back into its display DTO. `Tariff::verify` is checked here too —
/// defense in depth, since every `Tariff` this crate ever stores was signed by itself, but a
/// stale/tampered value should never be silently displayed as if it were valid.
pub(crate) fn tariff_to_dto(t: &Tariff) -> Result<TariffDto, AdminError> {
    t.verify()
        .map_err(|e| AdminError::Internal(format!("stored tariff no longer verifies: {e}")))?;
    let schedule = TariffSchedule::from_tariff(t)
        .map_err(|e| AdminError::Internal(format!("stored tariff schedule malformed: {e}")))?;
    Ok(TariffDto {
        identity_hex: hex::encode(&t.identity),
        schedule: schedule_to_dto(&schedule),
        sig_hex: hex::encode(&t.sig),
    })
}

pub async fn get_tariff(
    State(state): State<Arc<AdminState>>,
) -> Result<Json<Option<TariffDto>>, AdminError> {
    let t = state.tariff.read().expect("tariff lock poisoned").clone();
    let dto = t.map(|t| tariff_to_dto(&t)).transpose()?;
    Ok(Json(dto))
}

pub async fn put_tariff(
    State(state): State<Arc<AdminState>>,
    Json(body): Json<TariffScheduleDto>,
) -> Result<Json<TariffDto>, AdminError> {
    let schedule = schedule_from_dto(body)?;
    let signed = state.keys.with_current(|ik| schedule.sign(ik));
    *state.tariff.write().expect("tariff lock poisoned") = Some(signed.clone());
    Ok(Json(tariff_to_dto(&signed)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_kind_names_round_trip() {
        for k in [
            ResourceKind::BytesForwarded,
            ResourceKind::Connections,
            ResourceKind::Messages,
            ResourceKind::ComputeSeconds,
        ] {
            assert_eq!(resource_kind_from_name(resource_kind_name(k)).unwrap(), k);
        }
        assert!(resource_kind_from_name("not-a-kind").is_err());
    }

    #[test]
    fn token_field_is_rejected() {
        let dto = TariffScheduleDto {
            currency: "USD".into(),
            token: Some(serde_json::json!({"mint": true})),
            ..Default::default()
        };
        let err = schedule_from_dto(dto).expect_err("must reject a token");
        assert!(matches!(err, AdminError::BadRequest(_)));
    }

    #[test]
    fn schedule_dto_round_trips() {
        let mut prices = BTreeMap::new();
        prices.insert("bytes_forwarded".to_string(), 1u64);
        let dto = TariffScheduleDto {
            currency: "USDC".into(),
            prices,
            free_allowance: BTreeMap::new(),
            period_seconds: Some(3600),
            token: None,
        };
        let schedule = schedule_from_dto(dto).expect("valid schedule");
        let back = schedule_to_dto(&schedule);
        assert_eq!(back.currency, "USDC");
        assert_eq!(back.prices.get("bytes_forwarded"), Some(&1));
    }
}
