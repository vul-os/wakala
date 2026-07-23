//! Metering + receipts view (CONTRACT §6) and an operator-triggered billing run.
//!
//! GET-only for the raw meter/receipt data, per the wave brief. The one write path here,
//! [`run_billing`], is deliberately explicit and operator-triggered (evaluate the current
//! tariff against a payer's accumulated usage, issue signed receipts, reset the meter) — a real
//! coordinator's data plane is expected to call [`broker_billing::Meter::record`] directly
//! (through the same [`crate::AdminState::meter`] handle this crate constructs), not through this
//! HTTP surface; `run_billing` exists so an operator can close out a billing period, or a demo/
//! test can produce real signed receipts, without reaching into process-internal state.
//!
//! ## The one-directional audit — read before trusting a receipt list
//! [`ReceiptsResponse::one_directional_audit_caveat`] is not decoration: `UsageReceipt::verify()`
//! (surfaced here as [`ReceiptDto::verifies`]) proves the operator's key signed a claim, never
//! that the claim is true, and never that every chargeable operation was receipted at all. See
//! `broker_billing::receipt`'s module doc for the full disclosure (CONTRACT §6, R-6).

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::Json;
use serde::Serialize;

use broker_billing::{BilledOperation, TariffSchedule};
use broker_economics::UsageReceipt;

use crate::error::AdminError;
use crate::tariff::resource_kind_name;
use crate::AdminState;

fn decode_payer(payer_hex: &str) -> Result<Vec<u8>, AdminError> {
    hex::decode(payer_hex).map_err(|e| AdminError::BadRequest(format!("bad payer hex: {e}")))
}

#[derive(Serialize)]
pub struct UsageDto {
    pub payer_hex: String,
    pub usage: BTreeMap<String, u64>,
}

pub async fn get_usage(
    State(state): State<Arc<AdminState>>,
    Path(payer_hex): Path<String>,
) -> Result<Json<UsageDto>, AdminError> {
    let payer = decode_payer(&payer_hex)?;
    let usage = state.meter.usage(&payer);
    Ok(Json(UsageDto {
        payer_hex,
        usage: usage
            .into_iter()
            .map(|(k, v)| (resource_kind_name(k).to_string(), v))
            .collect(),
    }))
}

const AUDIT_CAVEAT: &str = "a signed usage receipt proves the operator's key produced this \
claim; it does NOT prove the claim is true, and it cannot prove every chargeable operation was \
receipted at all — the one-directional audit (CONTRACT §6, R-6). Disclosed, not hidden.";

#[derive(Serialize)]
pub struct ReceiptDto {
    pub identity_hex: String,
    pub sig_hex: String,
    pub payer_hex: String,
    pub kind: String,
    pub metered_units: u64,
    pub billed_units: u64,
    pub amount: u64,
    pub currency: String,
    pub sequence: u64,
    /// The result of `UsageReceipt::verify()` — see the module doc: this proves attribution,
    /// never completeness or truth.
    pub verifies: bool,
}

fn receipt_dto(r: &UsageReceipt) -> ReceiptDto {
    let verifies = r.verify().is_ok();
    let op = BilledOperation::from_receipt(r).ok();
    ReceiptDto {
        identity_hex: hex::encode(&r.identity),
        sig_hex: hex::encode(&r.sig),
        payer_hex: op
            .as_ref()
            .map(|o| hex::encode(&o.payer))
            .unwrap_or_default(),
        kind: op
            .as_ref()
            .map(|o| resource_kind_name(o.kind).to_string())
            .unwrap_or_default(),
        metered_units: op.as_ref().map(|o| o.metered_units).unwrap_or(0),
        billed_units: op.as_ref().map(|o| o.billed_units).unwrap_or(0),
        amount: op.as_ref().map(|o| o.amount).unwrap_or(0),
        currency: op.as_ref().map(|o| o.currency.clone()).unwrap_or_default(),
        sequence: op.as_ref().map(|o| o.sequence).unwrap_or(0),
        verifies,
    }
}

#[derive(Serialize)]
pub struct ReceiptsResponse {
    pub receipts: Vec<ReceiptDto>,
    pub one_directional_audit_caveat: &'static str,
}

pub async fn get_receipts(State(state): State<Arc<AdminState>>) -> Json<ReceiptsResponse> {
    let log = state.receipts.read().expect("receipts lock poisoned");
    Json(ReceiptsResponse {
        receipts: log.receipts().iter().map(receipt_dto).collect(),
        one_directional_audit_caveat: AUDIT_CAVEAT,
    })
}

pub async fn get_receipts_for_payer(
    State(state): State<Arc<AdminState>>,
    Path(payer_hex): Path<String>,
) -> Result<Json<ReceiptsResponse>, AdminError> {
    let payer = decode_payer(&payer_hex)?;
    let log = state.receipts.read().expect("receipts lock poisoned");
    let receipts = log
        .receipts()
        .iter()
        .filter(|r| {
            BilledOperation::from_receipt(r)
                .map(|o| o.payer == payer)
                .unwrap_or(false)
        })
        .map(receipt_dto)
        .collect();
    Ok(Json(ReceiptsResponse {
        receipts,
        one_directional_audit_caveat: AUDIT_CAVEAT,
    }))
}

/// Evaluate `payer`'s current accumulated usage against the configured tariff, issue one signed
/// receipt per line item, and reset the meter (the billed snapshot is consumed). `409` if no
/// tariff is configured yet.
pub async fn run_billing(
    State(state): State<Arc<AdminState>>,
    Path(payer_hex): Path<String>,
) -> Result<Json<ReceiptsResponse>, AdminError> {
    let payer = decode_payer(&payer_hex)?;
    let tariff = state
        .tariff
        .read()
        .expect("tariff lock poisoned")
        .clone()
        .ok_or_else(|| AdminError::Conflict("no tariff configured; PUT /tariff first".into()))?;
    tariff
        .verify()
        .map_err(|e| AdminError::Internal(format!("stored tariff no longer verifies: {e}")))?;
    let schedule = TariffSchedule::from_tariff(&tariff)
        .map_err(|e| AdminError::Internal(format!("stored tariff schedule malformed: {e}")))?;

    let usage = state.meter.reset(&payer);
    let bill = schedule
        .evaluate(&usage)
        .map_err(|e| AdminError::BadRequest(e.to_string()))?;

    let issued = state.keys.with_current(|ik| {
        let mut log = state.receipts.write().expect("receipts lock poisoned");
        log.issue_for_bill(&payer, &bill, ik)
    });

    Ok(Json(ReceiptsResponse {
        receipts: issued.iter().map(receipt_dto).collect(),
        one_directional_audit_caveat: AUDIT_CAVEAT,
    }))
}
