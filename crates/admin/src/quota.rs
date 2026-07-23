//! Quota / rate policy: operator-set numbers (CONTRACT §6: "the numbers are operator policy"),
//! stored in-memory for this reference. Not wired to any enforcement point — a real coordinator
//! kind reads this crate's [`QuotaPolicy`] type and enforces it on its own data plane; this
//! surface is only the operator's place to declare/inspect the numbers.

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaPolicy {
    /// Requests admitted per minute, per payer. `None` = no configured cap.
    #[serde(default)]
    pub requests_per_minute: Option<u64>,
    /// Concurrent connections admitted, per payer. `None` = no configured cap.
    #[serde(default)]
    pub max_connections: Option<u64>,
    /// Bytes admitted per day, per payer. `None` = no configured cap.
    #[serde(default)]
    pub daily_byte_quota: Option<u64>,
    #[serde(default)]
    pub notes: Option<String>,
}

use crate::AdminState;

pub async fn get_quota(State(state): State<Arc<AdminState>>) -> Json<QuotaPolicy> {
    Json(state.quota.read().expect("quota lock poisoned").clone())
}

pub async fn put_quota(
    State(state): State<Arc<AdminState>>,
    Json(body): Json<QuotaPolicy>,
) -> Json<QuotaPolicy> {
    *state.quota.write().expect("quota lock poisoned") = body.clone();
    Json(body)
}
