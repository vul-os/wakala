//! A uniform admin-API error → HTTP response mapping.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

/// Every error an admin handler can return. Deliberately coarse (four HTTP statuses) — this is
/// an operator-local control plane, not a public API that needs a rich error taxonomy.
#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    /// Missing/invalid bearer token (SEC-1 fail-closed default-deny — see `auth.rs`).
    #[error("unauthorized")]
    Unauthorized,
    /// Malformed request body/path (bad hex, unknown enum string, ...).
    #[error("bad request: {0}")]
    BadRequest(String),
    /// A referenced resource does not exist.
    #[error("not found: {0}")]
    NotFound(String),
    /// The request is well-formed but conflicts with current state (e.g. an undisclosed
    /// visibility downgrade, CONTRACT §3.2).
    #[error("conflict: {0}")]
    Conflict(String),
    /// Anything else — a bug or an invariant violated inside this crate's own signing/encoding.
    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        let status = match &self {
            AdminError::Unauthorized => StatusCode::UNAUTHORIZED,
            AdminError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AdminError::NotFound(_) => StatusCode::NOT_FOUND,
            AdminError::Conflict(_) => StatusCode::CONFLICT,
            AdminError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (
            status,
            Json(ErrorBody {
                error: self.to_string(),
            }),
        )
            .into_response()
    }
}
