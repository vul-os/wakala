//! Admin bearer-token authentication (SEC-1 fail-closed default-deny).
//!
//! This admin API manages the operator's signing key and re-signs the descriptor/tariff — an
//! unauthenticated admin surface would be a critical hole, not a convenience gap. So:
//!
//! - [`AdminAuth::disabled`] (no token configured) refuses **every** request `401` — the API is
//!   inert by default, not merely undocumented;
//! - a missing, malformed, or wrong bearer token is `401`;
//! - a matching token is compared in **constant time** ([`ct_eq`]) so a timing side-channel can't
//!   leak the token a byte at a time.
//!
//! This is intentionally the same shape as `crates/gateway/src/admin.rs`'s `AdminAuth` (this
//! crate does not depend on `gateway`, so it is reimplemented here rather than shared — see
//! `lib.rs` module doc on why every kind's admin surface stays composed, not coupled).
//!
//! Deployment note (documented, not enforced by this module): this API is **operator-local**. The
//! binary (`src/main.rs`/`bin/ephor-admin`) defaults its bind address to loopback
//! (`127.0.0.1`) — reachability beyond that host, and the admin token itself, are the operator's
//! own config/network responsibility (e.g. an SSH tunnel or a private network), same as any other
//! control-plane surface. This is *not* a user delivery path — see `lib.rs`.

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::sync::Arc;

use crate::error::AdminError;
use crate::AdminState;

/// The admin bearer-token authenticator.
#[derive(Debug, Clone, Default)]
pub struct AdminAuth {
    token: Option<String>,
}

impl AdminAuth {
    /// No token configured — every [`Self::authorize`] call is `false` (the API is off).
    pub fn disabled() -> Self {
        AdminAuth { token: None }
    }

    /// Accepts exactly `token`. A blank/whitespace-only token is treated as **disabled**
    /// (fail-closed): an empty secret must never authorize anything.
    pub fn with_token(token: impl Into<String>) -> Self {
        let t = token.into();
        if t.trim().is_empty() {
            AdminAuth { token: None }
        } else {
            AdminAuth { token: Some(t) }
        }
    }

    /// Whether an admin token is configured at all (the API is live).
    pub fn is_enabled(&self) -> bool {
        self.token.is_some()
    }

    /// Authorize a presented bearer token in constant time. `None` (no header) or any mismatch
    /// is `false`; with no token configured, always `false` (fail-closed).
    pub fn authorize(&self, presented: Option<&str>) -> bool {
        let Some(expected) = &self.token else {
            return false;
        };
        let Some(presented) = presented else {
            return false;
        };
        ct_eq(expected.as_bytes(), presented.as_bytes())
    }
}

/// Constant-time byte-slice equality (no early return on the first differing byte). A length
/// mismatch short-circuits (a length difference is not secret); equal-length comparison is
/// data-independent in its number of operations.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn bearer_token(req: &Request) -> Option<String> {
    let value = req.headers().get(axum::http::header::AUTHORIZATION)?;
    let value = value.to_str().ok()?;
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .map(str::to_string)
}

/// The axum middleware every protected route runs through (wired in [`crate::router`]).
pub async fn require_auth(
    State(state): State<Arc<AdminState>>,
    req: Request,
    next: Next,
) -> Response {
    let token = bearer_token(&req);
    if state.auth.authorize(token.as_deref()) {
        next.run(req).await
    } else {
        AdminError::Unauthorized.into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_denies_everything() {
        let a = AdminAuth::disabled();
        assert!(!a.is_enabled());
        assert!(!a.authorize(None));
        assert!(!a.authorize(Some("anything")));
    }

    #[test]
    fn blank_token_is_treated_as_disabled() {
        let a = AdminAuth::with_token("   ");
        assert!(!a.is_enabled());
        assert!(!a.authorize(Some("   ")));
    }

    #[test]
    fn correct_token_authorizes() {
        let a = AdminAuth::with_token("s3cr3t");
        assert!(a.is_enabled());
        assert!(a.authorize(Some("s3cr3t")));
        assert!(!a.authorize(Some("wrong")));
        assert!(!a.authorize(None));
    }

    #[test]
    fn ct_eq_matches_naive_equality() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}
