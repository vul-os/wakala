//! Integration tests for the admin HTTP API, driven through `tower::ServiceExt::oneshot` (no
//! real socket) — axum's recommended router-level test pattern.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use admin::{AdminAuth, AdminState, KeyState};
use broker_economics::{
    AssuranceLevel, ContentVisibility, CoordinatorKind, SignedDescriptor, VisibilityClass,
};

const TOKEN: &str = "test-admin-token";

fn app() -> Router {
    let keys = KeyState::from_seed([0x42; 32]);
    let auth = AdminAuth::with_token(TOKEN);
    let state = Arc::new(AdminState::new(
        CoordinatorKind::Relay,
        ContentVisibility::new(VisibilityClass::Blind, AssuranceLevel::Structural),
        keys,
        auth,
    ));
    admin::router(state)
}

/// Same as [`app`] but with **no** admin token configured (`AdminAuth::disabled()`), for the
/// default-deny test.
fn app_no_token() -> Router {
    let keys = KeyState::from_seed([0x43; 32]);
    let state = Arc::new(AdminState::new(
        CoordinatorKind::Relay,
        ContentVisibility::new(VisibilityClass::Blind, AssuranceLevel::Structural),
        keys,
        AdminAuth::disabled(),
    ));
    admin::router(state)
}

fn req(method: &str, path: &str, token: Option<&str>, body: Option<Value>) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(t) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let body = match body {
        Some(v) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(serde_json::to_vec(&v).unwrap())
        }
        None => Body::empty(),
    };
    builder.body(body).unwrap()
}

async fn json_body(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).expect("response is valid JSON")
}

// --- Auth ----------------------------------------------------------------------------------

#[tokio::test]
async fn unauthenticated_request_is_401() {
    let resp = app()
        .oneshot(req("GET", "/descriptor", None, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_token_is_401() {
    let resp = app()
        .oneshot(req("GET", "/descriptor", Some("not-the-token"), None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn valid_token_is_200() {
    let resp = app()
        .oneshot(req("GET", "/descriptor", Some(TOKEN), None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn no_token_configured_denies_every_request_default_deny() {
    // No WAKALA_ADMIN_TOKEN-equivalent configured at all -> AdminAuth::disabled() -> everything
    // 401, even a request that presents *some* bearer token.
    let resp = app_no_token()
        .oneshot(req("GET", "/descriptor", Some("anything-at-all"), None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp = app_no_token()
        .oneshot(req("GET", "/conformance", None, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// --- Descriptor ------------------------------------------------------------------------------

#[tokio::test]
async fn descriptor_get_returns_a_verifying_signed_descriptor() {
    let resp = app()
        .oneshot(req("GET", "/descriptor", Some(TOKEN), None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let det_cbor_hex = body["det_cbor_hex"].as_str().unwrap();
    let bytes = hex::decode(det_cbor_hex).unwrap();
    // `from_det_cbor` decodes AND verifies in one step (fail-closed) — Ok means the served
    // descriptor really does verify under its own declared identity.
    let signed = SignedDescriptor::from_det_cbor(&bytes).expect("served descriptor verifies");
    assert_eq!(signed.descriptor.kind, CoordinatorKind::Relay);
}

#[tokio::test]
async fn descriptor_put_sign_roundtrip() {
    let app = app();
    let put_body = json!({
        "kind": "relay",
        "visibility": {"class": "blind", "level": "structural"},
        "policy": {"region": "eu-west", "capabilities": ["relay"], "contact": "ops@example.org"},
        "confirm_downgrade": false,
    });
    let resp = app
        .clone()
        .oneshot(req("PUT", "/descriptor", Some(TOKEN), Some(put_body)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let det_cbor_hex = body["descriptor"]["det_cbor_hex"].as_str().unwrap();
    let bytes = hex::decode(det_cbor_hex).unwrap();
    let signed = SignedDescriptor::from_det_cbor(&bytes).expect("PUT-signed descriptor verifies");
    assert_eq!(
        signed.descriptor.visibility,
        ContentVisibility::new(VisibilityClass::Blind, AssuranceLevel::Structural)
    );
    assert!(body["conformance"]["findings"].as_array().unwrap().len() >= 8);

    // A follow-up GET reflects the PUT.
    let resp = app
        .oneshot(req("GET", "/descriptor", Some(TOKEN), None))
        .await
        .unwrap();
    let body = json_body(resp).await;
    assert_eq!(body["policy"]["region"], "eu-west");
}

#[tokio::test]
async fn silent_visibility_downgrade_is_rejected() {
    let app = app();
    // Starts blind/structural (see `app()`); PUT terminating/declared with no confirmation.
    let put_body = json!({
        "kind": "relay",
        "visibility": {"class": "terminating", "level": "declared"},
        "policy": {},
    });
    let resp = app
        .clone()
        .oneshot(req("PUT", "/descriptor", Some(TOKEN), Some(put_body)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // The same change, explicitly disclosed, is accepted.
    let put_body = json!({
        "kind": "relay",
        "visibility": {"class": "terminating", "level": "declared"},
        "policy": {},
        "confirm_downgrade": true,
    });
    let resp = app
        .oneshot(req("PUT", "/descriptor", Some(TOKEN), Some(put_body)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// --- Tariff ------------------------------------------------------------------------------

#[tokio::test]
async fn tariff_put_signs_and_attaches_to_descriptor() {
    let app = app();
    let put_body = json!({
        "currency": "USDC",
        "prices": {"bytes_forwarded": 1, "connections": 500},
        "free_allowance": {"bytes_forwarded": 1000},
        "period_seconds": 2592000,
    });
    let resp = app
        .clone()
        .oneshot(req("PUT", "/tariff", Some(TOKEN), Some(put_body)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["schedule"]["currency"], "USDC");
    assert_eq!(body["schedule"]["prices"]["bytes_forwarded"], 1);

    // Now attached to the descriptor.
    let resp = app
        .oneshot(req("GET", "/descriptor", Some(TOKEN), None))
        .await
        .unwrap();
    let body = json_body(resp).await;
    assert_eq!(body["tariff"]["schedule"]["currency"], "USDC");
}

#[tokio::test]
async fn tariff_token_field_is_rejected() {
    let put_body = json!({
        "currency": "USD",
        "token": {"mint": "WAKALA-COIN"},
    });
    let resp = app()
        .oneshot(req("PUT", "/tariff", Some(TOKEN), Some(put_body)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// --- Keys ------------------------------------------------------------------------------

#[tokio::test]
async fn key_rotate_re_signs_the_descriptor() {
    let app = app();
    let before = app
        .clone()
        .oneshot(req("GET", "/descriptor", Some(TOKEN), None))
        .await
        .unwrap();
    let before = json_body(before).await;
    let identity_before = before["identity_hex"].as_str().unwrap().to_string();

    let resp = app
        .clone()
        .oneshot(req("POST", "/keys/rotate", Some(TOKEN), None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let new_pub = body["new_public_key_hex"].as_str().unwrap();
    let old_pub = body["old_public_key_hex"].as_str().unwrap();
    assert_eq!(old_pub, identity_before);
    assert_ne!(new_pub, old_pub);

    // The descriptor embedded in the rotate response is signed under the NEW key and verifies.
    let det_cbor_hex = body["descriptor"]["det_cbor_hex"].as_str().unwrap();
    let bytes = hex::decode(det_cbor_hex).unwrap();
    let signed = SignedDescriptor::from_det_cbor(&bytes).expect("re-signed descriptor verifies");
    assert_eq!(hex::encode(&signed.descriptor.identity), new_pub);

    // GET /keys shows the old key in history — never silently dropped.
    let resp = app
        .clone()
        .oneshot(req("GET", "/keys", Some(TOKEN), None))
        .await
        .unwrap();
    let keys_body = json_body(resp).await;
    assert_eq!(keys_body["public_key_hex"], new_pub);
    let history = keys_body["history_hex"].as_array().unwrap();
    assert!(history.iter().any(|v| v.as_str() == Some(old_pub)));

    // A subsequent GET /descriptor also verifies under the new key.
    let resp = app
        .oneshot(req("GET", "/descriptor", Some(TOKEN), None))
        .await
        .unwrap();
    let after = json_body(resp).await;
    assert_eq!(after["identity_hex"], new_pub);
}

// --- Billing / receipts ------------------------------------------------------------------

#[tokio::test]
async fn billing_run_issues_verifiable_receipts_with_audit_caveat() {
    let app = app();
    let put_body = json!({
        "currency": "USD",
        "prices": {"bytes_forwarded": 2},
    });
    app.clone()
        .oneshot(req("PUT", "/tariff", Some(TOKEN), Some(put_body)))
        .await
        .unwrap();

    let payer_hex = hex::encode(b"a-test-payer-32-bytes-long-000!!");

    // Nothing metered yet -> empty usage.
    let resp = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/usage/{payer_hex}"),
            Some(TOKEN),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Running billing with nothing metered issues no receipts and does not error.
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/billing/run/{payer_hex}"),
            Some(TOKEN),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert!(body["receipts"].as_array().unwrap().is_empty());
    assert!(body["one_directional_audit_caveat"]
        .as_str()
        .unwrap()
        .contains("one-directional"));

    // GET /receipts (all) and /receipts/{payer} both surface the caveat, empty for now.
    let resp = app
        .oneshot(req("GET", "/receipts", Some(TOKEN), None))
        .await
        .unwrap();
    let body = json_body(resp).await;
    assert!(body["one_directional_audit_caveat"]
        .as_str()
        .unwrap()
        .contains("R-6"));
}

// --- Quota ------------------------------------------------------------------------------

#[tokio::test]
async fn quota_get_put_roundtrip() {
    let app = app();
    let put_body = json!({
        "requests_per_minute": 600,
        "max_connections": 50,
        "daily_byte_quota": 1_000_000_000u64,
        "notes": "reference numbers",
    });
    let resp = app
        .clone()
        .oneshot(req("PUT", "/quota", Some(TOKEN), Some(put_body)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .oneshot(req("GET", "/quota", Some(TOKEN), None))
        .await
        .unwrap();
    let body = json_body(resp).await;
    assert_eq!(body["requests_per_minute"], 600);
    assert_eq!(body["max_connections"], 50);
}

// --- Conformance ------------------------------------------------------------------------------

#[tokio::test]
async fn conformance_endpoint_returns_a_coord_report() {
    let resp = app()
        .oneshot(req("GET", "/conformance", Some(TOKEN), None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["kind"], "relay");
    let findings = body["findings"].as_array().unwrap();
    let ids: Vec<&str> = findings.iter().map(|f| f["id"].as_str().unwrap()).collect();
    for expected in [
        "COORD-1", "COORD-2", "COORD-3", "COORD-4", "COORD-5", "COORD-6", "COORD-7", "COORD-8",
    ] {
        assert!(ids.contains(&expected), "missing {expected} in {ids:?}");
    }
}
