//! `wakala-admin` — serves the operator admin API (see `admin::router`) over HTTP, bound to
//! loopback by default (`WAKALA_ADMIN_BIND` overrides). Config is entirely environment-driven —
//! see `admin::config::AdminBinConfig`.

use std::sync::Arc;

use admin::config::AdminBinConfig;
use admin::{AdminAuth, AdminState, KeyState};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cfg = match AdminBinConfig::from_env() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("wakala-admin: config error: {e}");
            std::process::exit(1);
        }
    };

    let keys = match cfg.key_seed {
        Some(seed) => KeyState::from_seed(seed),
        None => {
            let ks = KeyState::generate();
            tracing::warn!(
                public_key = %hex::encode(ks.public()),
                "no WAKALA_ADMIN_KEY_SEED_HEX/WAKALA_ADMIN_KEY_FILE configured — generated an \
                 EPHEMERAL operator identity; it will NOT survive a restart. Configure a \
                 persisted seed for anything but local dev (CONTRACT §2.1: this is the \
                 accountable identity)."
            );
            ks
        }
    };

    let auth = match &cfg.admin_token {
        Some(t) => AdminAuth::with_token(t.clone()),
        None => {
            tracing::warn!(
                "WAKALA_ADMIN_TOKEN not set — the admin API is DISABLED (fail-closed, SEC-1): \
                 every request will be 401 until a token is configured."
            );
            AdminAuth::disabled()
        }
    };

    let state = Arc::new(AdminState::new(cfg.kind, cfg.visibility, keys, auth));
    let app = admin::router(state);

    let listener = tokio::net::TcpListener::bind(cfg.bind_addr)
        .await
        .unwrap_or_else(|e| panic!("wakala-admin: failed to bind {}: {e}", cfg.bind_addr));

    tracing::info!(
        addr = %cfg.bind_addr,
        "wakala-admin listening — operator-local control plane; do not expose this bind address \
         beyond the operator's own reach (see admin::auth / crate docs)"
    );

    axum::serve(listener, app)
        .await
        .expect("wakala-admin: server error");
}
