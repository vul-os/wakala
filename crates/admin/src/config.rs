//! Binary config for `ephor-admin` (`src/main.rs`), read from the environment. A library
//! consumer that embeds [`crate::AdminState`] directly (e.g. inside a coordinator-kind binary)
//! is free to skip this and construct `AdminState`/`KeyState`/`AdminAuth` itself.

use std::net::SocketAddr;

use broker_economics::{AssuranceLevel, ContentVisibility, CoordinatorKind, VisibilityClass};

/// `EPHOR_ADMIN_BIND` — defaults to loopback (operator-local; see `auth.rs`/`lib.rs` module
/// docs on why this surface must never be assumed safe to expose beyond the operator's own host).
const DEFAULT_BIND: &str = "127.0.0.1:8090";

pub struct AdminBinConfig {
    pub bind_addr: SocketAddr,
    /// `None` = no `EPHOR_ADMIN_TOKEN` configured — the server still starts, but
    /// [`crate::auth::AdminAuth::disabled`] refuses every request (fail-closed, SEC-1).
    pub admin_token: Option<String>,
    pub kind: CoordinatorKind,
    pub visibility: ContentVisibility,
    /// A 32-byte Ed25519 seed, if `EPHOR_ADMIN_KEY_SEED_HEX`/`EPHOR_ADMIN_KEY_FILE` was
    /// configured. `None` means `main.rs` generates an ephemeral key (loudly, at startup).
    pub key_seed: Option<[u8; 32]>,
}

impl AdminBinConfig {
    pub fn from_env() -> Result<Self, String> {
        let bind_addr = match std::env::var("EPHOR_ADMIN_BIND") {
            Ok(v) => v
                .parse()
                .map_err(|e| format!("EPHOR_ADMIN_BIND {v:?} is not a socket address: {e}"))?,
            Err(_) => DEFAULT_BIND.parse().expect("DEFAULT_BIND is valid"),
        };

        let admin_token = std::env::var("EPHOR_ADMIN_TOKEN").ok();

        let kind = match std::env::var("EPHOR_ADMIN_KIND") {
            Ok(v) => CoordinatorKind::from_wire_str(&v).ok_or_else(|| {
                format!("EPHOR_ADMIN_KIND {v:?} is not a known coordinator kind")
            })?,
            Err(_) => CoordinatorKind::Relay,
        };

        let visibility =
            match (
                std::env::var("EPHOR_ADMIN_VISIBILITY_CLASS").ok(),
                std::env::var("EPHOR_ADMIN_VISIBILITY_LEVEL").ok(),
            ) {
                (Some(c), Some(l)) => parse_visibility(&c, &l)?,
                (None, None) => kind.typical_visibility().unwrap_or(ContentVisibility::new(
                    VisibilityClass::Terminating,
                    AssuranceLevel::Declared,
                )),
                _ => return Err(
                    "EPHOR_ADMIN_VISIBILITY_CLASS and EPHOR_ADMIN_VISIBILITY_LEVEL must both \
                     be set together, or both omitted"
                        .into(),
                ),
            };

        let key_seed = match std::env::var("EPHOR_ADMIN_KEY_SEED_HEX") {
            Ok(v) => Some(parse_seed_hex(&v)?),
            Err(_) => match std::env::var("EPHOR_ADMIN_KEY_FILE") {
                Ok(path) => {
                    let contents = std::fs::read_to_string(&path)
                        .map_err(|e| format!("reading EPHOR_ADMIN_KEY_FILE {path:?}: {e}"))?;
                    Some(parse_seed_hex(contents.trim())?)
                }
                Err(_) => None,
            },
        };

        Ok(AdminBinConfig {
            bind_addr,
            admin_token,
            kind,
            visibility,
            key_seed,
        })
    }
}

fn parse_visibility(class: &str, level: &str) -> Result<ContentVisibility, String> {
    let class = match class {
        "blind" => VisibilityClass::Blind,
        "blind-routing" => VisibilityClass::BlindRouting,
        "terminating" => VisibilityClass::Terminating,
        other => return Err(format!("unknown visibility class {other:?}")),
    };
    let level = match level {
        "structural" => AssuranceLevel::Structural,
        "attested" => AssuranceLevel::Attested,
        "declared" => AssuranceLevel::Declared,
        other => return Err(format!("unknown assurance level {other:?}")),
    };
    Ok(ContentVisibility::new(class, level))
}

fn parse_seed_hex(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|e| format!("key seed is not valid hex: {e}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("key seed must be 32 bytes, got {}", v.len()))?;
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_hex_round_trips() {
        let seed = [7u8; 32];
        let hex_str = hex::encode(seed);
        assert_eq!(parse_seed_hex(&hex_str).unwrap(), seed);
    }

    #[test]
    fn wrong_length_seed_is_rejected() {
        assert!(parse_seed_hex("aabb").is_err());
    }
}
