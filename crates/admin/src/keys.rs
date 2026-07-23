//! Operator key management (CONTRACT §2.1 — the accountable identity).
//!
//! [`KeyState`] holds the operator's real `kotva-core` `IdentityKey` behind a lock so it can be
//! rotated in place. Rotation generates a fresh key and makes it current, but — the whole point
//! of §2.1's "accountable identity" — it MUST NOT silently drop the old identity anywhere this
//! crate persists state: [`KeyState::rotate`] appends the outgoing public key to `history`
//! (never cleared), and [`KeysDto`]/[`get_keys`] surface that trail over the admin API.

use std::sync::{Arc, RwLock};

use axum::extract::State;
use axum::Json;
use broker_economics::IdentityKey;
use serde::Serialize;

use crate::descriptor::{sign_descriptor, to_dto, SignedDescriptorDto};
use crate::AdminState;

/// The operator's signing identity, rotatable in place without losing the trail of prior keys.
pub struct KeyState {
    current: RwLock<IdentityKey>,
    /// Every public key this identity has rotated away from, oldest first. Never cleared.
    history: RwLock<Vec<Vec<u8>>>,
}

impl KeyState {
    /// Load a deterministic identity from a 32-byte Ed25519 seed (operator-configured, e.g. from
    /// a seed file — see `config.rs`).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        KeyState {
            current: RwLock::new(IdentityKey::from_seed(&seed)),
            history: RwLock::new(Vec::new()),
        }
    }

    /// A fresh, OS-CSPRNG-generated identity (dev/reference use — see `main.rs`'s loud warning
    /// when no seed is configured: this key does not survive a restart).
    pub fn generate() -> Self {
        KeyState {
            current: RwLock::new(IdentityKey::generate()),
            history: RwLock::new(Vec::new()),
        }
    }

    /// The current identity's public key.
    pub fn public(&self) -> Vec<u8> {
        self.current.read().expect("key lock poisoned").public()
    }

    /// Run `f` against the current signing key without ever cloning it out (`IdentityKey` has no
    /// `Clone` — it holds a private key, so every use goes through a borrow like this one).
    pub fn with_current<R>(&self, f: impl FnOnce(&IdentityKey) -> R) -> R {
        let guard = self.current.read().expect("key lock poisoned");
        f(&guard)
    }

    /// Generate a fresh identity and make it current. Returns `(old_public, new_public)`. The
    /// outgoing public key is appended to [`Self::history`] — never dropped (§2.1).
    pub fn rotate(&self) -> (Vec<u8>, Vec<u8>) {
        let mut cur = self.current.write().expect("key lock poisoned");
        let old_pub = cur.public();
        let new_key = IdentityKey::generate();
        let new_pub = new_key.public();
        *cur = new_key;
        drop(cur);
        self.history
            .write()
            .expect("key lock poisoned")
            .push(old_pub.clone());
        (old_pub, new_pub)
    }

    /// Every public key rotated away from, oldest first (empty if never rotated).
    pub fn history(&self) -> Vec<Vec<u8>> {
        self.history.read().expect("key lock poisoned").clone()
    }
}

#[derive(Serialize)]
pub struct KeysDto {
    pub public_key_hex: String,
    /// Prior public keys, oldest first — the accountable-identity trail (§2.1). Kept even after
    /// rotation so nothing referencing an old key is silently orphaned.
    pub history_hex: Vec<String>,
}

pub async fn get_keys(State(state): State<Arc<AdminState>>) -> Json<KeysDto> {
    Json(KeysDto {
        public_key_hex: hex::encode(state.keys.public()),
        history_hex: state.keys.history().into_iter().map(hex::encode).collect(),
    })
}

#[derive(Serialize)]
pub struct RotateResponse {
    pub old_public_key_hex: String,
    pub new_public_key_hex: String,
    /// The descriptor, RE-SIGNED under the new key (its `identity` field now points at
    /// `new_public_key_hex`) — a rotation without this would leave a stale, now-unverifiable
    /// descriptor on offer.
    pub descriptor: SignedDescriptorDto,
}

pub async fn rotate_keys(State(state): State<Arc<AdminState>>) -> Json<RotateResponse> {
    let (old_pub, new_pub) = state.keys.rotate();
    let signed = sign_descriptor(&state);
    Json(RotateResponse {
        old_public_key_hex: hex::encode(old_pub),
        new_public_key_hex: hex::encode(new_pub),
        descriptor: to_dto(&signed),
    })
}
