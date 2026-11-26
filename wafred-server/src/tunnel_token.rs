//! Minting of the short-lived session tokens the edges verify.
//!
//! The signing key is **derived from `jwt_secret`** with a domain-separated
//! hash, so there is no new secret to store, back up or rotate independently:
//! the key exists only in the control plane's memory and rotates with the JWT
//! secret. The public half travels in every rule bundle, which is what lets an
//! edge verify a token without ever holding the connector's credential.
//!
//! Deriving rather than storing is deliberate: a stored Ed25519 key would be a
//! second secret with its own backup/restore problem, and this one has no
//! reason to outlive the deployment's existing secret.

use std::sync::OnceLock;

use anyhow::{anyhow, Result};
use ring::signature::{Ed25519KeyPair, KeyPair};
use sha2::{Digest, Sha256};

use wafred_tunnel::token::{self, SessionTokenClaims};

/// Domain separator: the same `jwt_secret` must never yield the same key for
/// two different purposes.
const SEED_CONTEXT: &[u8] = b"wafred-tunnel-session-token-v1";

struct Signer {
    key: Ed25519KeyPair,
    public_hex: String,
}

static SIGNER: OnceLock<Signer> = OnceLock::new();

/// Derives the signing key from the deployment's JWT secret.
///
/// Idempotent: the first call wins, later calls are no-ops, so a hot reload of
/// the configuration cannot silently swap the key out from under the edges.
pub fn init(jwt_secret: &str) {
    if SIGNER.get().is_some() {
        return;
    }
    let mut hasher = Sha256::new();
    hasher.update(SEED_CONTEXT);
    hasher.update(jwt_secret.as_bytes());
    let seed = hasher.finalize();
    match Ed25519KeyPair::from_seed_unchecked(seed.as_slice()) {
        Ok(key) => {
            let public_hex = token::public_key_hex(key.public_key().as_ref());
            let _ = SIGNER.set(Signer { key, public_hex });
        },
        Err(err) => {
            tracing::error!(error = %err, "cannot derive the tunnel session-token key");
        },
    }
}

/// Hex public key the rule bundle carries. Empty before [`init`].
pub fn public_key_hex() -> String {
    SIGNER
        .get()
        .map(|signer| signer.public_hex.clone())
        .unwrap_or_default()
}

/// Mints a token for `tunnel_id`, valid for `ttl_secs`.
///
/// Returns the token and its expiry (unix seconds), or an error when the key
/// was never initialised — the caller then refuses the pairing rather than
/// handing out a token no edge can verify.
pub fn mint(tunnel_id: &str, ttl_secs: u64) -> Result<(String, i64)> {
    let signer = SIGNER.get().ok_or_else(|| {
        anyhow!("the tunnel session-token key is not initialised")
    })?;
    let now = chrono::Utc::now().timestamp();
    let ttl = ttl_secs.clamp(60, 86_400) as i64;
    let claims = SessionTokenClaims {
        tunnel_id: tunnel_id.to_string(),
        issued_at: now,
        expires_at: now + ttl,
    };
    let payload = token::payload_bytes(&claims);
    let signature = signer.key.sign(&payload);
    Ok((
        token::encode(&claims, signature.as_ref()),
        claims.expires_at,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minted_token_verifies_against_the_published_key() {
        // The tests share one process-wide key; initialise it once.
        init("unit-test-jwt-secret-value");
        let (token, expires_at) = mint("tunnel-1", 600).unwrap();
        let now = chrono::Utc::now().timestamp();
        assert!(expires_at > now);
        let claims = token::verify(&token, &public_key_hex(), "tunnel-1", now)
            .expect("the freshly minted token must verify");
        assert_eq!(claims.expires_at, expires_at);
        // …and not for another tunnel.
        assert!(
            token::verify(&token, &public_key_hex(), "tunnel-2", now).is_err()
        );
    }

    #[test]
    fn the_ttl_is_clamped() {
        init("unit-test-jwt-secret-value");
        let (_, expires_at) = mint("tunnel-1", 1).unwrap();
        let now = chrono::Utc::now().timestamp();
        assert!(
            expires_at >= now + 60,
            "a token must live at least a minute"
        );
    }
}
