//! Short-lived session tokens.
//!
//! The connector does not present a reusable secret to an edge. It presents a
//! token the control plane signed with an Ed25519 key; the edge only holds the
//! public key (in the rule bundle) and checks the signature, the tunnel id and
//! the expiry. A compromised edge therefore learns a token that is useless
//! after its lifetime and cannot be replayed against another tunnel.
//!
//! The format is deliberately boring — `v1.<hex(payload)>.<hex(signature)>`
//! with `payload = "<tunnel_id>|<issued_at>|<expires_at>"` — so both ends parse
//! the same bytes without a canonicalisation step, and no JSON field order can
//! change the signed content.
//!
//! Signing lives in the control plane (`pingwaf-server`); verification lives
//! here so the edge and the control plane cannot drift apart.

use anyhow::{Result, anyhow, bail};
use ring::signature::{ED25519, UnparsedPublicKey};

/// Prefix of every token this build understands.
pub const TOKEN_VERSION: &str = "v1";

/// Clock skew tolerated when checking the validity window.
const LEEWAY_SECS: i64 = 60;

/// What a token asserts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTokenClaims {
    pub tunnel_id: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

/// The exact bytes that are signed.
pub fn payload_bytes(claims: &SessionTokenClaims) -> Vec<u8> {
    format!(
        "{}|{}|{}",
        claims.tunnel_id, claims.issued_at, claims.expires_at
    )
    .into_bytes()
}

/// Assembles a token from its claims and signature.
pub fn encode(claims: &SessionTokenClaims, signature: &[u8]) -> String {
    format!(
        "{}.{}.{}",
        TOKEN_VERSION,
        hex::encode(payload_bytes(claims)),
        hex::encode(signature)
    )
}

/// Splits a token into claims, the signed payload and the signature.
fn split(token: &str) -> Result<(SessionTokenClaims, Vec<u8>, Vec<u8>)> {
    let mut parts = token.trim().split('.');
    let version = parts.next().unwrap_or_default();
    if version != TOKEN_VERSION {
        bail!("unsupported tunnel token version");
    }
    let payload_hex = parts
        .next()
        .ok_or_else(|| anyhow!("tunnel token has no payload"))?;
    let signature_hex = parts
        .next()
        .ok_or_else(|| anyhow!("tunnel token has no signature"))?;
    if parts.next().is_some() {
        bail!("tunnel token has trailing data");
    }
    let payload = hex::decode(payload_hex).map_err(|err| {
        anyhow!("tunnel token payload is not hexadecimal: {err}")
    })?;
    let signature = hex::decode(signature_hex).map_err(|err| {
        anyhow!("tunnel token signature is not hexadecimal: {err}")
    })?;
    let text = std::str::from_utf8(&payload)
        .map_err(|_| anyhow!("tunnel token payload is not UTF-8"))?;
    let mut fields = text.split('|');
    let tunnel_id = fields
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("tunnel token has no tunnel id"))?;
    let issued_at: i64 = fields
        .next()
        .ok_or_else(|| anyhow!("tunnel token has no issue time"))?
        .parse()
        .map_err(|_| anyhow!("tunnel token issue time is not a number"))?;
    let expires_at: i64 = fields
        .next()
        .ok_or_else(|| anyhow!("tunnel token has no expiry"))?
        .parse()
        .map_err(|_| anyhow!("tunnel token expiry is not a number"))?;
    if fields.next().is_some() {
        bail!("tunnel token payload has trailing fields");
    }
    Ok((
        SessionTokenClaims {
            tunnel_id: tunnel_id.to_string(),
            issued_at,
            expires_at,
        },
        payload,
        signature,
    ))
}

/// Verifies a token against the tunnel's public key.
///
/// Checks, in order: the format, the signature, that the token is for
/// `tunnel_id`, and that it is inside its validity window. Every failure is an
/// error — the caller refuses the session, it never falls back to "no auth".
pub fn verify(
    token: &str,
    public_key_hex: &str,
    tunnel_id: &str,
    now: i64,
) -> Result<SessionTokenClaims> {
    let (claims, payload, signature) = split(token)?;
    let public_key = hex::decode(public_key_hex.trim()).map_err(|err| {
        anyhow!("tunnel public key is not hexadecimal: {err}")
    })?;
    if public_key.len() != 32 {
        bail!("tunnel public key is not an Ed25519 key");
    }
    UnparsedPublicKey::new(&ED25519, &public_key)
        .verify(&payload, &signature)
        .map_err(|_| anyhow!("tunnel token signature is invalid"))?;
    if claims.tunnel_id != tunnel_id {
        bail!("tunnel token is for another tunnel");
    }
    if claims.expires_at + LEEWAY_SECS < now {
        bail!("tunnel token expired");
    }
    if claims.issued_at - LEEWAY_SECS > now {
        bail!("tunnel token is not valid yet");
    }
    Ok(claims)
}

/// Hex form of an Ed25519 public key, as it travels in the rule bundle.
pub fn public_key_hex(key: &[u8]) -> String {
    hex::encode(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn signer(seed: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
    }

    fn claims(expires_in: i64) -> SessionTokenClaims {
        let now = 1_800_000_000;
        SessionTokenClaims {
            tunnel_id: "tunnel-1".to_string(),
            issued_at: now,
            expires_at: now + expires_in,
        }
    }

    fn token_for(claims: &SessionTokenClaims, key: &Ed25519KeyPair) -> String {
        encode(claims, key.sign(&payload_bytes(claims)).as_ref())
    }

    #[test]
    fn a_valid_token_verifies() {
        let key = signer(7);
        let public = public_key_hex(key.public_key().as_ref());
        let claims = claims(3600);
        let token = token_for(&claims, &key);
        let verified =
            verify(&token, &public, "tunnel-1", claims.issued_at + 60).unwrap();
        assert_eq!(verified, claims);
    }

    #[test]
    fn an_expired_token_is_refused() {
        let key = signer(7);
        let public = public_key_hex(key.public_key().as_ref());
        let claims = claims(60);
        let token = token_for(&claims, &key);
        // Beyond the expiry plus the leeway.
        assert!(
            verify(&token, &public, "tunnel-1", claims.expires_at + 120)
                .is_err()
        );
    }

    #[test]
    fn a_token_for_another_tunnel_is_refused() {
        let key = signer(7);
        let public = public_key_hex(key.public_key().as_ref());
        let claims = claims(3600);
        let token = token_for(&claims, &key);
        assert!(verify(&token, &public, "tunnel-2", claims.issued_at).is_err());
    }

    #[test]
    fn a_token_signed_by_another_key_is_refused() {
        let key = signer(7);
        let other = signer(8);
        let public = public_key_hex(other.public_key().as_ref());
        let claims = claims(3600);
        let token = token_for(&claims, &key);
        assert!(verify(&token, &public, "tunnel-1", claims.issued_at).is_err());
    }

    #[test]
    fn a_tampered_payload_is_refused() {
        let key = signer(7);
        let public = public_key_hex(key.public_key().as_ref());
        let claims = claims(3600);
        let token = token_for(&claims, &key);
        let mut parts: Vec<&str> = token.split('.').collect();
        let mut payload = hex::decode(parts[1]).unwrap();
        // Flip the expiry to something far in the future.
        let text = String::from_utf8(payload.clone()).unwrap();
        let tampered = text.replace(
            &claims.expires_at.to_string(),
            &(claims.expires_at + 86_400).to_string(),
        );
        payload = tampered.into_bytes();
        let tampered_token =
            format!("{}.{}.{}", parts[0], hex::encode(payload), parts[2]);
        assert!(
            verify(&tampered_token, &public, "tunnel-1", claims.issued_at)
                .is_err()
        );
        parts.clear();
    }

    #[test]
    fn malformed_tokens_are_refused() {
        let key = signer(7);
        let public = public_key_hex(key.public_key().as_ref());
        for token in
            ["", "v1", "v2.00.00", "v1.zz.00", "v1.00.zz", "v1.00.00.99"]
        {
            assert!(verify(token, &public, "tunnel-1", 0).is_err(), "{token}");
        }
        // A well-formed but unsigned payload is still refused.
        let claims = claims(3600);
        let unsigned = format!("v1.{}", hex::encode(payload_bytes(&claims)));
        assert!(
            verify(&unsigned, &public, "tunnel-1", claims.issued_at).is_err()
        );
    }
}
