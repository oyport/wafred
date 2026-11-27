//! Certificate pinning for the tunnel client.
//!
//! The edge's tunnel certificate is self-signed and generated locally, so a
//! connector does not build a chain to a CA — it accepts exactly the leaf the
//! control plane told it to expect, by SHA-256 fingerprint. The pin is the
//! identity: the control plane learned it from the agent's heartbeat and hands
//! it to the connector over an authenticated channel, so "same key material as
//! the node I paired with" is the whole check. Hostname verification is
//! deliberately not part of it (an edge can be reached under several names, and
//! a shared ingress name fronts several edges); the fingerprint is stricter
//! than a name.

use std::sync::Arc;

use anyhow::{Result, anyhow, bail};
use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error,
    SignatureScheme,
};
use sha2::{Digest, Sha256};

use crate::protocol::ALPN;

/// Verifies a server certificate against a fixed set of SHA-256 fingerprints.
#[derive(Debug)]
pub struct PinnedCertVerifier {
    fingerprints: Vec<[u8; 32]>,
    provider: Arc<CryptoProvider>,
}

impl PinnedCertVerifier {
    /// Builds the verifier from lower-case hex fingerprints.
    ///
    /// An empty or malformed list is an error, never "accept anything": a
    /// connector without a pin must not connect at all.
    pub fn new(
        fingerprints_hex: &[String],
        provider: Arc<CryptoProvider>,
    ) -> Result<Self> {
        let mut fingerprints = Vec::new();
        for raw in fingerprints_hex {
            let bytes = hex::decode(raw.trim()).map_err(|err| {
                anyhow!("pinned fingerprint {raw:?} is not hexadecimal: {err}")
            })?;
            let fingerprint: [u8; 32] = bytes.try_into().map_err(|_| {
                anyhow!("pinned fingerprint {raw:?} is not a SHA-256 digest")
            })?;
            fingerprints.push(fingerprint);
        }
        if fingerprints.is_empty() {
            bail!("no pinned tunnel certificate fingerprint was provided");
        }
        Ok(Self {
            fingerprints,
            provider,
        })
    }
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, Error> {
        let digest = Sha256::digest(end_entity.as_ref());
        if !self
            .fingerprints
            .iter()
            .any(|pinned| crate::protocol::constant_time_eq(&digest, pinned))
        {
            return Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        // The pin says "this is the node"; the expiry says "it is still the
        // node". The edge renews its certificate a month before this date, so
        // an expired pin means the edge has not been running.
        let (_, cert) =
            x509_parser::parse_x509_certificate(end_entity.as_ref()).map_err(
                |_| Error::InvalidCertificate(CertificateError::BadEncoding),
            )?;
        let not_after = cert.validity().not_after.timestamp();
        if not_after > 0 && now.as_secs() > not_after as u64 {
            return Err(Error::InvalidCertificate(CertificateError::Expired));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The process's rustls provider.
///
/// The host binary installs one at startup (ring, matching pingora's rustls
/// backend); this crate never installs its own, so both ends of the tunnel use
/// the same provider as everything else in the process.
pub fn default_provider() -> Result<Arc<CryptoProvider>> {
    CryptoProvider::get_default()
        .cloned()
        .ok_or_else(|| anyhow!("no rustls crypto provider is installed"))
}

/// A client configuration that trusts exactly the pinned fingerprints.
pub fn client_config(
    fingerprints_hex: &[String],
    provider: Arc<CryptoProvider>,
) -> Result<ClientConfig> {
    let verifier =
        Arc::new(PinnedCertVerifier::new(fingerprints_hex, provider.clone())?);
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| anyhow!("cannot build the tunnel TLS client: {err}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::TunnelCertificate;

    fn provider() -> Arc<CryptoProvider> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        default_provider().unwrap()
    }

    #[test]
    fn a_pinned_certificate_is_accepted_and_a_different_one_is_not() {
        let pinned =
            TunnelCertificate::generate(&["localhost".to_string()]).unwrap();
        let other =
            TunnelCertificate::generate(&["localhost".to_string()]).unwrap();
        let verifier = PinnedCertVerifier::new(
            std::slice::from_ref(&pinned.fingerprint_sha256),
            provider(),
        )
        .unwrap();
        let (certs, _) = pinned.rustls_material().unwrap();
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(
            time::OffsetDateTime::now_utc().unix_timestamp() as u64,
        ));
        let name = ServerName::try_from("localhost").unwrap();
        assert!(
            verifier
                .verify_server_cert(&certs[0], &[], &name, &[], now)
                .is_ok()
        );

        let (other_certs, _) = other.rustls_material().unwrap();
        assert!(
            verifier
                .verify_server_cert(&other_certs[0], &[], &name, &[], now)
                .is_err()
        );
    }

    #[test]
    fn an_empty_pin_list_is_refused() {
        assert!(PinnedCertVerifier::new(&[], provider()).is_err());
        assert!(
            PinnedCertVerifier::new(&["not-hex".to_string()], provider())
                .is_err()
        );
    }

    #[test]
    fn an_expired_certificate_is_refused_even_when_pinned() {
        let cert =
            TunnelCertificate::generate(&["localhost".to_string()]).unwrap();
        let verifier = PinnedCertVerifier::new(
            std::slice::from_ref(&cert.fingerprint_sha256),
            provider(),
        )
        .unwrap();
        let (certs, _) = cert.rustls_material().unwrap();
        let far_future =
            UnixTime::since_unix_epoch(std::time::Duration::from_secs(
                (time::OffsetDateTime::now_utc().unix_timestamp() as u64)
                    + 60 * 60 * 24 * 365 * 20,
            ));
        let name = ServerName::try_from("localhost").unwrap();
        assert!(
            verifier
                .verify_server_cert(&certs[0], &[], &name, &[], far_future)
                .is_err()
        );
    }
}
