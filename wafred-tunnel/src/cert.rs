//! The edge's own TLS identity for the tunnel listener.
//!
//! The certificate is self-signed and generated locally: the control plane
//! never holds a tunnel CA key, and no key material has to be distributed to a
//! data plane. A connector does not build a chain to a CA — it pins the
//! SHA-256 of this leaf, which the control plane learned from the agent's
//! heartbeat. Rotation is therefore just "generate a new leaf, report the new
//! fingerprint"; connectors pick it up with their next config refresh.
//!
//! Everything is written atomically (`temp + fsync + rename`) into the agent's
//! cache directory, and the private key is `0600` — the same discipline the
//! rule cache follows, so a crash never leaves a half-written key behind.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rcgen::{
    CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

/// File name of the certificate inside the tunnel directory.
pub const CERT_FILE: &str = "cert.pem";
/// File name of the private key inside the tunnel directory.
pub const KEY_FILE: &str = "key.pem";
/// Lifetime of a generated tunnel certificate. It is pinned, not chained, so
/// the lifetime only bounds how often the fingerprint is re-reported.
pub const VALIDITY_DAYS: i64 = 3650;
/// A certificate this close to expiry is regenerated on the next start.
pub const RENEW_BEFORE_DAYS: i64 = 30;

/// The edge's tunnel certificate and the fingerprint connectors pin.
#[derive(Debug, Clone)]
pub struct TunnelCertificate {
    pub cert_pem: String,
    pub key_pem: String,
    /// Lower-case hex SHA-256 over the DER of the leaf.
    pub fingerprint_sha256: String,
    pub not_after: OffsetDateTime,
}

impl TunnelCertificate {
    /// Loads the certificate from `dir`, generating one when it is missing,
    /// unreadable or close to expiry.
    ///
    /// `names` become the certificate's subject alternative names. They are
    /// informational only (a connector pins the fingerprint), but a readable
    /// SAN makes `openssl s_client` output explain what the listener is.
    pub fn load_or_generate(dir: &Path, names: &[String]) -> Result<Self> {
        match Self::load(dir) {
            Ok(Some(cert)) => {
                let remaining = cert.not_after - OffsetDateTime::now_utc();
                if remaining >= Duration::days(RENEW_BEFORE_DAYS) {
                    return Ok(cert);
                }
                tracing::info!(
                    target: "pingwaf::tunnel",
                    not_after = %cert.not_after,
                    "tunnel certificate is near expiry, regenerating"
                );
            },
            Ok(None) => {},
            Err(error) => {
                tracing::warn!(
                    target: "pingwaf::tunnel",
                    error = %error,
                    "stored tunnel certificate is unusable, regenerating"
                );
            },
        }
        let cert = Self::generate(names)?;
        cert.store(dir)?;
        Ok(cert)
    }

    /// Reads `cert.pem`/`key.pem` from `dir`; `Ok(None)` when absent.
    pub fn load(dir: &Path) -> Result<Option<Self>> {
        let cert_path = dir.join(CERT_FILE);
        let key_path = dir.join(KEY_FILE);
        if !cert_path.is_file() || !key_path.is_file() {
            return Ok(None);
        }
        let cert_pem = std::fs::read_to_string(&cert_path)
            .with_context(|| format!("cannot read {}", cert_path.display()))?;
        let key_pem = std::fs::read_to_string(&key_path)
            .with_context(|| format!("cannot read {}", key_path.display()))?;
        let fingerprint_sha256 = fingerprint_of_pem(&cert_pem)?;
        let not_after = not_after_of_pem(&cert_pem)?;
        Ok(Some(Self {
            cert_pem,
            key_pem,
            fingerprint_sha256,
            not_after,
        }))
    }

    /// Generates a self-signed leaf for the given names.
    pub fn generate(names: &[String]) -> Result<Self> {
        let mut sans: Vec<String> = names
            .iter()
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty())
            .collect();
        if sans.is_empty() {
            sans.push("localhost".to_string());
        }
        let mut params = CertificateParams::new(sans).map_err(|err| {
            anyhow::anyhow!("invalid tunnel certificate names: {err}")
        })?;
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(DnType::CommonName, "WAFred tunnel");
        dn.push(DnType::OrganizationName, "WAFred");
        params.distinguished_name = dn;
        // Not a CA: the connector pins this exact leaf, there is nothing to
        // sign with it.
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let now = OffsetDateTime::now_utc();
        // A little clock skew tolerance for peers whose clock runs behind.
        params.not_before = now - Duration::minutes(5);
        params.not_after = now + Duration::days(VALIDITY_DAYS);

        let key = KeyPair::generate().map_err(|err| {
            anyhow::anyhow!("cannot generate a tunnel key: {err}")
        })?;
        let cert = params.self_signed(&key).map_err(|err| {
            anyhow::anyhow!("cannot sign the tunnel certificate: {err}")
        })?;
        let cert_pem = cert.pem();
        let key_pem = key.serialize_pem();
        let fingerprint_sha256 = fingerprint_of_pem(&cert_pem)?;
        Ok(Self {
            cert_pem,
            key_pem,
            fingerprint_sha256,
            not_after: params.not_after,
        })
    }

    /// Writes the pair into `dir` atomically, with the key readable by the
    /// owner only.
    pub fn store(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("cannot create {}", dir.display()))?;
        write_atomic(&dir.join(CERT_FILE), self.cert_pem.as_bytes(), false)?;
        write_atomic(&dir.join(KEY_FILE), self.key_pem.as_bytes(), true)?;
        Ok(())
    }

    /// rustls material for the listener.
    pub fn rustls_material(
        &self,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let certs = rustls_pemfile::certs(&mut self.cert_pem.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("cannot parse the tunnel certificate PEM")?;
        if certs.is_empty() {
            anyhow::bail!("the tunnel certificate PEM holds no certificate");
        }
        let key = rustls_pemfile::private_key(&mut self.key_pem.as_bytes())
            .context("cannot parse the tunnel key PEM")?
            .context("the tunnel key PEM holds no private key")?;
        Ok((certs, key))
    }

    /// Path of the certificate file inside `dir`, for logs.
    pub fn cert_path(dir: &Path) -> PathBuf {
        dir.join(CERT_FILE)
    }
}

/// SHA-256 of the leaf DER, lower-case hex.
pub fn fingerprint_of_pem(cert_pem: &str) -> Result<String> {
    let der = first_der(cert_pem)?;
    Ok(hex::encode(Sha256::digest(&der)))
}

/// Expiry of the leaf certificate.
pub fn not_after_of_pem(cert_pem: &str) -> Result<OffsetDateTime> {
    let der = first_der(cert_pem)?;
    let (_, cert) =
        x509_parser::parse_x509_certificate(&der).map_err(|err| {
            anyhow::anyhow!("cannot parse the tunnel certificate: {err}")
        })?;
    Ok(OffsetDateTime::from_unix_timestamp(
        cert.validity().not_after.timestamp(),
    )?)
}

fn first_der(cert_pem: &str) -> Result<Vec<u8>> {
    let (_, block) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes())
        .map_err(|err| {
            anyhow::anyhow!("cannot parse the tunnel certificate PEM: {err}")
        })?;
    Ok(block.contents)
}

/// Writes `bytes` to `path` through a same-directory temp file, fsync and
/// rename, so a crash leaves either the old file or the new one.
fn write_atomic(path: &Path, bytes: &[u8], private: bool) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        anyhow::anyhow!("{} has no parent directory", path.display())
    })?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            anyhow::anyhow!("{} has no file name", path.display())
        })?;
    let tmp = parent.join(format!(".{file_name}.tmp"));
    {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(if private { 0o600 } else { 0o644 });
        }
        let mut file = options
            .open(&tmp)
            .with_context(|| format!("cannot write {}", tmp.display()))?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path).with_context(|| {
        format!("cannot rename {} into place", path.display())
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names() -> Vec<String> {
        vec!["edge-1.internal".to_string(), "127.0.0.1".to_string()]
    }

    #[test]
    fn generate_round_trips_through_rustls() {
        let cert = TunnelCertificate::generate(&names()).unwrap();
        assert_eq!(cert.fingerprint_sha256.len(), 64);
        assert!(cert.not_after > OffsetDateTime::now_utc());
        let (certs, key) = cert.rustls_material().unwrap();
        assert_eq!(certs.len(), 1);
        assert!(matches!(
            key,
            PrivateKeyDer::Pkcs8(_)
                | PrivateKeyDer::Pkcs1(_)
                | PrivateKeyDer::Sec1(_)
        ));
        // The fingerprint is over the DER that rustls will serve.
        assert_eq!(
            hex::encode(Sha256::digest(certs[0].as_ref())),
            cert.fingerprint_sha256
        );
    }

    #[test]
    fn load_or_generate_persists_and_reloads_the_same_identity() {
        let dir = tempfile::tempdir().unwrap();
        let first =
            TunnelCertificate::load_or_generate(dir.path(), &names()).unwrap();
        let second =
            TunnelCertificate::load_or_generate(dir.path(), &names()).unwrap();
        assert_eq!(first.fingerprint_sha256, second.fingerprint_sha256);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join(KEY_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "the tunnel key must not be group/world readable"
            );
        }
    }

    #[test]
    fn a_corrupt_certificate_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(CERT_FILE), "not a pem").unwrap();
        std::fs::write(dir.path().join(KEY_FILE), "not a key").unwrap();
        let cert =
            TunnelCertificate::load_or_generate(dir.path(), &names()).unwrap();
        assert_eq!(cert.fingerprint_sha256.len(), 64);
        assert!(TunnelCertificate::load(dir.path()).unwrap().is_some());
    }
}
