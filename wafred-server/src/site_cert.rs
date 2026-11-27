//! Site-level self-signed certificates.
//!
//! `site_ssl.self_signed` used to be a flag the control plane stored and the
//! data plane ignored. A site that enabled HTTPS in "self-signed" mode pushed a
//! TLS listener with no certificate at all, so every handshake died with
//! `tls_choose_sigalg: no suitable signature algorithm` while the console
//! promised "WAFred issues and renews a certificate automatically".
//!
//! The control plane now issues the leaf itself and stores it in
//! `site_ssl.cert_pem/key_pem` — the same columns an uploaded certificate uses,
//! which is what the data plane already serves, so no agent change is needed
//! and remote agents receive it in the normal rule bundle.
//!
//! Everything here is pure (PEM in, PEM out, no database), so the decision
//! logic can be unit-tested without a control plane.

use chrono::{DateTime, Duration, Utc};
use x509_parser::extensions::GeneralName;

use crate::pki::mtls::{parse_pem_block, parse_x509, MtlsError};
use crate::pki::tls::generate_self_signed;

/// Issuer recorded on every certificate this module generates. It is also how
/// the write path recognises its own material: an operator-uploaded PEM must
/// never be deleted because the site switched to another source.
pub const SELF_SIGNED_ISSUER: &str = "WAFred Self-Signed";

/// Lifetime of a generated site certificate.
///
/// Deliberately shorter than the dashboard's 825 days: this leaf is replaced
/// automatically, and a shorter life keeps a compromised key's window small.
pub const SITE_CERT_DAYS: i64 = 365;

/// How close to expiry a generated certificate is renewed.
pub const RENEW_BEFORE_DAYS: i64 = 30;

/// The material a self-signed site is served with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedCert {
    pub cert_pem: String,
    pub key_pem: String,
    pub expires_at: DateTime<Utc>,
}

/// What a posture write should do with the row's certificate columns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertAction {
    /// Leave the stored material alone.
    Keep,
    /// Store freshly issued material.
    Set(IssuedCert),
    /// Drop material this module generated (the site moved to another source).
    Clear,
}

/// The certificate columns a `site_ssl` row already carries.
#[derive(Debug, Clone, Copy, Default)]
pub struct StoredCert<'a> {
    pub issuer: Option<&'a str>,
    pub cert_pem: Option<&'a str>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Whether the stored issuer names a certificate this module generated.
pub fn is_generated(issuer: Option<&str>) -> bool {
    issuer.is_some_and(|value| value.trim() == SELF_SIGNED_ISSUER)
}

/// The hostnames a site is served under, normalised for a SAN list.
///
/// Order is kept (primary domain first) and duplicates are dropped: a site
/// whose alternate list repeats the primary would otherwise get an invalid
/// certificate with two identical SAN entries.
pub fn hostnames(domain: &str, alternates: &[String]) -> Vec<String> {
    let mut names: Vec<String> = Vec::with_capacity(alternates.len() + 1);
    for raw in
        std::iter::once(domain).chain(alternates.iter().map(String::as_str))
    {
        let name = raw.trim().to_ascii_lowercase();
        if name.is_empty() || names.contains(&name) {
            continue;
        }
        names.push(name);
    }
    names
}

/// Issues a leaf certificate covering every hostname the site answers on.
pub fn issue(
    domain: &str,
    alternates: &[String],
    days: i64,
) -> Result<IssuedCert, MtlsError> {
    let names = hostnames(domain, alternates);
    let common_name = names.first().map(String::as_str).unwrap_or(domain);
    let material = generate_self_signed(common_name, &names, days)?;
    let key_pem = material.key_pem.ok_or_else(|| {
        MtlsError::Certificate(
            "the generated certificate has no private key".to_string(),
        )
    })?;
    let expires_at = DateTime::<Utc>::from_timestamp(
        material.meta.not_after.unix_timestamp(),
        0,
    )
    .ok_or_else(|| {
        MtlsError::Certificate(
            "the generated certificate has an invalid expiry".to_string(),
        )
    })?;
    Ok(IssuedCert {
        cert_pem: material.cert_pem,
        key_pem,
        expires_at,
    })
}

/// Whether a certificate is close enough to expiry to be replaced.
///
/// A row without an expiry cannot be planned around and is renewed too: that
/// is also how a row that predates this behaviour gets its first certificate.
pub fn needs_renewal(
    expires_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    days_before: i64,
) -> bool {
    match expires_at {
        None => true,
        Some(expires_at) => expires_at <= now + Duration::days(days_before),
    }
}

/// The DNS names a PEM certificate carries, lowercased.
fn cert_hostnames(cert_pem: &str) -> Option<Vec<String>> {
    let block = parse_pem_block(cert_pem).ok()?;
    let cert = parse_x509(&block).ok()?;
    let mut names = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            if let GeneralName::DNSName(dns) = name {
                names.push(dns.to_ascii_lowercase());
            }
        }
    }
    Some(names)
}

/// Whether the stored certificate still covers exactly the site's hostnames.
///
/// An exact set comparison, not a wildcard match: this module only ever
/// generates the hostnames themselves, so a mismatch means the site's domains
/// changed and the certificate has to be reissued.
pub(crate) fn covers(cert_pem: &str, names: &[String]) -> bool {
    let Some(stored) = cert_hostnames(cert_pem) else {
        return false;
    };
    if stored.len() != names.len() {
        return false;
    }
    names
        .iter()
        .all(|name| stored.iter().any(|held| held == name))
}

/// Decides what a posture write does with the certificate columns.
///
/// Precedence is the caller's job for anything beyond the generated material
/// (an upload, a selected certificate row or an ACME order all arrive as
/// `self_signed == false`), so this only has to answer "issue, keep or clear".
pub fn resolve(
    self_signed: bool,
    domain: &str,
    alternates: &[String],
    stored: StoredCert<'_>,
    now: DateTime<Utc>,
) -> Result<CertAction, MtlsError> {
    if !self_signed {
        // The site moved to another source; drop material we generated, but
        // leave an uploaded PEM where the operator put it.
        return Ok(if is_generated(stored.issuer) {
            CertAction::Clear
        } else {
            CertAction::Keep
        });
    }

    let names = hostnames(domain, alternates);
    let usable = is_generated(stored.issuer)
        && stored.cert_pem.is_some_and(|pem| covers(pem, &names));
    if usable && !needs_renewal(stored.expires_at, now, RENEW_BEFORE_DAYS) {
        return Ok(CertAction::Keep);
    }
    Ok(CertAction::Set(issue(domain, alternates, SITE_CERT_DAYS)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_800_000_000, 0).unwrap()
    }

    #[test]
    fn hostnames_are_normalised_and_deduplicated() {
        let names = hostnames(
            " Example.COM ",
            &[
                "www.example.com".to_string(),
                "EXAMPLE.com".to_string(),
                "".to_string(),
                "  ".to_string(),
            ],
        );
        assert_eq!(names, vec!["example.com", "www.example.com"]);
    }

    #[test]
    fn an_issued_certificate_covers_every_site_hostname() {
        let issued = issue(
            "example.com",
            &["www.example.com".to_string()],
            SITE_CERT_DAYS,
        )
        .unwrap();
        let names = cert_hostnames(&issued.cert_pem).unwrap();
        assert!(names.contains(&"example.com".to_string()));
        assert!(names.contains(&"www.example.com".to_string()));
        // A leaf, not a CA: browsers must not treat it as a trust anchor.
        // rcgen omits the extension entirely for `IsCa::NoCa`, so absence is
        // the expected encoding and only a present `CA:TRUE` is a failure.
        let block = parse_pem_block(&issued.cert_pem).unwrap();
        let cert = parse_x509(&block).unwrap();
        if let Ok(Some(ca)) = cert.basic_constraints() {
            assert!(
                !ca.value.ca,
                "a generated site certificate must not be a CA"
            );
        }
        // And it has to be usable as a server certificate.
        let eku = cert.extended_key_usage().unwrap().unwrap();
        assert!(eku.value.server_auth);
        assert!(issued.expires_at > now());
    }

    #[test]
    fn renewal_is_due_only_inside_the_window() {
        let expiring = now() + Duration::days(RENEW_BEFORE_DAYS - 1);
        let healthy = now() + Duration::days(RENEW_BEFORE_DAYS + 1);
        assert!(needs_renewal(Some(expiring), now(), RENEW_BEFORE_DAYS));
        assert!(!needs_renewal(Some(healthy), now(), RENEW_BEFORE_DAYS));
        // No expiry is a row that cannot be planned around: renew it.
        assert!(needs_renewal(None, now(), RENEW_BEFORE_DAYS));
    }

    #[test]
    fn switching_to_self_signed_issues_a_certificate() {
        let action =
            resolve(true, "example.com", &[], StoredCert::default(), now())
                .unwrap();
        assert!(matches!(action, CertAction::Set(_)));
    }

    #[test]
    fn a_fresh_generated_certificate_is_kept() {
        let issued = issue("example.com", &[], SITE_CERT_DAYS).unwrap();
        let action = resolve(
            true,
            "example.com",
            &[],
            StoredCert {
                issuer: Some(SELF_SIGNED_ISSUER),
                cert_pem: Some(&issued.cert_pem),
                expires_at: Some(issued.expires_at),
            },
            now(),
        )
        .unwrap();
        assert_eq!(action, CertAction::Keep);
    }

    #[test]
    fn a_changed_hostname_set_reissues() {
        let issued = issue("example.com", &[], SITE_CERT_DAYS).unwrap();
        let action = resolve(
            true,
            "example.com",
            &["www.example.com".to_string()],
            StoredCert {
                issuer: Some(SELF_SIGNED_ISSUER),
                cert_pem: Some(&issued.cert_pem),
                expires_at: Some(issued.expires_at),
            },
            now(),
        )
        .unwrap();
        assert!(matches!(action, CertAction::Set(_)));
    }

    #[test]
    fn an_expiring_certificate_is_reissued() {
        let issued = issue("example.com", &[], SITE_CERT_DAYS).unwrap();
        let action = resolve(
            true,
            "example.com",
            &[],
            StoredCert {
                issuer: Some(SELF_SIGNED_ISSUER),
                cert_pem: Some(&issued.cert_pem),
                expires_at: Some(now() + Duration::days(1)),
            },
            now(),
        )
        .unwrap();
        assert!(matches!(action, CertAction::Set(_)));
    }

    #[test]
    fn leaving_self_signed_clears_only_generated_material() {
        let generated = resolve(
            false,
            "example.com",
            &[],
            StoredCert {
                issuer: Some(SELF_SIGNED_ISSUER),
                cert_pem: Some("pem"),
                expires_at: None,
            },
            now(),
        )
        .unwrap();
        assert_eq!(generated, CertAction::Clear);

        let uploaded = resolve(
            false,
            "example.com",
            &[],
            StoredCert {
                issuer: Some("Let's Encrypt"),
                cert_pem: Some("pem"),
                expires_at: None,
            },
            now(),
        )
        .unwrap();
        assert_eq!(uploaded, CertAction::Keep);
    }

    #[test]
    fn a_foreign_certificate_under_self_signed_is_replaced() {
        let action = resolve(
            true,
            "example.com",
            &[],
            StoredCert {
                issuer: Some("Let's Encrypt"),
                cert_pem: Some("pem"),
                expires_at: Some(now() + Duration::days(90)),
            },
            now(),
        )
        .unwrap();
        assert!(matches!(action, CertAction::Set(_)));
    }
}
