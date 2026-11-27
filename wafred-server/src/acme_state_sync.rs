//! Syncs ACME-issued PEMs from the embedded data plane into the database.
//!
//! In all-in-one mode the data plane's lets-encrypt task is the issuer: it
//! writes the issued certificate and key into its local `acme_state.toml` (the
//! memory config manager mirrors every write there). The control plane's
//! `build_site_config` reads `site_certificates` from PostgreSQL, so before
//! this sync the row still had an empty `cert_pem`: every *other* agent was
//! told "ACME is enabled, no PEM", tried to issue its own HTTP-01 order, and
//! failed because the CA's validation request reaches whichever instance owns
//! port 80 — not necessarily the agent that saved the token.
//!
//! The sync is deliberately read-only against the data plane and only writes
//! `site_certificates` rows that are ACME-managed (`auto_renew` and an
//! `acme_email`). Uploaded/manual PEMs are never overwritten: a row without
//! ACME management is skipped, and a row whose current PEM already matches is
//! a no-op.
//!
//! A remote agent that issues a certificate is still not reported back here;
//! that needs a PEM report over the control-plane channel. The embedded data
//! plane is the designated issuer for sites whose DNS points at the control
//! plane, which is the deployment this sync fixes.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::Deserialize;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::api::ssl::cert_status;
use crate::api::state::AppState;
use crate::models::{agent, site_certificates, site_ssl};
use crate::site_cert;

/// How often the file is checked. Issuance is rare; a 30 s delay only means
/// the other agents stop retrying a little later.
const SYNC_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Default, Deserialize)]
struct AcmeState {
    #[serde(default)]
    certificates: HashMap<String, AcmeCertificate>,
}

#[derive(Debug, Default, Deserialize)]
struct AcmeCertificate {
    acme: Option<String>,
    #[serde(default)]
    domains: String,
    #[serde(default)]
    tls_cert: String,
    #[serde(default)]
    tls_key: String,
}

struct CertificateMeta {
    issuer: String,
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

/// Starts the periodic sync. `path` is the embedded data plane's
/// `acme_state.toml`; a missing file is normal in server-only mode.
pub fn spawn(state: AppState, path: PathBuf) {
    tokio::spawn(async move {
        let mut last_modified: Option<SystemTime> = None;
        let mut ticker = tokio::time::interval(SYNC_INTERVAL);
        loop {
            ticker.tick().await;
            if let Err(err) = sync_once(&state, &path, &mut last_modified).await
            {
                warn!(
                    error = %err,
                    path = %path.display(),
                    "ACME state sync failed"
                );
            }
        }
    });
}

async fn sync_once(
    state: &AppState,
    path: &Path,
    last_modified: &mut Option<SystemTime>,
) -> anyhow::Result<usize> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            debug!(path = %path.display(), "no ACME state file yet");
            return Ok(0);
        },
        Err(err) => return Err(err.into()),
    };
    let modified = metadata.modified().ok();
    if modified == *last_modified {
        return Ok(0);
    }

    let text = std::fs::read_to_string(path)?;
    let parsed: AcmeState = match toml::from_str(&text) {
        Ok(parsed) => parsed,
        Err(_) => {
            // The data plane writes atomically, but a malformed file must not
            // take the control plane down or retry in a tight loop. Wait for
            // the next write before trying again.
            *last_modified = modified;
            return Err(anyhow::anyhow!(
                "cannot parse ACME state file {}",
                path.display()
            ));
        },
    };

    let mut updated = 0;
    for (name, cert) in &parsed.certificates {
        let Some(site_id) = site_id_from_key(name) else {
            continue;
        };
        if cert.acme.as_deref().is_none_or(str::is_empty)
            || cert.domains.trim().is_empty()
            || cert.tls_cert.trim().is_empty()
            || cert.tls_key.trim().is_empty()
        {
            continue;
        }
        if import_certificate(
            &state.db,
            site_id,
            &cert.domains,
            &cert.tls_cert,
            &cert.tls_key,
            None,
        )
        .await?
            == ImportOutcome::Updated
        {
            updated += 1;
        }
    }

    *last_modified = modified;
    if updated > 0 {
        // The PEM is now in the row `build_site_config` reads, so every agent
        // gets it on the next push. Without this, agents only see it on the
        // next unrelated config change.
        crate::grpc::notify_all_config_changed(state, Some("acme-state-sync"))
            .await;
    }
    Ok(updated)
}

/// What an ACME state entry did to the certificate row.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ImportOutcome {
    /// The row now carries the submitted material.
    Updated,
    /// The row already carried exactly this material; no write happened.
    Unchanged,
    /// The entry was refused (or is not this file's to apply). The reason is
    /// safe to log and, for the agent publication RPC, to return to the caller.
    Skipped(&'static str),
}

/// Applies one ACME-issued certificate to the site's certificate row.
///
/// `expected_issuer` is the agent that published the material, or `None` for
/// the local file sync. A row designated to another agent is skipped: only the
/// designated issuer may replace its material.
pub(crate) async fn import_certificate(
    db: &sea_orm::DatabaseConnection,
    site_id: Uuid,
    domains: &str,
    cert_pem: &str,
    key_pem: &str,
    expected_issuer: Option<Uuid>,
) -> anyhow::Result<ImportOutcome> {
    // A site can own several certificates. Reordered SANs identify the same
    // set, while an arbitrary first row can distribute another site's key.
    let names = |value: &str| -> std::collections::BTreeSet<String> {
        value
            .split(',')
            .map(|name| name.trim().to_ascii_lowercase())
            .collect()
    };
    let expected = names(domains);
    let candidates = site_certificates::Entity::find()
        .filter(site_certificates::Column::SiteId.eq(site_id))
        .all(db)
        .await?;
    let has_candidates = !candidates.is_empty();
    let mut matches = candidates
        .into_iter()
        .filter(|row| names(&row.domain) == expected);
    let row = matches.next();
    if matches.next().is_some() {
        warn!(%site_id, domains, "ambiguous certificate rows for ACME state");
        return Ok(ImportOutcome::Skipped(
            "ambiguous certificate rows for the hostname set",
        ));
    }
    let Some(row) = row else {
        // The file can outlive a deleted certificate row. Not an error: the
        // next issuance or a site edit removes it. But a site that still owns
        // certificate rows and none of them matches the ACME state's SAN set
        // is a configuration drift an operator needs to see.
        if has_candidates {
            warn!(
                %site_id,
                domains,
                "ACME certificate has no certificate row with this exact hostname set"
            );
            return Ok(ImportOutcome::Skipped(
                "no certificate row matches the hostname set",
            ));
        }
        debug!(site_id = %site_id, domains, "ACME certificate has no row");
        return Ok(ImportOutcome::Skipped("no certificate row for the site"));
    };

    // A certificate designated to one agent is that agent's to publish. The
    // local file sync (`expected_issuer == None`) must not overwrite it, and
    // another agent must not either.
    if let Some(designated) = row.acme_issuer_agent_id {
        let accepted = match expected_issuer {
            Some(issuer) => issuer == designated,
            None => {
                // The local file belongs to the embedded issuer. A
                // certificate designated to that loopback-registered agent is
                // still this file's to apply; one designated to a remote
                // agent must wait for that agent's publication.
                agent::Entity::find_by_id(designated)
                    .one(db)
                    .await?
                    .is_some_and(|agent| {
                        agent.peer_ip.as_deref().is_some_and(peer_is_loopback)
                    })
            },
        };
        if !accepted {
            warn!(
                %site_id,
                domains,
                designated = %designated,
                caller = ?expected_issuer,
                "ACME certificate is designated to another issuer"
            );
            return Ok(ImportOutcome::Skipped(
                "the certificate is designated to another issuer",
            ));
        }
    }

    // Only ACME-managed rows are this file's to update. A manual upload (or a
    // row whose auto-renew was turned off) must never be replaced by an old
    // ACME PEM that happens to share the site id.
    if !row.auto_renew
        || row
            .acme_email
            .as_deref()
            .map(str::trim)
            .is_none_or(str::is_empty)
    {
        return Ok(ImportOutcome::Skipped(
            "the certificate row is not ACME-managed",
        ));
    }
    if row.cert_pem.as_deref() == Some(cert_pem)
        && row.key_pem.as_deref() == Some(key_pem)
    {
        return Ok(ImportOutcome::Unchanged);
    }

    let hostnames: Vec<_> = expected.into_iter().collect();
    if !site_cert::covers(cert_pem, &hostnames)
        || crate::api::validation::validate_certificate_and_key(
            cert_pem, key_pem,
        )
        .is_err()
    {
        warn!(%site_id, domains, "ACME state PEM or key does not match certificate configuration");
        return Ok(ImportOutcome::Skipped(
            "the PEM or key does not match the certificate configuration",
        ));
    }
    let Some(meta) = parse_certificate_meta(cert_pem) else {
        warn!(%site_id, domains, "ACME state PEM cannot be parsed");
        return Ok(ImportOutcome::Skipped("the PEM cannot be parsed"));
    };
    if let Err(reason) = validate_imported_certificate(
        &meta,
        row.expires_at,
        Utc::now(),
        staging_allowed(),
    ) {
        warn!(%site_id, domains, reason, "ACME state certificate rejected");
        return Ok(ImportOutcome::Skipped(reason));
    }
    let mut active: site_certificates::ActiveModel = row.clone().into();
    active.cert_pem = Set(Some(cert_pem.to_string()));
    active.key_pem = Set(Some(key_pem.to_string()));
    active.status = Set(cert_status::ACTIVE.to_string());
    active.failure_reason = Set(None);
    active.updated_at = Set(Utc::now());
    active.issuer = Set(Some(meta.issuer.clone()));
    active.not_before = Set(Some(meta.not_before));
    active.expires_at = Set(Some(meta.expires_at));
    let certificate_id = row.id;
    active.update(db).await?;

    // The issued PEM is the site's certificate now. A generated self-signed
    // leaf would otherwise keep winning — the data plane prefers an inline PEM
    // over an ACME order — so the site would serve the wrong certificate
    // forever. Point the posture at this row and drop our generated material.
    let posture_row = site_ssl::Entity::find()
        .filter(site_ssl::Column::SiteId.eq(site_id))
        .one(db)
        .await?;
    if let Some(ssl) = posture_row {
        if ssl.self_signed || site_cert::is_generated(ssl.issuer.as_deref()) {
            let mut posture: site_ssl::ActiveModel = ssl.into();
            posture.self_signed = Set(false);
            posture.certificate_id = Set(Some(certificate_id));
            posture.cert_pem = Set(None);
            posture.key_pem = Set(None);
            posture.issuer = Set(Some(meta.issuer.clone()));
            posture.expires_at = Set(Some(meta.expires_at));
            posture.update(db).await?;
            info!(
                site_id = %site_id,
                cert_id = %certificate_id,
                "ACME certificate took over from the self-signed leaf"
            );
        }
    }

    info!(
        site_id = %site_id,
        domain = %row.domain,
        cert_len = cert_pem.len(),
        key_len = key_pem.len(),
        "synced ACME certificate into the control plane"
    );
    Ok(ImportOutcome::Updated)
}

fn site_id_from_key(name: &str) -> Option<Uuid> {
    let site = name.strip_suffix("_cert")?;
    Uuid::parse_str(site).ok()
}

/// How far a certificate may be from "now" before it is considered
/// unusable. The issuer and the control plane run on different clocks.
const IMPORT_CLOCK_LEEWAY_MINUTES: i64 = 5;

/// Whether a stored peer address is the loopback registration of the
/// embedded all-in-one agent. A dual-stack listener can report the mapped
/// form, which `Ipv6Addr::is_loopback` alone does not cover.
fn peer_is_loopback(peer: &str) -> bool {
    peer.parse::<std::net::IpAddr>().is_ok_and(|ip| match ip {
        std::net::IpAddr::V4(v4) => v4.is_loopback(),
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        },
    })
}

/// Whether the deployment explicitly opted into the ACME staging directory.
fn staging_allowed() -> bool {
    std::env::var("PINGAP_ACME_STAGING").is_ok_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on" | "staging" | "stage"
        )
    })
}

/// Let's Encrypt staging intermediates carry a marker in the issuer DN.
fn is_staging_issuer(issuer: &str) -> bool {
    let upper = issuer.to_ascii_uppercase();
    upper.contains("(STAGING)") || upper.contains("FAKE LE")
}

/// Refuses an ACME state entry that must not become the site's certificate.
///
/// The file is written by the issuer, but it can be stale, restored from a
/// backup, or left behind by a staging run. Importing such material would
/// mark an unusable certificate active and push it to every consumer.
fn validate_imported_certificate(
    meta: &CertificateMeta,
    current_expires_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    staging_allowed: bool,
) -> Result<(), &'static str> {
    if meta.expires_at <= now {
        return Err("the certificate has already expired");
    }
    if meta.not_before
        > now + chrono::Duration::minutes(IMPORT_CLOCK_LEEWAY_MINUTES)
    {
        return Err("the certificate is not valid yet");
    }
    if current_expires_at.is_some_and(|current| meta.expires_at < current) {
        return Err("the certificate is older than the stored one");
    }
    if !staging_allowed && is_staging_issuer(&meta.issuer) {
        return Err("the certificate was issued by an ACME staging CA");
    }
    Ok(())
}

fn parse_certificate_meta(cert_pem: &str) -> Option<CertificateMeta> {
    let (_, block) =
        x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()).ok()?;
    let cert = block.parse_x509().ok()?;
    let validity = cert.validity();
    let not_before = validity.not_before.to_datetime();
    let expires_at = validity.not_after.to_datetime();
    Some(CertificateMeta {
        // `site_certificates.issuer` is varchar(200); a pathological DN must
        // not make the PEM update fail.
        issuer: cert.issuer().to_string().chars().take(200).collect(),
        not_before: DateTime::<Utc>::from_timestamp(
            not_before.unix_timestamp(),
            0,
        )?,
        expires_at: DateTime::<Utc>::from_timestamp(
            expires_at.unix_timestamp(),
            0,
        )?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(
        not_before: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        issuer: &str,
    ) -> CertificateMeta {
        CertificateMeta {
            issuer: issuer.to_string(),
            not_before,
            expires_at,
        }
    }

    #[test]
    fn rejects_unusable_certificates_before_import() {
        let now = Utc::now();
        let day = chrono::Duration::days(1);
        let valid = meta(
            now - day,
            now + chrono::Duration::days(60),
            "CN=R3, O=Let's Encrypt",
        );
        assert!(validate_imported_certificate(&valid, None, now, false).is_ok());
        // Re-importing the same certificate is idempotent, not "older".
        assert!(validate_imported_certificate(
            &valid,
            Some(valid.expires_at),
            now,
            false
        )
        .is_ok());

        let expired =
            meta(now - chrono::Duration::days(60), now - day, "CN=R3");
        assert_eq!(
            validate_imported_certificate(&expired, None, now, false),
            Err("the certificate has already expired")
        );

        let future = meta(now + day, now + chrono::Duration::days(60), "CN=R3");
        assert_eq!(
            validate_imported_certificate(&future, None, now, false),
            Err("the certificate is not valid yet")
        );

        let older = meta(now - day, now + chrono::Duration::days(10), "CN=R3");
        assert_eq!(
            validate_imported_certificate(
                &older,
                Some(now + chrono::Duration::days(30)),
                now,
                false
            ),
            Err("the certificate is older than the stored one")
        );

        for issuer in
            ["CN=(STAGING) Pretend Pear X1", "CN=Fake LE Intermediate X1"]
        {
            let staging =
                meta(now - day, now + chrono::Duration::days(60), issuer);
            assert_eq!(
                validate_imported_certificate(&staging, None, now, false),
                Err("the certificate was issued by an ACME staging CA")
            );
            assert!(validate_imported_certificate(&staging, None, now, true)
                .is_ok());
        }
    }

    #[test]
    fn loopback_peer_detection_handles_mapped_v4() {
        assert!(peer_is_loopback("127.0.0.1"));
        assert!(peer_is_loopback("::1"));
        assert!(peer_is_loopback("::ffff:127.0.0.1"));
        assert!(!peer_is_loopback("10.0.0.1"));
        assert!(!peer_is_loopback("not-an-ip"));
    }

    #[test]
    fn parses_issued_certificate_metadata() {
        use rcgen::{CertificateParams, KeyPair};

        let params =
            CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let meta = parse_certificate_meta(&cert.pem()).unwrap();
        assert!(!meta.issuer.is_empty());
        assert!(meta.expires_at > meta.not_before);
    }

    #[test]
    fn parses_certificate_entries_and_skips_empty_ones() {
        let state: AcmeState = toml::from_str(
            r#"
[certificates.11111111-1111-1111-1111-111111111111_cert]
domains = "example.com,www.example.com"
acme = "enabled"
tls_cert = "CERT"
tls_key = "KEY"

[certificates.22222222-2222-2222-2222-222222222222_cert]
domains = "empty.example"
tls_cert = ""
tls_key = ""
"#,
        )
        .unwrap();
        let site_id =
            Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let cert = state
            .certificates
            .get("11111111-1111-1111-1111-111111111111_cert")
            .unwrap();
        assert_eq!(cert.domains, "example.com,www.example.com");
        assert_eq!(cert.tls_cert, "CERT");
        assert_eq!(cert.tls_key, "KEY");
        assert_eq!(
            site_id_from_key("11111111-1111-1111-1111-111111111111_cert"),
            Some(site_id)
        );
        assert_eq!(site_id_from_key("not-a-uuid_cert"), None);
        assert_eq!(
            site_id_from_key("11111111-1111-1111-1111-111111111111"),
            None
        );
    }
}
