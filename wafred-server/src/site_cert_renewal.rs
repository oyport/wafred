//! Issues and renews the self-signed certificates sites are served with.
//!
//! Two passes share one scan. The boot pass fills in material for rows that
//! enabled HTTPS before the control plane issued leaves — including the ones
//! the `site_ssl_self_signed_backfill` migration flags — so an upgraded
//! deployment stops failing every handshake without an operator clicking
//! anything. The hourly pass renews leaves close to expiry.
//!
//! Both write `site_ssl.cert_pem/key_pem`, the columns an uploaded certificate
//! uses and the only ones the data plane reads, so no agent-side change is
//! involved and remote agents receive the material in the normal bundle.

use std::time::Duration;

use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbErr, EntityTrait,
    QueryFilter, Set,
};
use tokio::task::JoinHandle;

use crate::api::state::AppState;
use crate::models::{site, site_ssl};
use crate::site_cert::{self, CertAction, StoredCert};

/// One scan per hour. A generated leaf lives a year and renews with a month to
/// spare, so the exact interval is not load-bearing.
const SCAN_INTERVAL: Duration = Duration::from_secs(3600);

/// Spawns the hourly renewal pass; the handle is detached by the caller.
pub fn spawn(state: AppState) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(SCAN_INTERVAL).await;
            match reconcile(&state).await {
                Ok(0) => {},
                Ok(count) => {
                    tracing::info!(
                        count,
                        "renewed self-signed site certificates"
                    )
                },
                Err(err) => tracing::warn!(
                    error = %err,
                    "self-signed certificate renewal scan failed"
                ),
            }
        }
    })
}

/// Issues or renews every self-signed site certificate that needs it.
///
/// Returns how many rows were written. A single unreadable row is logged and
/// skipped: one bad site must not stop the rest of the fleet from renewing.
pub async fn reconcile(state: &AppState) -> Result<usize, DbErr> {
    let rows = site_ssl::Entity::find()
        .filter(site_ssl::Column::SelfSigned.eq(true))
        .all(&state.db)
        .await?;
    let mut written = 0;

    for row in rows {
        let Some(site) =
            site::Entity::find_by_id(row.site_id).one(&state.db).await?
        else {
            // The FK cascades, so this is a torn read, not a real state.
            continue;
        };
        match issue_if_needed(&state.db, &site).await {
            Ok(true) => written += 1,
            Ok(false) => {},
            Err(err) => tracing::warn!(
                site_id = %site.id,
                error = %err,
                "cannot issue a self-signed site certificate"
            ),
        }
    }

    if written > 0 {
        // Agents only reload on a version change; without this the new
        // material would sit in the database until the next unrelated edit.
        crate::grpc::notify_all_config_changed(
            state,
            Some("site-cert-renewal"),
        )
        .await;
    }
    Ok(written)
}

/// Issues or renews one site's self-signed certificate when it needs it.
///
/// Returns whether a row was written. Does nothing for a site that is not in
/// self-signed mode, so callers may pass any site (the clone path does).
pub(crate) async fn issue_if_needed<C: ConnectionTrait>(
    db: &C,
    site: &site::Model,
) -> Result<bool, DbErr> {
    let Some(row) = site_ssl::Entity::find()
        .filter(site_ssl::Column::SiteId.eq(site.id))
        .one(db)
        .await?
    else {
        return Ok(false);
    };
    if !row.self_signed {
        return Ok(false);
    }

    let stored = StoredCert {
        issuer: row.issuer.as_deref(),
        cert_pem: row.cert_pem.as_deref(),
        expires_at: row.expires_at,
    };
    let action = site_cert::resolve(
        true,
        &site.domain,
        &site.alternate_domains,
        stored,
        Utc::now(),
    )
    .map_err(|err| DbErr::Custom(err.to_string()))?;
    let CertAction::Set(cert) = action else {
        return Ok(false);
    };

    let site_id = row.site_id;
    let mut active: site_ssl::ActiveModel = row.into();
    active.cert_pem = Set(Some(cert.cert_pem));
    active.key_pem = Set(Some(cert.key_pem));
    active.issuer = Set(Some(site_cert::SELF_SIGNED_ISSUER.to_string()));
    active.expires_at = Set(Some(cert.expires_at));
    active.update(db).await?;

    tracing::info!(
        %site_id,
        expires = %cert.expires_at,
        "issued a self-signed site certificate"
    );
    Ok(true)
}
