//! Private, deployment-only showcase account. No public API or dashboard setting.

use anyhow::{bail, Context, Result};
use chrono::{Duration, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait,
    QueryFilter, QueryOrder, Set, TransactionTrait,
};
use uuid::Uuid;

use crate::api::auth::normalise_email;
use crate::api::sites::{create_site_for_user, CreateSiteRequest};
use crate::auth::password::{hash_password, verify_password};
use crate::models::security_events::{access_logs, security_events};
use crate::models::{
    api_key, passkey_credential, role, site, site_status, user,
};

const ENABLED_ENV: &str = "WAFRED_DEMO_ENABLED";
const EMAIL_ENV: &str = "WAFRED_DEMO_EMAIL";
const PASSWORD_ENV: &str = "WAFRED_DEMO_PASSWORD";
const SAMPLE_DOMAIN: &str = "demo.example.com";
const SAMPLE_AGENT: &str = "Mozilla/5.0 (WAFred Showcase Sample)";

struct Credentials {
    email: String,
    password: String,
}

pub fn enabled() -> bool {
    parse_enabled(&std::env::var(ENABLED_ENV).unwrap_or_default())
        .unwrap_or(false)
}

fn parse_enabled(value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "0" | "false" | "no" | "off" => Ok(false),
        "1" | "true" | "yes" | "on" => Ok(true),
        _ => bail!("{ENABLED_ENV} must be true or false"),
    }
}

fn validate_credentials(email: &str, password: String) -> Result<Credentials> {
    let email = normalise_email(email).map_err(|_| {
        anyhow::anyhow!("{EMAIL_ENV} is not a valid e-mail address")
    })?;
    // bcrypt only considers the first 72 bytes. Refuse a silently truncated
    // showcase credential and require more than the regular account minimum.
    if password.chars().count() < 12 || password.len() > 72 {
        bail!("{PASSWORD_ENV} must be at least 12 characters and at most 72 bytes");
    }
    Ok(Credentials { email, password })
}

fn credentials_from_env() -> Result<Option<Credentials>> {
    let enabled = std::env::var(ENABLED_ENV).unwrap_or_default();
    if !parse_enabled(&enabled)? {
        return Ok(None);
    }

    let email = std::env::var(EMAIL_ENV).with_context(|| {
        format!("{EMAIL_ENV} is required when {ENABLED_ENV} is set")
    })?;
    let password = std::env::var(PASSWORD_ENV).with_context(|| {
        format!("{PASSWORD_ENV} is required when {ENABLED_ENV} is set")
    })?;
    Ok(Some(validate_credentials(&email, password)?))
}

/// Reconciles one marked account on each start. Disabling revokes outstanding
/// access and refresh tokens through the existing disabled/token-version checks.
pub async fn sync_account(db: &DatabaseConnection) -> Result<()> {
    let credentials = credentials_from_env()?;
    if credentials.is_some() {
        let unfinished_admin = user::Entity::find()
            .filter(user::Column::Role.eq(role::ADMIN))
            .filter(user::Column::Disabled.eq(false))
            .filter(user::Column::MustChangePassword.eq(true))
            .one(db)
            .await?;
        if unfinished_admin.is_some() {
            bail!("complete the initial administrator password change before enabling the showcase account");
        }
    }
    let existing = user::Entity::find()
        .filter(user::Column::IsDemo.eq(true))
        .one(db)
        .await?;

    let Some(credentials) = credentials else {
        if let Some(account) = existing {
            if !account.disabled {
                let mut active: user::ActiveModel = account.into();
                active.disabled = Set(true);
                active.token_version = Set(active.token_version.unwrap() + 1);
                active.updated_at = Set(Utc::now());
                active.update(db).await?;
                tracing::info!("showcase account disabled");
            }
        }
        return Ok(());
    };

    if let Some(account) = existing {
        if account.email != credentials.email {
            let collision = user::Entity::find()
                .filter(user::Column::Email.eq(&credentials.email))
                .one(db)
                .await?;
            if collision.is_some() {
                bail!("showcase e-mail belongs to another account");
            }
        }

        let password_matches =
            verify_password(&credentials.password, &account.password_hash)?;
        let changed_credentials =
            account.email != credentials.email || !password_matches;
        let changed = changed_credentials
            || account.role != role::AUDITOR
            || account.disabled
            || account.must_change_password
            || account.name.as_deref() != Some("WAFred Demo");
        let id = account.id;
        if changed {
            let mut active: user::ActiveModel = account.into();
            active.email = Set(credentials.email);
            if !password_matches {
                active.password_hash =
                    Set(hash_password(&credentials.password)?);
            }
            active.name = Set(Some("WAFred Demo".to_string()));
            active.role = Set(role::AUDITOR.to_string());
            active.disabled = Set(false);
            active.must_change_password = Set(false);
            active.token_version = Set(active.token_version.unwrap() + 1);
            active.updated_at = Set(Utc::now());
            active.update(db).await?;
        }
        remove_secondary_credentials(db, id).await?;
        let site_id = sync_site(db, id).await?;
        refresh_sample_data(db, site_id).await?;
        tracing::info!("showcase account enabled");
        return Ok(());
    }

    let collision = user::Entity::find()
        .filter(user::Column::Email.eq(&credentials.email))
        .one(db)
        .await?;
    if collision.is_some() {
        bail!("showcase e-mail belongs to another account");
    }
    let now = Utc::now();
    let account = user::ActiveModel {
        id: Set(Uuid::new_v4()),
        email: Set(credentials.email),
        password_hash: Set(hash_password(&credentials.password)?),
        name: Set(Some("WAFred Demo".to_string())),
        role: Set(role::AUDITOR.to_string()),
        disabled: Set(false),
        must_change_password: Set(false),
        is_demo: Set(true),
        token_version: Set(0),
        created_at: Set(now),
        updated_at: Set(now),
    };
    let account = account.insert(db).await?;
    let site_id = sync_site(db, account.id).await?;
    refresh_sample_data(db, site_id).await?;
    tracing::info!("showcase account created");
    Ok(())
}

async fn sync_site(db: &DatabaseConnection, owner_id: Uuid) -> Result<Uuid> {
    let owned = site::Entity::find()
        .filter(site::Column::UserId.eq(owner_id))
        .all(db)
        .await?;
    if owned.iter().any(|row| row.domain != SAMPLE_DOMAIN) {
        bail!("the showcase account owns a non-showcase site");
    }
    let existing = owned.into_iter().next();
    if let Some(existing) = existing {
        return Ok(existing.id);
    }

    let site = create_site_for_user(
        db,
        owner_id,
        CreateSiteRequest {
            name: "WAFred 示例商店".to_string(),
            domain: SAMPLE_DOMAIN.to_string(),
            alternate_domains: None,
            upstream_address: "127.0.0.1:8081".to_string(),
            upstream_tls: Some(false),
            status: Some(site_status::PAUSED.to_string()),
            plan: Some("demo".to_string()),
            downstream_timeout_secs:
                crate::defaults::DEFAULT_SITE_DOWNSTREAM_TIMEOUT_SECS as u32,
        },
    )
    .await
    .context("could not create the showcase site")?;
    Ok(site.id)
}

/// Replaces only marked sample rows for the designated site. The periodic
/// refresh keeps the dashboard's rolling 24-hour charts populated.
pub async fn refresh_sample_data(
    db: &DatabaseConnection,
    site_id: Uuid,
) -> Result<()> {
    let latest = access_logs::Entity::find()
        .filter(access_logs::Column::SiteId.eq(site_id))
        .filter(access_logs::Column::UserAgent.eq(SAMPLE_AGENT))
        .order_by_desc(access_logs::Column::Timestamp)
        .one(db)
        .await?;
    let now = Utc::now();
    if latest.is_some_and(|row| row.timestamp > now - Duration::minutes(10)) {
        return Ok(());
    }

    let txn = db.begin().await?;
    access_logs::Entity::delete_many()
        .filter(access_logs::Column::SiteId.eq(site_id))
        .filter(access_logs::Column::UserAgent.eq(SAMPLE_AGENT))
        .exec(&txn)
        .await?;
    security_events::Entity::delete_many()
        .filter(security_events::Column::SiteId.eq(site_id))
        .filter(security_events::Column::UserAgent.eq(SAMPLE_AGENT))
        .exec(&txn)
        .await?;

    let mut requests = Vec::with_capacity(96);
    let mut events = Vec::new();
    for index in 0..96 {
        let timestamp = now - Duration::minutes(1 + (95 - index) * 15);
        let path = ["/", "/products", "/products/42", "/api/search", "/login"]
            [index as usize % 5];
        let client_ip =
            ["192.0.2.24", "198.51.100.18", "203.0.113.42"][index as usize % 3];
        let country_code = ["US", "DE", "JP"][index as usize % 3];
        let status = if index % 17 == 0 {
            429
        } else if index % 9 == 0 {
            403
        } else {
            200
        };
        let request_id = Uuid::new_v4().to_string();
        requests.push(access_logs::ActiveModel {
            site_id: Set(Some(site_id)),
            request_id: Set(Some(request_id.clone())),
            timestamp: Set(timestamp),
            client_ip: Set(client_ip.to_string()),
            method: Set("GET".to_string()),
            host: Set(Some(SAMPLE_DOMAIN.to_string())),
            path: Set(Some(path.to_string())),
            status_code: Set(Some(status)),
            response_size: Set(Some(if status == 200 { 4096 } else { 512 })),
            upstream_latency_ms: Set(Some(20 + index % 15)),
            total_latency_ms: Set(Some(30 + index % 20)),
            cache_status: Set(Some(
                if index % 3 == 0 { "hit" } else { "miss" }.to_string(),
            )),
            user_agent: Set(Some(SAMPLE_AGENT.to_string())),
            country_code: Set(Some(country_code.to_string())),
            tls_version: Set(Some("TLSv1.3".to_string())),
            scheme: Set(Some("https".to_string())),
            protocol: Set(Some("HTTP/2".to_string())),
            ..Default::default()
        });
        if status != 200 {
            let rate_limited = status == 429;
            let (rule_id, rule_name, event_type) = if rate_limited {
                ("WAFRED-DEMO-RATE", "示例频率限制", "rate_limit")
            } else {
                ("WAFRED-DEMO-WAF", "示例 Web 防护规则", "waf")
            };
            events.push(security_events::ActiveModel {
                site_id: Set(Some(site_id)),
                request_id: Set(Some(request_id)),
                timestamp: Set(timestamp),
                client_ip: Set(client_ip.to_string()),
                method: Set("GET".to_string()),
                host: Set(Some(SAMPLE_DOMAIN.to_string())),
                path: Set(Some(path.to_string())),
                rule_id: Set(Some(rule_id.to_string())),
                rule_name: Set(Some(rule_name.to_string())),
                event_type: Set(Some(event_type.to_string())),
                action: Set("block".to_string()),
                score: Set(Some(if rate_limited { 70 } else { 90 })),
                country_code: Set(Some(country_code.to_string())),
                user_agent: Set(Some(SAMPLE_AGENT.to_string())),
                created_at: Set(timestamp),
                ..Default::default()
            });
        }
    }
    access_logs::Entity::insert_many(requests)
        .exec(&txn)
        .await?;
    security_events::Entity::insert_many(events)
        .exec(&txn)
        .await?;
    txn.commit().await?;
    Ok(())
}

/// Keeps synthetic activity current without making the sample site live.
pub async fn run_sample_refresh(db: DatabaseConnection) {
    let mut interval =
        tokio::time::interval(std::time::Duration::from_secs(15 * 60));
    interval.tick().await;
    loop {
        interval.tick().await;
        let result = async {
            let account = user::Entity::find()
                .filter(user::Column::IsDemo.eq(true))
                .filter(user::Column::Disabled.eq(false))
                .one(&db)
                .await?;
            if let Some(account) = account {
                let site_id = sync_site(&db, account.id).await?;
                refresh_sample_data(&db, site_id).await?;
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;
        if let Err(err) = result {
            tracing::warn!(error = %err, "showcase sample refresh failed");
        }
    }
}

async fn remove_secondary_credentials(
    db: &DatabaseConnection,
    id: Uuid,
) -> Result<()> {
    api_key::Entity::delete_many()
        .filter(api_key::Column::UserId.eq(id))
        .exec(db)
        .await?;
    passkey_credential::Entity::delete_many()
        .filter(passkey_credential::Column::UserId.eq(id))
        .exec(db)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_switch_and_credentials_are_required() {
        assert!(!parse_enabled("").unwrap());
        assert!(!parse_enabled("off").unwrap());
        assert!(parse_enabled(" TRUE ").unwrap());
        assert!(parse_enabled("unexpected").is_err());
        assert!(
            validate_credentials("invalid", "long enough password".into())
                .is_err()
        );
        assert!(validate_credentials("demo@example.com", "too-short".into())
            .is_err());
        assert!(
            validate_credentials("demo@example.com", "x".repeat(73)).is_err()
        );
        let valid = validate_credentials(
            " Demo@Example.COM ",
            "long enough password".into(),
        )
        .unwrap();
        assert_eq!(valid.email, "demo@example.com");
    }
}
