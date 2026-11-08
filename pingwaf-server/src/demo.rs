//! Private, deployment-only showcase account. No public API or dashboard setting.

use anyhow::{bail, Context, Result};
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait,
    QueryFilter, Set,
};
use uuid::Uuid;

use crate::api::auth::normalise_email;
use crate::auth::password::{hash_password, verify_password};
use crate::models::{api_key, passkey_credential, role, user};

const ENABLED_ENV: &str = "WAFRED_DEMO_ENABLED";
const EMAIL_ENV: &str = "WAFRED_DEMO_EMAIL";
const PASSWORD_ENV: &str = "WAFRED_DEMO_PASSWORD";

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
    account.insert(db).await?;
    tracing::info!("showcase account created");
    Ok(())
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
