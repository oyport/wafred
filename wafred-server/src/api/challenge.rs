//! Challenge/CC protection settings management per site.

use axum::extract::{Path, State};
use axum::routing::get;
use axum::Json;
use axum::Router;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::Deserialize;
use uuid::Uuid;

use crate::api::common::{load_site_read, load_site_write, parse_uuid};
use crate::api::error::ApiError;
use crate::api::sites::touch_site;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::grpc::notify_config_changed;
use crate::models::challenge_settings;

/// Valid challenge levels.
pub mod challenge_level {
    pub const NONE: &str = "none";
    pub const NON_INTERACTIVE: &str = "non_interactive";
    pub const MANAGED: &str = "managed";
    pub const INTERACTIVE: &str = "interactive";

    pub fn is_valid(level: &str) -> bool {
        matches!(level, NONE | NON_INTERACTIVE | MANAGED | INTERACTIVE)
    }

    /// Maps to proto `ChallengeLevel` enum.
    pub fn to_proto(level: &str) -> i32 {
        match level {
            NONE => 0,
            NON_INTERACTIVE => 1,
            MANAGED => 2,
            INTERACTIVE => 3,
            _ => 1,
        }
    }
}

#[derive(Debug, Deserialize)]
// axum 0.8 maps a serde `deny_unknown_fields` rejection to **422
// Unprocessable Entity** (not 400), with a plain-text body — keep any
// documentation of this endpoint aligned with that.
#[serde(deny_unknown_fields)]
pub struct UpdateChallengeRequest {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub under_attack_mode: Option<bool>,
    #[serde(default)]
    pub default_level: Option<String>,
    #[serde(default)]
    pub clearance_duration_secs: Option<i32>,
    #[serde(default)]
    pub rate_threshold: Option<i32>,
    #[serde(default)]
    pub exempt_paths: Option<Vec<String>>,
    #[serde(default)]
    pub browser_integrity_check: Option<bool>,
    #[serde(default)]
    pub tls_fingerprint_check: Option<bool>,
    /// Proof-of-work difficulty a quiet visitor solves (leading zero bits).
    #[serde(default)]
    pub base_difficulty: Option<i32>,
    /// Ceiling adaptive difficulty may rise to under pressure.
    #[serde(default)]
    pub max_difficulty: Option<i32>,
    /// Challenge pages issued per host+IP per 60-second window.
    #[serde(default)]
    pub issue_limit_per_min: Option<i32>,
    /// Solution submissions accepted per host+IP per 60-second window.
    #[serde(default)]
    pub verify_limit_per_min: Option<i32>,
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new().route(
        "/sites/{site_id}/challenge",
        get(get_challenge).put(update_challenge),
    )
}

/// `GET /api/v1/sites/{site_id}/challenge`
async fn get_challenge(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<challenge_settings::Model>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, id, &current).await?;

    let row = find_or_create(&state, id).await?;
    Ok(Json(row))
}

/// `PUT /api/v1/sites/{site_id}/challenge`
async fn update_challenge(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<UpdateChallengeRequest>,
) -> Result<Json<challenge_settings::Model>, ApiError> {
    let id = parse_uuid(&site_id, "site id")?;
    load_site_write(&state.db, id, &current).await?;

    let row = find_or_create(&state, id).await?;
    // The current row is kept for cross-field validation: a partial update
    // must be checked against the values it does not touch.
    let existing = row.clone();
    let mut active: challenge_settings::ActiveModel = row.into();

    if let Some(enabled) = payload.enabled {
        active.enabled = Set(enabled);
    }
    if let Some(uam) = payload.under_attack_mode {
        active.under_attack_mode = Set(uam);
        // Under-attack mode is meaningless without the challenge gate: the
        // engine short-circuits to Pass when `enabled` is false, so turning
        // the banner on forces the gate on. Turning it off leaves `enabled`
        // alone — the operator may still want plain CC protection.
        if uam {
            active.enabled = Set(true);
        }
    }
    if let Some(level) = payload.default_level {
        if !challenge_level::is_valid(&level) {
            return Err(ApiError::BadRequest(format!(
                "invalid challenge level '{level}'; expected none, non_interactive, managed, interactive"
            )));
        }
        active.default_level = Set(level);
    }
    if let Some(duration) = payload.clearance_duration_secs {
        if !(60..=86400).contains(&duration) {
            return Err(ApiError::BadRequest(
                "clearance_duration_secs must be between 60 and 86400"
                    .to_string(),
            ));
        }
        active.clearance_duration_secs = Set(duration);
    }
    if let Some(threshold) = payload.rate_threshold {
        if !(1..=10_000_000).contains(&threshold) {
            return Err(ApiError::BadRequest(
                "rate_threshold must be between 1 and 10000000".to_string(),
            ));
        }
        active.rate_threshold = Set(threshold);
    }
    if let Some(paths) = payload.exempt_paths {
        active.exempt_paths = Set(validate_exempt_paths(&paths)?);
    }
    if let Some(bic) = payload.browser_integrity_check {
        active.browser_integrity_check = Set(bic);
    }
    if let Some(tls) = payload.tls_fingerprint_check {
        active.tls_fingerprint_check = Set(tls);
    }
    if let Some(base) = payload.base_difficulty {
        validate_difficulty("base_difficulty", base)?;
        active.base_difficulty = Set(base);
    }
    if let Some(max) = payload.max_difficulty {
        validate_difficulty("max_difficulty", max)?;
        active.max_difficulty = Set(max);
    }
    if payload.base_difficulty.is_some() || payload.max_difficulty.is_some() {
        validate_difficulty_pair(
            payload.base_difficulty.unwrap_or(existing.base_difficulty),
            payload.max_difficulty.unwrap_or(existing.max_difficulty),
        )?;
    }
    if let Some(limit) = payload.issue_limit_per_min {
        validate_limit_per_min("issue_limit_per_min", limit)?;
        active.issue_limit_per_min = Set(limit);
    }
    if let Some(limit) = payload.verify_limit_per_min {
        validate_limit_per_min("verify_limit_per_min", limit)?;
        active.verify_limit_per_min = Set(limit);
    }
    active.updated_at = Set(chrono::Utc::now());

    let updated = active.update(&state.db).await?;
    tracing::info!(site_id = %id, "challenge settings updated");
    touch_site(&state, id).await?;
    notify_config_changed(&state, id, Some(&current.email)).await;

    Ok(Json(updated))
}

/// Smallest proof-of-work difficulty the API accepts. Below this the work is
/// decorative; the historical default is 20.
const MIN_DIFFICULTY: i32 = 4;
/// Largest proof-of-work difficulty the API accepts. A browser must still be
/// able to finish the work, so even an explicit request is bounded.
const MAX_DIFFICULTY: i32 = 28;
/// Bounds for the per host+IP per-minute limits. Zero is rejected on purpose:
/// "unlimited" is not a value an operator should be able to store by accident,
/// and the data plane reads a stored 0 as "unset, use the default".
const MIN_LIMIT_PER_MIN: i32 = 1;
const MAX_LIMIT_PER_MIN: i32 = 1_000_000;

/// Validates one difficulty setting.
fn validate_difficulty(field: &str, value: i32) -> Result<(), ApiError> {
    if !(MIN_DIFFICULTY..=MAX_DIFFICULTY).contains(&value) {
        return Err(ApiError::BadRequest(format!(
            "{field} must be between {MIN_DIFFICULTY} and {MAX_DIFFICULTY}"
        )));
    }
    Ok(())
}

/// Validates the adaptive range as a pair. A max below the base would make the
/// adaptive step meaningless, so the two are checked together against the
/// values the update leaves in place.
fn validate_difficulty_pair(base: i32, max: i32) -> Result<(), ApiError> {
    if max < base {
        return Err(ApiError::BadRequest(format!(
            "max_difficulty ({max}) must be greater than or equal to base_difficulty ({base})"
        )));
    }
    Ok(())
}

/// Validates one per-minute per-IP limit.
fn validate_limit_per_min(field: &str, value: i32) -> Result<(), ApiError> {
    if !(MIN_LIMIT_PER_MIN..=MAX_LIMIT_PER_MIN).contains(&value) {
        return Err(ApiError::BadRequest(format!(
            "{field} must be between {MIN_LIMIT_PER_MIN} and {MAX_LIMIT_PER_MIN}"
        )));
    }
    Ok(())
}

/// Upper bounds for `exempt_paths`: a path-bypass list is small by nature,
/// and unbounded entries would let a console payload inflate the rule bundle
/// pushed to every agent.
const MAX_EXEMPT_PATHS: usize = 100;
const MAX_EXEMPT_PATH_LEN: usize = 512;

/// Normalises and validates the `exempt_paths` bypass list.
///
/// Entries are trimmed and blanks dropped; each remaining entry must start
/// with `/`, contain no whitespace or control characters, and fit the
/// per-entry and per-list size caps.
fn validate_exempt_paths(paths: &[String]) -> Result<Vec<String>, ApiError> {
    if paths.len() > MAX_EXEMPT_PATHS {
        return Err(ApiError::BadRequest(format!(
            "exempt_paths accepts at most {MAX_EXEMPT_PATHS} entries"
        )));
    }
    let mut normalised = Vec::with_capacity(paths.len());
    for raw in paths {
        let path = raw.trim();
        if path.is_empty() {
            continue;
        }
        if !path.starts_with('/') {
            return Err(ApiError::BadRequest(format!(
                "invalid exempt path '{path}': must start with '/'"
            )));
        }
        if path.len() > MAX_EXEMPT_PATH_LEN {
            return Err(ApiError::BadRequest(format!(
                "invalid exempt path '{path}': at most {MAX_EXEMPT_PATH_LEN} characters"
            )));
        }
        if path.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(ApiError::BadRequest(format!(
                "invalid exempt path '{path}': whitespace and control characters are not allowed"
            )));
        }
        normalised.push(path.to_string());
    }
    Ok(normalised)
}

/// Finds the challenge_settings row for a site, creating a default one if absent.
async fn find_or_create(
    state: &AppState,
    site_id: Uuid,
) -> Result<challenge_settings::Model, ApiError> {
    if let Some(row) = challenge_settings::Entity::find()
        .filter(challenge_settings::Column::SiteId.eq(site_id))
        .one(&state.db)
        .await?
    {
        return Ok(row);
    }

    let now = chrono::Utc::now();
    let model = challenge_settings::ActiveModel {
        id: Set(Uuid::new_v4()),
        site_id: Set(site_id),
        enabled: Set(false),
        under_attack_mode: Set(false),
        default_level: Set(challenge_level::NON_INTERACTIVE.to_string()),
        clearance_duration_secs: Set(1800),
        rate_threshold: Set(100),
        exempt_paths: Set(Vec::new()),
        browser_integrity_check: Set(true),
        tls_fingerprint_check: Set(false),
        base_difficulty: Set(20),
        max_difficulty: Set(24),
        issue_limit_per_min: Set(120),
        verify_limit_per_min: Set(300),
        updated_at: Set(now),
    }
    .insert(&state.db)
    .await?;

    Ok(model)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exempt_paths_are_trimmed_and_blanks_dropped() {
        let paths =
            validate_exempt_paths(&[" /a ".to_string(), "  ".to_string()])
                .unwrap();
        assert_eq!(paths, vec!["/a".to_string()]);
        assert!(validate_exempt_paths(&[]).unwrap().is_empty());
    }

    #[test]
    fn exempt_paths_must_start_with_slash() {
        assert!(validate_exempt_paths(&["api/health".to_string()]).is_err());
        assert!(validate_exempt_paths(&["*".to_string()]).is_err());
    }

    #[test]
    fn exempt_paths_reject_whitespace_and_control_chars() {
        assert!(
            validate_exempt_paths(&["/a b".to_string()]).is_err(),
            "embedded whitespace is refused"
        );
        assert!(validate_exempt_paths(&["/a\tb".to_string()]).is_err());
        assert!(
            validate_exempt_paths(&["/a\u{7}b".to_string()]).is_err(),
            "control characters are refused"
        );
    }

    #[test]
    fn difficulty_bounds_are_enforced() {
        assert!(validate_difficulty("base_difficulty", 4).is_ok());
        assert!(validate_difficulty("base_difficulty", 20).is_ok());
        assert!(validate_difficulty("max_difficulty", 28).is_ok());
        assert!(validate_difficulty("base_difficulty", 3).is_err());
        assert!(validate_difficulty("max_difficulty", 29).is_err());
        assert!(validate_difficulty("base_difficulty", -1).is_err());
    }

    #[test]
    fn max_difficulty_must_not_undercut_the_base() {
        assert!(validate_difficulty_pair(20, 24).is_ok());
        assert!(validate_difficulty_pair(20, 20).is_ok());
        assert!(validate_difficulty_pair(24, 20).is_err());
    }

    #[test]
    fn per_minute_limits_must_be_positive_and_bounded() {
        assert!(validate_limit_per_min("issue_limit_per_min", 1).is_ok());
        assert!(validate_limit_per_min("issue_limit_per_min", 120).is_ok());
        assert!(validate_limit_per_min(
            "verify_limit_per_min",
            MAX_LIMIT_PER_MIN
        )
        .is_ok());
        // Zero is the data plane's "unset" marker, not an operator value.
        assert!(validate_limit_per_min("issue_limit_per_min", 0).is_err());
        assert!(validate_limit_per_min(
            "verify_limit_per_min",
            MAX_LIMIT_PER_MIN + 1
        )
        .is_err());
    }

    #[test]
    fn exempt_paths_are_size_capped() {
        let long = format!("/{}", "a".repeat(MAX_EXEMPT_PATH_LEN));
        assert!(validate_exempt_paths(&[long]).is_err());

        let many: Vec<String> =
            (0..=MAX_EXEMPT_PATHS).map(|i| format!("/p{i}")).collect();
        assert!(validate_exempt_paths(&many).is_err());
        let ok: Vec<String> =
            (0..MAX_EXEMPT_PATHS).map(|i| format!("/p{i}")).collect();
        assert_eq!(validate_exempt_paths(&ok).unwrap().len(), MAX_EXEMPT_PATHS);
    }
}
