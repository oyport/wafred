//! Per-site path restrictions: block requests, challenge with Basic Auth, or
//! require a site's OIDC session for selected paths.

use axum::extract::{Path, State};
use axum::routing::get;
use axum::Json;
use axum::Router;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, Set,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::common::{load_site_read, load_site_write, parse_uuid};
use crate::api::error::ApiError;
use crate::api::sites::touch_site;
use crate::api::state::AppState;
use crate::api::validation::validate_expression;
use crate::auth::AuthUser;
use crate::grpc::notify_config_changed;
use crate::models::{path_restrictions, site_basic_auth, site_oidc};

pub const MAX_PATH_RESTRICTIONS: usize = 64;
pub const MAX_PATH_LEN: usize = 512;
pub const MAX_NAME_LEN: usize = 120;
pub const MAX_EXPRESSION_LEN: usize = 4096;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/sites/{site_id}/path-restrictions", get(list).post(create))
        .route(
            "/sites/{site_id}/path-restrictions/{id}",
            get(show).put(update).delete(delete),
        )
}

#[derive(Debug, Deserialize, Default)]
pub struct PathRestrictionRequest {
    pub name: Option<String>,
    pub path: Option<String>,
    pub match_type: Option<String>,
    pub expression: Option<String>,
    pub action: Option<String>,
    pub threshold: Option<u32>,
    pub period_seconds: Option<u32>,
    pub block_duration_seconds: Option<u32>,
    pub schedule_enabled: Option<bool>,
    pub schedule_timezone: Option<String>,
    pub schedule_days: Option<Vec<i32>>,
    pub schedule_start: Option<String>,
    pub schedule_end: Option<String>,
    pub enabled: Option<bool>,
    pub priority: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct PathRestrictionView {
    pub id: Uuid,
    pub site_id: Uuid,
    pub name: String,
    pub path: String,
    pub match_type: String,
    pub expression: String,
    pub action: String,
    pub threshold: u32,
    pub period_seconds: u32,
    pub block_duration_seconds: u32,
    pub schedule_enabled: bool,
    pub schedule_timezone: String,
    pub schedule_days: Vec<i32>,
    pub schedule_start: String,
    pub schedule_end: String,
    pub enabled: bool,
    pub priority: u32,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
}

impl From<path_restrictions::Model> for PathRestrictionView {
    fn from(row: path_restrictions::Model) -> Self {
        Self {
            id: row.id,
            site_id: row.site_id,
            name: row.name,
            path: row.path,
            match_type: row.match_type,
            expression: row.expression,
            action: row.action,
            threshold: row.threshold.max(0) as u32,
            period_seconds: row.period_seconds.max(1) as u32,
            block_duration_seconds: row.block_duration_seconds.max(0) as u32,
            schedule_enabled: row.schedule_enabled,
            schedule_timezone: row.schedule_timezone,
            schedule_days: row.schedule_days,
            schedule_start: row.schedule_start,
            schedule_end: row.schedule_end,
            enabled: row.enabled,
            priority: row.priority.max(0) as u32,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(Debug)]
struct Resolved {
    name: String,
    path: String,
    match_type: String,
    expression: String,
    action: String,
    threshold: u32,
    period_seconds: u32,
    block_duration_seconds: u32,
    schedule_enabled: bool,
    schedule_timezone: String,
    schedule_days: Vec<i32>,
    schedule_start: String,
    schedule_end: String,
    enabled: bool,
    priority: u32,
}

impl Resolved {
    fn defaults() -> Self {
        Self {
            name: String::new(),
            path: String::new(),
            match_type: "prefix".to_string(),
            expression: String::new(),
            action: "block".to_string(),
            threshold: 0,
            period_seconds: 60,
            block_duration_seconds: 60,
            schedule_enabled: false,
            schedule_timezone: "UTC".to_string(),
            schedule_days: (1..=7).collect(),
            schedule_start: "00:00".to_string(),
            schedule_end: "23:59".to_string(),
            enabled: true,
            priority: 100,
        }
    }

    fn from_row(row: &path_restrictions::Model) -> Self {
        Self {
            name: row.name.clone(),
            path: row.path.clone(),
            match_type: row.match_type.clone(),
            expression: row.expression.clone(),
            action: row.action.clone(),
            threshold: row.threshold.max(0) as u32,
            period_seconds: row.period_seconds.max(1) as u32,
            block_duration_seconds: row.block_duration_seconds.max(0) as u32,
            schedule_enabled: row.schedule_enabled,
            schedule_timezone: row.schedule_timezone.clone(),
            schedule_days: row.schedule_days.clone(),
            schedule_start: row.schedule_start.clone(),
            schedule_end: row.schedule_end.clone(),
            enabled: row.enabled,
            priority: row.priority.max(0) as u32,
        }
    }

    fn merge(&mut self, payload: PathRestrictionRequest) {
        if let Some(value) = payload.name {
            self.name = value;
        }
        if let Some(value) = payload.path {
            self.path = value;
        }
        if let Some(value) = payload.match_type {
            self.match_type = value;
        }
        if let Some(value) = payload.expression {
            self.expression = value;
        }
        if let Some(value) = payload.action {
            self.action = value;
        }
        if let Some(value) = payload.threshold {
            self.threshold = value;
        }
        if let Some(value) = payload.period_seconds {
            self.period_seconds = value;
        }
        if let Some(value) = payload.block_duration_seconds {
            self.block_duration_seconds = value;
        }
        if let Some(value) = payload.schedule_enabled {
            self.schedule_enabled = value;
        }
        if let Some(value) = payload.schedule_timezone {
            self.schedule_timezone = value;
        }
        if let Some(value) = payload.schedule_days {
            self.schedule_days = value;
        }
        if let Some(value) = payload.schedule_start {
            self.schedule_start = value;
        }
        if let Some(value) = payload.schedule_end {
            self.schedule_end = value;
        }
        if let Some(value) = payload.enabled {
            self.enabled = value;
        }
        if let Some(value) = payload.priority {
            self.priority = value;
        }
    }

    fn validate(&mut self) -> Result<(), ApiError> {
        self.name = self.name.trim().to_string();
        if self.name.is_empty() {
            return Err(ApiError::BadRequest(
                "name must not be empty".to_string(),
            ));
        }
        if self.name.chars().count() > MAX_NAME_LEN {
            return Err(ApiError::BadRequest(format!(
                "name accepts at most {MAX_NAME_LEN} characters"
            )));
        }
        self.match_type = self.match_type.trim().to_string();
        if !matches!(
            self.match_type.as_str(),
            "prefix" | "exact" | "wildcard" | "regex"
        ) {
            return Err(ApiError::BadRequest(
                "match_type must be prefix, exact, wildcard, or regex"
                    .to_string(),
            ));
        }
        self.path = validate_path(&self.path, &self.match_type)?;
        self.action = self.action.trim().to_string();
        if !matches!(self.action.as_str(), "block" | "basic_auth" | "oidc") {
            return Err(ApiError::BadRequest(
                "action must be block, basic_auth, or oidc".to_string(),
            ));
        }
        self.expression = self.expression.trim().to_string();
        if self.expression.len() > MAX_EXPRESSION_LEN {
            return Err(ApiError::BadRequest(format!(
                "expression accepts at most {MAX_EXPRESSION_LEN} bytes"
            )));
        }
        if !self.expression.is_empty() {
            validate_expression(&self.expression)?;
        }
        if !(1..=86_400).contains(&self.period_seconds) {
            return Err(ApiError::BadRequest(
                "period_seconds must be between 1 and 86400".to_string(),
            ));
        }
        if self.block_duration_seconds > 604_800 {
            return Err(ApiError::BadRequest(
                "block_duration_seconds must not exceed 604800".to_string(),
            ));
        }
        if self.action != "block" && self.threshold != 0 {
            return Err(ApiError::BadRequest(
                "threshold is only available for block rules".to_string(),
            ));
        }
        if self.threshold > i32::MAX as u32 {
            return Err(ApiError::BadRequest(
                "threshold must fit a signed 32-bit value".to_string(),
            ));
        }
        if self.priority > i32::MAX as u32 {
            return Err(ApiError::BadRequest(
                "priority must fit a signed 32-bit value".to_string(),
            ));
        }
        self.schedule_timezone = self.schedule_timezone.trim().to_string();
        if self.schedule_timezone.is_empty() {
            self.schedule_timezone = "UTC".to_string();
        }
        if self.schedule_timezone.len() > 64 {
            return Err(ApiError::BadRequest(
                "schedule_timezone must be at most 64 bytes".to_string(),
            ));
        }
        if self.schedule_timezone.parse::<chrono_tz::Tz>().is_err() {
            return Err(ApiError::BadRequest(
                "schedule_timezone must be a valid IANA time zone".to_string(),
            ));
        }
        self.schedule_days.sort_unstable();
        self.schedule_days.dedup();
        if self.schedule_days.iter().any(|day| !(1..=7).contains(day))
            || (self.schedule_enabled && self.schedule_days.is_empty())
        {
            return Err(ApiError::BadRequest("schedule_days must contain weekdays 1 through 7 when scheduling is enabled".to_string()));
        }
        validate_time(&self.schedule_start)?;
        validate_time(&self.schedule_end)?;
        if self.schedule_enabled && self.schedule_start == self.schedule_end {
            return Err(ApiError::BadRequest(
                "schedule_start and schedule_end must differ".to_string(),
            ));
        }
        Ok(())
    }
}

fn validate_time(value: &str) -> Result<(), ApiError> {
    let mut parts = value.split(':');
    let hour = parts.next().and_then(|v| v.parse::<u8>().ok());
    let minute = parts.next().and_then(|v| v.parse::<u8>().ok());
    if parts.next().is_some()
        || hour.is_none_or(|v| v > 23)
        || minute.is_none_or(|v| v > 59)
        || value.len() != 5
    {
        return Err(ApiError::BadRequest(
            "schedule times must use HH:MM (24-hour) format".to_string(),
        ));
    }
    Ok(())
}

fn validate_path(raw: &str, match_type: &str) -> Result<String, ApiError> {
    let path = raw.trim();
    if path.is_empty() || path.len() > MAX_PATH_LEN {
        return Err(ApiError::BadRequest(format!(
            "path must be 1 to {MAX_PATH_LEN} characters"
        )));
    }
    if path.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(ApiError::BadRequest(
            "path must not contain whitespace or control characters"
                .to_string(),
        ));
    }
    if match_type == "regex" {
        regex::RegexBuilder::new(path)
            .size_limit(4 * 1024 * 1024)
            .dfa_size_limit(4 * 1024 * 1024)
            .build()
            .map_err(|err| {
                ApiError::BadRequest(format!("invalid path regex: {err}"))
            })?;
        return Ok(path.to_string());
    }
    if !path.starts_with('/') {
        return Err(ApiError::BadRequest(
            "path must start with '/'".to_string(),
        ));
    }
    if match_type == "wildcard" {
        if !path.ends_with('*') || path[..path.len() - 1].contains('*') {
            return Err(ApiError::BadRequest(
                "wildcard paths must have one trailing '*'".to_string(),
            ));
        }
    } else if path.contains('*') {
        return Err(ApiError::BadRequest(
            "'*' is only supported with wildcard matching".to_string(),
        ));
    }
    Ok(path.to_string())
}

async fn validate_auth_dependencies(
    state: &AppState,
    site_id: Uuid,
    action: &str,
) -> Result<(), ApiError> {
    match action {
        "basic_auth" => {
            let ready = site_basic_auth::Entity::find()
                .filter(site_basic_auth::Column::SiteId.eq(site_id))
                .filter(site_basic_auth::Column::Enabled.eq(true))
                .one(&state.db)
                .await?
                .is_some();
            if !ready {
                return Err(ApiError::BadRequest("configure and enable Basic Auth in Access Control before adding this rule".to_string()));
            }
        },
        "oidc" => {
            let ready = site_oidc::Entity::find()
                .filter(site_oidc::Column::SiteId.eq(site_id))
                .filter(site_oidc::Column::Enabled.eq(true))
                .filter(site_oidc::Column::AuthScope.eq("path"))
                .one(&state.db)
                .await?
                .is_some_and(|oidc| oidc.auth_mode == "oidc");
            if !ready {
                return Err(ApiError::BadRequest("enable OIDC with 'path restrictions only' scope before adding this rule".to_string()));
            }
        },
        _ => {},
    }
    Ok(())
}

async fn list(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
) -> Result<Json<Vec<PathRestrictionView>>, ApiError> {
    let site_id = parse_uuid(&site_id, "site id")?;
    load_site_read(&state.db, site_id, &current).await?;
    let rows = path_restrictions::Entity::find()
        .filter(path_restrictions::Column::SiteId.eq(site_id))
        .order_by_asc(path_restrictions::Column::Priority)
        .order_by_asc(path_restrictions::Column::Id)
        .all(&state.db)
        .await?;
    Ok(Json(
        rows.into_iter().map(PathRestrictionView::from).collect(),
    ))
}

async fn show(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, id)): Path<(String, String)>,
) -> Result<Json<PathRestrictionView>, ApiError> {
    let site_id = parse_uuid(&site_id, "site id")?;
    let id = parse_uuid(&id, "path restriction id")?;
    load_site_read(&state.db, site_id, &current).await?;
    let row = find(&state, site_id, id).await?;
    Ok(Json(PathRestrictionView::from(row)))
}

async fn create(
    State(state): State<AppState>,
    current: AuthUser,
    Path(site_id): Path<String>,
    Json(payload): Json<PathRestrictionRequest>,
) -> Result<Json<PathRestrictionView>, ApiError> {
    let site_id = parse_uuid(&site_id, "site id")?;
    load_site_write(&state.db, site_id, &current).await?;
    let count = path_restrictions::Entity::find()
        .filter(path_restrictions::Column::SiteId.eq(site_id))
        .count(&state.db)
        .await? as usize;
    if count >= MAX_PATH_RESTRICTIONS {
        return Err(ApiError::BadRequest(format!(
            "a site can have at most {MAX_PATH_RESTRICTIONS} path restrictions"
        )));
    }
    let mut resolved = Resolved::defaults();
    resolved.merge(payload);
    if resolved.name.is_empty() {
        resolved.name = resolved.path.clone();
    }
    resolved.validate()?;
    validate_auth_dependencies(&state, site_id, &resolved.action).await?;
    let now = Utc::now();
    let row = path_restrictions::ActiveModel {
        id: Set(Uuid::new_v4()),
        site_id: Set(site_id),
        name: Set(resolved.name),
        path: Set(resolved.path),
        match_type: Set(resolved.match_type),
        expression: Set(resolved.expression),
        action: Set(resolved.action),
        threshold: Set(resolved.threshold as i32),
        period_seconds: Set(resolved.period_seconds as i32),
        block_duration_seconds: Set(resolved.block_duration_seconds as i32),
        schedule_enabled: Set(resolved.schedule_enabled),
        schedule_timezone: Set(resolved.schedule_timezone),
        schedule_days: Set(resolved.schedule_days),
        schedule_start: Set(resolved.schedule_start),
        schedule_end: Set(resolved.schedule_end),
        enabled: Set(resolved.enabled),
        priority: Set(resolved.priority as i32),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&state.db)
    .await?;
    touch_site(&state, site_id).await?;
    notify_config_changed(&state, site_id, Some(&current.email)).await;
    Ok(Json(PathRestrictionView::from(row)))
}

async fn update(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, id)): Path<(String, String)>,
    Json(payload): Json<PathRestrictionRequest>,
) -> Result<Json<PathRestrictionView>, ApiError> {
    let site_id = parse_uuid(&site_id, "site id")?;
    let id = parse_uuid(&id, "path restriction id")?;
    load_site_write(&state.db, site_id, &current).await?;
    let row = find(&state, site_id, id).await?;
    let mut resolved = Resolved::from_row(&row);
    resolved.merge(payload);
    resolved.validate()?;
    validate_auth_dependencies(&state, site_id, &resolved.action).await?;
    let mut active: path_restrictions::ActiveModel = row.into();
    active.name = Set(resolved.name);
    active.path = Set(resolved.path);
    active.match_type = Set(resolved.match_type);
    active.expression = Set(resolved.expression);
    active.action = Set(resolved.action);
    active.threshold = Set(resolved.threshold as i32);
    active.period_seconds = Set(resolved.period_seconds as i32);
    active.block_duration_seconds = Set(resolved.block_duration_seconds as i32);
    active.schedule_enabled = Set(resolved.schedule_enabled);
    active.schedule_timezone = Set(resolved.schedule_timezone);
    active.schedule_days = Set(resolved.schedule_days);
    active.schedule_start = Set(resolved.schedule_start);
    active.schedule_end = Set(resolved.schedule_end);
    active.enabled = Set(resolved.enabled);
    active.priority = Set(resolved.priority as i32);
    active.updated_at = Set(Utc::now());
    let row = active.update(&state.db).await?;
    touch_site(&state, site_id).await?;
    notify_config_changed(&state, site_id, Some(&current.email)).await;
    Ok(Json(PathRestrictionView::from(row)))
}

async fn delete(
    State(state): State<AppState>,
    current: AuthUser,
    Path((site_id, id)): Path<(String, String)>,
) -> Result<axum::http::StatusCode, ApiError> {
    let site_id = parse_uuid(&site_id, "site id")?;
    let id = parse_uuid(&id, "path restriction id")?;
    load_site_write(&state.db, site_id, &current).await?;
    let result = path_restrictions::Entity::delete_many()
        .filter(path_restrictions::Column::SiteId.eq(site_id))
        .filter(path_restrictions::Column::Id.eq(id))
        .exec(&state.db)
        .await?;
    if result.rows_affected == 0 {
        return Err(ApiError::NotFound(format!(
            "path restriction {id} not found"
        )));
    }
    touch_site(&state, site_id).await?;
    notify_config_changed(&state, site_id, Some(&current.email)).await;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

async fn find(
    state: &AppState,
    site_id: Uuid,
    id: Uuid,
) -> Result<path_restrictions::Model, ApiError> {
    path_restrictions::Entity::find_by_id(id)
        .filter(path_restrictions::Column::SiteId.eq(site_id))
        .one(&state.db)
        .await?
        .ok_or_else(|| {
            ApiError::NotFound(format!("path restriction {id} not found"))
        })
}
