//! Tunnel connectors: creation, pairing, revocation and visibility.
//!
//! A tunnel is created here, not by the connector: the console mints a one-time
//! pairing token and shows the command that uses it. The connector redeems the
//! token over gRPC ([`crate::grpc::control_plane`]) and receives a long-lived
//! credential; from then on the edges admit it by the credential's SHA-256,
//! which this module keeps in step with the rule bundle.
//!
//! Nothing here touches the data path. Revoking a tunnel writes the database,
//! pushes a fresh bundle to the edges (which drop the live session within one
//! reload) and tells a connected connector it has been revoked.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use sea_orm::sea_query::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, Set,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::common::{parse_uuid, require_write, Page, Pagination};
use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::auth::AuthUser;
use crate::grpc::{
    notify_all_config_changed, notify_all_tunnel_connectors,
    notify_tunnel_connectors, TUNNEL_CONNECTORS,
};
use crate::models::{
    agent, site, site_upstream_pools, tunnel_connector, tunnel_session,
    tunnel_setting, tunnel_status,
};
use crate::tunnel_policy;

/// Installer published with the repository root, fetched over HTTPS so a bare
/// host needs nothing but `curl` (same script the agent uses).
const INSTALL_SCRIPT_URL: &str =
    "https://raw.githubusercontent.com/oyport/wafred/main/install.sh";

const MAX_NAME_LEN: usize = 120;
const MAX_DESCRIPTION_LEN: usize = 500;

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/tunnels", get(list).post(create))
        .route(
            "/tunnels/{tunnel_id}",
            get(show).patch(update).delete(remove),
        )
        .route("/tunnels/{tunnel_id}/pairing", post(mint_pairing))
        .route("/tunnels/{tunnel_id}/revoke", post(revoke))
        .route("/tunnels/{tunnel_id}/sessions", get(sessions))
        .route("/settings/tunnel", get(show_settings).put(update_settings))
}

// ─────────────────────────────────────────────────────────────
// Views
// ─────────────────────────────────────────────────────────────

/// One tunnel as the console shows it.
#[derive(Debug, Serialize)]
pub struct TunnelView {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub status: String,
    /// A credential exists (the tunnel has been paired at least once).
    pub paired: bool,
    /// The deployment switch is on and this tunnel is not disabled.
    pub enabled: bool,
    /// A connector currently holds the control stream.
    pub connector_online: bool,
    pub connector_version: Option<String>,
    pub connector_hostname: Option<String>,
    pub last_seen_at: Option<DateTime<Utc>>,
    /// Internal origins the connector serves, derived from the pools bound to
    /// this tunnel.
    pub targets: Vec<String>,
    /// Domains of the sites whose origin pools are bound to this tunnel. The
    /// blast radius of disabling or deleting it.
    pub sites: Vec<String>,
    /// Public `host:port` endpoints a connector can dial right now (an edge
    /// with a bound listener *and* an operator-set ingress address). Empty
    /// means no connector can connect yet — the console shows what is missing
    /// instead of leaving the operator with a pairing command that cannot work.
    pub ingress: Vec<String>,
    pub sessions: Vec<SessionView>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// One edge session held by a connector.
#[derive(Debug, Serialize)]
pub struct SessionView {
    pub agent_id: Uuid,
    pub agent_name: String,
    pub agent_status: String,
    pub connected_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub streams_active: i32,
    pub rtt_ms: i32,
    pub version: Option<String>,
    pub hostname: Option<String>,
}

/// What creating a tunnel (or minting a new pairing token) returns.
#[derive(Debug, Serialize)]
pub struct PairingView {
    pub tunnel: TunnelView,
    /// The one-time token. Returned exactly once; only its digest is stored.
    pub pairing_token: String,
    /// Command that installs the connector and pairs it in one step.
    pub pairing_command: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct DeleteQuery {
    /// Delete even when origin pools are still bound (they fall back to direct
    /// origins). Without it a bound tunnel is a `409`.
    #[serde(default)]
    pub force: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    pub search: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(flatten)]
    pub pagination: Pagination,
}

#[derive(Debug, Deserialize)]
pub struct CreateRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// `active` or `disabled`; `pending` is managed by pairing.
    #[serde(default)]
    pub status: Option<String>,
}

// ─────────────────────────────────────────────────────────────
// Handlers
// ─────────────────────────────────────────────────────────────

/// `GET /api/v1/tunnels`.
async fn list(
    State(state): State<AppState>,
    current: AuthUser,
    Query(query): Query<ListQuery>,
) -> Result<Json<Page<TunnelView>>, ApiError> {
    let pagination = query.pagination.normalise();
    let mut find = tunnel_connector::Entity::find()
        .order_by_desc(tunnel_connector::Column::CreatedAt);
    // Tunnels are deployment infrastructure, but the internal addresses they
    // expose belong to the sites they serve. A non-admin sees only the tunnels
    // at least one of their own sites is bound to — the same boundary
    // `agents::list` draws for a node.
    if let Some(visible) = visible_tunnel_ids(&state, &current).await? {
        find = find.filter(tunnel_connector::Column::Id.is_in(visible));
    }
    if let Some(status) = query
        .status
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        find = find.filter(tunnel_connector::Column::Status.eq(status));
    }
    if let Some(search) = query
        .search
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        find = find.filter(tunnel_connector::Column::Name.contains(search));
    }
    let total = find.clone().count(&state.db).await?;
    let rows = find
        .paginate(&state.db, pagination.page_size)
        .fetch_page(pagination.page.saturating_sub(1))
        .await?;
    let views = build_views(&state, rows, scope_owner(&current)).await?;
    Ok(Json(Page::new(views, total, pagination)))
}

/// `GET /api/v1/tunnels/{id}`.
async fn show(
    State(state): State<AppState>,
    current: AuthUser,
    Path(tunnel_id): Path<String>,
) -> Result<Json<TunnelView>, ApiError> {
    let tunnel_id = parse_uuid(&tunnel_id, "tunnel id")?;
    let row = load(&state, tunnel_id).await?;
    ensure_visible(&state, &current, &row).await?;
    let mut views =
        build_views(&state, vec![row], scope_owner(&current)).await?;
    views
        .pop()
        .map(Json)
        .ok_or_else(|| ApiError::NotFound("tunnel not found".to_string()))
}

/// `POST /api/v1/tunnels` — creates a tunnel and returns its pairing command.
async fn create(
    State(state): State<AppState>,
    current: AuthUser,
    headers: HeaderMap,
    Json(payload): Json<CreateRequest>,
) -> Result<Response, ApiError> {
    require_write(&current)?;
    let name = validate_name(&payload.name)?;
    let description = validate_description(payload.description)?;
    let settings = tunnel_policy::load_settings(&state.db).await?;

    let now = Utc::now();
    let row = tunnel_connector::ActiveModel {
        id: Set(Uuid::new_v4()),
        name: Set(name),
        description: Set(description),
        status: Set(tunnel_status::PENDING.to_string()),
        pairing_token_hash: Set(None),
        pairing_token_expires_at: Set(None),
        credential_sha256: Set(None),
        credential_issued_at: Set(None),
        version: Set(None),
        hostname: Set(None),
        os_info: Set(None),
        last_seen_at: Set(None),
        created_by: Set(Some(current.id)),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&state.db)
    .await?;

    let (view, token, expires_at) = issue_pairing_token(
        &state,
        row,
        settings.pairing_ttl_seconds,
        scope_owner(&current),
    )
    .await?;
    let command = pairing_command(&state, &headers, &token);
    tracing::info!(tunnel_id = %view.id, actor = %current.id, "tunnel created");
    Ok((
        StatusCode::CREATED,
        Json(PairingView {
            tunnel: view,
            pairing_token: token,
            pairing_command: command,
            expires_at,
        }),
    )
        .into_response())
}

/// `PATCH /api/v1/tunnels/{id}`.
async fn update(
    State(state): State<AppState>,
    current: AuthUser,
    Path(tunnel_id): Path<String>,
    Json(payload): Json<UpdateRequest>,
) -> Result<Json<TunnelView>, ApiError> {
    require_write(&current)?;
    let tunnel_id = parse_uuid(&tunnel_id, "tunnel id")?;
    let row = load(&state, tunnel_id).await?;
    // Read before the row is consumed: `active` means "a credential exists".
    let paired_before = row
        .credential_sha256
        .as_deref()
        .is_some_and(|digest| !digest.is_empty());
    let mut active: tunnel_connector::ActiveModel = row.into();
    if let Some(name) = payload.name.as_deref() {
        active.name = Set(validate_name(name)?);
    }
    if let Some(description) = payload.description.as_deref() {
        active.description =
            Set(validate_description(Some(description.to_string()))?);
    }
    let mut disabled = false;
    if let Some(status) = payload.status.as_deref().map(str::trim) {
        match status {
            tunnel_status::ACTIVE => {
                // Enabling a tunnel that was never paired (or whose
                // credential was revoked) must not turn the row into a green
                // "Paired": it stays pending until the connector redeems a
                // token.
                active.status = Set(if paired_before {
                    tunnel_status::ACTIVE.to_string()
                } else {
                    tunnel_status::PENDING.to_string()
                });
            },
            tunnel_status::DISABLED => {
                active.status = Set(tunnel_status::DISABLED.to_string());
                disabled = true;
            },
            other => {
                return Err(ApiError::BadRequest(format!(
                    "status must be 'active' or 'disabled', got '{other}'"
                )));
            },
        }
    }
    active.updated_at = Set(Utc::now());
    let row = active.update(&state.db).await?;

    // A disabled tunnel must stop working now, not on the next unrelated push.
    notify_all_config_changed(&state, Some(&current.id.to_string())).await;
    if disabled {
        notify_tunnel_connectors(
            &state.db,
            tunnel_id,
            Some("this tunnel was disabled by an operator".to_string()),
        )
        .await;
    } else {
        notify_tunnel_connectors(&state.db, tunnel_id, None).await;
    }
    tracing::info!(%tunnel_id, actor = %current.id, status = %row.status, "tunnel updated");
    let mut views =
        build_views(&state, vec![row], scope_owner(&current)).await?;
    views
        .pop()
        .map(Json)
        .ok_or_else(|| ApiError::NotFound("tunnel not found".to_string()))
}

/// `DELETE /api/v1/tunnels/{id}`.
///
/// The pools bound to it keep their rows: the foreign key clears their
/// `tunnel_id`, which turns them back into direct origins rather than failing
/// the delete.
async fn remove(
    State(state): State<AppState>,
    current: AuthUser,
    Path(tunnel_id): Path<String>,
    Query(query): Query<DeleteQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_write(&current)?;
    let tunnel_id = parse_uuid(&tunnel_id, "tunnel id")?;
    let row = load(&state, tunnel_id).await?;
    let name = row.name.clone();
    // Deleting a bound tunnel silently turns its pools into DIRECT origins:
    // the edge starts dialing `10.0.0.5:8080` itself, which may either fail or
    // — worse — reach a network the tunnel was there to isolate. Make that an
    // explicit decision (`?force=true`) instead of a side effect.
    let bound = site_upstream_pools::Entity::find()
        .filter(site_upstream_pools::Column::TunnelId.eq(tunnel_id))
        .all(&state.db)
        .await?;
    if !bound.is_empty() {
        if !query.force.unwrap_or(false) {
            return Err(ApiError::Conflict(format!(
                "tunnel is still bound to {} origin pool(s); unbind them first, or retry with force=true to fall back to direct origins",
                bound.len()
            )));
        }
        site_upstream_pools::Entity::update_many()
            .col_expr(
                site_upstream_pools::Column::TunnelId,
                Expr::value(Option::<Uuid>::None),
            )
            .filter(site_upstream_pools::Column::TunnelId.eq(tunnel_id))
            .exec(&state.db)
            .await?;
        tracing::info!(
            %tunnel_id,
            pools = bound.len(),
            "tunnel deleted: bound origin pools fall back to direct origins"
        );
    }
    tunnel_connector::Entity::delete_by_id(tunnel_id)
        .exec(&state.db)
        .await?;
    // The per-edge session rows have no foreign key (an agent reports them and
    // may be offline when the tunnel goes away), so they are cleared here
    // instead of waiting for a heartbeat that may never come.
    let _ = tunnel_session::Entity::delete_many()
        .filter(tunnel_session::Column::TunnelId.eq(tunnel_id))
        .exec(&state.db)
        .await;
    notify_tunnel_connectors(
        &state.db,
        tunnel_id,
        Some("this tunnel was deleted".to_string()),
    )
    .await;
    notify_all_config_changed(&state, Some(&current.id.to_string())).await;
    tracing::info!(%tunnel_id, actor = %current.id, %name, "tunnel deleted");
    Ok(Json(serde_json::json!({ "deleted": tunnel_id })))
}

/// `POST /api/v1/tunnels/{id}/pairing` — re-pairs (rotates the credential).
///
/// The old credential stops working immediately: the edges learn the empty
/// digest on the next push and a live connector is told it was replaced.
async fn mint_pairing(
    State(state): State<AppState>,
    current: AuthUser,
    headers: HeaderMap,
    Path(tunnel_id): Path<String>,
) -> Result<Json<PairingView>, ApiError> {
    require_write(&current)?;
    let tunnel_id = parse_uuid(&tunnel_id, "tunnel id")?;
    let row = load(&state, tunnel_id).await?;
    let settings = tunnel_policy::load_settings(&state.db).await?;

    // Rotating drops the current credential: a connector that is running will
    // have to pair again with the new token.
    let mut active: tunnel_connector::ActiveModel = row.into();
    active.credential_sha256 = Set(None);
    active.credential_issued_at = Set(None);
    active.status = Set(tunnel_status::PENDING.to_string());
    active.updated_at = Set(Utc::now());
    let row = active.update(&state.db).await?;
    notify_tunnel_connectors(
        &state.db,
        tunnel_id,
        Some(
            "the tunnel was re-paired; run the new pairing command".to_string(),
        ),
    )
    .await;
    notify_all_config_changed(&state, Some(&current.id.to_string())).await;

    let (view, token, expires_at) = issue_pairing_token(
        &state,
        row,
        settings.pairing_ttl_seconds,
        scope_owner(&current),
    )
    .await?;
    let command = pairing_command(&state, &headers, &token);
    tracing::info!(%tunnel_id, actor = %current.id, "tunnel pairing token minted");
    Ok(Json(PairingView {
        tunnel: view,
        pairing_token: token,
        pairing_command: command,
        expires_at,
    }))
}

/// `POST /api/v1/tunnels/{id}/revoke` — drops the credential, keeps the row.
async fn revoke(
    State(state): State<AppState>,
    current: AuthUser,
    Path(tunnel_id): Path<String>,
) -> Result<Json<TunnelView>, ApiError> {
    require_write(&current)?;
    let tunnel_id = parse_uuid(&tunnel_id, "tunnel id")?;
    let row = load(&state, tunnel_id).await?;
    let mut active: tunnel_connector::ActiveModel = row.into();
    active.credential_sha256 = Set(None);
    active.credential_issued_at = Set(None);
    active.pairing_token_hash = Set(None);
    active.pairing_token_expires_at = Set(None);
    active.status = Set(tunnel_status::PENDING.to_string());
    active.updated_at = Set(Utc::now());
    let row = active.update(&state.db).await?;

    notify_tunnel_connectors(
        &state.db,
        tunnel_id,
        Some("this tunnel was revoked by an operator".to_string()),
    )
    .await;
    notify_all_config_changed(&state, Some(&current.id.to_string())).await;
    tracing::info!(%tunnel_id, actor = %current.id, "tunnel credential revoked");
    let mut views =
        build_views(&state, vec![row], scope_owner(&current)).await?;
    views
        .pop()
        .map(Json)
        .ok_or_else(|| ApiError::NotFound("tunnel not found".to_string()))
}

/// `GET /api/v1/tunnels/{id}/sessions` — the edges currently serving it.
async fn sessions(
    State(state): State<AppState>,
    current: AuthUser,
    Path(tunnel_id): Path<String>,
) -> Result<Json<Vec<SessionView>>, ApiError> {
    let tunnel_id = parse_uuid(&tunnel_id, "tunnel id")?;
    let row = load(&state, tunnel_id).await?;
    ensure_visible(&state, &current, &row).await?;
    let rows = tunnel_session::Entity::find()
        .filter(tunnel_session::Column::TunnelId.eq(tunnel_id))
        .order_by_asc(tunnel_session::Column::ConnectedAt)
        .all(&state.db)
        .await?;
    let names = agent_names(&state).await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| session_view(row, &names))
            .collect(),
    ))
}

/// `GET /api/v1/settings/tunnel` — administrators only.
async fn show_settings(
    State(state): State<AppState>,
    current: AuthUser,
) -> Result<Json<tunnel_setting::Model>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    Ok(Json(tunnel_policy::load_settings(&state.db).await?))
}

#[derive(Debug, Deserialize)]
pub struct UpdateSettingsRequest {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub pairing_ttl_seconds: Option<i32>,
    #[serde(default)]
    pub max_streams_per_session: Option<i32>,
    #[serde(default)]
    pub max_targets_per_tunnel: Option<i32>,
    #[serde(default)]
    pub idle_timeout_seconds: Option<i32>,
    #[serde(default)]
    pub heartbeat_seconds: Option<i32>,
    #[serde(default)]
    pub session_token_ttl_seconds: Option<i32>,
}

/// `PUT /api/v1/settings/tunnel` — administrators only.
async fn update_settings(
    State(state): State<AppState>,
    current: AuthUser,
    Json(payload): Json<UpdateSettingsRequest>,
) -> Result<Json<tunnel_setting::Model>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let row = tunnel_policy::load_settings(&state.db).await?;
    let mut active: tunnel_setting::ActiveModel = row.into();
    if let Some(value) = payload.enabled {
        active.enabled = Set(value);
    }
    if let Some(value) = payload.pairing_ttl_seconds {
        active.pairing_ttl_seconds = Set(value);
    }
    if let Some(value) = payload.max_streams_per_session {
        active.max_streams_per_session = Set(value);
    }
    if let Some(value) = payload.max_targets_per_tunnel {
        active.max_targets_per_tunnel = Set(value);
    }
    if let Some(value) = payload.idle_timeout_seconds {
        active.idle_timeout_seconds = Set(value);
    }
    if let Some(value) = payload.heartbeat_seconds {
        active.heartbeat_seconds = Set(value);
    }
    if let Some(value) = payload.session_token_ttl_seconds {
        active.session_token_ttl_seconds = Set(value);
    }
    active.updated_at = Set(Utc::now());
    let row = active.update(&state.db).await?.sanitized();
    tracing::info!(
        actor = %current.id,
        enabled = row.enabled,
        max_streams = row.max_streams_per_session,
        "tunnel settings updated"
    );
    notify_all_config_changed(&state, Some(&current.id.to_string())).await;
    notify_all_tunnel_connectors(&state.db).await;
    Ok(Json(row))
}

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

/// Tunnels a non-admin may see: those bound to one of their sites.
///
/// `None` means "no restriction" (an administrator). An empty set is a real
/// answer — the caller owns no site bound to any tunnel, so the list is empty.
/// What the caller may see of the derived tunnel facts: an administrator sees
/// everything, everyone else only their own sites.
fn scope_owner(current: &AuthUser) -> Option<Uuid> {
    (!current.is_admin()).then_some(current.id)
}

async fn visible_tunnel_ids(
    state: &AppState,
    current: &AuthUser,
) -> Result<Option<Vec<Uuid>>, ApiError> {
    if current.is_admin() {
        return Ok(None);
    }
    let site_ids: Vec<Uuid> = site::Entity::find()
        .filter(site::Column::UserId.eq(current.id))
        .all(&state.db)
        .await?
        .into_iter()
        .map(|row| row.id)
        .collect();
    if site_ids.is_empty() {
        return Ok(Some(Vec::new()));
    }
    let ids: Vec<Uuid> = site_upstream_pools::Entity::find()
        .filter(site_upstream_pools::Column::SiteId.is_in(site_ids))
        .filter(site_upstream_pools::Column::TunnelId.is_not_null())
        .all(&state.db)
        .await?
        .into_iter()
        .filter_map(|pool| pool.tunnel_id)
        .collect();
    Ok(Some(ids))
}

/// Hides a tunnel a non-admin's sites are not bound to behind a 404.
async fn ensure_visible(
    state: &AppState,
    current: &AuthUser,
    row: &tunnel_connector::Model,
) -> Result<(), ApiError> {
    if let Some(visible) = visible_tunnel_ids(state, current).await? {
        if !visible.contains(&row.id) {
            return Err(ApiError::NotFound("tunnel not found".to_string()));
        }
    }
    Ok(())
}

async fn load(
    state: &AppState,
    tunnel_id: Uuid,
) -> Result<tunnel_connector::Model, ApiError> {
    tunnel_connector::Entity::find_by_id(tunnel_id)
        .one(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound("tunnel not found".to_string()))
}

/// Stores a fresh pairing token and returns the view, the token and its expiry.
async fn issue_pairing_token(
    state: &AppState,
    row: tunnel_connector::Model,
    ttl_seconds: i32,
    owner: Option<Uuid>,
) -> Result<(TunnelView, String, DateTime<Utc>), ApiError> {
    let token = tunnel_policy::generate_secret();
    let expires_at =
        Utc::now() + Duration::seconds(ttl_seconds.clamp(60, 86_400) as i64);
    let mut active: tunnel_connector::ActiveModel = row.into();
    active.pairing_token_hash = Set(Some(tunnel_policy::digest_hex(&token)));
    active.pairing_token_expires_at = Set(Some(expires_at));
    active.updated_at = Set(Utc::now());
    let row = active.update(&state.db).await?;
    let mut views = build_views(state, vec![row], owner).await?;
    let view = views
        .pop()
        .ok_or_else(|| ApiError::NotFound("tunnel not found".to_string()))?;
    Ok((view, token, expires_at))
}

/// The command that installs the connector and pairs it in one step.
fn pairing_command(
    state: &AppState,
    headers: &HeaderMap,
    token: &str,
) -> String {
    let server_url = crate::api::agents::agent_server_url(state, headers);
    format!(
        "curl -fsSL {INSTALL_SCRIPT_URL} | sudo bash -s -- --mode tunnel \
         --server-url {server_url} --token {token}"
    )
}

/// Builds the console view of a set of rows.
/// `owner` scopes the derived facts: `None` for an administrator, `Some` for a
/// non-admin, whose view must not include other tenants' domains or internal
/// addresses on a shared tunnel.
async fn build_views(
    state: &AppState,
    rows: Vec<tunnel_connector::Model>,
    owner: Option<Uuid>,
) -> Result<Vec<TunnelView>, ApiError> {
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let settings = tunnel_policy::load_settings(&state.db).await?;
    let derived = tunnel_policy::derive_for(&state.db, owner).await?;
    let targets = derived.targets;
    let sites = derived.sites;
    let ingress: Vec<String> = tunnel_policy::ingress_endpoints(&state.db)
        .await?
        .into_iter()
        .map(|endpoint| endpoint.endpoint)
        .collect();
    let online = TUNNEL_CONNECTORS.online().await;
    let names = agent_names(state).await?;
    let sessions = tunnel_session::Entity::find().all(&state.db).await?;
    let mut by_tunnel: std::collections::HashMap<Uuid, Vec<SessionView>> =
        std::collections::HashMap::new();
    for row in sessions {
        by_tunnel
            .entry(row.tunnel_id)
            .or_default()
            .push(session_view(row, &names));
    }
    Ok(rows
        .into_iter()
        .map(|row| {
            let paired = row
                .credential_sha256
                .as_deref()
                .is_some_and(|digest| !digest.is_empty());
            let enabled =
                settings.enabled && row.status != tunnel_status::DISABLED;
            let mut targets = targets.get(&row.id).cloned().unwrap_or_default();
            let limit = settings.max_targets_per_tunnel.max(1) as usize;
            targets.truncate(limit);
            TunnelView {
                id: row.id,
                name: row.name,
                description: row.description,
                status: row.status,
                paired,
                enabled,
                connector_online: online.contains_key(&row.id),
                connector_version: row.version,
                connector_hostname: row.hostname,
                last_seen_at: row.last_seen_at,
                sites: sites.get(&row.id).cloned().unwrap_or_default(),
                ingress: ingress.clone(),
                targets,
                sessions: by_tunnel.remove(&row.id).unwrap_or_default(),
                created_at: row.created_at,
                updated_at: row.updated_at,
            }
        })
        .collect())
}

struct AgentName {
    name: String,
    status: String,
}

async fn agent_names(
    state: &AppState,
) -> Result<std::collections::HashMap<Uuid, AgentName>, ApiError> {
    let rows = agent::Entity::find().all(&state.db).await?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let name = row
                .display_name
                .filter(|name| !name.trim().is_empty())
                .unwrap_or(row.hostname);
            (
                row.id,
                AgentName {
                    name,
                    status: row.status,
                },
            )
        })
        .collect())
}

fn session_view(
    row: tunnel_session::Model,
    names: &std::collections::HashMap<Uuid, AgentName>,
) -> SessionView {
    let agent = names.get(&row.agent_id);
    SessionView {
        agent_id: row.agent_id,
        agent_name: agent
            .map(|agent| agent.name.clone())
            .unwrap_or_else(|| row.agent_id.to_string()),
        agent_status: agent
            .map(|agent| agent.status.clone())
            .unwrap_or_default(),
        connected_at: row.connected_at,
        last_seen_at: row.last_seen_at,
        streams_active: row.streams_active,
        rtt_ms: row.rtt_ms,
        version: row.version,
        hostname: row.hostname,
    }
}

fn validate_name(raw: &str) -> Result<String, ApiError> {
    let name = raw.trim();
    if name.is_empty() {
        return Err(ApiError::BadRequest("name is required".to_string()));
    }
    if name.chars().count() > MAX_NAME_LEN {
        return Err(ApiError::BadRequest(format!(
            "name must be at most {MAX_NAME_LEN} characters"
        )));
    }
    if name.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(
            "name must not contain control characters".to_string(),
        ));
    }
    Ok(name.to_string())
}

fn validate_description(
    raw: Option<String>,
) -> Result<Option<String>, ApiError> {
    let Some(description) = raw else {
        return Ok(None);
    };
    let description = description.trim().to_string();
    if description.is_empty() {
        return Ok(None);
    }
    if description.chars().count() > MAX_DESCRIPTION_LEN {
        return Err(ApiError::BadRequest(format!(
            "description must be at most {MAX_DESCRIPTION_LEN} characters"
        )));
    }
    Ok(Some(description))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_trimmed_and_bounded() {
        assert_eq!(validate_name("  edge-a  ").unwrap(), "edge-a");
        assert!(validate_name("   ").is_err());
        assert!(validate_name(&"x".repeat(MAX_NAME_LEN + 1)).is_err());
        assert!(validate_name("bad\u{0}name").is_err());
    }

    #[test]
    fn descriptions_collapse_to_none_when_empty() {
        assert_eq!(validate_description(None).unwrap(), None);
        assert_eq!(validate_description(Some("  ".to_string())).unwrap(), None);
        assert_eq!(
            validate_description(Some(" internal ".to_string())).unwrap(),
            Some("internal".to_string())
        );
    }
}
