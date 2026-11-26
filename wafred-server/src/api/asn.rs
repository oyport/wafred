//! ASN data source management: the MaxMind ASN database the control plane
//! reads to fill `access_logs.asn` when the edge cannot resolve it.
//!
//! The edge's GeoIP snapshot carries country ranges only, so without a source
//! here the ASN ranking on the traffic pages is empty. Administrators install
//! a database once (GeoLite2-ASN, GeoIP2-ISP or GeoIP2-Enterprise) — either by
//! uploading it through `POST /asn/database`, or by pointing `WAFRED_ASN_MMDB`
//! at a file they manage. Both are local files: nothing is downloaded or
//! queried at request time, and the operator owns the MaxMind licence.

use axum::extract::{DefaultBodyLimit, Multipart, State};
use axum::routing::get;
use axum::Json;
use axum::Router;

use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::asn::{self, AsnDatabaseStatus};
use crate::auth::AuthUser;

/// Runs a blocking ASN-database operation off the async runtime.
///
/// Reading a MaxMind database means reading the whole file (≈8–10 MB), and an
/// upload also writes and renames it. Doing that inline would stall whichever
/// runtime worker happens to serve the request, so every filesystem-touching
/// call goes through `spawn_blocking`. A panicked task is a server fault, never
/// a client error.
async fn run_blocking<T, F>(operation: F) -> Result<T, ApiError>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|error| {
            ApiError::Internal(format!("ASN database task failed: {error}"))
        })
}

/// Routes contributed to `/api/v1`.
pub fn routes() -> Router<AppState> {
    Router::new().route(
        "/asn/database",
        get(show)
            .post(upload)
            .delete(remove)
            .layer(DefaultBodyLimit::max(asn::MAX_MMDB_BYTES as usize)),
    )
}

/// `GET /api/v1/asn/database` — administrators only.
///
/// Reports the data source and loads it first, so an operator who just copied
/// a file in sees the result immediately instead of waiting for traffic.
async fn show(
    State(_state): State<AppState>,
    current: AuthUser,
) -> Result<Json<AsnDatabaseStatus>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    // `status` may read the database when one appeared after startup.
    let status = run_blocking(asn::status).await?;
    Ok(Json(status))
}

/// `POST /api/v1/asn/database` — administrators only.
///
/// Multipart field `file` holding a MaxMind ASN database. The upload is
/// validated before it replaces the previous database, so a wrong file (a
/// country database, a truncated download) is a `400` and the working
/// database keeps serving.
async fn upload(
    State(_state): State<AppState>,
    current: AuthUser,
    mut multipart: Multipart,
) -> Result<Json<AsnDatabaseStatus>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;

    let mut bytes: Option<Vec<u8>> = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|err| ApiError::BadRequest(err.to_string()))?
    {
        if field.name() == Some("file") {
            bytes = Some(
                field
                    .bytes()
                    .await
                    .map_err(|err| ApiError::BadRequest(err.to_string()))?
                    .to_vec(),
            );
            break;
        }
    }
    let Some(bytes) = bytes else {
        return Err(ApiError::BadRequest(
            "multipart field 'file' is required".to_string(),
        ));
    };

    // Validation, the write and the in-memory swap are blocking work; the
    // buffer is moved into the task rather than copied.
    let bytes_len = bytes.len();
    let status = run_blocking(move || asn::install_from_bytes(bytes))
        .await?
        .map_err(|error| {
            // A rejected file is the operator's input; a failed write is the
            // server's. The message says which in both cases.
            if error.starts_with("cannot ") {
                ApiError::Internal(error)
            } else {
                ApiError::BadRequest(error)
            }
        })?;
    tracing::info!(
        actor = %current.email,
        bytes = bytes_len,
        path = %status.path,
        database_type = status.database_type.as_deref().unwrap_or("-"),
        "ASN database installed"
    );
    Ok(Json(status))
}

/// `DELETE /api/v1/asn/database` — administrators only.
///
/// Removes the uploaded database and clears the in-memory copy; the ASN
/// ranking then stays empty until another source is installed. Refused
/// (`409`) when `WAFRED_ASN_MMDB` names the file, because that path belongs
/// to the operator rather than to the upload.
async fn remove(
    State(_state): State<AppState>,
    current: AuthUser,
) -> Result<Json<AsnDatabaseStatus>, ApiError> {
    current.require_admin().map_err(ApiError::from)?;
    let status =
        run_blocking(asn::remove_uploaded).await?.map_err(|error| {
            if error.contains("set by WAFRED_ASN_MMDB") {
                ApiError::Conflict(error)
            } else {
                ApiError::Internal(error)
            }
        })?;
    tracing::info!(actor = %current.email, "ASN database removed");
    Ok(Json(status))
}
