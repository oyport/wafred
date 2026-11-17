//! Uniform error type and JSON error envelope for the REST API.
//!
//! Every failure is rendered as
//! `{"error": {"code": "<machine_readable>", "message": "<human readable>"}}`
//! together with the matching HTTP status code, which keeps the frontend's
//! error handling down to a single shape.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use sea_orm::DbErr;
use serde_json::json;

/// Builds the shared `{"error": {...}}` envelope.
pub fn error_response(
    status: StatusCode,
    code: &str,
    message: &str,
) -> Response {
    let body = json!({ "error": { "code": code, "message": message } });
    (status, Json(body)).into_response()
}

/// Fixed text for an unexpected failure.
///
/// The detail stays in the log: a `DbErr` or an I-O error names tables, files
/// and connection strings, and this is what a caller who did nothing wrong
/// gets to read.
const INTERNAL_MESSAGE: &str = "internal server error";

/// Fixed text for a row the database reports as missing.
///
/// `DbErr::RecordNotFound` carries whatever text the lookup used, and a
/// generated `find_related` / `update` path puts the table name in it, so the
/// message is not safe to echo.
const NOT_FOUND_MESSAGE: &str = "not found";

/// Errors surfaced by API handlers.
#[derive(Debug)]
pub enum ApiError {
    /// Malformed input, invalid identifiers, out-of-range pagination.
    BadRequest(String),
    /// Missing or invalid credentials.
    Unauthorized(String),
    /// Authenticated but not allowed to perform the action.
    Forbidden(String),
    /// The resource does not exist (or is not visible to this user).
    NotFound(String),
    /// Uniqueness violation, e.g. a domain that is already registered.
    Conflict(String),
    /// A budget shared by all callers was exhausted.
    TooManyRequests(String),
    /// Semantically invalid payload (well-formed JSON, bad values).
    Unprocessable(String),
    /// The endpoint exists but cannot run on this deployment, e.g. CPU
    /// profiling on non-Linux platforms.
    NotImplemented(String),
    /// An upstream dependency (e.g. a subscription source) failed; the
    /// upstream's own error text is safe to show to the operator.
    BadGateway(String),
    /// The endpoint is disabled on this deployment, e.g. profiling captures
    /// turned off via the deployment switch.
    ServiceUnavailable(String),
    /// Unexpected failure; the message is logged in full and a generic text is
    /// returned to the client.
    Internal(String),
    /// Wraps another error with a more specific machine-readable code.
    ///
    /// The HTTP status and the human-readable message are inherited from
    /// `inner`; only the envelope's `code` changes. Built with
    /// [`ApiError::with_code`] so a handler can name the exact failure (for
    /// example `auth.invalid_credentials`) without changing the status or the
    /// text the client sees today.
    Coded {
        inner: Box<ApiError>,
        code: &'static str,
    },
}

impl ApiError {
    /// Error code embedded in the response body.
    pub fn code(&self) -> &'static str {
        match self {
            ApiError::BadRequest(_) => "bad_request",
            ApiError::Unauthorized(_) => "unauthorized",
            ApiError::Forbidden(_) => "forbidden",
            ApiError::NotFound(_) => "not_found",
            ApiError::Conflict(_) => "conflict",
            ApiError::TooManyRequests(_) => "too_many_requests",
            ApiError::Unprocessable(_) => "unprocessable_entity",
            ApiError::NotImplemented(_) => "not_implemented",
            ApiError::BadGateway(_) => "bad_gateway",
            ApiError::ServiceUnavailable(_) => "service_unavailable",
            ApiError::Internal(_) => "internal_error",
            ApiError::Coded { code, .. } => code,
        }
    }

    /// HTTP status code for this error.
    pub fn status(&self) -> StatusCode {
        match self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden(_) => StatusCode::FORBIDDEN,
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::TooManyRequests(_) => StatusCode::TOO_MANY_REQUESTS,
            ApiError::Unprocessable(_) => StatusCode::UNPROCESSABLE_ENTITY,
            ApiError::NotImplemented(_) => StatusCode::NOT_IMPLEMENTED,
            ApiError::BadGateway(_) => StatusCode::BAD_GATEWAY,
            ApiError::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::Coded { inner, .. } => inner.status(),
        }
    }

    /// Attaches a specific machine-readable code to this error.
    ///
    /// Status and message are untouched — only the envelope's `code` becomes
    /// `code` — so a handler can name the exact failure (e.g.
    /// `auth.invalid_credentials`) for the console's localised hints while the
    /// HTTP contract stays byte-identical. Re-wrapping a coded error replaces
    /// the code instead of nesting another layer.
    pub fn with_code(self, code: &'static str) -> Self {
        match self {
            ApiError::Coded { inner, .. } => ApiError::Coded { inner, code },
            other => ApiError::Coded {
                inner: Box::new(other),
                code,
            },
        }
    }

    pub fn internal(err: impl std::fmt::Display) -> Self {
        ApiError::Internal(err.to_string())
    }

    /// An unexpected failure whose detail must not leave the process.
    ///
    /// The error is logged here — with its cause chain — and the reply carries
    /// [`INTERNAL_MESSAGE`] only. Prefer this over
    /// `ApiError::Internal(x.to_string())`: the variant keeps `x` in the enum,
    /// where `Display` would hand it to whoever formats the error next (the
    /// MCP endpoint, a log line, a future response), and only the log is
    /// allowed to see it.
    pub fn internal_generic(err: impl std::fmt::Display) -> Self {
        tracing::error!(error = %err, "internal API error");
        ApiError::Internal(INTERNAL_MESSAGE.to_string())
    }

    pub fn bad_request(err: impl std::fmt::Display) -> Self {
        ApiError::BadRequest(err.to_string())
    }

    pub fn not_found(err: impl std::fmt::Display) -> Self {
        ApiError::NotFound(err.to_string())
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::BadRequest(msg)
            | ApiError::Unauthorized(msg)
            | ApiError::Forbidden(msg)
            | ApiError::NotFound(msg)
            | ApiError::Conflict(msg)
            | ApiError::TooManyRequests(msg)
            | ApiError::Unprocessable(msg)
            | ApiError::NotImplemented(msg)
            | ApiError::BadGateway(msg)
            | ApiError::ServiceUnavailable(msg)
            | ApiError::Internal(msg) => f.write_str(msg),
            ApiError::Coded { inner, .. } => {
                std::fmt::Display::fmt(inner.as_ref(), f)
            },
        }
    }
}

impl std::error::Error for ApiError {}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let code = self.code();
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            // The cause was already logged where it was known
            // (`internal_generic`, the `DbErr` / `anyhow` conversions); this
            // line only records that a 500 went out.
            tracing::error!(error = %self, "internal API error");
            return error_response(status, code, INTERNAL_MESSAGE);
        }
        if status.is_server_error() {
            tracing::error!(error = %self, "API error");
        } else {
            tracing::debug!(error = %self, code, "API rejected request");
        }
        error_response(status, code, &self.to_string())
    }
}

impl From<DbErr> for ApiError {
    fn from(err: DbErr) -> Self {
        match &err {
            // The lookup text can name the table the row was searched in; the
            // 404 body says only that it is gone.
            DbErr::RecordNotFound(_) => {
                ApiError::NotFound(NOT_FOUND_MESSAGE.to_string())
            },
            DbErr::Exec(runtime_err) | DbErr::Query(runtime_err)
                if runtime_err.to_string().contains("duplicate key") =>
            {
                ApiError::Conflict("resource already exists".to_string())
            },
            other => ApiError::internal_generic(other),
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        // `{:#}` flattens the context chain into the single log line; the
        // client never sees any of it.
        ApiError::internal_generic(format!("{err:#}"))
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(err: serde_json::Error) -> Self {
        ApiError::BadRequest(format!("invalid JSON: {err}"))
    }
}

impl From<uuid::Error> for ApiError {
    fn from(err: uuid::Error) -> Self {
        ApiError::BadRequest(format!("invalid UUID: {err}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    /// Renders the error the way Axum does, and returns the status plus the
    /// parsed envelope.
    async fn envelope(err: ApiError) -> (StatusCode, serde_json::Value) {
        let response = err.into_response();
        let status = response.status();
        let body = to_bytes(response.into_body(), 8192).await.unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }

    /// The message the login handler uses for both failure shapes.
    const INVALID: &str = "invalid e-mail or password";

    /// D11: `DbErr::RecordNotFound` carries the lookup text, which on a
    /// generated query names the table — a 404 must not echo it back.
    #[tokio::test]
    async fn record_not_found_is_reported_without_the_database_text() {
        let err = ApiError::from(DbErr::RecordNotFound(
            "sites: no row for id 7".to_string(),
        ));
        let (status, body) = envelope(err).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"]["code"], "not_found");
        assert_eq!(body["error"]["message"], NOT_FOUND_MESSAGE);
    }

    /// A 404 the handler phrased itself (an id the operator typed) still says
    /// what was missing.
    #[tokio::test]
    async fn handler_not_found_keeps_its_message() {
        let (status, body) =
            envelope(ApiError::NotFound("site 42 not found".to_string())).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"]["message"], "site 42 not found");
    }

    /// The generic constructor logs the cause and puts none of it in the body.
    #[tokio::test]
    async fn internal_generic_body_omits_the_cause() {
        let err = ApiError::from(DbErr::Query(sea_orm::RuntimeErr::Internal(
            "connection refused: wafred@10.0.0.2:5432".to_string(),
        )));
        let (status, body) = envelope(err).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"]["code"], "internal_error");
        assert_eq!(body["error"]["message"], INTERNAL_MESSAGE);
    }

    /// `with_code` changes only the envelope's `code`: the HTTP status and the
    /// human-readable message keep coming from the wrapped error, so adding a
    /// specific code cannot change the contract a client already depends on.
    #[tokio::test]
    async fn with_code_changes_only_the_code() {
        let err = ApiError::Unauthorized(INVALID.to_string())
            .with_code("auth.invalid_credentials");
        assert_eq!(err.code(), "auth.invalid_credentials");
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(err.to_string(), INVALID);

        let (status, body) = envelope(err).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "auth.invalid_credentials");
        assert_eq!(body["error"]["message"], INVALID);
    }

    /// Wrapping an already-coded error replaces the code instead of nesting
    /// another layer, so the last (most specific) call wins.
    #[test]
    fn with_code_replaces_an_existing_code() {
        let err = ApiError::BadRequest("domain conflict".to_string())
            .with_code("site.domain_conflict")
            .with_code("site.domain_conflict");
        assert_eq!(err.code(), "site.domain_conflict");
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
        assert_eq!(err.to_string(), "domain conflict");

        let err = ApiError::Conflict("x".to_string())
            .with_code("a.first")
            .with_code("a.second");
        assert_eq!(err.code(), "a.second");
        assert_eq!(err.status(), StatusCode::CONFLICT);
    }

    /// Every default code and status is untouched by the new variant: a coded
    /// wrapper is opt-in per call site.
    #[test]
    fn default_codes_and_statuses_are_unchanged() {
        let cases = [
            (ApiError::BadRequest(String::new()), "bad_request"),
            (ApiError::Unauthorized(String::new()), "unauthorized"),
            (ApiError::Forbidden(String::new()), "forbidden"),
            (ApiError::NotFound(String::new()), "not_found"),
            (ApiError::Conflict(String::new()), "conflict"),
            (
                ApiError::TooManyRequests(String::new()),
                "too_many_requests",
            ),
            (
                ApiError::Unprocessable(String::new()),
                "unprocessable_entity",
            ),
            (ApiError::NotImplemented(String::new()), "not_implemented"),
            (ApiError::BadGateway(String::new()), "bad_gateway"),
            (
                ApiError::ServiceUnavailable(String::new()),
                "service_unavailable",
            ),
            (ApiError::Internal(String::new()), "internal_error"),
        ];
        for (err, code) in cases {
            assert_eq!(err.code(), code);
            let status = err.status();
            // A coded wrapper never changes the status either.
            assert_eq!(
                err.with_code("some.specific_code").status(),
                status,
                "{code} status must survive with_code"
            );
        }
    }

    /// A coded `Internal` keeps the 500 status and the generic body text: the
    /// specific code must not leak the cause either.
    #[tokio::test]
    async fn coded_internal_keeps_the_generic_body() {
        let err = ApiError::Internal("connection refused".to_string())
            .with_code("storage.unavailable");
        let (status, body) = envelope(err).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"]["code"], "storage.unavailable");
        assert_eq!(body["error"]["message"], INTERNAL_MESSAGE);
    }
}
