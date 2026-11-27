// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Challenge plugin — CC protection / "5-second shield".
//!
//! Runs at [`PluginStep::EarlyRequest`]. For every request it either:
//! * serves the `/_pingwaf/challenge/verify` endpoint (solution submission), or
//! * asks the [`ChallengeEngine`] whether the visitor should be challenged and,
//!   if so, returns the JS challenge page (503) or a hard block (403).
//!
//! The WAF plugin delegates its `Challenge` verdicts here: both plugins share
//! the [`PENDING_CHALLENGES`] store so a challenge issued by one can be
//! verified by the other's verify endpoint.

use super::{
    Error, get_hash_key, get_int_conf_or_default, get_str_conf,
    get_str_slice_conf,
};
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use dashmap::DashMap;
use http::header;
use http::{HeaderValue, StatusCode};
use pingap_config::{PluginCategory, PluginConf};
use pingap_core::{
    Ctx, HTTP_HEADER_CONTENT_HTML, HttpResponse, Plugin, PluginStep,
    ProxyTrust, RequestPluginResult, ensure_client_ip, get_cookie_value,
    get_host, get_req_header_value, resolve_client_ip_with_trust,
};
use pingora::proxy::Session;
use pingwaf_agent::WafredAgent;
use pingwaf_agent::cache::{
    ChallengeConfig as CacheChallengeConfig,
    ChallengeLevel as CacheChallengeLevel,
};
use pingwaf_challenge::js_challenge::page::{
    ChallengePageParams, REQUIRED_DOM_IDS, challenge_scripts,
    generate_interactive_challenge_html, generate_js_challenge_html,
    generate_managed_challenge_html,
};
use pingwaf_challenge::{
    AdaptiveDifficulty, BrowserFingerprint, ChallengeConfig, ChallengeDecision,
    ChallengeEngine, ChallengeRequest, ChallengeSubmission, ClearanceLevel,
    DEFAULT_MAX_TRACKED_KEYS, DIFFICULTY_DECAY_SECS, DifficultyState,
    FixedWindowLimiter, LIMIT_WINDOW_SECS, LimitDecision, MAX_FAILURE_STEPS,
    VerifyResult, generate_request_id,
};
use std::borrow::Cow;
use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, LazyLock, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tera::{Context, Tera};
use tracing::{debug, warn};

use crate::host_cache::{HostCacheSweep, touch};

type Result<T, E = Error> = std::result::Result<T, E>;

/// Endpoint the challenge page POSTs its proof-of-work solution to.
pub(crate) const VERIFY_ENDPOINT: &str = "/_pingwaf/challenge/verify";

/// Maximum request-body size accepted on the verify endpoint (64 KiB).
const MAX_VERIFY_BODY: usize = 64 * 1024;

/// Sliding fixed-window (60s) length used for per-IP rate estimation.
const RATE_WINDOW_SECS: i64 = 60;

// ─────────────────────────────────────────────────────────────
// Shared pending-challenge store
// ─────────────────────────────────────────────────────────────

/// State kept server-side between issuing a challenge and verifying the
/// solution. The browser echoes back `{request_id, solution, fingerprint_json,
/// timestamp}`; the nonce is necessarily embedded in the page so the browser
/// can compute the proof-of-work, while the site id and the request context
/// (client IP / User-Agent) stay server-side.
#[derive(Clone)]
pub(crate) struct PendingChallenge {
    pub nonce: String,
    pub site_id: String,
    pub original_url: String,
    /// Proof-of-work difficulty this challenge was issued with. Adaptive
    /// difficulty changes the required work per challenge, so verification
    /// must use this value and not the site's current (or static) setting.
    pub difficulty: u32,
    /// Client IP observed when the challenge was issued. Verification must
    /// come from the same address.
    pub client_ip: String,
    /// Request User-Agent observed when the challenge was issued. The
    /// submitted fingerprint UA must match this and the live request.
    pub user_agent: String,
    pub created_at: i64,
    /// Approximate heap size, used by the process-wide byte budget.
    bytes: usize,
}

/// Process-wide map of outstanding challenges, keyed by request id. Shared by
/// the WAF and Challenge plugins.
pub(crate) static PENDING_CHALLENGES: LazyLock<
    DashMap<String, Arc<PendingChallenge>>,
> = LazyLock::new(DashMap::new);

/// How long an unverified challenge stays resolvable (5 minutes).
const PENDING_TTL_SECS: i64 = 300;

/// Process-wide fallback signing secret for standalone deployments with
/// neither an agent (whose cache dir persists a generated secret) nor a
/// configured `cookie_secret`. Random per process: clearance cookies simply
/// do not survive a restart, whereas the historical `"change-me"` fallback
/// was public knowledge and let anyone forge valid clearances.
pub(crate) static FALLBACK_COOKIE_SECRET: LazyLock<String> =
    LazyLock::new(|| {
        warn!(
            "no challenge cookie_secret configured and no agent cache dir; \
             using a per-process random key (clearances will not survive a \
             restart) — configure `cookie_secret` to persist them"
        );
        uuid::Uuid::new_v4().simple().to_string()
    });

/// Last-resort secret for a cache directory that exists but cannot be
/// written. It must stay stable for the process: callers on both sides of the
/// clearance contract (WAF verification and challenge signing) resolve it
/// independently, and a fresh UUID per call would make every cookie invalid.
static UNPERSISTED_COOKIE_SECRET: OnceLock<String> = OnceLock::new();

#[inline]
fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Restricts a client-supplied redirect target to a same-origin absolute
/// path. Anything that does not start with a single solidus (including
/// protocol-relative `//host` and `/\\host`, which browsers normalize to
/// `//host`) falls back to `/`.
fn safe_redirect_target(url: &str) -> &str {
    if url.starts_with('/') && !url.starts_with("//") && !url.starts_with("/\\")
    {
        url
    } else {
        "/"
    }
}

/// Generate a random 32-hex-char nonce (the challenge crate keeps its own
/// generator private).
fn generate_nonce() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// Only sweep the challenge map above this many outstanding entries.
const PENDING_CHALLENGE_GC_THRESHOLD: usize = 1024;

/// Hard ceiling on outstanding challenges. The TTL alone is not a bound:
/// under a unique-URL flood (every request gets a fresh challenge and never
/// verifies) the map would hold `QPS x 300s` entries, each carrying an
/// attacker-controlled path/query (1k rps at 1KB ≈ 300MB). Past the ceiling
/// the challenge is still issued (the nonce reaches the client) but not
/// remembered — verification then fails closed and the client retries,
/// which is the same outcome as an expired challenge.
const PENDING_CHALLENGE_MAX_ENTRIES: usize = 2048;

/// The request path/query is attacker-controlled. A challenge flood with
/// unique long URLs must not turn the pending map into an unbounded string
/// cache: longer targets fall back to `/` (the visitor still gets a working
/// verification, just not a redirect to the oversized URL).
const PENDING_CHALLENGE_MAX_URL_BYTES: usize = 2048;

/// Total approximate heap budget for the pending map. The entry cap alone is
/// not enough when each original URL can be 2 KiB.
const PENDING_CHALLENGE_MAX_BYTES: usize = 8 * 1024 * 1024;

/// Approximate bytes currently held by `PENDING_CHALLENGES`.
static PENDING_CHALLENGE_BYTES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

fn pending_bytes(entry: &PendingChallenge) -> usize {
    entry.nonce.len()
        + entry.site_id.len()
        + entry.original_url.len()
        + entry.client_ip.len()
        + entry.user_agent.len()
        + std::mem::size_of::<PendingChallenge>()
}

fn account_pending_removed(entry: &PendingChallenge) {
    PENDING_CHALLENGE_BYTES
        .fetch_sub(entry.bytes, std::sync::atomic::Ordering::Relaxed);
}

fn sweep_pending(now: i64) {
    PENDING_CHALLENGES
        .retain(|_, v| now.saturating_sub(v.created_at) < PENDING_TTL_SECS);
    // Recompute rather than trying to track every retain callback. This runs
    // only on the throttled GC path, not per request.
    let after: usize = PENDING_CHALLENGES.iter().map(|entry| entry.bytes).sum();
    PENDING_CHALLENGE_BYTES.store(after, std::sync::atomic::Ordering::Relaxed);
}

/// Throttle for the O(N) TTL sweeps: every Nth insert does the scan.
static GC_TICK: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Record a freshly issued challenge, opportunistically dropping stale ones.
pub(crate) fn store_pending(
    request_id: &str,
    site_id: &str,
    original_url: &str,
    client_ip: &str,
    user_agent: &str,
    difficulty: u32,
) -> String {
    let now = now_secs();
    // Opportunistic garbage collection so the map cannot grow without bound.
    // Under a challenge flood (unauthenticated traffic) a per-request full
    // scan is itself a CPU amplifier: once over the threshold, sweep only
    // every 64th insert. The TTL sweep still bounds the map, it just stops
    // costing O(N) on every request (2026-10-18 audit H2).
    if PENDING_CHALLENGES.len() > PENDING_CHALLENGE_GC_THRESHOLD
        && GC_TICK
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .is_multiple_of(64)
    {
        sweep_pending(now);
    }
    if PENDING_CHALLENGES.len() >= PENDING_CHALLENGE_MAX_ENTRIES {
        // Reached the hard ceiling: issue the nonce without remembering it.
        return generate_nonce();
    }
    let original_url = if original_url.len() > PENDING_CHALLENGE_MAX_URL_BYTES {
        "/".to_string()
    } else {
        original_url.to_string()
    };
    let nonce = generate_nonce();
    let entry = PendingChallenge {
        nonce: nonce.clone(),
        site_id: site_id.to_string(),
        original_url,
        difficulty,
        client_ip: client_ip.to_string(),
        user_agent: user_agent.to_string(),
        created_at: now,
        bytes: 0,
    };
    let bytes = pending_bytes(&entry);
    let current =
        PENDING_CHALLENGE_BYTES.load(std::sync::atomic::Ordering::Relaxed);
    if current.saturating_add(bytes) > PENDING_CHALLENGE_MAX_BYTES {
        // Bound the map even when URLs are short: issue a nonce without a
        // pending record; verification fails closed (the client retries).
        return nonce;
    }
    PENDING_CHALLENGES.insert(
        request_id.to_string(),
        Arc::new(PendingChallenge { bytes, ..entry }),
    );
    PENDING_CHALLENGE_BYTES
        .fetch_add(bytes, std::sync::atomic::Ordering::Relaxed);
    nonce
}

/// Look up a pending challenge without consuming it.
///
/// The entry is removed only after the submission verifies. Taking it first
/// made every failed PoW/fingerprint attempt unrecoverable: the browser had
/// already lost the nonce by the time it tried to correct the answer.
pub(crate) fn peek_pending(request_id: &str) -> Option<Arc<PendingChallenge>> {
    let pending = PENDING_CHALLENGES
        .get(request_id)
        .map(|entry| entry.clone())?;
    if now_secs().saturating_sub(pending.created_at) >= PENDING_TTL_SECS {
        if let Some((_, removed)) = PENDING_CHALLENGES.remove(request_id) {
            account_pending_removed(&removed);
        }
        return None;
    }
    Some(pending)
}

/// Which challenge page to render.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChallengeKind {
    Js,
    Managed,
    Interactive,
}

/// The control plane's challenge page template, when the site carries one.
///
/// The template is global (`error_pages` scope `challenge`, status 503), but
/// it is delivered in every site bundle; the challenge page is rendered only
/// when the request's site has it enabled.
fn challenge_page_template(site_id: &str) -> Option<String> {
    let agent = WafredAgent::instance()?;
    let rules = agent.get_rules_for_domain(site_id)?;
    rules
        .error_pages
        .iter()
        .find(|page| {
            page.enabled
                && page.scope == "challenge"
                && page.status_code == 503
                && page.content_type == "text/html"
        })
        .map(|page| page.body_template.clone())
}

fn has_dom_id(html: &str, id: &str) -> bool {
    html.contains(&format!("id=\"{id}\""))
        || html.contains(&format!("id='{id}'"))
}

/// The control-plane template is global and changes rarely; compiling Tera on
/// every challenge would put a template parse on the hot path. Keep the last
/// compiled template, keyed by its source, and rebuild only when it changes.
type ChallengeTeraCache = Mutex<Option<(String, Arc<Tera>)>>;
static CHALLENGE_TERA: OnceLock<ChallengeTeraCache> = OnceLock::new();

fn challenge_tera(template: &str) -> Option<Arc<Tera>> {
    let cache = CHALLENGE_TERA.get_or_init(|| Mutex::new(None));
    let mut guard = cache.lock().ok()?;
    if let Some((cached, tera)) = guard.as_ref()
        && cached == template
    {
        return Some(Arc::clone(tera));
    }
    let mut tera = Tera::default();
    tera.add_raw_template("challenge.html", template).ok()?;
    let tera = Arc::new(tera);
    *guard = Some((template.to_string(), Arc::clone(&tera)));
    Some(tera)
}

/// Renders a control-plane challenge template through the same Tera engine the
/// custom error pages use. The challenge script is injected as
/// `challenge_scripts`; a template that omits `| safe` (Tera escapes it),
/// contains its own `<script>`, or loses a required DOM id is rejected and the
/// built-in page is used instead.
fn render_challenge_template(
    template: &str,
    params: &ChallengePageParams,
) -> Option<String> {
    if template.to_ascii_lowercase().contains("<script") {
        warn!("challenge template contains <script>; using the built-in page");
        return None;
    }
    let scripts = challenge_scripts(params);
    let tera = challenge_tera(template)?;
    let mut context = Context::new();
    context.insert("brand_name", &params.brand_name);
    context.insert("request_id", &params.request_id);
    context.insert("difficulty", &params.difficulty);
    context.insert("verify_endpoint", &params.verify_endpoint);
    context.insert("original_url", &params.original_url);
    context.insert("challenge_scripts", &scripts);
    let html = match tera.render("challenge.html", &context) {
        Ok(html) => html,
        Err(err) => {
            warn!(error = %err, "challenge template render failed; using the built-in page");
            return None;
        },
    };
    // `challenge_scripts` is HTML; Tera escapes it unless the template uses
    // `| safe`. A page without the compiled script can never pass the check.
    if !html.contains("<script") || !html.contains("computeProofOfWork") {
        warn!(
            "challenge template did not inject the compiled script; use the documented challenge_scripts | safe filter; using the built-in page"
        );
        return None;
    }
    for id in REQUIRED_DOM_IDS {
        if !has_dom_id(&html, id) {
            warn!(
                id,
                "challenge template is missing a required DOM id; using the built-in page"
            );
            return None;
        }
    }
    Some(html)
}

/// Build a 503 challenge response, registering the pending challenge so the
/// verify endpoint can later resolve the nonce.
pub(crate) fn build_challenge_response(
    request_id: &str,
    original_url: &str,
    site_id: &str,
    client_ip: &str,
    user_agent: &str,
    difficulty: u32,
    kind: ChallengeKind,
) -> HttpResponse {
    let nonce = store_pending(
        request_id,
        site_id,
        original_url,
        client_ip,
        user_agent,
        difficulty,
    );
    let params = ChallengePageParams {
        request_id: request_id.to_string(),
        challenge_nonce: nonce,
        difficulty,
        verify_endpoint: VERIFY_ENDPOINT.to_string(),
        original_url: original_url.to_string(),
        brand_name: "WAFred".to_string(),
    };
    let body = challenge_page_template(site_id)
        .and_then(|template| render_challenge_template(&template, &params))
        .unwrap_or_else(|| match kind {
            ChallengeKind::Js => generate_js_challenge_html(&params),
            ChallengeKind::Managed => generate_managed_challenge_html(&params),
            ChallengeKind::Interactive => {
                generate_interactive_challenge_html(&params)
            },
        });
    HttpResponse::builder(StatusCode::SERVICE_UNAVAILABLE)
        .body(body)
        .header(HTTP_HEADER_CONTENT_HTML.clone())
        .header(edge_server_header())
        .header(mitigated_header(Mitigation::Challenge))
        .no_store()
        .finish()
}

// ─────────────────────────────────────────────────────────────
// Branded short-circuit pages
// ─────────────────────────────────────────────────────────────

/// The `Server` header every edge-generated response carries: visitors (and
/// site owners) can tell at a glance the response came through WAFred, the
/// way `server: cloudflare` works.
pub(crate) fn edge_server_header() -> (header::HeaderName, HeaderValue) {
    (header::SERVER, HeaderValue::from_static("wafred"))
}

/// What kind of edge action produced the response, mirroring Cloudflare's
/// `cf-mitigated`: a visitor (or the site owner debugging a report) sees from
/// the header alone whether security intervened.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Mitigation {
    /// A WAF verdict or defense-mode IP block.
    Block,
    /// A challenge was issued and must be solved.
    Challenge,
}

impl Mitigation {
    fn value(self) -> &'static str {
        match self {
            Mitigation::Block => "block",
            Mitigation::Challenge => "challenge",
        }
    }
}

fn mitigated_header(
    mitigation: Mitigation,
) -> (header::HeaderName, HeaderValue) {
    (
        header::HeaderName::from_static("x-pingwaf-mitigated"),
        HeaderValue::from_static(mitigation.value()),
    )
}

/// Minimal HTML escaping for values embedded in brand pages. Reasons come
/// from rule descriptions today, but any future user-influenced text keeps
/// the page inert this way.
fn escape_html(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Wraps short-circuit page content in the same visual family as the
/// error_page plugin's built-in templates (shared `PW_STYLE` partial).
///
/// `details` rows are pre-built `<div class="row">…</div>` markup — callers
/// escape their values via [`escape_html`].
fn brand_page(
    title: &str,
    icon: &str,
    code_label: &str,
    heading: &str,
    message_html: &str,
    details: &str,
) -> String {
    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · WAFred</title>
{pw_style}
</head>
<body>
<div class="card">
  <div class="icon"><svg viewBox="0 0 24 24">{icon}</svg></div>
  <div class="code">{code_label}</div>
  <h1>{heading}</h1>
  <p class="msg">{message_html}</p>
  <div class="details">{details}</div>
  <p class="brand">Protected by <a href="https://waf.red" target="_blank" rel="noopener"><b>WAFred</b></a></p>
</div>
</body>
</html>"##,
        title = escape_html(title),
        icon = icon,
        code_label = escape_html(code_label),
        heading = escape_html(heading),
        message_html = message_html,
        details = details,
        pw_style = super::error_page::PW_STYLE,
    )
}

/// One `Request ID`/value pair for a brand page's details block.
fn detail_row(label: &str, value: &str) -> String {
    format!(
        r#"<div class="row"><span class="k">{label}</span><span class="v">{}</span></div>"#,
        escape_html(value)
    )
}

/// The shared block-page body: makes unmistakably clear that *WAFred
/// Security* issued the block — the exact distinction that used to be lost
/// when origin errors borrowed a WAF-styled page.
fn block_body(request_id: &str, reason: &str) -> String {
    let details = format!(
        "{}{}{}",
        detail_row("Request ID", request_id),
        detail_row("Reason", reason),
        detail_row(
            "Time",
            &chrono::Utc::now()
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        ),
    );
    brand_page(
        "Request Blocked",
        r#"<path d="M12 3l7 3v5.5c0 4.4-2.9 7.6-7 9-4.1-1.4-7-4.6-7-9V6z"/><path d="M9.6 9.6l4.8 4.8M14.4 9.6l-4.8 4.8"/>"#,
        "Error 403",
        "Request Blocked",
        "Your request was blocked by <b>WAFred Security</b> before it reached \
the website. If you believe this is a mistake, contact the site \
administrator with the Request ID below.",
        &details,
    )
}

/// A 403 HTML block page.
pub(crate) fn block_page(request_id: &str, reason: &str) -> HttpResponse {
    HttpResponse::builder(StatusCode::FORBIDDEN)
        .body(block_body(request_id, reason))
        .header(HTTP_HEADER_CONTENT_HTML.clone())
        .header(edge_server_header())
        .header(mitigated_header(Mitigation::Block))
        .no_store()
        .finish()
}

/// A 401 HTML page asking the client to authenticate, sent by the site-wide
/// basic auth gate and by access rules that require credentials.
pub(crate) fn basic_auth_page(
    request_id: &str,
    realm: &str,
    reason: &str,
) -> HttpResponse {
    let challenge = format!(r#"Basic realm="{realm}""#);
    let details = format!(
        "{}{}",
        detail_row("Request ID", request_id),
        detail_row("Reason", reason),
    );
    let body = brand_page(
        "Authentication Required",
        r#"<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 018 0v4"/>"#,
        "Error 401",
        "Authentication Required",
        "This resource requires basic authentication. Sign in with the \
credentials the site owner gave you to continue.",
        &details,
    );
    HttpResponse::builder(StatusCode::UNAUTHORIZED)
        .body(body)
        .header(HTTP_HEADER_CONTENT_HTML.clone())
        .header((
            header::WWW_AUTHENTICATE,
            HeaderValue::from_str(&challenge).unwrap_or(
                HeaderValue::from_static("Basic realm=\"Restricted\""),
            ),
        ))
        .header(edge_server_header())
        .no_store()
        .finish()
}

/// A 503 maintenance page for a paused site. Sending a response instead of
/// dropping the site from the data-plane config keeps the certificate and the
/// log pipeline live, so the dashboard still shows the traffic.
pub(crate) fn paused_page(request_id: &str) -> HttpResponse {
    const RETRY_AFTER_SECS: &str = "3600";
    let details = detail_row("Request ID", request_id);
    let body = brand_page(
        "Site Paused",
        r#"<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>"#,
        "Error 503",
        "Site Temporarily Paused",
        "The site owner has paused this website. It should be back shortly — \
please try again later.",
        &details,
    );
    HttpResponse::builder(StatusCode::SERVICE_UNAVAILABLE)
        .body(body)
        .header(HTTP_HEADER_CONTENT_HTML.clone())
        .header((
            header::RETRY_AFTER,
            HeaderValue::from_static(RETRY_AFTER_SECS),
        ))
        .header(edge_server_header())
        .no_store()
        .finish()
}

/// A 503 page served by edges configured to fail closed: the control plane
/// is unreachable and the site has no synced rules, so the request is refused
/// instead of proxied unprotected.
pub(crate) fn fail_closed_page(request_id: &str) -> HttpResponse {
    const RETRY_AFTER_SECS: &str = "30";
    let details = detail_row("Request ID", request_id);
    let body = brand_page(
        "Temporarily Unavailable",
        r#"<path d="M12 3l7 3v5.5c0 4.4-2.9 7.6-7 9-4.1-1.4-7-4.6-7-9V6z"/><path d="M12 8v4M12 15h.01"/>"#,
        "Error 503",
        "Temporarily Unavailable",
        "This site is protected by WAFred in fail-closed mode. The edge node \
cannot reach its control plane right now, so requests are refused instead \
of proxied unprotected. Please retry in a moment.",
        &details,
    );
    HttpResponse::builder(StatusCode::SERVICE_UNAVAILABLE)
        .body(body)
        .header(HTTP_HEADER_CONTENT_HTML.clone())
        .header((
            header::RETRY_AFTER,
            HeaderValue::from_static(RETRY_AFTER_SECS),
        ))
        .header(edge_server_header())
        .no_store()
        .finish()
}

/// A 429 HTML page for requests stopped by a rate limit rule, telling the
/// client when it may retry.
pub(crate) fn rate_limit_page(
    request_id: &str,
    reason: &str,
    retry_after_secs: u64,
) -> HttpResponse {
    let retry_hint = if retry_after_secs > 0 {
        format!("Please try again in about <b>{retry_after_secs}</b> seconds.")
    } else {
        "Please slow down and try again shortly.".to_string()
    };
    let mut details = format!(
        "{}{}",
        detail_row("Request ID", request_id),
        detail_row("Reason", reason),
    );
    if retry_after_secs > 0 {
        details.push_str(&detail_row(
            "Retry after",
            &format!("{retry_after_secs}s"),
        ));
    }
    let body = brand_page(
        "Rate Limit Exceeded",
        r#"<circle cx="12" cy="13" r="8"/><path d="M12 13V9M9 2h6"/>"#,
        "Error 429",
        "Rate Limit Exceeded",
        &format!(
            "You have sent too many requests in a short period of time. \
{retry_hint}"
        ),
        &details,
    );
    let mut response = HttpResponse::builder(StatusCode::TOO_MANY_REQUESTS)
        .body(body)
        .header(HTTP_HEADER_CONTENT_HTML.clone())
        .header(edge_server_header())
        .header(mitigated_header(Mitigation::Block))
        .no_store();
    if retry_after_secs > 0 {
        response = response.header((
            header::RETRY_AFTER,
            HeaderValue::from_str(&retry_after_secs.to_string())
                .unwrap_or(HeaderValue::from_static("60")),
        ));
    }
    response.finish()
}

// ─────────────────────────────────────────────────────────────
// Per-IP fixed-window rate counter
// ─────────────────────────────────────────────────────────────

struct RateWindow {
    count: u32,
    window_start: i64,
}

// ─────────────────────────────────────────────────────────────
// Per-site decision engines (control-plane mode)
// ─────────────────────────────────────────────────────────────

/// Challenge pages issued per host+IP per 60-second window when neither the
/// site nor the plugin states a limit.
pub(crate) const DEFAULT_ISSUE_LIMIT_PER_MIN: u32 = 120;

/// Solution submissions accepted per host+IP per 60-second window by default.
pub(crate) const DEFAULT_VERIFY_LIMIT_PER_MIN: u32 = 300;

/// Hard ceiling on tracked host+IP pressure entries. Reaching it only loses
/// the adaptive raise for new keys (they stay at the site's base difficulty),
/// never the challenge itself.
const PRESSURE_MAX_ENTRIES: usize = 8192;

/// The per-site guards the request path applies on top of the decision engine.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ChallengeLimits {
    /// Base/max proof-of-work difficulty and the pressure signals feeding it.
    pub(crate) adaptive: AdaptiveDifficulty,
    /// Challenge pages issued per host+IP per minute.
    pub(crate) issue_limit: u32,
    /// Solution submissions accepted per host+IP per minute.
    pub(crate) verify_limit: u32,
}

impl ChallengeLimits {
    /// Guards for a caller that has only its own configuration: standalone
    /// mode, or a site whose challenge settings row is absent.
    pub(crate) fn standalone(
        base: u32,
        max: u32,
        issue_limit: u32,
        verify_limit: u32,
    ) -> Self {
        Self {
            adaptive: AdaptiveDifficulty::new(base, max),
            issue_limit,
            verify_limit,
        }
    }
}

/// Request rate the engine and the adaptive difficulty use for a site, with
/// the control plane's "0 means rate-based challenging is off" mapped onto the
/// sentinel the engine understands.
fn effective_rate_threshold(cfg: &CacheChallengeConfig) -> u32 {
    if cfg.request_threshold == 0 {
        u32::MAX
    } else {
        cfg.request_threshold
    }
}

// ─────────────────────────────────────────────────────────────
// Process-wide guards shared by every challenge minting path
// ─────────────────────────────────────────────────────────────

/// Issuance budget shared by the CC gate in this module and the WAF plugin's
/// `Challenge` verdicts, keyed by host+IP. A page minted by either path costs
/// the same budget, so a rule challenge cannot be used to bypass the per-IP
/// limit the site configured.
static ISSUE_LIMITER: LazyLock<FixedWindowLimiter> = LazyLock::new(|| {
    FixedWindowLimiter::new(LIMIT_WINDOW_SECS, DEFAULT_MAX_TRACKED_KEYS)
});

/// Verification budget, keyed the same way.
static VERIFY_LIMITER: LazyLock<FixedWindowLimiter> = LazyLock::new(|| {
    FixedWindowLimiter::new(LIMIT_WINDOW_SECS, DEFAULT_MAX_TRACKED_KEYS)
});

/// Verification-failure pressure feeding adaptive difficulty, per host+IP.
static DIFFICULTY_PRESSURE: LazyLock<DashMap<String, DifficultyState>> =
    LazyLock::new(DashMap::new);

/// Key for the per-site, per-address guards. Shared by the rate window, the
/// issuance budget and the difficulty pressure so one request's decision,
/// budget and difficulty all describe the same client.
fn guard_key(host: &str, client_ip: &str) -> String {
    if host.is_empty() {
        client_ip.to_string()
    } else {
        format!("{host}:{client_ip}")
    }
}

/// Current verification-failure pressure for `key`.
fn pressure_state(key: &str) -> DifficultyState {
    DIFFICULTY_PRESSURE
        .get(key)
        .map(|state| *state)
        .unwrap_or_default()
}

/// Records the outcome of one verification attempt for `key`.
///
/// A success clears the record outright; a failure adds one (decayed) step,
/// bounded by the table ceiling. Reaching the ceiling only means new keys stay
/// at the base difficulty — the challenge itself still runs.
fn note_verification(
    key: &str,
    adaptive: AdaptiveDifficulty,
    success: bool,
    now: i64,
) {
    if success {
        DIFFICULTY_PRESSURE.remove(key);
        return;
    }
    if !DIFFICULTY_PRESSURE.contains_key(key)
        && DIFFICULTY_PRESSURE.len() >= PRESSURE_MAX_ENTRIES
    {
        return;
    }
    let mut entry = DIFFICULTY_PRESSURE.entry(key.to_string()).or_default();
    *entry = adaptive.record_failure(*entry, now);
}

/// Drops pressure records whose failure steps have fully decayed, so the map
/// cannot accumulate one entry per address that ever failed once. Throttled
/// like the pending-challenge sweep: a full scan per request would be a CPU
/// amplifier under the flood this exists to survive.
fn sweep_pressure(now: i64) {
    if DIFFICULTY_PRESSURE.len() <= 1024
        || !GC_TICK
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .is_multiple_of(64)
    {
        return;
    }
    let ttl =
        DIFFICULTY_DECAY_SECS.saturating_mul(i64::from(MAX_FAILURE_STEPS));
    DIFFICULTY_PRESSURE
        .retain(|_, state| now.saturating_sub(state.updated_at) < ttl);
}

/// The site's mint configuration from the agent cache: its guards and the rate
/// threshold request pressure is measured against.
///
/// Unlike the challenge plugin's `site_challenge` this does **not** require the
/// site's CC gate to be enabled: a WAF rule (or an IP/geo/rate-limit rule) may
/// answer with a challenge on a site whose passive CC gate is off, and that
/// page must still honour the site's difficulty and per-IP budget. `None` means
/// "no site configuration" (standalone, or no row), so the caller's own
/// configuration applies.
fn site_mint_config(host: &str) -> Option<(ChallengeLimits, u32)> {
    let agent = WafredAgent::instance()?;
    let rules = agent.get_rules_for_domain(host)?;
    let cfg = rules.challenge_config.as_ref()?;
    Some((site_limits(cfg), effective_rate_threshold(cfg)))
}

/// Everything one challenge mint needs from the caller.
pub(crate) struct MintRequest<'a> {
    /// Request id the page is built with (and the pending entry is keyed by).
    pub(crate) request_id: &'a str,
    /// Path (and query) the visitor is redirected to after solving.
    pub(crate) original_url: &'a str,
    /// Host the challenge is bound to; also the site id in the cookie.
    pub(crate) site_id: &'a str,
    pub(crate) client_ip: &'a str,
    pub(crate) user_agent: &'a str,
    /// Requests from this client in the current window when the caller tracks
    /// one; `0` means "not measured" and contributes no rate pressure.
    pub(crate) request_rate: u32,
    pub(crate) kind: ChallengeKind,
    /// Guards to use when the site carries no challenge configuration.
    pub(crate) fallback: ChallengeLimits,
    /// Rate threshold paired with `fallback` for request pressure.
    pub(crate) fallback_rate_threshold: u32,
}

/// What one guarded mint produced.
pub(crate) enum MintOutcome {
    /// Send this challenge page (503).
    Challenge(HttpResponse),
    /// The client is over its issuance budget: send this 429 page instead.
    RateLimited(HttpResponse),
}

impl MintOutcome {
    /// Whether the response is a challenge page (as opposed to a rate-limit
    /// refusal), which decides the `x-pingwaf-mitigated` value.
    pub(crate) fn is_challenge(&self) -> bool {
        matches!(self, Self::Challenge(_))
    }

    pub(crate) fn into_response(self) -> HttpResponse {
        match self {
            Self::Challenge(response) | Self::RateLimited(response) => response,
        }
    }
}

/// Mints a challenge page through the single guarded path every issuer uses
/// (this plugin's CC gate and the WAF plugin's rule/access/rate-limit
/// challenges).
///
/// It resolves the site's guards, charges the shared per-host+IP issuance
/// budget and derives the adaptive difficulty from the shared pressure, then
/// records the difficulty in the pending entry so verification checks exactly
/// what the page was told.
///
/// Budget semantics follow [`FixedWindowLimiter`]: `Deny` is the only outcome
/// that refuses the page. `Saturated` — the table is full of *other* clients —
/// still mints, without a budget entry, because locking every new visitor out
/// after an attacker fills the table would turn a burst guard into an outage.
pub(crate) fn mint_challenge(request: MintRequest<'_>) -> MintOutcome {
    let (limits, rate_threshold) = site_mint_config(request.site_id)
        .unwrap_or((request.fallback, request.fallback_rate_threshold));
    let key = guard_key(request.site_id, request.client_ip);
    let now = now_secs();
    match ISSUE_LIMITER.allow(&key, limits.issue_limit, now) {
        LimitDecision::Deny => {
            warn!(
                request_id = %request.request_id,
                site = %request.site_id,
                "challenge issuance rate limit exceeded"
            );
            return MintOutcome::RateLimited(rate_limit_page(
                request.request_id,
                "too many challenges issued to this client; retry shortly",
                LIMIT_WINDOW_SECS as u64,
            ));
        },
        LimitDecision::Saturated => {
            // Table full of other clients: mint without counting rather than
            // refuse a legitimate visitor. Logged at debug so a many-source
            // flood cannot turn this into a log amplifier.
            debug!(
                site = %request.site_id,
                "challenge issuance table saturated; issuing without a budget entry"
            );
        },
        LimitDecision::Allow => {},
    }

    sweep_pressure(now);
    let difficulty = limits.adaptive.difficulty(
        pressure_state(&key),
        now,
        request.request_rate,
        rate_threshold,
    );
    MintOutcome::Challenge(build_challenge_response(
        request.request_id,
        request.original_url,
        request.site_id,
        request.client_ip,
        request.user_agent,
        difficulty,
        request.kind,
    ))
}

/// Resolves a site's guards from its cached challenge configuration.
///
/// A zero in the cache means "field absent": either the control plane predates
/// the setting or the snapshot was written before the column existed. Falling
/// back to the documented defaults keeps such a site on the historical
/// behaviour (difficulty 20) instead of issuing difficulty-0 challenges.
fn site_limits(cfg: &CacheChallengeConfig) -> ChallengeLimits {
    let base = if cfg.base_difficulty == 0 {
        pingwaf_challenge::DEFAULT_BASE_DIFFICULTY
    } else {
        cfg.base_difficulty
    };
    let max = if cfg.max_difficulty == 0 {
        pingwaf_challenge::DEFAULT_MAX_DIFFICULTY
    } else {
        cfg.max_difficulty
    };
    ChallengeLimits {
        adaptive: AdaptiveDifficulty::new(base, max),
        issue_limit: if cfg.issue_limit_per_minute == 0 {
            DEFAULT_ISSUE_LIMIT_PER_MIN
        } else {
            cfg.issue_limit_per_minute
        },
        verify_limit: if cfg.verify_limit_per_minute == 0 {
            DEFAULT_VERIFY_LIMIT_PER_MIN
        } else {
            cfg.verify_limit_per_minute
        },
    }
}

/// A cached per-site decision engine plus the guard configuration and the
/// agent config fingerprint it was built from.
struct CachedChallengeEngine {
    /// Config fingerprint the engine was built from. An `Arc` so the per
    /// request fingerprint check stays allocation-free.
    fingerprint: Arc<str>,
    engine: Option<Arc<ChallengeEngine>>,
    limits: ChallengeLimits,
    /// Unix seconds of the last cache hit; feeds the host-cache TTL sweep
    /// (`host_cache`) — wildcard-matched scanner hosts would otherwise cache
    /// a compiled engine forever.
    last_used: AtomicU64,
}

/// Builds the decision engine for one site's challenge configuration. Every
/// engine shares the plugin's clearance-cookie secret so a cookie earned on
/// one site validates everywhere the plugin runs.
fn build_site_engine(
    cfg: &CacheChallengeConfig,
    cookie_secret: &str,
    cookie_name: &str,
    base_difficulty: u32,
) -> ChallengeEngine {
    let default_level = match cfg.default_level {
        CacheChallengeLevel::None => ClearanceLevel::None,
        CacheChallengeLevel::NonInteractive => ClearanceLevel::NonInteractive,
        CacheChallengeLevel::Managed => ClearanceLevel::Managed,
        CacheChallengeLevel::Interactive => ClearanceLevel::Interactive,
    };
    let clearance_duration_secs = if cfg.clearance_duration_seconds == 0 {
        1800
    } else {
        i64::from(cfg.clearance_duration_seconds)
    };
    ChallengeEngine::new(ChallengeConfig {
        enabled: true,
        under_attack_mode: cfg.under_attack_mode,
        default_level,
        clearance_duration_secs,
        exempt_paths: cfg.exempt_paths.clone(),
        exempt_user_agents: Vec::new(),
        // A zero threshold from the control plane means rate-based
        // challenging is disabled; the engine would otherwise challenge
        // everything above zero requests.
        rate_threshold: effective_rate_threshold(cfg),
        browser_integrity_check: cfg.browser_integrity_check,
        tls_fingerprint_check: cfg.tls_fingerprint_check,
        cookie_secret: cookie_secret.to_string(),
        cookie_name: cookie_name.to_string(),
        // The engine's static difficulty is the site's base; the plugin issues
        // pages with the adaptive value and records it in the pending entry,
        // so verification never depends on this field.
        pow_difficulty: base_difficulty,
        submission_max_age_secs: 300,
    })
}

/// Resolves the clearance-cookie signing secret.
///
/// Standalone deployments take it from the plugin config. Under the Wafred
/// agent the generated config carries no secret: one is generated on first
/// boot and persisted in the agent cache dir so clearance cookies survive
/// config reloads and process restarts.
pub(crate) fn resolve_cookie_secret(configured: &str) -> String {
    if !configured.is_empty() && configured != "change-me" {
        return configured.to_string();
    }
    let Some(agent) = WafredAgent::instance() else {
        // Standalone: never fall back to a publicly-known key.
        return FALLBACK_COOKIE_SECRET.clone();
    };
    let dir = Path::new(&agent.config.cache_dir);
    let path = dir.join("challenge_cookie_secret");
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let trimmed = existing.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    let secret = uuid::Uuid::new_v4().simple().to_string();
    if std::fs::create_dir_all(dir).is_ok()
        && std::fs::write(&path, secret.as_bytes()).is_ok()
    {
        secret
    } else {
        // Keep the clearance system working even on a read-only cache dir;
        // cookies merely do not survive a restart. The value is process-wide
        // so the WAF and the challenge plugin agree on it.
        UNPERSISTED_COOKIE_SECRET
            .get_or_init(|| uuid::Uuid::new_v4().simple().to_string())
            .clone()
    }
}

/// Resolves the site-level proxy trust for `host` from the agent cache.
///
/// `None` when the site is not behind a trusted proxy, in which case the
/// default client-IP resolution applies.
fn site_proxy_trust(host: &str) -> Option<ProxyTrust> {
    let agent = WafredAgent::instance()?;
    let site_rules = agent.get_rules_for_domain(host)?;
    let trust = &site_rules.proxy_trust;
    trust.enabled.then(|| {
        ProxyTrust::new(
            trust.enabled,
            trust.effective_header(),
            trust.last_hop_only,
            &trust.trusted_ranges,
        )
    })
}

// ─────────────────────────────────────────────────────────────
// ChallengePlugin
// ─────────────────────────────────────────────────────────────

/// CC protection / browser challenge plugin.
pub struct ChallengePlugin {
    plugin_step: PluginStep,
    /// Statically configured engine: the decision engine in standalone mode
    /// and the clearance-cookie signer everywhere (per-site engines share its
    /// secret, and only the nonce — which never depends on the engine — is
    /// needed to verify a submission).
    engine: Arc<ChallengeEngine>,
    hash_value: String,
    enabled: bool,
    cookie_name: String,
    cookie_secret: String,
    /// Per-site decision engines built from agent rules, keyed by host.
    site_engines: DashMap<String, CachedChallengeEngine>,
    /// Sweep gate for the `site_engines` host cache (TTL + hard cap).
    engine_sweep: HostCacheSweep,
    /// Per host+IP request counter used to feed `request_rate` to the engine.
    rates: DashMap<String, RateWindow>,
    /// Guards used when no per-site configuration resolves: standalone mode,
    /// or a request whose site has no challenge settings.
    standalone_limits: ChallengeLimits,
}

impl ChallengePlugin {
    /// Create a new plugin from configuration.
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new challenge plugin");
        Self::try_from(params)
    }

    /// Record a hit for `ip` and return its request count in the current
    /// 60-second window.
    fn record_rate(&self, ip: &str) -> u32 {
        let now = now_secs();
        let mut entry =
            self.rates.entry(ip.to_string()).or_insert(RateWindow {
                count: 0,
                window_start: now,
            });
        if now.saturating_sub(entry.window_start) >= RATE_WINDOW_SECS {
            entry.count = 0;
            entry.window_start = now;
        }
        entry.count = entry.count.saturating_add(1);
        let count = entry.count;
        drop(entry);
        // Opportunistic cleanup so the map does not grow unbounded; same
        // throttle as the challenge map — a per-request full scan would be
        // a CPU amplifier under many-source traffic (2026-10-18 audit H3).
        if self.rates.len() > 8192
            && GC_TICK
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                .is_multiple_of(64)
        {
            self.rates.retain(|_, w| {
                now.saturating_sub(w.window_start) < RATE_WINDOW_SECS * 2
            });
        }
        count
    }

    /// Resolves the decision engine for `host`: the per-site engine built
    /// from agent rules in control-plane mode, the statically configured
    /// engine in standalone mode. `None` means pass everything through.
    fn site_challenge(
        &self,
        host: &str,
    ) -> Option<(Arc<ChallengeEngine>, ChallengeLimits)> {
        if WafredAgent::instance().is_none() {
            return Some((Arc::clone(&self.engine), self.standalone_limits));
        }
        if host.is_empty() {
            return None;
        }
        let agent = WafredAgent::instance()?;
        let now = crate::host_cache::unix_now();
        self.engine_sweep.prune(&self.site_engines, now, |cached| {
            cached.last_used.load(std::sync::atomic::Ordering::Relaxed)
        });
        let Some(site_rules) = agent.get_rules_for_domain(host) else {
            // The host no longer resolves in the cache (deleted or renamed
            // site): drop the compiled engine so the per-domain cache
            // cannot grow without bound across config churn.
            self.site_engines.remove(host);
            return None;
        };
        let cfg = site_rules
            .challenge_config
            .as_ref()
            .filter(|cfg| cfg.enabled)?;

        let fingerprint = agent.config_hash();
        if let Some(cached) = self.site_engines.get(host)
            && cached.fingerprint == fingerprint
        {
            touch(&cached.last_used, now);
            return cached.engine.clone().map(|engine| (engine, cached.limits));
        }
        let limits = site_limits(cfg);
        let engine = Arc::new(build_site_engine(
            cfg,
            &self.cookie_secret,
            &self.cookie_name,
            limits.adaptive.base(),
        ));
        self.site_engines.insert(
            host.to_string(),
            CachedChallengeEngine {
                fingerprint,
                engine: Some(Arc::clone(&engine)),
                limits,
                last_used: AtomicU64::new(now),
            },
        );
        Some((engine, limits))
    }

    /// Bind a submission to the context that requested the challenge.
    ///
    /// The nonce/PoW alone only proves that *someone* spent the work. Without
    /// this check, a page fetched from one address could be solved on another
    /// machine and submitted with a fabricated `fingerprint_json`. The live
    /// request IP/User-Agent and the fingerprint UA must all agree with what
    /// the edge observed when it issued the challenge.
    fn pending_matches_request(
        pending: &PendingChallenge,
        client_ip: &str,
        user_agent: &str,
        fingerprint_json: &str,
    ) -> Result<(), &'static str> {
        if !pending.client_ip.is_empty() && pending.client_ip != client_ip {
            return Err("challenge was issued to a different client address");
        }
        if !pending.user_agent.is_empty() && pending.user_agent != user_agent {
            return Err("challenge was issued to a different User-Agent");
        }
        let fingerprint = BrowserFingerprint::from_json(fingerprint_json)
            .map_err(|_| "invalid fingerprint data")?;
        if fingerprint.user_agent != user_agent {
            return Err("fingerprint User-Agent does not match the request");
        }
        if !pending.user_agent.is_empty()
            && fingerprint.user_agent != pending.user_agent
        {
            return Err("fingerprint User-Agent does not match the challenge");
        }
        Ok(())
    }

    /// Handle a POST to the verify endpoint: validate the proof-of-work and,
    /// on success, hand back a clearance cookie plus a redirect to the
    /// originally requested URL. The cookie's `Secure` attribute follows the
    /// connection's TLS state — browsers refuse to store a `Secure` cookie
    /// on a plain HTTP page, which would make the challenge unsolvable there.
    async fn handle_verify(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        let mut buf = BytesMut::with_capacity(4096);
        while let Some(chunk) = session.read_request_body().await? {
            // Cap before copying: the old order copied the whole chunk and
            // only then checked, so the buffer could exceed the limit by a
            // full chunk and still be parsed (2026-10-18 audit).
            if buf.len() >= MAX_VERIFY_BODY {
                break;
            }
            let room = MAX_VERIFY_BODY - buf.len();
            let take = room.min(chunk.len());
            buf.put(&chunk[..take]);
            if take < chunk.len() {
                break;
            }
        }

        let value: serde_json::Value = match serde_json::from_slice(&buf) {
            Ok(v) => v,
            Err(_) => {
                return Ok(RequestPluginResult::Respond(block_page(
                    "-",
                    "malformed challenge submission",
                )));
            },
        };

        let request_id = value
            .get("request_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let solution = value
            .get("solution")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let fingerprint_json = value
            .get("fingerprint_json")
            .and_then(|v| v.as_str())
            .unwrap_or("{}")
            .to_string();
        let timestamp = value
            .get("timestamp")
            .and_then(|v| v.as_i64())
            .unwrap_or_else(now_secs);
        // The submission names the challenge it answers; carry it on the
        // request context so an edge-generated answer (the over-limit 429)
        // can be written to the access log under the same id the page shows.
        ctx.state.request_id = Some(request_id.clone());

        // The pending entry identifies the site the challenge was issued for;
        // resolving the budget from it (rather than from the request's Host
        // header) keeps a forged Host from steering which site's limits apply
        // and from making the edge compile an engine for every random name.
        let Some(pending) = peek_pending(&request_id) else {
            return Ok(RequestPluginResult::Respond(block_page(
                &request_id,
                "challenge expired or unknown, please retry",
            )));
        };

        // Resolve the same trusted client address the challenge issuance
        // used, then bind the submission to it and to the live User-Agent.
        if let Some(trust) = site_proxy_trust(&pending.site_id)
            && let Some(ip) = resolve_client_ip_with_trust(session, &trust)
        {
            ctx.conn.client_ip = Some(ip);
        }
        let actual_ip = ensure_client_ip(session, ctx).to_string();
        let actual_user_agent =
            get_req_header_value(session.req_header(), "user-agent")
                .unwrap_or_default();
        let guard_key = guard_key(&pending.site_id, &actual_ip);
        let now = now_secs();

        // Per-address verification budget, checked before any verification
        // work: an over-limit attempt must fail closed and must not spend the
        // pending nonce, or a flood of guesses could burn a legitimate
        // visitor's challenge. The nonce is only consumed once a submission
        // has actually been accepted.
        let (engine, limits) = self
            .site_challenge(&pending.site_id)
            .unwrap_or((Arc::clone(&self.engine), self.standalone_limits));
        // Unlike issuance, verification fails closed when the table is full:
        // a full table must not become an unmetered guessing channel. The
        // visitor's challenge survives either way, so they can retry once the
        // window rolls over.
        if VERIFY_LIMITER.allow(&guard_key, limits.verify_limit, now)
            != LimitDecision::Allow
        {
            warn!(
                request_id = %request_id,
                site = %pending.site_id,
                "challenge verification rate limit exceeded"
            );
            let response = rate_limit_page(
                &request_id,
                "too many challenge verification attempts from this client",
                LIMIT_WINDOW_SECS as u64,
            );
            // This branch answers the request itself, so the access-log
            // response phase never runs: emit the entry here, like the other
            // edge-generated responses, or the refusal is invisible in
            // analytics.
            super::waf::emit_challenge_access(
                session,
                ctx,
                &pending.site_id,
                &actual_ip,
                &response,
            );
            return Ok(RequestPluginResult::Respond(response));
        }

        if let Err(reason) = Self::pending_matches_request(
            &pending,
            &actual_ip,
            actual_user_agent,
            &fingerprint_json,
        ) {
            warn!(
                request_id = %request_id,
                reason,
                "challenge submission context does not match the issued challenge"
            );
            note_verification(&guard_key, limits.adaptive, false, now);
            return Ok(RequestPluginResult::Respond(block_page(
                &request_id,
                reason,
            )));
        }

        let submission = ChallengeSubmission {
            request_id: request_id.clone(),
            challenge_nonce: pending.nonce.clone(),
            solution,
            fingerprint_json,
            timestamp,
            site_id: pending.site_id.clone(),
        };

        // Verify with the same per-site engine that issued the challenge.
        // Using the static plugin engine here silently ignored site-level
        // `browser_integrity_check`, clearance duration and TLS-fingerprint
        // settings: a site that disabled the integrity check still rejected
        // every headless/automated browser during verification.
        let result = engine.verify_solution_for_pending(
            &submission,
            ctx.conn.tls_version.is_some(),
            // The difficulty recorded when this challenge was issued — not
            // the site's current setting, which adaptive pressure may have
            // changed since.
            pending.difficulty,
        );
        note_verification(
            &guard_key,
            limits.adaptive,
            matches!(result, VerifyResult::Success { .. }),
            now,
        );

        match result {
            VerifyResult::Success {
                cookie_value,
                cookie_attributes,
            } => {
                // The nonce is spent and the challenge resolved; drop it only
                // after the verifier accepted the submission.
                if let Some((_, removed)) =
                    PENDING_CHALLENGES.remove(&request_id)
                {
                    account_pending_removed(&removed);
                }
                let set_cookie = format!(
                    "{}={}; {}",
                    self.cookie_name, cookie_value, cookie_attributes
                );
                // Redirect instead of echoing the URL into an inline script:
                // the original URL is client-controlled, and reflecting it
                // into a `javascript:` string is XSS. Only same-origin
                // absolute paths are honored; anything else falls back to
                // "/" (so `//evil.com` cannot become a protocol-relative
                // open redirect either).
                let target = safe_redirect_target(&pending.original_url);
                // Return the redirect in the body instead of a 303. XHR follows
                // a 303 to the original URL; when that URL redirects to an
                // external auth portal the browser reports a CORS failure and
                // the challenge page shows "Verification Failed" even though
                // the clearance cookie is already set. A 200 keeps the
                // redirect under this page's control.
                let body = serde_json::json!({
                    "ok": true,
                    "redirect": target,
                })
                .to_string();
                let builder =
                    HttpResponse::builder(StatusCode::OK).body(body).header((
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/json"),
                    ));
                let mut builder = builder;
                if let Ok(hv) = HeaderValue::from_str(&set_cookie) {
                    builder = builder.header((header::SET_COOKIE, hv));
                }
                Ok(RequestPluginResult::Respond(builder.no_store().finish()))
            },
            VerifyResult::Failed { reason } => {
                warn!(request_id = %request_id, reason = %reason, "challenge verification failed");
                Ok(RequestPluginResult::Respond(block_page(
                    &request_id,
                    &reason,
                )))
            },
        }
    }
}

impl TryFrom<&PluginConf> for ChallengePlugin {
    type Error = Error;

    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let category = PluginCategory::Challenge.to_string();

        // A challenge plugin that is added is meant to be active; only an
        // explicit `enabled = false` disables it.
        let enabled = value
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let under_attack_mode = value
            .get("under_attack_mode")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let clearance_duration_secs =
            get_int_conf_or_default(value, "clearance_duration_secs", 1800);
        let rate_threshold =
            get_int_conf_or_default(value, "rate_threshold", 100) as u32;
        // Standalone guards. `pow_difficulty` is the base a quiet visitor
        // solves; `pow_max_difficulty` is the adaptive ceiling (clamped up to
        // the base, so a site that raises the base keeps a coherent pair).
        let pow_difficulty =
            get_int_conf_or_default(value, "pow_difficulty", 20) as u32;
        let pow_max_difficulty = get_int_conf_or_default(
            value,
            "pow_max_difficulty",
            i64::from(pingwaf_challenge::DEFAULT_MAX_DIFFICULTY),
        ) as u32;
        let standalone_limits = ChallengeLimits {
            adaptive: AdaptiveDifficulty::new(
                pow_difficulty,
                pow_max_difficulty,
            ),
            issue_limit: get_int_conf_or_default(
                value,
                "pow_issue_limit_per_min",
                i64::from(DEFAULT_ISSUE_LIMIT_PER_MIN),
            )
            .clamp(0, i64::from(u32::MAX)) as u32,
            verify_limit: get_int_conf_or_default(
                value,
                "pow_verify_limit_per_min",
                i64::from(DEFAULT_VERIFY_LIMIT_PER_MIN),
            )
            .clamp(0, i64::from(u32::MAX)) as u32,
        };

        let mut cookie_secret =
            resolve_cookie_secret(&get_str_conf(value, "cookie_secret"));
        if cookie_secret.is_empty() {
            // Unreachable with the resolution above, but never sign with an
            // empty key.
            cookie_secret = FALLBACK_COOKIE_SECRET.clone();
        }
        let mut cookie_name = get_str_conf(value, "cookie_name");
        if cookie_name.is_empty() {
            cookie_name = "__pingwaf_clearance".to_string();
        }
        let exempt_paths = get_str_slice_conf(value, "exempt_paths");
        let exempt_user_agents =
            get_str_slice_conf(value, "exempt_user_agents");

        let plugin_step = match super::get_step_conf_in(
            value,
            "challenge",
            PluginStep::EarlyRequest,
            &[PluginStep::EarlyRequest, PluginStep::Request],
        ) {
            Ok(step) => step,
            Err(e) => {
                return Err(Error::Invalid {
                    category,
                    message: e.to_string(),
                });
            },
        };

        let config = ChallengeConfig {
            enabled,
            under_attack_mode,
            default_level: ClearanceLevel::NonInteractive,
            clearance_duration_secs,
            exempt_paths,
            exempt_user_agents,
            rate_threshold,
            browser_integrity_check: value
                .get("browser_integrity_check")
                .and_then(|v| v.as_bool())
                .unwrap_or(true),
            tls_fingerprint_check: false,
            cookie_secret: cookie_secret.clone(),
            cookie_name: cookie_name.clone(),
            pow_difficulty,
            submission_max_age_secs: get_int_conf_or_default(
                value,
                "submission_max_age_secs",
                300,
            ),
        };

        Ok(Self {
            plugin_step,
            engine: Arc::new(ChallengeEngine::new(config)),
            hash_value,
            enabled,
            cookie_name,
            cookie_secret,
            standalone_limits,
            site_engines: DashMap::new(),
            engine_sweep: HostCacheSweep::default(),
            rates: DashMap::new(),
        })
    }
}

#[async_trait]
impl Plugin for ChallengePlugin {
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if step != self.plugin_step {
            return Ok(RequestPluginResult::Skipped);
        }

        // ACME http-01 validation requests are answered by the proxy before
        // the plugin chain runs; skip them here too, as a second line of
        // defense: challenging a CA verification request would make the
        // certificate unissuable regardless of `exempt_paths`.
        if session
            .req_header()
            .uri
            .path()
            .starts_with(super::waf::ACME_HTTP_01_PATH_PREFIX)
        {
            return Ok(RequestPluginResult::Continue);
        }

        let path = session.req_header().uri.path().to_string();
        let method = session.req_header().method.as_str().to_string();

        // The verify endpoint is always served, even if challenges would
        // otherwise be skipped for this path.
        if path == VERIFY_ENDPOINT && method == "POST" {
            return self.handle_verify(session, ctx).await;
        }

        // Only the decision path needs the feature switch. The verify endpoint
        // above must stay reachable even when CC/challenge settings are off:
        // the WAF plugin can issue a challenge page on its own, and without
        // this endpoint the browser's solution falls through to the upstream
        // (typically an auth redirect) and shows "Verification Failed".
        if !self.enabled {
            return Ok(RequestPluginResult::Skipped);
        }

        // A path exception that skips the challenge layer exempts this
        // request from the standalone challenge gate too. The fast path is
        // the pending-access entry the WAF stamps when it runs; a missing
        // entry (WAF not in the chain, table full) falls through to the
        // direct site-rule lookup below.
        if let Some(request_id) = ctx.state.request_id.as_deref()
            && (super::waf::pending_path_bypasses_challenge(request_id)
                || super::waf::pending_path_bypasses_rate_limit(request_id))
        {
            return Ok(RequestPluginResult::Continue);
        }

        let host = get_host(session.req_header())
            .unwrap_or_default()
            .to_string();
        // Resolve the site's exceptions directly instead of relying only on
        // the WAF's pending-access handshake: the WAF may be absent from the
        // chain or its pending table may be full, yet `skip_layers = ["*"]`
        // must still suppress this gate.
        if super::waf::path_exception_skips_challenge(&host, &path) {
            return Ok(RequestPluginResult::Continue);
        }
        // Sites behind a CDN/proxy derive the client IP from the trusted
        // forwarded header so challenge rate limiting keys on the real
        // visitor address.
        if let Some(trust) = site_proxy_trust(&host)
            && let Some(ip) = resolve_client_ip_with_trust(session, &trust)
        {
            ctx.conn.client_ip = Some(ip);
        }
        let client_ip = ensure_client_ip(session, ctx).to_string();
        let user_agent =
            get_req_header_value(session.req_header(), "user-agent")
                .unwrap_or_default()
                .to_string();

        let Some((engine, limits)) = self.site_challenge(&host) else {
            return Ok(RequestPluginResult::Continue);
        };

        // A clearance cookie issued for *this* host short-circuits
        // everything. Per-site engines share this engine's secret, so a valid
        // signature only says that some site in this deployment issued the
        // cookie — the site id inside it is what says which. Without the
        // comparison, solving the challenge on one site exempted every site
        // the deployment serves (the WAF's clearance path has always bound
        // the two; see `waf::clearance_valid`). The level is checked too, so
        // a JS clearance cannot stand in for an interactive one.
        if let Some(cookie) =
            get_cookie_value(session.req_header(), &self.cookie_name)
            && let Some(payload) = self.engine.validate_clearance(&cookie)
            && payload.site_id == host
            && engine.clearance_level_sufficient(&payload)
        {
            return Ok(RequestPluginResult::Continue);
        }

        // Rate windows are per site so one domain's burst never charges
        // another's budget.
        let rate_key = guard_key(&host, &client_ip);
        let request_rate = self.record_rate(&rate_key);
        let challenge_request = ChallengeRequest {
            path,
            method,
            client_ip: client_ip.clone(),
            user_agent: user_agent.clone(),
            cookies: Vec::new(),
            has_js_support: None,
            request_rate,
            // The host is this deployment's site id, on the issuing side and
            // the checking side alike: the challenge page is built with it
            // (see `build_challenge_response` below) and the cookie it issues
            // is bound to it.
            site_id: host.clone(),
        };

        let decision = engine.should_challenge(&challenge_request);

        if decision == ChallengeDecision::Pass {
            return Ok(RequestPluginResult::Continue);
        }
        if decision == ChallengeDecision::Block {
            let request_id = ctx
                .state
                .request_id
                .clone()
                .unwrap_or_else(generate_request_id);
            ctx.state.request_id = Some(request_id.clone());
            let response =
                block_page(&request_id, "blocked by challenge policy");
            // L3-005: plugin-generated responses never reach the access-log
            // response phase; emit the entry here so the refusal stays
            // visible in analytics.
            super::waf::emit_challenge_access(
                session, ctx, &host, &client_ip, &response,
            );
            return Ok(RequestPluginResult::Respond(response));
        }

        // Any challenge flavour needs the original URL and a request id.
        let uri = &session.req_header().uri;
        let original_url = match uri.query() {
            Some(q) => format!("{}?{}", uri.path(), q),
            None => uri.path().to_string(),
        };
        // The same value the request was evaluated against, so the cookie
        // issued here is bound to exactly the site it was checked for.
        let site_id = challenge_request.site_id;
        let request_id = ctx
            .state
            .request_id
            .clone()
            .unwrap_or_else(generate_request_id);
        ctx.state.request_id = Some(request_id.clone());

        let kind = match decision {
            ChallengeDecision::ManagedChallenge => ChallengeKind::Managed,
            ChallengeDecision::InteractiveChallenge => {
                ChallengeKind::Interactive
            },
            _ => ChallengeKind::Js,
        };

        // One guarded mint for every issuer: the shared per-host+IP budget
        // decides between a challenge page and an explicit 429, and the
        // shared pressure decides the adaptive difficulty. The issued
        // difficulty is recorded in the pending entry, so verification checks
        // exactly what the page was told.
        let outcome = mint_challenge(MintRequest {
            request_id: &request_id,
            original_url: &original_url,
            site_id: &site_id,
            client_ip: &client_ip,
            user_agent: &user_agent,
            request_rate,
            kind,
            fallback: limits,
            fallback_rate_threshold: engine.config().rate_threshold,
        });
        let response = outcome.into_response();
        // L3-005: the challenge 503 never reached the access-log response
        // phase, so analytics showed none of the challenged traffic. Emit
        // the entry here, keyed by the host the challenge was issued for.
        super::waf::emit_challenge_access(
            session, ctx, &site_id, &client_ip, &response,
        );
        Ok(RequestPluginResult::Respond(response))
    }
}

register_plugin!("challenge", ChallengePlugin);

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use pingap_core::PluginStep;
    use pingora::proxy::Session;
    use tokio_test::io::Builder;

    /// Reads one response header value, case-insensitively.
    fn header_value(resp: &HttpResponse, name: &str) -> Option<String> {
        resp.headers
            .as_ref()?
            .iter()
            .find(|(n, _)| n.as_str().eq_ignore_ascii_case(name))
            .map(|(_, v)| v.to_str().unwrap_or_default().to_string())
    }

    fn pending_for_context() -> PendingChallenge {
        PendingChallenge {
            nonce: "nonce".to_string(),
            site_id: "example.com".to_string(),
            original_url: "/".to_string(),
            difficulty: 20,
            client_ip: "203.0.113.10".to_string(),
            user_agent: "TestBrowser/1.0".to_string(),
            created_at: now_secs(),
            bytes: 0,
        }
    }

    fn fingerprint_json(user_agent: &str) -> String {
        serde_json::json!({
            "user_agent": user_agent,
            "screen_width": 1920,
            "screen_height": 1080,
            "timezone_offset": 0,
            "language": "en",
            "platform": "MacIntel",
            "canvas_hash": "abc",
            "webgl_vendor": "",
            "webgl_renderer": "",
            "plugins_count": 0,
            "touch_support": false,
            "hardware_concurrency": 8,
            "device_memory": 8.0
        })
        .to_string()
    }

    #[test]
    fn challenge_submission_is_bound_to_request_context() {
        let pending = pending_for_context();
        let ok = fingerprint_json("TestBrowser/1.0");
        assert!(
            ChallengePlugin::pending_matches_request(
                &pending,
                "203.0.113.10",
                "TestBrowser/1.0",
                &ok
            )
            .is_ok()
        );

        assert!(
            ChallengePlugin::pending_matches_request(
                &pending,
                "198.51.100.7",
                "TestBrowser/1.0",
                &ok
            )
            .is_err()
        );
        assert!(
            ChallengePlugin::pending_matches_request(
                &pending,
                "203.0.113.10",
                "OtherBrowser/1.0",
                &ok
            )
            .is_err()
        );
        assert!(
            ChallengePlugin::pending_matches_request(
                &pending,
                "203.0.113.10",
                "TestBrowser/1.0",
                &fingerprint_json("OtherBrowser/1.0")
            )
            .is_err()
        );
    }

    #[test]
    fn pending_challenge_rejects_oversized_original_urls() {
        let request_id =
            format!("pending-url-{}", uuid::Uuid::new_v4().simple());
        let long_url =
            format!("/{}", "a".repeat(PENDING_CHALLENGE_MAX_URL_BYTES + 16));
        store_pending(
            &request_id,
            "site-test",
            &long_url,
            "203.0.113.10",
            "test-agent",
            20,
        );
        let pending = peek_pending(&request_id).expect("pending entry");
        assert_eq!("/", pending.original_url);
        assert!(pending.bytes > 0);
        if let Some((_, removed)) = PENDING_CHALLENGES.remove(&request_id) {
            account_pending_removed(&removed);
        }
    }

    /// The footer brand on every shared page links to the official site, and
    /// the new tab cannot reach back through `window.opener`.
    #[test]
    fn brand_pages_link_to_the_official_site() {
        let pages: Vec<(&str, String)> = vec![
            (
                "block",
                String::from_utf8_lossy(&block_page("r", "x").body).to_string(),
            ),
            (
                "paused",
                String::from_utf8_lossy(&paused_page("r").body).to_string(),
            ),
            (
                "rate-limit",
                String::from_utf8_lossy(&rate_limit_page("r", "x", 30).body)
                    .to_string(),
            ),
            (
                "basic-auth",
                String::from_utf8_lossy(&basic_auth_page("r", "x", "y").body)
                    .to_string(),
            ),
            (
                "fail-closed",
                String::from_utf8_lossy(&fail_closed_page("r").body)
                    .to_string(),
            ),
        ];
        for (label, body) in pages {
            assert!(
                body.contains(r#"href="https://waf.red""#),
                "{label}: {body}"
            );
            assert!(body.contains(r#"rel="noopener""#), "{label}: {body}");
            assert!(body.contains("Protected by"), "{label}: {body}");
        }
    }

    #[test]
    fn block_page_is_branded_and_stamped() {
        let resp = block_page("req-abc", "SQLi rule matched");
        assert_eq!(StatusCode::FORBIDDEN, resp.status);
        let body = String::from_utf8_lossy(&resp.body).to_string();
        // The page must make clear *who* blocked the request, and carry the
        // identifiers a site owner needs to look the event up.
        assert!(body.contains("Request Blocked"), "body: {body}");
        assert!(body.contains("WAFred Security"), "body: {body}");
        assert!(body.contains("req-abc"), "body: {body}");
        assert!(body.contains("SQLi rule matched"), "body: {body}");
        assert_eq!(Some("wafred"), header_value(&resp, "server").as_deref());
        assert_eq!(
            Some("block"),
            header_value(&resp, "x-pingwaf-mitigated").as_deref()
        );
    }

    #[test]
    fn block_page_escapes_reason_html() {
        let resp = block_page("req-1", r#"<script>alert("x")</script>"#);
        let body = String::from_utf8_lossy(&resp.body).to_string();
        assert!(!body.contains("<script>"), "body: {body}");
        assert!(body.contains("&lt;script&gt;"), "body: {body}");
    }

    #[test]
    fn challenge_response_carries_mitigation_headers() {
        let resp = build_challenge_response(
            "req-ch",
            "/original",
            "site-1",
            "203.0.113.10",
            "test-agent",
            0,
            ChallengeKind::Js,
        );
        assert_eq!(StatusCode::SERVICE_UNAVAILABLE, resp.status);
        assert_eq!(Some("wafred"), header_value(&resp, "server").as_deref());
        assert_eq!(
            Some("challenge"),
            header_value(&resp, "x-pingwaf-mitigated").as_deref()
        );
    }

    #[test]
    fn status_pages_are_branded_edge_responses() {
        let paused = paused_page("req-p");
        assert_eq!(StatusCode::SERVICE_UNAVAILABLE, paused.status);
        let body = String::from_utf8_lossy(&paused.body).to_string();
        assert!(body.contains("Temporarily Paused"), "body: {body}");
        assert_eq!(Some("wafred"), header_value(&paused, "server").as_deref());
        // A paused site is a site-owner action, not a security mitigation:
        // no mitigated header, or dashboards would read it as a block.
        assert_eq!(None, header_value(&paused, "x-pingwaf-mitigated"));

        let rate = rate_limit_page("req-r", "over threshold", 30);
        assert_eq!(StatusCode::TOO_MANY_REQUESTS, rate.status);
        let body = String::from_utf8_lossy(&rate.body).to_string();
        assert!(body.contains("Rate Limit Exceeded"), "body: {body}");
        assert_eq!(
            Some("block"),
            header_value(&rate, "x-pingwaf-mitigated").as_deref()
        );

        let auth = basic_auth_page("req-a", "restricted", "login required");
        assert_eq!(StatusCode::UNAUTHORIZED, auth.status);
        assert_eq!(Some("wafred"), header_value(&auth, "server").as_deref());

        let closed = fail_closed_page("req-f");
        assert_eq!(StatusCode::SERVICE_UNAVAILABLE, closed.status);
        assert_eq!(Some("wafred"), header_value(&closed, "server").as_deref());
    }

    #[test]
    fn brand_page_does_not_emit_nested_style_tags() {
        // Regression: `PW_STYLE` is itself a complete `<style>...</style>`
        // partial — wrapping it in another `<style>` produced
        // `<style><style>...</style></style>`, which fails strict HTML
        // validation even though browsers tolerate it.
        for (label, body) in [
            (
                "paused",
                String::from_utf8_lossy(&paused_page("req-p").body).to_string(),
            ),
            (
                "rate-limit",
                String::from_utf8_lossy(
                    &rate_limit_page("req-r", "over threshold", 30).body,
                )
                .to_string(),
            ),
            (
                "auth",
                String::from_utf8_lossy(
                    &basic_auth_page("req-a", "restricted", "login required")
                        .body,
                )
                .to_string(),
            ),
            (
                "fail-closed",
                String::from_utf8_lossy(&fail_closed_page("req-f").body)
                    .to_string(),
            ),
        ] {
            assert_eq!(
                1,
                body.matches("<style>").count(),
                "{label}: expected exactly one <style> tag, body head: {}",
                &body[..body.len().min(400)]
            );
            assert_eq!(
                1,
                body.matches("</style>").count(),
                "{label}: expected exactly one </style> tag"
            );
        }
    }

    #[test]
    fn safe_redirect_target_keeps_same_origin_paths_only() {
        assert_eq!(safe_redirect_target("/admin?id=1"), "/admin?id=1");
        assert_eq!(safe_redirect_target("/"), "/");
        // Protocol-relative and absolute URLs are open-redirect material.
        assert_eq!(safe_redirect_target("//evil.com"), "/");
        assert_eq!(safe_redirect_target("https://evil.com/x"), "/");
        // Backslash tricks browsers into treating this as scheme-relative.
        assert_eq!(safe_redirect_target("/\\evil.com"), "/");
    }

    #[test]
    fn fallback_cookie_secret_is_random_and_stable_per_process() {
        let first = FALLBACK_COOKIE_SECRET.clone();
        assert!(!first.is_empty());
        assert_ne!(first, "change-me");
        assert_eq!(first.len(), 32);
        assert_eq!(FALLBACK_COOKIE_SECRET.clone(), first);
    }

    #[test]
    fn test_challenge_params() {
        let plugin = ChallengePlugin::new(
            &toml::from_str::<PluginConf>(
                r###"
enabled = true
under_attack_mode = true
clearance_duration_secs = 600
rate_threshold = 50
pow_difficulty = 0
cookie_secret = "test-secret"
cookie_name = "__test_clearance"
exempt_paths = ["/health"]
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(plugin.enabled);
        assert_eq!("__test_clearance", plugin.cookie_name);
        assert_eq!(0, plugin.standalone_limits.adaptive.base());
        assert_eq!(
            DEFAULT_ISSUE_LIMIT_PER_MIN,
            plugin.standalone_limits.issue_limit
        );
        assert_eq!(
            DEFAULT_VERIFY_LIMIT_PER_MIN,
            plugin.standalone_limits.verify_limit
        );
        assert_eq!(PluginStep::EarlyRequest, plugin.plugin_step);
    }

    #[tokio::test]
    async fn test_under_attack_challenges() {
        // Standalone behaviour requires the agent paths to stay off, and a
        // sibling test may otherwise hold an installed agent.
        let _agent_lock = lock_agent().await;
        WafredAgent::set_agent_instance(None);
        let plugin = ChallengePlugin::new(
            &toml::from_str::<PluginConf>(
                r###"
under_attack_mode = true
pow_difficulty = 0
cookie_secret = "test-secret"
"###,
            )
            .unwrap(),
        )
        .unwrap();

        let input_header =
            "GET /dashboard HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = plugin
            .handle_request(
                PluginStep::EarlyRequest,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        let RequestPluginResult::Respond(resp) = result else {
            panic!("expected a challenge response");
        };
        assert_eq!(StatusCode::SERVICE_UNAVAILABLE, resp.status);
    }

    #[tokio::test]
    async fn test_exempt_path_passes() {
        let _agent_lock = lock_agent().await;
        WafredAgent::set_agent_instance(None);
        let plugin = ChallengePlugin::new(
            &toml::from_str::<PluginConf>(
                r###"
under_attack_mode = true
exempt_paths = ["/health"]
cookie_secret = "test-secret"
"###,
            )
            .unwrap(),
        )
        .unwrap();

        let input_header = "GET /health HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = plugin
            .handle_request(
                PluginStep::EarlyRequest,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert!(result == RequestPluginResult::Continue);
    }

    /// ACME http-01 validation requests pass even in under-attack mode and
    /// without any `exempt_paths` entry: challenging the CA would make the
    /// certificate unissuable.
    #[tokio::test]
    async fn test_acme_challenge_path_is_exempt() {
        let _agent_lock = lock_agent().await;
        WafredAgent::set_agent_instance(None);
        let plugin = ChallengePlugin::new(
            &toml::from_str::<PluginConf>(
                r###"
under_attack_mode = true
pow_difficulty = 0
cookie_secret = "test-secret"
"###,
            )
            .unwrap(),
        )
        .unwrap();

        let input_header = "GET /.well-known/acme-challenge/x-token HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = plugin
            .handle_request(
                PluginStep::EarlyRequest,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert!(result == RequestPluginResult::Continue);
    }

    // ── Control-plane mode (WafredAgent installed) ──────────────

    use pingap_core::PluginStep as TestPluginStep;
    use pingora::proxy::Session as TestSession;

    use crate::waf::tests::lock_agent;
    use pingwaf_agent::cache::RuleCache;
    use pingwaf_agent::client::ControlPlaneClient;
    use pingwaf_agent::config::AgentConfig;
    use pingwaf_agent::heartbeat::MetricsCollector;
    use pingwaf_proto::control_plane as proto;

    /// Installs an agent whose site carries the given challenge config, plus
    /// a second site with none, to exercise per-site resolution.
    pub(crate) async fn install_challenge_agent(
        challenge: Option<proto::ChallengeConfig>,
    ) -> (
        tokio::sync::MutexGuard<'static, ()>,
        Arc<WafredAgent>,
        tempfile::TempDir,
    ) {
        install_challenge_agent_with_exceptions(challenge, Vec::new()).await
    }

    async fn install_challenge_agent_with_exceptions(
        challenge: Option<proto::ChallengeConfig>,
        path_exceptions: Vec<proto::PathException>,
    ) -> (
        tokio::sync::MutexGuard<'static, ()>,
        Arc<WafredAgent>,
        tempfile::TempDir,
    ) {
        let lock = lock_agent().await;
        let dir = tempfile::tempdir().unwrap();
        let config = AgentConfig {
            cache_dir: dir.path().to_string_lossy().to_string(),
            ..Default::default()
        };
        let rule_cache =
            RuleCache::new(dir.path().to_path_buf(), "test-agent".to_string())
                .unwrap();
        let metrics = Arc::new(MetricsCollector::new());
        let client = Arc::new(ControlPlaneClient::new(
            config.clone(),
            Arc::clone(&rule_cache),
            Arc::clone(&metrics),
        ));
        let agent_id = config.resolved_agent_id();
        let agent = Arc::new(WafredAgent {
            config,
            agent_id,
            client,
            rule_cache,
            metrics,
        });
        WafredAgent::set_agent_instance(Some(Arc::clone(&agent)));

        agent
            .rule_cache
            .update_from_site_config(&proto::SiteConfig {
                sites: vec![
                    proto::Site {
                        host_bindings: vec![],
                        id: "site-1".to_string(),
                        name: "example".to_string(),
                        domain: "example.com".to_string(),
                        alternate_domains: Vec::new(),
                        status: 0,
                        rules: Some(proto::RuleBundle {
                            site_id: "site-1".to_string(),
                            config_hash: "hash-1".to_string(),
                            challenge: challenge.clone(),
                            path_exceptions,
                            ..Default::default()
                        }),
                        trust_proxy_headers: false,
                        trusted_header: String::new(),
                        trust_last_hop: false,
                        trusted_proxy_ranges: Vec::new(),
                        downstream_timeout_secs: 60,
                    },
                    proto::Site {
                        host_bindings: vec![],
                        id: "site-2".to_string(),
                        name: "bare".to_string(),
                        domain: "bare.example.com".to_string(),
                        alternate_domains: Vec::new(),
                        status: 0,
                        rules: Some(proto::RuleBundle {
                            site_id: "site-2".to_string(),
                            config_hash: "hash-1".to_string(),
                            ..Default::default()
                        }),
                        trust_proxy_headers: false,
                        trusted_header: String::new(),
                        trust_last_hop: false,
                        trusted_proxy_ranges: Vec::new(),
                        downstream_timeout_secs: 60,
                    },
                ],
                config_hash: "hash-1".to_string(),
                updated_at: None,
            })
            .unwrap();
        (lock, agent, dir)
    }

    async fn run_challenge_request(
        plugin: &ChallengePlugin,
        host: &str,
        path: &str,
    ) -> RequestPluginResult {
        run_challenge_request_with_cookie(plugin, host, path, "").await
    }

    async fn run_challenge_request_with_cookie(
        plugin: &ChallengePlugin,
        host: &str,
        path: &str,
        cookie: &str,
    ) -> RequestPluginResult {
        run_challenge_request_with_headers(plugin, host, path, cookie, "").await
    }

    /// Requests a page as `client_ip`, so the process-wide guards see a client
    /// no other test uses. (A mock session has no peer address, so the
    /// forwarded header is what resolves.)
    async fn run_challenge_request_as(
        plugin: &ChallengePlugin,
        host: &str,
        path: &str,
        client_ip: &str,
    ) -> RequestPluginResult {
        run_challenge_request_with_headers(plugin, host, path, "", client_ip)
            .await
    }

    async fn run_challenge_request_with_headers(
        plugin: &ChallengePlugin,
        host: &str,
        path: &str,
        cookie: &str,
        client_ip: &str,
    ) -> RequestPluginResult {
        let forwarded = if client_ip.is_empty() {
            String::new()
        } else {
            format!("X-Forwarded-For: {client_ip}\r\n")
        };
        let input_header = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nCookie: {cookie}\r\n{forwarded}\r\n"
        );
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = TestSession::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        plugin
            .handle_request(
                TestPluginStep::EarlyRequest,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap()
    }

    /// A path exception that skips the rate/challenge layer must suppress
    /// this plugin's own gate even when the WAF registered no pending entry
    /// (the standalone/old-agent case). `rate_limit` is included because
    /// this plugin shares its CC rate window with that layer.
    #[tokio::test]
    async fn test_path_exception_skips_the_challenge_gate() {
        let (_guard, _agent, _dir) = install_challenge_agent_with_exceptions(
            Some(proto::ChallengeConfig {
                enabled: true,
                under_attack_mode: true,
                default_level: proto::ChallengeLevel::ChallengeNonInteractive
                    as i32,
                clearance_duration_seconds: 1800,
                exempt_paths: Vec::new(),
                request_threshold: 0,
                browser_integrity_check: true,
                tls_fingerprint_check: false,
                base_difficulty: 20,
                max_difficulty: 24,
                issue_limit_per_minute: 120,
                verify_limit_per_minute: 300,
            }),
            vec![proto::PathException {
                id: "rate-api".to_string(),
                path: "/api".to_string(),
                match_type: proto::PathMatchType::PathMatchPrefix as i32,
                skip_layers: vec!["rate_limit".to_string()],
                enabled: true,
                log_hits: false,
                note: String::new(),
            }],
        )
        .await;
        let plugin = ChallengePlugin::new(
            &toml::from_str::<PluginConf>(
                r###"cookie_secret = "test-secret""###,
            )
            .unwrap(),
        )
        .unwrap();

        assert!(
            run_challenge_request(&plugin, "example.com", "/api/x").await
                == RequestPluginResult::Continue,
            "the exception must suppress this plugin's gate"
        );
        assert!(matches!(
            run_challenge_request(&plugin, "example.com", "/other").await,
            RequestPluginResult::Respond(_)
        ));
    }

    /// Under attack mode is enforced per site: the configured site gets the
    /// JS challenge, exempt paths pass, and a site without challenge config
    /// is never challenged.
    #[tokio::test]
    async fn test_agent_under_attack_mode_applies_per_site() {
        let (_guard, _agent, _dir) =
            install_challenge_agent(Some(proto::ChallengeConfig {
                enabled: true,
                under_attack_mode: true,
                default_level: proto::ChallengeLevel::ChallengeNonInteractive
                    as i32,
                clearance_duration_seconds: 1800,
                exempt_paths: vec!["/health".to_string()],
                request_threshold: 0,
                browser_integrity_check: true,
                tls_fingerprint_check: false,
                base_difficulty: 20,
                max_difficulty: 24,
                issue_limit_per_minute: 120,
                verify_limit_per_minute: 300,
            }))
            .await;
        let plugin = ChallengePlugin::new(
            &toml::from_str::<PluginConf>(
                r###"cookie_secret = "test-secret""###,
            )
            .unwrap(),
        )
        .unwrap();

        let RequestPluginResult::Respond(resp) =
            run_challenge_request(&plugin, "example.com", "/dashboard").await
        else {
            panic!("expected under-attack mode to challenge");
        };
        assert_eq!(StatusCode::SERVICE_UNAVAILABLE, resp.status);

        assert!(
            run_challenge_request(&plugin, "example.com", "/health").await
                == RequestPluginResult::Continue
        );
        assert!(
            run_challenge_request(&plugin, "bare.example.com", "/dashboard")
                .await
                == RequestPluginResult::Continue
        );
    }

    /// A clearance solved on one site must not exempt another. Per-site
    /// engines share the signing secret, so a valid signature only proves
    /// that some site in this deployment issued the cookie; the site id
    /// inside it says which one, and the plugin has to compare that with the
    /// host it is serving. Without the comparison one solved challenge
    /// exempted every site — the cookie is portable because it is signed by a
    /// secret all of them share.
    #[tokio::test]
    async fn test_clearance_is_bound_to_the_site_that_issued_it() {
        let (_guard, _agent, _dir) =
            install_challenge_agent(Some(proto::ChallengeConfig {
                enabled: true,
                under_attack_mode: true,
                default_level: proto::ChallengeLevel::ChallengeNonInteractive
                    as i32,
                clearance_duration_seconds: 1800,
                exempt_paths: Vec::new(),
                request_threshold: 0,
                browser_integrity_check: false,
                tls_fingerprint_check: false,
                base_difficulty: 20,
                max_difficulty: 24,
                issue_limit_per_minute: 120,
                verify_limit_per_minute: 300,
            }))
            .await;
        let plugin = ChallengePlugin::new(
            &toml::from_str::<PluginConf>(
                r###"cookie_secret = "test-secret""###,
            )
            .unwrap(),
        )
        .unwrap();
        // Same secret the plugin signs with, so both cookies below verify.
        let manager =
            pingwaf_challenge::CookieManager::new(b"test-secret", 1800);

        let mine = manager.issue_clearance(
            ClearanceLevel::NonInteractive,
            "example.com",
            "fingerprint",
        );
        assert!(
            run_challenge_request_with_cookie(
                &plugin,
                "example.com",
                "/dashboard",
                &format!("{}={mine}", plugin.cookie_name),
            )
            .await
                == RequestPluginResult::Continue
        );

        let foreign = manager.issue_clearance(
            ClearanceLevel::NonInteractive,
            "bare.example.com",
            "fingerprint",
        );
        let RequestPluginResult::Respond(resp) =
            run_challenge_request_with_cookie(
                &plugin,
                "example.com",
                "/dashboard",
                &format!("{}={foreign}", plugin.cookie_name),
            )
            .await
        else {
            panic!(
                "a clearance issued for another site must not exempt this one"
            );
        };
        assert_eq!(StatusCode::SERVICE_UNAVAILABLE, resp.status);
    }

    /// A site without challenge config is never challenged, and the verify
    /// endpoint stays reachable for challenges issued by other rules.
    #[tokio::test]
    async fn test_agent_verify_endpoint_is_served() {
        let (_guard, _agent, _dir) = install_challenge_agent(None).await;
        let plugin = ChallengePlugin::new(
            &toml::from_str::<PluginConf>(
                r###"cookie_secret = "test-secret""###,
            )
            .unwrap(),
        )
        .unwrap();

        // Requests pass everywhere: no site has challenge config.
        assert!(
            run_challenge_request(&plugin, "example.com", "/").await
                == RequestPluginResult::Continue
        );

        // The verify endpoint answers (403 for a malformed body) instead of
        // falling through to the upstream.
        let input_header = "POST /_pingwaf/challenge/verify HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nbody";
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = TestSession::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = plugin
            .handle_request(
                TestPluginStep::EarlyRequest,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        let RequestPluginResult::Respond(resp) = result else {
            panic!("expected the verify endpoint to answer");
        };
        assert_eq!(StatusCode::FORBIDDEN, resp.status);
    }
    /// A cache snapshot (or an older control plane) that predates the new
    /// settings deserialises them as 0; the guards must fall back to the
    /// documented defaults instead of issuing difficulty-0 challenges, so an
    /// existing site keeps behaving exactly as before.
    #[test]
    fn a_site_without_the_new_settings_keeps_difficulty_20() {
        let cfg: CacheChallengeConfig =
            serde_json::from_value(serde_json::json!({
                "enabled": true,
                "under_attack_mode": false,
                "default_level": "non_interactive",
                "clearance_duration_seconds": 1800,
                "exempt_paths": [],
                "request_threshold": 100,
                "browser_integrity_check": true,
                "tls_fingerprint_check": false,
            }))
            .expect("a snapshot written before the settings existed");
        let limits = site_limits(&cfg);
        assert_eq!(20, limits.adaptive.base());
        assert_eq!(24, limits.adaptive.max());
        assert_eq!(DEFAULT_ISSUE_LIMIT_PER_MIN, limits.issue_limit);
        assert_eq!(DEFAULT_VERIFY_LIMIT_PER_MIN, limits.verify_limit);
        // A quiet visitor is issued the historical difficulty.
        assert_eq!(
            20,
            limits
                .adaptive
                .difficulty(DifficultyState::default(), 0, 0, 100)
        );
    }

    /// Runs one solution submission against the verify endpoint.
    async fn run_verify_submission_as(
        plugin: &ChallengePlugin,
        host: &str,
        client_ip: &str,
        payload: &serde_json::Value,
    ) -> RequestPluginResult {
        let body = payload.to_string();
        let forwarded = if client_ip.is_empty() {
            String::new()
        } else {
            format!("X-Forwarded-For: {client_ip}\r\n")
        };
        let input_header = format!(
            "POST {VERIFY_ENDPOINT} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n{forwarded}Content-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = TestSession::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        plugin
            .handle_request(
                TestPluginStep::EarlyRequest,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap()
    }

    /// Reads a `field: value` entry out of the challenge page's JS config.
    fn page_config(body: &str, field: &str) -> String {
        let marker = format!("{field}: ");
        let start = body
            .find(&marker)
            .unwrap_or_else(|| panic!("{field} missing from page"))
            + marker.len();
        let rest = &body[start..];
        let end = rest.find(",\n").unwrap_or(rest.len());
        rest[..end].trim().trim_matches('"').to_string()
    }

    /// The submission the page would send for `request_id`/`nonce` at
    /// `difficulty`, with an empty User-Agent matching the mock request.
    fn verify_payload(
        request_id: &str,
        solution: &str,
        timestamp: i64,
    ) -> serde_json::Value {
        serde_json::json!({
            "request_id": request_id,
            "solution": solution,
            "fingerprint_json": serde_json::json!({
                "user_agent": "",
                "screen_width": 1920,
                "screen_height": 1080,
                "timezone_offset": 0,
                "language": "en",
                "platform": "MacIntel",
                "canvas_hash": "abc",
                "webgl_vendor": "",
                "webgl_renderer": "",
                "plugins_count": 0,
                "touch_support": false,
                "hardware_concurrency": 8,
                "device_memory": 8.0
            })
            .to_string(),
            "timestamp": timestamp,
        })
    }

    /// Brute-forces a solution that satisfies `difficulty` for `nonce`.
    fn solve(nonce: &str, difficulty: u32) -> String {
        (0u32..)
            .map(|candidate| candidate.to_string())
            .find(|candidate| {
                pingwaf_challenge::js_challenge::verify::verify_proof_of_work(
                    nonce, candidate, difficulty,
                )
            })
            .expect("a solution")
    }

    /// A solution that does *not* satisfy `difficulty` for `nonce`.
    fn unsolved(nonce: &str, difficulty: u32) -> String {
        (0u32..)
            .map(|candidate| candidate.to_string())
            .find(|candidate| {
                !pingwaf_challenge::js_challenge::verify::verify_proof_of_work(
                    nonce, candidate, difficulty,
                )
            })
            .expect("an unsolved candidate")
    }

    /// Requests one challenge page as `client_ip` and returns
    /// (status, body, request id). The address is explicit because the guards
    /// are process-wide: a test that asserts a budget must describe a client
    /// of its own.
    async fn challenge_page_as(
        plugin: &ChallengePlugin,
        host: &str,
        client_ip: &str,
    ) -> (StatusCode, String, String) {
        let RequestPluginResult::Respond(resp) =
            run_challenge_request_as(plugin, host, "/dashboard", client_ip)
                .await
        else {
            panic!("expected a challenge response");
        };
        let body = String::from_utf8_lossy(&resp.body).to_string();
        let request_id = page_config(&body, "requestId");
        (resp.status, body, request_id)
    }

    /// Clears the process-wide guard tables when the test ends, so a test that
    /// deliberately saturates them cannot leak into the next one. Every test
    /// that touches a budget holds the agent lock, so the tables are its own
    /// while it runs.
    struct GuardTablesReset;

    impl Drop for GuardTablesReset {
        fn drop(&mut self) {
            ISSUE_LIMITER.clear();
            VERIFY_LIMITER.clear();
            DIFFICULTY_PRESSURE.clear();
        }
    }

    pub(crate) fn site_challenge_config(
        issue_limit: u32,
        verify_limit: u32,
        base: u32,
        max: u32,
    ) -> proto::ChallengeConfig {
        proto::ChallengeConfig {
            enabled: true,
            under_attack_mode: true,
            default_level: proto::ChallengeLevel::ChallengeNonInteractive
                as i32,
            clearance_duration_seconds: 1800,
            exempt_paths: Vec::new(),
            request_threshold: 0,
            browser_integrity_check: false,
            tls_fingerprint_check: false,
            base_difficulty: base,
            max_difficulty: max,
            issue_limit_per_minute: issue_limit,
            verify_limit_per_minute: verify_limit,
        }
    }

    /// A client above the site's issuance limit gets an explicit 429 (a
    /// challenge it cannot complete would just loop), stamped as mitigated.
    #[tokio::test]
    async fn test_issuance_over_the_limit_returns_429() {
        let (_guard, _agent, _dir) =
            install_challenge_agent(Some(site_challenge_config(2, 300, 4, 4)))
                .await;
        let _reset = GuardTablesReset;
        let plugin = ChallengePlugin::new(
            &toml::from_str::<PluginConf>(
                r###"cookie_secret = "test-secret""###,
            )
            .unwrap(),
        )
        .unwrap();
        // The guards are process-wide, so this test uses a client address no
        // other test issues for.
        let client = "198.51.100.11";

        for _ in 0..2 {
            let (status, _, _) =
                challenge_page_as(&plugin, "example.com", client).await;
            assert_eq!(StatusCode::SERVICE_UNAVAILABLE, status);
        }
        let RequestPluginResult::Respond(resp) = run_challenge_request_as(
            &plugin,
            "example.com",
            "/dashboard",
            client,
        )
        .await
        else {
            panic!("over the issuance limit the plugin must answer");
        };
        assert_eq!(StatusCode::TOO_MANY_REQUESTS, resp.status);
        let body = String::from_utf8_lossy(&resp.body).to_string();
        assert!(body.contains("Rate Limit Exceeded"), "body: {body}");
        assert_eq!(
            Some("block"),
            header_value(&resp, "x-pingwaf-mitigated").as_deref()
        );
        assert_eq!(Some("wafred"), header_value(&resp, "server").as_deref());
    }

    /// Regression (R1): a full issuance table must not lock new visitors out.
    ///
    /// `Saturated` means "the table is full of *other* clients", not "this
    /// client is over budget" — only `Deny` may refuse a page. Treating
    /// saturation as a refusal turned an attacker's address space into a
    /// site-wide outage, because every visitor the table had no room for got
    /// a 429.
    #[tokio::test]
    async fn test_saturated_issuance_table_still_issues_a_challenge() {
        let (_guard, _agent, _dir) = install_challenge_agent(Some(
            site_challenge_config(300, 300, 4, 4),
        ))
        .await;
        let _reset = GuardTablesReset;
        let plugin = ChallengePlugin::new(
            &toml::from_str::<PluginConf>(
                r###"cookie_secret = "test-secret""###,
            )
            .unwrap(),
        )
        .unwrap();

        // Fill the shared budget exactly as a many-source flood would: one
        // key per address, none of them over its own limit.
        let now = now_secs();
        for index in 0..DEFAULT_MAX_TRACKED_KEYS {
            ISSUE_LIMITER.allow(&format!("filler.example:{index}"), 5, now);
        }
        assert_eq!(
            LimitDecision::Saturated,
            ISSUE_LIMITER.allow("new.example:203.0.113.99", 5, now),
            "the table must actually be saturated for this test to mean anything"
        );

        // A visitor the table has never seen still gets a challenge page, and
        // the page is solvable: the difficulty it states is the one recorded
        // with the pending entry, so verification accepts the same work.
        let (status, body, request_id) =
            challenge_page_as(&plugin, "example.com", "198.51.100.14").await;
        assert_eq!(StatusCode::SERVICE_UNAVAILABLE, status);
        assert_eq!("4", page_config(&body, "difficulty"));
        let pending = peek_pending(&request_id).expect("pending challenge");
        assert_eq!(4, pending.difficulty);
    }

    /// Over the verification limit an attempt fails closed *before* the
    /// pending lookup, so a flood of guesses cannot spend a legitimate
    /// visitor's nonce.
    #[tokio::test]
    async fn test_verify_over_the_limit_does_not_consume_the_nonce() {
        let (_guard, _agent, _dir) =
            install_challenge_agent(Some(site_challenge_config(300, 2, 4, 4)))
                .await;
        let _reset = GuardTablesReset;
        let plugin = ChallengePlugin::new(
            &toml::from_str::<PluginConf>(
                r###"cookie_secret = "test-secret""###,
            )
            .unwrap(),
        )
        .unwrap();
        let client = "198.51.100.12";

        let (_, _, request_id) =
            challenge_page_as(&plugin, "example.com", client).await;
        let pending = peek_pending(&request_id).expect("pending challenge");
        let timestamp = chrono::Utc::now().timestamp();
        let wrong = verify_payload(
            &request_id,
            &unsolved(&pending.nonce, 4),
            timestamp,
        );

        // Two wrong answers are allowed through to the verifier and rejected
        // there; the pending entry survives (a failed proof is retryable).
        for _ in 0..2 {
            let RequestPluginResult::Respond(resp) = run_verify_submission_as(
                &plugin,
                "example.com",
                client,
                &wrong,
            )
            .await
            else {
                panic!("a wrong solution must be rejected");
            };
            assert_eq!(StatusCode::FORBIDDEN, resp.status);
            assert!(peek_pending(&request_id).is_some());
        }

        // The third attempt is over the limit: a 429, and the nonce is still
        // there — the visitor can retry once the window rolls over.
        let RequestPluginResult::Respond(resp) = run_verify_submission_as(
            &plugin,
            "example.com",
            client,
            &verify_payload(
                &request_id,
                &solve(&pending.nonce, 4),
                chrono::Utc::now().timestamp(),
            ),
        )
        .await
        else {
            panic!("over the verify limit the plugin must answer");
        };
        assert_eq!(StatusCode::TOO_MANY_REQUESTS, resp.status);
        assert!(peek_pending(&request_id).is_some());
    }

    /// Regression (R4): the over-limit verification refusal answers the
    /// request itself, so the access-log response phase never runs. It must be
    /// written explicitly, like every other edge-generated response — an
    /// invisible 429 would make the limiter look like a silent outage.
    #[tokio::test]
    async fn verify_rate_limit_is_written_to_the_access_log() {
        let (_guard, agent, _dir) =
            install_challenge_agent(Some(site_challenge_config(300, 1, 4, 4)))
                .await;
        let _reset = GuardTablesReset;
        let plugin = ChallengePlugin::new(
            &toml::from_str::<PluginConf>(
                r###"cookie_secret = "test-secret""###,
            )
            .unwrap(),
        )
        .unwrap();
        let client = "198.51.100.15";
        let (_, _, request_id) =
            challenge_page_as(&plugin, "example.com", client).await;
        let pending = peek_pending(&request_id).expect("pending challenge");
        // The issuance page itself is logged; this test is about the refusal.
        while agent.client.pop_log().await.is_some() {}

        let wrong = verify_payload(
            &request_id,
            &unsolved(&pending.nonce, 4),
            chrono::Utc::now().timestamp(),
        );
        // The one allowed attempt reaches the verifier and is rejected there;
        // that answer is a plain 403, not a generated edge response.
        let RequestPluginResult::Respond(resp) =
            run_verify_submission_as(&plugin, "example.com", client, &wrong)
                .await
        else {
            panic!("a wrong solution must be rejected");
        };
        assert_eq!(StatusCode::FORBIDDEN, resp.status);
        assert!(agent.client.pop_log().await.is_none());

        // The next attempt is over the budget: a 429 that must be logged.
        let RequestPluginResult::Respond(resp) =
            run_verify_submission_as(&plugin, "example.com", client, &wrong)
                .await
        else {
            panic!("over the verify limit the plugin must answer");
        };
        assert_eq!(StatusCode::TOO_MANY_REQUESTS, resp.status);
        let entry = agent
            .client
            .pop_log()
            .await
            .expect("the verify 429 must reach the access log");
        assert_eq!(429, entry.response_status);
        assert_eq!(request_id, entry.request_id);
        assert_eq!(client, entry.client_ip);
        assert_eq!("example.com", entry.site_id);
    }

    /// Adaptive difficulty: repeated verification failures raise the work the
    /// next page states, up to the site's ceiling, and the same page's
    /// solution verifies — the value is per challenge, not a static setting.
    #[tokio::test]
    async fn test_adaptive_difficulty_raises_then_resets() {
        let (_guard, _agent, _dir) = install_challenge_agent(Some(
            site_challenge_config(300, 300, 4, 6),
        ))
        .await;
        let _reset = GuardTablesReset;
        let plugin = ChallengePlugin::new(
            &toml::from_str::<PluginConf>(
                r###"cookie_secret = "test-secret""###,
            )
            .unwrap(),
        )
        .unwrap();
        let client = "198.51.100.13";

        let (_, body, request_id) =
            challenge_page_as(&plugin, "example.com", client).await;
        assert_eq!("4", page_config(&body, "difficulty"));

        // Three failures are three steps, capped at the site's max.
        let pending = peek_pending(&request_id).expect("pending challenge");
        let wrong = verify_payload(
            &request_id,
            &unsolved(&pending.nonce, 4),
            chrono::Utc::now().timestamp(),
        );
        for _ in 0..3 {
            let RequestPluginResult::Respond(resp) = run_verify_submission_as(
                &plugin,
                "example.com",
                client,
                &wrong,
            )
            .await
            else {
                panic!("a wrong solution must be rejected");
            };
            assert_eq!(StatusCode::FORBIDDEN, resp.status);
        }

        let (_, raised_body, raised_id) =
            challenge_page_as(&plugin, "example.com", client).await;
        assert_eq!(
            "6",
            page_config(&raised_body, "difficulty"),
            "failures must raise the issued difficulty up to the ceiling"
        );

        // The page and the verifier agree on that difficulty: solving it
        // mints a clearance.
        let raised = peek_pending(&raised_id).expect("pending challenge");
        let RequestPluginResult::Respond(resp) = run_verify_submission_as(
            &plugin,
            "example.com",
            client,
            &verify_payload(
                &raised_id,
                &solve(&raised.nonce, 6),
                chrono::Utc::now().timestamp(),
            ),
        )
        .await
        else {
            panic!("the page's own solution must verify");
        };
        assert_eq!(StatusCode::OK, resp.status);
        assert!(
            header_value(&resp, "set-cookie")
                .unwrap_or_default()
                .contains(&plugin.cookie_name)
        );

        // A success resets the pressure: the next visitor state is the base.
        assert!(
            !DIFFICULTY_PRESSURE
                .contains_key(&guard_key("example.com", client)),
            "success must clear the pressure"
        );
        let (_, reset_body, _) =
            challenge_page_as(&plugin, "example.com", client).await;
        assert_eq!("4", page_config(&reset_body, "difficulty"));
    }

    fn challenge_template_fixture() -> String {
        r#"<!DOCTYPE html>
<html><head><title>{{ brand_name }}</title></head><body>
<div id="countdown"></div>
<h1 id="title"></h1>
<p id="subtitle"></p>
<div id="status"></div>
<div id="spinnerWrap"></div>
<div id="progressBar"><div id="progressFill"></div></div>
<p>{{ brand_name }} / {{ request_id }}</p>
{{ challenge_scripts | safe }}
</body></html>"#
            .to_string()
    }

    #[test]
    fn challenge_tera_is_compiled_once_per_template() {
        let template = challenge_template_fixture();
        let first = challenge_tera(&template).expect("compiled");
        let second = challenge_tera(&template).expect("cached");
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn challenge_template_injects_the_compiled_scripts() {
        let params = ChallengePageParams {
            brand_name: "Brand".to_string(),
            request_id: "ray-1".to_string(),
            ..Default::default()
        };
        let html =
            render_challenge_template(&challenge_template_fixture(), &params)
                .expect("valid template");
        assert!(html.contains("Brand"));
        assert!(html.contains("ray-1"));
        assert!(html.contains("<script"));
        assert!(html.contains("computeProofOfWork"));
    }

    #[test]
    fn challenge_template_without_safe_filter_falls_back() {
        let params = ChallengePageParams::default();
        let template = challenge_template_fixture().replace(
            "{{ challenge_scripts | safe }}",
            "{{ challenge_scripts }}",
        );
        assert!(render_challenge_template(&template, &params).is_none());
    }

    #[test]
    fn challenge_template_missing_dom_id_falls_back() {
        let params = ChallengePageParams::default();
        let template = challenge_template_fixture()
            .replace("id=\"status\"", "id=\"not-status\"");
        assert!(render_challenge_template(&template, &params).is_none());
    }

    #[test]
    fn challenge_template_with_script_tag_falls_back() {
        let params = ChallengePageParams::default();
        let template = challenge_template_fixture().replace(
            "{{ challenge_scripts | safe }}",
            "<script>alert(1)</script>{{ challenge_scripts | safe }}",
        );
        assert!(render_challenge_template(&template, &params).is_none());
    }
}
