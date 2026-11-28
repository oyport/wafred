//! Per-request allocation / latency baseline plus engine resident-memory
//! measurement for the WAFred detection engine, derived from PingWAF (`wafred-waf`).
//!
//! Run with the shipped profile:
//!
//! ```bash
//! cargo run --release -p wafred-waf --example resource_bench
//! ```
//!
//! What it measures, all single-threaded:
//!
//! * A counting global allocator (relaxed atomics) reports, per request type:
//!   allocation calls, requested bytes, the per-inspection peak net growth of
//!   the live-byte counter, and the retained (leaked) delta after the verdict
//!   is dropped.
//! * `Instant` around `WafEngine::inspect` gives p50/p95/p99. The request
//!   objects are built *before* the timed region and reused; `RequestData`
//!   clone cost is measured separately so the reuse is not hiding a cost.
//! * `wafred-profiler` is used to split each inspection into the normalize /
//!   signature (Stage 1) / expression (Stage 2) scopes the engine itself
//!   records, plus the residual the engine does not attribute.
//! * Engine resident memory: shared-base cost, per-site incremental cost for
//!   100 engines of one profile, and mixed-profile 1/10/100/500 engine sets,
//!   reported both as allocator live bytes and as `ps -o rss=` deltas.
//!
//! Caveats (repeated in the report): the counters count *requested* bytes, not
//! RSS — allocator size-class rounding, malloc metadata and mmap-backed pages
//! are not counted; the release profile is the shipped size profile
//! (`opt-level = "z"`, LTO, `panic = "abort"`), not `release-perf`; the
//! counting allocator itself adds two relaxed atomics to every allocation and
//! free, so latency here is slightly pessimistic versus a plain build.

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use wafred_profiler::ProfileSnapshot;
use wafred_waf::normalize::{normalize_request, ValueSource};
use wafred_waf::rules::managed::default_managed_rules;
use wafred_waf::rules::signatures::{
    ci_backtick_interleaved, ci_chr_chain, detect_deser_shape, detect_sqli,
    detect_xss, pt_remote_backslash_include, SignatureEngine,
};
use wafred_waf::{
    CompiledRule, RequestData, RuleAction, StackSet, WafEngine,
    WafEngineConfig, WafLevel,
};
use regex::Regex;

// ---------------------------------------------------------------------------
// Counting global allocator
// ---------------------------------------------------------------------------

struct CountingAllocator;

/// Number of `alloc` / `realloc` calls.
static ALLOC_CALLS: AtomicU64 = AtomicU64::new(0);
/// Requested bytes: `layout.size()` for `alloc`, `new_size` for `realloc`.
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
/// Live requested bytes.
static CURRENT: AtomicUsize = AtomicUsize::new(0);
/// High-water mark of `CURRENT` since the last explicit `PEAK.store`.
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
            ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
            let now = CURRENT.fetch_add(layout.size(), Ordering::Relaxed)
                + layout.size();
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        CURRENT.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) };
    }

    unsafe fn realloc(
        &self,
        ptr: *mut u8,
        old: Layout,
        new_size: usize,
    ) -> *mut u8 {
        let new_ptr = unsafe { System.realloc(ptr, old, new_size) };
        if !new_ptr.is_null() {
            ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
            ALLOC_BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
            if new_size > old.size() {
                let delta = new_size - old.size();
                let now = CURRENT.fetch_add(delta, Ordering::Relaxed) + delta;
                PEAK.fetch_max(now, Ordering::Relaxed);
            } else {
                CURRENT.fetch_sub(old.size() - new_size, Ordering::Relaxed);
            }
        }
        new_ptr
    }
}

#[global_allocator]
static ALLOC: CountingAllocator = CountingAllocator;

#[derive(Clone, Copy, Debug)]
struct Snap {
    calls: u64,
    bytes: u64,
}

fn snap() -> Snap {
    Snap {
        calls: ALLOC_CALLS.load(Ordering::Relaxed),
        bytes: ALLOC_BYTES.load(Ordering::Relaxed),
    }
}

/// Builds `value` and reports how many bytes it retained and how far the live
/// counter peaked above the pre-build baseline.
fn measure_component<T>(build: impl FnOnce() -> T) -> (usize, usize) {
    let before = CURRENT.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let value = build();
    let retained = CURRENT.load(Ordering::Relaxed).saturating_sub(before);
    let peak = PEAK.load(Ordering::Relaxed).saturating_sub(before);
    black_box(&value);
    drop(value);
    (retained, peak)
}

// ---------------------------------------------------------------------------
// Environment helpers
// ---------------------------------------------------------------------------

/// Resident set size of this process in KiB via `ps -o rss= -p <pid>`.
///
/// macOS has no `/proc`; shelling out to `ps` avoids adding a `libc`
/// dependency (the crate manifest must not change). Returns `None` when the
/// command fails so the report can say "not measured" instead of inventing a
/// number.
fn rss_kb() -> Option<u64> {
    let pid = std::process::id().to_string();
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", pid.as_str()])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout).trim().parse().ok()
}

/// Deterministic xorshift-ish generator; the benchmark must be reproducible
/// and must not pull a `rand` dependency into the example.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }

    fn nonce(&mut self) -> String {
        format!("{:x}", self.next_u64())
    }
}

// ---------------------------------------------------------------------------
// Request construction
// ---------------------------------------------------------------------------

const WARMUP: usize = 200;
const MEASURE: usize = 2_000;
const STAGE_RUNS: usize = 1_000;
const POOL: usize = WARMUP + MEASURE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    CleanGet,
    ManyHeaders,
    JsonPost,
    FormPost,
    SqliQuery,
    XssQuery,
    CmdBody,
}

impl Kind {
    const ALL: [Kind; 7] = [
        Kind::CleanGet,
        Kind::ManyHeaders,
        Kind::JsonPost,
        Kind::FormPost,
        Kind::SqliQuery,
        Kind::XssQuery,
        Kind::CmdBody,
    ];

    fn name(self) -> &'static str {
        match self {
            Kind::CleanGet => "clean_get",
            Kind::ManyHeaders => "many_headers",
            Kind::JsonPost => "json_post",
            Kind::FormPost => "form_post",
            Kind::SqliQuery => "sqli_query",
            Kind::XssQuery => "xss_query",
            Kind::CmdBody => "cmd_body",
        }
    }

    fn seed(self) -> u64 {
        match self {
            Kind::CleanGet => 0x1000,
            Kind::ManyHeaders => 0x2000,
            Kind::JsonPost => 0x3000,
            Kind::FormPost => 0x4000,
            Kind::SqliQuery => 0x5000,
            Kind::XssQuery => 0x6000,
            Kind::CmdBody => 0x7000,
        }
    }
}

fn base_headers() -> Vec<(String, String)> {
    vec![
        ("host".to_string(), "api.example.com".to_string()),
        (
            "user-agent".to_string(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
                .to_string(),
        ),
        (
            "accept".to_string(),
            "application/json, text/plain, */*".to_string(),
        ),
        (
            "accept-language".to_string(),
            "zh-CN,zh;q=0.9,en;q=0.8".to_string(),
        ),
        (
            "accept-encoding".to_string(),
            "gzip, deflate, br".to_string(),
        ),
        ("connection".to_string(), "keep-alive".to_string()),
        (
            "cookie".to_string(),
            "session=8f14e45fceea167a5a36dedd4bea2543; theme=dark".to_string(),
        ),
        (
            "referer".to_string(),
            "https://example.com/dashboard".to_string(),
        ),
    ]
}

/// Twelve extra headers, making the `many_headers` scenario 20 in total.
fn extra_headers() -> Vec<(String, String)> {
    let mut headers = Vec::with_capacity(12);
    for index in 0..12 {
        headers.push((
            format!("x-bench-{index}"),
            format!("value-{index}-0123456789abcdef"),
        ));
    }
    headers
}

/// ~4 KiB of clean JSON. The largest member stays below the normalizer's
/// 8 KiB per-value cap, so this exercises the JSON member unpacking without
/// triggering a truncation note.
fn json_body() -> String {
    let mut filler = String::with_capacity(4 * 1024);
    while filler.len() < 3_800 {
        filler.push_str(
            "lorem ipsum dolor sit amet consectetur adipiscing elit sed do \
             eiusmod tempor incididunt ut labore ",
        );
    }
    format!(
        "{{\"id\":42,\"name\":\"widget\",\"description\":\"{filler}\",\
         \"tags\":[\"alpha\",\"beta\",\"gamma\"],\"price\":19.99,\
         \"nested\":{{\"sku\":\"A-100\",\"stock\":7}}}}"
    )
}

/// ~10 KiB of clean `application/x-www-form-urlencoded` body split across
/// several members, so no single value hits the 8 KiB per-value cap.
fn form_body() -> String {
    let mut body = String::with_capacity(10 * 1024 + 256);
    body.push_str("id=42&page=2&sort=name&filter=active&token=abc123def456&");
    let fields = ["note", "comment", "summary", "extra"];
    for (index, field) in fields.iter().enumerate() {
        body.push_str(field);
        body.push('=');
        let mut chunk = String::with_capacity(2_500);
        while chunk.len() < 2_400 {
            chunk.push_str(
                "lorem ipsum dolor sit amet consectetur adipiscing elit ",
            );
        }
        body.push_str(&chunk);
        if index + 1 < fields.len() {
            body.push('&');
        }
    }
    body
}

/// Builds the request pool for one scenario *before* any timing starts.
///
/// Every entry gets a unique client IP; the malicious scenarios additionally
/// get a unique harmless suffix, so no cross-request cache or short-circuit in
/// the harness can make later iterations cheaper.
fn build_pool(kind: Kind) -> Vec<RequestData> {
    let mut rng = Rng::new(kind.seed());
    let json = json_body();
    let form = form_body();
    let mut pool = Vec::with_capacity(POOL);
    for index in 0..POOL {
        let mut request = RequestData::new("GET", "/api/v1/items");
        request.client_ip = format!("10.0.{}.{}", index / 256, index % 256);
        match kind {
            Kind::CleanGet => {
                request.query = "id=42&page=2".to_string();
                request.headers = base_headers();
            },
            Kind::ManyHeaders => {
                request.query = "id=42&page=2".to_string();
                let mut headers = base_headers();
                headers.extend(extra_headers());
                request.headers = headers;
            },
            Kind::JsonPost => {
                request.method = "POST".to_string();
                let mut headers = base_headers();
                headers.push((
                    "content-type".to_string(),
                    "application/json".to_string(),
                ));
                headers.push((
                    "content-length".to_string(),
                    json.len().to_string(),
                ));
                request.headers = headers;
                request.body =
                    Some(bytes::Bytes::from(json.clone().into_bytes()));
            },
            Kind::FormPost => {
                request.method = "POST".to_string();
                request.path = "/api/v1/submit".to_string();
                let mut headers = base_headers();
                headers.push((
                    "content-type".to_string(),
                    "application/x-www-form-urlencoded".to_string(),
                ));
                headers.push((
                    "content-length".to_string(),
                    form.len().to_string(),
                ));
                request.headers = headers;
                request.body =
                    Some(bytes::Bytes::from(form.clone().into_bytes()));
            },
            Kind::SqliQuery => {
                request.query =
                    format!("id=1%27+OR+%271%27%3D%271&r={}", rng.nonce());
                request.headers = base_headers();
            },
            Kind::XssQuery => {
                request.query = format!(
                    "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E&r={}",
                    rng.nonce()
                );
                request.headers = base_headers();
            },
            Kind::CmdBody => {
                request.method = "POST".to_string();
                request.path = "/api/v1/exec".to_string();
                let mut headers = base_headers();
                headers.push((
                    "content-type".to_string(),
                    "application/x-www-form-urlencoded".to_string(),
                ));
                request.headers = headers;
                let body = format!("cmd=; cat /etc/passwd&r={}", rng.nonce());
                request.body = Some(bytes::Bytes::from(body.into_bytes()));
            },
        }
        pool.push(request);
    }
    pool
}

// ---------------------------------------------------------------------------
// Measurements
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Default)]
struct Latency {
    mean_us: f64,
    p50_us: f64,
    p95_us: f64,
    p99_us: f64,
    max_us: f64,
}

fn percentile(sorted_ns: &[u64], p: f64) -> f64 {
    if sorted_ns.is_empty() {
        return 0.0;
    }
    let index = ((p * sorted_ns.len() as f64).ceil() as usize)
        .saturating_sub(1)
        .min(sorted_ns.len() - 1);
    sorted_ns[index] as f64 / 1_000.0
}

/// Times `inspect()` over the measurement slice. The verdict's `Drop` is
/// deliberately outside the timed region: this is the engine cost, not the
/// caller's cleanup.
fn measure_latency(engine: &WafEngine, requests: &[RequestData]) -> Latency {
    for request in &requests[..WARMUP] {
        let verdict = engine.inspect(request);
        black_box(&verdict);
    }
    let mut samples = Vec::with_capacity(MEASURE);
    for request in &requests[WARMUP..WARMUP + MEASURE] {
        let started = Instant::now();
        let verdict = engine.inspect(request);
        let elapsed = started.elapsed().as_nanos() as u64;
        black_box(&verdict);
        drop(verdict);
        samples.push(elapsed);
    }
    samples.sort_unstable();
    Latency {
        mean_us: samples.iter().sum::<u64>() as f64
            / samples.len() as f64
            / 1_000.0,
        p50_us: percentile(&samples, 0.50),
        p95_us: percentile(&samples, 0.95),
        p99_us: percentile(&samples, 0.99),
        max_us: *samples.last().unwrap_or(&0) as f64 / 1_000.0,
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct AllocCost {
    /// Allocator calls per inspection (`alloc` + `realloc`).
    calls: f64,
    /// Requested bytes per inspection.
    bytes: f64,
    /// Max over iterations of (peak live bytes during the call − live bytes
    /// before the call).
    peak_net: usize,
    /// Max over iterations of (live bytes after the verdict is dropped − live
    /// bytes before the call); a positive value is a real leak.
    leak_max: i64,
    leak_mean: f64,
}

/// Counts allocations for the measurement slice. Per iteration it resets the
/// peak gauge to the current live value, so the reported peak is per
/// inspection rather than a process-wide high-water mark.
fn measure_alloc(engine: &WafEngine, requests: &[RequestData]) -> AllocCost {
    let before = snap();
    let mut peak_net = 0usize;
    let mut leak_max = i64::MIN;
    let mut leak_sum = 0i64;
    for request in &requests[WARMUP..WARMUP + MEASURE] {
        let current_before = CURRENT.load(Ordering::Relaxed);
        PEAK.store(current_before, Ordering::Relaxed);
        let verdict = engine.inspect(request);
        let peak = PEAK.load(Ordering::Relaxed);
        black_box(&verdict);
        drop(verdict);
        let current_after = CURRENT.load(Ordering::Relaxed);
        peak_net = peak_net.max(peak.saturating_sub(current_before));
        let leak = current_after as i64 - current_before as i64;
        leak_max = leak_max.max(leak);
        leak_sum += leak;
    }
    let after = snap();
    AllocCost {
        calls: (after.calls - before.calls) as f64 / MEASURE as f64,
        bytes: (after.bytes - before.bytes) as f64 / MEASURE as f64,
        peak_net,
        leak_max: if leak_max == i64::MIN { 0 } else { leak_max },
        leak_mean: leak_sum as f64 / MEASURE as f64,
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct StageRow {
    calls: u64,
    avg_us: f64,
}

#[derive(Clone, Copy, Debug, Default)]
struct StageSplit {
    normalize: StageRow,
    signature: StageRow,
    expression: StageRow,
}

/// Runs the profiler-instrumented scopes over `STAGE_RUNS` inspections and
/// reads the rows the engine records itself (`waf::normalize`,
/// `waf::signature`, `waf::expression`). The tables are process-global, hence
/// the `reset` before each scenario.
fn measure_stages(engine: &WafEngine, requests: &[RequestData]) -> StageSplit {
    ProfileSnapshot::reset();
    for request in &requests[WARMUP..WARMUP + STAGE_RUNS] {
        let verdict = engine.inspect(request);
        black_box(&verdict);
    }
    let snapshot = ProfileSnapshot::collect();
    let mut split = StageSplit::default();
    for row in &snapshot.methods {
        let target = match row.method {
            "waf::normalize" => &mut split.normalize,
            "waf::signature" => &mut split.signature,
            "waf::expression" => &mut split.expression,
            _ => continue,
        };
        target.calls = row.calls;
        target.avg_us = row.avg_us;
    }
    split
}

/// Cost of cloning one `RequestData` (allocation + deallocation), reported so
/// the "requests are built outside the timed region" choice is explicit.
///
/// Returns `(min_us, alloc_calls, alloc_bytes)`; the timing is the minimum of
/// three 2,000-clone repetitions because a single run on macOS is noisy at the
/// sub-microsecond scale. Allocation counts are summed over one repetition.
fn measure_clone(request: &RequestData) -> (f64, f64, f64) {
    for _ in 0..200 {
        black_box(request.clone());
    }
    let mut best_us = f64::INFINITY;
    let mut calls = 0.0;
    let mut bytes = 0.0;
    for _ in 0..3 {
        let before = snap();
        let started = Instant::now();
        for _ in 0..2_000 {
            let cloned = request.clone();
            black_box(&cloned);
        }
        let elapsed = started.elapsed();
        let after = snap();
        best_us = best_us.min(elapsed.as_nanos() as f64 / 2_000.0 / 1_000.0);
        calls = (after.calls - before.calls) as f64 / 2_000.0;
        bytes = (after.bytes - before.bytes) as f64 / 2_000.0;
    }
    (best_us, calls, bytes)
}

/// Times `f` and returns microseconds per call.
fn time_calls(iterations: usize, mut f: impl FnMut()) -> f64 {
    for _ in 0..(iterations / 10).max(10) {
        f();
    }
    let started = Instant::now();
    for _ in 0..iterations {
        f();
    }
    started.elapsed().as_nanos() as f64 / iterations as f64 / 1_000.0
}

fn repeated(filler: &str, size: usize) -> String {
    let mut text = String::with_capacity(size + filler.len());
    while text.len() < size {
        text.push_str(filler);
    }
    text
}

/// How many decoded values one request produces — the multiplier in
/// "fixed per-value cost × N". `normalize_request` is public, so this reads
/// the same structure the Stage-1 loop iterates.
fn decoded_value_counts() {
    println!("\n== diagnostics: decoded value counts (per request) ==");
    println!(
        "{:<14} {:>7} {:>6} {:>8} {:>6} {:>6} {:>6} {:>6} {:>6}",
        "scenario",
        "values",
        "query",
        "headers",
        "cookie",
        "body",
        "path",
        "hdr",
        "trunc"
    );
    for kind in Kind::ALL {
        let requests = build_pool(kind);
        let request = &requests[0];
        let normalized = normalize_request(
            &request.method,
            &request.path,
            &request.query,
            &request.headers,
            request.body.as_deref(),
            WafEngineConfig::default().max_decode_layers,
            false,
        );
        let count = |source: ValueSource| {
            normalized
                .decoded_values
                .iter()
                .filter(|value| value.source == source)
                .count()
        };
        let trunc = normalized.truncation.is_empty();
        println!(
            "{:<14} {:>7} {:>6} {:>8} {:>6} {:>6} {:>6} {:>6} {:>6}",
            kind.name(),
            normalized.decoded_values.len(),
            count(ValueSource::QueryParam),
            normalized.headers.len(),
            normalized.cookies.len(),
            count(ValueSource::Body),
            count(ValueSource::Path),
            count(ValueSource::Header),
            if trunc { "no" } else { "yes" },
        );
    }
}

// ---------------------------------------------------------------------------
// Bench-only copies of the detector internals (the real ones are private in
// `rules::signatures`). Pattern strings and the fingerprint tokenizer are
// copied verbatim so the ranking reflects what the engine actually runs.
// ---------------------------------------------------------------------------

const SQL_KEYWORDS: &[&str] = &[
    "select",
    "union",
    "all",
    "distinct",
    "from",
    "where",
    "and",
    "or",
    "not",
    "in",
    "like",
    "between",
    "is",
    "null",
    "having",
    "group",
    "order",
    "by",
    "limit",
    "offset",
    "asc",
    "desc",
    "insert",
    "into",
    "values",
    "update",
    "set",
    "delete",
    "drop",
    "alter",
    "create",
    "truncate",
    "table",
    "database",
    "schema",
    "user",
    "version",
    "current_user",
    "session_user",
    "join",
    "inner",
    "left",
    "right",
    "outer",
    "on",
    "as",
    "case",
    "when",
    "then",
    "else",
    "end",
    "exists",
    "any",
    "some",
    "with",
    "recursive",
    "cast",
    "convert",
    "exec",
    "execute",
    "begin",
    "commit",
    "rollback",
    "savepoint",
    "grant",
    "revoke",
    "show",
    "describe",
    "true",
    "false",
];

const SQL_FUNCTIONS: &[&str] = &[
    "sleep",
    "benchmark",
    "waitfor",
    "delay",
    "pg_sleep",
    "load_file",
    "outfile",
    "dumpfile",
    "extractvalue",
    "updatexml",
    "concat",
    "concat_ws",
    "group_concat",
    "char",
    "ascii",
    "ord",
    "hex",
    "unhex",
    "substring",
    "substr",
    "mid",
    "left",
    "right",
    "length",
    "count",
    "sum",
    "avg",
    "min",
    "max",
    "rand",
    "floor",
    "ceil",
    "round",
    "if",
    "ifnull",
    "nullif",
    "coalesce",
    "version",
    "user",
    "database",
    "schema",
    "current_user",
    "session_user",
    "system_user",
    "row_number",
    "rank",
    "dense_rank",
    "xp_cmdshell",
    "sp_executesql",
    "make_set",
    "elt",
    "find_in_set",
    "regexp",
    "rlike",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum SqlTok {
    Keyword,
    Function,
    Operator,
    Ident,
}

impl SqlTok {
    fn fp_char(self) -> char {
        match self {
            SqlTok::Keyword => 'k',
            SqlTok::Function => 'f',
            SqlTok::Operator => 't',
            SqlTok::Ident => 'n',
        }
    }
}

/// Verbatim copy of `rules::signatures::fingerprint_sql` (private there).
fn fingerprint_sql_copy(lower: &str) -> String {
    let bytes = lower.as_bytes();
    let mut fp = String::with_capacity(bytes.len() / 2 + 4);
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b' ' | b'\t' | b'\n' | b'\r' => i += 1,
            b'\'' | b'"' | b'`' => {
                let quote = b;
                let mut j = i + 1;
                while j < bytes.len() {
                    if bytes[j] == b'\\' {
                        j += 2;
                        continue;
                    }
                    if bytes[j] == quote {
                        if j + 1 < bytes.len() && bytes[j + 1] == quote {
                            j += 2;
                            continue;
                        }
                        break;
                    }
                    j += 1;
                }
                fp.push(if quote == b'`' { 'n' } else { 's' });
                i = (j + 1).min(bytes.len());
            },
            b'-' if i + 1 < bytes.len() && bytes[i + 1] == b'-' => {
                fp.push('-');
                i = bytes.len();
            },
            b'#' => {
                fp.push('-');
                i = bytes.len();
            },
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                fp.push('-');
                let mut j = i + 2;
                while j + 1 < bytes.len()
                    && !(bytes[j] == b'*' && bytes[j + 1] == b'/')
                {
                    j += 1;
                }
                i = (j + 2).min(bytes.len());
            },
            b'(' => {
                fp.push('(');
                i += 1;
            },
            b')' => {
                fp.push(')');
                i += 1;
            },
            b',' => {
                fp.push(',');
                i += 1;
            },
            b';' => {
                fp.push(';');
                i += 1;
            },
            b'=' | b'<' | b'>' | b'!' => {
                fp.push('o');
                let mut j = i + 1;
                while j < bytes.len()
                    && matches!(bytes[j], b'=' | b'<' | b'>' | b'!')
                {
                    j += 1;
                }
                i = j;
            },
            b'+' | b'-' | b'*' | b'/' | b'%' => {
                fp.push('o');
                i += 1;
            },
            b'|' if i + 1 < bytes.len() && bytes[i + 1] == b'|' => {
                fp.push('t');
                i += 2;
            },
            b'&' if i + 1 < bytes.len() && bytes[i + 1] == b'&' => {
                fp.push('t');
                i += 2;
            },
            b'|' | b'&' | b'^' | b'~' => {
                fp.push('o');
                i += 1;
            },
            b'@' => {
                fp.push('v');
                i += 1;
                while i < bytes.len()
                    && (bytes[i].is_ascii_alphanumeric()
                        || bytes[i] == b'_'
                        || bytes[i] == b'@')
                {
                    i += 1;
                }
            },
            b':' if i + 1 < bytes.len()
                && bytes[i + 1].is_ascii_alphabetic() =>
            {
                fp.push('v');
                i += 1;
                while i < bytes.len()
                    && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_')
                {
                    i += 1;
                }
            },
            b if b.is_ascii_digit() => {
                while i < bytes.len()
                    && (bytes[i].is_ascii_digit()
                        || bytes[i] == b'.'
                        || bytes[i] == b'e'
                        || bytes[i] == b'E'
                        || bytes[i] == b'x'
                        || bytes[i] == b'X')
                {
                    i += 1;
                }
                fp.push('1');
            },
            b if b.is_ascii_alphabetic() || b == b'_' => {
                let start = i;
                while i < bytes.len()
                    && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_')
                {
                    i += 1;
                }
                let word = &lower[start..i];
                let tok = if SQL_FUNCTIONS.contains(&word) {
                    SqlTok::Function
                } else if matches!(word, "and" | "or" | "xor") {
                    SqlTok::Operator
                } else if SQL_KEYWORDS.contains(&word) {
                    SqlTok::Keyword
                } else {
                    SqlTok::Ident
                };
                fp.push(tok.fp_char());
            },
            _ => i += 1,
        }
    }
    fp
}

/// The 14 SQLi "strong" confirmation regexes, copied verbatim from
/// `rules::signatures` (names match the static names there).
fn sqli_strong_regexes() -> Vec<(&'static str, Regex)> {
    [
        ("SQLI_UNION_SELECT", r"(?i)\bunion\b[\s/*!]+(?:\ball\b[\s/*!]+)?\bselect\b"),
        ("SQLI_UNION_COMMENT_SPLIT", r"(?i)\bunion(?:#|--)[\s\S]{0,64}?\bselect(?:[^a-z]|$)"),
        ("SQLI_STACKED", r"(?i);\s*(?:select|insert|update|delete|drop|alter|create|truncate|exec|execute|grant|revoke|declare|begin|shutdown)\b"),
        ("SQLI_DANGEROUS_FN", r"(?i)\b(?:sleep|benchmark|pg_sleep|waitfor|load_file|extractvalue|updatexml|xp_cmdshell|sp_executesql)\s*\("),
        ("SQLI_WAITFOR", r"(?i)\bwaitfor\b"),
        ("SQLI_TAUTOLOGY", r#"(?i)(?:\bor\b|\band\b|\|\||&&)\s*(?:['"`][\w.\- ]{0,32}['"`]\s*=\s*['"`][\w.\- ]{0,32}['"`]?|['"`]?\d+['"`]?\s*=\s*['"`]?\d+['"`]?|\b1\s*<>\s*0\b|\b1\s*>\s*0\b)"#),
        ("SQLI_TRUNCATED_TAUTOLOGY", r#"(?i)(?:\bor\b|\band\b|\|\|)\s*['"`]{1,2}\s*=\s*['"`]{0,2}\s*(?:--|#)?\s*$"#),
        ("SQLI_QUOTE_KEYWORD", r#"(?i)['"][\s);]{0,4}\b(?:union|select|insert|update|delete|drop|alter|create|truncate|exec|execute)\b"#),
        ("SQLI_BARE_SELECT", r#"(?i)\bselect\s+(?:\*|\w+\s*,\s*[\w.\'"()]+\s*(?:,\s*[\w.\'"()]+)*)\s+from\s+[\w."']"#),
        ("SQLI_FULL_QUERY_CLAUSE", r"(?i)\b(?:where|group\s+by|order\s+by|having|limit|offset|join)\b"),
        ("SQLI_BLIND_PROBE", r#"(?i)\bselect\s+case\s+when\b|(?:\bselect\b|\b(?:and|or)\b|\|\||;|['"`(])\s*case\s+when\b[\s\S]{0,80}\bthen\b|\bto_char\s*\(\s*[\w'"]+\s*/\s*[\w'"]+\s*\)"#),
        ("SQLI_BOOL_SUBQUERY", r#"(?i)\b(?:and|or)\b\s*(?:\(\s*select\b|\d+\s*=\s*(?:\(\s*)?(?:cast\s*\(\s*\(?\s*)?select\b)|\b\d+\s*=\s*\(\s*select\b"#),
        ("SQLI_INFO_SCHEMA", r"(?i)information_schema|\bsqlite_master\b|\bpg_catalog\b|\bsysobjects\b|\bsyscolumns\b"),
        ("SQLI_INTO_FILE", r"(?i)\binto\s+(?:out|dump)file\b"),
    ]
    .into_iter()
    .map(|(name, pattern)| (name, Regex::new(pattern).expect("sqli regex")))
    .collect()
}

fn sqli_weak_regex() -> Regex {
    Regex::new(r"(?:--\s|--$|#\s|#$|/\*[\s\S]*?\*/)").expect("comment-term")
}

/// The 8 XSS confirmation regexes, copied verbatim from `rules::signatures`.
fn xss_regexes() -> Vec<(&'static str, Regex)> {
    [
        ("XSS_SCRIPT_TAG", r"(?i)<\s*/?\s*script\b"),
        ("XSS_EVENT_HANDLER", r"(?i)(?:\s|\+)on[a-z]+\s*="),
        ("XSS_JS_URI", r"(?i)\b(?:javascript|vbscript|livescript|mocha)\s*:"),
        ("XSS_DANGEROUS_TAG", r"(?i)<\s*(?:iframe|object|embed|svg|math|form|input|body|frame|frameset|applet|meta|link|base|style|marquee|details|audio|video|template|portal)\b"),
        ("XSS_DATA_URI", r"(?i)data\s*:\s*(?:text/html|application/xhtml|text/javascript|application/javascript)"),
        ("XSS_STYLE_EXPR", r#"(?i)expression\s*\(|url\s*\(\s*['"]?\s*javascript"#),
        ("XSS_HTML_COMMENT_BREAK", r"(?i)<\s*/\s*(?:style|title|textarea|noscript|comment)\b"),
        ("XSS_DOM_CHAIN", r#"(?i)constructor\s*(?:\.\s*prototype|\.\s*constructor|\[\s*['"]constructor|\[\s*['"]prototype)"#),
    ]
    .into_iter()
    .map(|(name, pattern)| (name, Regex::new(pattern).expect("xss regex")))
    .collect()
}

/// Per-regex `is_match` cost, descending, for the four inputs the lead asked
/// for. This is the "which regex is pathological" table: a long-alternation
/// `(?i)` pattern with lazy-DFA cache thrash shows up as one row dominating
/// its detector's total.
fn regex_ranking() {
    println!("\n== diagnostics: per-regex cost, descending (ns/call, 10,000 iters) ==");
    println!(
        "note: only meaningful in a build where regex feature \"perf\" is on"
    );
    let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
              AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 \
              Safari/537.36";
    let prose = "lorem ipsum dolor sit amet consectetur adipiscing elit sed \
                 do eiusmod tempor incididunt ut labore";
    let mut zh = String::from(
        "这是一段两百字节左右的商品描述，包含 and 与 or 以及 on 等英文子串，\
         用于验证 UTF-8 长文本下各检测器的固定成本。",
    );
    while zh.len() < 203 {
        zh.push_str("描述");
    }
    let prose_8k = repeated(prose, 8 * 1024);
    let neutral_8k = repeated("xyzqjvbnm", 8 * 1024);
    let sqli = sqli_strong_regexes();
    let xss = xss_regexes();
    let weak = sqli_weak_regex();
    for (label, input) in [
        ("prose_8k", prose_8k.as_str()),
        ("neutral_8k", neutral_8k.as_str()),
        ("ua", ua),
        ("zh_200", zh.as_str()),
    ] {
        println!("\n-- {label} ({} bytes) --", input.len());
        println!("{:<26} {:>12} {:>9}", "regex", "ns/call", "share");
        let mut rows: Vec<(&'static str, f64, &'static str)> = Vec::new();
        let mut sqli_sum = 0.0f64;
        let mut xss_sum = 0.0f64;
        for (name, re) in &sqli {
            let ns = time_calls(10_000, || {
                black_box(re.is_match(black_box(input)));
            }) * 1_000.0;
            sqli_sum += ns;
            rows.push((name, ns, "sqli"));
        }
        for (name, re) in &xss {
            let ns = time_calls(10_000, || {
                black_box(re.is_match(black_box(input)));
            }) * 1_000.0;
            xss_sum += ns;
            rows.push((name, ns, "xss"));
        }
        let weak_ns = time_calls(10_000, || {
            black_box(weak.is_match(black_box(input)));
        }) * 1_000.0;
        rows.sort_by(|a, b| {
            b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal)
        });
        let total = sqli_sum + xss_sum + weak_ns;
        for (name, ns, family) in &rows {
            println!(
                "{:<26} {:>12.1} {:>8.1}%  [{family}]",
                name,
                ns,
                ns / total * 100.0
            );
        }
        println!(
            "  sum: sqli14={sqli_sum:.1} ns  xss8={xss_sum:.1} ns  \
             weak_comment_term={weak_ns:.1} ns  total={total:.1} ns"
        );
        let (is_sqli, _) = detect_sqli(input);
        let (is_xss, _) = detect_xss(input);
        println!(
            "  reference: detect_sqli={} ({:.1} ns incl. lowercase+fingerprint+prefilter), \
             detect_xss={} ({:.1} ns)",
            is_sqli,
            time_calls(2_000, || {
                black_box(detect_sqli(black_box(input)));
            }) * 1_000.0,
            is_xss,
            time_calls(2_000, || {
                black_box(detect_xss(black_box(input)));
            }) * 1_000.0,
        );
    }
}

/// Decompose the SQLi confirmation path on prose_8k and the UA header:
/// lowercase copy + `fingerprint_sql` + 14 strong regexes + weak comment-term.
fn sqli_path_decomposition() {
    println!(
        "\n== diagnostics: SQLi confirmation path decomposition (ns/call) =="
    );
    println!(
        "note: only meaningful in a build where regex feature \"perf\" is on"
    );
    let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
              AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 \
              Safari/537.36";
    let prose = "lorem ipsum dolor sit amet consectetur adipiscing elit sed \
                 do eiusmod tempor incididunt ut labore";
    let prose_8k = repeated(prose, 8 * 1024);
    let sqli = sqli_strong_regexes();
    let weak = sqli_weak_regex();
    println!(
        "{:<12} {:>10} {:>12} {:>14} {:>14} {:>12} {:>14}",
        "input",
        "bytes",
        "lowercase",
        "fingerprint",
        "regex14_sum",
        "weak_regex",
        "detect_sqli"
    );
    for (label, input) in [("ua", ua), ("prose_8k", prose_8k.as_str())] {
        let lowercase_ns = time_calls(10_000, || {
            black_box(black_box(input).to_ascii_lowercase());
        }) * 1_000.0;
        let lower = input.to_ascii_lowercase();
        let fingerprint_ns = time_calls(10_000, || {
            black_box(fingerprint_sql_copy(black_box(&lower)));
        }) * 1_000.0;
        let regex_sum: f64 = sqli
            .iter()
            .map(|(_, re)| {
                time_calls(10_000, || {
                    black_box(re.is_match(black_box(&lower)));
                }) * 1_000.0
            })
            .sum();
        let weak_ns = time_calls(10_000, || {
            black_box(weak.is_match(black_box(&lower)));
        }) * 1_000.0;
        let total = time_calls(2_000, || {
            black_box(detect_sqli(black_box(input)));
        }) * 1_000.0;
        println!(
            "{:<12} {:>10} {:>12.1} {:>14.1} {:>14.1} {:>12.1} {:>14.1}",
            label,
            input.len(),
            lowercase_ns,
            fingerprint_ns,
            regex_sum,
            weak_ns,
            total
        );
        println!(
            "  accounted={:.1} ns, residual (prefilter + weak checks + \
             fingerprint branches)={:.1} ns",
            lowercase_ns + fingerprint_ns + regex_sum + weak_ns,
            total - (lowercase_ns + fingerprint_ns + regex_sum + weak_ns)
        );
    }
}

/// Micro-cost of the individual detector functions the Stage-1 loop calls for
/// every decoded value. All values are ns/call; `black_box` prevents the
/// optimiser from folding a detector whose result is unused.
///
/// The two libinjection prefilters are private statics inside
/// `rules::signatures`, so their cost is measured as the floor of
/// `detect_sqli` / `detect_xss` on a neutral value (prefilter miss = automaton
/// scan only, then return).
fn detector_micro_cost() {
    println!("\n== diagnostics: detector micro-cost (ns/call) ==");
    let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
              AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 \
              Safari/537.36";
    let order_status = "order_status";
    let timestamp = "2026-11-15T12:00:00Z";
    let sqli = "1' OR '1'='1";
    let xss = "<script>alert(1)</script>";
    let neutral = "xyzqjvbnm";
    let prose = "lorem ipsum dolor sit amet consectetur adipiscing elit sed \
                 do eiusmod tempor incididunt ut labore";
    let mut zh = String::from(
        "这是一段两百字节左右的商品描述，包含 and 与 or 以及 on 等英文子串，\
         用于验证 UTF-8 长文本下各检测器的固定成本。",
    );
    while zh.len() < 200 {
        zh.push_str("描述");
    }
    let prose_8k = repeated(prose, 8 * 1024);
    let neutral_8k = repeated(neutral, 8 * 1024);
    let signature =
        SignatureEngine::for_profile(WafLevel::Normal, StackSet::ALL);
    let mut hits = Vec::new();
    let mut seen = Vec::new();
    println!(
        "{:<12} {:>6} {:>9} {:>9} {:>9} {:>10} {:>10} {:>10} {:>10}",
        "input",
        "bytes",
        "sqli",
        "xss",
        "deser",
        "backtick",
        "chr_chain",
        "remote_bs",
        "ac_scan"
    );
    let cases: [(&str, &str); 9] = [
        ("ua", ua),
        ("order_status", order_status),
        ("timestamp", timestamp),
        ("zh_200", zh.as_str()),
        ("sqli", sqli),
        ("xss", xss),
        ("neutral_short", neutral),
        ("neutral_8k", neutral_8k.as_str()),
        ("prose_8k", prose_8k.as_str()),
    ];
    for (label, input) in cases {
        // Large inputs are dominated by the regex battery; keep the runtime
        // bounded while still averaging enough samples.
        let iterations = if input.len() <= 512 {
            10_000
        } else if input.len() <= 2_048 {
            2_000
        } else {
            200
        };
        let sqli_ns = time_calls(iterations, || {
            black_box(detect_sqli(black_box(input)));
        }) * 1_000.0;
        let xss_ns = time_calls(iterations, || {
            black_box(detect_xss(black_box(input)));
        }) * 1_000.0;
        let deser_ns = time_calls(iterations, || {
            black_box(detect_deser_shape(black_box(input)));
        }) * 1_000.0;
        let backtick_ns = time_calls(iterations, || {
            black_box(ci_backtick_interleaved(black_box(input)));
        }) * 1_000.0;
        let chr_ns = time_calls(iterations, || {
            black_box(ci_chr_chain(black_box(input)));
        }) * 1_000.0;
        let remote_ns = time_calls(iterations, || {
            black_box(pt_remote_backslash_include(black_box(input)));
        }) * 1_000.0;
        let ac_ns = time_calls(iterations, || {
            signature.scan_into(black_box(input), &mut hits, &mut seen);
        }) * 1_000.0;
        println!(
            "{:<12} {:>6} {:>9.1} {:>9.1} {:>9.1} {:>10.1} {:>10.1} \
             {:>10.1} {:>10.1}",
            label,
            input.len(),
            sqli_ns,
            xss_ns,
            deser_ns,
            backtick_ns,
            chr_ns,
            remote_ns,
            ac_ns
        );
    }
}

/// Why the "fast path" is the rare path: the libinjection prefilters are plain
/// substring automata, so ordinary words contain their needles — `into` inside
/// `Macintosh`, `or` inside `order`/`dolor`, `on` inside `consectetur`. Removing
/// just the needle substring from an otherwise identical value collapses the
/// cost from the full regex battery to the automaton-miss floor.
fn needle_gate_evidence() {
    println!("\n== diagnostics: prefilter needle evidence (ns/call) ==");
    let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
              AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 \
              Safari/537.36";
    let ua_no_into = "Mozilla/5.0 (Macint0sh; Intel Mac OS X 10_15_7) \
                      AppleWebKit/537.36 (KHTML, like Gecko) \
                      Chrome/120.0.0.0 Safari/537.36";
    let prose = "lorem ipsum dolor sit amet consectetur adipiscing elit";
    let prose_no_needles = "lqrem ipsum dqlqr sit amet cqnsectetur adipiscing";
    let zh = "这是一段两百字节左右的商品描述，包含 and 与 or 以及 on 等英文子串，用于验证 UTF-8 长文本下各检测器的固定成本。";
    println!(
        "{:<18} {:>7} {:>12} {:>12} {:>18}",
        "value", "bytes", "sqli_ns", "xss_ns", "note"
    );
    for (label, input, note) in [
        ("ua", ua, "contains \"into\" in Macintosh"),
        ("ua_no_into", ua_no_into, "needle removed"),
        ("order_status", "order_status", "contains \"or\""),
        ("status", "status", "needle removed"),
        ("prose", prose, "contains or/on"),
        ("prose_no_needles", prose_no_needles, "needles removed"),
        ("zh_200", zh, "contains and/or/on"),
    ] {
        let sqli = time_calls(10_000, || {
            black_box(detect_sqli(black_box(input)));
        }) * 1_000.0;
        let xss = time_calls(10_000, || {
            black_box(detect_xss(black_box(input)));
        }) * 1_000.0;
        println!(
            "{:<18} {:>7} {:>12.1} {:>12.1} {:>18}",
            label,
            input.len(),
            sqli,
            xss,
            note
        );
    }
}

/// `inspect()` cost as a function of clean body size and body content. A
/// natural-language body hits the SQLi/XSS prefilters (`or` inside `dolor`,
/// `on` inside `consectetur`); a neutral filler does not. Comparing the two
/// isolates "scan every byte" from "run the whole regex suite".
fn body_scaling(engine: &WafEngine) {
    println!("\n== diagnostics: inspect cost vs body size (text/plain) ==");
    let prose = "lorem ipsum dolor sit amet consectetur adipiscing elit sed \
                 do eiusmod tempor incididunt ut labore";
    let neutral = "xyzqjvbnm";
    println!(
        "{:<10} {:>8} {:>10} {:>12} {:>10} {:>10} {:>10} {:>7}",
        "filler",
        "bytes",
        "mean_us",
        "us_per_byte",
        "p50_us",
        "p95_us",
        "alloc_calls",
        "trunc"
    );
    for (label, filler, sizes) in [
        (
            "prose",
            prose,
            [1_024usize, 4_096, 8_192, 16_384].as_slice(),
        ),
        ("neutral", neutral, [1_024usize, 4_096, 8_192].as_slice()),
    ] {
        for &size in sizes {
            let body = repeated(filler, size);
            let mut request = RequestData::new("POST", "/api/v1/submit");
            request.headers =
                vec![("content-type".to_string(), "text/plain".to_string())];
            request.body = Some(bytes::Bytes::from(body.into_bytes()));
            let truncated = engine.inspect(&request).details.contains("trunc");
            let before = snap();
            let mut samples = Vec::with_capacity(100);
            for _ in 0..20 {
                let verdict = engine.inspect(&request);
                black_box(&verdict);
            }
            for _ in 0..100 {
                let started = Instant::now();
                let verdict = engine.inspect(&request);
                let elapsed = started.elapsed().as_nanos() as u64;
                black_box(&verdict);
                drop(verdict);
                samples.push(elapsed);
            }
            let after = snap();
            samples.sort_unstable();
            let mean_us = samples.iter().sum::<u64>() as f64
                / samples.len() as f64
                / 1_000.0;
            println!(
                "{:<10} {:>8} {:>10.3} {:>12.4} {:>10.3} {:>10.3} {:>10.2} \
                 {:>7}",
                label,
                request.body.as_ref().map_or(0, |body| body.len()),
                mean_us,
                mean_us
                    / request.body.as_ref().map_or(1, |body| body.len()) as f64,
                percentile(&samples, 0.50),
                percentile(&samples, 0.95),
                (after.calls - before.calls) as f64 / 100.0,
                if truncated { "yes" } else { "no" },
            );
        }
    }
}

/// Marginal cost of one more decoded value: clean headers added one group at a
/// time, same path/query.
fn header_scaling(engine: &WafEngine) {
    println!("\n== diagnostics: inspect cost vs header count ==");
    println!(
        "{:<10} {:>10} {:>10} {:>10}",
        "headers", "mean_us", "p50_us", "p95_us"
    );
    for count in [0usize, 1, 4, 8, 20] {
        let mut request = RequestData::new("GET", "/api/v1/items");
        request.query = "id=42&page=2".to_string();
        request.headers =
            base_headers().into_iter().take(count.min(8)).collect();
        while request.headers.len() < count {
            let index = request.headers.len();
            request.headers.push((
                format!("x-bench-{index}"),
                "value-0123456789abcdef".to_string(),
            ));
        }
        for _ in 0..50 {
            let verdict = engine.inspect(&request);
            black_box(&verdict);
        }
        let mut samples = Vec::with_capacity(500);
        for _ in 0..500 {
            let started = Instant::now();
            let verdict = engine.inspect(&request);
            let elapsed = started.elapsed().as_nanos() as u64;
            black_box(&verdict);
            drop(verdict);
            samples.push(elapsed);
        }
        samples.sort_unstable();
        let mean_us =
            samples.iter().sum::<u64>() as f64 / samples.len() as f64 / 1_000.0;
        println!(
            "{:<10} {:>10.3} {:>10.3} {:>10.3}",
            count,
            mean_us,
            percentile(&samples, 0.50),
            percentile(&samples, 0.95),
        );
    }
}

/// Builds `configs.len()` engines, keeps them alive through the measurement,
/// then drops them. RSS is sampled outside the allocator counter window so
/// the `ps` subprocess does not pollute the byte counts.
fn measure_engines(configs: &[WafEngineConfig]) -> (usize, usize, Option<i64>) {
    let rss_before = rss_kb();
    let before = CURRENT.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let engines: Vec<WafEngine> = configs.iter().map(WafEngine::new).collect();
    let retained = CURRENT.load(Ordering::Relaxed).saturating_sub(before);
    let peak = PEAK.load(Ordering::Relaxed).saturating_sub(before);
    let rss_after = rss_kb();
    black_box(&engines);
    drop(engines);
    let rss_delta = match (rss_before, rss_after) {
        (Some(a), Some(b)) => Some(b as i64 - a as i64),
        _ => None,
    };
    (retained, peak, rss_delta)
}

// ---------------------------------------------------------------------------
// Engine-config matrix
// ---------------------------------------------------------------------------

/// The four detection profiles the multi-site matrix cycles through.
fn mixed_profile(index: usize) -> (WafLevel, StackSet) {
    match index % 4 {
        0 => (WafLevel::Normal, StackSet::ALL),
        1 => (WafLevel::Normal, StackSet::GENERIC),
        2 => (WafLevel::Strict, StackSet::ALL),
        _ => (WafLevel::Normal, StackSet::GENERIC.union(StackSet::JAVA)),
    }
}

fn custom_rules(site: usize) -> Vec<CompiledRule> {
    let specs = [
        (
            "path",
            r#"http.request.uri.path starts_with "/admin""#,
            RuleAction::Block,
        ),
        (
            "method",
            r#"http.request.method eq "DELETE""#,
            RuleAction::Block,
        ),
        (
            "ua",
            r#"http.request.headers["user-agent"] contains "curl""#,
            RuleAction::Block,
        ),
        ("ip", r#"ip.src in {10.0.0.0/8}"#, RuleAction::Log),
        (
            "debug",
            r#"http.request.uri.query contains "debug=1""#,
            RuleAction::Log,
        ),
    ];
    specs
        .iter()
        .map(|(suffix, expression, action)| {
            CompiledRule::compile(
                format!("BENCH-{site:03}-{suffix}"),
                format!("benchmark rule {suffix} for site {site}"),
                expression,
                *action,
                3,
                vec!["bench".to_string()],
            )
            .expect("benchmark expression must compile")
        })
        .collect()
}

fn mixed_configs(sites: usize) -> Vec<WafEngineConfig> {
    (0..sites)
        .map(|index| {
            let (level, stacks) = mixed_profile(index);
            let rules = if index % 3 == 0 {
                custom_rules(index)
            } else {
                Vec::new()
            };
            WafEngineConfig {
                level,
                stacks,
                rules,
                // Measure the whole scan, not the first 20 ms of it: this
                // benchmark exists to price Stage-1 detection.
                inspection_deadline: std::time::Duration::ZERO,
                ..WafEngineConfig::default()
            }
        })
        .collect()
}

fn profile_config(level: WafLevel, stacks: StackSet) -> WafEngineConfig {
    WafEngineConfig {
        level,
        stacks,
        inspection_deadline: std::time::Duration::ZERO,
        ..WafEngineConfig::default()
    }
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

fn print_environment() {
    println!("== wafred-waf resource_bench ==");
    println!(
        "profile: release (opt-level=\"z\", lto=true, codegen-units=1, \
         panic=\"abort\"), debug_assertions={}",
        cfg!(debug_assertions)
    );
    println!("rustc: {}", rustc_version_hint());
    println!("engine_size={} bytes", std::mem::size_of::<WafEngine>());
    println!("warmup={WARMUP} measure={MEASURE} stage_runs={STAGE_RUNS}");
    println!("process_rss_start_kb={:?}", rss_kb());
    println!(
        "allocator_current_start={}",
        CURRENT.load(Ordering::Relaxed)
    );
}

/// `rustc_version` is not a dependency; report what `rustc -V` says instead of
/// hard-coding a version that could drift from the toolchain in use.
fn rustc_version_hint() -> String {
    std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown (rustc not on PATH)".to_string())
}

fn print_default_config(config: &WafEngineConfig) {
    println!(
        "default_config: mode={:?} level={:?} stacks={:#09b} threshold={} \
         paranoia_level={} max_decode_layers={} enable_managed_rules={} \
         fast_path_block_on_critical={} inspection_deadline={:?} \
         monitor_categories={:#011b} monitor_stacks={:#09b}",
        config.mode,
        config.level,
        config.stacks.bits(),
        config.threshold,
        config.paranoia_level,
        config.max_decode_layers,
        config.enable_managed_rules,
        config.fast_path_block_on_critical,
        config.inspection_deadline,
        config.monitor_categories.bits(),
        config.monitor_stacks.bits(),
    );
}

fn probe_verdict(engine: &WafEngine, request: &RequestData) -> String {
    let verdict = engine.inspect(request);
    let matched: Vec<String> =
        verdict.matched_rules.iter().take(3).cloned().collect();
    let details: String = verdict.details.chars().take(120).collect();
    format!(
        "action={:?} score={} matched={} first_matched={:?} enforced={:?} \
         details={:?}",
        verdict.action,
        verdict.score,
        verdict.matched_rules.len(),
        matched,
        verdict.enforced_rule_id,
        details,
    )
}

fn print_latency(latency: &Latency) {
    println!(
        "latency_us: mean={:.3} p50={:.3} p95={:.3} p99={:.3} max={:.3}",
        latency.mean_us,
        latency.p50_us,
        latency.p95_us,
        latency.p99_us,
        latency.max_us,
    );
}

fn print_alloc(cost: &AllocCost) {
    println!(
        "alloc_per_inspect: calls={:.2} bytes={:.0} peak_net_bytes={} \
         leak_max_bytes={} leak_mean_bytes={:.3}",
        cost.calls, cost.bytes, cost.peak_net, cost.leak_max, cost.leak_mean,
    );
}

fn print_stages(split: &StageSplit, latency: &Latency) {
    let expr_effective = split.expression.avg_us
        * (split.expression.calls as f64 / STAGE_RUNS as f64);
    let residual = latency.mean_us
        - split.normalize.avg_us
        - split.signature.avg_us
        - expr_effective;
    println!(
        "stage_us: normalize={:.3} (calls={}, {:.1}% of mean) | \
         signature={:.3} (calls={}, {:.1}%) | expression={:.3} \
         (calls={}, effective {:.3}, {:.1}%) | residual={:.3} ({:.1}%)",
        split.normalize.avg_us,
        split.normalize.calls,
        share(split.normalize.avg_us, latency.mean_us),
        split.signature.avg_us,
        split.signature.calls,
        share(split.signature.avg_us, latency.mean_us),
        split.expression.avg_us,
        split.expression.calls,
        expr_effective,
        share(expr_effective, latency.mean_us),
        residual,
        share(residual, latency.mean_us),
    );
}

fn share(part: f64, total: f64) -> f64 {
    if total <= 0.0 {
        0.0
    } else {
        part / total * 100.0
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
    print_environment();
    let default_config = WafEngineConfig::default();
    print_default_config(&default_config);

    // `--diag-only` runs just the micro-benchmarks (seconds instead of
    // minutes): useful for re-checking detector cost without the per-request
    // sweeps.
    if std::env::args().any(|arg| arg == "--diag-only") {
        decoded_value_counts();
        detector_micro_cost();
        needle_gate_evidence();
        regex_ranking();
        sqli_path_decomposition();
        return;
    }

    // ---- one-time engine material -----------------------------------------
    println!("\n== engine material ==");
    let (sig_retained, sig_peak) = measure_component(|| {
        SignatureEngine::for_profile(WafLevel::Normal, StackSet::ALL)
    });
    println!("signature_retained={sig_retained} signature_peak={sig_peak}");
    let (managed_retained, managed_peak) =
        measure_component(|| default_managed_rules(WafLevel::Normal));
    println!("managed_retained={managed_retained} managed_peak={managed_peak}");

    // First engine of each profile: pays that profile's shared base. The very
    // first (Normal/ALL) also pays the managed-rule cache for `Normal`; the
    // first `Strict` engine pays the `Strict` cache. Later engines of the same
    // profile reuse both.
    let (cold_normal_all, cold_normal_all_peak) =
        measure_component(|| WafEngine::new(&default_config));
    println!(
        "cold_engine_normal_all_retained={cold_normal_all} \
         cold_engine_normal_all_peak={cold_normal_all_peak} \
         (includes Normal managed-rule cache)"
    );
    for (label, level, stacks) in [
        ("normal_generic", WafLevel::Normal, StackSet::GENERIC),
        ("strict_all", WafLevel::Strict, StackSet::ALL),
        (
            "normal_generic_java",
            WafLevel::Normal,
            StackSet::GENERIC.union(StackSet::JAVA),
        ),
    ] {
        let config = profile_config(level, stacks);
        let (retained, peak) = measure_component(|| WafEngine::new(&config));
        println!(
            "cold_engine_{label}_retained={retained} \
             cold_engine_{label}_peak={peak}"
        );
    }

    let engine = WafEngine::new(&default_config);
    println!("default_engine_debug={:?}", engine);
    println!("default_engine_rule_count={}", engine.rule_count());

    // ---- per-request scenarios -------------------------------------------
    println!("\n== per-request scenarios ==");
    let mut summary: Vec<(Kind, Latency, AllocCost, StageSplit)> = Vec::new();
    for kind in Kind::ALL {
        let requests = build_pool(kind);
        println!("\n--- {} ---", kind.name());
        println!("verdict: {}", probe_verdict(&engine, &requests[0]));
        let latency = measure_latency(&engine, &requests);
        print_latency(&latency);
        let alloc = measure_alloc(&engine, &requests);
        print_alloc(&alloc);
        let stages = measure_stages(&engine, &requests);
        print_stages(&stages, &latency);
        if matches!(kind, Kind::CleanGet | Kind::JsonPost) {
            let (us, calls, bytes) = measure_clone(&requests[0]);
            println!(
                "request_clone_us={us:.3} clone_alloc_calls={calls:.2} \
                 clone_alloc_bytes={bytes:.0} (per RequestData clone+drop)"
            );
        }
        summary.push((kind, latency, alloc, stages));
    }

    // ---- compact tables ---------------------------------------------------
    println!("\n== summary: allocation ==");
    println!(
        "{:<14} {:>10} {:>12} {:>14} {:>14} {:>12}",
        "scenario",
        "calls/req",
        "bytes/req",
        "peak_net_bytes",
        "leak_max_bytes",
        "leak_mean"
    );
    for (kind, _, alloc, _) in &summary {
        println!(
            "{:<14} {:>10.2} {:>12.0} {:>14} {:>14} {:>12.3}",
            kind.name(),
            alloc.calls,
            alloc.bytes,
            alloc.peak_net,
            alloc.leak_max,
            alloc.leak_mean
        );
    }
    println!("\n== summary: latency (us) ==");
    println!(
        "{:<14} {:>10} {:>10} {:>10} {:>10} {:>10}",
        "scenario", "mean", "p50", "p95", "p99", "max"
    );
    for (kind, latency, _, _) in &summary {
        println!(
            "{:<14} {:>10.3} {:>10.3} {:>10.3} {:>10.3} {:>10.3}",
            kind.name(),
            latency.mean_us,
            latency.p50_us,
            latency.p95_us,
            latency.p99_us,
            latency.max_us
        );
    }
    println!("\n== summary: stage split (us, % of scenario mean) ==");
    println!(
        "{:<14} {:>12} {:>12} {:>12} {:>12}",
        "scenario", "normalize", "signature", "expression", "residual"
    );
    for (kind, latency, _, stages) in &summary {
        let expr_effective = stages.expression.avg_us
            * (stages.expression.calls as f64 / STAGE_RUNS as f64);
        let residual = latency.mean_us
            - stages.normalize.avg_us
            - stages.signature.avg_us
            - expr_effective;
        println!(
            "{:<14} {:>7.3} {:>4.1}% {:>7.3} {:>4.1}% {:>7.3} {:>4.1}% \
             {:>7.3} {:>4.1}%",
            kind.name(),
            stages.normalize.avg_us,
            share(stages.normalize.avg_us, latency.mean_us),
            stages.signature.avg_us,
            share(stages.signature.avg_us, latency.mean_us),
            expr_effective,
            share(expr_effective, latency.mean_us),
            residual,
            share(residual, latency.mean_us),
        );
    }

    // ---- diagnostics ------------------------------------------------------
    decoded_value_counts();
    detector_micro_cost();
    needle_gate_evidence();
    regex_ranking();
    sqli_path_decomposition();
    body_scaling(&engine);
    header_scaling(&engine);

    // ---- resident memory --------------------------------------------------
    println!("\n== resident memory ==");
    println!(
        "note: allocator counters report requested bytes, not RSS; RSS via \
         ps is page-granular and includes allocator metadata."
    );
    let per_site_configs = vec![default_config.clone(); 100];
    let (shared_retained, shared_peak, shared_rss) =
        measure_engines(&per_site_configs);
    println!(
        "shared_100_engines_normal_all: retained={shared_retained} \
         per_site={:.1} peak={shared_peak} rss_delta_kb={:?}",
        shared_retained as f64 / 100.0,
        shared_rss
    );

    println!(
        "\n{:<8} {:>14} {:>12} {:>14} {:>16}",
        "sites", "retained", "per_site", "peak", "rss_delta_kb"
    );
    for sites in [1usize, 10, 100, 500] {
        let configs = mixed_configs(sites);
        let (retained, peak, rss_delta) = measure_engines(&configs);
        println!(
            "{:<8} {:>14} {:>12.1} {:>14} {:>16}",
            sites,
            retained,
            retained as f64 / sites as f64,
            peak,
            match rss_delta {
                Some(delta) => delta.to_string(),
                None => "n/a".to_string(),
            }
        );
    }

    // ---- end state --------------------------------------------------------
    println!("\n== end state ==");
    println!("allocator_current_end={}", CURRENT.load(Ordering::Relaxed));
    println!("process_rss_end_kb={:?}", rss_kb());
}
