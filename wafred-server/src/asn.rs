//! ASN → organization-name resolution for the traffic analytics API.
//!
//! The GeoIP database the edge ships (`tor-geoip`) maps an address to an AS
//! *number* only, so the control plane resolves the human-readable name
//! itself. Two sources are merged once per process (a later entry wins):
//!
//! 1. The bundled snapshot `wafred-server/assets/asn_names.tsv`, compiled into
//!    the binary — the major CDN / hyperscaler / ISP / hosting networks.
//! 2. An optional operator file named by [`NAMES_FILE_ENV`], with the same
//!    two-column, tab-separated format (`<asn>\t<organization>`). Blank lines
//!    and `#` comments are accepted, an `AS` prefix is optional, and a
//!    malformed line is skipped with a warning that names the line.
//!
//! The mapping is loaded lazily on first use and then read-only, so a request
//! never performs a network call, a download or a file read: replacing the
//! operator file takes effect on the next restart, and there is no runtime
//! dependency on any registry. An operator who needs complete coverage exports
//! it once (PeeringDB, an iptoasn.com dump, RIR delegation files, …) and
//! points the environment variable at it.
//!
//! An unresolved number is never rendered as a bare `AS12345`: callers use
//! [`display_name`], which answers `Unknown (AS12345)` — the fallback is part
//! of the API contract documented in `docs/api.md`.
//!
//! ## Where the AS *number* comes from
//!
//! This module also owns the control-plane side of the number itself. The
//! edge resolves the ASN from the GeoIP data it ships, but that snapshot
//! carries country ranges only (`tor_geoip`'s embedded database has no ASN
//! table), so an agent normally reports `0` and the number has to be
//! recovered on the control plane. The supported source is a **MaxMind ASN
//! database** (GeoLite2-ASN, or GeoIP2-ISP / GeoIP2-Enterprise, which carry
//! the same `autonomous_system_number` field) read from a local file:
//!
//! * [`MMDB_ENV`] (`WAFRED_ASN_MMDB`) names the file, or
//! * an administrator uploads it through `POST /api/v1/asn/database`, which
//!   writes [`DEFAULT_MMDB_PATH`] (inside the shipped data volume).
//!
//! The database is read once into memory, so a lookup is a binary search in
//! process memory: no network call, no per-row file I/O. Without a configured
//! database [`lookup_ip`] answers `None` and `access_logs.asn` stays NULL —
//! the ranking is then empty, which is the documented behaviour rather than a
//! guessed value.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, RwLock};

use chrono::{DateTime, Utc};
use serde::Serialize;

/// Environment variable naming an operator-supplied name file.
///
/// Read once, on first use of the resolver; the value is a filesystem path.
pub const NAMES_FILE_ENV: &str = "WAFRED_ASN_NAMES_FILE";

/// Bundled snapshot. `include_str!` keeps it in the binary, so a deployment
/// needs no data file of its own.
const BUNDLED: &str = include_str!("../assets/asn_names.tsv");

/// Refuse an operator file larger than this. A complete ASN→organization
/// export is a few megabytes; anything past this bound is a wrong path (a
/// log, an archive, a database dump) rather than a name file, and reading it
/// would stall the first analytics request.
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Longest organization name kept, in characters. The name lands in a JSON
/// response row; a pathological line should not be able to blow it up.
const MAX_NAME_CHARS: usize = 120;

/// Hard cap on the number of entries loaded from the operator file.
const MAX_ENTRIES: usize = 200_000;

/// The merged, read-only mapping. Loaded on first use, never mutated after.
static NAMES: LazyLock<HashMap<u32, String>> = LazyLock::new(load);

/// Organization name registered for `asn`, when the mapping knows it.
pub fn name_for(asn: u32) -> Option<&'static str> {
    NAMES.get(&asn).map(String::as_str)
}

/// The name to show for `asn`.
///
/// Falls back to `Unknown (AS<number>)` — the number stays visible, so a row
/// is always actionable (an operator can look the ASN up) and a missing name
/// can never be mistaken for a name that happens to be a number.
pub fn display_name(asn: u32) -> String {
    match name_for(asn) {
        Some(name) => name.to_string(),
        None => format!("Unknown (AS{asn})"),
    }
}

/// Forces the ASN→name mapping to load, so the first analytics request does
/// not pay for the (small) file read. Called from the startup warm-up task.
pub fn warm_names() {
    let _ = &*NAMES;
}

/// Builds the process-wide mapping: bundled snapshot first, operator file on
/// top.
fn load() -> HashMap<u32, String> {
    let (mut names, issues) = parse(BUNDLED);
    report("bundled", &issues);

    let Some(path) = std::env::var_os(NAMES_FILE_ENV) else {
        tracing::debug!(
            entries = names.len(),
            "ASN name mapping loaded from the bundled snapshot"
        );
        return names;
    };

    let path = std::path::PathBuf::from(path);
    // Not named `display`: the `%value` sigil of the `tracing` macros expands
    // to `tracing::field::display`, and a local of that name shadows it.
    let file_label = path.display().to_string();
    let file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(err) => {
            // A missing/unreadable override is a configuration mistake, not a
            // reason to lose the bundled names: the endpoint keeps working
            // with the fallback for everything else.
            tracing::warn!(
                file = %file_label,
                error = %err,
                "cannot open the ASN name file; using the bundled snapshot only"
            );
            return names;
        },
    };
    let too_large = file
        .metadata()
        .map(|meta| meta.len() > MAX_FILE_BYTES)
        .unwrap_or(false);
    if too_large {
        tracing::warn!(
            file = %file_label,
            max_bytes = MAX_FILE_BYTES,
            "ASN name file is larger than the supported bound; ignoring it"
        );
        return names;
    }
    let source = match std::fs::read_to_string(&path) {
        Ok(source) => source,
        Err(err) => {
            tracing::warn!(
                file = %file_label,
                error = %err,
                "cannot read the ASN name file; using the bundled snapshot only"
            );
            return names;
        },
    };

    let (overrides, issues) = parse(&source);
    report(&file_label, &issues);
    let overridden = overrides
        .iter()
        .filter(|(asn, name)| names.get(asn) != Some(name))
        .count();
    names.extend(overrides);
    tracing::info!(
        file = %file_label,
        entries = names.len(),
        overridden,
        "ASN name mapping loaded"
    );
    names
}

/// Logs parse issues, bounded so a fully malformed file cannot flood the log.
fn report(source: &str, issues: &[String]) {
    const MAX_REPORTED: usize = 20;
    for issue in issues.iter().take(MAX_REPORTED) {
        tracing::warn!(source, issue, "ignoring ASN name entry");
    }
    if issues.len() > MAX_REPORTED {
        tracing::warn!(
            source,
            skipped = issues.len(),
            reported = MAX_REPORTED,
            "more ASN name entries were ignored than are listed here"
        );
    }
}

/// Parses a name file. Returns the entries it could read plus one message per
/// skipped line, so the caller can log the problems without failing startup.
fn parse(source: &str) -> (HashMap<u32, String>, Vec<String>) {
    let mut names = HashMap::new();
    let mut issues = Vec::new();
    for (index, raw) in source.lines().enumerate() {
        let line_number = index + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((number, name)) = line.split_once('\t') else {
            issues.push(format!(
                "line {line_number}: expected `<asn><tab><organization>`"
            ));
            continue;
        };
        let Some(asn) = parse_asn(number) else {
            issues.push(format!(
                "line {line_number}: `{}` is not an AS number",
                number.trim()
            ));
            continue;
        };
        let Some(name) = clean_name(name) else {
            issues.push(format!(
                "line {line_number}: AS{asn} has an empty organization name"
            ));
            continue;
        };
        if names.len() >= MAX_ENTRIES {
            issues.push(format!(
                "line {line_number}: more than {MAX_ENTRIES} entries; the rest of the file is ignored"
            ));
            break;
        }
        names.insert(asn, name);
    }
    (names, issues)
}

/// Accepts `13335` and `AS13335` (any casing); rejects 0, which is not a real
/// AS number and would otherwise become a bucket of its own.
fn parse_asn(raw: &str) -> Option<u32> {
    let trimmed = raw.trim();
    // `get(..2)` rather than a byte slice: a multi-byte first character is
    // not a char boundary at index 2, and slicing there would panic.
    let digits = match trimmed.get(..2) {
        Some(prefix) if prefix.eq_ignore_ascii_case("as") => &trimmed[2..],
        _ => trimmed,
    };
    match digits.trim().parse::<u32>() {
        Ok(0) | Err(_) => None,
        Ok(asn) => Some(asn),
    }
}

/// Trims the name, drops control characters and caps its length in characters
/// (not bytes, so a multi-byte name is never cut mid-character).
fn clean_name(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        return None;
    }
    let capped: String = trimmed.chars().take(MAX_NAME_CHARS).collect();
    Some(capped.trim_end().to_string())
}

// ── MaxMind ASN database (where the AS number comes from) ────────────────────

/// Environment variable naming the MaxMind ASN database to read.
pub const MMDB_ENV: &str = "WAFRED_ASN_MMDB";

/// Default database path, and the file the admin upload writes.
///
/// `/var/lib/wafred` is the data volume of the shipped compose file, so an
/// uploaded database survives container recreation and redeploys.
pub const DEFAULT_MMDB_PATH: &str = "/var/lib/wafred/asn.mmdb";

/// Largest database accepted, from either source. A GeoLite2-ASN file is
/// roughly 8 MiB; anything far beyond that is not an ASN database (a country
/// database is ~70 MiB and is rejected by type anyway).
pub const MAX_MMDB_BYTES: u64 = 64 * 1024 * 1024;

/// The file the server reads: the configured path, else the upload default.
pub fn mmdb_path() -> PathBuf {
    path_from(std::env::var_os(MMDB_ENV))
}

/// True when the path comes from [`MMDB_ENV`] rather than the upload default.
pub fn mmdb_path_from_env() -> bool {
    std::env::var_os(MMDB_ENV).is_some_and(|value| !value.is_empty())
}

fn path_from(configured: Option<std::ffi::OsString>) -> PathBuf {
    match configured {
        Some(value) if !value.is_empty() => PathBuf::from(value),
        _ => PathBuf::from(DEFAULT_MMDB_PATH),
    }
}

/// One loaded database plus the metadata worth reporting.
struct AsnDatabase {
    reader: maxminddb::Reader<Vec<u8>>,
    database_type: String,
    build_epoch: u64,
    path: PathBuf,
}

impl AsnDatabase {
    /// The AS number the database assigns to `ip`.
    ///
    /// A miss, an undecodable record and AS0 all answer `None`: the caller
    /// stores NULL rather than inventing a network.
    fn lookup(&self, ip: IpAddr) -> Option<u32> {
        let record = self
            .reader
            .lookup(ip)
            .ok()?
            .decode::<maxminddb::geoip2::Asn>()
            .ok()??;
        record.autonomous_system_number.filter(|asn| *asn != 0)
    }
}

/// Process-wide state. `attempted` keeps a missing or broken file from being
/// re-read on every log batch; the upload path resets it.
#[derive(Default)]
struct State {
    database: Option<Arc<AsnDatabase>>,
    attempted: bool,
    error: Option<String>,
}

static STATE: LazyLock<RwLock<State>> =
    LazyLock::new(|| RwLock::new(State::default()));

fn state() -> std::sync::RwLockReadGuard<'static, State> {
    // A panic while holding the lock cannot leave a partially written state
    // (every writer assigns whole fields), so recovering is safe and keeps a
    // poisoned lock from breaking traffic ingestion for the process lifetime.
    STATE.read().unwrap_or_else(|poison| poison.into_inner())
}

fn state_mut() -> std::sync::RwLockWriteGuard<'static, State> {
    STATE.write().unwrap_or_else(|poison| poison.into_inner())
}

/// The AS number registered for `ip` by the loaded database.
///
/// `None` when no database is loaded, or the address is not in it.
///
/// **Never performs I/O.** The file is read by [`warm`] at startup and by
/// [`status`] / [`install_from_bytes`] (all of which run on a blocking thread
/// — see `api::asn`), so the log-ingestion hot path is one lock acquisition
/// plus an in-memory lookup. A database that appears later is picked up by the
/// status endpoint or an upload, not by traffic.
pub fn lookup_ip(ip: IpAddr) -> Option<u32> {
    let guard = state();
    guard
        .database
        .as_ref()
        .and_then(|database| database.lookup(ip))
}

/// Loads the configured database, once per process. Called at startup (so the
/// first log batch never pays for it); [`lookup_ip`] only reads the warmed
/// in-memory state and never performs file I/O.
pub fn warm() {
    if !state().attempted {
        load_from_disk();
    }
}

/// Reads the database from [`mmdb_path`] and installs it, once per process.
/// Returns true when a database is active afterwards.
fn load_from_disk() -> bool {
    if state().attempted {
        return state().database.is_some();
    }
    let path = mmdb_path();
    let loaded = read_database(&path);
    apply_load(loaded)
}

/// Re-reads the database regardless of an earlier failure.
///
/// The once-only rule above keeps a missing file from being re-read on every
/// log batch; this is the explicit refresh used by the status endpoint (so a
/// file copied in after startup is picked up without a restart) and by the
/// upload path.
fn reload_from_disk() -> bool {
    let path = mmdb_path();
    let loaded = read_database(&path);
    apply_load(loaded)
}

fn apply_load(loaded: Result<AsnDatabase, String>) -> bool {
    let mut guard = state_mut();
    guard.attempted = true;
    match loaded {
        Ok(database) => {
            tracing::info!(
                path = %database.path.display(),
                database_type = %database.database_type,
                build_epoch = database.build_epoch,
                "ASN database loaded; access logs are enriched from it"
            );
            guard.error = None;
            guard.database = Some(Arc::new(database));
            true
        },
        Err(error) => {
            // Not an error the operator must fix to run WAFred: without the
            // database `access_logs.asn` stays NULL and the ASN ranking is
            // empty, which is documented. One warning per load attempt is
            // enough — the hot path never retries.
            tracing::warn!(%error, "ASN database not loaded; ASN analytics stays empty");
            guard.error = Some(error);
            guard.database = None;
            false
        },
    }
}

fn read_database(path: &Path) -> Result<AsnDatabase, String> {
    let metadata = std::fs::metadata(path).map_err(|err| {
        format!("no ASN database at {}: {err}", path.display())
    })?;
    if metadata.len() > MAX_MMDB_BYTES {
        return Err(format!(
            "{} is {} bytes, larger than the {MAX_MMDB_BYTES}-byte ASN database bound",
            path.display(),
            metadata.len()
        ));
    }
    let reader = maxminddb::Reader::open_readfile(path).map_err(|err| {
        format!("{} is not a valid MaxMind database: {err}", path.display())
    })?;
    let database_type = reader.metadata().database_type.clone();
    validate_database_type(&database_type)?;
    let build_epoch = reader.metadata().build_epoch;
    Ok(AsnDatabase {
        reader,
        database_type,
        build_epoch,
        path: path.to_path_buf(),
    })
}

/// Rejects a database that cannot answer an ASN query.
///
/// MaxMind's ASN data lives in GeoLite2-ASN, GeoIP2-ISP and
/// GeoIP2-Enterprise; the country/city databases are refused so an operator
/// cannot upload the wrong file and see an empty ranking with no explanation.
fn validate_database_type(database_type: &str) -> Result<(), String> {
    let lowered = database_type.to_ascii_lowercase();
    if lowered.contains("asn")
        || lowered.contains("isp")
        || lowered.contains("enterprise")
    {
        return Ok(());
    }
    Err(format!(
        "`{database_type}` is not an ASN database; use GeoLite2-ASN, GeoIP2-ISP or GeoIP2-Enterprise"
    ))
}

/// Status of the ASN data source, for `GET /api/v1/asn/database`.
#[derive(Debug, Serialize)]
pub struct AsnDatabaseStatus {
    /// File the server reads (configured path or upload default).
    pub path: String,
    /// True when the path comes from [`MMDB_ENV`] rather than the upload.
    pub path_from_env: bool,
    /// The file exists.
    pub configured: bool,
    /// The database is loaded — ASN enrichment is active.
    pub active: bool,
    /// `database_type` from the file's metadata.
    pub database_type: Option<String>,
    /// Build timestamp from the file's metadata.
    pub build_time: Option<DateTime<Utc>>,
    /// Why the database is not active, when it is not.
    pub error: Option<String>,
}

/// Reports the data source.
///
/// A file that appeared after startup (or after a failed load) is picked up
/// here — this is the call an operator makes right after copying the database
/// in, so it must not report a stale "missing" from boot.
pub fn status() -> AsnDatabaseStatus {
    let path = mmdb_path();
    if state().database.is_none() && path.exists() {
        reload_from_disk();
    }
    let guard = state();
    AsnDatabaseStatus {
        configured: path.exists(),
        path_from_env: mmdb_path_from_env(),
        active: guard.database.is_some(),
        database_type: guard
            .database
            .as_ref()
            .map(|database| database.database_type.clone()),
        build_time: guard
            .database
            .as_ref()
            .and_then(|database| build_time(database.build_epoch)),
        error: guard.error.clone(),
        path: path.display().to_string(),
    }
}

fn build_time(epoch: u64) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(i64::try_from(epoch).ok()?, 0)
}

/// Installs an uploaded database: validates it, persists it at
/// [`mmdb_path`] and swaps the in-memory copy.
///
/// The file is written to a sibling temp path first and renamed only after it
/// validates, so a corrupt upload leaves the previous database in place.
pub fn install_from_bytes(bytes: Vec<u8>) -> Result<AsnDatabaseStatus, String> {
    if bytes.is_empty() {
        return Err("uploaded file is empty".to_string());
    }
    if bytes.len() as u64 > MAX_MMDB_BYTES {
        return Err(format!(
            "uploaded file is larger than the {MAX_MMDB_BYTES}-byte ASN database bound"
        ));
    }
    let path = mmdb_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| {
            format!("cannot create {}: {err}", parent.display())
        })?;
    }
    // A unique temp name: two administrators uploading at once must not
    // interleave their bytes into one file and fail validation.
    let temp =
        path.with_extension(format!("mmdb.{}.tmp", uuid::Uuid::new_v4()));
    std::fs::write(&temp, &bytes)
        .map_err(|err| format!("cannot write {}: {err}", temp.display()))?;
    let mut database = match read_database(&temp) {
        Ok(database) => database,
        Err(error) => {
            let _ = std::fs::remove_file(&temp);
            return Err(error);
        },
    };
    if let Err(err) = std::fs::rename(&temp, &path) {
        let _ = std::fs::remove_file(&temp);
        return Err(format!("cannot replace {}: {err}", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            &path,
            std::fs::Permissions::from_mode(0o600),
        );
    }
    database.path = path;
    let database_type = database.database_type.clone();
    let build_epoch = database.build_epoch;
    {
        let mut guard = state_mut();
        guard.attempted = true;
        guard.error = None;
        guard.database = Some(Arc::new(database));
    }
    tracing::info!(
        path = %mmdb_path().display(),
        database_type = %database_type,
        build_epoch,
        bytes = bytes.len(),
        "ASN database uploaded"
    );
    Ok(status())
}

/// Removes an uploaded database and clears the in-memory copy.
///
/// Refused when [`MMDB_ENV`] names the file: that path is the operator's, not
/// the upload's, so deleting it behind their back would be a surprise.
pub fn remove_uploaded() -> Result<AsnDatabaseStatus, String> {
    if mmdb_path_from_env() {
        return Err(format!(
            "the ASN database path is set by {MMDB_ENV}; remove the file on the host instead"
        ));
    }
    let path = mmdb_path();
    match std::fs::remove_file(&path) {
        Ok(()) => {},
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {},
        Err(err) => {
            return Err(format!("cannot remove {}: {err}", path.display()));
        },
    }
    {
        let mut guard = state_mut();
        guard.database = None;
        guard.attempted = false;
        guard.error = None;
    }
    tracing::info!(path = %path.display(), "ASN database removed");
    Ok(status())
}

/// Loads an in-memory database into the process-wide slot. Tests only: the
/// production paths are [`warm`] and [`install_from_bytes`].
#[cfg(test)]
fn install_for_tests(bytes: &[u8]) -> Result<(), String> {
    let reader = maxminddb::Reader::from_source(bytes.to_vec())
        .map_err(|err| err.to_string())?;
    let database_type = reader.metadata().database_type.clone();
    let build_epoch = reader.metadata().build_epoch;
    let mut guard = state_mut();
    guard.attempted = true;
    guard.error = None;
    guard.database = Some(Arc::new(AsnDatabase {
        reader,
        database_type,
        build_epoch,
        path: PathBuf::from("test://asn-test.mmdb"),
    }));
    Ok(())
}

#[cfg(test)]
fn reset_for_tests() {
    let mut guard = state_mut();
    guard.database = None;
    guard.attempted = false;
    guard.error = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialises the tests that touch the process-wide database slot.
    static MMDB_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// The bundled file is compiled in, so a typo in it would only surface at
    /// runtime — parse it here and require it to be clean.
    #[test]
    fn bundled_snapshot_parses_without_issues() {
        let (names, issues) = parse(BUNDLED);
        assert_eq!(issues, Vec::<String>::new(), "{issues:?}");
        assert!(names.len() >= 40, "only {} entries", names.len());
    }

    #[test]
    fn bundled_snapshot_names_the_major_networks() {
        let (names, _) = parse(BUNDLED);
        for (asn, expected) in [
            (13335u32, "Cloudflare, Inc."),
            (16509, "Amazon.com, Inc. (AWS)"),
            (15169, "Google LLC"),
            (8075, "Microsoft Corporation"),
            (4134, "Chinanet (China Telecom)"),
        ] {
            assert_eq!(
                names.get(&asn).map(String::as_str),
                Some(expected),
                "AS{asn}"
            );
        }
    }

    /// The documented fallback: an unknown ASN keeps its number and is
    /// labelled as unknown — never rendered as a bare `AS12345`.
    #[test]
    fn unknown_asn_falls_back_to_a_labelled_number() {
        // 64512 is in the private-use range, so no registry names it.
        assert_eq!(None, name_for(64_512));
        assert_eq!("Unknown (AS64512)", display_name(64_512));
    }

    #[test]
    fn operator_file_overrides_the_bundled_names() {
        let (mut names, _) = parse(BUNDLED);
        let (overrides, issues) = parse(
            "# operator export\n\
             AS13335\tCloudflare (operator label)\n\
             64500\tExample Hosting, Ltd.\n",
        );
        assert_eq!(issues, Vec::<String>::new(), "{issues:?}");
        names.extend(overrides);
        assert_eq!(
            names.get(&13335).map(String::as_str),
            Some("Cloudflare (operator label)")
        );
        assert_eq!(
            names.get(&64_500).map(String::as_str),
            Some("Example Hosting, Ltd.")
        );
    }

    #[test]
    fn malformed_lines_are_skipped_and_reported() {
        let (names, issues) = parse(
            "13335\tCloudflare, Inc.\n\
             \n\
             # comment\n\
             16509 Cloudflare without a tab\n\
             not-a-number\tSomebody\n\
             0\tZero is not an ASN\n\
             64500\t   \n\
             AS64501\tPadded name   \n",
        );
        assert_eq!(
            Some("Cloudflare, Inc."),
            names.get(&13335).map(String::as_str)
        );
        assert_eq!(Some("Padded name"), names.get(&64_501).map(String::as_str));
        assert!(!names.contains_key(&0));
        assert_eq!(4, issues.len(), "{issues:?}");
        assert!(issues[0].starts_with("line 4:"), "{}", issues[0]);
        assert!(issues[1].starts_with("line 5:"), "{}", issues[1]);
        assert!(issues[2].starts_with("line 6:"), "{}", issues[2]);
        assert!(issues[3].starts_with("line 7:"), "{}", issues[3]);
    }

    /// A name may carry commas, dots and non-ASCII text; only a tab would
    /// split it, and the length cap counts characters, not bytes.
    #[test]
    fn names_are_kept_whole_and_capped_by_characters() {
        let (names, issues) =
            parse("64500\tExample, Inc. (AS64500) — 示例网络\n");
        assert_eq!(issues, Vec::<String>::new(), "{issues:?}");
        assert_eq!(
            Some("Example, Inc. (AS64500) — 示例网络"),
            names.get(&64_500).map(String::as_str)
        );

        let long = "名".repeat(MAX_NAME_CHARS + 20);
        let (names, _) = parse(&format!("64501\t{long}\n"));
        let kept = names.get(&64_501).expect("entry kept");
        assert_eq!(MAX_NAME_CHARS, kept.chars().count());
    }

    // ── MaxMind ASN database ────────────────────────────────────────────────

    /// The committed fixture (see `scripts/gen-asn-test-mmdb.py`) really
    /// decodes as an ASN database: the reader, the record decode and the
    /// metadata all work end to end.
    #[test]
    fn the_fixture_database_decodes_an_asn_record() {
        let bytes = include_bytes!("../assets/test/asn-test.mmdb");
        let reader = maxminddb::Reader::from_source(bytes.to_vec())
            .expect("fixture is a valid MaxMind database");
        let database_type = reader.metadata().database_type.clone();
        let build_epoch = reader.metadata().build_epoch;
        assert_eq!("GeoLite2-ASN", database_type);

        let database = AsnDatabase {
            reader,
            database_type,
            build_epoch,
            path: PathBuf::from("test://asn-test.mmdb"),
        };
        assert_eq!(
            Some(64_500),
            database.lookup("8.8.8.8".parse().unwrap()),
            "the fixture covers 8.8.8.0/24"
        );
        assert_eq!(Some(64_500), database.lookup("8.8.8.200".parse().unwrap()));
        assert_eq!(
            None,
            database.lookup("8.8.9.1".parse().unwrap()),
            "outside the fixture's prefix"
        );
        assert_eq!(None, database.lookup("1.2.3.4".parse().unwrap()));
    }

    /// The process-wide slot is what ingestion consults: installing a
    /// database makes `lookup_ip` answer from it, and a miss stays `None`
    /// (no invented AS number). Holds the test lock so the global state does
    /// not leak into another test.
    #[test]
    fn the_installed_database_answers_the_ingestion_lookup() {
        let _guard = MMDB_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        install_for_tests(include_bytes!("../assets/test/asn-test.mmdb"))
            .expect("fixture installs");
        assert_eq!(Some(64_500), lookup_ip("8.8.8.8".parse().unwrap()));
        assert_eq!(None, lookup_ip("1.2.3.4".parse().unwrap()));
        reset_for_tests();
        assert_eq!(None, lookup_ip("8.8.8.8".parse().unwrap()));
    }

    /// The ingestion hot path never reads the database from disk: an
    /// unloaded state answers `None` and stays unloaded, which is what keeps
    /// log shipping from blocking on file I/O.
    #[test]
    fn the_ingestion_lookup_never_loads_the_database() {
        let _guard = MMDB_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        reset_for_tests();
        assert_eq!(None, lookup_ip("8.8.8.8".parse().unwrap()));
        assert!(
            !state().attempted,
            "lookup_ip must not attempt a load; loading belongs to warm()/status()"
        );
    }

    /// Only databases that can answer an ASN query are accepted, so the
    /// wrong upload fails loudly instead of producing an empty ranking.
    #[test]
    fn only_asn_databases_are_accepted() {
        for accepted in ["GeoLite2-ASN", "GeoIP2-ISP", "GeoIP2-Enterprise"] {
            assert_eq!(Ok(()), validate_database_type(accepted), "{accepted}");
        }
        for rejected in ["GeoLite2-Country", "GeoIP2-City", ""] {
            let error = validate_database_type(rejected)
                .err()
                .unwrap_or_else(|| panic!("{rejected} must be rejected"));
            assert!(error.contains("is not an ASN database"), "{error}");
        }
    }

    /// A file that is not a MaxMind database is rejected with the path in the
    /// message, which is what the upload endpoint returns as a 400.
    #[test]
    fn a_file_that_is_not_an_mmdb_is_rejected() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("asn.mmdb");
        std::fs::write(&path, b"definitely not a maxmind database")
            .expect("write");
        let error = read_database(&path).err().expect("garbage must not load");
        assert!(error.contains("is not a valid MaxMind database"), "{error}");

        let missing = read_database(&dir.path().join("absent.mmdb"))
            .err()
            .expect("missing file must not load");
        assert!(missing.contains("no ASN database at"), "{missing}");
    }

    /// The configured path wins over the upload default, and an empty value
    /// falls back to the default rather than pointing at "".
    #[test]
    fn the_configured_path_wins_over_the_upload_default() {
        assert_eq!(
            PathBuf::from(DEFAULT_MMDB_PATH),
            path_from(None),
            "no configuration"
        );
        assert_eq!(
            PathBuf::from(DEFAULT_MMDB_PATH),
            path_from(Some(std::ffi::OsString::new())),
            "empty configuration"
        );
        assert_eq!(
            PathBuf::from("/srv/geoip/GeoLite2-ASN.mmdb"),
            path_from(Some("/srv/geoip/GeoLite2-ASN.mmdb".into()))
        );
    }

    /// The status payload is what the dashboard/operator reads to tell
    /// "no source" from "source loaded".
    #[test]
    fn the_status_reports_the_loaded_database() {
        let _guard = MMDB_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        install_for_tests(include_bytes!("../assets/test/asn-test.mmdb"))
            .expect("fixture installs");
        let status = status();
        assert!(status.active);
        assert_eq!(Some("GeoLite2-ASN".to_string()), status.database_type);
        assert_eq!(
            Some(DateTime::from_timestamp(1_700_000_000, 0).unwrap()),
            status.build_time
        );
        assert_eq!(None, status.error);
        reset_for_tests();
    }

    /// The last line for an AS number wins, which is what makes the operator
    /// file able to override the bundled snapshot.
    #[test]
    fn a_later_entry_replaces_an_earlier_one() {
        let (names, issues) = parse("64500\tFirst Name\n64500\tSecond Name\n");
        assert_eq!(issues, Vec::<String>::new(), "{issues:?}");
        assert_eq!(Some("Second Name"), names.get(&64_500).map(String::as_str));
    }
}
