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

//! WAFred CLI subcommand definitions.
//!
//! These are additive to the existing pingap CLI and are detected before
//! the normal argument parsing runs.

use std::path::{Path, PathBuf};

use clap::{CommandFactory, Parser, Subcommand};

/// WAFred top-level CLI wrapper.
///
/// When the first positional argument is one of the WAFred subcommand
/// names — the three run modes (`server`, `agent`, `all-in-one`) or a
/// maintenance command (`user`, `mode`, `security`, `config`) — the binary
/// switches to WAFred mode.
#[derive(Parser, Debug)]
#[command(
    name = "wafred",
    about = "WAFred — Web Application Firewall control plane and data plane",
    version
)]
pub struct WafredCli {
    #[command(subcommand)]
    pub command: WafredCommand,
}

#[derive(Subcommand, Debug)]
pub enum WafredCommand {
    /// Run the control plane server only (REST API + gRPC + dashboard)
    #[cfg(not(feature = "edge"))]
    Server(ServerOpts),
    /// Run the data plane agent only (connects to a remote control plane)
    Agent(AgentOpts),
    /// Run both control plane and data plane in a single process
    #[cfg(not(feature = "edge"))]
    AllInOne(AllInOneOpts),
    /// Dashboard user administration
    User {
        #[command(subcommand)]
        command: UserSubcommand,
    },
    /// Observation mode: run every detection, enforce nothing
    Mode {
        #[command(subcommand)]
        command: ModeCommand,
    },
    /// Control plane (9080) self-protection switches
    Security {
        #[command(subcommand)]
        command: SecurityCommand,
    },
    /// WAF configuration version history: list, inspect, roll back
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
}

/// Options shared by all WAFred modes.
#[derive(Parser, Debug, Clone)]
pub struct CommonOpts {
    /// PostgreSQL connection string
    #[arg(
        long,
        env = "WAFRED_DB_URL",
        default_value = "postgres://wafred:wafred@localhost:5432/wafred"
    )]
    pub db_url: String,

    /// Read the PostgreSQL connection string from a file instead of
    /// `--db-url`/`WAFRED_DB_URL`. The file content is trimmed and used as
    /// the whole connection string, keeping its password out of the process
    /// list (`ps`) and shell history.
    #[arg(long, env = "WAFRED_DB_URL_FILE")]
    pub db_url_file: Option<PathBuf>,

    /// HTTP admin/API listen address
    #[arg(long, env = "WAFRED_ADMIN_ADDR", default_value = "0.0.0.0:9080")]
    pub admin_addr: String,

    /// gRPC listen/connect address
    #[arg(long, env = "WAFRED_GRPC_ADDR", default_value = "0.0.0.0:9090")]
    pub grpc_addr: String,

    /// Optional TLS for the gRPC control plane: PEM certificate chain, used
    /// together with --grpc-tls-key. Agents then connect via `https://`.
    #[arg(long, env = "WAFRED_GRPC_TLS_CERT")]
    pub grpc_tls_cert: Option<String>,

    /// PEM private key for --grpc-tls-cert.
    #[arg(long, env = "WAFRED_GRPC_TLS_KEY")]
    pub grpc_tls_key: Option<String>,

    /// Transport security of the gRPC control plane: `tls` (the default)
    /// serves the configured certificate or, absent one, the self-signed
    /// control-plane certificate; `off` serves plaintext (degraded).
    #[arg(long, env = "WAFRED_GRPC_TLS_MODE", default_value = "tls")]
    pub grpc_tls_mode: pingwaf_server::config::GrpcTlsMode,

    /// Serve the admin dashboard and REST API over TLS. A self-signed
    /// certificate is generated on first boot; upload a real one from
    /// Settings → Control plane HTTPS. Set to false behind a reverse proxy
    /// that terminates TLS.
    #[arg(
        long,
        env = "WAFRED_TLS_ENABLED",
        default_value = "true",
        num_args = 0..=1,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    pub tls_enabled: bool,

    /// Subject alternative names of the generated self-signed certificate,
    /// comma separated (DNS names and IP addresses)
    #[arg(long, env = "WAFRED_TLS_SANS", value_delimiter = ',')]
    pub tls_sans: Vec<String>,

    /// Host the dashboard is reached under from the outside, optionally with
    /// a port. Pinned into the HTTP-to-HTTPS redirect target instead of the
    /// client's Host header.
    #[arg(long, env = "WAFRED_PUBLIC_HOST")]
    pub public_host: Option<String>,
}

/// Control plane server options.
#[cfg(not(feature = "edge"))]
#[derive(Parser, Debug, Clone)]
#[command(args_override_self = true)]
pub struct ServerOpts {
    #[command(flatten)]
    pub common: CommonOpts,

    /// TOML configuration file; its `[server]` and `[agent]` tables hold
    /// these same settings. Precedence is this file, then the `WAFRED_*`
    /// environment variables, then the command line.
    #[arg(long, env = "WAFRED_CONFIG")]
    pub config: Option<String>,

    /// JWT signing secret (must be at least 16 characters)
    #[arg(
        long,
        env = "WAFRED_JWT_SECRET",
        default_value = "change-me-in-production"
    )]
    pub jwt_secret: String,

    /// Default admin email for initial seeding
    #[arg(
        long,
        env = "WAFRED_ADMIN_EMAIL",
        default_value = "admin@wafred.local"
    )]
    pub admin_email: String,

    /// Default admin password for initial seeding
    #[arg(long, env = "WAFRED_ADMIN_PASSWORD", default_value = "wafred123")]
    pub admin_password: String,

    /// Whether to serve the embedded frontend (SPA)
    #[arg(
        long,
        env = "WAFRED_SERVE_FRONTEND",
        default_value = "true",
        num_args = 0..=1,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    pub serve_frontend: bool,
}

/// Data plane agent options.
#[derive(Parser, Debug, Clone)]
#[command(args_override_self = true)]
pub struct AgentOpts {
    /// TOML configuration file; its `[server]` and `[agent]` tables hold
    /// these same settings. In agent mode the file wins over the `WAFRED_*`
    /// environment variables, and the command line wins over both.
    #[arg(long, env = "WAFRED_CONFIG")]
    pub config: Option<String>,

    /// Control plane gRPC URL to connect to
    #[arg(
        long,
        env = "WAFRED_SERVER_URL",
        default_value = "http://localhost:9090"
    )]
    pub server_url: String,

    /// Optional PEM file with the CA (or chain) that signed the control
    /// plane's gRPC certificate; defaults to the bundled webpki roots.
    #[arg(long, env = "WAFRED_SERVER_CA_CERT")]
    pub server_ca_cert: Option<String>,

    /// Name used for TLS SNI and certificate verification instead of the host
    /// in --server-url. Set it to a SAN of the control plane's certificate
    /// when that certificate does not name the host the agent dials.
    #[arg(long, env = "WAFRED_SERVER_TLS_NAME")]
    pub server_tls_name: Option<String>,

    /// API key for agent authentication
    #[arg(long, env = "WAFRED_API_KEY", default_value = "")]
    pub api_key: String,

    /// Read the agent API key from a file instead of `--api-key`/
    /// `WAFRED_API_KEY`. The file content is trimmed, keeping the key out of
    /// the process list (`ps`) and shell history.
    #[arg(long, env = "WAFRED_API_KEY_FILE")]
    pub api_key_file: Option<PathBuf>,

    /// Local rule cache directory
    #[arg(long, env = "WAFRED_CACHE_DIR", default_value = "./data/cache")]
    pub cache_dir: String,

    /// Fallback policy when disconnected with no synced rules for a host;
    /// per-site failover policies and the control-plane default win when
    /// they have been synced
    #[arg(
        long,
        env = "WAFRED_FAIL_OPEN",
        default_value = "true",
        num_args = 0..=1,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    pub fail_open: bool,

    /// Address the tunnel listener binds (`0.0.0.0:9443`); empty disables it.
    /// A connector reaches this address out of the private network, so it is
    /// only enabled on an edge that is meant to be a tunnel ingress.
    #[arg(long, env = "WAFRED_TUNNEL_ADDR", default_value = "")]
    pub tunnel_addr: String,

    /// Heartbeat interval in seconds
    #[arg(long, env = "WAFRED_HEARTBEAT_INTERVAL", default_value = "30")]
    pub heartbeat_interval_secs: u64,

    /// Maximum log batch size before flush
    #[arg(long, default_value = "100")]
    pub log_batch_size: usize,

    /// Log flush interval in seconds
    #[arg(long, default_value = "5")]
    pub log_flush_interval_secs: u64,

    /// Maximum request body size to log (bytes)
    #[arg(long, default_value = "8192")]
    pub max_body_log_size: usize,

    /// Metrics shipping interval in seconds (0 disables metric shipping)
    #[arg(long, env = "WAFRED_METRICS_SHIP_INTERVAL", default_value = "30")]
    pub metrics_ship_interval_secs: u64,

    /// Install the control plane's build automatically when the versions
    /// differ. The swap replaces this binary and restarts the process, so it
    /// is off unless asked for; it also requires --upgrade-url
    #[arg(
        long,
        env = "WAFRED_AUTO_UPGRADE",
        default_value = "false",
        num_args = 0..=1,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    pub auto_upgrade: bool,

    /// Control plane REST base URL for self-upgrade, e.g.
    /// https://cp.example.com:9080. It cannot be derived from the gRPC URL, so
    /// auto-upgrade stays disabled while this is unset
    #[arg(long, env = "WAFRED_UPGRADE_URL")]
    pub upgrade_url: Option<String>,
}

/// All-in-one mode options (server + agent in one process).
#[cfg(not(feature = "edge"))]
#[derive(Parser, Debug, Clone)]
#[command(args_override_self = true)]
pub struct AllInOneOpts {
    #[command(flatten)]
    pub common: CommonOpts,

    /// TOML configuration file; its `[server]` and `[agent]` tables hold
    /// these same settings. Precedence is this file, then the `WAFRED_*`
    /// environment variables, then the command line.
    #[arg(long, env = "WAFRED_CONFIG")]
    pub config: Option<String>,

    // ── Server ────────────────────────────────────────────────────────
    /// JWT signing secret (must be at least 16 characters)
    #[arg(
        long,
        env = "WAFRED_JWT_SECRET",
        default_value = "change-me-in-production"
    )]
    pub jwt_secret: String,

    /// Default admin email for initial seeding
    #[arg(
        long,
        env = "WAFRED_ADMIN_EMAIL",
        default_value = "admin@wafred.local"
    )]
    pub admin_email: String,

    /// Default admin password for initial seeding
    #[arg(long, env = "WAFRED_ADMIN_PASSWORD", default_value = "wafred123")]
    pub admin_password: String,

    /// Whether to serve the embedded frontend (SPA)
    #[arg(
        long,
        env = "WAFRED_SERVE_FRONTEND",
        default_value = "true",
        num_args = 0..=1,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    pub serve_frontend: bool,

    // ── Agent ─────────────────────────────────────────────────────────
    /// API key for agent authentication (empty = auto-register via loopback)
    #[arg(long, env = "WAFRED_API_KEY", default_value = "")]
    pub api_key: String,

    /// Read the agent API key from a file instead of `--api-key`/
    /// `WAFRED_API_KEY` (see `wafred agent --help`).
    #[arg(long, env = "WAFRED_API_KEY_FILE")]
    pub api_key_file: Option<PathBuf>,

    /// Local rule cache directory
    #[arg(long, env = "WAFRED_CACHE_DIR", default_value = "./data/cache")]
    pub cache_dir: String,

    /// Fallback policy when disconnected with no synced rules for a host;
    /// per-site failover policies and the control-plane default win when
    /// they have been synced
    #[arg(
        long,
        env = "WAFRED_FAIL_OPEN",
        default_value = "true",
        num_args = 0..=1,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    pub fail_open: bool,

    /// Address the tunnel listener binds (`0.0.0.0:9443`); empty disables it.
    /// A connector reaches this address out of the private network, so it is
    /// only enabled on an edge that is meant to be a tunnel ingress.
    #[arg(long, env = "WAFRED_TUNNEL_ADDR", default_value = "")]
    pub tunnel_addr: String,

    /// Heartbeat interval in seconds
    #[arg(long, env = "WAFRED_HEARTBEAT_INTERVAL", default_value = "30")]
    pub heartbeat_interval_secs: u64,

    /// Maximum log batch size before flush
    #[arg(long, default_value = "100")]
    pub log_batch_size: usize,

    /// Log flush interval in seconds
    #[arg(long, default_value = "5")]
    pub log_flush_interval_secs: u64,

    /// Maximum request body size to log (bytes)
    #[arg(long, default_value = "8192")]
    pub max_body_log_size: usize,

    /// Metrics shipping interval in seconds (0 disables metric shipping)
    #[arg(long, env = "WAFRED_METRICS_SHIP_INTERVAL", default_value = "30")]
    pub metrics_ship_interval_secs: u64,
}

/// Database connection options of the maintenance commands.
///
/// Those commands talk straight to PostgreSQL instead of the REST API, so
/// they keep working when the control plane is down or its IP allowlist has
/// locked the operator out. A running control plane notices their writes
/// within a few seconds.
#[derive(clap::Args, Debug, Clone)]
pub struct DbOpts {
    /// PostgreSQL connection string
    #[arg(
        long,
        env = "WAFRED_DB_URL",
        default_value = "postgres://wafred:wafred@localhost:5432/wafred"
    )]
    pub db_url: String,

    /// Read the PostgreSQL connection string from a file instead of
    /// `--db-url`/`WAFRED_DB_URL` (keeps the password out of the process
    /// list and shell history).
    #[arg(long, env = "WAFRED_DB_URL_FILE")]
    pub db_url_file: Option<PathBuf>,
}

/// `user` — dashboard account administration.
#[derive(Subcommand, Debug)]
pub enum UserSubcommand {
    /// List dashboard accounts
    List(DbOpts),
    /// Create an administrator account
    AddAdmin(AddAdminOpts),
    /// Set a new password for an account
    ResetPassword(ResetPasswordOpts),
}

#[derive(clap::Args, Debug)]
pub struct AddAdminOpts {
    #[command(flatten)]
    pub db: DbOpts,

    /// E-mail address of the new administrator
    #[arg(long)]
    pub email: String,
    /// Display name
    #[arg(long)]
    pub name: Option<String>,
    /// Password; when omitted a random one is generated and printed
    #[arg(long)]
    pub password: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct ResetPasswordOpts {
    #[command(flatten)]
    pub db: DbOpts,

    /// E-mail address of the account
    #[arg(long)]
    pub email: String,
    /// New password; when omitted a random one is generated and printed
    #[arg(long)]
    pub password: Option<String>,
}

/// `mode` — the observation mode switch.
#[derive(Subcommand, Debug)]
pub enum ModeCommand {
    /// Turn observation mode on: detect everything, block nothing
    Observe(DbOpts),
    /// Turn observation mode off: protections enforce again
    Enforce(DbOpts),
    /// Print the current observation mode
    Status(DbOpts),
}

/// `security` — quick switches for the control plane's own protection.
#[derive(Subcommand, Debug)]
pub enum SecurityCommand {
    /// Print the 9080 protection settings and the effective allowlist
    Status(DbOpts),
    /// Turn the API IP allowlist on or off (the break-glass switch when the
    /// console is unreachable)
    Allowlist(AllowlistOpts),
}

/// `config` — the WAF configuration version history.
///
/// Like the other maintenance commands it talks straight to PostgreSQL, so
/// it keeps working when the control plane is down. Note that a *running*
/// control plane is not notified of a CLI rollback (unlike the console
/// rollback, which pushes to the agents immediately).
#[derive(Subcommand, Debug)]
pub enum ConfigCommand {
    /// List recorded configuration versions, newest first
    History(ConfigHistoryOpts),
    /// Print one version's metadata and snapshot summary
    Show(ConfigShowOpts),
    /// Restore a recorded configuration version
    Rollback(ConfigRollbackOpts),
}

#[derive(clap::Args, Debug)]
pub struct ConfigHistoryOpts {
    #[command(flatten)]
    pub db: DbOpts,

    /// Restrict the history to one site: its UUID, or `global` for the
    /// deployment-wide settings
    #[arg(long)]
    pub site: Option<String>,

    /// How many versions to print
    #[arg(long, default_value_t = 20)]
    pub limit: u32,
}

#[derive(clap::Args, Debug)]
pub struct ConfigShowOpts {
    #[command(flatten)]
    pub db: DbOpts,

    /// The version number to print
    pub version: i64,

    /// Print the full snapshot as JSON instead of a summary
    #[arg(long)]
    pub json: bool,
}

#[derive(clap::Args, Debug)]
pub struct ConfigRollbackOpts {
    #[command(flatten)]
    pub db: DbOpts,

    /// The version number to restore
    pub version: i64,

    /// Skip the confirmation prompt
    #[arg(long)]
    pub yes: bool,
}

#[derive(clap::Args, Debug)]
pub struct AllowlistOpts {
    #[command(flatten)]
    pub db: DbOpts,

    /// New state of the allowlist
    #[arg(value_enum)]
    pub state: OnOff,
    /// Enable even when the allowlist is empty (refuses every API caller)
    #[arg(long)]
    pub force: bool,
}

/// An `on` / `off` command line value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum OnOff {
    On,
    Off,
}

/// The run modes: the subcommands that start a long-running process.
///
/// Test-only: production mode detection comes from clap via [`is_mode`], and
/// the parity test keeps this list honest. The agent-only build exposes just
/// `agent`, so its list shrinks with the CLI.
#[cfg(all(test, not(feature = "edge")))]
pub const RUN_MODES: [&str; 3] = ["server", "agent", "all-in-one"];
#[cfg(all(test, feature = "edge"))]
pub const RUN_MODES: [&str; 1] = ["agent"];

/// The maintenance commands: they run against the database and exit.
#[cfg(test)]
const MAINTENANCE_MODES: [&str; 4] = ["user", "mode", "security", "config"];

/// Whether `value` names a WAFred subcommand.
///
/// Derived from clap rather than from a second list: a subcommand added to
/// `WafredCommand` is then recognised automatically. The arrays above stay
/// for the tests and documentation, and a parity test pins them to clap.
fn is_mode(value: &str) -> bool {
    WafredCli::command().find_subcommand(value).is_some()
}

/// The mode named by `WAFRED_MODE`, when it names one.
fn mode_from_env() -> Option<String> {
    let mode = std::env::var("WAFRED_MODE").ok()?;
    let mode = mode.trim().to_lowercase();
    is_mode(&mode).then_some(mode)
}

/// Check whether the command line invokes a WAFred subcommand.
///
/// Returns `true` if the first non-binary argument is one of the WAFred
/// subcommand names, or if `WAFRED_MODE` environment variable is set.
pub fn is_wafred_mode() -> bool {
    let from_argv = std::env::args().nth(1).is_some_and(|arg| is_mode(&arg));
    from_argv || mode_from_env().is_some()
}

/// The version banner shared with the pingap-mode `--version`.
fn version_banner() -> &'static str {
    crate::version_banner()
}

/// Print the version and exit. `--version` carries the long banner, `-V` the
/// bare number, matching how clap answers the two forms elsewhere.
///
/// clap serves `--version` from the top-level command, which an injected
/// subcommand hides, so the flag is answered here instead.
fn print_version(args: &[String]) -> ! {
    if args.iter().skip(1).any(|arg| arg == "--version") {
        println!("wafred {}", version_banner());
    } else {
        println!("wafred {}", env!("CARGO_PKG_VERSION"));
    }
    std::process::exit(0);
}

/// Whether the arguments ask for the version rather than a mode.
fn wants_version(args: &[String]) -> bool {
    args.iter()
        .skip(1)
        .any(|arg| arg == "--version" || arg == "-V")
}

/// Reads one secret from a file: surrounding whitespace and the trailing
/// newline are trimmed, and an empty file is refused instead of silently
/// configuring an empty password/key.
fn load_secret_file(path: &Path, flag: &str) -> Result<String, String> {
    let value = std::fs::read_to_string(path).map_err(|err| {
        format!("{flag} {} cannot be read: {err}", path.display())
    })?;
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("{flag} {} is empty", path.display()));
    }
    Ok(value.to_string())
}

fn apply_db_file(db: &mut DbOpts) -> Result<(), String> {
    if let Some(path) = db.db_url_file.as_deref() {
        db.db_url = load_secret_file(path, "--db-url-file")?;
    }
    Ok(())
}

#[cfg(not(feature = "edge"))]
fn apply_common_file(common: &mut CommonOpts) -> Result<(), String> {
    if let Some(path) = common.db_url_file.as_deref() {
        common.db_url = load_secret_file(path, "--db-url-file")?;
    }
    Ok(())
}

fn apply_api_key_file(
    api_key: &mut String,
    file: Option<&Path>,
) -> Result<(), String> {
    if let Some(path) = file {
        *api_key = load_secret_file(path, "--api-key-file")?;
    }
    Ok(())
}

fn apply_user_subcommand(command: &mut UserSubcommand) -> Result<(), String> {
    match command {
        UserSubcommand::List(db) => apply_db_file(db),
        UserSubcommand::AddAdmin(opts) => apply_db_file(&mut opts.db),
        UserSubcommand::ResetPassword(opts) => apply_db_file(&mut opts.db),
    }
}

fn apply_mode_subcommand(command: &mut ModeCommand) -> Result<(), String> {
    match command {
        ModeCommand::Observe(db)
        | ModeCommand::Enforce(db)
        | ModeCommand::Status(db) => apply_db_file(db),
    }
}

fn apply_security_subcommand(
    command: &mut SecurityCommand,
) -> Result<(), String> {
    match command {
        SecurityCommand::Status(db) => apply_db_file(db),
        SecurityCommand::Allowlist(opts) => apply_db_file(&mut opts.db),
    }
}

fn apply_config_subcommand(command: &mut ConfigCommand) -> Result<(), String> {
    match command {
        ConfigCommand::History(opts) => apply_db_file(&mut opts.db),
        ConfigCommand::Show(opts) => apply_db_file(&mut opts.db),
        ConfigCommand::Rollback(opts) => apply_db_file(&mut opts.db),
    }
}

/// Resolves `--db-url-file` / `--api-key-file` over the inline values.
///
/// The file wins over `--db-url`/`--api-key` (and their environment
/// variables): a caller that passes both gets the file, and the inline-secret
/// warning below still tells them the inline value was visible.
fn apply_secret_files(command: &mut WafredCommand) -> Result<(), String> {
    match command {
        WafredCommand::Server(opts) => apply_common_file(&mut opts.common),
        WafredCommand::AllInOne(opts) => {
            apply_common_file(&mut opts.common)?;
            apply_api_key_file(&mut opts.api_key, opts.api_key_file.as_deref())
        },
        WafredCommand::Agent(opts) => {
            apply_api_key_file(&mut opts.api_key, opts.api_key_file.as_deref())
        },
        WafredCommand::User { command } => apply_user_subcommand(command),
        WafredCommand::Mode { command } => apply_mode_subcommand(command),
        WafredCommand::Security { command } => {
            apply_security_subcommand(command)
        },
        WafredCommand::Config { command } => apply_config_subcommand(command),
    }
}

/// True when `flag` appears as `--flag` or `--flag=...` in the raw argv.
fn flag_present(argv: &[String], flag: &str) -> bool {
    let prefix = format!("{flag}=");
    argv.iter()
        .skip(1)
        .any(|arg| arg == flag || arg.starts_with(&prefix))
}

/// Warnings for secrets passed inline: argv is visible to other local users
/// through the process list (`ps`) and often ends up in shell history/CI logs.
/// A `--db-url-file` / `--api-key-file` alternative is offered instead.
fn inline_secret_warnings(argv: &[String]) -> Vec<String> {
    let mut warnings = Vec::new();
    for (flag, file_flag, env) in [
        ("--db-url", "--db-url-file", "WAFRED_DB_URL_FILE"),
        ("--api-key", "--api-key-file", "WAFRED_API_KEY_FILE"),
    ] {
        if flag_present(argv, flag) && !flag_present(argv, file_flag) {
            warnings.push(format!(
                "{flag} is visible to other local users in the process list; \
                 prefer {file_flag} or the {env} environment variable"
            ));
        }
    }
    warnings
}

/// Parse the WAFred CLI from command line arguments.
///
/// If `WAFRED_MODE` is set but no subcommand is given on the command line,
/// injects the mode as a subcommand so that env-only invocation works. The
/// settings of a `--config` file are added last, underneath the command line.
pub fn parse_wafred_cli() -> WafredCli {
    let args: Vec<String> = std::env::args().collect();

    if wants_version(&args) {
        print_version(&args);
    }

    let mode = args
        .get(1)
        .filter(|arg| is_mode(arg))
        .cloned()
        .or_else(mode_from_env);
    let Some(mode) = mode else {
        eprintln!("error: no WAFred subcommand or WAFRED_MODE specified");
        std::process::exit(1);
    };

    let mut argv = if args.get(1).map(String::as_str) == Some(mode.as_str()) {
        args.clone()
    } else {
        let mut injected = args.clone();
        injected.insert(1, mode.clone());
        injected
    };

    // The file's arguments go next to the subcommand so that the command line,
    // parsed after them, still wins.
    match crate::config_file::injections(&mode, &argv) {
        Ok(extra) => {
            argv.splice(2..2, extra);
        },
        Err(err) => {
            eprintln!("wafred: {err}");
            std::process::exit(1);
        },
    }

    let mut cli = WafredCli::parse_from(argv);
    if let Err(err) = apply_secret_files(&mut cli.command) {
        eprintln!("wafred: {err}");
        std::process::exit(1);
    }
    for warning in inline_secret_warnings(&args) {
        eprintln!("warning: {warning}");
    }
    cli
}

/// Parse the command line of the agent-only `wafred-agent` binary.
///
/// Two spellings are accepted:
///
/// * `wafred-agent agent --server-url ...` — the same invocation as
///   `wafred agent`, which matters because a self-upgrade replaces the file
///   with the control plane's all-in-one build while the unit's `ExecStart`
///   keeps saying `... agent`.
/// * `wafred-agent --server-url ...` — the redundant subcommand omitted.
///
/// `--config` layering, `--api-key-file`, `--version` and the inline-secret
/// warnings are shared with [`parse_pingwaf_cli`].
#[cfg(feature = "edge")]
pub fn parse_agent_cli() -> AgentOpts {
    parse_agent_args(std::env::args().collect())
}

#[cfg(feature = "edge")]
fn parse_agent_args(args: Vec<String>) -> AgentOpts {
    if wants_version(&args) {
        print_version(&args);
    }

    let mut argv = args.clone();
    // `--help` and a bare flag list are parsed as `agent ...`, so clap prints
    // the agent's own help instead of the top-level command's.
    if argv.get(1).map(String::as_str) != Some("agent") {
        argv.insert(1, "agent".to_string());
    }

    // The file's arguments go next to the subcommand so the command line,
    // parsed after them, still wins (same contract as `wafred agent`).
    match crate::config_file::injections("agent", &argv) {
        Ok(extra) => {
            argv.splice(2..2, extra);
        },
        Err(err) => {
            eprintln!("wafred-agent: {err}");
            std::process::exit(1);
        },
    }

    let mut cli = PingWafCli::parse_from(argv);
    if let Err(err) = apply_secret_files(&mut cli.command) {
        eprintln!("wafred-agent: {err}");
        std::process::exit(1);
    }
    for warning in inline_secret_warnings(&args) {
        eprintln!("warning: {warning}");
    }
    match cli.command {
        PingWafCommand::Agent(opts) => opts,
        _ => {
            // Only reachable if the injected `agent` was overridden by
            // something clap accepted as a different subcommand; the agent
            // build must not silently start another role.
            eprintln!(
                "wafred-agent only runs the data plane agent (agent mode)"
            );
            std::process::exit(2);
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> WafredCommand {
        WafredCli::try_parse_from(args).unwrap().command
    }

    /// The agent-only binary is invoked both ways: by the installer/unit
    /// (`wafred-agent agent ...`, which is also what a self-upgraded
    /// all-in-one binary understands) and directly (`wafred-agent ...`).
    #[cfg(feature = "edge")]
    #[test]
    fn the_agent_binary_accepts_both_spellings() {
        let opts = parse_agent_args(vec![
            "wafred-agent".to_string(),
            "--server-url=http://control-plane:9090".to_string(),
        ]);
        assert_eq!(opts.server_url, "http://control-plane:9090");

        let opts = parse_agent_args(vec![
            "wafred-agent".to_string(),
            "agent".to_string(),
            "--server-url=http://control-plane-2:9090".to_string(),
        ]);
        assert_eq!(opts.server_url, "http://control-plane-2:9090");
    }

    #[test]
    fn flags_that_default_to_true_can_be_turned_off() {
        // Bare flag and no flag both mean the default; only an explicit value
        // (or environment variable) turns it off.
        let WafredCommand::Agent(opts) = parse(&["wafred", "agent"]) else {
            panic!("expected the agent mode");
        };
        assert!(opts.fail_open);
        assert!(opts.config.is_none());

        let WafredCommand::Agent(opts) =
            parse(&["wafred", "agent", "--fail-open"])
        else {
            panic!("expected the agent mode");
        };
        assert!(opts.fail_open);

        let WafredCommand::Agent(opts) =
            parse(&["wafred", "agent", "--fail-open=false"])
        else {
            panic!("expected the agent mode");
        };
        assert!(!opts.fail_open);
    }

    #[cfg(not(feature = "edge"))]
    #[test]
    fn the_last_spelling_of_an_argument_wins() {
        // The configuration file is layered in as earlier arguments, so an
        // argument repeated on the command line has to override it.
        let WafredCommand::Server(opts) = parse(&[
            "wafred",
            "server",
            "--config=/etc/wafred/wafred.toml",
            "--jwt-secret=from-file-16-chars",
            "--jwt-secret=from-cli-16-chars",
        ]) else {
            panic!("expected the server mode");
        };
        assert_eq!(opts.jwt_secret, "from-cli-16-chars");
        assert_eq!(opts.config.as_deref(), Some("/etc/wafred/wafred.toml"));

        let WafredCommand::AllInOne(opts) = parse(&[
            "wafred",
            "all-in-one",
            "--serve-frontend=false",
            "--serve-frontend",
        ]) else {
            panic!("expected the all-in-one mode");
        };
        assert!(opts.serve_frontend);
    }

    #[test]
    fn every_run_mode_accepts_a_config_file() {
        for mode in RUN_MODES {
            let path = format!("--config=/{mode}.toml");
            let args = ["wafred", mode, path.as_str()];
            let cli = WafredCli::try_parse_from(args).unwrap();
            let config = match cli.command {
                WafredCommand::Server(opts) => opts.config,
                WafredCommand::Agent(opts) => opts.config,
                WafredCommand::AllInOne(opts) => opts.config,
                _ => panic!("{mode} is not a run mode"),
            };
            assert_eq!(
                config.as_deref(),
                Some(format!("/{mode}.toml").as_str())
            );
        }
    }

    #[test]
    fn maintenance_commands_parse_with_their_database_options() {
        let WafredCommand::User { command } = parse(&[
            "wafred",
            "user",
            "add-admin",
            "--email=ops@example.com",
            "--db-url=postgres://other/db",
        ]) else {
            panic!("expected the user command");
        };
        let UserSubcommand::AddAdmin(opts) = command else {
            panic!("expected add-admin");
        };
        assert_eq!(opts.email, "ops@example.com");
        assert_eq!(opts.db.db_url, "postgres://other/db");
        assert!(opts.password.is_none());

        let WafredCommand::Mode { command } =
            parse(&["wafred", "mode", "observe"])
        else {
            panic!("expected the mode command");
        };
        assert!(matches!(command, ModeCommand::Observe(_)));

        let WafredCommand::Security { command } =
            parse(&["wafred", "security", "allowlist", "off"])
        else {
            panic!("expected the security command");
        };
        let SecurityCommand::Allowlist(opts) = command else {
            panic!("expected allowlist");
        };
        assert_eq!(opts.state, OnOff::Off);
        assert!(!opts.force);
    }

    #[test]
    fn config_commands_parse_with_their_filters() {
        let WafredCommand::Config { command } = parse(&[
            "wafred",
            "config",
            "history",
            "--site=global",
            "--limit=5",
            "--db-url=postgres://other/db",
        ]) else {
            panic!("expected the config command");
        };
        let ConfigCommand::History(opts) = command else {
            panic!("expected history");
        };
        assert_eq!(opts.site.as_deref(), Some("global"));
        assert_eq!(opts.limit, 5);
        assert_eq!(opts.db.db_url, "postgres://other/db");

        let WafredCommand::Config { command } =
            parse(&["wafred", "config", "show", "42", "--json"])
        else {
            panic!("expected the config command");
        };
        let ConfigCommand::Show(opts) = command else {
            panic!("expected show");
        };
        assert_eq!(opts.version, 42);
        assert!(opts.json);

        let WafredCommand::Config { command } =
            parse(&["wafred", "config", "rollback", "7", "--yes"])
        else {
            panic!("expected the config command");
        };
        let ConfigCommand::Rollback(opts) = command else {
            panic!("expected rollback");
        };
        assert_eq!(opts.version, 7);
        assert!(opts.yes);
    }

    #[test]
    fn mode_registries_match_the_clap_subcommands() {
        // `is_mode` now derives from clap; the arrays are still used by docs
        // and by this test, so pin them to the real command tree. Without
        // this, a new subcommand was silently invisible to `WAFRED_MODE`
        // and to argv-derived mode selection.
        let mut declared: Vec<String> = WafredCli::command()
            .get_subcommands()
            .map(|command| command.get_name().to_string())
            .filter(|name| name != "help")
            .collect();
        declared.sort();

        let mut registered: Vec<String> = RUN_MODES
            .into_iter()
            .chain(MAINTENANCE_MODES)
            .map(str::to_string)
            .collect();
        registered.sort();
        assert_eq!(
            declared, registered,
            "RUN_MODES/MAINTENANCE_MODES drifted from the clap subcommands"
        );

        for mode in &registered {
            assert!(is_mode(mode), "{mode} must select WAFred mode");
        }
        assert!(!is_mode("reset-password"));
        assert!(!is_mode(""));
    }

    #[test]
    fn the_version_flag_is_recognised_wherever_it_appears() {
        // With WAFRED_MODE the mode is injected, so the flag must be caught
        // before the subcommand would reject it as an unknown argument.
        let argv = |args: &[&str]| {
            args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>()
        };
        assert!(wants_version(&argv(&["wafred", "--version"])));
        assert!(wants_version(&argv(&["wafred", "-V"])));
        assert!(wants_version(&argv(&["wafred", "server", "--version"])));
        assert!(!wants_version(&argv(&["wafred", "server", "--config=x"])));
        assert!(!wants_version(&argv(&["wafred"])));
    }

    /// Writes a secret to a temporary file for the `*-file` option tests.
    fn secret_file(contents: &str) -> tempfile::NamedTempFile {
        use std::io::Write as _;
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        file.write_all(contents.as_bytes())
            .expect("write secret file");
        file.flush().expect("flush secret file");
        file
    }

    #[cfg(not(feature = "edge"))]
    #[test]
    fn db_url_file_is_trimmed_and_wins_over_the_inline_value() {
        let file = secret_file("postgres://file:pw@db:5432/wafred\n\n");
        let path = file.path().to_str().unwrap();
        let mut cli = WafredCli::try_parse_from([
            "wafred",
            "server",
            "--db-url=postgres://inline:pw@inline:5432/wafred",
            &format!("--db-url-file={path}"),
        ])
        .unwrap();
        apply_secret_files(&mut cli.command).unwrap();
        let WafredCommand::Server(opts) = cli.command else {
            panic!("expected the server mode");
        };
        assert_eq!(opts.common.db_url, "postgres://file:pw@db:5432/wafred");
    }

    #[test]
    fn agent_api_key_file_is_applied() {
        let file = secret_file("pwk_from_file\n");
        let path = file.path().to_str().unwrap();
        let mut cli = WafredCli::try_parse_from([
            "wafred",
            "agent",
            "--api-key=pwk_inline",
            &format!("--api-key-file={path}"),
        ])
        .unwrap();
        apply_secret_files(&mut cli.command).unwrap();
        let WafredCommand::Agent(opts) = cli.command else {
            panic!("expected the agent mode");
        };
        assert_eq!(opts.api_key, "pwk_from_file");
    }

    #[test]
    fn maintenance_commands_accept_a_db_url_file() {
        let file = secret_file("postgres://file:pw@db:5432/wafred");
        let path = file.path().to_str().unwrap();
        let mut cli = WafredCli::try_parse_from([
            "wafred",
            "user",
            "list",
            &format!("--db-url-file={path}"),
        ])
        .unwrap();
        apply_secret_files(&mut cli.command).unwrap();
        let WafredCommand::User {
            command: UserSubcommand::List(opts),
        } = cli.command
        else {
            panic!("expected the user list command");
        };
        assert_eq!(opts.db_url, "postgres://file:pw@db:5432/wafred");
    }

    #[cfg(not(feature = "edge"))]
    #[test]
    fn empty_or_missing_secret_files_are_refused() {
        let empty = secret_file("  \n");
        let path = empty.path().to_str().unwrap();
        let mut cli = WafredCli::try_parse_from([
            "wafred",
            "server",
            &format!("--db-url-file={path}"),
        ])
        .unwrap();
        let err = apply_secret_files(&mut cli.command).unwrap_err();
        assert!(err.contains("is empty"), "unexpected error: {err}");

        let mut cli = WafredCli::try_parse_from([
            "wafred",
            "server",
            "--db-url-file=/nonexistent/secret-file",
        ])
        .unwrap();
        let err = apply_secret_files(&mut cli.command).unwrap_err();
        assert!(err.contains("cannot be read"), "unexpected error: {err}");
    }

    #[test]
    fn inline_secrets_warn_but_file_flags_do_not() {
        let argv = |args: &[&str]| {
            args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>()
        };

        let warnings =
            inline_secret_warnings(&argv(&["wafred", "server", "--db-url=x"]));
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("--db-url"));
        assert!(warnings[0].contains("--db-url-file"));

        assert!(
            inline_secret_warnings(&argv(&[
                "wafred",
                "server",
                "--db-url-file=/run/secrets/db-url",
            ]))
            .is_empty()
        );

        let warnings = inline_secret_warnings(&argv(&[
            "wafred",
            "agent",
            "--api-key=pwk_x",
        ]));
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("--api-key"));

        assert!(
            inline_secret_warnings(&argv(&[
                "wafred",
                "agent",
                "--api-key-file=/run/secrets/api-key",
            ]))
            .is_empty()
        );

        // Values passed through the environment are not in argv, so no
        // warning is emitted for them.
        assert!(
            inline_secret_warnings(&argv(&["wafred", "server"])).is_empty()
        );
    }

    #[test]
    fn flag_presence_matches_both_spellings() {
        let argv = |args: &[&str]| {
            args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>()
        };
        let args = argv(&["wafred", "server", "--db-url", "x"]);
        assert!(flag_present(&args, "--db-url"));
        let args = argv(&["wafred", "server", "--db-url=x"]);
        assert!(flag_present(&args, "--db-url"));
        let args = argv(&["wafred", "server", "--db-url-file=x"]);
        assert!(!flag_present(&args, "--db-url"));
    }
}
