//! Entry point of the standalone tunnel connector (`wafred-tunnel`).
//!
//! The binary only ever dials out: the control plane for pairing and policy, the
//! edge ingresses for the data plane. It is shipped as its own archive because a
//! private-network host has no reason to run the data plane or the control
//! plane, and because the connector is the only piece that needs to be
//! installed inside that network.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

use wafred_tunnel::client::pair::{self, PairConfig};
use wafred_tunnel::client::{Connector, ConnectorConfig, IngressEndpoint};
use wafred_tunnel::socks5::Socks5Proxy;

/// Default location of the connector's configuration (and its credential).
const DEFAULT_CONFIG: &str = "/etc/wafred/tunnel.toml";

#[derive(Parser, Debug)]
#[command(
    name = "wafred-tunnel",
    version,
    about = "WAFred tunnel connector: serve a NATed origin through the edge without an inbound port",
    after_help = "Run `wafred-tunnel run --token <pairing-token> --server-url https://<control-plane>:9090` \
                  on a fresh host to pair and start serving."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Configuration file (written by `pair`, read by `run`/`status`).
    #[arg(long, global = true, default_value = DEFAULT_CONFIG, env = "WAFRED_TUNNEL_CONFIG")]
    config: PathBuf,

    /// Where `run` publishes its live state and `status` reads it.
    #[arg(
        long,
        global = true,
        default_value = "/var/lib/wafred/tunnel/status.json",
        env = "WAFRED_TUNNEL_STATUS_FILE"
    )]
    status_file: PathBuf,

    /// One-time pairing token from the console (Tunnels tab).
    #[arg(long, global = true, env = "WAFRED_TUNNEL_TOKEN")]
    token: Option<String>,

    /// Read the pairing token from a file instead of `--token`: a token on the
    /// command line is visible to every local user through `ps` for as long as
    /// the process runs.
    #[arg(long, global = true, env = "WAFRED_TUNNEL_TOKEN_FILE")]
    token_file: Option<PathBuf>,

    /// Control-plane gRPC endpoint, e.g. `https://cp.example.com:9090`.
    #[arg(long, global = true, env = "WAFRED_TUNNEL_SERVER_URL")]
    server_url: Option<String>,

    /// PEM file with the CA that signed the control plane's certificate.
    #[arg(long, global = true, env = "WAFRED_TUNNEL_SERVER_CA")]
    server_ca_cert: Option<String>,

    /// Name used for SNI and certificate verification when it differs from the
    /// host in `--server-url`.
    #[arg(long, global = true, env = "WAFRED_TUNNEL_SERVER_TLS_NAME")]
    server_tls_name: Option<String>,

    /// SOCKS5 proxy for a host with no direct egress, e.g.
    /// `socks5://user:pass@10.0.0.1:1080` or `10.0.0.1:1080`.
    #[arg(long, global = true, env = "WAFRED_TUNNEL_SOCKS5_PROXY")]
    socks5_proxy: Option<String>,

    /// SOCKS5 username (wins over userinfo embedded in `--socks5-proxy`).
    #[arg(long, global = true, env = "WAFRED_TUNNEL_SOCKS5_USERNAME")]
    socks5_username: Option<String>,

    /// SOCKS5 password. Prefer the environment variable over the flag: a flag
    /// is visible in `ps`.
    #[arg(long, global = true, env = "WAFRED_TUNNEL_SOCKS5_PASSWORD")]
    socks5_password: Option<String>,

    /// Edge ingresses as `host:port[=sha256fingerprint]`, comma separated.
    ///
    /// Only needed when the connector is configured by hand; pairing returns
    /// the list (with fingerprints) from the control plane.
    #[arg(long, global = true, env = "WAFRED_TUNNEL_INGRESS")]
    ingress: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the connector (the default when no subcommand is given).
    Run,
    /// Redeem a pairing token and write the configuration, then exit.
    Pair,
    /// Print the stored configuration and, when reachable, the live policy.
    Status,
}

/// The on-disk configuration. The credential lives here, so the file is `0600`.
#[derive(Debug, Default, Serialize, Deserialize)]
struct TunnelFile {
    #[serde(default)]
    tunnel_id: String,
    #[serde(default)]
    credential: String,
    #[serde(default)]
    server_url: String,
    #[serde(default)]
    server_ca_cert: Option<String>,
    #[serde(default)]
    server_tls_name: Option<String>,
    /// Local second line of defence; empty means "whatever the control plane
    /// says".
    #[serde(default)]
    allowed_targets: Vec<String>,
    /// SOCKS5 proxy every outbound dial goes through. Set it on a host that
    /// has no direct egress; the connector reaches both the control plane and
    /// the edge ingresses through it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    socks5_proxy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    socks5_username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    socks5_password: Option<String>,
    #[serde(default)]
    ingress: Vec<IngressEndpoint>,
    /// Session token from the last run. Kept so a restart can still open edge
    /// sessions while the control plane is briefly unreachable; the edges
    /// enforce its expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    session_token: Option<String>,
    #[serde(default, skip_serializing_if = "is_zero")]
    session_token_expires_at: i64,
}

fn is_zero(value: &i64) -> bool {
    *value == 0
}

impl TunnelFile {
    fn load(path: &Path) -> Result<Option<Self>> {
        if !path.is_file() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        let file: Self = toml::from_str(&raw)
            .with_context(|| format!("cannot parse {}", path.display()))?;
        Ok(Some(file))
    }

    fn store(&self, path: &Path) -> Result<()> {
        let body = toml::to_string_pretty(self)
            .context("cannot serialize the configuration")?;
        let parent = path.parent().ok_or_else(|| {
            anyhow::anyhow!("{} has no parent directory", path.display())
        })?;
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
        let tmp = parent.join(format!(
            ".{}.tmp",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("tunnel.toml")
        ));
        {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(&tmp)
                .with_context(|| format!("cannot write {}", tmp.display()))?;
            file.write_all(body.as_bytes())?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp, path)
            .context("cannot move the configuration into place")?;
        Ok(())
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    // The host binary installs ring for the whole process; the connector is its
    // own process, so it does the same before any TLS client is built.
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let mut cli = Cli::parse();
    match cli.command.take().unwrap_or(Command::Run) {
        Command::Run => run(cli).await,
        Command::Pair => pair_command(cli).await,
        Command::Status => status(cli).await,
    }
}

async fn pair_command(cli: Cli) -> Result<()> {
    let mut file = TunnelFile::load(&cli.config)?.unwrap_or_default();
    apply_overrides(&mut file, &cli);
    pair_into(&mut file, &cli).await?;
    file.store(&cli.config)?;
    println!(
        "paired tunnel {} ({})",
        file.tunnel_id,
        if file.ingress.is_empty() {
            "no ingress advertised".to_string()
        } else {
            format!("{} ingress endpoint(s)", file.ingress.len())
        }
    );
    println!("configuration written to {}", cli.config.display());
    Ok(())
}

async fn run(cli: Cli) -> Result<()> {
    let mut file = TunnelFile::load(&cli.config)?.unwrap_or_default();
    apply_overrides(&mut file, &cli);
    if cli.token.is_some() {
        pair_into(&mut file, &cli).await?;
        file.store(&cli.config)?;
    }
    if file.tunnel_id.is_empty() || file.credential.is_empty() {
        bail!(
            "no tunnel is paired yet: pass --token <pairing-token> --server-url <control-plane> once \
             (the console's Tunnels tab shows the exact command), or write {}",
            cli.config.display()
        );
    }
    if file.server_url.is_empty() {
        bail!(
            "no control-plane URL: set --server-url or `server_url` in {}",
            cli.config.display()
        );
    }

    let config = ConnectorConfig {
        tunnel_id: file.tunnel_id.clone(),
        credential: file.credential.clone(),
        server_url: file.server_url.clone(),
        server_ca_cert: file.server_ca_cert.clone(),
        server_ca_pem: None,
        server_tls_name: file.server_tls_name.clone(),
        ingress: file.ingress.clone(),
        allowed_targets: file.allowed_targets.clone(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        hostname: hostname(),
        os: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        session_token: file.session_token.clone(),
        socks5: configured_proxy(&file, &cli)?,
    };
    let connector = Connector::new(config);
    // Publish the live state for `status`; best effort — an unwritable path
    // must never keep the connector from serving.
    let status_path = cli.status_file.clone();
    let status_connector = Arc::clone(&connector);
    let status_task = tokio::spawn(async move {
        loop {
            let state = status_connector.state();
            RuntimeStatus {
                updated_at: chrono::Utc::now().to_rfc3339(),
                tunnel_id: status_connector.tunnel_id().to_string(),
                sessions: status_connector.connected_ingress(),
                targets: state.targets.clone(),
                revoked: state.revoked.clone(),
            }
            .store(&status_path);
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    });
    let runner = tokio::spawn(Arc::clone(&connector).run());
    tokio::select! {
        result = runner => {
            result.map_err(|err| anyhow::anyhow!("connector task failed: {err}"))??;
        },
        _ = shutdown_signal() => {
            tracing::info!(target: "wafred::tunnel", "received a shutdown signal");
        },
    }
    status_task.abort();
    Ok(())
}

async fn status(cli: Cli) -> Result<()> {
    let Some(file) = TunnelFile::load(&cli.config)? else {
        println!("no configuration at {}", cli.config.display());
        return Ok(());
    };
    println!(
        "tunnel id     : {}",
        if file.tunnel_id.is_empty() {
            "(unpaired)"
        } else {
            &file.tunnel_id
        }
    );
    println!(
        "control plane : {}",
        if file.server_url.is_empty() {
            "(unset)"
        } else {
            &file.server_url
        }
    );
    println!(
        "credential    : {}",
        if file.credential.is_empty() {
            "(none)"
        } else {
            "(stored, redacted)"
        }
    );
    println!(
        "ingress       : {}",
        if file.ingress.is_empty() {
            "(none — set a Tunnel ingress address on an edge)".to_string()
        } else {
            file.ingress
                .iter()
                .map(|entry| entry.endpoint.clone())
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
    if let Some(proxy) = &file.socks5_proxy {
        println!(
            "socks5 proxy  : {}{}",
            proxy,
            if file.socks5_username.is_some() {
                " (authenticated)"
            } else {
                ""
            }
        );
    }
    println!(
        "local targets : {}",
        if file.allowed_targets.is_empty() {
            "(follow the control plane)".to_string()
        } else {
            file.allowed_targets.join(", ")
        }
    );

    // The live state comes from the file `run` maintains. Deliberately not a
    // control-plane probe: a second TunnelControl stream would take the slot
    // of the connector that is actually serving traffic.
    match RuntimeStatus::load(&cli.status_file) {
        Ok(Some(status)) => {
            println!();
            println!("live state    : updated {}", status.updated_at);
            println!(
                "  sessions    : {}",
                if status.sessions.is_empty() {
                    "(none)".to_string()
                } else {
                    status.sessions.join(", ")
                }
            );
            println!(
                "  targets     : {}",
                if status.targets.is_empty() {
                    "(none)".to_string()
                } else {
                    status.targets.join(", ")
                }
            );
            if let Some(reason) = &status.revoked {
                println!("  revoked     : {reason}");
            }
        },
        Ok(None) => println!(
            "\nlive state    : not running (no {} yet)",
            cli.status_file.display()
        ),
        Err(error) => println!("\nlive state    : unreadable ({error})"),
    }
    Ok(())
}

/// What `run` publishes for `status` (and for an operator reading the file).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct RuntimeStatus {
    updated_at: String,
    tunnel_id: String,
    /// Ingress endpoints a session is currently established to.
    sessions: Vec<String>,
    targets: Vec<String>,
    revoked: Option<String>,
}

impl RuntimeStatus {
    fn load(path: &Path) -> Result<Option<Self>> {
        if !path.is_file() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        Ok(serde_json::from_str(&raw).ok())
    }

    fn store(&self, path: &Path) {
        let Ok(body) = serde_json::to_vec_pretty(self) else {
            return;
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(path, body);
    }
}

/// Redeems `--token` and folds the answer into `file`.
async fn pair_into(file: &mut TunnelFile, cli: &Cli) -> Result<()> {
    // The file wins when both are given: it is the form that does not leak the
    // token into the process list.
    let token = match cli.token_file.as_deref() {
        Some(path) => Some(
            std::fs::read_to_string(path)
                .with_context(|| format!("cannot read {}", path.display()))?
                .trim()
                .to_string(),
        ),
        None => cli.token.clone(),
    };
    let Some(token) = token.filter(|value| !value.is_empty()) else {
        bail!("pairing needs --token or --token-file");
    };
    if file.server_url.is_empty() {
        bail!("pairing needs --server-url https://<control-plane>:9090");
    }
    let server_url = file.server_url.clone();
    let outcome = pair::pair(&PairConfig {
        server_url,
        server_ca_cert: file.server_ca_cert.clone(),
        server_ca_pem: None,
        server_tls_name: file.server_tls_name.clone(),
        pairing_token: token,
        hostname: hostname(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        os: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        socks5: configured_proxy(file, cli)?,
    })
    .await?;
    file.tunnel_id = outcome.tunnel_id;
    file.credential = outcome.credential;
    if !outcome.session_token.is_empty() {
        file.session_token = Some(outcome.session_token);
        file.session_token_expires_at = outcome.session_token_expires_at;
    }
    if !outcome.ingress.is_empty() {
        file.ingress = outcome.ingress;
    }
    tracing::info!(
        target: "wafred::tunnel",
        tunnel = %file.tunnel_id,
        name = %outcome.name,
        ingress = file.ingress.len(),
        targets = outcome.targets.len(),
        "tunnel paired"
    );
    Ok(())
}

/// The configured SOCKS5 proxy, when there is one.
///
/// Explicit flags win over the file; a malformed value is an error rather than
/// a silent direct dial, because a host that needs the proxy cannot reach
/// anything without it.
fn configured_proxy(
    file: &TunnelFile,
    cli: &Cli,
) -> Result<Option<Socks5Proxy>> {
    let Some(raw) = cli
        .socks5_proxy
        .clone()
        .or_else(|| file.socks5_proxy.clone())
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(None);
    };
    let username = cli
        .socks5_username
        .clone()
        .or_else(|| file.socks5_username.clone());
    let password = cli
        .socks5_password
        .clone()
        .or_else(|| file.socks5_password.clone());
    Socks5Proxy::parse(&raw, username, password).map(Some)
}

/// CLI flags win over the file.
fn apply_overrides(file: &mut TunnelFile, cli: &Cli) {
    if let Some(url) = &cli.server_url {
        file.server_url = url.clone();
    }
    if let Some(ca) = &cli.server_ca_cert {
        file.server_ca_cert = Some(ca.clone());
    }
    if let Some(name) = &cli.server_tls_name {
        file.server_tls_name = Some(name.clone());
    }
    if let Some(raw) = &cli.ingress {
        let ingress = parse_ingress(raw);
        if !ingress.is_empty() {
            file.ingress = ingress;
        }
    }
    if let Some(raw) = &cli.socks5_proxy {
        file.socks5_proxy = Some(raw.clone());
    }
    if let Some(value) = &cli.socks5_username {
        file.socks5_username = Some(value.clone());
    }
    if let Some(value) = &cli.socks5_password {
        file.socks5_password = Some(value.clone());
    }
}

/// Parses `host:port[=fp[;fp]]` entries.
fn parse_ingress(raw: &str) -> Vec<IngressEndpoint> {
    raw.split(',')
        .filter_map(|entry| {
            let entry = entry.trim();
            if entry.is_empty() {
                return None;
            }
            let (endpoint, fingerprints) = match entry.split_once('=') {
                Some((endpoint, fingerprints)) => (
                    endpoint.trim(),
                    fingerprints
                        .split(';')
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty())
                        .collect(),
                ),
                None => (entry, Vec::new()),
            };
            Some(IngressEndpoint {
                endpoint: endpoint.to_string(),
                fingerprints,
            })
        })
        .collect()
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            std::env::var("HOSTNAME")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        ) {
            signal.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ingress_parsing_accepts_bare_and_pinned_entries() {
        let parsed = parse_ingress("waf1.example:9443=ab, waf2.example:9443");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].endpoint, "waf1.example:9443");
        assert_eq!(parsed[0].fingerprints, vec!["ab".to_string()]);
        assert!(parsed[1].fingerprints.is_empty());
    }

    #[test]
    fn a_round_trip_through_the_config_file_keeps_the_credential() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tunnel.toml");
        let file = TunnelFile {
            tunnel_id: "t-1".to_string(),
            credential: "secret".to_string(),
            server_url: "https://cp:9090".to_string(),
            ingress: vec![IngressEndpoint {
                endpoint: "waf1:9443".to_string(),
                fingerprints: vec!["ab".to_string()],
            }],
            ..TunnelFile::default()
        };
        file.store(&path).unwrap();
        let loaded = TunnelFile::load(&path).unwrap().unwrap();
        assert_eq!(loaded.tunnel_id, "t-1");
        assert_eq!(loaded.credential, "secret");
        assert_eq!(loaded.ingress.len(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "the credential file must be owner-only"
            );
        }
    }
}
