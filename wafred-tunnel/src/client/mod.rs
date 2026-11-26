//! The tunnel connector: the process that runs inside the private network.
//!
//! It dials out to the control plane (pairing, config) and to every edge
//! ingress (the data plane). Nothing dials in, which is what makes it work
//! behind NAT. Each edge connection carries one yamux session: the connector
//! opens a control stream (hello, heartbeats, policy), and the edge opens one
//! data stream per proxied connection, each of which the connector turns into a
//! TCP connection to the internal target.

pub mod pair;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use futures::future::poll_fn;
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{Notify, mpsc, watch};
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::{debug, info, warn};

use crate::protocol::{
    ControlFrame, PROTOCOL_VERSION, TunnelSettings, normalize_target,
    read_frame, read_open_target, write_frame,
};

/// Time allowed to reach an ingress endpoint.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Time allowed for the TLS handshake with an ingress.
const TLS_TIMEOUT: Duration = Duration::from_secs(10);
/// Time allowed for the hello exchange.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// Time allowed to reach an internal target.
const TARGET_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Backoff bounds for reconnects (control plane and ingress alike).
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);

/// One edge ingress the connector dials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressEndpoint {
    /// `host:port` of the edge's tunnel listener.
    pub endpoint: String,
    /// Lower-case hex SHA-256 of the edge's tunnel certificate.
    #[serde(default)]
    pub fingerprints: Vec<String>,
}

/// What the control plane last told the connector.
#[derive(Debug, Clone, Default)]
pub struct ConnectorState {
    pub ingress: Vec<IngressEndpoint>,
    /// Targets this connector may dial, as decided by the control plane.
    pub targets: Vec<String>,
    pub settings: TunnelSettings,
    pub enabled: bool,
    /// Set when the tunnel was revoked; the process stops.
    pub revoked: Option<String>,
    /// Short-lived token the edges verify. Minted by the control plane on
    /// connect and refreshed on every config push.
    pub session_token: Option<String>,
    /// Unix seconds the token expires at; 0 = unknown.
    pub session_token_expires_at: i64,
}

impl ConnectorState {
    fn allows(&self, target: &str) -> bool {
        self.enabled && self.targets.iter().any(|entry| entry == target)
    }
}

/// What the session loop should do with the current connector state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionAction {
    /// The tunnel was revoked: stop for good.
    Stop,
    /// Tunnels are disabled deployment-wide: wait, do not dial.
    Wait,
    /// Dial (or redial) the edge.
    Connect,
}

fn session_action(state: &ConnectorState) -> SessionAction {
    if state.revoked.is_some() {
        return SessionAction::Stop;
    }
    if !state.enabled {
        return SessionAction::Wait;
    }
    SessionAction::Connect
}

/// Static configuration of one connector process.
#[derive(Debug, Clone)]
pub struct ConnectorConfig {
    pub tunnel_id: String,
    pub credential: String,
    pub server_url: String,
    pub server_ca_cert: Option<String>,
    pub server_ca_pem: Option<String>,
    pub server_tls_name: Option<String>,
    /// Ingress endpoints from the config file, used until the control plane
    /// answers (and whenever it cannot be reached).
    pub ingress: Vec<IngressEndpoint>,
    /// Local second line of defence: when non-empty, a target must be both in
    /// this list and in the control plane's list.
    pub allowed_targets: Vec<String>,
    pub version: String,
    pub hostname: String,
    pub os: String,
    /// A session token cached from the last run (config file), used until the
    /// control plane pushes a fresh one.
    pub session_token: Option<String>,
    /// SOCKS5 proxy every outbound dial goes through, for a connector that has
    /// no direct egress.
    pub socks5: Option<crate::socks5::Socks5Proxy>,
}

/// The running connector.
pub struct Connector {
    config: Arc<ConnectorConfig>,
    state: Arc<RwLock<ConnectorState>>,
    changed: Arc<Notify>,
    active_streams: Arc<AtomicU32>,
    live_sessions: Arc<AtomicU32>,
    /// Ingress endpoints with an established session, for `status`.
    connected: std::sync::Mutex<std::collections::HashSet<String>>,
}

impl Connector {
    pub fn new(config: ConnectorConfig) -> Arc<Self> {
        // Until the control plane answers, the config file's targets are the
        // policy; an empty list means "whatever the control plane says".
        let state = ConnectorState {
            ingress: config.ingress.clone(),
            targets: config.allowed_targets.clone(),
            settings: TunnelSettings::default(),
            enabled: true,
            revoked: None,
            session_token: config.session_token.clone(),
            session_token_expires_at: 0,
        };
        Arc::new(Self {
            config: Arc::new(config),
            state: Arc::new(RwLock::new(state)),
            changed: Arc::new(Notify::new()),
            active_streams: Arc::new(AtomicU32::new(0)),
            live_sessions: Arc::new(AtomicU32::new(0)),
            connected: std::sync::Mutex::new(std::collections::HashSet::new()),
        })
    }

    pub fn tunnel_id(&self) -> &str {
        &self.config.tunnel_id
    }

    /// Ingress endpoints that currently hold a session, sorted for stable
    /// output in `wafred-tunnel status`.
    pub fn connected_ingress(&self) -> Vec<String> {
        let mut endpoints: Vec<String> = self
            .connected
            .lock()
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default();
        endpoints.sort();
        endpoints
    }

    fn note_connected(&self, endpoint: &str, connected: bool) {
        if let Ok(mut set) = self.connected.lock() {
            if connected {
                set.insert(endpoint.to_string());
            } else {
                set.remove(endpoint);
            }
        }
    }

    pub fn state(&self) -> ConnectorState {
        self.state
            .read()
            .map(|state| state.clone())
            .unwrap_or_default()
    }

    /// Runs until the tunnel is revoked or the process is stopped.
    pub async fn run(self: Arc<Self>) -> Result<()> {
        info!(
            target: "pingwaf::tunnel",
            tunnel = %self.config.tunnel_id,
            ingress = self.state().ingress.len(),
            "tunnel connector starting"
        );
        let control = tokio::spawn(Arc::clone(&self).control_plane_loop());
        let mut sessions: HashMap<String, JoinHandle<()>> = HashMap::new();

        loop {
            let state = self.state();
            if let Some(reason) = &state.revoked {
                warn!(
                    target: "pingwaf::tunnel",
                    tunnel = %self.config.tunnel_id,
                    reason = %reason,
                    "tunnel was revoked; stopping"
                );
                break;
            }
            let desired: Vec<IngressEndpoint> = if state.ingress.is_empty() {
                self.config.ingress.clone()
            } else {
                state.ingress.clone()
            };
            if desired.is_empty() {
                // Nothing to dial yet: the control plane has not handed out an
                // ingress list and the config file carries none. Say so once
                // per wait instead of looking healthy while doing nothing.
                warn!(
                    target: "pingwaf::tunnel",
                    tunnel = %self.config.tunnel_id,
                    "no tunnel ingress configured or advertised yet; \
                     set an ingress address on an edge or pass --ingress"
                );
            }
            // Stop sessions for endpoints that are no longer wanted.
            let wanted: Vec<&str> = desired
                .iter()
                .map(|entry| entry.endpoint.as_str())
                .collect();
            sessions.retain(|endpoint, handle| {
                let keep = wanted.contains(&endpoint.as_str());
                if !keep {
                    handle.abort();
                }
                keep
            });
            // Start sessions for new endpoints.
            for ingress in desired {
                if sessions.contains_key(&ingress.endpoint) {
                    continue;
                }
                let handle = tokio::spawn(
                    Arc::clone(&self).session_loop(ingress.clone()),
                );
                sessions.insert(ingress.endpoint, handle);
            }

            tokio::select! {
                _ = self.changed.notified() => {},
                _ = tokio::time::sleep(Duration::from_secs(30)) => {},
            }
        }

        for (_, handle) in sessions {
            handle.abort();
        }
        control.abort();
        Ok(())
    }

    /// Keeps one ingress connection alive, reconnecting with backoff.
    async fn session_loop(self: Arc<Self>, ingress: IngressEndpoint) {
        let mut backoff = BACKOFF_MIN;
        loop {
            match session_action(&self.state()) {
                SessionAction::Stop => return,
                SessionAction::Wait => {
                    // The deployment-wide switch is off: the edge has already
                    // been told to close this session, and dialing again would
                    // only produce a refusal every backoff window. Wait for
                    // the next push instead (the control plane notifies on a
                    // settings change).
                    info!(
                        target: "pingwaf::tunnel",
                        endpoint = %ingress.endpoint,
                        "tunnel support is disabled deployment-wide; waiting for it to be re-enabled"
                    );
                    self.changed.notified().await;
                    backoff = BACKOFF_MIN;
                    continue;
                },
                SessionAction::Connect => {},
            }
            match Arc::clone(&self).run_session(ingress.clone()).await {
                Ok(()) => {
                    backoff = BACKOFF_MIN;
                    info!(
                        target: "pingwaf::tunnel",
                        endpoint = %ingress.endpoint,
                        "tunnel session closed by the edge, reconnecting"
                    );
                },
                Err(error) => {
                    warn!(
                        target: "pingwaf::tunnel",
                        endpoint = %ingress.endpoint,
                        error = %error,
                        retry_in_secs = backoff.as_secs(),
                        "tunnel session failed"
                    );
                },
            }
            let jitter = Duration::from_millis(rand::random::<u64>() % 1000);
            // Wait out the backoff, but wake as soon as the control plane
            // pushes something (a fresh session token after a rotation, a new
            // ingress list): retrying a refused token should not cost a full
            // backoff window.
            tokio::select! {
                _ = tokio::time::sleep(backoff + jitter) => {},
                _ = self.changed.notified() => {},
            }
            backoff = (backoff * 2).min(BACKOFF_MAX);
        }
    }

    /// One connection to one edge ingress, from TLS to the last data stream.
    async fn run_session(
        self: Arc<Self>,
        ingress: IngressEndpoint,
    ) -> Result<()> {
        if ingress.fingerprints.is_empty() {
            bail!(
                "ingress {} carries no pinned certificate fingerprint; re-pair the connector",
                ingress.endpoint
            );
        }
        let tcp = self.dial(&ingress.endpoint, CONNECT_TIMEOUT).await?;
        let _ = tcp.set_nodelay(true);

        let provider = crate::verify::default_provider()?;
        let tls_config =
            crate::verify::client_config(&ingress.fingerprints, provider)?;
        let connector = TlsConnector::from(Arc::new(tls_config));
        let server_name = server_name_for(&ingress.endpoint)?;
        let tls = tokio::time::timeout(
            TLS_TIMEOUT,
            connector.connect(server_name, tcp),
        )
        .await
        .map_err(|_| {
            anyhow!("TLS handshake with {} timed out", ingress.endpoint)
        })?
        .with_context(|| {
            format!("TLS handshake with {} failed", ingress.endpoint)
        })?;

        let mut yamux_config = yamux::Config::default();
        // Match the edge's ceiling so a policy limit above yamux's 512 default
        // is not silently capped by the multiplexer.
        yamux_config.set_max_num_streams(4096);
        let mut connection = yamux::Connection::new(
            tls.compat(),
            yamux_config,
            yamux::Mode::Client,
        );
        let control = poll_fn(|cx| connection.poll_new_outbound(cx))
            .await
            .context("cannot open the tunnel control stream")?;
        let mut control = control.compat();

        // The connection has to be driven from the moment it exists: yamux
        // moves a stream's bytes only while the connection is polled, so
        // waiting for the hello without a driver would deadlock.
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut data = tokio::spawn(data_loop(
            Arc::clone(&self),
            connection,
            shutdown_rx.clone(),
        ));

        let hello_result = self.exchange_hello(&mut control).await;
        let (policy_version, allowed, settings) = match hello_result {
            Ok(answer) => answer,
            Err(error) => {
                let _ = shutdown_tx.send(true);
                data.abort();
                return Err(error);
            },
        };
        {
            let mut guard = self
                .state
                .write()
                .map_err(|_| anyhow!("connector state lock poisoned"))?;
            guard.targets = allowed.clone();
            guard.settings = settings.clone();
            guard.enabled = true;
        }
        self.changed.notify_waiters();
        self.live_sessions.fetch_add(1, Ordering::SeqCst);
        self.note_connected(&ingress.endpoint, true);
        info!(
            target: "pingwaf::tunnel",
            endpoint = %ingress.endpoint,
            tunnel = %self.config.tunnel_id,
            targets = allowed.len(),
            "tunnel session established"
        );

        let control_task = tokio::spawn(control_loop(
            Arc::clone(&self),
            control,
            shutdown_tx.clone(),
            shutdown_rx.clone(),
        ));
        let _ = policy_version;
        // The session lives as long as either half does.
        tokio::select! {
            _ = &mut data => {},
            _ = control_task => {},
        }
        self.live_sessions.fetch_sub(1, Ordering::SeqCst);
        self.note_connected(&ingress.endpoint, false);
        let _ = shutdown_tx.send(true);
        data.abort();
        Ok(())
    }

    /// The targets this connector may dial: valid `host:port`, and inside the
    /// local `allowed_targets` allowlist when one is configured.
    ///
    /// Every policy path (handshake, `PolicyUpdate`, pushed `Config`) goes
    /// through this, so the local allowlist cannot be bypassed by whichever
    /// frame happens to arrive last.
    fn policy_targets(&self, targets: Vec<String>) -> Vec<String> {
        targets
            .into_iter()
            .filter(|target| {
                normalize_target(target).is_some()
                    && (self.config.allowed_targets.is_empty()
                        || self
                            .config
                            .allowed_targets
                            .iter()
                            .any(|entry| entry == target))
            })
            .collect()
    }

    /// Sends the hello and validates the edge's answer.
    async fn exchange_hello(
        &self,
        control: &mut tokio_util::compat::Compat<yamux::Stream>,
    ) -> Result<(u64, Vec<String>, TunnelSettings)> {
        write_frame(
            control,
            &ControlFrame::Hello {
                protocol: PROTOCOL_VERSION,
                tunnel_id: self.config.tunnel_id.clone(),
                token: self
                    .state()
                    .session_token
                    .ok_or_else(|| {
                        anyhow!(
                            "no tunnel session token yet; the control plane issues one on connect"
                        )
                    })?,
                version: self.config.version.clone(),
                hostname: self.config.hostname.clone(),
                os: self.config.os.clone(),
            },
        )
        .await
        .context("cannot send the tunnel hello")?;
        let answer = tokio::time::timeout(HELLO_TIMEOUT, read_frame(control))
            .await
            .map_err(|_| anyhow!("the edge did not answer the tunnel hello"))?
            .context("cannot read the tunnel hello answer")?;
        let (policy_version, targets, settings) = match answer {
            ControlFrame::HelloOk {
                policy_version,
                targets,
                settings,
            } => (policy_version, targets, settings),
            ControlFrame::Rejected { code, message } => {
                bail!(
                    "the edge refused the session ({}): {message}",
                    code.as_str()
                )
            },
            other => bail!("unexpected answer to the hello: {}", other.kind()),
        };
        let allowed: Vec<String> = targets
            .into_iter()
            .filter(|target| {
                normalize_target(target).is_some()
                    && (self.config.allowed_targets.is_empty()
                        || self
                            .config
                            .allowed_targets
                            .iter()
                            .any(|entry| entry == target))
            })
            .collect();
        Ok((policy_version, allowed, settings))
    }

    /// Opens a TCP connection to `endpoint` (`host:port`), through the SOCKS5
    /// proxy when one is configured.
    ///
    /// Every outbound dial the connector makes goes through here — the
    /// control-plane channel has its own path in `pair::channel` — so an
    /// environment with no direct egress never silently attempts one.
    async fn dial(
        &self,
        endpoint: &str,
        timeout: Duration,
    ) -> Result<TcpStream> {
        let host = host_of(endpoint)?;
        let port = endpoint
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok())
            .ok_or_else(|| anyhow!("{endpoint} is not a valid host:port"))?;
        match &self.config.socks5 {
            Some(proxy) => {
                proxy.connect(host, port, timeout).await.with_context(|| {
                    format!("cannot reach {endpoint} through the socks5 proxy")
                })
            },
            None => tokio::time::timeout(timeout, TcpStream::connect(endpoint))
                .await
                .map_err(|_| anyhow!("connecting to {endpoint} timed out"))?
                .with_context(|| format!("cannot connect to {endpoint}")),
        }
    }

    /// Handles one inbound data stream.
    async fn handle_stream(self: Arc<Self>, stream: yamux::Stream) {
        let settings = self.state().settings;
        let limit = settings.max_streams.max(1);
        let active = self.active_streams.fetch_add(1, Ordering::SeqCst) + 1;
        if active > limit {
            self.active_streams.fetch_sub(1, Ordering::SeqCst);
            debug!(
                target: "pingwaf::tunnel",
                limit,
                "refusing a tunnel data stream: concurrency limit"
            );
            drop(stream);
            return;
        }
        let mut stream = stream.compat();
        let target = match read_open_target(&mut stream).await {
            Ok(target) => target,
            Err(error) => {
                debug!(
                    target: "pingwaf::tunnel",
                    error = %error,
                    "malformed tunnel data stream"
                );
                self.active_streams.fetch_sub(1, Ordering::SeqCst);
                return;
            },
        };
        if !self.state().allows(&target) {
            warn!(
                target: "pingwaf::tunnel",
                target = %target,
                "refusing a tunnel target that is not in the policy"
            );
            self.active_streams.fetch_sub(1, Ordering::SeqCst);
            return;
        }
        let mut socket = match tokio::time::timeout(
            TARGET_CONNECT_TIMEOUT,
            TcpStream::connect(&target),
        )
        .await
        {
            Ok(Ok(socket)) => socket,
            Ok(Err(error)) => {
                warn!(
                    target: "pingwaf::tunnel",
                    target = %target,
                    error = %error,
                    "tunnel target is unreachable"
                );
                self.active_streams.fetch_sub(1, Ordering::SeqCst);
                return;
            },
            Err(_) => {
                warn!(
                    target: "pingwaf::tunnel",
                    target = %target,
                    "tunnel target connection timed out"
                );
                self.active_streams.fetch_sub(1, Ordering::SeqCst);
                return;
            },
        };
        let _ = socket.set_nodelay(true);
        let result =
            tokio::io::copy_bidirectional(&mut socket, &mut stream).await;
        self.active_streams.fetch_sub(1, Ordering::SeqCst);
        match result {
            Ok((from_edge, from_target)) => debug!(
                target: "pingwaf::tunnel",
                target = %target,
                from_edge,
                from_target,
                "tunnel data stream closed"
            ),
            Err(error) => debug!(
                target: "pingwaf::tunnel",
                target = %target,
                error = %error,
                "tunnel data stream ended with an error"
            ),
        }
        let _ = stream.shutdown().await;
        let _ = socket.shutdown().await;
    }

    /// Control-plane loop: keeps the connector's config fresh.
    async fn control_plane_loop(self: Arc<Self>) {
        let mut backoff = BACKOFF_MIN;
        loop {
            if self.state().revoked.is_some() {
                return;
            }
            match Arc::clone(&self).control_once().await {
                Ok(()) => backoff = BACKOFF_MIN,
                Err(error) => {
                    // `warn`, not `debug`: "the connector cannot reach the
                    // control plane" is the failure an operator is looking for
                    // in `journalctl -u wafred-tunnel`, and the backoff keeps
                    // the line at most once a minute.
                    warn!(
                        target: "pingwaf::tunnel",
                        error = %error,
                        retry_in_secs = backoff.as_secs(),
                        "cannot reach the control plane"
                    );
                },
            }
            if self.state().revoked.is_some() {
                return;
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(BACKOFF_MAX);
        }
    }

    async fn control_once(self: Arc<Self>) -> Result<()> {
        let mut client = pair::connect(self.config.as_ref()).await?;
        let (tx, rx) = mpsc::channel(8);
        tx.send(pingwaf_proto::control_plane::TunnelConnectorMessage {
            kind: Some(pingwaf_proto::control_plane::tunnel_connector_message::Kind::Hello(
                pingwaf_proto::control_plane::TunnelConnectorHello {
                    tunnel_id: self.config.tunnel_id.clone(),
                    credential: self.config.credential.clone(),
                    version: self.config.version.clone(),
                    hostname: self.config.hostname.clone(),
                    os_info: self.config.os.clone(),
                },
            )),
        })
        .await
        .map_err(|_| anyhow!("cannot queue the tunnel connector hello"))?;
        let mut stream = client.control(rx).await?;
        let mut heartbeat = tokio::time::interval(Duration::from_secs(20));
        heartbeat
            .set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = heartbeat.tick() => {
                    let state = self.state();
                    let message = pingwaf_proto::control_plane::TunnelConnectorMessage {
                        kind: Some(pingwaf_proto::control_plane::tunnel_connector_message::Kind::Heartbeat(
                            pingwaf_proto::control_plane::TunnelConnectorHeartbeat {
                                sessions: self.live_sessions.load(Ordering::SeqCst),
                                streams_active: self.active_streams.load(Ordering::SeqCst),
                                connected_ingress: state.ingress.iter().map(|i| i.endpoint.clone()).collect(),
                            },
                        )),
                    };
                    if tx.send(message).await.is_err() {
                        break;
                    }
                },
                command = stream.message() => {
                    let Some(command) = command? else { break };
                    self.apply_command(command);
                },
            }
        }
        Ok(())
    }

    /// Applies a command pushed by the control plane.
    fn apply_command(
        &self,
        command: pingwaf_proto::control_plane::TunnelConnectorCommand,
    ) {
        use pingwaf_proto::control_plane::tunnel_connector_command::Kind;
        match command.kind {
            Some(Kind::Config(config)) => {
                let ingress: Vec<IngressEndpoint> = config
                    .ingress
                    .into_iter()
                    .filter(|entry| !entry.endpoint.is_empty())
                    .map(|entry| IngressEndpoint {
                        endpoint: entry.endpoint,
                        fingerprints: entry.fingerprints,
                    })
                    .collect();
                // Every path that accepts a policy funnels through the same
                // filter: a pushed Config used to overwrite the local
                // `allowed_targets` allowlist with the control plane's full
                // list, so the second line of defence lasted until the next
                // push.
                // The pushed list is authoritative, including an empty one:
                // unbinding the last pool must stop the connector from dialing
                // anything, not leave the previous list in place.
                let allowed = self.policy_targets(config.targets);
                let mut guard = match self.state.write() {
                    Ok(guard) => guard,
                    Err(_) => return,
                };
                guard.ingress = ingress;
                guard.targets = allowed;
                if !config.session_token.is_empty() {
                    guard.session_token = Some(config.session_token);
                    guard.session_token_expires_at =
                        config.session_token_expires_at;
                }
                if let Some(settings) = config.settings {
                    guard.settings = TunnelSettings {
                        max_streams: settings.max_streams,
                        idle_timeout_secs: settings.idle_timeout_secs,
                        heartbeat_secs: settings.heartbeat_secs,
                    };
                }
                guard.enabled = config.enabled;
                drop(guard);
                self.changed.notify_waiters();
            },
            Some(Kind::Revoked(revoked)) => {
                if let Ok(mut guard) = self.state.write() {
                    guard.revoked = Some(revoked.message);
                }
                self.changed.notify_waiters();
            },
            None => {},
        }
    }
}

/// Reads control frames on an established session and keeps the edge informed.
async fn control_loop(
    connector: Arc<Connector>,
    stream: tokio_util::compat::Compat<yamux::Stream>,
    shutdown_tx: watch::Sender<bool>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let settings = connector.state().settings;
    let heartbeat_secs = settings.heartbeat_secs.max(5) as u64;
    // Mirror of the edge's silence bound: a peer that stops answering is gone.
    let liveness = Duration::from_secs(
        (settings.heartbeat_secs.max(5) * 3)
            .max(settings.idle_timeout_secs.max(30)) as u64,
    );
    let mut heartbeat =
        tokio::time::interval(Duration::from_secs(heartbeat_secs));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => break,
            _ = heartbeat.tick() => {
                let message = ControlFrame::Heartbeat {
                    streams_active: connector.active_streams.load(Ordering::SeqCst),
                    rtt_ms: 0,
                };
                if write_frame(&mut writer, &message).await.is_err() {
                    break;
                }
            },
            frame = tokio::time::timeout(liveness, read_frame(&mut reader)) => {
                let frame = match frame {
                    Ok(frame) => frame,
                    Err(_) => {
                        warn!(
                            target: "pingwaf::tunnel",
                            timeout_secs = liveness.as_secs(),
                            "the edge stopped answering, reconnecting"
                        );
                        break;
                    },
                };
                match frame {
                    Ok(ControlFrame::PolicyUpdate { policy_version: _, targets, settings }) => {
                        let allowed = connector.policy_targets(targets);
                        if let Ok(mut guard) = connector.state.write() {
                            guard.targets = allowed;
                            guard.settings = settings;
                        }
                        connector.changed.notify_waiters();
                    },
                    Ok(ControlFrame::HeartbeatAck { .. }) => {},
                    Ok(ControlFrame::Revoked { message }) => {
                        if let Ok(mut guard) = connector.state.write() {
                            guard.revoked = Some(message);
                        }
                        connector.changed.notify_waiters();
                        break;
                    },
                    Ok(ControlFrame::Drain { grace_secs }) => {
                        info!(
                            target: "pingwaf::tunnel",
                            grace_secs,
                            "the edge is draining the tunnel session"
                        );
                        break;
                    },
                    Ok(other) => debug!(
                        target: "pingwaf::tunnel",
                        frame = other.kind(),
                        "unexpected control frame from the edge"
                    ),
                    Err(error) => {
                        debug!(
                            target: "pingwaf::tunnel",
                            error = %error,
                            "tunnel control stream ended"
                        );
                        break;
                    },
                }
            },
        }
    }
    let _ = writer.shutdown().await;
    let _ = shutdown_tx.send(true);
}

/// Accepts data streams from the edge until the connection ends.
async fn data_loop(
    connector: Arc<Connector>,
    mut connection: yamux::Connection<
        tokio_util::compat::Compat<tokio_rustls::client::TlsStream<TcpStream>>,
    >,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    loop {
        let next = tokio::select! {
            _ = shutdown.changed() => return Ok(()),
            next = poll_fn(|cx| connection.poll_next_inbound(cx)) => next,
        };
        match next {
            Some(Ok(stream)) => {
                tokio::spawn(Arc::clone(&connector).handle_stream(stream));
            },
            Some(Err(error)) => {
                return Err(anyhow!("tunnel session ended: {error}"));
            },
            None => return Ok(()),
        }
    }
}

/// Server name for the TLS handshake.
///
/// The pinned verifier ignores the name, so this only has to be something
/// rustls accepts: an IP literal when the endpoint is an address, the host
/// name otherwise.
fn server_name_for(endpoint: &str) -> Result<ServerName<'static>> {
    let host = host_of(endpoint)?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }
    ServerName::try_from(host.to_string())
        .map_err(|err| anyhow!("{endpoint} is not a valid server name: {err}"))
}

/// Host part of `host:port`, with IPv6 brackets stripped.
fn host_of(endpoint: &str) -> Result<&str> {
    if let Some(rest) = endpoint.strip_prefix('[') {
        let (host, _) = rest
            .split_once(']')
            .ok_or_else(|| anyhow!("{endpoint} is not a valid host:port"))?;
        return Ok(host);
    }
    endpoint
        .rsplit_once(':')
        .map(|(host, _)| host)
        .filter(|host| !host.is_empty())
        .ok_or_else(|| anyhow!("{endpoint} is not a valid host:port"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_parsing_handles_names_and_ip_literals() {
        assert_eq!(
            host_of("waf1.example.com:9443").unwrap(),
            "waf1.example.com"
        );
        assert_eq!(host_of("[::1]:9443").unwrap(), "::1");
        assert_eq!(host_of("127.0.0.1:9443").unwrap(), "127.0.0.1");
        assert!(host_of("nope").is_err());
        assert!(host_of(":9443").is_err());
    }

    #[test]
    fn a_disabled_deployment_waits_instead_of_redialing() {
        let mut state = ConnectorState {
            enabled: true,
            ..ConnectorState::default()
        };
        assert_eq!(session_action(&state), SessionAction::Connect);
        // The global switch is off: the edge closes the session and the
        // connector must wait for the next push, not produce a refusal every
        // backoff window.
        state.enabled = false;
        assert_eq!(session_action(&state), SessionAction::Wait);
        // A revocation outranks the switch: the process stops.
        state.revoked = Some("revoked by an operator".to_string());
        assert_eq!(session_action(&state), SessionAction::Stop);
    }

    #[test]
    fn a_target_outside_the_policy_is_refused() {
        let mut state = ConnectorState {
            enabled: true,
            targets: vec!["10.0.0.5:80".to_string()],
            ..ConnectorState::default()
        };
        assert!(state.allows("10.0.0.5:80"));
        assert!(!state.allows("10.0.0.6:80"));
        state.enabled = false;
        assert!(!state.allows("10.0.0.5:80"));
    }
}
