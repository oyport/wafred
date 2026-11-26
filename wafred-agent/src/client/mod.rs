use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use tracing::{debug, error, info, warn};

use pingwaf_proto::control_plane::{
    self as proto, control_plane_client::ControlPlaneClient as ProtoClient,
};

use crate::body_budget::{BodyBudget, LOG_BODY_BUDGET_BYTES};
use crate::cache::{BlockedIpEntry, RuleCache};
use crate::cert_events::{
    attribute_events, cert_event_buffer, CertAttribution,
};
use crate::config::AgentConfig;
use crate::heartbeat::{MetricsCollector, SystemMetrics};
use crate::probe::{self, HostSample, ProbeBuffer};

/// The subset of the data plane's `acme_state.toml` the publisher needs.
///
/// The file is written by the config manager; the publisher only reports
/// ACME-managed entries that carry material.
#[derive(Debug, Default, serde::Deserialize)]
struct AcmeStateFile {
    #[serde(default)]
    certificates: HashMap<String, AcmeStateCertificate>,
}

#[derive(Debug, Default, serde::Deserialize)]
struct AcmeStateCertificate {
    #[serde(default)]
    acme: Option<String>,
    #[serde(default)]
    domains: String,
    #[serde(default)]
    tls_cert: String,
    #[serde(default)]
    tls_key: String,
}

/// Stable in-process key for "this exact PEM was already handled".
fn certificate_fingerprint(site_id: &str, cert_pem: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    cert_pem.hash(&mut hasher);
    format!("{site_id}:{:x}", hasher.finish())
}

/// Whether retrying the same PEM cannot succeed (a permission or validation
/// refusal). Transport and internal errors are worth retrying.
fn permanent_publish_error(error: &anyhow::Error) -> bool {
    error.downcast_ref::<tonic::Status>().is_some_and(|status| {
        matches!(
            status.code(),
            tonic::Code::PermissionDenied
                | tonic::Code::InvalidArgument
                | tonic::Code::FailedPrecondition
        )
    })
}

/// Log entry that can be queued for shipping to the control plane.
/// This is a simplified local type that gets converted to proto at send time.
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub site_id: String,
    pub request_id: String,
    pub client_ip: String,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub path: String,
    pub query_string: String,
    pub protocol: String,
    pub request_headers: std::collections::HashMap<String, String>,
    pub request_body: Option<Vec<u8>>,
    pub request_body_size: u64,
    pub request_body_truncated: bool,
    pub response_status: u32,
    pub response_headers: std::collections::HashMap<String, String>,
    pub response_body: Option<Vec<u8>>,
    pub response_body_size: u64,
    pub response_body_truncated: bool,
    pub upstream_addr: String,
    pub upstream_latency_ms: u64,
    /// Status returned by the origin; repeats `response_status` when the data
    /// plane answered itself (block, challenge, cache hit, edge error).
    pub upstream_status: u32,
    pub waf_score: u32,
    pub waf_action: String,
    pub waf_rule_id: String,
    /// Rule that actually enforced the verdict (L3-006); empty when the
    /// block came from the score gate rather than a specific rule.
    pub waf_enforced_rule_id: String,
    pub waf_rule_name: String,
    pub waf_event_type: String,
    pub waf_details: String,
    pub waf_matched_tags: Vec<String>,
    /// Who the request was made by, when the site authenticated them: the
    /// OIDC session's `sub`. Empty for an anonymous request. An identifier
    /// the provider issued, never a secret, so it is safe to store.
    pub user_identity: String,
    pub total_latency_ms: u64,
    pub cache_status: String,
    pub tls_version: String,
    pub ja3_hash: String,
    pub country_code: String,
    pub city: String,
    pub asn: u32,
    pub user_agent: String,
    pub referer: String,
}

impl LogEntry {
    /// Body-prefix bytes this entry carries, both directions.
    fn body_bytes(&self) -> usize {
        self.request_body.as_ref().map_or(0, Vec::len)
            + self.response_body.as_ref().map_or(0, Vec::len)
    }

    /// Drops the body prefixes and flags each dropped one as truncated, so
    /// the stored entry does not read as "this exchange had no body".
    fn shed_bodies(&mut self) {
        if self
            .request_body
            .take()
            .is_some_and(|body| !body.is_empty())
        {
            self.request_body_truncated = true;
        }
        if self
            .response_body
            .take()
            .is_some_and(|body| !body.is_empty())
        {
            self.response_body_truncated = true;
        }
    }
}

/// Host callback invoked when the server requests a cache purge:
/// `(site_id, urls, tags)`.
type PurgeCacheFn = Box<dyn Fn(&str, &[String], &[String]) + Send + Sync>;

/// Consecutive refusals of a whole batch before the log shipper sends its
/// entries one at a time (see `LogBacklog::isolate`).
const LOG_SHIP_ISOLATION_THRESHOLD: u32 = 3;
/// Ceiling for that threshold. It doubles each time a one-by-one pass gets
/// nothing through, so a control plane that refuses everything is probed
/// with a full pass every few minutes instead of every few seconds.
const LOG_SHIP_ISOLATION_THRESHOLD_MAX: u32 = 48;
/// How often expired dynamic IP blocks are swept from the rule cache.
const BLOCK_SWEEP_INTERVAL_SECS: u64 = 60;

/// How often the debounced blocked-IP disk flush runs (see
/// `RuleCache::flush_blocked_ips`). Blocks take effect in memory instantly;
/// this only bounds how far a crash can set the disk copy back.
const BLOCK_FLUSH_INTERVAL_SECS: u64 = 5;
/// Upper bound on `blocked_ips` entries per heartbeat. The full list may hold
/// 100 000 rows; a heartbeat that big exceeds tonic's 4 MiB frame limit, and
/// every reconnect then fails on its first frame.
const MAX_HEARTBEAT_BLOCKED_IPS: usize = 4096;

/// Callback types for server commands that affect the host application.
#[derive(Default)]
pub struct CommandHandlers {
    /// Called when the server requests a cache purge.
    pub on_purge_cache: Option<PurgeCacheFn>,
    /// Called when the server requests a config reload.
    pub on_config_reload: Option<Box<dyn Fn() + Send + Sync>>,
    /// Called when the server requests agent restart.
    pub on_restart: Option<Box<dyn Fn(bool) + Send + Sync>>,
}

/// The main gRPC client that manages the connection to the control plane server.
///
/// Responsibilities:
/// - Establish and maintain the gRPC channel
/// - Register the agent and keep the token fresh
/// - Send periodic heartbeats with system metrics
/// - Ship access/security logs in batches
/// - Receive and apply server commands (rule updates, IP blocks, etc.)
/// - Handle disconnection with exponential backoff reconnection
pub struct ControlPlaneClient {
    config: AgentConfig,
    /// Agent authentication token received during registration
    agent_token: ArcSwapOption<String>,
    /// Whether we are currently connected to the server
    connected: AtomicBool,
    /// Shutdown signal
    shutdown_signal: Arc<AtomicBool>,
    /// Shared rule cache
    rule_cache: Arc<RuleCache>,
    /// Shared metrics collector
    metrics: Arc<MetricsCollector>,
    /// Channel for queuing log entries (bounded to prevent memory exhaustion)
    log_sender: mpsc::Sender<LogEntry>,
    /// Body-prefix bytes of the entries waiting in the queue. The queue is
    /// capped by entry count; this caps what those entries can pin.
    queued_bodies: BodyBudget,
    /// The queue's receiving end and the batch being shipped. Owned by the
    /// client rather than the shipper task, so a reconnect resumes with the
    /// entries the previous session had not delivered.
    log_state: Arc<tokio::sync::Mutex<LogShipState>>,
    /// Optional command handlers
    command_handlers: Arc<tokio::sync::RwLock<CommandHandlers>>,
    /// Buffered host probe samples, shipped with each heartbeat
    probe: Arc<ProbeBuffer>,
    /// Wakes the log shipper when the server sends a `flush_logs` command,
    /// so queued entries reach the control plane immediately instead of
    /// waiting out the batch interval.
    flush_notify: Arc<tokio::sync::Notify>,
    /// Current reconnect backoff in milliseconds, shared between the
    /// connection loop and the registration path so a successful register
    /// can retire stale backoff immediately.
    retry_delay_ms: AtomicU64,
}

impl ControlPlaneClient {
    /// The agent token minted at registration, once it succeeded.
    ///
    /// The self-upgrade loop authenticates against the REST API with the same
    /// credential the gRPC stream carries, so it needs the value this client
    /// already holds rather than a second registration.
    pub fn current_agent_token(&self) -> Option<String> {
        self.agent_token.load_full().map(|token| (*token).clone())
    }

    /// Create a new control plane client.
    ///
    /// The client does not connect immediately — call `connect()` or `start()` to begin.
    pub fn new(
        config: AgentConfig,
        rule_cache: Arc<RuleCache>,
        metrics: Arc<MetricsCollector>,
    ) -> Self {
        // Bounded on purpose: entries carry headers plus a body prefix
        // (8-64 KiB each), so 16384 entries could pin ~1 GB while the
        // control plane is unreachable (2026-10-17 audit). 2048 caps the
        // entries, `queued_bodies` caps the body bytes they hold; entries
        // beyond the first are dropped and counted in `send_log`, bodies
        // beyond the second are shed there.
        let (log_tx, log_rx) = mpsc::channel(2048);
        let retry_delay_ms = AtomicU64::new(config.reconnect_initial_delay_ms);

        // A purge is actionable without the host application: the edge cache
        // and its quota ledger live in the rule cache, so the default handler
        // is wired here rather than left to `set_command_handlers`. An
        // application that does register handlers replaces this one.
        let purge_cache = Arc::clone(&rule_cache);
        let handlers = CommandHandlers {
            on_purge_cache: Some(Box::new(move |site_id, urls, tags| {
                let cache = Arc::clone(&purge_cache);
                let site_id = site_id.to_string();
                let urls = urls.to_vec();
                if !tags.is_empty() {
                    // Cached objects carry no tags, so there is nothing to
                    // match them against. Say so rather than report a purge
                    // that silently removed nothing.
                    warn!(site_id = %site_id, tags = tags.len(),
                        "cache purge by tag is not supported, ignoring tags");
                }
                // Off the command loop: a full-site purge walks the disk.
                tokio::spawn(async move {
                    if let Err(e) = cache.purge_site(&site_id, &urls).await {
                        error!(error = %e, site_id = %site_id, "cache purge failed");
                    }
                });
            })),
            ..CommandHandlers::default()
        };

        Self {
            config,
            agent_token: ArcSwapOption::empty(),
            connected: AtomicBool::new(false),
            shutdown_signal: Arc::new(AtomicBool::new(false)),
            rule_cache,
            metrics,
            log_sender: log_tx,
            queued_bodies: BodyBudget::new(LOG_BODY_BUDGET_BYTES),
            log_state: Arc::new(tokio::sync::Mutex::new(LogShipState {
                receiver: log_rx,
                backlog: LogBacklog::default(),
            })),
            command_handlers: Arc::new(tokio::sync::RwLock::new(handlers)),
            probe: Arc::new(ProbeBuffer::new()),
            flush_notify: Arc::new(tokio::sync::Notify::new()),
            retry_delay_ms,
        }
    }

    /// Check if the client is currently connected.
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    /// Set command handlers for server-initiated actions.
    pub async fn set_command_handlers(&self, handlers: CommandHandlers) {
        let mut h = self.command_handlers.write().await;
        *h = handlers;
    }

    /// Replace the callback used by a server-initiated process restart while
    /// preserving the built-in purge and any config-reload handlers.
    pub async fn set_restart_handler(
        &self,
        handler: impl Fn(bool) + Send + Sync + 'static,
    ) {
        self.command_handlers.write().await.on_restart =
            Some(Box::new(handler));
    }

    /// Queue a log entry for shipping to the server (non-blocking).
    ///
    /// If the log buffer is full, the entry is dropped and counted; the
    /// count reaches the control plane with the next heartbeat. If only the
    /// queue's body budget is exhausted, the entry is queued without its body
    /// prefixes, flagged as truncated.
    pub fn send_log(&self, mut entry: LogEntry) {
        static DROPPED: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(0);
        static BODIES_SHED: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(0);
        let mut body_bytes = entry.body_bytes();
        if body_bytes > 0 && !self.queued_bodies.try_reserve(body_bytes) {
            entry.shed_bodies();
            body_bytes = 0;
            let shed = BODIES_SHED
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;
            if shed == 1 || shed.is_multiple_of(1024) {
                warn!(
                    shed,
                    "Log queue body budget exhausted, queueing entries \
                     without their bodies"
                );
            }
        }
        if let Err(e) = self.log_sender.try_send(entry) {
            self.queued_bodies.release(body_bytes);
            self.metrics.record_logs_dropped(1);
            match e {
                mpsc::error::TrySendError::Full(_) => {
                    // One warning per drop made an unreachable control plane
                    // flood the agent's own log. Report on the first drop and
                    // then every 1024th, with the running total.
                    let dropped = DROPPED
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                        + 1;
                    if dropped == 1 || dropped.is_multiple_of(1024) {
                        warn!(dropped, "Log buffer full, dropping entries");
                    }
                },
                mpsc::error::TrySendError::Closed(_) => {
                    debug!("Log channel closed, dropping entry");
                },
            }
        }
    }

    /// Pop the next queued log entry without the shipper task running.
    /// Only compiled with the `test-util` feature.
    #[cfg(feature = "test-util")]
    pub async fn pop_log(&self) -> Option<LogEntry> {
        let entry = self.log_state.lock().await.receiver.try_recv().ok()?;
        self.queued_bodies.release(entry.body_bytes());
        Some(entry)
    }

    /// Establish the gRPC channel to the control plane server.
    async fn create_channel(&self) -> anyhow::Result<Channel> {
        let endpoint = Endpoint::from_shared(self.config.server_url.clone())
            .map_err(|e| anyhow::anyhow!("Invalid server URL: {}", e))?
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(300))
            .keep_alive_while_idle(true)
            .http2_keep_alive_interval(Duration::from_secs(30))
            .tcp_nodelay(true);
        let endpoint = apply_client_tls(
            endpoint,
            &self.config.server_url,
            &self.config.server_ca_cert,
            &self.config.server_ca_pem,
            &self.config.server_tls_name,
        )?;

        let channel = endpoint.connect().await?;
        Ok(channel)
    }

    /// Register this agent with the control plane.
    ///
    /// Returns the agent token and initial configuration if provided.
    async fn register(
        &self,
        channel: Channel,
    ) -> anyhow::Result<proto::RegisterAgentResponse> {
        let mut client = ProtoClient::new(channel);

        let hostname = get_hostname();
        let (cpu_cores, memory_bytes, os_info) = get_system_info();
        let addresses = self.probe.addresses();

        let request = proto::RegisterAgentRequest {
            api_key: self.config.api_key.clone(),
            hostname,
            ip_address: get_local_ip(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            os_info,
            cpu_cores,
            memory_bytes,
            public_ip: addresses.public_ip,
            private_ip: addresses.private_ip,
        };

        let response = client.register_agent(request).await?.into_inner();

        // Store the agent token
        self.agent_token
            .store(Some(Arc::new(response.agent_token.clone())));

        info!(
            agent_id = %response.agent_id,
            heartbeat_interval = response.heartbeat_interval_seconds,
            "Registered with control plane"
        );

        // The initial config is authoritative even when it lists no site: an
        // agent that was offline while its last site was deleted must drop
        // it, not keep serving the copy on disk.
        if let Some(ref site_config) = response.initial_config {
            if let Err(e) = self.rule_cache.update_from_site_config(site_config)
            {
                error!(error = %e, "Failed to apply initial site config");
            }
        }

        Ok(response)
    }

    /// Start the client: connect, register, and spawn background tasks.
    ///
    /// Returns join handles for the spawned tasks (heartbeat, log shipper, rule sync).
    pub async fn start(
        self: &Arc<Self>,
    ) -> anyhow::Result<Vec<JoinHandle<()>>> {
        let mut handles = Vec::new();

        // Host probe runs on its own thread: reading /proc and shelling out to
        // `df`/`ip` must never stall the async runtime.
        probe::spawn(
            Arc::clone(&self.probe),
            self.config.probe_interval_secs,
            self.config.probe_disk_path.clone(),
            Arc::clone(&self.shutdown_signal),
        );

        // Spawn the connection manager with reconnection logic
        let this = Arc::clone(self);
        let handle = tokio::spawn(async move {
            this.connection_loop().await;
        });
        handles.push(handle);

        // Expired dynamic IP blocks are dropped on read too, but sweeping on a
        // timer keeps the map, its disk copy and the heartbeat report in sync
        // even on agents that see no traffic for a while.
        let rule_cache = Arc::clone(&self.rule_cache);
        let shutdown = Arc::clone(&self.shutdown_signal);
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(
                BLOCK_SWEEP_INTERVAL_SECS,
            ));
            interval.set_missed_tick_behavior(
                tokio::time::MissedTickBehavior::Delay,
            );
            loop {
                interval.tick().await;
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                rule_cache.cleanup_expired_blocks();
            }
        });
        handles.push(handle);

        // Blocked-IP persistence is debounced off the request hot path: each
        // persist serializes the whole map and fsyncs, so N rapid blocks
        // must not cost N×O(N) fsyncs. This loop writes the latest state out
        // every few seconds; shutdown still persists through
        // `persist_to_disk`.
        let rule_cache = Arc::clone(&self.rule_cache);
        let shutdown = Arc::clone(&self.shutdown_signal);
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(
                BLOCK_FLUSH_INTERVAL_SECS,
            ));
            interval.set_missed_tick_behavior(
                tokio::time::MissedTickBehavior::Delay,
            );
            loop {
                interval.tick().await;
                if shutdown.load(Ordering::Relaxed) {
                    rule_cache.flush_rule_cache_if_dirty();
                    break;
                }
                rule_cache.flush_blocked_ips();
                rule_cache.flush_rule_cache_if_dirty();
            }
        });
        handles.push(handle);

        Ok(handles)
    }

    /// Retires backoff accumulated by earlier outages: registration just
    /// proved the connection healthy, so the next reconnect must start from
    /// the initial delay instead of paying for failures long past.
    fn retire_backoff(&self) {
        self.retry_delay_ms
            .store(self.config.reconnect_initial_delay_ms, Ordering::Relaxed);
    }

    /// Main connection loop with exponential backoff reconnection.
    ///
    /// The backoff lives in `retry_delay_ms` so that a successful
    /// registration (see `try_connect_and_run`) can reset it: backoff
    /// accumulated by past outages must not penalize the next reconnect
    /// after a healthy connection drops.
    async fn connection_loop(self: &Arc<Self>) {
        loop {
            if self.shutdown_signal.load(Ordering::Relaxed) {
                info!("Agent shutting down");
                break;
            }

            let retry_delay = Duration::from_millis(
                self.retry_delay_ms.load(Ordering::Relaxed),
            );

            match self.try_connect_and_run().await {
                Ok(()) => {
                    // Clean disconnect (server closed connection gracefully)
                    info!("Disconnected from control plane, will reconnect");
                },
                Err(e) => {
                    warn!(
                        error = %e,
                        hint = connection_hint_field(
                            &e,
                            &self.config.server_url
                        ),
                        delay_ms = retry_delay.as_millis() as u64,
                        "Connection to control plane failed"
                    );
                },
            }

            self.connected.store(false, Ordering::Relaxed);

            // Wait before reconnecting with exponential backoff. The wait
            // must be interruptible: a shutdown should not sit through the
            // maximum 60 s backoff before the process can exit.
            tokio::select! {
                _ = tokio::time::sleep(retry_delay) => {},
                _ = self.wait_for_shutdown() => {
                    info!("Agent shutting down during reconnect backoff");
                    break;
                },
            }
            let next = next_backoff(
                retry_delay.as_millis() as u64,
                self.config.reconnect_max_delay_ms,
            );
            self.retry_delay_ms.store(next, Ordering::Relaxed);
        }
    }

    /// Try to connect, register, and run the heartbeat + log shipper.
    /// Returns Ok(()) on clean disconnect, Err on connection failure.
    async fn try_connect_and_run(&self) -> anyhow::Result<()> {
        let channel = self.create_channel().await?;

        // Register
        let reg_response = self.register(channel.clone()).await?;
        self.retire_backoff();
        self.connected.store(true, Ordering::Relaxed);
        info!("Connected to control plane at {}", self.config.server_url);

        // The server owns the agent identity: the token it minted carries its
        // row ID as subject, and every stream is authenticated against that.
        // Outbound messages must present exactly this ID, not a local one.
        let agent_id = reg_response.agent_id.clone();

        // Run heartbeat and log shipping concurrently
        let heartbeat_fut = self.run_heartbeat(channel.clone(), &reg_response);
        let log_shipper_fut = self.run_log_shipper(channel.clone(), &agent_id);
        let cert_shipper_fut =
            self.run_cert_event_shipper(channel.clone(), &agent_id);
        let metric_shipper_fut =
            self.run_metric_shipper(channel.clone(), &agent_id);
        let publisher_fut = self.run_certificate_publisher(channel, &agent_id);

        // Wait for either to complete (usually means disconnection)
        tokio::select! {
            result = heartbeat_fut => {
                if let Err(e) = result {
                    error!(error = %e, "Heartbeat stream ended");
                    return Err(e);
                }
            }
            result = log_shipper_fut => {
                if let Err(e) = result {
                    error!(error = %e, "Log shipper ended");
                    return Err(e);
                }
            }
            result = cert_shipper_fut => {
                if let Err(e) = result {
                    error!(error = %e, "Cert event shipper ended");
                    return Err(e);
                }
            }
            result = metric_shipper_fut => {
                if let Err(e) = result {
                    error!(error = %e, "Metric shipper ended");
                    return Err(e);
                }
            }
            result = publisher_fut => {
                if let Err(e) = result {
                    error!(error = %e, "Certificate publisher ended");
                    return Err(e);
                }
            }
            _ = self.wait_for_shutdown() => {
                info!("Shutdown signal received");
            }
        }

        Ok(())
    }

    /// Publishes locally issued ACME certificates to the control plane.
    ///
    /// The data plane writes issued material to `acme_state.toml`; a
    /// designated issuer reports it here so the control plane can store it and
    /// fan it out. The loop is idempotent: the server accepts an unchanged PEM
    /// as a no-op, and a refused PEM is remembered so the same bytes are not
    /// retried forever.
    async fn run_certificate_publisher(
        &self,
        channel: Channel,
        _agent_id: &str,
    ) -> anyhow::Result<()> {
        let path = self.rule_cache.cache_dir().join("acme_state.toml");
        let mut handled: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        interval
            .set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            if self.shutdown_signal.load(Ordering::Relaxed) {
                break;
            }
            let Ok(text) = tokio::fs::read_to_string(&path).await else {
                continue;
            };
            let Ok(state) = toml::from_str::<AcmeStateFile>(&text) else {
                continue;
            };
            for (name, cert) in state.certificates {
                let Some(site_id) = name.strip_suffix("_cert") else {
                    continue;
                };
                if cert.acme.as_deref().is_none_or(str::is_empty)
                    || cert.domains.trim().is_empty()
                    || cert.tls_cert.trim().is_empty()
                    || cert.tls_key.trim().is_empty()
                {
                    continue;
                }
                let fingerprint =
                    certificate_fingerprint(site_id, &cert.tls_cert);
                if handled.contains(&fingerprint) {
                    continue;
                }
                match self
                    .publish_certificate(
                        channel.clone(),
                        site_id,
                        &cert.domains,
                        &cert.tls_cert,
                        &cert.tls_key,
                    )
                    .await
                {
                    Ok(response) => {
                        handled.insert(fingerprint);
                        debug!(
                            site_id,
                            message = %response.message,
                            "certificate published"
                        );
                    },
                    Err(err) => {
                        if permanent_publish_error(&err) {
                            handled.insert(fingerprint);
                            warn!(
                                site_id,
                                error = %err,
                                "certificate publication refused"
                            );
                        } else {
                            warn!(
                                site_id,
                                error = %err,
                                "certificate publication failed; will retry"
                            );
                        }
                    },
                }
            }
        }
        Ok(())
    }

    /// Reports one issued certificate to the control plane.
    async fn publish_certificate(
        &self,
        channel: Channel,
        site_id: &str,
        domains: &str,
        cert_pem: &str,
        key_pem: &str,
    ) -> anyhow::Result<proto::PublishCertificateResponse> {
        let token = self.require_agent_token()?;
        let mut client = ProtoClient::new(channel);
        let response = tokio::time::timeout(
            Duration::from_secs(30),
            client.publish_certificate(proto::PublishCertificateRequest {
                agent_token: token,
                site_id: site_id.to_string(),
                domains: domains.to_string(),
                cert_pem: cert_pem.to_string(),
                key_pem: key_pem.to_string(),
            }),
        )
        .await
        .map_err(|_| anyhow::anyhow!("control plane timed out"))??;
        Ok(response.into_inner())
    }

    /// Run the periodic edge-metrics shipper.
    ///
    /// Samples the agent's process-wide counters and per-site cache gauges
    /// every `metrics_ship_interval_secs` (0 disables shipping) and pushes
    /// one `MetricBatch` per tick over the client-streaming `ShipMetrics`
    /// RPC. The control plane persists these for the analytics queries.
    async fn run_metric_shipper(
        &self,
        channel: Channel,
        agent_id: &str,
    ) -> anyhow::Result<()> {
        let interval_secs = self.config.metrics_ship_interval_secs;
        if interval_secs == 0 {
            // Shipping is disabled, but this future is part of the
            // `try_connect_and_run` select: returning would tear the session
            // down (reconnect storm, no commands). Park forever instead and
            // let the shutdown branch end the connection.
            debug!("Metric shipping disabled; idling shipper for the session");
            return metric_shipper_disabled().await;
        }
        let mut client = ProtoClient::new(channel);
        let agent_token = self.agent_token.load_full();

        let mut interval =
            tokio::time::interval(Duration::from_secs(interval_secs.max(1)));
        interval
            .set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = interval.tick() => {},
                _ = self.wait_for_shutdown() => break,
            }
            if self.shutdown_signal.load(Ordering::Relaxed) {
                break;
            }

            let batch = self.build_metric_batch(agent_id);
            let count = batch.metrics.len();
            let mut request = tonic::Request::new(tokio_stream::once(batch));
            attach_agent_token(&mut request, &agent_token);
            match client.ship_metrics(request).await {
                Ok(response) => {
                    let ack = response.into_inner();
                    debug!(
                        count,
                        received = ack.received_count,
                        "Shipped metrics to server"
                    );
                },
                Err(e) => {
                    // Transient failures are expected across reconnects; the
                    // next tick simply retries with fresh samples.
                    debug!(error = %e, "Metric ship failed");
                },
            }
        }

        Ok(())
    }

    /// Samples the current counters into one batch.
    fn build_metric_batch(&self, agent_id: &str) -> proto::MetricBatch {
        let metrics = &self.metrics;
        let mut metrics_list = vec![
            proto::Metric {
                name: "pingwaf_requests_total".to_string(),
                labels: HashMap::new(),
                value: metrics.requests_total() as f64,
                r#type: proto::MetricType::MetricCounter as i32,
            },
            proto::Metric {
                name: "pingwaf_blocked_requests_total".to_string(),
                labels: HashMap::new(),
                value: metrics.blocked_requests_total() as f64,
                r#type: proto::MetricType::MetricCounter as i32,
            },
            proto::Metric {
                name: "pingwaf_active_connections".to_string(),
                labels: HashMap::new(),
                value: metrics.active_connections() as f64,
                r#type: proto::MetricType::MetricGauge as i32,
            },
        ];
        for status in self.rule_cache.cache_statuses() {
            metrics_list.push(proto::Metric {
                name: "pingwaf_site_cache_used_bytes".to_string(),
                labels: HashMap::from([(
                    "site".to_string(),
                    status.domain.clone(),
                )]),
                value: status.cache_disk_bytes as f64,
                r#type: proto::MetricType::MetricGauge as i32,
            });
        }
        proto::MetricBatch {
            agent_id: agent_id.to_string(),
            timestamp: Some(prost_types::Timestamp {
                seconds: chrono::Utc::now().timestamp(),
                nanos: 0,
            }),
            metrics: metrics_list,
        }
    }

    /// Run the bidirectional heartbeat stream.
    ///
    /// Sends periodic heartbeats and processes server commands from the response stream.
    async fn run_heartbeat(
        &self,
        channel: Channel,
        reg_response: &proto::RegisterAgentResponse,
    ) -> anyhow::Result<()> {
        let mut client = ProtoClient::new(channel);

        // The control plane decides the heartbeat cadence — its staleness
        // thresholds are derived from the same value — so the interval it
        // handed down at registration wins; the local setting only applies
        // when the server did not send one.
        let heartbeat_interval = effective_heartbeat_interval(
            reg_response.heartbeat_interval_seconds,
            self.config.heartbeat_interval_secs,
        );

        // Create a channel for sending heartbeats to the stream
        let (hb_tx, hb_rx) = mpsc::channel::<proto::AgentHeartbeat>(4);
        let outbound = tokio_stream::wrappers::ReceiverStream::new(hb_rx);

        // Spawn the sender BEFORE opening the stream: the server does not
        // return response headers until it has read the first message (which
        // carries the auth token), so awaiting the call first would deadlock
        // both sides. The first interval tick fires immediately, sending the
        // opening message and unblocking the server.
        let agent_id = reg_response.agent_id.clone();
        let agent_token = self
            .agent_token
            .load_full()
            .map(|t| (*t).clone())
            .unwrap_or_default();
        let metrics = Arc::clone(&self.metrics);
        let rule_cache = Arc::clone(&self.rule_cache);
        let shutdown = Arc::clone(&self.shutdown_signal);
        let probe = Arc::clone(&self.probe);

        let sender_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(heartbeat_interval);
            interval.set_missed_tick_behavior(
                tokio::time::MissedTickBehavior::Delay,
            );

            loop {
                interval.tick().await;

                if shutdown.load(Ordering::Relaxed) {
                    break;
                }

                let system_metrics = metrics.collect();
                let addresses = probe.addresses();
                // A big block list must not push the heartbeat past tonic's
                // frame limit: the first frame would fail on every reconnect
                // and the control-plane link would never recover. Ship a
                // deterministic prefix and say it is partial, so the server
                // keeps the rows it did not see.
                // Page directly from the cache: only the bounded prefix is
                // cloned, never the whole map (see `blocked_ips_page`).
                let (blocked_ip_entries, blocked_ips_truncated) =
                    rule_cache.blocked_ips_page(MAX_HEARTBEAT_BLOCKED_IPS);
                let blocked_ips: Vec<proto::BlockedIp> = blocked_ip_entries
                    .iter()
                    .map(to_proto_blocked_ip)
                    .collect();
                let config_apply_error = rule_cache.config_apply_error();
                let hb = proto::AgentHeartbeat {
                    agent_id: agent_id.clone(),
                    agent_token: agent_token.clone(),
                    timestamp: Some(prost_types::Timestamp {
                        seconds: chrono::Utc::now().timestamp(),
                        nanos: 0,
                    }),
                    cpu_usage_percent: system_metrics.cpu_usage_percent,
                    memory_usage_bytes: system_metrics.memory_usage_bytes,
                    active_connections: system_metrics.active_connections,
                    requests_per_second: system_metrics.requests_per_second,
                    blocked_requests_total: system_metrics
                        .blocked_requests_total,
                    health: heartbeat_health(&config_apply_error) as i32,
                    config_hash: rule_cache.config_hash().to_string(),
                    config_apply_error,
                    logs_dropped_total: metrics.logs_dropped_total(),
                    // Per-site edge cache disk usage, straight from the quota
                    // ledger; this is what the control plane's
                    // `/api/v1/cache/status` reports.
                    site_statuses: rule_cache.cache_statuses(),
                    // Everything sampled since the last heartbeat, oldest
                    // first; draining keeps each sample shipped exactly once.
                    host_samples: probe
                        .drain()
                        .iter()
                        .map(to_proto_sample)
                        .collect(),
                    public_ip: addresses.public_ip,
                    private_ip: addresses.private_ip,
                    // Dynamic IP blocks in force at this tick; the control
                    // plane reconciles its copy against every heartbeat.
                    blocked_ips,
                    blocked_ips_truncated,
                    last_config_sync_at: rule_cache.config_synced_at().map(
                        |at| prost_types::Timestamp {
                            seconds: at.timestamp(),
                            nanos: 0,
                        },
                    ),
                    last_policy_sync_at: rule_cache.policy_synced_at().map(
                        |at| prost_types::Timestamp {
                            seconds: at.timestamp(),
                            nanos: 0,
                        },
                    ),
                    // Rule-cache disk health; the control plane alerts on a
                    // false here because the edge is then running on empty
                    // rules until the next sync lands.
                    cache_persist_healthy: Some(
                        rule_cache.cache_persist_healthy(),
                    ),
                    cache_status_reason: rule_cache.cache_status_reason(),
                    // Per-upstream backend health from the load balancer's
                    // circuit breakers; the control plane turns sustained
                    // loss into site.upstream_* alerts.
                    upstream_health: crate::upstream_health::heartbeat_statuses(
                    ),
                    process_rss_bytes: system_metrics.process_rss_bytes,
                    // The tunnel listener and its sessions, when this process
                    // runs one. `None` tells the control plane the edge is not
                    // an ingress, which is also what clears a stale address.
                    tunnel_listener: wafred_tunnel::runtime().map(|runtime| {
                        proto::TunnelListenerStatus {
                            active: runtime.listener_addr.is_some(),
                            addr: runtime
                                .listener_addr
                                .map(|addr| addr.to_string())
                                .unwrap_or_default(),
                            cert_sha256: runtime.cert_fingerprint.clone(),
                            last_error: runtime
                                .listener_error
                                .clone()
                                .unwrap_or_default(),
                        }
                    }),
                    tunnel_sessions: wafred_tunnel::runtime()
                        .map(|runtime| {
                            runtime
                                .registry
                                .session_reports()
                                .into_iter()
                                .map(|report| proto::TunnelSessionReport {
                                    tunnel_id: report.tunnel_id,
                                    connector_version: report.connector_version,
                                    hostname: report.hostname,
                                    connected_at: Some(
                                        prost_types::Timestamp {
                                            seconds: report
                                                .connected_at
                                                .unix_timestamp(),
                                            nanos: 0,
                                        },
                                    ),
                                    streams_active: report.streams_active,
                                    rtt_ms: report.rtt_ms,
                                })
                                .collect()
                        })
                        .unwrap_or_default(),
                };

                if hb_tx.send(hb).await.is_err() {
                    debug!("Heartbeat channel closed");
                    break;
                }
            }
        });

        // Start the bidirectional stream; on failure stop the sender so it
        // does not buffer heartbeats no one will ever read.
        let response = match client.heartbeat(outbound).await {
            Ok(response) => response,
            Err(e) => {
                sender_task.abort();
                return Err(e.into());
            },
        };
        let mut inbound = response.into_inner();

        // Process incoming server commands
        let rule_cache = Arc::clone(&self.rule_cache);
        let command_handlers = Arc::clone(&self.command_handlers);
        let shutdown = Arc::clone(&self.shutdown_signal);

        loop {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }

            tokio::select! {
                msg = inbound.message() => {
                    match msg {
                        Ok(Some(command)) => {
                            Self::handle_server_command(
                                &command,
                                &rule_cache,
                                &command_handlers,
                                &self.flush_notify,
                            )
                            .await;
                        }
                        Ok(None) => {
                            info!("Server closed heartbeat stream");
                            break;
                        }
                        Err(e) => {
                            error!(error = %e, "Heartbeat stream error");
                            return Err(e.into());
                        }
                    }
                }
                _ = self.wait_for_shutdown() => {
                    break;
                }
            }
        }

        sender_task.abort();
        Ok(())
    }

    /// Handle a server command received via the heartbeat stream.
    async fn handle_server_command(
        command: &proto::ServerCommand,
        rule_cache: &Arc<RuleCache>,
        command_handlers: &Arc<tokio::sync::RwLock<CommandHandlers>>,
        flush_notify: &tokio::sync::Notify,
    ) {
        let command_type = proto::CommandType::try_from(command.r#type)
            .unwrap_or(proto::CommandType::CommandUnknown);

        debug!(
            command_id = %command.command_id,
            command_type = ?command_type,
            "Received server command"
        );

        match &command.payload {
            Some(proto::server_command::Payload::RuleUpdate(update)) => {
                if let Some(ref bundle) = update.rules {
                    if let Err(e) = rule_cache.update_from_bundle(bundle) {
                        error!(error = %e, "Failed to apply rule update");
                    } else {
                        info!(site_id = %update.site_id, "Applied rule update from server");
                    }
                }
            },
            Some(proto::server_command::Payload::BlockIp(block)) => {
                let duration = if block.duration_seconds > 0 {
                    Some(Duration::from_secs(block.duration_seconds as u64))
                } else {
                    None
                };
                for ip in &block.ip_addresses {
                    rule_cache.block_ip(
                        &block.site_id,
                        ip,
                        duration,
                        &block.reason,
                    );
                }
            },
            Some(proto::server_command::Payload::UnblockIp(unblock)) => {
                for ip in &unblock.ip_addresses {
                    rule_cache.unblock_ip(&unblock.site_id, ip);
                }
            },
            Some(proto::server_command::Payload::ConfigReload(reload)) => {
                if let Some(ref config) = reload.config {
                    if let Err(e) = rule_cache.update_from_site_config(config) {
                        error!(error = %e, "Failed to apply config reload");
                    } else {
                        info!("Applied full config reload from server");
                    }
                }
                let handlers = command_handlers.read().await;
                if let Some(ref cb) = handlers.on_config_reload {
                    cb();
                }
            },
            Some(proto::server_command::Payload::PurgeCache(purge)) => {
                info!(
                    site_id = %purge.site_id,
                    urls = purge.urls.len(),
                    tags = purge.tags.len(),
                    "Received cache purge command"
                );
                let handlers = command_handlers.read().await;
                if let Some(ref cb) = handlers.on_purge_cache {
                    cb(&purge.site_id, &purge.urls, &purge.tags);
                }
            },
            Some(proto::server_command::Payload::UpdateSite(update)) => {
                if let Some(ref site_config) = update.site_config {
                    if let Err(e) =
                        rule_cache.update_from_site_config(site_config)
                    {
                        error!(error = %e, "Failed to apply site update");
                    }
                }
            },
            Some(proto::server_command::Payload::RestartAgent(restart)) => {
                warn!(
                    reason = %restart.reason,
                    graceful = restart.graceful,
                    "Server requested agent restart"
                );
                let handlers = command_handlers.read().await;
                if let Some(ref cb) = handlers.on_restart {
                    cb(restart.graceful);
                }
            },
            Some(proto::server_command::Payload::FlushLogs(flush)) => {
                info!(
                    reason = %flush.reason,
                    "Server requested log flush"
                );
                // One-way command: the shipper flushes its current batch and
                // drains what arrived since, the effect shows up in the next
                // heartbeat's pending-log counters.
                flush_notify.notify_one();
            },
            None => {
                debug!("Received server command with no payload");
            },
        }
    }

    /// Run the log shipping loop.
    ///
    /// Batches log entries and sends them to the server periodically or when
    /// the batch size threshold is reached.
    async fn run_log_shipper(
        &self,
        channel: Channel,
        agent_id: &str,
    ) -> anyhow::Result<()> {
        let mut sink = GrpcLogSink {
            client: ProtoClient::new(channel),
            agent_token: self.agent_token.load_full(),
        };
        let mut state = self.log_state.lock().await;
        let LogShipState { receiver, backlog } = &mut *state;
        // Entries carried over from the previous session were stamped with
        // the identity it had registered under.
        backlog.restamp(agent_id);
        let batch_cap = self.config.log_batch_size.max(1);

        let flush_interval =
            Duration::from_secs(self.config.log_flush_interval_secs.max(1));
        let mut interval = tokio::time::interval(flush_interval);
        interval
            .set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            if self.shutdown_signal.load(Ordering::Relaxed) {
                // Flush remaining logs before shutdown
                self.flush_backlog(backlog, &mut sink).await;
                break;
            }

            tokio::select! {
                // A full batch the control plane has not taken stops the
                // intake: the queue behind it then holds the backlog, and
                // what overflows is dropped (and counted) in `send_log`.
                entry = receiver.recv(), if backlog.len() < batch_cap => {
                    match entry {
                        Some(log_entry) => {
                            backlog.push(self.dequeue(agent_id, log_entry));
                            // Flush when the batch is full - unless the last
                            // attempt failed, which waits for the next tick
                            // rather than retrying on every entry.
                            if backlog.len() >= batch_cap && !backlog.stalled {
                                self.flush_backlog(backlog, &mut sink).await;
                            }
                        }
                        None => {
                            // Channel closed
                            debug!("Log channel closed");
                            break;
                        }
                    }
                }
                _ = interval.tick() => {
                    // Periodic flush
                    self.flush_backlog(backlog, &mut sink).await;
                }
                _ = self.flush_notify.notified() => {
                    // A server-initiated flush: ship the current batch now,
                    // then drain whatever arrived while the RPC was in
                    // flight — up to one batch, so a flood cannot turn a
                    // single command into an unbounded send loop.
                    self.flush_backlog(backlog, &mut sink).await;
                    while backlog.len() < batch_cap {
                        match receiver.try_recv() {
                            Ok(entry) => {
                                backlog.push(self.dequeue(agent_id, entry))
                            },
                            Err(mpsc::error::TryRecvError::Empty) => break,
                            Err(mpsc::error::TryRecvError::Disconnected) => {
                                debug!("Log channel closed");
                                break;
                            },
                        }
                    }
                    if !backlog.stalled {
                        self.flush_backlog(backlog, &mut sink).await;
                    }
                    // The next periodic flush measures from now, not from
                    // the tick that was interrupted mid-cycle.
                    interval.reset();
                }
                _ = self.wait_for_shutdown() => {
                    self.flush_backlog(backlog, &mut sink).await;
                    break;
                }
            }
        }

        Ok(())
    }

    /// Converts an entry taken off the queue for the batch, returning its
    /// body bytes to the queue's budget. The batch is not charged: it is
    /// bounded by `log_batch_size`.
    fn dequeue(&self, agent_id: &str, entry: LogEntry) -> proto::LogEntry {
        self.queued_bodies.release(entry.body_bytes());
        Self::convert_log_entry(agent_id, entry)
    }

    /// Ships the backlog and accounts for what the control plane refused.
    async fn flush_backlog(
        &self,
        backlog: &mut LogBacklog,
        sink: &mut impl LogSink,
    ) {
        let dropped = backlog.flush(sink).await;
        if dropped > 0 {
            let total = self.metrics.record_logs_dropped(dropped as u64);
            error!(
                dropped,
                total, "dropped log entries the control plane refused to store"
            );
        }
    }

    /// Run the certificate-event shipping loop.
    ///
    /// Drains the global ACME capture buffer on the same cadence as the log
    /// shipper. Errors are logged and swallowed: a control plane without the
    /// `ShipCertEvents` RPC must not tear down an otherwise healthy
    /// connection.
    async fn run_cert_event_shipper(
        &self,
        channel: Channel,
        agent_id: &str,
    ) -> anyhow::Result<()> {
        let mut client = ProtoClient::new(channel);
        let agent_token = self.agent_token.load_full();

        let flush_interval =
            Duration::from_secs(self.config.log_flush_interval_secs.max(1));
        let mut interval = tokio::time::interval(flush_interval);
        interval
            .set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            if self.shutdown_signal.load(Ordering::Relaxed) {
                let entries = self.drain_cert_events(agent_id);
                if !entries.is_empty() {
                    Self::flush_cert_events(&mut client, entries, &agent_token)
                        .await;
                }
                break;
            }

            tokio::select! {
                _ = interval.tick() => {
                    let entries = self.drain_cert_events(agent_id);
                    if !entries.is_empty() {
                        Self::flush_cert_events(&mut client, entries, &agent_token)
                            .await;
                    }
                }
                _ = self.wait_for_shutdown() => {
                    let entries = self.drain_cert_events(agent_id);
                    if !entries.is_empty() {
                        Self::flush_cert_events(&mut client, entries, &agent_token)
                            .await;
                    }
                    break;
                }
            }
        }

        Ok(())
    }

    /// Drain the capture buffer and stamp each event with its site and
    /// certificate, resolved against the current site rules: the tracing
    /// layer sees only log text, so attribution happens here, where the
    /// domain → site topology lives (see [`attribute_events`]).
    fn drain_cert_events(&self, agent_id: &str) -> Vec<proto::CertEventEntry> {
        let mut entries = cert_event_buffer().drain(agent_id);
        if entries.iter().any(|entry| entry.site_id.is_empty()) {
            let sites = self.rule_cache.all_sites();
            let attributions: Vec<CertAttribution> = sites
                .sites
                .values()
                .map(|site| {
                    let mut domains = vec![site.domain.to_lowercase()];
                    domains.extend(
                        site.alternate_domains
                            .iter()
                            .map(|domain| domain.to_lowercase()),
                    );
                    CertAttribution {
                        domains,
                        site_id: site.site_id.to_string(),
                        certificate_id: site
                            .ssl_config
                            .as_ref()
                            .map(|ssl| ssl.certificate_id.clone())
                            .unwrap_or_default(),
                    }
                })
                .collect();
            attribute_events(&mut entries, &attributions);
        }
        entries
    }

    /// Flush a batch of certificate events to the server.
    async fn flush_cert_events(
        client: &mut ProtoClient<Channel>,
        entries: Vec<proto::CertEventEntry>,
        agent_token: &Option<Arc<String>>,
    ) {
        let count = entries.len();
        let mut request = tonic::Request::new(tokio_stream::iter(entries));
        attach_agent_token(&mut request, agent_token);
        match client.ship_cert_events(request).await {
            Ok(response) => {
                let ack = response.into_inner();
                if ack.success {
                    debug!(
                        count,
                        received = ack.received_count,
                        "Flushed cert events to server"
                    );
                } else {
                    warn!(
                        error = %ack.error_message,
                        "Server rejected cert event batch"
                    );
                }
            },
            Err(e) => {
                error!(error = %e, count, "Failed to ship cert events");
            },
        }
    }

    /// Convert a local LogEntry to the proto LogEntry type.
    fn convert_log_entry(agent_id: &str, entry: LogEntry) -> proto::LogEntry {
        proto::LogEntry {
            agent_id: agent_id.to_string(),
            site_id: entry.site_id,
            request_id: entry.request_id,
            timestamp: Some(prost_types::Timestamp {
                seconds: chrono::Utc::now().timestamp(),
                nanos: 0,
            }),
            client_ip: entry.client_ip,
            method: entry.method,
            scheme: entry.scheme,
            host: entry.host,
            path: entry.path,
            query_string: entry.query_string,
            protocol: entry.protocol,
            request_headers: entry.request_headers,
            request_body: entry.request_body.unwrap_or_default(),
            request_body_size: entry.request_body_size,
            request_body_truncated: entry.request_body_truncated,
            response_status: entry.response_status,
            response_headers: entry.response_headers,
            response_body: entry.response_body.unwrap_or_default(),
            response_body_size: entry.response_body_size,
            response_body_truncated: entry.response_body_truncated,
            upstream_addr: entry.upstream_addr,
            upstream_latency_ms: entry.upstream_latency_ms,
            upstream_status: entry.upstream_status,
            waf_score: entry.waf_score,
            waf_action: entry.waf_action,
            waf_rule_id: entry.waf_rule_id,
            waf_enforced_rule_id: entry.waf_enforced_rule_id,
            waf_rule_name: entry.waf_rule_name,
            waf_event_type: entry.waf_event_type,
            waf_details: entry.waf_details,
            waf_matched_tags: entry.waf_matched_tags,
            user_identity: entry.user_identity,
            total_latency_ms: entry.total_latency_ms,
            cache_status: entry.cache_status,
            tls_version: entry.tls_version,
            ja3_hash: entry.ja3_hash,
            country_code: entry.country_code,
            city: entry.city,
            asn: entry.asn,
            user_agent: entry.user_agent,
            referer: entry.referer,
        }
    }

    /// Wait until the shutdown signal is set.
    async fn wait_for_shutdown(&self) {
        let shutdown = Arc::clone(&self.shutdown_signal);
        loop {
            if shutdown.load(Ordering::Relaxed) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Signal the client to shut down gracefully.
    pub fn shutdown(&self) {
        info!("Initiating agent shutdown");
        self.shutdown_signal.store(true, Ordering::Relaxed);
        // A debounced rule update may still be waiting for the flush loop.
        self.rule_cache.flush_rule_cache_if_dirty();
    }

    /// Get the current system metrics snapshot.
    ///
    /// This is a *read-only* sample on its own CPU baseline
    /// (`collect_snapshot`), not a heartbeat collection: `collect()` would
    /// consume the heartbeat's `LAST_CPU` baseline, and the two run on
    /// independent schedules, so a snapshot firing just before a heartbeat
    /// would leave it differencing over a near-zero interval.
    pub fn metrics_snapshot(&self) -> SystemMetrics {
        self.metrics.collect_snapshot()
    }
}

// ─────────────────────────────────────────────────────────────
// Helper functions for system information
// ─────────────────────────────────────────────────────────────

/// Future that never resolves: the value a disabled metric shipper parks on
/// so it neither ships nor completes the surrounding select. Tested with a
/// timeout — the contract is "does not complete".
async fn metric_shipper_disabled() -> anyhow::Result<()> {
    std::future::pending::<anyhow::Result<()>>().await
}

/// Attaches the agent token as `x-agent-token` metadata — the transport-level
/// credential the control plane authenticates the shipping streams with (the
/// ship message bodies carry no token field).
fn attach_agent_token<T>(
    request: &mut tonic::Request<T>,
    token: &Option<Arc<String>>,
) {
    if let Some(token) = token {
        if let Ok(value) = token.parse() {
            request.metadata_mut().insert("x-agent-token", value);
        }
    }
}

/// How long a visitor-auth call may take before it is treated as a refusal.
///
/// Short on purpose. A login is a person waiting at a form, and a control
/// plane that has not answered in this long is not going to answer usefully.
/// The data plane turns the timeout into "login is unavailable" rather than
/// letting the request hang, which is the fail-closed direction.
const VISITOR_AUTH_TIMEOUT: Duration = Duration::from_secs(10);

/// The visitor-authentication calls, on the same channel the rest of the
/// agent uses.
///
/// Every method here returns `Err` when the control plane cannot be reached.
/// The caller must treat that as a refusal — a login that cannot be checked is
/// not a login — rather than falling back to anything local.
impl ControlPlaneClient {
    /// Opens a client for one visitor-auth call.
    ///
    /// A fresh channel per call rather than a cached one: logins are rare
    /// (a person signing in, not a per-request path), and the connection
    /// machinery the long-lived streams use would otherwise need a second
    /// reconnect loop to keep alive. The cost is a TCP+HTTP/2 handshake on a
    /// login, which is the same order as the bcrypt verification that follows
    /// it.
    async fn visitor_auth_client(
        &self,
    ) -> anyhow::Result<ProtoClient<Channel>> {
        let channel = self.create_channel().await?;
        Ok(ProtoClient::new(channel))
    }

    /// The agent token, or an error when the agent has not registered yet.
    ///
    /// Every visitor RPC authenticates with it, so a call before registration
    /// cannot succeed and says so rather than sending an empty credential.
    fn require_agent_token(&self) -> anyhow::Result<String> {
        self.agent_token
            .load_full()
            .map(|token| token.as_ref().clone())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "agent is not registered with the control plane"
                )
            })
    }

    /// Asks for a proof-of-work challenge for a site's login form.
    pub async fn visitor_login_challenge(
        &self,
        agent_id: &str,
        site_id: &str,
    ) -> anyhow::Result<proto::VisitorChallengeResponse> {
        let token = self.require_agent_token()?;
        let mut client = self.visitor_auth_client().await?;
        let request = proto::VisitorChallengeRequest {
            agent_id: agent_id.to_string(),
            agent_token: token,
            site_id: site_id.to_string(),
        };
        let response = tokio::time::timeout(
            VISITOR_AUTH_TIMEOUT,
            client.visitor_login_challenge(request),
        )
        .await
        .map_err(|_| anyhow::anyhow!("control plane timed out"))?
        .map_err(|status| anyhow::anyhow!("control plane refused: {status}"))?;
        Ok(response.into_inner())
    }

    /// Exchanges a solved challenge and credentials for an identity.
    ///
    /// The password is passed through and never logged or retained here.
    #[allow(clippy::too_many_arguments)]
    pub async fn visitor_login(
        &self,
        agent_id: &str,
        site_id: &str,
        challenge_id: &str,
        solution: &str,
        timestamp: i64,
        email: &str,
        password: &str,
    ) -> anyhow::Result<proto::VisitorLoginResponse> {
        let token = self.require_agent_token()?;
        let mut client = self.visitor_auth_client().await?;
        let request = proto::VisitorLoginRequest {
            agent_id: agent_id.to_string(),
            agent_token: token,
            site_id: site_id.to_string(),
            challenge_id: challenge_id.to_string(),
            solution: solution.to_string(),
            timestamp,
            email: email.to_string(),
            password: password.to_string(),
        };
        let response = tokio::time::timeout(
            VISITOR_AUTH_TIMEOUT,
            client.visitor_login(request),
        )
        .await
        .map_err(|_| anyhow::anyhow!("control plane timed out"))?
        .map_err(|status| anyhow::anyhow!("control plane refused: {status}"))?;
        Ok(response.into_inner())
    }

    /// Reports the end of a visitor session.
    pub async fn visitor_logout(
        &self,
        agent_id: &str,
        visitor_id: &str,
        site_id: &str,
    ) -> anyhow::Result<()> {
        let token = self.require_agent_token()?;
        let mut client = self.visitor_auth_client().await?;
        let request = proto::VisitorLogoutRequest {
            agent_id: agent_id.to_string(),
            agent_token: token,
            visitor_id: visitor_id.to_string(),
            site_id: site_id.to_string(),
        };
        tokio::time::timeout(
            VISITOR_AUTH_TIMEOUT,
            client.visitor_logout(request),
        )
        .await
        .map_err(|_| anyhow::anyhow!("control plane timed out"))?
        .map_err(|status| anyhow::anyhow!("control plane refused: {status}"))?;
        Ok(())
    }

    /// Changes a visitor's password, returning the new token version.
    pub async fn visitor_change_password(
        &self,
        agent_id: &str,
        site_id: &str,
        visitor_id: &str,
        current_password: &str,
        new_password: &str,
    ) -> anyhow::Result<proto::VisitorChangePasswordResponse> {
        let token = self.require_agent_token()?;
        let mut client = self.visitor_auth_client().await?;
        let request = proto::VisitorChangePasswordRequest {
            agent_id: agent_id.to_string(),
            agent_token: token,
            visitor_id: visitor_id.to_string(),
            current_password: current_password.to_string(),
            new_password: new_password.to_string(),
            site_id: site_id.to_string(),
        };
        let response = tokio::time::timeout(
            VISITOR_AUTH_TIMEOUT,
            client.visitor_change_password(request),
        )
        .await
        .map_err(|_| anyhow::anyhow!("control plane timed out"))?
        .map_err(|status| anyhow::anyhow!("control plane refused: {status}"))?;
        Ok(response.into_inner())
    }

    /// The sites a visitor may enter, for the portal.
    pub async fn visitor_grants(
        &self,
        agent_id: &str,
        site_id: &str,
        visitor_id: &str,
    ) -> anyhow::Result<proto::VisitorGrantsResponse> {
        let token = self.require_agent_token()?;
        let mut client = self.visitor_auth_client().await?;
        let request = proto::VisitorGrantsRequest {
            agent_id: agent_id.to_string(),
            agent_token: token,
            visitor_id: visitor_id.to_string(),
            site_id: site_id.to_string(),
        };
        let response = tokio::time::timeout(
            VISITOR_AUTH_TIMEOUT,
            client.visitor_grants(request),
        )
        .await
        .map_err(|_| anyhow::anyhow!("control plane timed out"))?
        .map_err(|status| anyhow::anyhow!("control plane refused: {status}"))?;
        Ok(response.into_inner())
    }

    /// Starts a passkey registration for a signed-in visitor.
    pub async fn visitor_passkey_register_begin(
        &self,
        agent_id: &str,
        visitor_id: &str,
        site_id: &str,
    ) -> anyhow::Result<proto::VisitorPasskeyOptionsResponse> {
        let token = self.require_agent_token()?;
        let mut client = self.visitor_auth_client().await?;
        let request = proto::VisitorPasskeyBeginRequest {
            agent_id: agent_id.to_string(),
            agent_token: token,
            visitor_id: visitor_id.to_string(),
            site_id: site_id.to_string(),
        };
        let response = tokio::time::timeout(
            VISITOR_AUTH_TIMEOUT,
            client.visitor_passkey_register_begin(request),
        )
        .await
        .map_err(|_| anyhow::anyhow!("control plane timed out"))?
        .map_err(|status| anyhow::anyhow!("control plane refused: {status}"))?;
        Ok(response.into_inner())
    }

    /// Finishes a passkey registration.
    pub async fn visitor_passkey_register_finish(
        &self,
        agent_id: &str,
        site_id: &str,
        ceremony_id: &str,
        credential_json: &str,
        name: &str,
    ) -> anyhow::Result<proto::VisitorPasskeyFinishResponse> {
        let token = self.require_agent_token()?;
        let mut client = self.visitor_auth_client().await?;
        let request = proto::VisitorPasskeyFinishRequest {
            agent_id: agent_id.to_string(),
            agent_token: token,
            site_id: site_id.to_string(),
            ceremony_id: ceremony_id.to_string(),
            credential_json: credential_json.to_string(),
            name: name.to_string(),
        };
        let response = tokio::time::timeout(
            VISITOR_AUTH_TIMEOUT,
            client.visitor_passkey_register_finish(request),
        )
        .await
        .map_err(|_| anyhow::anyhow!("control plane timed out"))?
        .map_err(|status| anyhow::anyhow!("control plane refused: {status}"))?;
        Ok(response.into_inner())
    }

    /// Starts a passkey sign-in.
    pub async fn visitor_passkey_login_begin(
        &self,
        agent_id: &str,
        site_id: &str,
    ) -> anyhow::Result<proto::VisitorPasskeyOptionsResponse> {
        let token = self.require_agent_token()?;
        let mut client = self.visitor_auth_client().await?;
        let request = proto::VisitorPasskeyBeginRequest {
            agent_id: agent_id.to_string(),
            agent_token: token,
            visitor_id: String::new(),
            site_id: site_id.to_string(),
        };
        let response = tokio::time::timeout(
            VISITOR_AUTH_TIMEOUT,
            client.visitor_passkey_login_begin(request),
        )
        .await
        .map_err(|_| anyhow::anyhow!("control plane timed out"))?
        .map_err(|status| anyhow::anyhow!("control plane refused: {status}"))?;
        Ok(response.into_inner())
    }

    /// Finishes a passkey sign-in, returning the identity on success.
    pub async fn visitor_passkey_login_finish(
        &self,
        agent_id: &str,
        site_id: &str,
        ceremony_id: &str,
        credential_json: &str,
    ) -> anyhow::Result<proto::VisitorLoginResponse> {
        let token = self.require_agent_token()?;
        let mut client = self.visitor_auth_client().await?;
        let request = proto::VisitorPasskeyFinishRequest {
            agent_id: agent_id.to_string(),
            agent_token: token,
            site_id: site_id.to_string(),
            ceremony_id: ceremony_id.to_string(),
            credential_json: credential_json.to_string(),
            name: String::new(),
        };
        let response = tokio::time::timeout(
            VISITOR_AUTH_TIMEOUT,
            client.visitor_passkey_login_finish(request),
        )
        .await
        .map_err(|_| anyhow::anyhow!("control plane timed out"))?
        .map_err(|status| anyhow::anyhow!("control plane refused: {status}"))?;
        Ok(response.into_inner())
    }

    /// Lists a visitor's passkeys, for the portal.
    pub async fn visitor_passkey_list(
        &self,
        agent_id: &str,
        site_id: &str,
        visitor_id: &str,
    ) -> anyhow::Result<proto::VisitorPasskeyListResponse> {
        let token = self.require_agent_token()?;
        let mut client = self.visitor_auth_client().await?;
        let request = proto::VisitorGrantsRequest {
            agent_id: agent_id.to_string(),
            agent_token: token,
            visitor_id: visitor_id.to_string(),
            site_id: site_id.to_string(),
        };
        let response = tokio::time::timeout(
            VISITOR_AUTH_TIMEOUT,
            client.visitor_passkey_list(request),
        )
        .await
        .map_err(|_| anyhow::anyhow!("control plane timed out"))?
        .map_err(|status| anyhow::anyhow!("control plane refused: {status}"))?;
        Ok(response.into_inner())
    }

    /// Checks that a session is still valid.
    ///
    /// The data plane caches the answer briefly, so this is called at most
    /// once per cache window per session rather than on every request.
    pub async fn visitor_validate_session(
        &self,
        agent_id: &str,
        site_id: &str,
        visitor_id: &str,
        token_version: i64,
    ) -> anyhow::Result<proto::VisitorValidateResponse> {
        let token = self.require_agent_token()?;
        let mut client = self.visitor_auth_client().await?;
        let request = proto::VisitorValidateRequest {
            agent_id: agent_id.to_string(),
            agent_token: token,
            site_id: site_id.to_string(),
            visitor_id: visitor_id.to_string(),
            token_version,
        };
        let response = tokio::time::timeout(
            VISITOR_AUTH_TIMEOUT,
            client.visitor_validate_session(request),
        )
        .await
        .map_err(|_| anyhow::anyhow!("control plane timed out"))?
        .map_err(|status| anyhow::anyhow!("control plane refused: {status}"))?;
        Ok(response.into_inner())
    }

    /// Toggles the portal's per-site "show this here" switch.
    pub async fn visitor_set_site_visible(
        &self,
        agent_id: &str,
        visitor_id: &str,
        site_id: &str,
        visible: bool,
    ) -> anyhow::Result<proto::VisitorSetVisibleResponse> {
        let token = self.require_agent_token()?;
        let mut client = self.visitor_auth_client().await?;
        let request = proto::VisitorSetVisibleRequest {
            agent_id: agent_id.to_string(),
            agent_token: token,
            visitor_id: visitor_id.to_string(),
            site_id: site_id.to_string(),
            visible,
        };
        let response = tokio::time::timeout(
            VISITOR_AUTH_TIMEOUT,
            client.visitor_set_site_visible(request),
        )
        .await
        .map_err(|_| anyhow::anyhow!("control plane timed out"))?
        .map_err(|status| anyhow::anyhow!("control plane refused: {status}"))?;
        Ok(response.into_inner())
    }
}

/// Enables TLS for `https://` server URLs.
///
/// `Endpoint::from_shared` does not do this on its own — without the explicit
/// config the agent would speak cleartext h2 into a TLS port. With inline CA
/// PEM (all-in-one) or a configured CA file that material is the only trust
/// anchor; otherwise the bundled webpki roots apply.
///
/// `tls_name` overrides the name used for SNI and certificate verification,
/// for control planes whose certificate carries no SAN for the host being
/// dialed (a self-signed certificate issued for the container hostname,
/// reached through a public name). The chain and the name are still checked:
/// the value must be one of the certificate's SANs.
fn apply_client_tls(
    endpoint: Endpoint,
    server_url: &str,
    ca_cert_path: &Option<String>,
    ca_cert_pem: &Option<String>,
    tls_name: &Option<String>,
) -> anyhow::Result<Endpoint> {
    if !has_scheme(server_url, "https://") {
        return Ok(endpoint);
    }
    let mut tls = ClientTlsConfig::new();
    if let Some(pem) = ca_cert_pem {
        tls = tls.ca_certificate(Certificate::from_pem(pem));
    } else if let Some(path) = ca_cert_path {
        let pem = std::fs::read_to_string(path).map_err(|err| {
            anyhow::anyhow!(
                "failed to read server CA certificate {path}: {err}"
            )
        })?;
        tls = tls.ca_certificate(Certificate::from_pem(pem));
    } else {
        tls = tls.with_enabled_roots();
    }
    if let Some(name) = tls_name {
        tls = tls.domain_name(name.clone());
    }
    Ok(endpoint.tls_config(tls)?)
}

/// Whether `url` starts with `scheme`, ignoring ASCII case.
///
/// URI schemes are case-insensitive (`HTTPS://host` is valid), so a
/// case-sensitive `starts_with` would silently skip the TLS setup and send
/// cleartext h2 to a TLS port again.
fn has_scheme(url: &str, scheme: &str) -> bool {
    url.get(..scheme.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(scheme))
}

/// Doubles the current reconnect backoff, capped at the configured maximum,
/// then shrinks it to a random point in the lower half of that value.
///
/// The jitter stops a fleet of agents that lost the control plane together —
/// a deploy, a network blip — from reconnecting in a lockstep burst every
/// `reconnect_max_delay_ms`.
fn next_backoff(current_ms: u64, max_ms: u64) -> u64 {
    let capped = current_ms.saturating_mul(2).min(max_ms);
    let factor = 0.5 + rand::random::<f64>() * 0.5;
    ((capped as f64 * factor) as u64).max(1)
}

/// Actionable advice for a control-plane connection failure, or `None` when
/// the error does not match a known configuration mistake.
///
/// TLS misconfiguration otherwise surfaces as an opaque h2 error: the only
/// visible symptom is `h2 protocol error` / `FRAME_SIZE_ERROR`, which sends
/// operators looking at the wrong layer. The match runs over the whole anyhow
/// chain (`{:#}`) because tonic wraps the rustls error several levels deep.
fn connection_hint(
    error: &anyhow::Error,
    server_url: &str,
) -> Option<&'static str> {
    const PLAINTEXT: &str = "server_url uses http:// but the control plane's gRPC port serves TLS (symptom: h2 protocol error / FRAME_SIZE_ERROR); use https:// and set agent.server_ca_cert (or --server-ca-cert) to the control plane certificate";
    const UNKNOWN_ISSUER: &str = "the control plane certificate is not trusted; download it (Settings -> Control plane HTTPS) and set agent.server_ca_cert (or --server-ca-cert)";
    const NAME_MISMATCH: &str = "the certificate does not name the host in server_url; set agent.server_tls_name to one of its SANs, or dial a name the certificate carries";
    const UNREACHABLE: &str = "the control plane is unreachable; check server_url, that the gRPC port (9090) is open, and the firewall";

    let chain = format!("{error:#}").to_ascii_lowercase();
    let h2_error = chain.contains("frame_size_error")
        || chain.contains("h2 protocol error")
        || chain.contains("http2 error");
    // Only blame plaintext when the URL is plaintext: an h2 error over https
    // is a protocol problem, not a scheme mistake.
    if has_scheme(server_url, "http://") && h2_error {
        return Some(PLAINTEXT);
    }
    if chain.contains("unknownissuer")
        || chain.contains("unknown issuer")
        || chain.contains("unable to get local issuer")
    {
        return Some(UNKNOWN_ISSUER);
    }
    // rustls's Display form is `certificate not valid for name "…"`; the
    // variant spellings are defensive against a different rustls wording.
    if chain.contains("notvalidforname")
        || chain.contains("not valid for name")
        || chain.contains("certificate not valid for")
    {
        return Some(NAME_MISMATCH);
    }
    if chain.contains("connection refused")
        || chain.contains("tcp connect error")
        || chain.contains("timed out")
        || chain.contains("deadline has elapsed")
        || chain.contains("connection reset")
    {
        return Some(UNREACHABLE);
    }
    None
}

/// The `hint` field written to the failure log: empty when unrecognised.
fn connection_hint_field(
    error: &anyhow::Error,
    server_url: &str,
) -> &'static str {
    connection_hint(error, server_url).unwrap_or("")
}

/// The cadence the heartbeat sender ticks at.
///
/// The server-sent interval wins whenever the control plane handed one down
/// (a positive value; its config validation guarantees one in practice),
/// otherwise the agent's local configuration applies. Either way the result
/// is clamped so a pathological value cannot silence liveness reporting.
fn effective_heartbeat_interval(server_secs: i64, local_secs: u64) -> Duration {
    let secs = if server_secs > 0 {
        server_secs as u64
    } else {
        local_secs
    };
    Duration::from_secs(secs.max(5))
}

/// Health reported in the heartbeat. `config_hash` names the configuration
/// the agent received; when the data plane could not apply it in full the
/// node is serving something else, which the control plane must not read as
/// healthy.
fn heartbeat_health(config_apply_error: &str) -> proto::AgentHealthStatus {
    if config_apply_error.is_empty() {
        proto::AgentHealthStatus::AgentHealthHealthy
    } else {
        proto::AgentHealthStatus::AgentHealthDegraded
    }
}

/// Convert a probe sample into its wire representation.
fn to_proto_sample(sample: &HostSample) -> proto::HostSample {
    proto::HostSample {
        ts_millis: sample.ts_millis,
        cpu_usage_percent: sample.cpu_usage_percent,
        load1: sample.load1,
        load5: sample.load5,
        load15: sample.load15,
        memory_total_bytes: sample.memory_total_bytes,
        memory_used_bytes: sample.memory_used_bytes,
        memory_available_bytes: sample.memory_available_bytes,
        swap_total_bytes: sample.swap_total_bytes,
        swap_used_bytes: sample.swap_used_bytes,
        disk_total_bytes: sample.disk_total_bytes,
        disk_used_bytes: sample.disk_used_bytes,
        net_rx_bytes: sample.net_rx_bytes,
        net_tx_bytes: sample.net_tx_bytes,
        disk_read_bytes: sample.disk_read_bytes,
        disk_write_bytes: sample.disk_write_bytes,
        process_count: sample.process_count,
        tcp_connections: sample.tcp_connections,
        uptime_secs: sample.uptime_secs,
        process_rss_bytes: sample.process_rss_bytes,
    }
}

/// Sort a block list into a deterministic prefix and report whether anything
/// was dropped; the control plane uses the flag to keep the rows it did not
/// see this round.
///
/// Test-only reference: the production heartbeat now calls
/// `RuleCache::blocked_ips_page` directly. This is the original
/// "clone-everything, sort, truncate" implementation kept so tests can assert
/// the page produces an identical prefix.
#[cfg(test)]
fn heartbeat_blocked_ips(
    mut entries: Vec<BlockedIpEntry>,
) -> (Vec<proto::BlockedIp>, bool) {
    entries.sort_by(|a, b| {
        (a.site_id.as_str(), a.ip.as_str())
            .cmp(&(b.site_id.as_str(), b.ip.as_str()))
    });
    let truncated = entries.len() > MAX_HEARTBEAT_BLOCKED_IPS;
    entries.truncate(MAX_HEARTBEAT_BLOCKED_IPS);
    (entries.iter().map(to_proto_blocked_ip).collect(), truncated)
}

/// Convert a dynamic IP block into its wire representation.
fn to_proto_blocked_ip(entry: &BlockedIpEntry) -> proto::BlockedIp {
    proto::BlockedIp {
        ip: entry.ip.clone(),
        site_id: entry.site_id.clone(),
        reason: entry.reason.clone(),
        blocked_at: Some(prost_types::Timestamp {
            seconds: entry.blocked_at.timestamp(),
            nanos: 0,
        }),
        expires_at: entry.expires_at.map(|exp| prost_types::Timestamp {
            seconds: exp.timestamp(),
            nanos: 0,
        }),
    }
}

fn get_hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| {
            std::env::var("HOSTNAME")
                .or_else(|_| std::env::var("COMPUTERNAME"))
                .unwrap_or_else(|_| "unknown".to_string())
        })
}

fn get_local_ip() -> String {
    // Same egress probe the metrics sampler uses: it tries an IPv4 then an
    // IPv6 destination, so an IPv6-only node reports its real address instead
    // of the loopback fallback the hard-coded `0.0.0.0` socket produced.
    crate::probe::egress_ip()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string())
}

fn get_system_info() -> (u32, u64, String) {
    let cpu_cores = std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1);

    let memory_bytes = get_total_memory();

    let os_info =
        format!("{} {}", std::env::consts::OS, std::env::consts::ARCH);

    (cpu_cores, memory_bytes, os_info)
}

fn get_total_memory() -> u64 {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|content| {
                content
                    .lines()
                    .find(|l| l.starts_with("MemTotal:"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|v| v.parse::<u64>().ok())
                    .map(|kb| kb * 1024)
            })
            .unwrap_or(0)
    }
    #[cfg(target_os = "macos")]
    {
        // Use sysctl to get total memory on macOS
        std::process::Command::new("sysctl")
            .args(["-n", "hw.memsize"])
            .output()
            .ok()
            .and_then(|output| {
                String::from_utf8_lossy(&output.stdout)
                    .trim()
                    .parse::<u64>()
                    .ok()
            })
            .unwrap_or(0)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        0
    }
}

/// How one shipment of log entries ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShipOutcome {
    /// The control plane stored the entries.
    Accepted,
    /// The link, or the control plane as a whole, failed. Nothing says the
    /// entries are at fault: they are kept and sent again.
    Unavailable,
    /// The control plane received the entries and refused to store them.
    Rejected,
}

/// Tells a refusal of the entries apart from a failure to reach, or to be
/// served by, the control plane.
///
/// Only the codes the control plane answers with after reading the stream
/// count as a refusal: a storage error (`Internal`) and a message it could
/// not accept (`InvalidArgument`, `OutOfRange`, `ResourceExhausted`,
/// `FailedPrecondition`, `DataLoss`). Everything else - a dropped connection,
/// a timeout, an expired token - would fail for any entry.
fn classify_ship_error(status: &tonic::Status) -> ShipOutcome {
    use tonic::Code;
    match status.code() {
        Code::Internal
        | Code::InvalidArgument
        | Code::OutOfRange
        | Code::ResourceExhausted
        | Code::FailedPrecondition
        | Code::DataLoss => ShipOutcome::Rejected,
        _ => ShipOutcome::Unavailable,
    }
}

/// Where the log shipper sends entries; a seam so the retry and isolation
/// rules can be exercised without a control plane.
trait LogSink {
    /// Ships `entries[range]` as one request.
    async fn ship(
        &mut self,
        entries: Arc<Vec<proto::LogEntry>>,
        range: std::ops::Range<usize>,
    ) -> ShipOutcome;
}

struct GrpcLogSink {
    client: ProtoClient<Channel>,
    agent_token: Option<Arc<String>>,
}

impl LogSink for GrpcLogSink {
    async fn ship(
        &mut self,
        entries: Arc<Vec<proto::LogEntry>>,
        range: std::ops::Range<usize>,
    ) -> ShipOutcome {
        let count = range.len();
        // The request stream reads from the shared batch and copies one
        // entry at a time as it is encoded, instead of duplicating the whole
        // batch (bodies included) before the call.
        let mut request = tonic::Request::new(tokio_stream::iter(
            range.map(move |index| entries[index].clone()),
        ));
        attach_agent_token(&mut request, &self.agent_token);
        match self.client.ship_logs(request).await {
            Ok(response) => {
                let ack = response.into_inner();
                if ack.success {
                    debug!(
                        count,
                        received = ack.received_count,
                        "Flushed logs to server"
                    );
                    ShipOutcome::Accepted
                } else {
                    // The server lost the stream part-way through reading
                    // it: a broken link, not a verdict on the entries.
                    warn!(
                        error = %ack.error_message,
                        count,
                        "Control plane did not receive the whole log batch; keeping it"
                    );
                    ShipOutcome::Unavailable
                }
            },
            Err(status) => {
                let outcome = classify_ship_error(&status);
                if outcome == ShipOutcome::Rejected {
                    warn!(error = %status, count, "Control plane refused the log batch");
                } else {
                    warn!(error = %status, count, "Failed to ship logs; keeping the batch");
                }
                outcome
            },
        }
    }
}

/// The log shipper's state that outlives a control-plane session.
struct LogShipState {
    receiver: mpsc::Receiver<LogEntry>,
    backlog: LogBacklog,
}

/// Log entries converted for the wire and not yet stored by the control
/// plane.
///
/// Entries leave only when the control plane has stored them or has singled
/// them out as unstorable. A shipment that fails, or is cancelled because the
/// session ended, leaves them in place for the next attempt.
struct LogBacklog {
    /// Shared with the request stream of the shipment in flight.
    entries: Arc<Vec<proto::LogEntry>>,
    /// Consecutive shipments of the whole batch the control plane refused.
    rejections: u32,
    /// Refusals needed before the next one-by-one pass.
    isolate_after: u32,
    /// The last shipment did not go through; the next one waits for the
    /// flush interval.
    stalled: bool,
}

impl Default for LogBacklog {
    fn default() -> Self {
        Self {
            entries: Arc::default(),
            rejections: 0,
            isolate_after: LOG_SHIP_ISOLATION_THRESHOLD,
            stalled: false,
        }
    }
}

impl LogBacklog {
    fn len(&self) -> usize {
        self.entries.len()
    }

    fn push(&mut self, entry: proto::LogEntry) {
        Arc::make_mut(&mut self.entries).push(entry);
    }

    /// Re-stamps the entries with the identity of the current session.
    fn restamp(&mut self, agent_id: &str) {
        if self.entries.iter().all(|entry| entry.agent_id == agent_id) {
            return;
        }
        for entry in Arc::make_mut(&mut self.entries) {
            entry.agent_id = agent_id.to_string();
        }
    }

    /// Removes the first `count` entries.
    fn discard_front(&mut self, count: usize) {
        match Arc::get_mut(&mut self.entries) {
            Some(entries) => {
                entries.drain(..count);
            },
            // A request stream that is still being torn down holds the
            // other reference; leave it its copy.
            None => self.entries = Arc::new(self.entries[count..].to_vec()),
        }
    }

    /// Ships the batch. Returns how many entries were given up on.
    ///
    /// A batch that could not be delivered is kept whole. Only repeated
    /// refusals by the control plane lead to [`Self::isolate`].
    async fn flush(&mut self, sink: &mut impl LogSink) -> usize {
        let count = self.len();
        if count == 0 {
            return 0;
        }
        match sink.ship(Arc::clone(&self.entries), 0..count).await {
            ShipOutcome::Accepted => {
                self.discard_front(count);
                self.rejections = 0;
                self.isolate_after = LOG_SHIP_ISOLATION_THRESHOLD;
                self.stalled = false;
                0
            },
            ShipOutcome::Unavailable => {
                self.stalled = true;
                0
            },
            ShipOutcome::Rejected => {
                self.stalled = true;
                self.rejections += 1;
                if self.rejections < self.isolate_after {
                    return 0;
                }
                self.rejections = 0;
                self.isolate(sink).await
            },
        }
    }

    /// Ships the batch one entry per request, to find the entries the
    /// control plane cannot store. Returns how many were dropped.
    ///
    /// One unstorable entry (before the server-side NUL sanitiser shipped, a
    /// binary body did exactly this) must not hold back every log line
    /// behind it. An entry is only dropped when another one of the same pass
    /// was stored: that is what shows the control plane is working and the
    /// entry is the problem. A pass that gets nothing through means the
    /// control plane is refusing everything (its database is down, say), so
    /// the batch is kept and the next pass is put off for longer.
    async fn isolate(&mut self, sink: &mut impl LogSink) -> usize {
        let mut refused = 0;
        let mut tried = 0;
        let mut interrupted = false;
        while tried < self.len() {
            let range = tried..tried + 1;
            match sink.ship(Arc::clone(&self.entries), range).await {
                ShipOutcome::Accepted => {},
                ShipOutcome::Rejected => refused += 1,
                // The link went away mid-pass: the rest waits.
                ShipOutcome::Unavailable => {
                    interrupted = true;
                    break;
                },
            }
            tried += 1;
        }
        if refused == tried {
            if !interrupted {
                self.isolate_after = self
                    .isolate_after
                    .saturating_mul(2)
                    .min(LOG_SHIP_ISOLATION_THRESHOLD_MAX);
            }
            return 0;
        }
        self.discard_front(tried);
        self.isolate_after = LOG_SHIP_ISOLATION_THRESHOLD;
        self.stalled = self.len() > 0;
        refused
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The heartbeat used to say "healthy" unconditionally, so a node whose
    /// reload failed looked exactly like one running the new configuration.
    #[test]
    fn heartbeat_health_follows_the_reload_outcome() {
        assert_eq!(
            heartbeat_health(""),
            proto::AgentHealthStatus::AgentHealthHealthy
        );
        assert_eq!(
            heartbeat_health("certificates: bad pem(site-a)"),
            proto::AgentHealthStatus::AgentHealthDegraded
        );
    }

    /// A sink that answers from a script: the verdict of each request, then
    /// `Accepted` once the script runs out. `poison` entries are refused
    /// whenever they are part of a request, whatever the script says.
    #[derive(Default)]
    struct ScriptedSink {
        script: std::collections::VecDeque<ShipOutcome>,
        poison: Vec<String>,
        /// The request ids of every request, in order.
        requests: Vec<Vec<String>>,
        stored: Vec<String>,
    }

    impl LogSink for ScriptedSink {
        async fn ship(
            &mut self,
            entries: Arc<Vec<proto::LogEntry>>,
            range: std::ops::Range<usize>,
        ) -> ShipOutcome {
            let ids: Vec<String> = entries[range]
                .iter()
                .map(|entry| entry.request_id.clone())
                .collect();
            self.requests.push(ids.clone());
            let scripted =
                self.script.pop_front().unwrap_or(ShipOutcome::Accepted);
            let outcome = if scripted == ShipOutcome::Accepted
                && ids.iter().any(|id| self.poison.contains(id))
            {
                ShipOutcome::Rejected
            } else {
                scripted
            };
            if outcome == ShipOutcome::Accepted {
                self.stored.extend(ids);
            }
            outcome
        }
    }

    fn backlog_of(ids: &[&str]) -> LogBacklog {
        let mut backlog = LogBacklog::default();
        for id in ids {
            backlog.push(proto::LogEntry {
                request_id: id.to_string(),
                ..Default::default()
            });
        }
        backlog
    }

    fn ids(backlog: &LogBacklog) -> Vec<&str> {
        backlog
            .entries
            .iter()
            .map(|entry| entry.request_id.as_str())
            .collect()
    }

    /// An unreachable control plane used to cost the batch after three
    /// attempts: the one-by-one fallback dropped every entry whose request
    /// failed, whatever the reason.
    #[tokio::test]
    async fn unreachable_control_plane_never_costs_the_batch() {
        let mut backlog = backlog_of(&["a", "b", "c"]);
        let mut sink = ScriptedSink {
            script: std::iter::repeat_n(ShipOutcome::Unavailable, 20).collect(),
            ..Default::default()
        };
        for _ in 0..20 {
            assert_eq!(backlog.flush(&mut sink).await, 0);
            assert!(backlog.stalled);
        }
        assert_eq!(ids(&backlog), ["a", "b", "c"]);
        // Always the whole batch: no entry was ever sent on its own.
        assert!(sink.requests.iter().all(|request| request.len() == 3));

        assert_eq!(backlog.flush(&mut sink).await, 0);
        assert_eq!(sink.stored, ["a", "b", "c"]);
        assert_eq!(backlog.len(), 0);
        assert!(!backlog.stalled);
    }

    /// One entry the control plane cannot store is singled out and dropped;
    /// the entries around it are delivered.
    #[tokio::test]
    async fn refused_entry_is_isolated_and_the_rest_delivered() {
        let mut backlog = backlog_of(&["a", "bad", "c"]);
        let mut sink = ScriptedSink {
            poison: vec!["bad".to_string()],
            ..Default::default()
        };
        for _ in 1..LOG_SHIP_ISOLATION_THRESHOLD {
            assert_eq!(backlog.flush(&mut sink).await, 0);
            assert_eq!(backlog.len(), 3, "kept while the batch is retried");
        }
        assert_eq!(backlog.flush(&mut sink).await, 1);
        assert_eq!(sink.stored, ["a", "c"]);
        assert_eq!(backlog.len(), 0);
        assert!(!backlog.stalled);
    }

    /// A control plane that refuses everything (its database is down) is not
    /// a reason to drop anything: nothing in the pass was stored, so nothing
    /// shows the entries are at fault. The passes are spaced out instead.
    #[tokio::test]
    async fn control_plane_refusing_everything_keeps_the_batch() {
        let mut backlog = backlog_of(&["a", "b"]);
        let mut sink = ScriptedSink {
            script: std::iter::repeat_n(ShipOutcome::Rejected, 500).collect(),
            ..Default::default()
        };
        let mut passes = Vec::new();
        for attempt in 1..=100 {
            let before = sink.requests.len();
            assert_eq!(backlog.flush(&mut sink).await, 0);
            if sink.requests.len() - before > 1 {
                passes.push(attempt);
            }
        }
        assert_eq!(ids(&backlog), ["a", "b"]);
        // After 3 refusals, then 6, 12, 24 and 48 more.
        assert_eq!(passes, [3, 9, 21, 45, 93]);
        assert_eq!(backlog.isolate_after, LOG_SHIP_ISOLATION_THRESHOLD_MAX);

        // The control plane recovers: the batch goes through and the
        // threshold starts over.
        sink.script.clear();
        assert_eq!(backlog.flush(&mut sink).await, 0);
        assert_eq!(sink.stored, ["a", "b"]);
        assert_eq!(backlog.isolate_after, LOG_SHIP_ISOLATION_THRESHOLD);
    }

    /// A pass cut short by the link keeps what it had not got to, and what
    /// it had judged is settled: delivered entries are not sent twice.
    #[tokio::test]
    async fn interrupted_isolation_keeps_the_untried_entries() {
        let mut backlog = backlog_of(&["a", "bad", "c", "d"]);
        let mut sink = ScriptedSink {
            poison: vec!["bad".to_string()],
            script: [
                ShipOutcome::Rejected,
                ShipOutcome::Rejected,
                ShipOutcome::Rejected,
                // The pass: a stored, bad refused, then the link drops.
                ShipOutcome::Accepted,
                ShipOutcome::Accepted,
                ShipOutcome::Unavailable,
            ]
            .into(),
            ..Default::default()
        };
        for _ in 1..LOG_SHIP_ISOLATION_THRESHOLD {
            assert_eq!(backlog.flush(&mut sink).await, 0);
        }
        assert_eq!(backlog.flush(&mut sink).await, 1);
        assert_eq!(ids(&backlog), ["c", "d"]);
        assert!(backlog.stalled);

        assert_eq!(backlog.flush(&mut sink).await, 0);
        assert_eq!(sink.stored, ["a", "c", "d"]);
    }

    /// The batch is shared with the request, not copied into it, and stays
    /// in the backlog until the control plane answers - so a session that
    /// ends mid-request (the future is dropped) loses nothing.
    #[tokio::test]
    async fn cancelled_shipment_leaves_the_batch_in_place() {
        struct Hanging;
        impl LogSink for Hanging {
            async fn ship(
                &mut self,
                _entries: Arc<Vec<proto::LogEntry>>,
                _range: std::ops::Range<usize>,
            ) -> ShipOutcome {
                std::future::pending().await
            }
        }

        let mut backlog = backlog_of(&["a", "b"]);
        let cancelled = tokio::time::timeout(
            Duration::from_millis(20),
            backlog.flush(&mut Hanging),
        )
        .await;
        assert!(cancelled.is_err());
        assert_eq!(ids(&backlog), ["a", "b"]);

        // The next session registers under another identity.
        backlog.restamp("agent-2");
        assert!(backlog
            .entries
            .iter()
            .all(|entry| entry.agent_id == "agent-2"));
        let mut sink = ScriptedSink::default();
        assert_eq!(backlog.flush(&mut sink).await, 0);
        assert_eq!(sink.stored, ["a", "b"]);
    }

    #[test]
    fn only_a_verdict_on_the_entries_counts_as_a_refusal() {
        use tonic::{Code, Status};
        for code in [
            Code::Internal,
            Code::InvalidArgument,
            Code::OutOfRange,
            Code::ResourceExhausted,
            Code::FailedPrecondition,
            Code::DataLoss,
        ] {
            assert_eq!(
                classify_ship_error(&Status::new(code, "")),
                ShipOutcome::Rejected,
                "{code:?}"
            );
        }
        for code in [
            Code::Unavailable,
            Code::Cancelled,
            Code::DeadlineExceeded,
            Code::Unknown,
            Code::Unauthenticated,
            Code::PermissionDenied,
            Code::Unimplemented,
            Code::Aborted,
        ] {
            assert_eq!(
                classify_ship_error(&Status::new(code, "")),
                ShipOutcome::Unavailable,
                "{code:?}"
            );
        }
    }

    /// A full queue used to be counted in a warning only the agent's own log
    /// carried.
    #[tokio::test]
    async fn queue_overflow_is_counted_for_the_heartbeat() {
        let client = test_client(100, 1000);
        let capacity = client.log_sender.max_capacity();
        for _ in 0..capacity + 3 {
            client.send_log(blank_log_entry());
        }
        assert_eq!(client.metrics.logs_dropped_total(), 3);
    }

    fn log_entry_with_bodies(request: usize, response: usize) -> LogEntry {
        LogEntry {
            request_body: Some(vec![b'a'; request]),
            request_body_size: request as u64,
            response_body: Some(vec![b'b'; response]),
            response_body_size: response as u64,
            ..blank_log_entry()
        }
    }

    /// With the queue's body budget spent, an entry is still queued — without
    /// its bodies, flagged truncated — and the budget comes back as entries
    /// leave the queue.
    #[tokio::test]
    async fn exhausted_body_budget_sheds_bodies_not_entries() {
        let client = test_client(100, 1000);
        // Room for exactly one 1000-byte entry.
        let preloaded = LOG_BODY_BUDGET_BYTES - 1500;
        assert!(client.queued_bodies.try_reserve(preloaded));

        client.send_log(log_entry_with_bodies(600, 400));
        client.send_log(log_entry_with_bodies(600, 400));
        assert_eq!(0, client.metrics.logs_dropped_total());
        assert_eq!(preloaded + 1000, client.queued_bodies.held());

        let (first, second) = {
            let mut state = client.log_state.lock().await;
            (
                state.receiver.try_recv().unwrap(),
                state.receiver.try_recv().unwrap(),
            )
        };
        let first = client.dequeue("agent", first);
        assert_eq!(600, first.request_body.len());
        assert_eq!(400, first.response_body.len());
        assert!(!first.request_body_truncated);
        assert!(!first.response_body_truncated);
        assert_eq!(preloaded, client.queued_bodies.held());

        let second = client.dequeue("agent", second);
        assert!(second.request_body.is_empty());
        assert!(second.response_body.is_empty());
        assert!(second.request_body_truncated);
        assert!(second.response_body_truncated);
        assert_eq!(600, second.request_body_size);
        assert_eq!(400, second.response_body_size);
        assert_eq!(preloaded, client.queued_bodies.held());
    }

    /// An entry the full queue turned away gives its reservation back.
    #[tokio::test]
    async fn overflowing_entry_does_not_keep_its_body_reservation() {
        let client = test_client(100, 1000);
        let capacity = client.log_sender.max_capacity();
        for _ in 0..capacity + 3 {
            client.send_log(log_entry_with_bodies(6, 4));
        }
        assert_eq!(3, client.metrics.logs_dropped_total());
        assert_eq!(capacity * 10, client.queued_bodies.held());
    }

    fn blank_log_entry() -> LogEntry {
        LogEntry {
            site_id: String::new(),
            request_id: String::new(),
            client_ip: String::new(),
            method: String::new(),
            scheme: String::new(),
            host: String::new(),
            path: String::new(),
            query_string: String::new(),
            protocol: String::new(),
            request_headers: HashMap::new(),
            request_body: None,
            request_body_size: 0,
            request_body_truncated: false,
            response_status: 0,
            response_headers: HashMap::new(),
            response_body: None,
            response_body_size: 0,
            response_body_truncated: false,
            upstream_addr: String::new(),
            upstream_latency_ms: 0,
            upstream_status: 0,
            waf_score: 0,
            waf_action: String::new(),
            waf_rule_id: String::new(),
            waf_enforced_rule_id: String::new(),
            waf_rule_name: String::new(),
            waf_event_type: String::new(),
            waf_details: String::new(),
            waf_matched_tags: Vec::new(),
            user_identity: String::new(),
            total_latency_ms: 0,
            cache_status: String::new(),
            tls_version: String::new(),
            ja3_hash: String::new(),
            country_code: String::new(),
            city: String::new(),
            asn: 0,
            user_agent: String::new(),
            referer: String::new(),
        }
    }

    #[tokio::test]
    async fn flush_logs_command_wakes_the_log_shipper() {
        let dir = tempfile::tempdir().unwrap();
        let config = AgentConfig {
            cache_dir: dir.path().to_string_lossy().to_string(),
            ..Default::default()
        };
        let rule_cache = Arc::new(
            RuleCache::new(dir.path().to_path_buf(), "test".to_string())
                .unwrap(),
        );
        let client = ControlPlaneClient::new(
            config,
            Arc::clone(&rule_cache),
            Arc::new(MetricsCollector::new()),
        );
        let notify = Arc::clone(&client.flush_notify);
        let waiter = tokio::spawn(async move {
            notify.notified().await;
        });
        let command = proto::ServerCommand {
            command_id: "cmd-1".to_string(),
            r#type: proto::CommandType::CommandFlushLogs as i32,
            issued_at: None,
            payload: Some(proto::server_command::Payload::FlushLogs(
                proto::FlushLogsCommand {
                    reason: "operator request".to_string(),
                },
            )),
        };
        let handlers =
            Arc::new(tokio::sync::RwLock::new(CommandHandlers::default()));
        ControlPlaneClient::handle_server_command(
            &command,
            &rule_cache,
            &handlers,
            &client.flush_notify,
        )
        .await;
        // The command must wake the shipper; a timeout means the branch
        // never fired.
        tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("flush command must signal the shipper")
            .unwrap();
    }

    #[test]
    fn attach_agent_token_sets_the_metadata() {
        let mut request = tonic::Request::new(());
        attach_agent_token(&mut request, &None);
        assert!(request.metadata().get("x-agent-token").is_none());
        let token = Some(Arc::new("abc.def.ghi".to_string()));
        attach_agent_token(&mut request, &token);
        assert_eq!(
            request.metadata().get("x-agent-token").unwrap(),
            "abc.def.ghi"
        );
    }

    #[test]
    fn heartbeat_block_list_is_bounded_and_marked() {
        let entries: Vec<BlockedIpEntry> = (0..MAX_HEARTBEAT_BLOCKED_IPS + 1)
            .map(|index| BlockedIpEntry {
                ip: format!("10.0.{}.{}", index / 256, index % 256),
                site_id: "00000000-0000-0000-0000-000000000001".to_string(),
                reason: "test".to_string(),
                blocked_at: chrono::Utc::now(),
                expires_at: None,
            })
            .collect();
        let (shipped, truncated) = heartbeat_blocked_ips(entries);
        assert!(truncated, "an over-long list must be marked as truncated");
        assert_eq!(MAX_HEARTBEAT_BLOCKED_IPS, shipped.len());

        let mut sorted = shipped.clone();
        sorted.sort_by(|a, b| {
            (a.site_id.as_str(), a.ip.as_str())
                .cmp(&(b.site_id.as_str(), b.ip.as_str()))
        });
        assert_eq!(shipped, sorted, "the shipped prefix must be deterministic");
    }

    // A disabled metric shipper must never complete: inside
    // `try_connect_and_run`'s select a completed future tears the whole
    // gRPC session down, causing a reconnect storm and lost commands.
    #[tokio::test]
    async fn disabled_metric_shipper_never_completes() {
        let result = tokio::time::timeout(
            Duration::from_millis(50),
            metric_shipper_disabled(),
        )
        .await;
        assert!(result.is_err(), "disabled shipper resolved too early");
    }

    #[test]
    fn plaintext_url_hitting_a_tls_port_is_explained() {
        // The exact shape a 0.32.16 agent logged when it spoke h2c to 9090.
        let err = anyhow::anyhow!(
            "transport error: h2 protocol error: http2 error: connection \
             error detected: frame with invalid size: GoAway(b\"\", \
             FRAME_SIZE_ERROR, Library)"
        );
        let hint =
            connection_hint(&err, "http://waf.example.com:9090").unwrap();
        assert!(hint.contains("https://"), "{hint}");
        assert!(hint.contains("server_ca_cert"), "{hint}");
        // URI schemes are case-insensitive; an uppercase scheme is still
        // plaintext.
        assert!(connection_hint(&err, "HTTP://waf.example.com:9090").is_some());
    }

    #[test]
    fn tls_url_with_an_h2_error_is_not_blamed_on_plaintext() {
        let err = anyhow::anyhow!(
            "transport error: h2 protocol error: FRAME_SIZE_ERROR"
        );
        assert!(connection_hint(&err, "https://waf.example.com:9090").is_none());
    }

    #[test]
    fn untrusted_certificate_points_at_the_ca_option() {
        let err = anyhow::anyhow!(
            "transport error: invalid peer certificate: UnknownIssuer"
        );
        let hint =
            connection_hint(&err, "https://waf.example.com:9090").unwrap();
        assert!(hint.contains("server_ca_cert"), "{hint}");
    }

    #[test]
    fn name_mismatch_points_at_the_tls_name_option() {
        // rustls maps webpki's `CertNotValidForName` to the `Context` variant,
        // whose Display carries the offending name and the valid SANs.
        let err = anyhow::anyhow!(
            "transport error: invalid peer certificate: certificate not \
             valid for name \"waf.example.com\"; certificate is only valid \
             for wafred"
        );
        let hint =
            connection_hint(&err, "https://waf.example.com:9090").unwrap();
        assert!(hint.contains("server_tls_name"), "{hint}");
    }

    #[test]
    fn the_logged_hint_field_is_empty_for_unrecognised_errors() {
        let known = anyhow::anyhow!(
            "transport error: invalid peer certificate: UnknownIssuer"
        );
        assert!(
            connection_hint_field(&known, "https://waf.example.com:9090")
                .contains("server_ca_cert")
        );
        let unknown = anyhow::anyhow!("transport error");
        assert!(connection_hint_field(
            &unknown,
            "https://waf.example.com:9090"
        )
        .is_empty());
    }

    #[test]
    fn unreachable_control_plane_points_at_the_port() {
        for text in [
            "tcp connect error: Connection refused (os error 111)",
            "transport error: timed out",
            "tcp connect error: connection reset by peer",
        ] {
            let err = anyhow::anyhow!(text.to_string());
            let hint =
                connection_hint(&err, "https://waf.example.com:9090").unwrap();
            assert!(hint.contains("9090"), "{text}: {hint}");
        }
    }

    #[test]
    fn unrelated_errors_get_no_hint() {
        let err =
            anyhow::anyhow!("invalid server URL: relative URL without a base");
        assert!(connection_hint(&err, "not-a-url").is_none());
    }

    #[test]
    fn plaintext_urls_skip_tls_config() {
        let endpoint = Endpoint::from_shared("http://localhost:9090").unwrap();
        assert!(apply_client_tls(
            endpoint,
            "http://localhost:9090",
            &None,
            &None,
            &None
        )
        .is_ok());
    }

    #[test]
    fn https_without_ca_uses_bundled_roots() {
        let endpoint =
            Endpoint::from_shared("https://waf.example.com:9090").unwrap();
        assert!(apply_client_tls(
            endpoint,
            "https://waf.example.com:9090",
            &None,
            &None,
            &None
        )
        .is_ok());
    }

    #[test]
    fn https_with_missing_ca_file_fails_early() {
        let endpoint =
            Endpoint::from_shared("https://waf.example.com:9090").unwrap();
        let err = apply_client_tls(
            endpoint,
            "https://waf.example.com:9090",
            &Some("/nonexistent/ca.pem".to_string()),
            &None,
            &None,
        )
        .expect_err("a missing CA file must fail before connecting");
        assert!(err.to_string().contains("/nonexistent/ca.pem"));
    }

    #[test]
    fn inline_ca_pem_wins_over_the_file() {
        let endpoint = Endpoint::from_shared("https://127.0.0.1:9090").unwrap();
        // `Certificate::from_pem` is lazy — validity is checked at handshake —
        // so an unusable inline PEM still configures successfully. The point
        // of the test: the (missing) CA file is never read, proving the inline
        // material takes precedence.
        assert!(apply_client_tls(
            endpoint,
            "https://127.0.0.1:9090",
            &Some("/nonexistent/ca.pem".to_string()),
            &Some("not a pem".to_string()),
            &None,
        )
        .is_ok());
    }

    #[test]
    fn tls_name_overrides_the_name_from_the_url() {
        // A control plane whose certificate only names its container host is
        // reachable through a public name once the SAN is supplied explicitly;
        // the URL host stays untouched.
        let endpoint =
            Endpoint::from_shared("https://waf.example.com:9090").unwrap();
        assert!(apply_client_tls(
            endpoint,
            "https://waf.example.com:9090",
            &None,
            &None,
            &Some("wafred".to_string()),
        )
        .is_ok());
    }

    fn test_client(initial_ms: u64, max_ms: u64) -> Arc<ControlPlaneClient> {
        test_client_at("http://127.0.0.1:1", initial_ms, max_ms)
    }

    fn test_client_at(
        server_url: &str,
        initial_ms: u64,
        max_ms: u64,
    ) -> Arc<ControlPlaneClient> {
        let dir = tempfile::tempdir().unwrap();
        let config = AgentConfig {
            server_url: server_url.to_string(),
            api_key: "test-key".to_string(),
            reconnect_initial_delay_ms: initial_ms,
            reconnect_max_delay_ms: max_ms,
            ..AgentConfig::default()
        };
        let rule_cache = RuleCache::new(
            dir.path().to_path_buf(),
            config.resolved_agent_id(),
        )
        .unwrap();
        Arc::new(ControlPlaneClient::new(
            config,
            rule_cache,
            Arc::new(MetricsCollector::new()),
        ))
    }

    #[test]
    fn backoff_doubles_is_capped_and_jittered() {
        // Each step lands in [50%, 100%] of the doubled-and-capped value —
        // still exponential, but a fleet of agents never reconnects in
        // lockstep.
        for _ in 0..100 {
            let next = next_backoff(100, 60_000);
            assert!((100..=200).contains(&next), "{next}");

            let capped = next_backoff(50_000, 60_000);
            assert!((30_000..=60_000).contains(&capped), "{capped}");

            // A pathological current value must neither overflow nor stall at
            // zero.
            let overflow = next_backoff(u64::MAX, 1_000);
            assert!((500..=1_000).contains(&overflow), "{overflow}");
        }
    }

    #[test]
    fn heartbeat_interval_prefers_the_server_value() {
        // A registered interval wins over the local default.
        assert_eq!(
            effective_heartbeat_interval(15, 30),
            Duration::from_secs(15)
        );
        // Servers that do not send one (0) fall back to the local config.
        assert_eq!(
            effective_heartbeat_interval(0, 30),
            Duration::from_secs(30)
        );
        assert_eq!(
            effective_heartbeat_interval(-5, 30),
            Duration::from_secs(30)
        );
        // Either source is clamped to the reporting minimum.
        assert_eq!(effective_heartbeat_interval(1, 30), Duration::from_secs(5));
        assert_eq!(effective_heartbeat_interval(0, 2), Duration::from_secs(5));
    }

    #[test]
    fn retire_backoff_restores_initial_delay() {
        let client = test_client(1_000, 60_000);
        client.retry_delay_ms.store(60_000, Ordering::Relaxed);
        client.retire_backoff();
        assert_eq!(
            client.retry_delay_ms.load(Ordering::Relaxed),
            1_000,
            "a successful registration must retire accumulated backoff"
        );
    }

    #[test]
    fn metric_batch_carries_global_counters() {
        let client = test_client(1_000, 60_000);
        let batch = client.build_metric_batch("agent-1");
        assert_eq!(batch.agent_id, "agent-1");
        assert!(batch.timestamp.is_some());

        let names: Vec<&str> =
            batch.metrics.iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"pingwaf_requests_total"));
        assert!(names.contains(&"pingwaf_blocked_requests_total"));
        assert!(names.contains(&"pingwaf_active_connections"));
        for metric in &batch.metrics {
            assert!(
                metric.labels.is_empty(),
                "global counters carry no labels"
            );
            assert!(metric.value.is_finite());
        }
    }

    #[tokio::test]
    async fn connection_loop_backs_off_against_dead_endpoint() {
        // Bind and drop a listener so the endpoint reliably refuses
        // connections, then let the loop exhaust its short backoff budget.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let client =
            test_client_at(&format!("http://127.0.0.1:{port}"), 10, 80);

        let this = Arc::clone(&client);
        let handle = tokio::spawn(async move { this.connection_loop().await });
        tokio::time::sleep(Duration::from_millis(1_000)).await;

        let observed = client.retry_delay_ms.load(Ordering::Relaxed);
        assert!(
            (40..=80).contains(&observed),
            "repeated failures must grow backoff into the jittered top half, got {observed}"
        );

        client.shutdown_signal.store(true, Ordering::Relaxed);
        handle.await.unwrap();
        let observed = client.retry_delay_ms.load(Ordering::Relaxed);
        assert!(
            (40..=80).contains(&observed),
            "no registration happened, so backoff must stay in the jittered top half, got {observed}"
        );
    }
}

#[cfg(test)]
mod publisher_tests {
    use super::*;

    #[test]
    fn parses_acme_state_entries_for_publication() {
        let text = r#"
[certificates.11111111-1111-1111-1111-111111111111_cert]
acme = "http://ops@example.com"
domains = "example.com,*.example.com"
tls_cert = "CERT"
tls_key = "KEY"

[certificates.22222222-2222-2222-2222-222222222222_cert]
domains = "empty.example"
"#;
        let state: AcmeStateFile = toml::from_str(text).unwrap();
        let cert = state
            .certificates
            .get("11111111-1111-1111-1111-111111111111_cert")
            .expect("the issued entry must parse");
        assert_eq!(cert.domains, "example.com,*.example.com");
        assert_eq!(cert.tls_cert, "CERT");
        assert!(cert.acme.is_some());
        let empty = state
            .certificates
            .get("22222222-2222-2222-2222-222222222222_cert")
            .expect("the empty entry must parse");
        assert!(empty.acme.is_none());
        assert!(empty.tls_cert.is_empty());
    }

    #[test]
    fn permanent_refusals_are_not_retried() {
        let refused = anyhow::anyhow!(tonic::Status::permission_denied("no"));
        assert!(permanent_publish_error(&refused));
        let transient = anyhow::anyhow!(tonic::Status::unavailable("down"));
        assert!(!permanent_publish_error(&transient));
    }
}
