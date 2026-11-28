//! The edge-side bookkeeping: which tunnels this node serves, which connector
//! sessions are live, and the loopback bridge each `(tunnel, target)` pair is
//! reached through.
//!
//! # Why a loopback bridge
//!
//! pingora's `HttpPeer` only carries a `SocketAddr`; there is no public hook to
//! give it a custom transport, and pingap has no unix-socket upstream. The edge
//! therefore binds a `127.0.0.1` listener per tunnel target and hands pingora
//! that port as if it were an ordinary origin. Everything after the connect —
//! HTTP/1.1, HTTP/2, WebSocket upgrades, TLS to the origin, connection pooling,
//! health checks, the WAF and every plugin — is the untouched request path.
//!
//! A bridge only holds a bound listener while a connector session is attached.
//! With no session the pool simply has no upstream, which is what makes a TCP
//! health probe report the truth instead of "port open, backend dead".

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::{debug, warn};

use crate::protocol::{
    ControlFrame, ErrorCode, TunnelSettings, write_open_target,
};
use crate::session::{Session, SessionReport};

/// One tunnel as the control plane described it in the rule bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelPolicy {
    pub tunnel_id: String,
    pub name: String,
    pub enabled: bool,
    /// Lower-case hex Ed25519 public key the connector's session token must
    /// verify against; empty = not paired, so no session can be opened.
    pub session_public_key: String,
    /// Internal `host:port` targets the connector serves, deduplicated.
    pub targets: Vec<String>,
    pub settings: TunnelSettings,
}

impl TunnelPolicy {
    /// Whether `token` opens this tunnel.
    ///
    /// Every failure mode (unpaired, disabled, wrong tunnel, expired, bad
    /// signature) is a refusal; there is no "no auth configured" pass.
    pub fn accepts(&self, token: &str, now: i64) -> bool {
        self.enabled
            && !self.session_public_key.is_empty()
            && crate::token::verify(
                token,
                &self.session_public_key,
                &self.tunnel_id,
                now,
            )
            .is_ok()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TargetKey {
    tunnel_id: String,
    target: String,
}

#[derive(Debug, Default)]
struct BridgeState {
    /// Whether the accept loop is running (and therefore the port is bound).
    attached: bool,
    port: u16,
    shutdown: Option<Arc<Notify>>,
    task: Option<JoinHandle<()>>,
    session: Option<Arc<Session>>,
}

/// A loopback listener for one `(tunnel, target)` pair.
#[derive(Debug, Default)]
pub struct Bridge {
    state: Mutex<BridgeState>,
}

impl Bridge {
    /// The loopback address pingora should dial, when a session is attached.
    pub fn addr(&self) -> Option<SocketAddr> {
        let state = self.state.lock().ok()?;
        state
            .attached
            .then(|| SocketAddr::from(([127, 0, 0, 1], state.port)))
    }

    /// Attaches `session`, binding the listener if this bridge is idle.
    ///
    /// Idempotent: a second attach for the same session does nothing. A
    /// different session replaces the previous one (the newest session wins,
    /// which is what a reconnect looks like from here).
    pub fn attach(&self, tunnel_id: &str, target: &str, session: Arc<Session>) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if state.attached
            && state
                .session
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &session))
        {
            return;
        }
        stop_loop(&mut state);

        // Reuse the port this bridge had before, when it is free: the edge
        // config still names it until the next reload, and binding the same
        // port keeps a stale config pointing at *this* bridge instead of at
        // whatever else grabbed the number.
        let preferred = state.port;
        let listener = if preferred != 0 {
            match std::net::TcpListener::bind(("127.0.0.1", preferred)) {
                Ok(listener) => listener,
                Err(_) => match std::net::TcpListener::bind(("127.0.0.1", 0)) {
                    Ok(listener) => listener,
                    Err(error) => {
                        warn!(
                            target: "wafred::tunnel",
                            tunnel = %tunnel_id,
                            target = %target,
                            error = %error,
                            "cannot bind a tunnel bridge listener"
                        );
                        return;
                    },
                },
            }
        } else {
            match std::net::TcpListener::bind(("127.0.0.1", 0)) {
                Ok(listener) => listener,
                Err(error) => {
                    warn!(
                        target: "wafred::tunnel",
                        tunnel = %tunnel_id,
                        target = %target,
                        error = %error,
                        "cannot bind a tunnel bridge listener"
                    );
                    return;
                },
            }
        };
        let port = match listener.local_addr() {
            Ok(addr) => addr.port(),
            Err(_) => return,
        };
        if let Err(error) = listener.set_nonblocking(true) {
            warn!(
                target: "wafred::tunnel",
                error = %error,
                "cannot set the tunnel bridge listener non-blocking"
            );
            return;
        }
        let handle = match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle,
            Err(_) => {
                debug!(
                    target: "wafred::tunnel",
                    "no tokio runtime, the tunnel bridge stays unbound"
                );
                return;
            },
        };
        let shutdown = Arc::new(Notify::new());
        let task = handle.spawn(
            BridgeTask {
                tunnel_id: tunnel_id.to_string(),
                target: target.to_string(),
                session: Arc::clone(&session),
                listener,
                shutdown: Arc::clone(&shutdown),
            }
            .run(),
        );
        state.attached = true;
        state.port = port;
        state.shutdown = Some(shutdown);
        state.task = Some(task);
        state.session = Some(session);
        debug!(
            target: "wafred::tunnel",
            tunnel = %tunnel_id,
            target = %target,
            port,
            "tunnel bridge attached"
        );
    }

    /// Drops the listener and stops accepting. The last port is kept for logs.
    pub fn detach(&self) {
        if let Ok(mut state) = self.state.lock() {
            stop_loop(&mut state);
        }
    }

    fn is_attached(&self) -> bool {
        self.state
            .lock()
            .map(|state| state.attached)
            .unwrap_or(false)
    }

    fn port(&self) -> u16 {
        self.state.lock().map(|state| state.port).unwrap_or(0)
    }
}

fn stop_loop(state: &mut BridgeState) {
    if let Some(shutdown) = state.shutdown.take() {
        shutdown.notify_waiters();
    }
    if let Some(task) = state.task.take() {
        task.abort();
    }
    state.attached = false;
    state.session = None;
}

/// The accept loop of one bridge. Owns the listener.
struct BridgeTask {
    tunnel_id: String,
    target: String,
    session: Arc<Session>,
    listener: std::net::TcpListener,
    shutdown: Arc<Notify>,
}

impl BridgeTask {
    async fn run(self) {
        let listener = match TcpListener::from_std(self.listener) {
            Ok(listener) => listener,
            Err(error) => {
                warn!(
                    target: "wafred::tunnel",
                    tunnel = %self.tunnel_id,
                    error = %error,
                    "cannot adopt the tunnel bridge listener"
                );
                return;
            },
        };
        loop {
            tokio::select! {
                _ = self.shutdown.notified() => break,
                accepted = listener.accept() => {
                    match accepted {
                        Ok((socket, peer)) => {
                            let session = Arc::clone(&self.session);
                            let target = self.target.clone();
                            let tunnel_id = self.tunnel_id.clone();
                            tokio::spawn(async move {
                                forward(socket, session, target, tunnel_id, peer).await;
                            });
                        },
                        Err(error) => {
                            // A transient accept error must not kill the
                            // bridge; a permanently broken listener would spin,
                            // so back off a little.
                            warn!(
                                target: "wafred::tunnel",
                                tunnel = %self.tunnel_id,
                                error = %error,
                                "tunnel bridge accept failed"
                            );
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        },
                    }
                }
            }
        }
    }
}

/// One proxied connection: loopback socket ↔ a new yamux stream.
async fn forward(
    mut socket: tokio::net::TcpStream,
    session: Arc<Session>,
    target: String,
    tunnel_id: String,
    peer: SocketAddr,
) {
    let (stream, lease) = match session.open_stream().await {
        Ok(pair) => pair,
        Err(code) => {
            debug!(
                target: "wafred::tunnel",
                tunnel = %tunnel_id,
                target = %target,
                peer = %peer,
                code = code.as_str(),
                "refusing a tunnel bridge connection"
            );
            let _ = socket.shutdown().await;
            return;
        },
    };
    let mut stream = stream.compat();
    if let Err(error) = write_open_target(&mut stream, &target).await {
        warn!(
            target: "wafred::tunnel",
            tunnel = %tunnel_id,
            target = %target,
            error = %error,
            "cannot open the tunnel data stream"
        );
        let _ = socket.shutdown().await;
        return;
    }
    match tokio::io::copy_bidirectional(&mut socket, &mut stream).await {
        Ok((from_client, from_origin)) => {
            debug!(
                target: "wafred::tunnel",
                tunnel = %tunnel_id,
                target = %target,
                from_client,
                from_origin,
                "tunnel stream closed"
            );
        },
        Err(error) => {
            debug!(
                target: "wafred::tunnel",
                tunnel = %tunnel_id,
                target = %target,
                error = %error,
                "tunnel stream ended with an error"
            );
        },
    }
    drop(lease);
}

#[derive(Debug, Default)]
struct RegistryInner {
    policies: HashMap<String, Arc<TunnelPolicy>>,
    bridges: HashMap<TargetKey, Arc<Bridge>>,
    sessions: HashMap<String, Vec<Arc<Session>>>,
}

/// Everything the data plane knows about tunnels.
#[derive(Debug, Default)]
pub struct TunnelRegistry {
    inner: RwLock<RegistryInner>,
    /// Bumped whenever a bridge's availability changed, so the hot-reload
    /// watcher knows it has to rebuild the config even though the rule cache
    /// did not change.
    generation: AtomicU64,
    policy_version: AtomicU64,
}

impl TunnelRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Current reload generation.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Revision of the policy set, handed to connectors at handshake time.
    pub fn policy_version(&self) -> u64 {
        self.policy_version.load(Ordering::SeqCst)
    }

    fn bump(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    /// Replaces the policy set with the one from the rule bundle.
    ///
    /// Returns `true` when the registry changed in a way the data plane must
    /// pick up (a target set, an enable flag or a session).
    pub fn apply_policies(&self, policies: Vec<TunnelPolicy>) -> bool {
        let mut changed = false;
        let next: HashMap<String, Arc<TunnelPolicy>> = policies
            .into_iter()
            .map(|policy| (policy.tunnel_id.clone(), Arc::new(policy)))
            .collect();

        let mut to_close: Vec<(Arc<Session>, ControlFrame)> = Vec::new();
        let mut to_update: Vec<(
            Arc<Session>,
            u64,
            Vec<String>,
            TunnelSettings,
        )> = Vec::new();
        let mut bridges_to_drop: Vec<TargetKey> = Vec::new();

        {
            let Ok(mut inner) = self.inner.write() else {
                return false;
            };
            let previous = inner.policies.clone();
            let next_version =
                self.policy_version.fetch_add(1, Ordering::SeqCst) + 1;
            // A removal changes the policy set even when the removed tunnel
            // has no session and no bridge (the loops below would miss it).
            if previous
                .keys()
                .any(|tunnel_id| !next.contains_key(tunnel_id))
            {
                changed = true;
            }

            for (tunnel_id, policy) in &next {
                match previous.get(tunnel_id) {
                    Some(old) if **old == **policy => {},
                    Some(old) => {
                        changed = true;
                        // A rotated signing key (or a revoked tunnel) takes
                        // effect at the edge immediately: the live session was
                        // opened under the old key and must not outlive it,
                        // even when the connector cannot be reached to be told.
                        let credential_changed =
                            old.session_public_key != policy.session_public_key;
                        if let Some(sessions) = inner.sessions.get(tunnel_id) {
                            for session in sessions {
                                if !policy.enabled {
                                    to_close.push((
                                        Arc::clone(session),
                                        ControlFrame::Revoked {
                                            message: "tunnel disabled"
                                                .to_string(),
                                        },
                                    ));
                                } else if credential_changed {
                                    to_close.push((
                                        Arc::clone(session),
                                        ControlFrame::Revoked {
                                            message: "the tunnel credential was rotated"
                                                .to_string(),
                                        },
                                    ));
                                } else {
                                    to_update.push((
                                        Arc::clone(session),
                                        next_version,
                                        policy.targets.clone(),
                                        policy.settings.clone(),
                                    ));
                                }
                            }
                        }
                    },
                    None => changed = true,
                }
            }
            for (tunnel_id, sessions) in &inner.sessions {
                if !next.get(tunnel_id).is_some_and(|policy| policy.enabled) {
                    changed = true;
                    for session in sessions {
                        to_close.push((
                            Arc::clone(session),
                            ControlFrame::Revoked {
                                message: "tunnel removed".to_string(),
                            },
                        ));
                    }
                }
            }
            // Bridges whose tunnel or target disappeared.
            for key in inner.bridges.keys() {
                let keep = next
                    .get(&key.tunnel_id)
                    .is_some_and(|policy| policy.targets.contains(&key.target));
                if !keep {
                    bridges_to_drop.push(key.clone());
                }
            }
            for key in bridges_to_drop {
                if let Some(bridge) = inner.bridges.remove(&key) {
                    bridge.detach();
                    changed = true;
                }
            }
            inner.policies = next;
        }

        for (session, frame) in to_close {
            session.close(frame);
            changed = true;
        }
        for (session, version, targets, settings) in to_update {
            session.push_policy(version, targets, settings);
        }
        if changed {
            self.bump();
        }
        changed
    }

    /// The policy for `tunnel_id`, when it exists.
    pub fn policy(&self, tunnel_id: &str) -> Option<Arc<TunnelPolicy>> {
        self.inner
            .read()
            .ok()
            .and_then(|inner| inner.policies.get(tunnel_id).cloned())
    }

    /// Validates a connector's session token.
    pub fn authenticate(
        &self,
        tunnel_id: &str,
        token: &str,
    ) -> std::result::Result<Arc<TunnelPolicy>, ErrorCode> {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let Some(policy) = self.policy(tunnel_id) else {
            // An unknown tunnel still pays for a signature check: a prober
            // must not learn from the timing whether an id exists.
            let _ = crate::token::verify(token, "", tunnel_id, now);
            return Err(ErrorCode::Unauthenticated);
        };
        // One code for every reason: "this tunnel exists but is disabled" is
        // not information an unauthenticated peer needs.
        if !policy.accepts(token, now) {
            return Err(ErrorCode::Unauthenticated);
        }
        Ok(policy)
    }

    /// Registers a new session, replacing any previous one for the tunnel and
    /// binding the bridges this edge references.
    pub fn attach_session(&self, session: Arc<Session>) {
        let tunnel_id = session.tunnel_id.clone();
        let mut replaced: Vec<Arc<Session>> = Vec::new();
        let mut bridges: Vec<(String, Arc<Bridge>)> = Vec::new();
        {
            let Ok(mut inner) = self.inner.write() else {
                return;
            };
            if let Some(previous) = inner.sessions.get_mut(&tunnel_id) {
                replaced.append(previous);
            }
            inner
                .sessions
                .insert(tunnel_id.clone(), vec![Arc::clone(&session)]);
            for (key, bridge) in &inner.bridges {
                if key.tunnel_id == tunnel_id {
                    bridges.push((key.target.clone(), Arc::clone(bridge)));
                }
            }
        }
        for previous in replaced {
            if !Arc::ptr_eq(&previous, &session) {
                previous.close(ControlFrame::Drain { grace_secs: 0 });
            }
        }
        for (target, bridge) in bridges {
            bridge.attach(&tunnel_id, &target, Arc::clone(&session));
        }
        self.bump();
    }

    /// Removes a session (its driver ended).
    ///
    /// The bridges are only torn down when this was the tunnel's *last*
    /// session. A reconnect replaces the old session first, and the old
    /// driver exits afterwards; detaching unconditionally would take the new
    /// session's bridges away for a whole reload period.
    pub fn detach_session(&self, tunnel_id: &str, session: &Arc<Session>) {
        let mut bridges: Vec<Arc<Bridge>> = Vec::new();
        let no_sessions_left;
        {
            let Ok(mut inner) = self.inner.write() else {
                return;
            };
            if let Some(sessions) = inner.sessions.get_mut(tunnel_id) {
                sessions.retain(|candidate| !Arc::ptr_eq(candidate, session));
                no_sessions_left = sessions.is_empty();
                if no_sessions_left {
                    inner.sessions.remove(tunnel_id);
                }
            } else {
                // Not registered at all (already replaced and removed): the
                // live session, if any, keeps its bridges.
                no_sessions_left = false;
            }
            if no_sessions_left {
                bridges = inner
                    .bridges
                    .iter()
                    .filter(|(key, _)| key.tunnel_id == tunnel_id)
                    .map(|(_, bridge)| Arc::clone(bridge))
                    .collect();
            }
        }
        for bridge in bridges {
            bridge.detach();
        }
        if no_sessions_left {
            self.bump();
        }
    }

    /// The loopback address for `(tunnel, target)`, binding a bridge when a
    /// session is live.
    ///
    /// `None` means "no upstream right now": the tunnel is unknown, disabled,
    /// does not list the target, or has no session on this edge.
    pub fn bridge_addr(
        &self,
        tunnel_id: &str,
        target: &str,
    ) -> Option<SocketAddr> {
        let policy = self.policy(tunnel_id)?;
        if !policy.enabled
            || !policy.targets.iter().any(|entry| entry == target)
        {
            return None;
        }
        let session = self.inner.read().ok().and_then(|inner| {
            inner
                .sessions
                .get(tunnel_id)
                .and_then(|list| list.last().cloned())
        });
        let session = session.filter(|session| !session.is_closed())?;
        let bridge = self.bridge_for(tunnel_id, target);
        let before = bridge.is_attached();
        bridge.attach(tunnel_id, target, session);
        let after = bridge.is_attached();
        if before != after {
            self.bump();
        }
        bridge.addr()
    }

    fn bridge_for(&self, tunnel_id: &str, target: &str) -> Arc<Bridge> {
        let key = TargetKey {
            tunnel_id: tunnel_id.to_string(),
            target: target.to_string(),
        };
        if let Ok(inner) = self.inner.read()
            && let Some(bridge) = inner.bridges.get(&key)
        {
            return Arc::clone(bridge);
        }
        let mut inner = match self.inner.write() {
            Ok(inner) => inner,
            Err(poisoned) => poisoned.into_inner(),
        };
        Arc::clone(
            inner
                .bridges
                .entry(key)
                .or_insert_with(|| Arc::new(Bridge::default())),
        )
    }

    /// Drops every bridge and session (shutdown).
    pub fn shutdown(&self) {
        let (sessions, bridges) = {
            let Ok(mut inner) = self.inner.write() else {
                return;
            };
            let sessions: Vec<Arc<Session>> = inner
                .sessions
                .drain()
                .flat_map(|(_, sessions)| sessions)
                .collect();
            let bridges: Vec<Arc<Bridge>> =
                inner.bridges.drain().map(|(_, bridge)| bridge).collect();
            (sessions, bridges)
        };
        for session in sessions {
            session.close(ControlFrame::Drain { grace_secs: 0 });
        }
        for bridge in bridges {
            bridge.detach();
        }
        self.bump();
    }

    /// Per-session state for the heartbeat.
    pub fn session_reports(&self) -> Vec<SessionReport> {
        let Ok(inner) = self.inner.read() else {
            return Vec::new();
        };
        inner
            .sessions
            .values()
            .flat_map(|sessions| {
                sessions.iter().map(|session| session.report())
            })
            .collect()
    }

    /// Number of live sessions.
    pub fn session_count(&self) -> usize {
        self.inner
            .read()
            .map(|inner| inner.sessions.values().map(Vec::len).sum())
            .unwrap_or(0)
    }

    /// Maps a bridge port back to `tunnel://<name>/<target>` for the access log.
    pub fn upstream_label(&self, addr: SocketAddr) -> Option<String> {
        if !addr.ip().is_loopback() {
            return None;
        }
        let inner = self.inner.read().ok()?;
        for (key, bridge) in &inner.bridges {
            if bridge.port() == addr.port() && bridge.is_attached() {
                let name = inner
                    .policies
                    .get(&key.tunnel_id)
                    .map(|policy| policy.name.as_str())
                    .unwrap_or(&key.tunnel_id);
                return Some(format!("tunnel://{name}/{}", key.target));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::KeyPair;

    /// A policy whose public key matches `token_signer()`.
    fn policy(id: &str, targets: &[&str]) -> TunnelPolicy {
        TunnelPolicy {
            tunnel_id: id.to_string(),
            name: format!("tunnel-{id}"),
            enabled: true,
            session_public_key: crate::token::public_key_hex(
                token_signer().public_key().as_ref(),
            ),
            targets: targets.iter().map(|t| t.to_string()).collect(),
            settings: TunnelSettings::default(),
        }
    }

    fn token_signer() -> ring::signature::Ed25519KeyPair {
        ring::signature::Ed25519KeyPair::from_seed_unchecked(&[3u8; 32])
            .unwrap()
    }

    /// A token for `tunnel_id`, signed by `token_signer()`.
    fn token_for(tunnel_id: &str) -> String {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let claims = crate::token::SessionTokenClaims {
            tunnel_id: tunnel_id.to_string(),
            issued_at: now,
            expires_at: now + 3600,
        };
        let signature =
            token_signer().sign(&crate::token::payload_bytes(&claims));
        crate::token::encode(&claims, signature.as_ref())
    }

    #[test]
    fn apply_policies_tracks_additions_and_removals() {
        let registry = TunnelRegistry::new();
        assert!(registry.apply_policies(vec![policy("a", &["10.0.0.5:80"])]));
        assert!(registry.policy("a").is_some());
        // Applying the same set again changes nothing.
        assert!(!registry.apply_policies(vec![policy("a", &["10.0.0.5:80"])]));
        assert!(registry.apply_policies(vec![]));
        assert!(registry.policy("a").is_none());
    }

    #[test]
    fn authentication_requires_the_right_credential_and_an_enabled_tunnel() {
        let registry = TunnelRegistry::new();
        registry.apply_policies(vec![policy("a", &["10.0.0.5:80"])]);
        let token = token_for("a");
        assert!(registry.authenticate("a", &token).is_ok());
        assert_eq!(
            registry.authenticate("a", "v1.00.00").err(),
            Some(ErrorCode::Unauthenticated)
        );
        // A token for another tunnel is refused even with the right signature.
        assert_eq!(
            registry.authenticate("a", &token_for("other")).err(),
            Some(ErrorCode::Unauthenticated)
        );
        assert_eq!(
            registry.authenticate("missing", &token).err(),
            Some(ErrorCode::Unauthenticated)
        );
        let mut disabled = policy("a", &["10.0.0.5:80"]);
        disabled.enabled = false;
        registry.apply_policies(vec![disabled]);
        // Deliberately indistinguishable from a bad token: an unauthenticated
        // peer must not learn that the id exists.
        assert_eq!(
            registry.authenticate("a", &token_for("a")).err(),
            Some(ErrorCode::Unauthenticated)
        );
    }

    #[test]
    fn a_replaced_session_does_not_tear_down_the_new_one() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let registry = TunnelRegistry::new();
            registry.apply_policies(vec![policy("a", &["10.0.0.5:80"])]);
            let first = test_session("a");
            registry.attach_session(Arc::clone(&first));
            // The connector reconnects: the new session replaces the old one.
            let second = test_session("a");
            registry.attach_session(Arc::clone(&second));
            assert!(
                !registry
                    .bridge_addr("a", "10.0.0.5:80")
                    .unwrap()
                    .port()
                    .eq(&0)
            );
            // The old driver now exits; the new session must keep its bridge.
            registry.detach_session("a", &first);
            assert!(
                registry.bridge_addr("a", "10.0.0.5:80").is_some(),
                "the replaced session tore down the live one's bridge"
            );
            registry.detach_session("a", &second);
            assert!(registry.bridge_addr("a", "10.0.0.5:80").is_none());
        });
    }

    #[test]
    fn rotating_the_credential_closes_the_live_session() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let registry = TunnelRegistry::new();
            registry.apply_policies(vec![policy("a", &["10.0.0.5:80"])]);
            let session = test_session("a");
            registry.attach_session(Arc::clone(&session));
            assert!(!session.is_closed());

            // Same tunnel, new signing key: the session was opened under the
            // old one and must not survive the rotation, even if the connector
            // is unreachable.
            let mut rotated = policy("a", &["10.0.0.5:80"]);
            rotated.session_public_key =
                crate::token::public_key_hex(&[9u8; 32]);
            registry.apply_policies(vec![rotated]);
            assert!(session.is_closed());
            assert!(registry.bridge_addr("a", "10.0.0.5:80").is_none());
        });
    }

    #[test]
    fn bridge_addr_is_none_without_a_session() {
        let registry = TunnelRegistry::new();
        registry.apply_policies(vec![policy("a", &["10.0.0.5:80"])]);
        assert!(registry.bridge_addr("a", "10.0.0.5:80").is_none());
        // A target the policy does not list is refused even before a session.
        assert!(registry.bridge_addr("a", "10.0.0.6:80").is_none());
    }

    #[test]
    fn a_bridge_binds_and_reports_a_loopback_address() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let registry = TunnelRegistry::new();
            registry.apply_policies(vec![policy("a", &["10.0.0.5:80"])]);
            let session = test_session("a");
            registry.attach_session(Arc::clone(&session));
            let addr = registry.bridge_addr("a", "10.0.0.5:80").unwrap();
            assert!(addr.ip().is_loopback());
            assert_ne!(addr.port(), 0);
            assert_eq!(
                registry.upstream_label(addr).as_deref(),
                Some("tunnel://tunnel-a/10.0.0.5:80")
            );
            // Detaching the session takes the listener away with it.
            registry.detach_session("a", &session);
            assert!(registry.bridge_addr("a", "10.0.0.5:80").is_none());
        });
    }

    fn test_session(tunnel_id: &str) -> Arc<Session> {
        let (open_tx, _open_rx) = tokio::sync::mpsc::channel(4);
        let (control_tx, _control_rx) = tokio::sync::mpsc::channel(4);
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        Arc::new(Session::new(
            tunnel_id.to_string(),
            "1.0.0".to_string(),
            "connector".to_string(),
            "127.0.0.1:1".parse().unwrap(),
            1,
            TunnelSettings::default(),
            open_tx,
            control_tx,
            shutdown_tx,
        ))
    }
}
