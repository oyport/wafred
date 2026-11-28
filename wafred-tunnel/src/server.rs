//! The edge-side tunnel listener.
//!
//! One TLS connection per connector, carrying one yamux session. The first
//! stream the connector opens is the control stream; after that every stream
//! the edge opens is one proxied connection.
//!
//! Authentication happens on the control stream, not in the TLS layer: the
//! credential is sent inside the encrypted channel and compared against the
//! digest the control plane put in the rule bundle. A rejected handshake is
//! answered with a `Rejected` frame and the connection is closed.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Weak};
use std::task::Poll;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use futures::future::poll_fn;
use rustls::ServerConfig;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_util::compat::{
    Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt,
};
use tracing::{debug, info, warn};

use crate::cert::TunnelCertificate;
use crate::protocol::{
    ALPN, ControlFrame, ErrorCode, PROTOCOL_VERSION, read_frame, write_frame,
};
use crate::registry::TunnelRegistry;
use crate::session::{OpenRequest, Session};

/// Time allowed for the TLS handshake.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Time allowed for the connector to open its control stream and say hello.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// Handshakes accepted per peer address per window.
const HANDSHAKES_PER_WINDOW: u32 = 30;
const HANDSHAKE_WINDOW: Duration = Duration::from_secs(60);
/// Handshakes allowed to be in flight at once (across all peers).
const MAX_CONCURRENT_HANDSHAKES: usize = 128;
/// Highest concurrent-stream count the settings allow; the yamux ceiling is
/// raised to it so a policy limit above yamux's 512 default is honoured.
const MAX_STREAMS_CEILING: usize = 4096;
/// How many control frames may queue up before the session is considered stuck.
const CONTROL_QUEUE: usize = 64;
/// How many data-stream opens may queue up behind the driver.
const OPEN_QUEUE: usize = 1024;

type TunnelStream = Compat<tokio_rustls::server::TlsStream<TcpStream>>;
/// A control stream: the connector-opened yamux stream adapted to tokio's IO
/// traits so the frame helpers can read and write it.
type ControlStream = Compat<yamux::Stream>;
type YamuxConnection = yamux::Connection<TunnelStream>;

/// The edge's tunnel listener.
pub struct TunnelAcceptor {
    registry: Arc<TunnelRegistry>,
    tls: TlsAcceptor,
    listener: TcpListener,
    local_addr: SocketAddr,
    limiter: HandshakeLimiter,
    /// Global bound on handshakes in flight: one task (and one TLS handshake)
    /// per accepted socket, so an unauthenticated flood must not be able to
    /// spawn unbounded work.
    permits: Arc<Semaphore>,
    /// Fingerprint of the certificate in use, for the heartbeat.
    fingerprint: String,
}

impl TunnelAcceptor {
    /// Binds `addr` and prepares the TLS listener.
    pub async fn bind(
        addr: &str,
        cert: &TunnelCertificate,
        registry: Arc<TunnelRegistry>,
    ) -> Result<Self> {
        let (certs, key) = cert.rustls_material()?;
        // Use the provider the process installed (the binaries install ring at
        // startup) instead of rustls' feature-based guess: this crate is built
        // with both `ring` and `aws-lc-rs` reachable through the workspace, so
        // the implicit choice would panic rather than pick one.
        let provider = crate::verify::default_provider()?;
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .context("cannot build the tunnel TLS configuration")?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("cannot build the tunnel TLS configuration")?;
        // A peer that does not speak the tunnel ALPN fails during the
        // handshake instead of after it.
        config.alpn_protocols = vec![ALPN.to_vec()];

        let listener = TcpListener::bind(addr).await.with_context(|| {
            format!("cannot bind the tunnel listener on {addr}")
        })?;
        let local_addr = listener
            .local_addr()
            .context("cannot read the tunnel listener address")?;
        Ok(Self {
            registry,
            tls: TlsAcceptor::from(Arc::new(config)),
            listener,
            local_addr,
            limiter: HandshakeLimiter::default(),
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT_HANDSHAKES)),
            fingerprint: cert.fingerprint_sha256.clone(),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Accepts connections until the process exits.
    pub async fn run(self) {
        info!(
            target: "wafred::tunnel",
            addr = %self.local_addr,
            fingerprint = %self.fingerprint,
            "tunnel listener started"
        );
        loop {
            let (socket, peer) = match self.listener.accept().await {
                Ok(accepted) => accepted,
                Err(error) => {
                    warn!(
                        target: "wafred::tunnel",
                        error = %error,
                        "tunnel listener accept failed"
                    );
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                },
            };
            if !self.limiter.allow(peer.ip()) {
                debug!(
                    target: "wafred::tunnel",
                    peer = %peer,
                    "refusing a tunnel handshake: rate limit"
                );
                drop(socket);
                continue;
            }
            let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned()
            else {
                debug!(
                    target: "wafred::tunnel",
                    peer = %peer,
                    "refusing a tunnel handshake: too many in flight"
                );
                drop(socket);
                continue;
            };
            let tls = self.tls.clone();
            let registry = Arc::clone(&self.registry);
            tokio::spawn(async move {
                // Held for the whole handshake, released when the task ends.
                let _permit = permit;
                if let Err(error) = handshake(socket, peer, tls, registry).await
                {
                    warn!(
                        target: "wafred::tunnel",
                        peer = %peer,
                        error = %error,
                        "tunnel handshake failed"
                    );
                }
            });
        }
    }

    /// Runs the listener on its own task.
    pub fn spawn(self) -> JoinHandle<()> {
        tokio::spawn(self.run())
    }
}

/// TLS + yamux + hello. On success the session is registered and both its
/// tasks are running.
async fn handshake(
    socket: TcpStream,
    peer: SocketAddr,
    tls: TlsAcceptor,
    registry: Arc<TunnelRegistry>,
) -> Result<()> {
    // Nagle would add a round trip to the small control frames.
    let _ = socket.set_nodelay(true);
    let stream =
        tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, tls.accept(socket))
            .await
            .map_err(|_| anyhow::anyhow!("TLS handshake timed out"))?
            .context("TLS handshake failed")?;
    // yamux caps concurrent streams itself (512 by default). The configured
    // policy limit can be higher, and a stream refused by yamux used to end the
    // whole session; raise the multiplexer's ceiling to the policy maximum so
    // the per-session limit (`max_streams`) is always the one that applies.
    let mut yamux_config = yamux::Config::default();
    yamux_config.set_max_num_streams(MAX_STREAMS_CEILING);
    let connection = yamux::Connection::new(
        stream.compat(),
        yamux_config,
        yamux::Mode::Server,
    );

    // The connection has to be driven from the moment it exists: a yamux
    // stream's bytes only move while `poll_next_inbound` (or any other
    // connection poll) runs. Driving it in this task while waiting for the
    // hello deadlocks — the first inbound frame would never be read.
    let (open_tx, open_rx) = mpsc::channel::<OpenRequest>(OPEN_QUEUE);
    let (control_tx, control_rx) = mpsc::channel::<ControlFrame>(CONTROL_QUEUE);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (first_tx, first_rx) = oneshot::channel();
    let mut driver = tokio::spawn(drive_connection(
        connection,
        open_rx,
        first_tx,
        shutdown_tx.clone(),
        shutdown_rx.clone(),
    ));

    let control_stream = tokio::time::timeout(HELLO_TIMEOUT, first_rx)
        .await
        .map_err(|_| {
            anyhow::anyhow!("the connector did not open a control stream")
        })?
        .context("the yamux session ended during the handshake")?;
    let mut control_stream = control_stream.compat();

    let hello =
        tokio::time::timeout(HELLO_TIMEOUT, read_frame(&mut control_stream))
            .await
            .map_err(|_| anyhow::anyhow!("the connector did not say hello"))?
            .context("cannot read the tunnel hello")?;

    let (tunnel_id, token, version, hostname) = match hello {
        ControlFrame::Hello {
            protocol,
            tunnel_id,
            token,
            version,
            hostname,
            ..
        } => {
            if protocol != PROTOCOL_VERSION {
                let _ = reject(
                    &mut control_stream,
                    ErrorCode::ProtocolError,
                    format!(
                        "unsupported tunnel protocol {protocol}, this edge speaks {PROTOCOL_VERSION}"
                    ),
                )
                .await;
                drain_rejected(&mut driver, &shutdown_tx).await;
                return Ok(());
            }
            (tunnel_id, token, version, hostname)
        },
        other => {
            let _ = reject(
                &mut control_stream,
                ErrorCode::ProtocolError,
                format!("expected a hello frame, got {}", other.kind()),
            )
            .await;
            drain_rejected(&mut driver, &shutdown_tx).await;
            return Ok(());
        },
    };

    let policy = match registry.authenticate(&tunnel_id, &token) {
        Ok(policy) => policy,
        Err(code) => {
            let message = match code {
                ErrorCode::TunnelDisabled => {
                    "this tunnel is disabled".to_string()
                },
                _ => "the tunnel credential was not accepted".to_string(),
            };
            let _ = reject(&mut control_stream, code, message).await;
            drain_rejected(&mut driver, &shutdown_tx).await;
            return Ok(());
        },
    };

    let settings = policy.settings.clone();
    let policy_version = registry.policy_version();
    write_frame(
        &mut control_stream,
        &ControlFrame::HelloOk {
            policy_version,
            targets: policy.targets.clone(),
            settings: settings.clone(),
        },
    )
    .await
    .context("cannot answer the tunnel hello")?;

    let session = Arc::new(Session::new(
        tunnel_id.clone(),
        version,
        hostname,
        peer,
        policy_version,
        settings,
        open_tx,
        control_tx,
        shutdown_tx.clone(),
    ));

    let control_task = tokio::spawn(control_loop(
        control_stream,
        control_rx,
        shutdown_rx.clone(),
        shutdown_tx.clone(),
        Arc::downgrade(&session),
        Arc::clone(&registry),
    ));
    session.set_control_task(control_task);
    registry.attach_session(Arc::clone(&session));

    info!(
        target: "wafred::tunnel",
        tunnel = %tunnel_id,
        connector = %session.hostname,
        version = %session.connector_version,
        peer = %peer,
        targets = policy.targets.len(),
        "tunnel session established"
    );

    // Live as long as the connection does. The driver exits when the peer goes
    // away or when `Session::close` flips the shutdown watch, and the session is
    // unregistered right after.
    let _ = driver.await;
    registry.detach_session(&tunnel_id, &session);
    info!(
        target: "wafred::tunnel",
        tunnel = %tunnel_id,
        "tunnel session closed"
    );
    Ok(())
}

/// Waits for a rejected peer to read its answer before the connection goes.
///
/// The rejection frame is queued behind the yamux command channel; tearing the
/// connection down immediately would race it out of the socket and the peer
/// would see a bare EOF instead of the reason. The peer closes after reading
/// it, which ends the driver.
async fn drain_rejected(
    driver: &mut JoinHandle<()>,
    shutdown_tx: &watch::Sender<bool>,
) {
    let _ = tokio::time::timeout(Duration::from_secs(5), &mut *driver).await;
    let _ = shutdown_tx.send(true);
}

/// Answers a refused handshake and closes the connection.
async fn reject(
    stream: &mut ControlStream,
    code: ErrorCode,
    message: String,
) -> Result<()> {
    debug!(
        target: "wafred::tunnel",
        code = code.as_str(),
        message = %message,
        "refusing a tunnel session"
    );
    let _ =
        write_frame(stream, &ControlFrame::Rejected { code, message }).await;
    let _ = stream.shutdown().await;
    Ok(())
}

/// Reads heartbeats and writes queued control frames.
async fn control_loop(
    stream: ControlStream,
    mut out_rx: mpsc::Receiver<ControlFrame>,
    mut shutdown: watch::Receiver<bool>,
    shutdown_tx: watch::Sender<bool>,
    session: Weak<Session>,
    registry: Arc<TunnelRegistry>,
) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    // A NAT that silently drops the flow leaves both ends believing the
    // session is alive, and every request then waits for the 15s open-stream
    // timeout. The connector heartbeats every `heartbeat_secs`, so a silence
    // longer than the liveness timeout means the peer is gone.
    let liveness = Duration::from_secs(u64::from(session_liveness_secs(
        session.upgrade().map(|s| s.settings.clone()),
    )));
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                // `Session::close` enqueues the terminal frame and then flips
                // the watch; the select may pick this branch first. Drain what
                // is already queued so the peer learns *why* it was closed.
                while let Ok(frame) = out_rx.try_recv() {
                    let terminal = matches!(
                        frame,
                        ControlFrame::Revoked { .. }
                            | ControlFrame::Drain { .. }
                            | ControlFrame::Rejected { .. }
                    );
                    let _ = write_frame(&mut writer, &frame).await;
                    if terminal {
                        break;
                    }
                }
                break;
            },
            frame = tokio::time::timeout(liveness, read_frame(&mut reader)) => {
                let frame = match frame {
                    Ok(frame) => frame,
                    Err(_) => {
                        warn!(
                            target: "wafred::tunnel",
                            timeout_secs = liveness.as_secs(),
                            "tunnel control stream went silent, closing the session"
                        );
                        break;
                    },
                };
                match frame {
                    Ok(ControlFrame::Heartbeat { streams_active: _, rtt_ms }) => {
                        if let Some(session) = session.upgrade() {
                            session.record_rtt(rtt_ms);
                        }
                        let ack = ControlFrame::HeartbeatAck {
                            policy_version: registry.policy_version(),
                            targets: None,
                            settings: None,
                        };
                        if write_frame(&mut writer, &ack).await.is_err() {
                            break;
                        }
                    },
                    Ok(other) => {
                        debug!(
                            target: "wafred::tunnel",
                            frame = other.kind(),
                            "unexpected control frame from the connector"
                        );
                    },
                    Err(error) => {
                        debug!(
                            target: "wafred::tunnel",
                            error = %error,
                            "tunnel control stream ended"
                        );
                        break;
                    },
                }
            },
            out = out_rx.recv() => {
                let Some(frame) = out else { break };
                let terminal = matches!(
                    frame,
                    ControlFrame::Revoked { .. } | ControlFrame::Drain { .. } | ControlFrame::Rejected { .. }
                );
                if write_frame(&mut writer, &frame).await.is_err() {
                    break;
                }
                if terminal {
                    break;
                }
            },
        }
    }
    let _ = writer.shutdown().await;
    let _ = shutdown_tx.send(true);
}

/// Owns the yamux connection: hands the first inbound stream (the control
/// stream) to the handshake, opens a stream per bridge connection, and notices
/// when the connector goes away.
async fn drive_connection(
    mut connection: YamuxConnection,
    mut open_rx: mpsc::Receiver<OpenRequest>,
    first_control: oneshot::Sender<yamux::Stream>,
    shutdown_tx: watch::Sender<bool>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut pending: Option<OpenRequest> = None;
    let mut first_control = Some(first_control);
    tokio::select! {
        _ = shutdown.changed() => {},
        () = poll_fn(|cx| {
            if pending.is_none() {
                match open_rx.poll_recv(cx) {
                    Poll::Ready(Some(waiter)) => pending = Some(waiter),
                    // Every Session handle is gone: nothing can ask for a
                    // stream any more, so the connection has no purpose.
                    Poll::Ready(None) => return Poll::Ready(()),
                    Poll::Pending => {},
                }
            }
            if pending.is_some() {
                match connection.poll_new_outbound(cx) {
                    Poll::Ready(Ok(stream)) => {
                        if let Some(waiter) = pending.take() {
                            let _ = waiter.send(Ok(stream));
                        }
                    },
                    Poll::Ready(Err(error)) => {
                        // One stream could not be opened (the multiplexer is
                        // at its ceiling); fail that request only. Ending the
                        // driver here would drop every connection on the
                        // session.
                        if let Some(waiter) = pending.take() {
                            let _ = waiter.send(Err(ErrorCode::StreamLimit));
                        }
                        debug!(
                            target: "wafred::tunnel",
                            error = %error,
                            "tunnel session cannot open another stream"
                        );
                    },
                    Poll::Pending => {},
                }
            }
            match connection.poll_next_inbound(cx) {
                Poll::Ready(Some(Ok(stream))) => {
                    if let Some(control) = first_control.take() {
                        // The connector's control stream; the handshake reads
                        // the hello from it.
                        let _ = control.send(stream);
                    } else {
                        // Only one inbound stream is expected; a second one is
                        // a protocol violation, dropped silently.
                        debug!(
                            target: "wafred::tunnel",
                            "dropping an unexpected inbound tunnel stream"
                        );
                        drop(stream);
                    }
                },
                Poll::Ready(Some(Err(error))) => {
                    debug!(
                        target: "wafred::tunnel",
                        error = %error,
                        "tunnel session ended"
                    );
                    return Poll::Ready(());
                },
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Pending => {},
            }
            Poll::Pending
        }) => {},
    }
    let _ = shutdown_tx.send(true);
}

/// How long a session may stay silent before it is considered dead.
///
/// At least three heartbeat intervals (so two lost frames do not kill a
/// healthy session), never below the configured liveness bound.
fn session_liveness_secs(
    settings: Option<crate::protocol::TunnelSettings>,
) -> u32 {
    let settings = settings.unwrap_or_default();
    (settings.heartbeat_secs.max(5) * 3).max(settings.idle_timeout_secs.max(30))
}

/// Fixed-window per-address handshake limiter.
///
/// A tunnel handshake costs a TLS handshake and a hash comparison, so the
/// bound is about keeping a scanner from pinning a core, not about a
/// per-credential policy (the credential itself is unguessable).
#[derive(Default)]
struct HandshakeLimiter {
    state: std::sync::Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl HandshakeLimiter {
    fn allow(&self, ip: IpAddr) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        let now = Instant::now();
        if state.len() > 4096 {
            state.retain(|_, (start, _)| {
                now.duration_since(*start) < HANDSHAKE_WINDOW
            });
        }
        let entry = state.entry(ip).or_insert((now, 0));
        if now.duration_since(entry.0) >= HANDSHAKE_WINDOW {
            *entry = (now, 1);
            return true;
        }
        entry.1 += 1;
        entry.1 <= HANDSHAKES_PER_WINDOW
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::TunnelSettings;
    use crate::registry::TunnelPolicy;
    use crate::token::{self, SessionTokenClaims};
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use tokio_rustls::TlsConnector;

    fn token_key() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[5u8; 32]).unwrap()
    }

    fn public_key_hex() -> String {
        token::public_key_hex(token_key().public_key().as_ref())
    }

    /// A token for `tunnel_id`, signed by the test key, valid for ten minutes.
    fn session_token(tunnel_id: &str) -> String {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let claims = SessionTokenClaims {
            tunnel_id: tunnel_id.to_string(),
            issued_at: now,
            expires_at: now + 600,
        };
        let signature = token_key().sign(&token::payload_bytes(&claims));
        token::encode(&claims, signature.as_ref())
    }

    fn policy(id: &str, targets: &[&str]) -> TunnelPolicy {
        TunnelPolicy {
            tunnel_id: id.to_string(),
            name: format!("tunnel-{id}"),
            enabled: true,
            session_public_key: public_key_hex(),
            targets: targets.iter().map(|t| t.to_string()).collect(),
            settings: TunnelSettings::default(),
        }
    }

    fn provider() -> Arc<rustls::crypto::CryptoProvider> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        crate::verify::default_provider().unwrap()
    }

    /// Starts a registry with one tunnel and a listener on an ephemeral port.
    async fn setup() -> (Arc<TunnelRegistry>, SocketAddr, TunnelCertificate) {
        // The listener builds its TLS configuration from the process provider,
        // which a test binary has to install itself.
        let _ = provider();
        let cert =
            TunnelCertificate::generate(&["localhost".to_string()]).unwrap();
        let registry = TunnelRegistry::new();
        registry.apply_policies(vec![policy("t-1", &["10.0.0.5:80"])]);
        let acceptor =
            TunnelAcceptor::bind("127.0.0.1:0", &cert, Arc::clone(&registry))
                .await
                .unwrap();
        let addr = acceptor.local_addr();
        acceptor.spawn();
        (registry, addr, cert)
    }

    #[test]
    fn the_handshake_limiter_bounds_one_address() {
        let limiter = HandshakeLimiter::default();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        for _ in 0..HANDSHAKES_PER_WINDOW {
            assert!(limiter.allow(ip));
        }
        assert!(!limiter.allow(ip));
        assert!(limiter.allow("203.0.113.8".parse().unwrap()));
    }

    #[tokio::test]
    async fn a_session_is_accepted_with_the_right_credential() {
        let (registry, addr, cert) = setup().await;
        let reply = connect(addr, &cert, "t-1", &session_token("t-1"))
            .await
            .unwrap();
        match reply {
            ControlFrame::HelloOk { targets, .. } => {
                assert_eq!(targets, vec!["10.0.0.5:80".to_string()]);
            },
            other => panic!("expected hello_ok, got {}", other.kind()),
        }
        // The session is registered once the handshake completed.
        for _ in 0..50 {
            if registry.session_count() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(registry.session_count(), 1);
    }

    #[tokio::test]
    async fn a_wrong_credential_is_rejected() {
        let (_registry, addr, cert) = setup().await;
        let reply = connect(addr, &cert, "t-1", &session_token("other-tunnel"))
            .await
            .unwrap();
        match reply {
            ControlFrame::Rejected { code, .. } => {
                assert_eq!(code, ErrorCode::Unauthenticated);
            },
            other => panic!("expected a rejection, got {}", other.kind()),
        }
    }

    #[tokio::test]
    async fn an_unknown_tunnel_is_rejected() {
        let (_registry, addr, cert) = setup().await;
        let reply = connect(addr, &cert, "nope", &session_token("nope"))
            .await
            .unwrap();
        assert!(matches!(
            reply,
            ControlFrame::Rejected {
                code: ErrorCode::Unauthenticated,
                ..
            }
        ));
    }

    /// Connects, says hello and returns the edge's answer. The yamux connection
    /// is driven on a background task so the handshake can complete.
    async fn connect(
        addr: SocketAddr,
        cert: &TunnelCertificate,
        tunnel_id: &str,
        token: &str,
    ) -> Result<ControlFrame> {
        let config = crate::verify::client_config(
            std::slice::from_ref(&cert.fingerprint_sha256),
            provider(),
        )?;
        let connector = TlsConnector::from(Arc::new(config));
        let tcp = TcpStream::connect(addr).await?;
        let name =
            rustls::pki_types::ServerName::try_from("localhost".to_string())?;
        let tls = connector.connect(name, tcp).await?;
        let mut connection = yamux::Connection::new(
            tls.compat(),
            yamux::Config::default(),
            yamux::Mode::Client,
        );
        let stream = poll_fn(|cx| connection.poll_new_outbound(cx)).await?;
        let mut stream = stream.compat();
        tokio::spawn(async move {
            let _ = poll_fn(|cx| connection.poll_next_inbound(cx)).await;
        });
        write_frame(
            &mut stream,
            &ControlFrame::Hello {
                protocol: PROTOCOL_VERSION,
                tunnel_id: tunnel_id.to_string(),
                token: token.to_string(),
                version: "0.0.0-test".to_string(),
                hostname: "connector-test".to_string(),
                os: "test".to_string(),
            },
        )
        .await?;
        Ok(read_frame(&mut stream).await?)
    }
}
