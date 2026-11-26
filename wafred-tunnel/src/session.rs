//! A live connector session as the edge sees it.
//!
//! The yamux connection itself is owned by the driver task in
//! [`crate::server`]; this handle is what the rest of the edge uses: open a data
//! stream per proxied connection, enqueue a control frame, or close the session
//! when the policy changes.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use anyhow::Result;
use time::OffsetDateTime;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::protocol::{ControlFrame, ErrorCode, TunnelSettings};

/// How long a bridge waits for the connector to accept a new data stream.
#[cfg(not(test))]
const OPEN_STREAM_TIMEOUT: Duration = Duration::from_secs(15);
#[cfg(test)]
const OPEN_STREAM_TIMEOUT: Duration = Duration::from_millis(50);

/// What the heartbeat reports about one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionReport {
    pub tunnel_id: String,
    pub connector_version: String,
    pub hostname: String,
    pub connected_at: OffsetDateTime,
    pub streams_active: u32,
    pub rtt_ms: u32,
}

/// Request a data stream from the driver task.
pub(crate) type OpenRequest =
    oneshot::Sender<std::result::Result<yamux::Stream, ErrorCode>>;

/// Keeps the session's active-stream counter accurate for as long as the
/// stream is alive. Dropped together with the stream by the caller.
#[derive(Debug)]
pub struct StreamLease {
    active: Arc<AtomicU32>,
}

impl Drop for StreamLease {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

/// One connector session on this edge.
#[derive(Debug)]
pub struct Session {
    pub tunnel_id: String,
    pub connector_version: String,
    pub hostname: String,
    pub connected_at: OffsetDateTime,
    pub peer: SocketAddr,
    pub policy_version: u64,
    pub settings: TunnelSettings,
    open_tx: mpsc::Sender<OpenRequest>,
    control_tx: mpsc::Sender<ControlFrame>,
    shutdown_tx: watch::Sender<bool>,
    closed: AtomicBool,
    streams_active: Arc<AtomicU32>,
    rtt_ms: AtomicU32,
    control_task: std::sync::Mutex<Option<JoinHandle<()>>>,
}

impl Session {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        tunnel_id: String,
        connector_version: String,
        hostname: String,
        peer: SocketAddr,
        policy_version: u64,
        settings: TunnelSettings,
        open_tx: mpsc::Sender<OpenRequest>,
        control_tx: mpsc::Sender<ControlFrame>,
        shutdown_tx: watch::Sender<bool>,
    ) -> Self {
        Self {
            tunnel_id,
            connector_version,
            hostname,
            connected_at: OffsetDateTime::now_utc(),
            peer,
            policy_version,
            settings,
            open_tx,
            control_tx,
            shutdown_tx,
            closed: AtomicBool::new(false),
            streams_active: Arc::new(AtomicU32::new(0)),
            rtt_ms: AtomicU32::new(0),
            control_task: std::sync::Mutex::new(None),
        }
    }

    /// Installs the control-stream task so `close()` can stop it too.
    pub(crate) fn set_control_task(&self, handle: JoinHandle<()>) {
        if let Ok(mut slot) = self.control_task.lock() {
            *slot = Some(handle);
        }
    }

    /// Opens a data stream, honouring the session's concurrency limit.
    ///
    /// The returned lease must be held for as long as the stream is in use: it
    /// is what decrements the active count.
    pub async fn open_stream(
        &self,
    ) -> Result<(yamux::Stream, StreamLease), ErrorCode> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(ErrorCode::Revoked);
        }
        let limit = self.settings.max_streams.max(1);
        let active = self.streams_active.fetch_add(1, Ordering::SeqCst) + 1;
        if active > limit {
            self.streams_active.fetch_sub(1, Ordering::SeqCst);
            return Err(ErrorCode::StreamLimit);
        }
        let lease = StreamLease {
            active: Arc::clone(&self.streams_active),
        };
        let (tx, rx) = oneshot::channel();
        if self.open_tx.send(tx).await.is_err() {
            return Err(ErrorCode::Revoked);
        }
        match tokio::time::timeout(OPEN_STREAM_TIMEOUT, rx).await {
            Ok(Ok(Ok(stream))) => Ok((stream, lease)),
            Ok(Ok(Err(code))) => Err(code),
            _ => Err(ErrorCode::ProtocolError),
        }
    }

    /// Enqueues a control frame. Returns false when the session is gone.
    pub fn send_control(&self, frame: ControlFrame) -> bool {
        !self.closed.load(Ordering::SeqCst)
            && self.control_tx.try_send(frame).is_ok()
    }

    /// Sends a policy update when the target list or the limits changed.
    pub fn push_policy(
        &self,
        policy_version: u64,
        targets: Vec<String>,
        settings: TunnelSettings,
    ) {
        self.send_control(ControlFrame::PolicyUpdate {
            policy_version,
            targets,
            settings,
        });
    }

    /// Records the connector's last reported round-trip time.
    pub fn record_rtt(&self, rtt_ms: u32) {
        self.rtt_ms.store(rtt_ms, Ordering::Relaxed);
    }

    pub fn streams_active(&self) -> u32 {
        self.streams_active.load(Ordering::Relaxed)
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Closes the session, telling the connector why when it still can.
    ///
    /// The terminal frame is enqueued before the driver is stopped so the
    /// control writer gets a chance to flush it; if the queue is full the
    /// session is simply torn down.
    pub fn close(&self, frame: ControlFrame) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        let _ = self.control_tx.try_send(frame);
        // The connection driver observes this and returns, dropping the yamux
        // connection (and with it every stream); the per-connection task then
        // unregisters the session. The control task gets a backstop abort for
        // the case where it is blocked on a full write.
        let _ = self.shutdown_tx.send(true);
        let control = self
            .control_task
            .lock()
            .ok()
            .and_then(|mut slot| slot.take());
        if let Some(control) = control {
            tokio::spawn(async move {
                // Give the control writer a moment to flush the terminal
                // frame before the task is torn down.
                tokio::time::sleep(Duration::from_millis(200)).await;
                control.abort();
            });
        }
    }

    pub fn report(&self) -> SessionReport {
        SessionReport {
            tunnel_id: self.tunnel_id.clone(),
            connector_version: self.connector_version.clone(),
            hostname: self.hostname.clone(),
            connected_at: self.connected_at,
            streams_active: self.streams_active(),
            rtt_ms: self.rtt_ms.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(limit: u32) -> Session {
        let (open_tx, mut open_rx) = mpsc::channel::<OpenRequest>(8);
        let (control_tx, _control_rx) = mpsc::channel(8);
        let (shutdown_tx, _) = watch::channel(false);
        // A driver that never answers: the lease accounting is what is under
        // test here, not the stream itself.
        tokio::spawn(async move { while open_rx.recv().await.is_some() {} });
        Session::new(
            "t-1".to_string(),
            "1.0.0".to_string(),
            "connector-1".to_string(),
            "127.0.0.1:1234".parse().unwrap(),
            1,
            TunnelSettings {
                max_streams: limit,
                ..TunnelSettings::default()
            },
            open_tx,
            control_tx,
            shutdown_tx,
        )
    }

    #[tokio::test]
    async fn the_stream_limit_is_enforced_and_released_by_the_lease() {
        let session = session(1);
        // No driver answer: the open times out, but the slot is taken for the
        // duration and released by the failing path.
        assert!(session.open_stream().await.is_err());
        assert_eq!(session.streams_active(), 0);
    }

    #[tokio::test]
    async fn a_closed_session_refuses_new_streams() {
        let session = session(4);
        session.close(ControlFrame::Revoked {
            message: "test".to_string(),
        });
        assert!(session.is_closed());
        assert_eq!(session.open_stream().await.err(), Some(ErrorCode::Revoked));
        assert!(!session.send_control(ControlFrame::HeartbeatAck {
            policy_version: 1,
            targets: None,
            settings: None,
        }));
    }
}
