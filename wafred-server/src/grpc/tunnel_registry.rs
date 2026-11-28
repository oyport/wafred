//! In-memory registry of tunnel connectors that hold an open control stream.
//!
//! The control plane pushes policy to a connector over the bidirectional
//! `TunnelControl` stream, so a REST handler (revoke, disable, delete, settings
//! change) needs a way to reach a live stream it knows nothing about. This
//! registry is that bridge, mirroring [`crate::grpc::registry::AgentRegistry`].
//!
//! Unlike an agent, a connector has nothing to queue for: its policy is also
//! delivered when it reconnects, so a command that finds no live stream is
//! dropped rather than stored. The tunnel row is the source of truth.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};

use chrono::{DateTime, Utc};
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;
use wafred_proto::control_plane::TunnelConnectorCommand;

/// Buffer depth of the per-connector command channel.
pub const TUNNEL_COMMAND_CAPACITY: usize = 16;

struct Connection {
    sender: mpsc::Sender<TunnelConnectorCommand>,
    connected_at: DateTime<Utc>,
    /// Monotonic stream id: a teardown only removes the entry when it still
    /// matches, so a stream that finishes after the connector reconnected
    /// cannot unregister the live one.
    generation: u64,
}

#[derive(Default)]
pub struct TunnelConnectorRegistry {
    inner: RwLock<HashMap<Uuid, Connection>>,
    next_generation: AtomicU64,
}

/// The process-wide registry.
pub static TUNNEL_CONNECTORS: LazyLock<Arc<TunnelConnectorRegistry>> =
    LazyLock::new(TunnelConnectorRegistry::new);

impl TunnelConnectorRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Registers a live connector, replacing any previous stream for the same
    /// tunnel.
    pub async fn register(
        &self,
        tunnel_id: Uuid,
    ) -> (u64, mpsc::Receiver<TunnelConnectorCommand>) {
        let (sender, receiver) = mpsc::channel(TUNNEL_COMMAND_CAPACITY);
        let generation =
            self.next_generation.fetch_add(1, Ordering::SeqCst) + 1;
        let mut inner = self.inner.write().await;
        inner.insert(
            tunnel_id,
            Connection {
                sender,
                connected_at: Utc::now(),
                generation,
            },
        );
        (generation, receiver)
    }

    /// Removes a stream if it is still the live one.
    pub async fn unregister(&self, tunnel_id: Uuid, generation: u64) {
        let mut inner = self.inner.write().await;
        if inner
            .get(&tunnel_id)
            .is_some_and(|connection| connection.generation == generation)
        {
            inner.remove(&tunnel_id);
        }
    }

    /// Pushes a command to a live connector. Returns whether it was queued.
    pub async fn push(
        &self,
        tunnel_id: Uuid,
        command: TunnelConnectorCommand,
    ) -> bool {
        let sender = {
            let inner = self.inner.read().await;
            inner
                .get(&tunnel_id)
                .map(|connection| connection.sender.clone())
        };
        match sender {
            Some(sender) => sender.send(command).await.is_ok(),
            None => false,
        }
    }

    /// When each connected tunnel last registered a stream.
    pub async fn online(&self) -> HashMap<Uuid, DateTime<Utc>> {
        self.inner
            .read()
            .await
            .iter()
            .map(|(id, connection)| (*id, connection.connected_at))
            .collect()
    }

    pub async fn is_online(&self, tunnel_id: Uuid) -> bool {
        self.inner.read().await.contains_key(&tunnel_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wafred_proto::control_plane::TunnelConnectorRevoked;

    fn revoked(message: &str) -> TunnelConnectorCommand {
        TunnelConnectorCommand {
            kind: Some(
                wafred_proto::control_plane::tunnel_connector_command::Kind::Revoked(
                    TunnelConnectorRevoked {
                        message: message.to_string(),
                    },
                ),
            ),
        }
    }

    #[tokio::test]
    async fn a_registered_connector_receives_commands() {
        let registry = TunnelConnectorRegistry::new();
        let id = Uuid::new_v4();
        let (generation, mut rx) = registry.register(id).await;
        assert!(registry.is_online(id).await);
        assert!(registry.push(id, revoked("bye")).await);
        let command = rx.recv().await.unwrap();
        assert!(matches!(
            command.kind,
            Some(wafred_proto::control_plane::tunnel_connector_command::Kind::Revoked(_))
        ));
        registry.unregister(id, generation).await;
        assert!(!registry.is_online(id).await);
        assert!(!registry.push(id, revoked("bye")).await);
    }

    #[tokio::test]
    async fn a_stale_stream_cannot_unregister_the_live_one() {
        let registry = TunnelConnectorRegistry::new();
        let id = Uuid::new_v4();
        let (first, _rx1) = registry.register(id).await;
        let (_second, _rx2) = registry.register(id).await;
        registry.unregister(id, first).await;
        assert!(registry.is_online(id).await);
    }
}
