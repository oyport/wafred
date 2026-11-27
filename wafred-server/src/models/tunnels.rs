//! Tunnel connectors, their global settings and the sessions edges report.
//!
//! The connector's credential and the pairing token are stored as SHA-256
//! digests only: the plaintext is returned exactly once, when it is minted.
//! The credential authenticates the connector's *control stream*; the edges
//! never see it. What they receive in the rule bundle is the public key of the
//! deployment's session-token signing key, and what the connector presents is a
//! short-lived token signed with it — see `tunnel_token.rs` and `SECURITY.md`.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Values `tunnel_connectors.status` accepts.
pub mod tunnel_status {
    /// Created, but no connector has redeemed its pairing token yet.
    pub const PENDING: &str = "pending";
    /// Paired: a credential exists.
    pub const ACTIVE: &str = "active";
    /// Paired but administratively switched off; edges refuse new sessions.
    pub const DISABLED: &str = "disabled";

    pub fn is_valid(status: &str) -> bool {
        matches!(status, PENDING | ACTIVE | DISABLED)
    }
}

/// `tunnel_connectors` — one row per tunnel connector process.
pub mod tunnel_connectors {
    use super::*;

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "tunnel_connectors")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub name: String,
        pub description: Option<String>,
        pub status: String,
        /// SHA-256 of the one-time pairing token; `None` once redeemed.
        pub pairing_token_hash: Option<String>,
        pub pairing_token_expires_at: Option<DateTimeUtc>,
        /// SHA-256 of the long-lived connector credential. Handed to the edges
        /// in the rule bundle; the secret itself is never stored.
        pub credential_sha256: Option<String>,
        pub credential_issued_at: Option<DateTimeUtc>,
        pub version: Option<String>,
        pub hostname: Option<String>,
        pub os_info: Option<String>,
        /// Last time the connector's control stream reported in.
        pub last_seen_at: Option<DateTimeUtc>,
        pub created_by: Option<Uuid>,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// `tunnel_settings` — the single global row of tunnel limits.
pub mod tunnel_settings {
    use super::*;

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "tunnel_settings")]
    pub struct Model {
        /// Always `1`: the settings are global, not per-tunnel.
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: i32,
        /// Master switch: when off, every edge refuses new sessions and the
        /// control plane hands connectors an empty policy.
        pub enabled: bool,
        /// How long a pairing token stays redeemable.
        pub pairing_ttl_seconds: i32,
        /// Concurrent data streams one connector session may carry.
        pub max_streams_per_session: i32,
        /// Upper bound on the targets a tunnel may advertise.
        pub max_targets_per_tunnel: i32,
        /// Idle timeout handed to connectors.
        pub idle_timeout_seconds: i32,
        /// Control-frame heartbeat cadence.
        pub heartbeat_seconds: i32,
        /// Lifetime of a connector session token. Also bounds how long a
        /// partitioned edge keeps accepting a revoked tunnel.
        pub session_token_ttl_seconds: i32,
        pub updated_at: DateTimeUtc,
    }

    impl Model {
        /// Values clamped to what the data plane can honour.
        pub fn sanitized(&self) -> Self {
            let mut model = self.clone();
            model.pairing_ttl_seconds =
                model.pairing_ttl_seconds.clamp(60, 86_400);
            model.max_streams_per_session =
                model.max_streams_per_session.clamp(1, 4096);
            model.max_targets_per_tunnel =
                model.max_targets_per_tunnel.clamp(1, 4096);
            model.idle_timeout_seconds =
                model.idle_timeout_seconds.clamp(10, 86_400);
            model.heartbeat_seconds = model.heartbeat_seconds.clamp(5, 300);
            model.session_token_ttl_seconds =
                model.session_token_ttl_seconds.clamp(60, 86_400);
            model
        }
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// `tunnel_sessions` — one live connector session on one edge.
pub mod tunnel_sessions {
    use super::*;

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "tunnel_sessions")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub tunnel_id: Uuid,
        pub agent_id: Uuid,
        pub connected_at: DateTimeUtc,
        pub last_seen_at: DateTimeUtc,
        pub version: Option<String>,
        pub hostname: Option<String>,
        pub streams_active: i32,
        pub rtt_ms: i32,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
