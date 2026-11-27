//! Entity for registered WAFred agents.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Connectivity state reported by the control plane.
pub mod agent_status {
    pub const ONLINE: &str = "online";
    pub const OFFLINE: &str = "offline";
    pub const DEGRADED: &str = "degraded";

    pub fn is_valid(status: &str) -> bool {
        matches!(status, ONLINE | OFFLINE | DEGRADED)
    }

    /// Maps `wafred::AgentHealthStatus` onto the persisted status string.
    pub fn from_proto_health(health: i32) -> &'static str {
        match health {
            1 => ONLINE,
            2 => DEGRADED,
            3 => OFFLINE,
            _ => ONLINE,
        }
    }
}

/// `agents` — one row per registered agent process.
pub mod agents {
    use super::*;

    #[derive(
        Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
    )]
    #[sea_orm(table_name = "agents")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub site_id: Option<Uuid>,
        /// `all` (legacy: every site owned by the API key) or `selected`
        /// (only the rows in `agent_sites`; may be empty).
        pub site_scope: String,
        /// Whether this agent may run ACME issuance and receive the site's
        /// DNS provider credentials. The embedded all-in-one issuer is marked
        /// automatically; consumer-only edges are not, so they serve the
        /// distributed PEM without ever seeing a Cloudflare/Aliyun token.
        pub acme_issuer: bool,
        pub hostname: String,
        /// Operator-editable label shown instead of `hostname` when set.
        ///
        /// Never used for identity: registration matches on
        /// `hostname + api_key_id`, so renaming the label cannot orphan a row.
        pub display_name: Option<String>,
        pub ip_address: String,
        /// Egress address as seen by the public internet, empty when unknown.
        pub public_ip: Option<String>,
        /// First non-virtual LAN address reported by the probe.
        pub private_ip: Option<String>,
        /// Transport peer of the agent's heartbeat stream: the address the
        /// control plane accepted the connection from, which is the closest
        /// thing to "the agent's public IP" when it sits behind NAT. Written
        /// from the RPC's `remote_addr`, not from anything the agent claims.
        pub peer_ip: Option<String>,
        /// When `peer_ip` was last observed on a live stream.
        pub peer_ip_seen_at: Option<DateTimeUtc>,
        pub version: Option<String>,
        pub os_info: Option<String>,
        pub cpu_cores: Option<i32>,
        /// Legacy single figure. Written with the capacity at registration and
        /// with the usage from the first heartbeat on, which is exactly the
        /// ambiguity `total_memory_bytes` and `used_memory_bytes` exist to
        /// remove. Kept — and still written by both paths — for
        /// readers that have not moved to the split columns.
        pub memory_bytes: Option<i64>,
        /// RAM the node has, as reported by the registration RPC. `None` on a
        /// row that has not re-registered since migration 000064 and has no
        /// retained probe sample to backfill from.
        pub total_memory_bytes: Option<i64>,
        /// RAM in use on the node, as reported by the last heartbeat. `None`
        /// until the first heartbeat after migration 000064.
        pub used_memory_bytes: Option<i64>,
        /// RSS of the agent process itself, as reported by the last heartbeat.
        /// `None` until the first heartbeat that carries it: unlike the memory
        /// counters there is no zero sentinel, so `None` is genuinely unknown.
        pub process_rss_bytes: Option<i64>,
        pub status: String,
        pub api_key_id: Option<Uuid>,
        pub config_hash: Option<String>,
        pub last_heartbeat: Option<DateTimeUtc>,
        /// When the agent last applied a full site config from the control
        /// plane (reported via heartbeat).
        pub last_config_sync_at: Option<DateTimeUtc>,
        /// When the agent last applied a per-site rule bundle.
        pub last_policy_sync_at: Option<DateTimeUtc>,
        pub registered_at: DateTimeUtc,
        /// Public `host:port` a connector should dial to reach this agent's
        /// tunnel listener; operator-set, `None` when the agent is not offered
        /// as a tunnel ingress.
        pub tunnel_ingress_addr: Option<String>,
        /// The address the agent's tunnel listener actually bound, empty/`None`
        /// when the listener is not enabled.
        pub tunnel_listener_addr: Option<String>,
        /// Lower-case hex SHA-256 of the leaf certificate the listener serves;
        /// connectors pin it.
        pub tunnel_cert_sha256: Option<String>,
        /// Why a configured tunnel listener is not running (bind failure,
        /// unusable certificate). `None` when it is active or never configured.
        pub tunnel_listener_error: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
