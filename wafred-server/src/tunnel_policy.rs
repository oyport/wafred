//! Tunnel policy: the bridge between the `tunnel_connectors` rows and what the
//! data planes and connectors are told.
//!
//! Two consumers share this module:
//!
//! * the rule bundle ([`bundle_tunnels`]) — every edge learns which tunnels it
//!   may accept, the public key its session token must verify against, and the
//!   target list;
//! * the connector control stream ([`connector_config`]) — the connector learns
//!   the same policy plus the ingress endpoints and the certificate
//!   fingerprints to pin.
//!
//! Targets are derived, never stored: they are the distinct peer addresses of
//! the origin pools bound to the tunnel. Renaming a pool node or deleting a site
//! therefore changes the policy without a second table to keep in sync.

use std::collections::HashMap;

use rand::RngExt;
use sea_orm::ActiveModelTrait;
use sea_orm::{
    ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter, Set,
};
use uuid::Uuid;

use pingwaf_proto::control_plane as proto;

use crate::models::{
    agent as agents, site_upstream_pools, site_upstreams,
    tunnel_connector as tunnel_connectors, tunnel_setting as tunnel_settings,
    tunnel_status,
};

/// Primary key of the single settings row.
pub const SETTINGS_ID: i32 = 1;

/// A fresh 32-byte secret, hex encoded.
///
/// Used for both the pairing token and the long-lived connector credential.
/// 256 bits of randomness is why a plain SHA-256 is the right storage: there is
/// nothing to guess, and the digest is what has to travel to the edges.
pub fn generate_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    hex::encode(bytes)
}

/// SHA-256 of a secret, lower-case hex.
pub fn digest_hex(secret: &str) -> String {
    wafred_tunnel::protocol::credential_digest(secret)
}

/// Loads the global tunnel settings, creating the default row on first use.
pub async fn load_settings(
    db: &DatabaseConnection,
) -> Result<tunnel_settings::Model, DbErr> {
    if let Some(row) = tunnel_settings::Entity::find_by_id(SETTINGS_ID)
        .one(db)
        .await?
    {
        return Ok(row.sanitized());
    }
    let now = chrono::Utc::now();
    let active = tunnel_settings::ActiveModel {
        id: Set(SETTINGS_ID),
        enabled: Set(true),
        pairing_ttl_seconds: Set(1800),
        max_streams_per_session: Set(256),
        max_targets_per_tunnel: Set(256),
        idle_timeout_seconds: Set(300),
        heartbeat_seconds: Set(20),
        session_token_ttl_seconds: Set(3600),
        updated_at: Set(now),
    };
    Ok(active.insert(db).await?.sanitized())
}

/// Distinct targets of every tunnel, keyed by tunnel id.
///
/// A pool with no tunnel contributes nothing; a peer address that is not a
/// valid `host:port` is dropped rather than handed to a connector's dialer.
pub async fn targets_by_tunnel(
    db: &DatabaseConnection,
) -> Result<HashMap<Uuid, Vec<String>>, DbErr> {
    let pools = site_upstream_pools::Entity::find().all(db).await?;
    let peers = site_upstreams::Entity::find().all(db).await?;
    Ok(collect_targets(&bindings(&pools), &peer_rows(&peers)))
}

/// `(pool id, tunnel id)` for every pool bound to a tunnel.
fn bindings(pools: &[site_upstream_pools::Model]) -> Vec<(Uuid, Option<Uuid>)> {
    pools.iter().map(|pool| (pool.id, pool.tunnel_id)).collect()
}

/// `(pool id, address, tls)` for every origin node.
fn peer_rows(peers: &[site_upstreams::Model]) -> Vec<(Uuid, String, bool)> {
    peers
        .iter()
        .map(|peer| (peer.pool_id, peer.address.clone(), peer.tls))
        .collect()
}

/// The pure part of [`targets_by_tunnel`]: which `host:port` each tunnel
/// serves, deduplicated and sorted.
///
/// The address goes through `normalize_pool_target`, the same function the edge
/// uses to look a bridge up. A pool may store a bare host (`app.internal`,
/// which the API accepts); deriving the target with the *strict* normalizer
/// dropped it, and the pool then silently had no upstream on the edge while the
/// connector refused to dial it. The default port follows the peer's TLS flag,
/// exactly as a direct origin would.
pub(crate) fn collect_targets(
    bindings: &[(Uuid, Option<Uuid>)],
    peers: &[(Uuid, String, bool)],
) -> HashMap<Uuid, Vec<String>> {
    let pool_tunnel: HashMap<Uuid, Uuid> = bindings
        .iter()
        .filter_map(|(pool_id, tunnel_id)| {
            tunnel_id.map(|tunnel| (*pool_id, tunnel))
        })
        .collect();
    let mut targets: HashMap<Uuid, Vec<String>> = HashMap::new();
    for (pool_id, address, tls) in peers {
        let Some(tunnel_id) = pool_tunnel.get(pool_id).copied() else {
            continue;
        };
        let Some(address) =
            wafred_tunnel::protocol::normalize_pool_target(address, *tls)
        else {
            continue;
        };
        let entry = targets.entry(tunnel_id).or_default();
        if !entry.iter().any(|existing| existing == &address) {
            entry.push(address);
        }
    }
    for list in targets.values_mut() {
        list.sort();
    }
    targets
}

/// Targets of one tunnel, capped by the deployment limit.
pub async fn targets_for_tunnel(
    db: &DatabaseConnection,
    tunnel_id: Uuid,
) -> Result<Vec<String>, DbErr> {
    let settings = load_settings(db).await?;
    let all = targets_by_tunnel(db).await?;
    let mut all = all;
    let mut targets = all.remove(&tunnel_id).unwrap_or_default();
    let limit = settings.max_targets_per_tunnel.max(1) as usize;
    if targets.len() > limit {
        tracing::warn!(
            %tunnel_id,
            targets = targets.len(),
            limit,
            "tunnel advertises more targets than the deployment limit; truncating"
        );
        targets.truncate(limit);
    }
    Ok(targets)
}

/// Domains of the sites whose origin pools are bound to each tunnel.
///
/// Used by the console to answer "what breaks if I disable/delete this?", so a
/// destructive action can name its blast radius instead of a count.
pub(crate) fn collect_sites(
    pools: &[site_upstream_pools::Model],
    domains: &HashMap<Uuid, String>,
) -> HashMap<Uuid, Vec<String>> {
    let mut by_tunnel: HashMap<Uuid, Vec<String>> = HashMap::new();
    for pool in pools {
        let Some(tunnel_id) = pool.tunnel_id else {
            continue;
        };
        let Some(domain) = domains.get(&pool.site_id) else {
            continue;
        };
        let entry = by_tunnel.entry(tunnel_id).or_default();
        if !entry.iter().any(|existing| existing == domain) {
            entry.push(domain.clone());
        }
    }
    for list in by_tunnel.values_mut() {
        list.sort();
    }
    by_tunnel
}

/// The derived tunnel facts, as one caller is allowed to see them.
#[derive(Debug, Default)]
pub struct TunnelDerivation {
    pub targets: HashMap<Uuid, Vec<String>>,
    pub sites: HashMap<Uuid, Vec<String>>,
}

/// Derives the per-tunnel targets and site domains.
///
/// `owner = None` is an administrator and sees everything. `Some(user_id)`
/// restricts both maps to that user's own sites: a non-admin whose site is
/// bound to a tunnel must not learn the *other* tenants' domains or internal
/// addresses that share it.
pub async fn derive_for(
    db: &DatabaseConnection,
    owner: Option<Uuid>,
) -> Result<TunnelDerivation, DbErr> {
    let sites = match owner {
        Some(user_id) => {
            crate::models::site::Entity::find()
                .filter(crate::models::site::Column::UserId.eq(user_id))
                .all(db)
                .await?
        },
        None => crate::models::site::Entity::find().all(db).await?,
    };
    let site_ids: Vec<Uuid> = sites.iter().map(|row| row.id).collect();
    if owner.is_some() && site_ids.is_empty() {
        return Ok(TunnelDerivation::default());
    }
    let domains: HashMap<Uuid, String> =
        sites.into_iter().map(|row| (row.id, row.domain)).collect();
    let pools = match owner {
        Some(_) => {
            site_upstream_pools::Entity::find()
                .filter(site_upstream_pools::Column::SiteId.is_in(site_ids))
                .all(db)
                .await?
        },
        None => site_upstream_pools::Entity::find().all(db).await?,
    };
    let peers = match owner {
        Some(_) => {
            let pool_ids: Vec<Uuid> =
                pools.iter().map(|pool| pool.id).collect();
            site_upstreams::Entity::find()
                .filter(site_upstreams::Column::PoolId.is_in(pool_ids))
                .all(db)
                .await?
        },
        None => site_upstreams::Entity::find().all(db).await?,
    };
    Ok(TunnelDerivation {
        targets: collect_targets(&bindings(&pools), &peer_rows(&peers)),
        sites: collect_sites(&pools, &domains),
    })
}

/// Ingress endpoints connectors should dial, grouped by public address.
///
/// An agent contributes when the operator gave it a public address *and* it
/// reported a certificate fingerprint: without a fingerprint a connector cannot
/// verify the edge, and an unverifiable ingress is not offered.
pub async fn ingress_endpoints(
    db: &DatabaseConnection,
) -> Result<Vec<proto::TunnelIngress>, DbErr> {
    let rows = agents::Entity::find().all(db).await?;
    let mut grouped: HashMap<String, Vec<String>> = HashMap::new();
    for row in rows {
        let (Some(addr), Some(fingerprint)) = (
            row.tunnel_ingress_addr.as_deref().map(str::trim),
            row.tunnel_cert_sha256.as_deref().map(str::trim),
        ) else {
            continue;
        };
        if addr.is_empty() || fingerprint.is_empty() {
            continue;
        }
        let entry = grouped.entry(addr.to_string()).or_default();
        if !entry.iter().any(|existing| existing == fingerprint) {
            entry.push(fingerprint.to_string());
        }
    }
    let mut endpoints: Vec<proto::TunnelIngress> = grouped
        .into_iter()
        .map(|(endpoint, fingerprints)| proto::TunnelIngress {
            endpoint,
            fingerprints,
        })
        .collect();
    endpoints.sort_by(|a, b| a.endpoint.cmp(&b.endpoint));
    Ok(endpoints)
}

/// The tunnel list and the limits, as the rule bundle carries them.
pub async fn bundle_tunnels(
    db: &DatabaseConnection,
) -> Result<(Vec<proto::TunnelConfig>, proto::TunnelSettings), DbErr> {
    let settings = load_settings(db).await?;
    let targets = targets_by_tunnel(db).await?;
    let rows = tunnel_connectors::Entity::find().all(db).await?;
    let mut tunnels = Vec::with_capacity(rows.len());
    for row in rows {
        let mut targets = targets.get(&row.id).cloned().unwrap_or_default();
        let limit = settings.max_targets_per_tunnel.max(1) as usize;
        if targets.len() > limit {
            targets.truncate(limit);
        }
        // An unpaired tunnel (never paired, or revoked) must not accept a
        // session even when a connector still holds an unexpired token: with
        // no key in the bundle nothing verifies, which is what makes a
        // revocation take effect on the next reload instead of waiting out the
        // token's lifetime.
        let paired = row.credential_sha256.is_some();
        tunnels.push(proto::TunnelConfig {
            tunnel_id: row.id.to_string(),
            name: row.name,
            // The edges verify a signature; they never receive the connector's
            // credential or its digest.
            session_public_key: if paired {
                crate::tunnel_token::public_key_hex()
            } else {
                String::new()
            },
            // A tunnel that was never paired, or that an operator disabled,
            // is not accepted by an edge even though the row still exists.
            enabled: accepts_sessions(settings.enabled, paired, &row.status),
            targets,
        });
    }
    tunnels.sort_by(|a, b| a.name.cmp(&b.name));
    Ok((
        tunnels,
        proto::TunnelSettings {
            max_streams: settings.max_streams_per_session.max(1) as u32,
            idle_timeout_secs: settings.idle_timeout_seconds.max(10) as u32,
            heartbeat_secs: settings.heartbeat_seconds.max(5) as u32,
            session_token_ttl_secs: settings.session_token_ttl_seconds.max(60)
                as u32,
        },
    ))
}

/// Whether an edge may accept a session for a tunnel.
///
/// All three conditions matter: the deployment switch, a paired credential
/// (an unpaired or revoked tunnel has no key to verify against) and the
/// per-tunnel status.
fn accepts_sessions(
    settings_enabled: bool,
    paired: bool,
    status: &str,
) -> bool {
    settings_enabled && paired && status != tunnel_status::DISABLED
}

/// The policy pushed to one connector.
pub async fn connector_config(
    db: &DatabaseConnection,
    tunnel_id: Uuid,
) -> Result<Option<proto::TunnelConnectorConfig>, DbErr> {
    let Some(row) = tunnel_connectors::Entity::find_by_id(tunnel_id)
        .one(db)
        .await?
    else {
        return Ok(None);
    };
    let settings = load_settings(db).await?;
    // Every push carries a freshly minted token: the connector must never have
    // to ask for one on the data path, and a rotating token is what bounds a
    // revoked tunnel's reach on a partitioned edge.
    let (session_token, session_token_expires_at) = crate::tunnel_token::mint(
        &tunnel_id.to_string(),
        settings.session_token_ttl_seconds.max(60) as u64,
    )
    .map_err(|err| sea_orm::DbErr::Custom(err.to_string()))?;
    Ok(Some(proto::TunnelConnectorConfig {
        ingress: ingress_endpoints(db).await?,
        targets: targets_for_tunnel(db, tunnel_id).await?,
        settings: Some(proto::TunnelSettings {
            max_streams: settings.max_streams_per_session.max(1) as u32,
            idle_timeout_secs: settings.idle_timeout_seconds.max(10) as u32,
            heartbeat_secs: settings.heartbeat_seconds.max(5) as u32,
            session_token_ttl_secs: settings.session_token_ttl_seconds.max(60)
                as u32,
        }),
        enabled: settings.enabled && row.status != tunnel_status::DISABLED,
        session_token,
        session_token_expires_at,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_secrets_are_256_bits_of_hex() {
        let first = generate_secret();
        let second = generate_secret();
        assert_eq!(first.len(), 64);
        assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(first, second);
    }

    #[test]
    fn a_digest_is_stable_and_distinguishes_secrets() {
        let digest = digest_hex("secret");
        assert_eq!(digest, digest_hex("secret"));
        assert_ne!(digest, digest_hex("secret2"));
        assert_eq!(digest.len(), 64);
        assert!(wafred_tunnel::protocol::credential_matches(
            "secret", &digest
        ));
        assert!(!wafred_tunnel::protocol::credential_matches(
            "other", &digest
        ));
    }

    #[test]
    fn targets_get_the_default_port_of_the_peer_tls_flag() {
        let tunnel = Uuid::new_v4();
        let pool = Uuid::new_v4();
        let bindings = vec![(pool, Some(tunnel))];
        let peers = vec![
            (pool, "app.internal".to_string(), false),
            (pool, "secure.internal".to_string(), true),
            (pool, "10.0.0.5:8080".to_string(), false),
            // Duplicated and unsorted on purpose: the derivation dedupes and
            // sorts, so a reordered pool does not churn the config hash.
            (pool, "10.0.0.5:8080".to_string(), false),
            (pool, "app.internal".to_string(), false),
        ];
        let targets = collect_targets(&bindings, &peers);
        assert_eq!(
            targets.get(&tunnel).cloned().unwrap_or_default(),
            vec![
                "10.0.0.5:8080".to_string(),
                "app.internal:80".to_string(),
                "secure.internal:443".to_string(),
            ],
            "a bare host must get the default port of its TLS flag, or the edge \
             and the bundle would disagree and the pool would have no upstream"
        );
    }

    #[test]
    fn an_unpaired_or_disabled_tunnel_refuses_sessions() {
        assert!(accepts_sessions(true, true, tunnel_status::ACTIVE));
        // Never paired, or revoked: no key in the bundle, so nothing verifies
        // — this is what makes a revocation immediate rather than bounded by
        // the token's lifetime.
        assert!(!accepts_sessions(true, false, tunnel_status::ACTIVE));
        // An operator disabled this one.
        assert!(!accepts_sessions(true, true, tunnel_status::DISABLED));
        // The deployment-wide switch is off.
        assert!(!accepts_sessions(false, true, tunnel_status::ACTIVE));
        // Still waiting for the connector to redeem its token.
        assert!(accepts_sessions(true, true, tunnel_status::PENDING));
    }

    #[test]
    fn an_unbound_pool_contributes_nothing() {
        let pool = Uuid::new_v4();
        let targets = collect_targets(
            &[(pool, None)],
            &[(pool, "10.0.0.5:8080".to_string(), false)],
        );
        assert!(targets.is_empty());
    }

    #[test]
    fn an_unparsable_address_is_dropped_instead_of_panicking() {
        let tunnel = Uuid::new_v4();
        let pool = Uuid::new_v4();
        let targets = collect_targets(
            &[(pool, Some(tunnel))],
            &[
                (pool, "bad:port:here".to_string(), false),
                (pool, "  ".to_string(), false),
            ],
        );
        assert!(targets.is_empty());
    }
}
