//! Tunnel connectors, the deployment-wide tunnel settings, and the pool binding.
//!
//! A tunnel is one connector process running inside a private network. It is
//! identified by a row here, admitted by a one-time pairing token and then by a
//! long-lived credential of which only the SHA-256 is stored — the edges receive
//! that digest in the rule bundle, so the secret itself never leaves the
//! connector and the control plane.
//!
//! `site_upstream_pools.tunnel_id` is what makes a pool's origins reachable
//! through that tunnel: the pool's peer addresses are then resolved by the
//! connector inside the private network instead of by the edge. `NULL` keeps the
//! historic behaviour (the edge dials the address itself).

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(TunnelConnectors::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(TunnelConnectors::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(TunnelConnectors::Name)
                            .string_len(120)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TunnelConnectors::Description)
                            .text()
                            .null(),
                    )
                    // `pending` (created, never paired), `active`, `disabled`.
                    .col(
                        ColumnDef::new(TunnelConnectors::Status)
                            .string_len(16)
                            .not_null()
                            .default("pending"),
                    )
                    // Only the digest: the token is shown once, in the response
                    // that mints it.
                    .col(
                        ColumnDef::new(TunnelConnectors::PairingTokenHash)
                            .string_len(64)
                            .null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(TunnelConnectors::PairingTokenExpiresAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(TunnelConnectors::CredentialSha256)
                            .string_len(64)
                            .null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(TunnelConnectors::CredentialIssuedAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(TunnelConnectors::Version)
                            .string_len(64)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(TunnelConnectors::Hostname)
                            .string_len(255)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(TunnelConnectors::OsInfo)
                            .string_len(255)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(TunnelConnectors::LastSeenAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(TunnelConnectors::CreatedBy)
                            .uuid()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(TunnelConnectors::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TunnelConnectors::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // One row, like the other `<topic>_settings` tables.
        manager
            .create_table(
                Table::create()
                    .table(TunnelSettings::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(TunnelSettings::Id)
                            .integer()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(TunnelSettings::Enabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(TunnelSettings::PairingTtlSeconds)
                            .integer()
                            .not_null()
                            .default(1800),
                    )
                    .col(
                        ColumnDef::new(TunnelSettings::MaxStreamsPerSession)
                            .integer()
                            .not_null()
                            .default(256),
                    )
                    .col(
                        ColumnDef::new(TunnelSettings::MaxTargetsPerTunnel)
                            .integer()
                            .not_null()
                            .default(256),
                    )
                    .col(
                        ColumnDef::new(TunnelSettings::IdleTimeoutSeconds)
                            .integer()
                            .not_null()
                            .default(300),
                    )
                    .col(
                        ColumnDef::new(TunnelSettings::HeartbeatSeconds)
                            .integer()
                            .not_null()
                            .default(20),
                    )
                    .col(
                        ColumnDef::new(TunnelSettings::SessionTokenTtlSeconds)
                            .integer()
                            .not_null()
                            .default(3600),
                    )
                    .col(
                        ColumnDef::new(TunnelSettings::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .get_connection()
            .execute_unprepared(
                "INSERT INTO tunnel_settings (id, enabled, pairing_ttl_seconds, \
                 max_streams_per_session, max_targets_per_tunnel, \
                 idle_timeout_seconds, heartbeat_seconds, \
                 session_token_ttl_seconds, updated_at) \
                 VALUES (1, true, 1800, 256, 256, 300, 20, 3600, now()) \
                 ON CONFLICT (id) DO NOTHING",
            )
            .await?;

        // The binding. `ON DELETE SET NULL` keeps a pool usable (as a direct
        // origin) when its tunnel is deleted, instead of failing the delete or
        // orphaning a dangling id.
        manager
            .alter_table(
                Table::alter()
                    .table(SiteUpstreamPools::Table)
                    .add_column(
                        ColumnDef::new(SiteUpstreamPools::TunnelId)
                            .uuid()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_foreign_key(
                ForeignKey::create()
                    .name("fk_site_upstream_pools_tunnel")
                    .from(SiteUpstreamPools::Table, SiteUpstreamPools::TunnelId)
                    .to(TunnelConnectors::Table, TunnelConnectors::Id)
                    .on_delete(ForeignKeyAction::SetNull)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_site_upstream_pools_tunnel")
                    .table(SiteUpstreamPools::Table)
                    .col(SiteUpstreamPools::TunnelId)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_site_upstream_pools_tunnel")
                    .table(SiteUpstreamPools::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_foreign_key(
                ForeignKey::drop()
                    .name("fk_site_upstream_pools_tunnel")
                    .table(SiteUpstreamPools::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(SiteUpstreamPools::Table)
                    .drop_column(SiteUpstreamPools::TunnelId)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(TunnelSettings::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(TunnelConnectors::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum TunnelConnectors {
    Table,
    Id,
    Name,
    Description,
    Status,
    PairingTokenHash,
    PairingTokenExpiresAt,
    CredentialSha256,
    CredentialIssuedAt,
    Version,
    Hostname,
    OsInfo,
    LastSeenAt,
    CreatedBy,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum TunnelSettings {
    Table,
    Id,
    Enabled,
    PairingTtlSeconds,
    MaxStreamsPerSession,
    MaxTargetsPerTunnel,
    IdleTimeoutSeconds,
    HeartbeatSeconds,
    SessionTokenTtlSeconds,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum SiteUpstreamPools {
    Table,
    TunnelId,
}
