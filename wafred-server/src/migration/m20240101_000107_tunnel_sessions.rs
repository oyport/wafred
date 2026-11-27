//! Tunnel sessions per edge, and the identity an edge reports for its listener.
//!
//! A connector can hold one session per edge. The rows here are a *report*, not
//! a source of truth: an agent sends its live sessions on every heartbeat and the
//! control plane replaces what it knew for that agent. A row that stops being
//! reported is deleted, so the console never shows a session that ended.
//!
//! The three agent columns are what the tunnel page needs to know about an edge
//! before a connector can use it: where its listener is reachable
//! (`tunnel_ingress_addr`, operator-set), whether it actually bound a listener
//! (`tunnel_listener_addr`), and the SHA-256 of the certificate a connector must
//! pin (`tunnel_cert_sha256`).

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(TunnelSessions::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(TunnelSessions::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(TunnelSessions::TunnelId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TunnelSessions::AgentId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TunnelSessions::ConnectedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TunnelSessions::LastSeenAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TunnelSessions::Version)
                            .string_len(64)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(TunnelSessions::Hostname)
                            .string_len(255)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(TunnelSessions::StreamsActive)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(TunnelSessions::RttMs)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .to_owned(),
            )
            .await?;
        // One session per (tunnel, edge): the newest one replaces the previous.
        manager
            .create_index(
                Index::create()
                    .name("idx_tunnel_sessions_tunnel_agent")
                    .table(TunnelSessions::Table)
                    .col(TunnelSessions::TunnelId)
                    .col(TunnelSessions::AgentId)
                    .unique()
                    .to_owned(),
            )
            .await?;
        // The heartbeat deletes by agent, the page lists by tunnel.
        manager
            .create_index(
                Index::create()
                    .name("idx_tunnel_sessions_agent")
                    .table(TunnelSessions::Table)
                    .col(TunnelSessions::AgentId)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Agents::Table)
                    .add_column(
                        ColumnDef::new(Agents::TunnelIngressAddr)
                            .string_len(255)
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(Agents::TunnelListenerAddr)
                            .string_len(255)
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(Agents::TunnelCertSha256)
                            .string_len(64)
                            .null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Agents::Table)
                    .drop_column(Agents::TunnelListenerError)
                    .drop_column(Agents::TunnelCertSha256)
                    .drop_column(Agents::TunnelListenerAddr)
                    .drop_column(Agents::TunnelIngressAddr)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(TunnelSessions::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum TunnelSessions {
    Table,
    Id,
    TunnelId,
    AgentId,
    ConnectedAt,
    LastSeenAt,
    Version,
    Hostname,
    StreamsActive,
    RttMs,
}

#[derive(DeriveIden)]
enum Agents {
    Table,
    TunnelIngressAddr,
    TunnelListenerAddr,
    TunnelCertSha256,
    TunnelListenerError,
}
