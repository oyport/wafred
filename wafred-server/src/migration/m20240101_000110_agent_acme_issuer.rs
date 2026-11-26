//! Mark which agents may run ACME issuance and receive DNS credentials.
//!
//! Every assigned agent used to receive the site's `acme_dns_config` — the
//! Cloudflare/Aliyun/Tencent/Huawei API token — and could start its own ACME
//! order. A consumer-only edge needs the certificate to serve TLS, not the
//! credentials to issue it.
//!
//! The embedded all-in-one issuer registers over loopback, so it is marked
//! here automatically. A deployment whose issuer is a remote agent must mark
//! it explicitly (`PATCH /api/v1/agents/{id}` with `{"acme_issuer": true}`).
//! A single-agent deployment keeps its previous behaviour: that one agent is
//! the issuer, whatever its address.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "ALTER TABLE agents ADD COLUMN acme_issuer BOOLEAN NOT NULL DEFAULT FALSE",
            )
            .await?;
        // The loopback registration is the embedded all-in-one issuer. The
        // single-agent fallback keeps an existing one-node deployment issuing
        // after the upgrade; a control-plane-only deployment with several
        // remote agents has no issuer until one is marked.
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE agents SET acme_issuer = TRUE \
                 WHERE peer_ip IN ('127.0.0.1', '::1', '::ffff:127.0.0.1') \
                    OR (SELECT count(*) FROM agents) = 1",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("ALTER TABLE agents DROP COLUMN acme_issuer")
            .await?;
        Ok(())
    }
}
