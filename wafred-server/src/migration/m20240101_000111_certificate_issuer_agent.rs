//! Bind a managed certificate to the agent that may issue it.
//!
//! The agent-level `acme_issuer` flag decides whether a node may issue at all;
//! this column narrows one certificate to one issuer. When it is set, only that
//! agent receives the certificate's ACME material and only that agent's
//! publication is accepted. A null value keeps the agent-level behaviour, so
//! existing rows and the embedded all-in-one issuer are unchanged.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "ALTER TABLE site_certificates ADD COLUMN acme_issuer_agent_id UUID",
            )
            .await?;
        manager
            .get_connection()
            .execute_unprepared(
                "CREATE INDEX IF NOT EXISTS idx_site_certificates_acme_issuer \
                 ON site_certificates (acme_issuer_agent_id)",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "DROP INDEX IF EXISTS idx_site_certificates_acme_issuer",
            )
            .await?;
        manager
            .get_connection()
            .execute_unprepared(
                "ALTER TABLE site_certificates DROP COLUMN acme_issuer_agent_id",
            )
            .await?;
        Ok(())
    }
}
