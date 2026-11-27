//! Marks control-plane-issued dynamic IP blocks so heartbeat reconciliation
//! cannot remove them before the target agent has applied the command.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "ALTER TABLE agent_blocked_ips \
                 ADD COLUMN manual BOOLEAN NOT NULL DEFAULT FALSE",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "ALTER TABLE agent_blocked_ips DROP COLUMN manual",
            )
            .await?;
        Ok(())
    }
}
