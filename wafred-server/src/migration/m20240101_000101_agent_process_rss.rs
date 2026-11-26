//! Record the RSS of the agent process itself, on the node row and per probe
//! sample.
//!
//! The heartbeat's `memory_usage_bytes` is node-wide; operators tuning cache
//! quotas or hunting a leak on a shared box need what the agent process alone
//! holds. The field is the first tri-state counter on the wire: an agent build
//! that predates it reports nothing (`None`), which must stay distinct from a
//! reported zero — so the columns are plain nullable bigints and no backfill is
//! performed. A zero on the wire is also stored as unknown by the writer, since
//! a process holding no bytes is not a real state.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Agents::Table)
                    .add_column(
                        ColumnDef::new(Agents::ProcessRssBytes)
                            .big_integer()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(HostSamples::Table)
                    .add_column(
                        ColumnDef::new(HostSamples::ProcessRssBytes)
                            .big_integer()
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
                    .drop_column(Agents::ProcessRssBytes)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(HostSamples::Table)
                    .drop_column(HostSamples::ProcessRssBytes)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Agents {
    Table,
    ProcessRssBytes,
}

#[derive(DeriveIden)]
enum HostSamples {
    Table,
    ProcessRssBytes,
}
