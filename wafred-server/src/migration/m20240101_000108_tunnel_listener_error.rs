//! Repairs the column 0.33.0 promised but never created.
//!
//! Migration `000106` added the three identity columns an edge reports for its
//! tunnel listener (`tunnel_ingress_addr`, `tunnel_listener_addr`,
//! `tunnel_cert_sha256`) but **not** `tunnel_listener_error`, even though
//! `models/agents.rs` selects it on every query. Every read of the `agents`
//! table therefore failed with
//! `column agents.tunnel_listener_error does not exist`: the console's agent and
//! tunnel pages answered 500, and no agent could register or heartbeat.
//!
//! `000106` is already recorded in every database that ran 0.33.0, so SeaORM
//! will never execute it again — editing it would fix nothing. The column is
//! added here instead, idempotently, so a database repaired by hand with the
//! same `ALTER TABLE` also comes out clean.
//!
//! `down` is deliberately a no-op: rollback order is 107 then 106, and 106's
//! own `down` already drops the column. Dropping it here would make 106 fail
//! with "column does not exist".

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
                    .add_column_if_not_exists(
                        ColumnDef::new(Agents::TunnelListenerError)
                            .text()
                            .null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // See the module doc: 106's `down` owns the column removal.
        Ok(())
    }
}

#[derive(DeriveIden)]
enum Agents {
    Table,
    TunnelListenerError,
}
