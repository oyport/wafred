//! Persists the client's autonomous system number on access logs.
//!
//! The agent has always looked the ASN up for geo rules and shipped it in the
//! protocol message (`LogEntry.asn`, field 82), and Elasticsearch documents
//! already carried it, but PostgreSQL dropped it on ingestion — so the traffic
//! pages could not rank networks. The column is nullable and nothing is
//! backfilled: rows written before this migration keep NULL (they simply do
//! not appear in the ranking), and an agent that cannot resolve the address
//! (or a private/reserved one) sends 0, which ingestion stores as NULL.
//!
//! BIGINT rather than INTEGER: AS numbers are unsigned 32-bit and the
//! 32-bit-ASN transition still allows values above `i32::MAX`.
//!
//! The index is `(site_id, timestamp DESC, asn)` restricted to rows that
//! actually carry an ASN. That is exactly the shape of the top-ASN
//! aggregation — filter a site's time window, group by ASN — so PostgreSQL can
//! answer it from the index alone, and legacy/unknown rows stay out of it
//! (they are never counted by the endpoint anyway).

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(AccessLogs::Table)
                    .add_column(
                        ColumnDef::new(AccessLogs::Asn).big_integer().null(),
                    )
                    .to_owned(),
            )
            .await?;

        let conn = manager.get_connection();
        conn.execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_access_logs_asn_site_time \
             ON access_logs (site_id, timestamp DESC, asn) \
             WHERE asn IS NOT NULL",
        )
        .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.execute_unprepared(
            "DROP INDEX IF EXISTS idx_access_logs_asn_site_time",
        )
        .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(AccessLogs::Table)
                    .drop_column(AccessLogs::Asn)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum AccessLogs {
    Table,
    Asn,
}
