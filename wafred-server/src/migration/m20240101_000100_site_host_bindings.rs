//! Per-host HTTP and HTTPS listener ports.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(SiteHostBindings::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(SiteHostBindings::SiteId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SiteHostBindings::Hostname)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SiteHostBindings::HttpPort)
                            .integer()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(SiteHostBindings::HttpsPort)
                            .integer()
                            .null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(SiteHostBindings::SiteId)
                            .col(SiteHostBindings::Hostname),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_site_host_bindings_site_id")
                            .from(
                                SiteHostBindings::Table,
                                SiteHostBindings::SiteId,
                            )
                            .to(Sites::Table, Sites::Id)
                            .on_update(ForeignKeyAction::Cascade)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        let conn = manager.get_connection();
        conn.execute_unprepared(concat!(
            "INSERT INTO site_host_bindings ",
            "(site_id, hostname, http_port, https_port) ",
            "SELECT id, lower(domain), 80, 443 FROM sites ",
            "UNION ALL ",
            "SELECT sites.id, lower(host.hostname), 80, 443 ",
            "FROM sites CROSS JOIN LATERAL ",
            "unnest(sites.alternate_domains) AS host(hostname) ",
            "WHERE true ",
            "ON CONFLICT (site_id, hostname) DO NOTHING",
        ))
        .await?;
        conn.execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_site_host_bindings_http_port \
             ON site_host_bindings (http_port) WHERE http_port IS NOT NULL",
        )
        .await?;
        conn.execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_site_host_bindings_https_port \
             ON site_host_bindings (https_port) WHERE https_port IS NOT NULL",
        )
        .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.execute_unprepared(
            "DROP INDEX IF EXISTS idx_site_host_bindings_https_port",
        )
        .await?;
        conn.execute_unprepared(
            "DROP INDEX IF EXISTS idx_site_host_bindings_http_port",
        )
        .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(SiteHostBindings::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum SiteHostBindings {
    Table,
    SiteId,
    Hostname,
    HttpPort,
    HttpsPort,
}

#[derive(DeriveIden)]
enum Sites {
    Table,
    Id,
}
