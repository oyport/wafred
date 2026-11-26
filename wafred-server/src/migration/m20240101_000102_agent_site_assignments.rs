//! Per-agent site assignments.
//!
//! Historically an agent either served one site (`agents.site_id`) or every
//! site owned by its API key. The latter is what makes a multi-tenant edge
//! carry every tenant's rule bundle, so this adds an explicit scope and a
//! join table: `all` keeps the legacy behaviour, `selected` narrows the
//! agent to the rows in `agent_sites` (which may be empty for an idle node).

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
                        ColumnDef::new(Agents::SiteScope)
                            .string_len(16)
                            .not_null()
                            .default("all"),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(AgentSites::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(AgentSites::AgentId).uuid().not_null())
                    .col(ColumnDef::new(AgentSites::SiteId).uuid().not_null())
                    .col(
                        ColumnDef::new(AgentSites::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .primary_key(
                        Index::create()
                            .name("pk_agent_sites")
                            .col(AgentSites::AgentId)
                            .col(AgentSites::SiteId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_agent_sites_agent")
                            .from(AgentSites::Table, AgentSites::AgentId)
                            .to(Agents::Table, Agents::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_agent_sites_site")
                            .from(AgentSites::Table, AgentSites::SiteId)
                            .to(Sites::Table, Sites::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_agent_sites_site")
                    .table(AgentSites::Table)
                    .col(AgentSites::SiteId)
                    .to_owned(),
            )
            .await?;

        // Preserve an existing single-site binding as a selected assignment:
        // `site_id` predates the scope column, and an agent that was bound to
        // one site must not silently start serving all of its owner's sites.
        let conn = manager.get_connection();
        conn.execute_unprepared(
            "INSERT INTO agent_sites (agent_id, site_id, created_at) \
             SELECT id, site_id, CURRENT_TIMESTAMP FROM agents \
             WHERE site_id IS NOT NULL",
        )
        .await?;
        conn.execute_unprepared(
            "UPDATE agents SET site_scope = 'selected' \
             WHERE site_id IS NOT NULL",
        )
        .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(AgentSites::Table).to_owned())
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Agents::Table)
                    .drop_column(Agents::SiteScope)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Agents {
    Table,
    Id,
    SiteScope,
}

#[derive(DeriveIden)]
enum Sites {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum AgentSites {
    Table,
    AgentId,
    SiteId,
    CreatedAt,
}
