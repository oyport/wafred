//! Per-site path restrictions enforced at the edge.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        db.execute_unprepared(
            "CREATE TABLE IF NOT EXISTS site_path_restrictions (\
                 id uuid PRIMARY KEY, \
                 site_id uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE, \
                 name varchar(120) NOT NULL, \
                 path varchar(512) NOT NULL, \
                 match_type varchar(10) NOT NULL DEFAULT 'prefix', \
                 expression text NOT NULL DEFAULT '', \
                 action varchar(20) NOT NULL DEFAULT 'block', \
                 threshold integer NOT NULL DEFAULT 0, \
                 period_seconds integer NOT NULL DEFAULT 60, \
                 block_duration_seconds integer NOT NULL DEFAULT 60, \
                 schedule_enabled boolean NOT NULL DEFAULT false, \
                 schedule_timezone varchar(64) NOT NULL DEFAULT 'UTC', \
                 schedule_days integer[] NOT NULL DEFAULT '{1,2,3,4,5,6,7}', \
                 schedule_start varchar(5) NOT NULL DEFAULT '00:00', \
                 schedule_end varchar(5) NOT NULL DEFAULT '23:59', \
                 enabled boolean NOT NULL DEFAULT true, \
                 priority integer NOT NULL DEFAULT 100, \
                 created_at timestamptz NOT NULL DEFAULT now(), \
                 updated_at timestamptz NOT NULL DEFAULT now(), \
                 CONSTRAINT ck_site_path_restrictions_match_type \
                     CHECK (match_type IN ('prefix', 'exact', 'wildcard', 'regex')), \
                 CONSTRAINT ck_site_path_restrictions_action \
                     CHECK (action IN ('block', 'basic_auth', 'oidc')), \
                 CONSTRAINT ck_site_path_restrictions_limits \
                     CHECK (threshold >= 0 AND period_seconds BETWEEN 1 AND 86400 \
                            AND block_duration_seconds BETWEEN 0 AND 604800)\
             )",
        )
        .await?;
        db.execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_site_path_restrictions_site_priority \
             ON site_path_restrictions (site_id, priority, id)",
        )
        .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS site_path_restrictions")
            .await?;
        Ok(())
    }
}
