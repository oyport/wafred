//! Whether site OIDC protects the whole site or only matched path restrictions.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "ALTER TABLE site_oidc ADD COLUMN IF NOT EXISTS \
                 auth_scope varchar(16) NOT NULL DEFAULT 'site'",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "ALTER TABLE site_oidc DROP COLUMN IF EXISTS auth_scope",
            )
            .await?;
        Ok(())
    }
}
