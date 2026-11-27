//! Clear ACME DNS provider values the managed API no longer accepts.
//!
//! The dashboard used to offer providers the data plane never implemented
//! (`digitalocean`, `cloudxns`, and a manual DNS-01 entry). Those rows fell
//! back to HTTP-01 at runtime, but the managed API now rejects an unknown
//! provider — which made every later edit of such a certificate fail with a
//! 400 until the value was changed by hand. Route 53 rows that were stored
//! with an HTTP-01 challenge are the same shape: the provider is unused and
//! the new validation refuses to save them.
//!
//! The backfill restores exactly the behaviour the data plane had: drop the
//! provider and its credentials, and move a DNS-01 challenge back to HTTP-01
//! when the provider it named cannot drive DNS-01. Rows already using a
//! supported provider are untouched.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Providers the managed API and the data plane both understand.
const SUPPORTED: &str =
    "'ali','aliyun','cf','cloudflare','tencent','dnspod','huawei','route53'";

fn backfill_sql(table: &str) -> String {
    format!(
        "UPDATE {table} \
         SET acme_dns_provider = NULL, \
             acme_dns_config = NULL, \
             acme_challenge_type = CASE \
                 WHEN lower(btrim(coalesce(acme_challenge_type, ''))) = 'dns-01' \
                  AND lower(btrim(acme_dns_provider)) NOT IN ({SUPPORTED}) \
                 THEN 'http-01' \
                 ELSE acme_challenge_type \
             END \
         WHERE acme_dns_provider IS NOT NULL \
           AND ( \
               lower(btrim(acme_dns_provider)) NOT IN ({SUPPORTED}) \
               OR ( \
                   lower(btrim(acme_dns_provider)) = 'route53' \
                   AND lower(btrim(coalesce(acme_challenge_type, ''))) <> 'dns-01' \
               ) \
           )"
    )
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for table in ["site_certificates", "site_ssl"] {
            manager
                .get_connection()
                .execute_unprepared(&backfill_sql(table))
                .await?;
        }
        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // A data backfill cannot be undone: the original provider string and
        // its credentials were never copied anywhere, and restoring them from
        // the code would invent configuration the operator did not choose.
        Ok(())
    }
}
