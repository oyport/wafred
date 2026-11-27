//! Flag sites that enable HTTPS with no certificate source at all.
//!
//! Every site created before the control plane issued self-signed leaves has
//! `https_enabled = true` and nothing to serve with it: the data plane binds
//! 443, pushes no certificate, and every handshake fails with an OpenSSL
//! signature-algorithm error. Those rows are exactly the ones that cannot
//! serve HTTPS today, so flagging them as self-signed is what lets the startup
//! reconcile issue a leaf for them.
//!
//! Rows that asked for ACME (`acme_email`), carry their own PEM, or select a
//! certificate are left untouched: they have a source, and overwriting it
//! would be a silent configuration change.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Only rows that are provably unable to complete a handshake: HTTPS on, no
/// inline PEM, no selected certificate and no ACME order.
const BACKFILL_SQL: &str = "UPDATE site_ssl SET self_signed = TRUE \
     WHERE https_enabled = TRUE \
       AND self_signed = FALSE \
       AND (cert_pem IS NULL OR btrim(cert_pem) = '') \
       AND (key_pem IS NULL OR btrim(key_pem) = '') \
       AND certificate_id IS NULL \
       AND (acme_email IS NULL OR btrim(acme_email) = '')";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(BACKFILL_SQL)
            .await?;
        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // A data backfill cannot be undone selectively: by the time this runs
        // the reconcile has written a certificate for exactly these rows, and
        // nothing records which ones were flipped here rather than by an
        // operator. Leaving the flag set is the honest state.
        Ok(())
    }
}
