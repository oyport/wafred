//! Schema smoke test: run every migration, then read every model.
//!
//! A migration and the model it backs are written by hand, in different files,
//! and nothing in the unit suite executes SQL. 0.33.0 shipped with a model that
//! selected `agents.tunnel_listener_error` while its migration never created the
//! column: every query touching the table failed, the console answered 500 and
//! no agent could register. This test is the missing gate — it runs the real
//! migrator against a real PostgreSQL, then issues one query per entity, so a
//! column the migrations never created fails loudly and names the table.
//!
//! It is `#[ignore]`d because it needs a database. Run it against a *throwaway*
//! one (the migrator writes to it):
//!
//! ```text
//! WAFRED_TEST_DB_URL=postgres://wafred:wafred@127.0.0.1:5432/wafred_schema \
//!   cargo test -p wafred-server --test schema_matches_models -- --ignored --nocapture
//! ```
//!
//! `scripts/tunnel-smoke.sh` runs it as part of its setup.

use sea_orm::{Database, EntityTrait, QuerySelect};
use sea_orm_migration::MigratorTrait;
use wafred_server::migration::Migrator;

/// Reads one row from every entity: any column the migrations did not create
/// makes the query fail at prepare time.
macro_rules! probe {
    ($db:expr, $($entity:path),+ $(,)?) => {
        $(
            if let Err(err) = <$entity>::find().limit(1).all($db).await {
                panic!(
                    "{} does not match the migrated schema: {err}",
                    stringify!($entity)
                );
            }
        )+
    };
}

async fn connected() -> sea_orm::DatabaseConnection {
    let url = std::env::var("WAFRED_TEST_DB_URL")
        .expect("set WAFRED_TEST_DB_URL to a throwaway PostgreSQL database");
    let db = Database::connect(&url)
        .await
        .expect("connect to WAFRED_TEST_DB_URL");
    Migrator::up(&db, None).await.expect("run the migrations");
    db
}

#[tokio::test]
#[ignore = "needs WAFRED_TEST_DB_URL pointing at a throwaway PostgreSQL"]
async fn every_model_matches_the_migrated_schema() {
    // One test, not two: a second test would run the migrator concurrently
    // against the same empty database and collide on `seaql_migrations`.
    let db = connected().await;
    probe!(
        &db,
        wafred_server::models::agent_blocked_ip::Entity,
        wafred_server::models::agent_metric::Entity,
        wafred_server::models::agent::Entity,
        wafred_server::models::ai_conversation::Entity,
        wafred_server::models::ai_message::Entity,
        wafred_server::models::ai_setting::Entity,
        wafred_server::models::site_ai_bot_policies::Entity,
        wafred_server::models::site_ai_crawl_settings::Entity,
        wafred_server::models::api_protection_setting::Entity,
        wafred_server::models::control_plane_access_log::Entity,
        wafred_server::models::site_certificates::Entity,
        wafred_server::models::config_backup_target::Entity,
        wafred_server::models::config_backup::Entity,
        wafred_server::models::config_version::Entity,
        wafred_server::models::control_plane_boot::Entity,
        wafred_server::models::control_plane_stop::Entity,
        wafred_server::models::control_plane_certificate::Entity,
        wafred_server::models::host_sample::Entity,
        wafred_server::models::instance_setting::Entity,
        wafred_server::models::login_history::Entity,
        wafred_server::models::mtls_ca::Entity,
        wafred_server::models::mtls_client_certificate::Entity,
        wafred_server::models::notification_channel::Entity,
        wafred_server::models::notification_event::Entity,
        wafred_server::models::oidc_provider::Entity,
        wafred_server::models::passkey_credential::Entity,
        wafred_server::models::passkey_state::Entity,
        wafred_server::models::refresh_token::Entity,
        wafred_server::models::cache_rules::Entity,
        wafred_server::models::rate_limit_rules::Entity,
        wafred_server::models::rule_groups::Entity,
        wafred_server::models::rule::Entity,
        wafred_server::models::access_log::Entity,
        wafred_server::models::security_event::Entity,
        wafred_server::models::site_visitor::Entity,
        wafred_server::models::site_routes::Entity,
        wafred_server::models::site_ssl::Entity,
        wafred_server::models::site_upstream_pools::Entity,
        wafred_server::models::site_upstreams::Entity,
        wafred_server::models::site::Entity,
        wafred_server::models::tunnel_connector::Entity,
        wafred_server::models::tunnel_session::Entity,
        wafred_server::models::tunnel_setting::Entity,
        wafred_server::models::api_key::Entity,
        wafred_server::models::user::Entity,
        wafred_server::models::visitor_auth_state::Entity,
        wafred_server::models::visitor_passkey_state::Entity,
        wafred_server::models::visitor_passkey::Entity,
        wafred_server::models::visitor_site_grant::Entity,
    );

    // The specific regression 0.33.0 shipped: a model column no migration
    // created. Asserted by name so the failure says which column and why.
    use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
    let row = db
        .query_one(Statement::from_string(
            DatabaseBackend::Postgres,
            "SELECT column_name FROM information_schema.columns \
             WHERE table_name = 'agents' AND column_name = 'tunnel_listener_error'"
                .to_string(),
        ))
        .await
        .expect("read information_schema");
    assert!(
        row.is_some(),
        "agents.tunnel_listener_error is missing: the 0.33.0 regression \
         (a model column no migration creates) has come back"
    );
}
