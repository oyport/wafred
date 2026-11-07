//! `site_path_restrictions` — per-path block, Basic Auth, and OIDC rules.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
)]
#[sea_orm(table_name = "site_path_restrictions")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub site_id: Uuid,
    pub name: String,
    pub path: String,
    pub match_type: String,
    pub expression: String,
    pub action: String,
    /// 0 blocks immediately; a positive value allows this many requests per client per period.
    pub threshold: i32,
    pub period_seconds: i32,
    pub block_duration_seconds: i32,
    pub schedule_enabled: bool,
    pub schedule_timezone: String,
    pub schedule_days: Vec<i32>,
    pub schedule_start: String,
    pub schedule_end: String,
    pub enabled: bool,
    pub priority: i32,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
