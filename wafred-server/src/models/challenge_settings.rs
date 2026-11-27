//! `challenge_settings` — per-site challenge/CC protection configuration.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize,
)]
#[sea_orm(table_name = "challenge_settings")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    #[sea_orm(unique)]
    pub site_id: Uuid,
    pub enabled: bool,
    pub under_attack_mode: bool,
    pub default_level: String,
    pub clearance_duration_secs: i32,
    pub rate_threshold: i32,
    pub exempt_paths: Vec<String>,
    pub browser_integrity_check: bool,
    pub tls_fingerprint_check: bool,
    /// Proof-of-work difficulty (leading zero bits) a quiet visitor solves.
    pub base_difficulty: i32,
    /// Ceiling the difficulty may rise to under request/failure pressure.
    pub max_difficulty: i32,
    /// Challenge pages issued per host+IP per 60-second window.
    pub issue_limit_per_min: i32,
    /// Solution submissions accepted per host+IP per 60-second window.
    pub verify_limit_per_min: i32,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
