//! Adaptive proof-of-work difficulty and per-IP challenge limits.
//!
//! The challenge subsystem has always run a fixed 20-bit proof of work and
//! issued unlimited pages. Both are wrong under a flood: the work is too cheap
//! for a scripted client and the page endpoint is a free amplifier. This
//! migration adds the four per-site knobs that drive the adaptive difficulty
//! (`base_difficulty`, `max_difficulty`) and the per host+IP issuance /
//! verification limits (`issue_limit_per_min`, `verify_limit_per_min`).
//!
//! Every default is the behaviour an existing site already had: difficulty 20
//! for a quiet visitor (adaptive headroom up to 24 is only used under
//! pressure), and limits high enough that ordinary traffic — including
//! visitors behind a shared NAT address — never reaches them.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Difficulty a quiet site issues. Matches the historical fixed value.
const DEFAULT_BASE_DIFFICULTY: i32 = 20;
/// Ceiling adaptive difficulty may raise the work to.
const DEFAULT_MAX_DIFFICULTY: i32 = 24;
/// Challenge pages issued per host+IP per 60-second window.
const DEFAULT_ISSUE_LIMIT_PER_MIN: i32 = 120;
/// Solution submissions accepted per host+IP per 60-second window.
const DEFAULT_VERIFY_LIMIT_PER_MIN: i32 = 300;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ChallengeSettings::Table)
                    .add_column(
                        ColumnDef::new(ChallengeSettings::BaseDifficulty)
                            .integer()
                            .not_null()
                            .default(DEFAULT_BASE_DIFFICULTY),
                    )
                    .add_column(
                        ColumnDef::new(ChallengeSettings::MaxDifficulty)
                            .integer()
                            .not_null()
                            .default(DEFAULT_MAX_DIFFICULTY),
                    )
                    .add_column(
                        ColumnDef::new(ChallengeSettings::IssueLimitPerMin)
                            .integer()
                            .not_null()
                            .default(DEFAULT_ISSUE_LIMIT_PER_MIN),
                    )
                    .add_column(
                        ColumnDef::new(ChallengeSettings::VerifyLimitPerMin)
                            .integer()
                            .not_null()
                            .default(DEFAULT_VERIFY_LIMIT_PER_MIN),
                    )
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ChallengeSettings::Table)
                    .drop_column(ChallengeSettings::VerifyLimitPerMin)
                    .drop_column(ChallengeSettings::IssueLimitPerMin)
                    .drop_column(ChallengeSettings::MaxDifficulty)
                    .drop_column(ChallengeSettings::BaseDifficulty)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum ChallengeSettings {
    Table,
    BaseDifficulty,
    MaxDifficulty,
    IssueLimitPerMin,
    VerifyLimitPerMin,
}
