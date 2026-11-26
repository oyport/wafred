//! Adaptive proof-of-work difficulty.
//!
//! A site has a **base** difficulty (what a normal visitor solves, 20 leading
//! zero bits by default — the value every deployment ran with before this was
//! configurable) and a **max** it may rise to under pressure. Pressure comes
//! from two observable signals only, both of which the edge already has:
//!
//! * failed verifications for the same host+IP (a client that keeps getting the
//!   answer wrong is either scripting it or has a broken page), and
//! * request volume for the same host+IP above the site's rate threshold.
//!
//! The difficulty is derived here, never taken from the client: the page states
//! a difficulty and the edge verifies against the value it recorded when it
//! issued that page (see `PendingChallenge::difficulty`).
//!
//! Decay is what keeps this from being a permanent punishment: one failure step
//! is forgotten per [`DIFFICULTY_DECAY_SECS`] without a new failure, and a
//! successful verification clears the record outright.

/// Difficulty a site gets when nothing is configured: the historical value.
pub const DEFAULT_BASE_DIFFICULTY: u32 = 20;

/// Default ceiling for adaptive difficulty. Four extra leading zero bits is
/// 16x the work — enough to price out a scripted flood without making a
/// browser wait long.
pub const DEFAULT_MAX_DIFFICULTY: u32 = 24;

/// Smallest difficulty accepted for either setting. Below this the proof of
/// work is decorative.
pub const MIN_DIFFICULTY: u32 = 4;

/// Hard ceiling accepted for either setting. A browser must still be able to
/// finish the work, so the value is bounded even for an operator who asks for
/// more.
pub const MAX_DIFFICULTY: u32 = 28;

/// One failure step is forgotten per this many seconds without a new failure.
pub const DIFFICULTY_DECAY_SECS: i64 = 60;

/// Request pressure alone adds at most this many steps.
pub const MAX_RATE_STEPS: u32 = 4;

/// A single client cannot accumulate more than this many failure steps.
pub const MAX_FAILURE_STEPS: u32 = 12;

/// Per-key failure record feeding [`AdaptiveDifficulty`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DifficultyState {
    /// Verification failures recorded since the last success.
    pub failures: u32,
    /// Unix seconds of the last recorded failure.
    pub updated_at: i64,
}

/// A site's base/max difficulty pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdaptiveDifficulty {
    base: u32,
    max: u32,
}

impl Default for AdaptiveDifficulty {
    fn default() -> Self {
        Self::new(DEFAULT_BASE_DIFFICULTY, DEFAULT_MAX_DIFFICULTY)
    }
}

impl AdaptiveDifficulty {
    /// Builds the pair, clamping it into `[0, MAX_DIFFICULTY]` and forcing
    /// `max >= base` so a misconfigured pair can never lower difficulty below
    /// the site's base.
    pub fn new(base: u32, max: u32) -> Self {
        let base = base.min(MAX_DIFFICULTY);
        let max = max.clamp(base, MAX_DIFFICULTY);
        Self { base, max }
    }

    /// The difficulty a normal visitor gets.
    pub fn base(self) -> u32 {
        self.base
    }

    /// The ceiling adaptive difficulty may reach.
    pub fn max(self) -> u32 {
        self.max
    }

    /// Difficulty to issue for a challenge right now.
    ///
    /// `request_rate` is the same per-minute counter the challenge decision
    /// used; `rate_threshold` is the site's threshold (a `u32::MAX` threshold
    /// means rate-based challenging is off and contributes no pressure).
    pub fn difficulty(
        self,
        state: DifficultyState,
        now: i64,
        request_rate: u32,
        rate_threshold: u32,
    ) -> u32 {
        let step = decayed_failures(state, now)
            .saturating_add(rate_steps(request_rate, rate_threshold));
        self.base.saturating_add(step).min(self.max)
    }

    /// Records a failed verification for a key, after applying decay.
    pub fn record_failure(
        self,
        state: DifficultyState,
        now: i64,
    ) -> DifficultyState {
        DifficultyState {
            failures: decayed_failures(state, now)
                .saturating_add(1)
                .min(MAX_FAILURE_STEPS),
            updated_at: now,
        }
    }

    /// Records a successful verification: the pressure resets.
    pub fn record_success(&self) -> DifficultyState {
        DifficultyState::default()
    }
}

/// Failures still standing after time decay.
fn decayed_failures(state: DifficultyState, now: i64) -> u32 {
    if state.failures == 0 {
        return 0;
    }
    let idle = now.saturating_sub(state.updated_at).max(0);
    if idle < DIFFICULTY_DECAY_SECS {
        return state.failures;
    }
    let forgotten =
        u32::try_from(idle / DIFFICULTY_DECAY_SECS).unwrap_or(u32::MAX);
    state.failures.saturating_sub(forgotten)
}

/// Extra steps contributed by request pressure.
fn rate_steps(request_rate: u32, rate_threshold: u32) -> u32 {
    if rate_threshold == 0 || rate_threshold == u32::MAX {
        return 0;
    }
    let over = request_rate.saturating_sub(rate_threshold);
    if over == 0 {
        return 0;
    }
    // The first threshold-worth above the limit is one step, the next
    // threshold-worth another, and so on — capped so the ceiling is reached
    // at a bounded multiple of the threshold instead of never.
    (1 + (over - 1) / rate_threshold).min(MAX_RATE_STEPS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_quiet_site_issues_its_base_difficulty() {
        let adaptive = AdaptiveDifficulty::new(20, 24);
        assert_eq!(
            20,
            adaptive.difficulty(DifficultyState::default(), 0, 0, 100)
        );
        // Requests below the threshold are not pressure.
        assert_eq!(
            20,
            adaptive.difficulty(DifficultyState::default(), 0, 100, 100)
        );
    }

    #[test]
    fn failures_raise_difficulty_up_to_the_maximum() {
        let adaptive = AdaptiveDifficulty::new(20, 24);
        let mut state = DifficultyState::default();
        let mut seen = Vec::new();
        for _ in 0..8 {
            state = adaptive.record_failure(state, 0);
            seen.push(adaptive.difficulty(state, 0, 0, 100));
        }
        assert_eq!(vec![21, 22, 23, 24, 24, 24, 24, 24], seen);
    }

    #[test]
    fn request_pressure_adds_steps_and_is_capped() {
        let adaptive = AdaptiveDifficulty::new(20, 30);
        // threshold 10: 11 requests is one step, 30 is two.
        assert_eq!(
            21,
            adaptive.difficulty(DifficultyState::default(), 0, 11, 10)
        );
        assert_eq!(
            22,
            adaptive.difficulty(DifficultyState::default(), 0, 30, 10)
        );
        // Far above the threshold the boost stops at MAX_RATE_STEPS.
        assert_eq!(
            20 + MAX_RATE_STEPS,
            adaptive.difficulty(DifficultyState::default(), 0, 100_000, 10)
        );
        // A disabled rate threshold contributes nothing.
        assert_eq!(
            20,
            adaptive.difficulty(DifficultyState::default(), 0, 100_000, 0)
        );
        assert_eq!(
            20,
            adaptive.difficulty(
                DifficultyState::default(),
                0,
                100_000,
                u32::MAX
            )
        );
    }

    #[test]
    fn failure_steps_decay_over_time() {
        let adaptive = AdaptiveDifficulty::new(20, 30);
        let state = DifficultyState {
            failures: 3,
            updated_at: 1_000,
        };
        assert_eq!(23, adaptive.difficulty(state, 1_000, 0, 100));
        // One minute: one step forgotten.
        assert_eq!(22, adaptive.difficulty(state, 1_060, 0, 100));
        assert_eq!(21, adaptive.difficulty(state, 1_120, 0, 100));
        // Fully decayed back to the base.
        assert_eq!(20, adaptive.difficulty(state, 1_180, 0, 100));
        assert_eq!(20, adaptive.difficulty(state, 9_999, 0, 100));
    }

    #[test]
    fn a_success_resets_the_pressure() {
        let adaptive = AdaptiveDifficulty::new(20, 24);
        let state = adaptive.record_failure(DifficultyState::default(), 0);
        let state = adaptive.record_failure(state, 0);
        assert_eq!(22, adaptive.difficulty(state, 0, 0, 100));
        let state = adaptive.record_success();
        assert_eq!(DifficultyState::default(), state);
        assert_eq!(20, adaptive.difficulty(state, 0, 0, 100));
    }

    #[test]
    fn a_failure_after_decay_restarts_from_the_decayed_value() {
        let adaptive = AdaptiveDifficulty::new(20, 30);
        let state = DifficultyState {
            failures: 4,
            updated_at: 0,
        };
        // Two minutes later two steps are forgotten, then the new failure
        // counts: 4 - 2 + 1 = 3.
        let state = adaptive.record_failure(state, 120);
        assert_eq!(3, state.failures);
        assert_eq!(120, state.updated_at);
        assert_eq!(23, adaptive.difficulty(state, 120, 0, 100));
    }

    #[test]
    fn stored_failures_are_bounded() {
        let adaptive = AdaptiveDifficulty::new(20, 28);
        let mut state = DifficultyState::default();
        for _ in 0..100 {
            state = adaptive.record_failure(state, 0);
        }
        assert_eq!(MAX_FAILURE_STEPS, state.failures);
    }

    #[test]
    fn a_max_below_the_base_is_raised_to_the_base() {
        let adaptive = AdaptiveDifficulty::new(22, 20);
        assert_eq!(22, adaptive.base());
        assert_eq!(22, adaptive.max());
        assert_eq!(
            22,
            adaptive.difficulty(DifficultyState::default(), 0, 0, 0)
        );
    }

    #[test]
    fn settings_are_clamped_to_the_supported_range() {
        let adaptive = AdaptiveDifficulty::new(0, 99);
        assert_eq!(0, adaptive.base());
        assert_eq!(MAX_DIFFICULTY, adaptive.max());
        assert_eq!(
            MAX_DIFFICULTY,
            adaptive.difficulty(
                DifficultyState {
                    failures: 100,
                    updated_at: 0,
                },
                0,
                0,
                0
            )
        );
        // The documented default is what an unconfigured site runs with.
        assert_eq!(
            DEFAULT_BASE_DIFFICULTY,
            AdaptiveDifficulty::default().base()
        );
        assert_eq!(DEFAULT_MAX_DIFFICULTY, AdaptiveDifficulty::default().max());
    }
}
