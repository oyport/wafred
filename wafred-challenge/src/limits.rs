//! Bounded per-key rate limiting for challenge issuance and verification.
//!
//! The counters are deliberately a plain data structure: no I/O, no globals,
//! and a caller-supplied `now`. Only the edge plugin wires them to a request,
//! which is what makes the behaviour testable without a live proxy.
//!
//! Every table is bounded twice: a key expires with its window, and the table
//! itself has a hard key ceiling. Under a many-source flood the ceiling is
//! what keeps the map from growing with the attacker's address space; what
//! happens when it is reached is the caller's decision, expressed by
//! [`LimitDecision::Saturated`] — issuance may proceed without state (a
//! legitimate visitor must not be locked out because an attacker filled the
//! table) while verification must fail closed.

use std::collections::HashMap;
use std::sync::Mutex;

/// Length of one counting window, in seconds.
pub const LIMIT_WINDOW_SECS: i64 = 60;

/// Default ceiling on tracked keys per limiter. At a 60-second window this is
/// ~136 distinct host+IP keys per second, far above any legitimate site.
pub const DEFAULT_MAX_TRACKED_KEYS: usize = 8192;

/// How many calls between two lazy sweeps of the key table. A full scan on
/// every call would itself be a CPU amplifier under the flood the limiter
/// exists to contain (same reasoning as the pending-challenge sweep).
const PRUNE_INTERVAL: u32 = 64;

/// Outcome of one rate-limit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitDecision {
    /// The attempt is within the limit and was counted.
    Allow,
    /// The key is at or above its limit for the current window.
    Deny,
    /// The table is full of other keys. The caller decides what that means:
    /// issuance continues without state, verification fails closed.
    Saturated,
}

#[derive(Debug, Clone, Copy)]
struct Window {
    count: u32,
    started_at: i64,
}

#[derive(Debug, Default)]
struct LimiterState {
    windows: HashMap<String, Window>,
    ticks: u32,
}

/// A fixed-window (60 s by default) counter per key.
///
/// A fixed window — rather than a sliding one — is the same trade-off the
/// per-IP request counter has always made: two windows' worth of attempts can
/// land back to back, but each window costs one integer per key instead of a
/// timestamp list per key.
#[derive(Debug)]
pub struct FixedWindowLimiter {
    window_secs: i64,
    max_keys: usize,
    state: Mutex<LimiterState>,
}

impl FixedWindowLimiter {
    /// Creates a limiter with a `window_secs` window and at most `max_keys`
    /// tracked keys.
    pub fn new(window_secs: i64, max_keys: usize) -> Self {
        Self {
            window_secs: if window_secs > 0 { window_secs } else { 60 },
            max_keys: if max_keys > 0 { max_keys } else { 1 },
            state: Mutex::new(LimiterState::default()),
        }
    }

    /// Counts one attempt for `key` and reports whether it is allowed.
    ///
    /// A `limit` of zero means "no limit configured" and is always allowed
    /// without touching the table: every caller normalises an unset value to
    /// its documented default before reaching here, so zero can only mean a
    /// deliberate opt-out.
    pub fn allow(&self, key: &str, limit: u32, now: i64) -> LimitDecision {
        if limit == 0 {
            return LimitDecision::Allow;
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.ticks = state.ticks.wrapping_add(1);
        // Lazy sweep: only once the table is half full, and only every
        // `PRUNE_INTERVAL` calls.
        if state.windows.len() >= self.max_keys / 2
            && state.ticks.is_multiple_of(PRUNE_INTERVAL)
        {
            let window = self.window_secs;
            state.windows.retain(|_, entry| {
                now.saturating_sub(entry.started_at) < window
            });
        }

        if let Some(entry) = state.windows.get_mut(key) {
            if now.saturating_sub(entry.started_at) >= self.window_secs {
                *entry = Window {
                    count: 0,
                    started_at: now,
                };
            }
            entry.count = entry.count.saturating_add(1);
            return if entry.count > limit {
                LimitDecision::Deny
            } else {
                LimitDecision::Allow
            };
        }

        if state.windows.len() >= self.max_keys {
            return LimitDecision::Saturated;
        }
        state.windows.insert(
            key.to_string(),
            Window {
                count: 1,
                started_at: now,
            },
        );
        LimitDecision::Allow
    }

    /// Drops every tracked key. Operator reset and test isolation only: the
    /// counters are a burst guard, so forgetting them cannot grant anything
    /// beyond the current window's worth of attempts.
    pub fn clear(&self) {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .windows
            .clear();
    }

    /// Number of keys currently tracked. Test and diagnostics only.
    pub fn tracked(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .windows
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_the_limit_then_denies() {
        let limiter = FixedWindowLimiter::new(LIMIT_WINDOW_SECS, 128);
        for _ in 0..3 {
            assert_eq!(
                limiter.allow("a.example:203.0.113.1", 3, 1_000),
                LimitDecision::Allow
            );
        }
        assert_eq!(
            limiter.allow("a.example:203.0.113.1", 3, 1_000),
            LimitDecision::Deny
        );
    }

    #[test]
    fn limits_are_per_key() {
        let limiter = FixedWindowLimiter::new(LIMIT_WINDOW_SECS, 128);
        assert_eq!(limiter.allow("host-a:1.1.1.1", 1, 0), LimitDecision::Allow);
        assert_eq!(limiter.allow("host-a:1.1.1.1", 1, 0), LimitDecision::Deny);
        // A different host or address has its own budget.
        assert_eq!(limiter.allow("host-a:2.2.2.2", 1, 0), LimitDecision::Allow);
        assert_eq!(limiter.allow("host-b:1.1.1.1", 1, 0), LimitDecision::Allow);
    }

    #[test]
    fn window_resets_after_a_minute() {
        let limiter = FixedWindowLimiter::new(LIMIT_WINDOW_SECS, 128);
        assert_eq!(limiter.allow("k", 1, 1_000), LimitDecision::Allow);
        assert_eq!(limiter.allow("k", 1, 1_030), LimitDecision::Deny);
        assert_eq!(limiter.allow("k", 1, 1_060), LimitDecision::Allow);
        assert_eq!(limiter.allow("k", 1, 1_061), LimitDecision::Deny);
    }

    #[test]
    fn zero_limit_is_unlimited_and_untracked() {
        let limiter = FixedWindowLimiter::new(LIMIT_WINDOW_SECS, 128);
        for _ in 0..10 {
            assert_eq!(limiter.allow("k", 0, 0), LimitDecision::Allow);
        }
        assert_eq!(0, limiter.tracked());
    }

    #[test]
    fn expired_keys_are_pruned_so_the_table_stays_bounded() {
        let limiter = FixedWindowLimiter::new(LIMIT_WINDOW_SECS, 8);
        // Fill the table with keys that all expire.
        for index in 0..8 {
            assert_eq!(
                limiter.allow(&format!("k{index}"), 5, 0),
                LimitDecision::Allow
            );
        }
        assert_eq!(8, limiter.tracked());
        // Long after the window, a sweep runs (the table is over half full and
        // this call is one of the throttled ones) and makes room again.
        let mut admitted = false;
        for tick in 0..PRUNE_INTERVAL * 2 {
            let now = 10_000 + i64::from(tick);
            if limiter.allow("fresh", 5, now) == LimitDecision::Allow {
                admitted = true;
                break;
            }
        }
        assert!(admitted, "pruning must make room for a new key");
        assert!(limiter.tracked() <= 8);
    }

    #[test]
    fn clear_forgets_every_key() {
        let limiter = FixedWindowLimiter::new(LIMIT_WINDOW_SECS, 8);
        assert_eq!(limiter.allow("k1", 1, 0), LimitDecision::Allow);
        assert_eq!(limiter.allow("k1", 1, 0), LimitDecision::Deny);
        limiter.clear();
        assert_eq!(0, limiter.tracked());
        assert_eq!(limiter.allow("k1", 1, 0), LimitDecision::Allow);
    }

    #[test]
    fn a_full_table_reports_saturation_for_an_unknown_key() {
        // No time passes, so nothing expires and the ceiling is reached.
        let limiter = FixedWindowLimiter::new(LIMIT_WINDOW_SECS, 2);
        assert_eq!(limiter.allow("k1", 5, 0), LimitDecision::Allow);
        assert_eq!(limiter.allow("k2", 5, 0), LimitDecision::Allow);
        assert_eq!(limiter.allow("k3", 5, 0), LimitDecision::Saturated);
        // A known key keeps being counted even when the table is full, so an
        // attacker cannot reset its own budget by filling the table.
        assert_eq!(limiter.allow("k1", 1, 0), LimitDecision::Deny);
    }
}
