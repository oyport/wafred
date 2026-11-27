use std::sync::atomic::{AtomicUsize, Ordering};

/// Body-prefix bytes one in-memory log stage may hold.
///
/// The stages — the data plane's pending-access pool and the agent's log
/// queue — are capped at 2048 entries each, but an entry carries up to 64 KiB
/// of body prefix per direction, which at the entry cap is 256 MiB per stage.
/// Each stage therefore also reserves its body bytes against a budget of this
/// size, and an entry whose bodies do not fit is kept without them: the
/// request facts are worth more than the payload. At the default
/// `max_body_log_size` (8 KiB) a full stage needs exactly this much, so the
/// budget only bites once that setting is raised.
pub const LOG_BODY_BUDGET_BYTES: usize = 32 * 1024 * 1024;

/// A byte budget shared by every entry of one log stage.
#[derive(Debug)]
pub struct BodyBudget {
    held: AtomicUsize,
    limit: usize,
}

impl BodyBudget {
    pub const fn new(limit: usize) -> Self {
        Self {
            held: AtomicUsize::new(0),
            limit,
        }
    }

    /// Bytes currently reserved.
    pub fn held(&self) -> usize {
        self.held.load(Ordering::Relaxed)
    }

    /// Reserves `bytes`. Returns false, reserving nothing, when they do not
    /// fit in what is left of the budget.
    pub fn try_reserve(&self, bytes: usize) -> bool {
        let mut held = self.held.load(Ordering::Relaxed);
        loop {
            let Some(total) =
                held.checked_add(bytes).filter(|total| *total <= self.limit)
            else {
                return false;
            };
            match self.held.compare_exchange_weak(
                held,
                total,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(current) => held = current,
            }
        }
    }

    /// Returns `bytes` reserved earlier.
    pub fn release(&self, bytes: usize) {
        self.held.fetch_sub(bytes, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservations_stop_at_the_limit_and_come_back_on_release() {
        let budget = BodyBudget::new(100);
        assert!(budget.try_reserve(60));
        assert!(!budget.try_reserve(41), "41 more would exceed the limit");
        assert_eq!(60, budget.held(), "a refused reservation holds nothing");
        assert!(budget.try_reserve(40));
        assert!(!budget.try_reserve(1));

        budget.release(60);
        assert_eq!(40, budget.held());
        assert!(budget.try_reserve(60));
    }
}
