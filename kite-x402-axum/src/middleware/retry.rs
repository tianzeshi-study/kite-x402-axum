//! Full-jitter delay calculation. Callers choose whether an operation is safe to retry.
use std::time::Duration;

/// Limits for an opt-in backoff calculation.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Number of calculated retry delays.
    pub max_attempts: u32,
    /// Initial exponential ceiling.
    pub base_delay: Duration,
    /// Maximum returned delay.
    pub max_delay: Duration,
}
impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(3),
        }
    }
}
impl RetryPolicy {
    /// Constructs a delay policy; this does not execute or retry any operation.
    #[must_use]
    pub fn new(max_attempts: u32, base_delay: Duration, max_delay: Duration) -> Self {
        Self {
            max_attempts,
            base_delay,
            max_delay,
        }
    }
    /// Returns full-jitter backoff for a zero-based retry, capped at max_delay.
    #[must_use]
    pub fn calculate_backoff(&self, attempt: u32) -> Duration {
        if attempt >= self.max_attempts {
            return self.max_delay;
        }
        let ceiling = self
            .base_delay
            .saturating_mul(2u32.saturating_pow(attempt))
            .min(self.max_delay);
        let millis = u64::try_from(ceiling.as_millis()).unwrap_or(u64::MAX);
        Duration::from_millis(rand::random_range(0..=millis))
    }
}
