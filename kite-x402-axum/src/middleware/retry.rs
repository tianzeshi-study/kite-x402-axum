use std::time::Duration;
use rand::Rng;

#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub base_delay: Duration,
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
    pub fn new(max_attempts: u32, base_delay: Duration, max_delay: Duration) -> Self {
        Self {
            max_attempts,
            base_delay,
            max_delay,
        }
    }

    /// Computes full-jitter backoff for attempt index (0-based)
    pub fn calculate_backoff(&self, attempt: u32) -> Duration {
        if attempt >= self.max_attempts {
            return self.max_delay;
        }

        let multiplier = 2u64.saturating_pow(attempt);
        let ceiling_millis = (self.base_delay.as_millis() as u64)
            .saturating_mul(multiplier)
            .min(self.max_delay.as_millis() as u64);

        let mut rng = rand::thread_rng();
        let jittered_millis = rng.gen_range(0..=ceiling_millis);

        Duration::from_millis(jittered_millis)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backoff_bounds() {
        let policy = RetryPolicy::default();
        for i in 0..5 {
            let delay = policy.calculate_backoff(i);
            assert!(delay <= policy.max_delay);
        }
    }
}
