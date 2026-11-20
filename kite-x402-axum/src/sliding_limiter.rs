//! Memory-efficient sliding-window rate limiter for Kite x402 payment endpoints.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Configuration for the sliding-window rate limiter.
#[derive(Debug, Clone)]
pub struct SlidingWindowConfig {
    /// Maximum requests allowed per key within the window.
    pub max_requests: usize,
    /// Length of the sliding window.
    pub window_duration: Duration,
}

impl Default for SlidingWindowConfig {
    fn default() -> Self {
        Self {
            max_requests: 60,
            window_duration: Duration::from_secs(60),
        }
    }
}

/// Per-key sliding-window rate limiter.
#[derive(Debug)]
pub struct SlidingWindowLimiter {
    config: SlidingWindowConfig,
    state: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl SlidingWindowLimiter {
    /// Creates a limiter with the given configuration.
    #[must_use]
    pub fn new(config: SlidingWindowConfig) -> Self {
        Self {
            config,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Records a request for `key`; returns the remaining quota, or `Err(retry_after)` if the limit is exceeded.
    pub fn check_and_record(&self, key: &str) -> Result<usize, Duration> {
        // A zero allowance means "reject everything". There is no recorded
        // timestamp to derive a retry hint from, so the whole window is
        // reported. Checking this first also keeps the code below off the
        // empty-window path, where `timestamps.front().unwrap()` would panic.
        if self.config.max_requests == 0 {
            return Err(self.config.window_duration);
        }

        let mut map = self.state.lock().unwrap();
        let now = Instant::now();
        let cutoff = now.checked_sub(self.config.window_duration).unwrap_or(now);

        let timestamps = map.entry(key.to_owned()).or_default();
        while let Some(&first) = timestamps.front() {
            if first < cutoff {
                timestamps.pop_front();
            } else {
                break;
            }
        }

        if timestamps.len() >= self.config.max_requests {
            let earliest = *timestamps.front().unwrap();
            let retry_after = earliest + self.config.window_duration - now;
            return Err(retry_after);
        }

        timestamps.push_back(now);
        Ok(self.config.max_requests - timestamps.len())
    }

    /// Clears all recorded requests for `key`.
    pub fn reset(&self, key: &str) {
        let mut map = self.state.lock().unwrap();
        map.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter(max_requests: usize, window_duration: Duration) -> SlidingWindowLimiter {
        SlidingWindowLimiter::new(SlidingWindowConfig {
            max_requests,
            window_duration,
        })
    }

    #[test]
    fn zero_allowance_rejects_instead_of_panicking() {
        let limiter = limiter(0, Duration::from_secs(30));

        assert_eq!(
            limiter.check_and_record("client-a"),
            Err(Duration::from_secs(30))
        );
        // The window is still empty on the second call: the previous code
        // reached `timestamps.front().unwrap()` and panicked here.
        assert_eq!(
            limiter.check_and_record("client-a"),
            Err(Duration::from_secs(30))
        );
    }

    #[test]
    fn zero_allowance_does_not_retain_keys() {
        let limiter = limiter(0, Duration::from_secs(30));

        for i in 0..100 {
            assert!(limiter.check_and_record(&format!("client-{i}")).is_err());
        }
        assert_eq!(limiter.state.lock().unwrap().len(), 0);
    }

    #[test]
    fn a_usable_allowance_still_counts_down_to_zero() {
        let limiter = limiter(2, Duration::from_secs(30));

        assert_eq!(limiter.check_and_record("client"), Ok(1));
        assert_eq!(limiter.check_and_record("client"), Ok(0));
        assert!(limiter.check_and_record("client").is_err());
    }

    #[test]
    fn quota_is_tracked_per_key() {
        let limiter = limiter(1, Duration::from_secs(30));

        assert_eq!(limiter.check_and_record("a"), Ok(0));
        assert!(limiter.check_and_record("a").is_err());
        assert_eq!(limiter.check_and_record("b"), Ok(0));
    }
}
