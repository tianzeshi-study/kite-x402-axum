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
