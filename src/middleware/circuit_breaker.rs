// Modular Circuit Breaker pattern implementation for Axum RPC calls
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct CircuitBreaker {
    failure_threshold: u32,
    cooldown_seconds: u64,
    consecutive_failures: AtomicU32,
    last_failure_time: AtomicU64,
}

impl CircuitBreaker {
    pub const fn new(failure_threshold: u32, cooldown_seconds: u64) -> Self {
        Self {
            failure_threshold,
            cooldown_seconds,
            consecutive_failures: AtomicU32::new(0),
            last_failure_time: AtomicU64::new(0),
        }
    }

    pub fn allow_request(&self) -> bool {
        let failures = self.consecutive_failures.load(Ordering::Relaxed);
        if failures < self.failure_threshold {
            return true;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let last = self.last_failure_time.load(Ordering::Relaxed);

        now.saturating_sub(last) > self.cooldown_seconds
    }

    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
    }

    pub fn record_failure(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
        self.last_failure_time.store(now, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_trips() {
        let cb = CircuitBreaker::new(3, 10);
        assert!(cb.allow_request());
        cb.record_failure();
        cb.record_failure();
        assert!(cb.allow_request());
        cb.record_failure();
        assert!(!cb.allow_request());
        cb.record_success();
        assert!(cb.allow_request());
    }
}
