// Thread-safe Token Bucket rate limiter implementation
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct TokenBucketLimiter {
    capacity: u64,
    refill_rate_per_sec: u64,
    tokens: AtomicU64,
    last_refill_timestamp: AtomicU64,
}

impl TokenBucketLimiter {
    pub fn new(capacity: u64, refill_rate_per_sec: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            capacity,
            refill_rate_per_sec,
            tokens: AtomicU64::new(capacity),
            last_refill_timestamp: AtomicU64::new(now),
        }
    }

    pub fn try_acquire(&self, requested: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let last = self.last_refill_timestamp.load(Ordering::Relaxed);
        let elapsed = now.saturating_sub(last);

        if elapsed > 0 {
            let tokens_to_add = elapsed * self.refill_rate_per_sec;
            let current_tokens = self.tokens.load(Ordering::Relaxed);
            let new_tokens = (current_tokens + tokens_to_add).min(self.capacity);
            self.tokens.store(new_tokens, Ordering::Relaxed);
            self.last_refill_timestamp.store(now, Ordering::Relaxed);
        }

        let mut current = self.tokens.load(Ordering::Relaxed);
        while current >= requested {
            match self.tokens.compare_exchange_weak(
                current,
                current - requested,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket_acquire() {
        let bucket = TokenBucketLimiter::new(10, 5);
        assert!(bucket.try_acquire(5));
        assert!(bucket.try_acquire(5));
        assert!(!bucket.try_acquire(1));
    }
}
