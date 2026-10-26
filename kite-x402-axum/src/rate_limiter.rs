//! In-memory token bucket rate limiter for x402 payment APIs.
//!
//! Enforces burst capacity limits and smooth replenishment intervals per IP or payer key.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;

/// Error returned when an operation exceeds the rate limit.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RateLimitError {
    #[error("rate limit exceeded; retry after {retry_after_secs}s")]
    Exceeded { retry_after_secs: u64 },
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

#[derive(Debug)]
struct Inner {
    buckets: HashMap<String, Bucket>,
    capacity: f64,
    refill_rate: f64, // tokens per second
}

/// Thread-safe keyed token bucket rate limiter.
#[derive(Debug, Clone)]
pub struct TokenBucketRateLimiter {
    inner: Arc<Mutex<Inner>>,
}

impl TokenBucketRateLimiter {
    /// Creates a new rate limiter with the specified bucket capacity and refill rate (tokens/sec).
    pub fn new(capacity: u32, refill_rate_per_sec: f64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                buckets: HashMap::new(),
                capacity: capacity as f64,
                refill_rate: refill_rate_per_sec.max(0.001),
            })),
        }
    }

    /// Attempts to consume `tokens` for the specified key.
    pub fn acquire(&self, key: &str, tokens: u32) -> Result<(), RateLimitError> {
        let mut inner = self.inner.lock().expect("rate limiter mutex poisoned");
        let now = Instant::now();
        let cost = tokens as f64;

        let refill_rate = inner.refill_rate;
        let capacity = inner.capacity;

        let bucket = inner.buckets.entry(key.to_string()).or_insert_with(|| Bucket {
            tokens: capacity,
            last_refill: now,
        });

        // Refill tokens according to elapsed time
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * refill_rate).min(capacity);
        bucket.last_refill = now;

        if bucket.tokens >= cost {
            bucket.tokens -= cost;
            Ok(())
        } else {
            let needed = cost - bucket.tokens;
            let wait_secs = (needed / refill_rate).ceil() as u64;
            Err(RateLimitError::Exceeded {
                retry_after_secs: wait_secs.max(1),
            })
        }
    }

    /// Removes inactive buckets that have been idle longer than `max_idle`.
    pub fn cleanup_idle(&self, max_idle: Duration) {
        let mut inner = self.inner.lock().expect("rate limiter mutex poisoned");
        let now = Instant::now();
        inner
            .buckets
            .retain(|_, b| now.duration_since(b.last_refill) < max_idle);
    }

    /// Returns the number of currently tracked rate limit buckets.
    pub fn len(&self) -> usize {
        let inner = self.inner.lock().expect("rate limiter mutex poisoned");
        inner.buckets.len()
    }

    /// Whether any buckets are tracked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
