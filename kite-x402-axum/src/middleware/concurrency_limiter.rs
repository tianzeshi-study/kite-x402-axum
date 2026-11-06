//! Bounded in-flight permits with automatic release when a request is dropped.

use std::sync::atomic::{AtomicUsize, Ordering};

/// A process-local limit on simultaneously held permits.
#[derive(Debug)]
pub struct ConcurrencyLimiter {
    active_requests: AtomicUsize,
    max_concurrent: usize,
}

/// A unique in-flight permit. Dropping it returns capacity to its limiter.
#[derive(Debug)]
#[must_use = "dropping a permit immediately releases its capacity"]
pub struct ConcurrencyPermit<'a> {
    limiter: &'a ConcurrencyLimiter,
}

impl ConcurrencyLimiter {
    /// Creates a limiter. A zero limit rejects all acquisitions.
    #[must_use]
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            active_requests: AtomicUsize::new(0),
            max_concurrent,
        }
    }

    /// Atomically reserves one slot without ever exceeding the configured limit.
    pub fn try_acquire(&self) -> Option<ConcurrencyPermit<'_>> {
        self.active_requests
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |current| {
                if current < self.max_concurrent {
                    Some(current + 1)
                } else {
                    None
                }
            })
            .ok()
            .map(|_| ConcurrencyPermit { limiter: self })
    }

    /// Returns the number of currently held permits.
    #[must_use]
    pub fn active_requests(&self) -> usize {
        self.active_requests.load(Ordering::Acquire)
    }
}

impl Drop for ConcurrencyPermit<'_> {
    fn drop(&mut self) {
        self.limiter.active_requests.fetch_sub(1, Ordering::Release);
    }
}
