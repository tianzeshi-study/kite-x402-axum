use std::sync::atomic::{AtomicUsize, Ordering};

pub struct ConcurrencyLimiter {
    active_requests: AtomicUsize,
    max_concurrent: usize,
}

impl ConcurrencyLimiter {
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            active_requests: AtomicUsize::new(0),
            max_concurrent,
        }
    }

    pub fn try_acquire(&self) -> bool {
        let current = self.active_requests.load(Ordering::Relaxed);
        if current >= self.max_concurrent {
            return false;
        }
        self.active_requests.fetch_add(1, Ordering::Relaxed);
        true
    }

    pub fn release(&self) {
        self.active_requests.fetch_sub(1, Ordering::Relaxed);
    }
}
