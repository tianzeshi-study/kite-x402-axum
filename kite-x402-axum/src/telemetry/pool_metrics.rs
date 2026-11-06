//! Process-local counters and an asynchronous drain check.
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// Connection-pool counters updated by the caller.
#[derive(Debug, Default)]
pub struct PoolMetrics {
    /// Active connections.
    pub active_connections: AtomicUsize,
    /// Idle connections.
    pub idle_connections: AtomicUsize,
    /// Number of queued waiters.
    pub wait_queue_depth: AtomicUsize,
}

impl PoolMetrics {
    /// Creates zeroed counters.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Increments active connections.
    pub fn inc_active(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }
    /// Decrements active connections without wrapping an empty counter.
    pub fn dec_active(&self) {
        let _ =
            self.active_connections
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    Some(value.saturating_sub(1))
                });
    }
    /// Returns active, idle and queued counts.
    #[must_use]
    pub fn snapshot(&self) -> (usize, usize, usize) {
        (
            self.active_connections.load(Ordering::Relaxed),
            self.idle_connections.load(Ordering::Relaxed),
            self.wait_queue_depth.load(Ordering::Relaxed),
        )
    }
    /// Waits until active connections reach zero, or returns false at the deadline.
    pub async fn wait_for_drain(&self, timeout: Duration) -> bool {
        let start = std::time::Instant::now();
        while self.active_connections.load(Ordering::Relaxed) > 0 {
            let Some(remaining) = timeout.checked_sub(start.elapsed()) else {
                return false;
            };
            if remaining.is_zero() {
                return false;
            }
            tokio::time::sleep(remaining.min(Duration::from_millis(50))).await;
        }
        true
    }
}
