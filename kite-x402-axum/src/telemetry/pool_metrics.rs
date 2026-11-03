use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

#[derive(Debug, Default)]
pub struct PoolMetrics {
    pub active_connections: AtomicUsize,
    pub idle_connections: AtomicUsize,
    pub wait_queue_depth: AtomicUsize,
}

impl PoolMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc_active(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_active(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> (usize, usize, usize) {
        (
            self.active_connections.load(Ordering::Relaxed),
            self.idle_connections.load(Ordering::Relaxed),
            self.wait_queue_depth.load(Ordering::Relaxed),
        )
    }

    pub async fn wait_for_drain(&self, timeout: Duration) -> bool {
        let start = std::time::Instant::now();
        while self.active_connections.load(Ordering::Relaxed) > 0 {
            if start.elapsed() >= timeout {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        true
    }
}
