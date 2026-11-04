use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[derive(Debug, Default)]
pub struct ReadinessProbe {
    rpc_healthy: AtomicBool,
    facilitator_healthy: AtomicBool,
}

impl ReadinessProbe {
    pub fn new() -> Self {
        Self {
            rpc_healthy: AtomicBool::new(true),
            facilitator_healthy: AtomicBool::new(true),
        }
    }

    pub fn set_rpc_status(&self, healthy: bool) {
        self.rpc_healthy.store(healthy, Ordering::Relaxed);
    }

    pub fn set_facilitator_status(&self, healthy: bool) {
        self.facilitator_healthy.store(healthy, Ordering::Relaxed);
    }

    pub fn is_ready(&self) -> bool {
        self.rpc_healthy.load(Ordering::Relaxed) && self.facilitator_healthy.load(Ordering::Relaxed)
    }
}
