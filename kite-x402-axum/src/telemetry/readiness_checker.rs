//! Explicit dependency-health flags, independent of network probing.
use std::sync::atomic::{AtomicBool, Ordering};

/// Reports ready only after both dependency flags are set healthy.
#[derive(Debug, Default)]
pub struct ReadinessProbe {
    rpc_healthy: AtomicBool,
    facilitator_healthy: AtomicBool,
}

impl ReadinessProbe {
    /// Creates a probe with unknown/unhealthy dependencies, matching Default.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Sets the last observed RPC health.
    pub fn set_rpc_status(&self, healthy: bool) {
        self.rpc_healthy.store(healthy, Ordering::Relaxed);
    }
    /// Sets the last observed facilitator health.
    pub fn set_facilitator_status(&self, healthy: bool) {
        self.facilitator_healthy.store(healthy, Ordering::Relaxed);
    }
    /// Returns true when both dependency flags are healthy.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.rpc_healthy.load(Ordering::Relaxed) && self.facilitator_healthy.load(Ordering::Relaxed)
    }
}
