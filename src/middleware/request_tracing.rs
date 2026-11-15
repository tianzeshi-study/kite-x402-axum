// Distributed request correlation tracing helper
use std::sync::atomic::{AtomicU64, Ordering};

static TRACE_COUNTER: AtomicU64 = AtomicU64::new(1);

pub struct CorrelationTracer;

impl CorrelationTracer {
    pub fn generate_trace_id(prefix: &str) -> String {
        let id = TRACE_COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("{}-{:08x}", prefix, id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_id_generation() {
        let t1 = CorrelationTracer::generate_trace_id("req");
        let t2 = CorrelationTracer::generate_trace_id("req");
        assert_ne!(t1, t2);
    }
}
