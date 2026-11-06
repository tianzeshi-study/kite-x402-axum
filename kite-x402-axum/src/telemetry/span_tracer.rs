//! Local correlation metadata; this is not a tracing exporter.
use std::time::Instant;

/// Metadata and elapsed time for a request.
#[derive(Debug, Clone)]
pub struct RequestSpan {
    /// Caller correlation ID or a locally generated random identifier.
    pub correlation_id: String,
    /// HTTP method label.
    pub method: String,
    /// Request path label.
    pub path: String,
    /// Monotonic start time.
    pub started_at: Instant,
}

impl RequestSpan {
    /// Creates span metadata without recording or transmitting request contents.
    #[must_use]
    pub fn new(
        method: impl Into<String>,
        path: impl Into<String>,
        correlation_id: Option<String>,
    ) -> Self {
        Self {
            correlation_id: correlation_id
                .unwrap_or_else(|| format!("trace-{:016x}", rand::random::<u64>())),
            method: method.into(),
            path: path.into(),
            started_at: Instant::now(),
        }
    }
    /// Returns elapsed milliseconds.
    #[must_use]
    pub fn elapsed_millis(&self) -> u128 {
        self.started_at.elapsed().as_millis()
    }
}
