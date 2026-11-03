use std::time::Instant;

#[derive(Debug, Clone)]
pub struct RequestSpan {
    pub correlation_id: String,
    pub method: String,
    pub path: String,
    pub started_at: Instant,
}

impl RequestSpan {
    pub fn new(method: impl Into<String>, path: impl Into<String>, correlation_id: Option<String>) -> Self {
        let cid = correlation_id.unwrap_or_else(|| {
            format!("trace-{:016x}", rand::random::<u64>())
        });
        Self {
            correlation_id: cid,
            method: method.into(),
            path: path.into(),
            started_at: Instant::now(),
        }
    }

    pub fn elapsed_millis(&self) -> u128 {
        self.started_at.elapsed().as_millis()
    }
}
