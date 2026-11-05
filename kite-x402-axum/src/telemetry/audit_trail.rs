use std::collections::VecDeque;
use std::sync::Mutex;

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub event_type: String,
    pub tx_hash: String,
    pub timestamp_ms: u64,
}

pub struct AuditTrailStore {
    buffer: Mutex<VecDeque<AuditEntry>>,
    capacity: usize,
}

impl AuditTrailStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
        }
    }

    pub fn append(&self, event_type: impl Into<String>, tx_hash: impl Into<String>, timestamp_ms: u64) {
        if let Ok(mut lock) = self.buffer.lock() {
            if lock.len() >= self.capacity {
                lock.pop_front();
            }
            lock.push_back(AuditEntry {
                event_type: event_type.into(),
                tx_hash: tx_hash.into(),
                timestamp_ms,
            });
        }
    }
}
