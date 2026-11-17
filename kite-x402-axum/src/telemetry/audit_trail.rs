//! Bounded process-local event snapshots; no durability or tamper-evidence guarantee.
use std::collections::VecDeque;
use std::sync::Mutex;

/// One copied audit event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    /// Operator-defined event label.
    pub event_type: String,
    /// Transaction identifier, if relevant to this event.
    pub tx_hash: String,
    /// Caller-supplied event time in milliseconds.
    pub timestamp_ms: u64,
}

/// A bounded FIFO event ring. Zero capacity disables collection.
#[derive(Debug)]
pub struct AuditTrailStore {
    buffer: Mutex<VecDeque<AuditEntry>>,
    capacity: usize,
}

impl AuditTrailStore {
    /// Creates an empty event ring.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: Mutex::new(VecDeque::new()),
            capacity,
        }
    }

    /// Appends a copied event, evicting the oldest when the ring is full.
    pub fn append(
        &self,
        event_type: impl Into<String>,
        tx_hash: impl Into<String>,
        timestamp_ms: u64,
    ) {
        if self.capacity == 0 {
            return;
        }
        if let Ok(mut entries) = self.buffer.lock() {
            if entries.len() >= self.capacity {
                entries.pop_front();
            }
            entries.push_back(AuditEntry {
                event_type: event_type.into(),
                tx_hash: tx_hash.into(),
                timestamp_ms,
            });
        }
    }

    /// Returns an isolated oldest-first snapshot, or no events after lock poisoning.
    #[must_use]
    pub fn snapshot(&self) -> Vec<AuditEntry> {
        self.buffer
            .lock()
            .map(|entries| entries.iter().cloned().collect())
            .unwrap_or_default()
    }
}
