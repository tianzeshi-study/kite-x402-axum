//! Structured JSON audit logger and compliance trace emitter for Kite x402 services.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogRecord {
    pub trace_id: String,
    pub timestamp_ms: u64,
    pub event_type: String,
    pub client_ip: Option<String>,
    pub payer_address: Option<String>,
    pub payment_amount: Option<String>,
    pub network: String,
    pub status: String,
    pub latency_ms: u64,
}

#[derive(Debug, Default)]
pub struct AuditLogger {
    record_count: AtomicU64,
}

impl AuditLogger {
    pub fn new() -> Self {
        Self {
            record_count: AtomicU64::new(0),
        }
    }

    pub fn build_record(
        &self,
        trace_id: impl Into<String>,
        event_type: impl Into<String>,
        payer: Option<String>,
        amount: Option<String>,
        network: impl Into<String>,
        status: impl Into<String>,
        latency_ms: u64,
    ) -> AuditLogRecord {
        self.record_count.fetch_add(1, Ordering::Relaxed);
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        AuditLogRecord {
            trace_id: trace_id.into(),
            timestamp_ms: now_ms,
            event_type: event_type.into(),
            client_ip: None,
            payer_address: payer,
            payment_amount: amount,
            network: network.into(),
            status: status.into(),
            latency_ms,
        }
    }

    pub fn total_emitted(&self) -> u64 {
        self.record_count.load(Ordering::Relaxed)
    }
}
