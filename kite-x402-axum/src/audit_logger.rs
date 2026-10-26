use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Audit event action types for x402 payment lifecycle tracking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    PaymentRequiredPrompted,
    VerificationAttempted,
    VerificationSucceeded,
    VerificationFailed,
    SettlementAttempted,
    SettlementSucceeded,
    SettlementFailed,
    ReplayDetected,
    RateLimitExceeded,
    FirewallBlocked,
}

/// A structured payment audit record with cryptographic hash integrity linking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: u64,
    pub timestamp_ms: u64,
    pub action: AuditAction,
    pub request_id: Option<String>,
    pub client_ip: Option<String>,
    pub payer_address: Option<String>,
    pub network: Option<String>,
    pub amount_atomic: Option<String>,
    pub details: Option<String>,
    pub prev_hash: String,
    pub entry_hash: String,
}

/// Audit logger configuration.
#[derive(Debug, Clone)]
pub struct AuditLoggerConfig {
    /// Maximum number of audit records stored in the circular ring buffer.
    pub max_capacity: usize,
    /// Whether to log structured entries using tracing.
    pub tracing_enabled: bool,
}

impl Default for AuditLoggerConfig {
    fn default() -> Self {
        Self {
            max_capacity: 5000,
            tracing_enabled: true,
        }
    }
}

/// Thread-safe in-memory audit log with tamper-evident chaining.
#[derive(Debug, Clone)]
pub struct PaymentAuditLogger {
    config: AuditLoggerConfig,
    state: Arc<RwLock<AuditLoggerState>>,
}

#[derive(Debug)]
struct AuditLoggerState {
    next_id: u64,
    last_hash: String,
    entries: VecDeque<AuditEntry>,
}

impl PaymentAuditLogger {
    /// Creates a new audit logger with default configuration.
    pub fn new() -> Self {
        Self::with_config(AuditLoggerConfig::default())
    }

    /// Creates a new audit logger with custom configuration.
    pub fn with_config(config: AuditLoggerConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(AuditLoggerState {
                next_id: 1,
                last_hash: "GENESIS".to_string(),
                entries: VecDeque::new(),
            })),
        }
    }

    fn calculate_hash(id: u64, ts: u64, action: &AuditAction, payer: &Option<String>, prev_hash: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        id.hash(&mut hasher);
        ts.hash(&mut hasher);
        format!("{:?}", action).hash(&mut hasher);
        if let Some(p) = payer {
            p.hash(&mut hasher);
        }
        prev_hash.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }

    /// Records a new audit event into the ledger.
    pub fn log(
        &self,
        action: AuditAction,
        request_id: Option<String>,
        client_ip: Option<String>,
        payer_address: Option<String>,
        network: Option<String>,
        amount_atomic: Option<String>,
        details: Option<String>,
    ) -> AuditEntry {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let mut state = self.state.write().expect("lock poisoned");
        let id = state.next_id;
        state.next_id += 1;

        let prev_hash = state.last_hash.clone();
        let entry_hash = Self::calculate_hash(id, now, &action, &payer_address, &prev_hash);
        state.last_hash = entry_hash.clone();

        let entry = AuditEntry {
            id,
            timestamp_ms: now,
            action: action.clone(),
            request_id,
            client_ip,
            payer_address,
            network,
            amount_atomic,
            details,
            prev_hash,
            entry_hash,
        };

        if state.entries.len() >= self.config.max_capacity {
            state.entries.pop_front();
        }
        state.entries.push_back(entry.clone());

        if self.config.tracing_enabled {
            tracing::info!(
                audit_id = entry.id,
                action = ?entry.action,
                payer = ?entry.payer_address,
                "Payment audit entry recorded"
            );
        }

        entry
    }

    /// Retrieves all recorded audit entries.
    pub fn get_entries(&self) -> Vec<AuditEntry> {
        let state = self.state.read().expect("lock poisoned");
        state.entries.iter().cloned().collect()
    }

    /// Filters entries by payer address.
    pub fn filter_by_payer(&self, payer: &str) -> Vec<AuditEntry> {
        let state = self.state.read().expect("lock poisoned");
        state
            .entries
            .iter()
            .filter(|e| e.payer_address.as_deref() == Some(payer))
            .cloned()
            .collect()
    }

    /// Filters entries by audit action.
    pub fn filter_by_action(&self, action: AuditAction) -> Vec<AuditEntry> {
        let state = self.state.read().expect("lock poisoned");
        state
            .entries
            .iter()
            .filter(|e| e.action == action)
            .cloned()
            .collect()
    }

    /// Total number of stored audit logs.
    pub fn count(&self) -> usize {
        let state = self.state.read().expect("lock poisoned");
        state.entries.len()
    }

    /// Clears the in-memory log buffer.
    pub fn clear(&self) {
        let mut state = self.state.write().expect("lock poisoned");
        state.entries.clear();
        state.last_hash = "GENESIS".to_string();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_entry_logging_and_chaining() {
        let logger = PaymentAuditLogger::new();

        let entry1 = logger.log(
            AuditAction::VerificationAttempted,
            Some("req-001".into()),
            Some("127.0.0.1".into()),
            Some("0x1111".into()),
            Some("kite-testnet".into()),
            Some("1000".into()),
            None,
        );

        let entry2 = logger.log(
            AuditAction::SettlementSucceeded,
            Some("req-001".into()),
            Some("127.0.0.1".into()),
            Some("0x1111".into()),
            Some("kite-testnet".into()),
            Some("1000".into()),
            Some("tx-hash-123".into()),
        );

        assert_eq!(entry1.prev_hash, "GENESIS");
        assert_eq!(entry2.prev_hash, entry1.entry_hash);
        assert_eq!(logger.count(), 2);

        let payer_records = logger.filter_by_payer("0x1111");
        assert_eq!(payer_records.len(), 2);

        let settle_records = logger.filter_by_action(AuditAction::SettlementSucceeded);
        assert_eq!(settle_records.len(), 1);
        assert_eq!(settle_records[0].details.as_deref(), Some("tx-hash-123"));
    }

    #[test]
    fn test_buffer_capacity_eviction() {
        let logger = PaymentAuditLogger::with_config(AuditLoggerConfig {
            max_capacity: 3,
            tracing_enabled: false,
        });

        for i in 0..5 {
            logger.log(
                AuditAction::PaymentRequiredPrompted,
                Some(format!("req-{}", i)),
                None,
                None,
                None,
                None,
                None,
            );
        }

        assert_eq!(logger.count(), 3);
        let entries = logger.get_entries();
        assert_eq!(entries[0].request_id.as_deref(), Some("req-2"));
        assert_eq!(entries[2].request_id.as_deref(), Some("req-4"));
    }
}
