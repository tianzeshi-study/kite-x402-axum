//! In-memory settlement ledger and reconciliation store for x402 payments.
//!
//! Records confirmed on-chain settlements, transaction hashes, amounts, and
//! payer metadata for post-settlement reconciliation and auditing.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

/// An immutable record of an x402 payment settlement event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementRecord {
    /// Transaction hash of the settlement.
    pub tx_hash: String,
    /// Address of the payer.
    pub payer: String,
    /// Address that received the payment.
    pub pay_to: String,
    /// Amount in atomic token units.
    pub amount: u64,
    /// Network identifier (CAIP-2).
    pub network: String,
    /// Unix timestamp in seconds.
    pub timestamp_secs: u64,
    /// Whether the settlement succeeded.
    pub success: bool,
    /// Failure reason, if the settlement failed.
    pub error_reason: Option<String>,
}

/// Aggregate statistics for the records currently retained in the ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerSummary {
    /// Sum of the amounts of all successful settlements.
    pub total_settled_volume: u64,
    /// Number of successful settlements.
    pub successful_count: u64,
    /// Number of failed settlements.
    pub failed_count: u64,
}

#[derive(Debug)]
struct Inner {
    records: VecDeque<SettlementRecord>,
    by_tx: HashMap<(String, String), SettlementRecord>,
    by_payer: HashMap<String, Vec<SettlementRecord>>,
    max_records: usize,
}

fn transaction_key(record: &SettlementRecord) -> Option<(String, String)> {
    let tx = record.tx_hash.trim().to_ascii_lowercase();
    (!tx.is_empty()).then(|| (record.network.clone(), tx))
}

impl Inner {
    fn remove_indexes(&mut self, record: &SettlementRecord) {
        if let Some(key) = transaction_key(record) {
            self.by_tx.remove(&key);
        }
        let payer = record.payer.to_ascii_lowercase();
        if let Some(records) = self.by_payer.get_mut(&payer) {
            if let Some(index) = records.iter().position(|item| item == record) {
                records.remove(index);
            }
            if records.is_empty() {
                self.by_payer.remove(&payer);
            }
        }
    }
}

/// Thread-safe settlement ledger.
#[derive(Debug, Clone)]
pub struct SettlementLedger {
    inner: Arc<Mutex<Inner>>,
}

impl SettlementLedger {
    /// Creates a new ledger with a maximum capacity.
    #[must_use]
    pub fn new(max_records: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                records: VecDeque::new(),
                by_tx: HashMap::new(),
                by_payer: HashMap::new(),
                max_records: max_records.max(100),
            })),
        }
    }

    /// Records a settlement attempt or confirmed transaction.
    ///
    /// Nonempty transaction hashes are unique per network while retained.
    /// A failed record can be replaced by a confirmation, but a confirmation
    /// is immutable. Attempts without a transaction hash remain independent.
    pub fn record(&self, record: SettlementRecord) {
        let mut inner = self.inner.lock().expect("settlement ledger mutex poisoned");

        if let Some(key) = transaction_key(&record) {
            if let Some(previous) = inner.by_tx.get(&key).cloned() {
                if previous.success {
                    return;
                }
                if let Some(index) = inner.records.iter().position(|item| item == &previous) {
                    inner.records.remove(index);
                }
                inner.remove_indexes(&previous);
            }
        }

        // Enforce capacity limit
        if inner.records.len() >= inner.max_records {
            if let Some(evicted) = inner.records.pop_front() {
                inner.remove_indexes(&evicted);
            }
        }

        let payer_key = record.payer.to_lowercase();
        if let Some(key) = transaction_key(&record) {
            inner.by_tx.insert(key, record.clone());
        }
        inner
            .by_payer
            .entry(payer_key)
            .or_default()
            .push(record.clone());
        inner.records.push_back(record);
    }

    /// Retrieves a transaction only when its hash identifies one retained network.
    /// Use [`Self::get_by_network_tx`] when the network is known.
    #[must_use]
    pub fn get_by_tx(&self, tx_hash: &str) -> Option<SettlementRecord> {
        let inner = self.inner.lock().expect("settlement ledger mutex poisoned");
        let tx = tx_hash.trim().to_ascii_lowercase();
        let mut matches = inner.by_tx.iter().filter(|((_, hash), _)| hash == &tx);
        let record = matches.next()?.1.clone();
        matches.next().is_none().then_some(record)
    }

    /// Retrieves a transaction by network and case-insensitive transaction hash.
    #[must_use]
    pub fn get_by_network_tx(&self, network: &str, tx_hash: &str) -> Option<SettlementRecord> {
        let inner = self.inner.lock().expect("settlement ledger mutex poisoned");
        inner
            .by_tx
            .get(&(network.to_owned(), tx_hash.trim().to_ascii_lowercase()))
            .cloned()
    }

    /// Returns all records for a given payer address.
    #[must_use]
    pub fn find_by_payer(&self, payer: &str) -> Vec<SettlementRecord> {
        let inner = self.inner.lock().expect("settlement ledger mutex poisoned");
        inner
            .by_payer
            .get(&payer.to_lowercase())
            .cloned()
            .unwrap_or_default()
    }

    /// Returns summary metrics for retained records, excluding evicted history.
    #[must_use]
    pub fn summary(&self) -> LedgerSummary {
        let inner = self.inner.lock().expect("settlement ledger mutex poisoned");
        inner.records.iter().fold(
            LedgerSummary {
                total_settled_volume: 0,
                successful_count: 0,
                failed_count: 0,
            },
            |mut summary, record| {
                if record.success {
                    summary.successful_count += 1;
                    summary.total_settled_volume =
                        summary.total_settled_volume.saturating_add(record.amount);
                } else {
                    summary.failed_count += 1;
                }
                summary
            },
        )
    }

    /// Number of entries currently stored in the ledger.
    #[must_use]
    pub fn len(&self) -> usize {
        let inner = self.inner.lock().expect("settlement ledger mutex poisoned");
        inner.records.len()
    }

    /// Whether the ledger is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for SettlementLedger {
    fn default() -> Self {
        Self::new(5000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(tx: &str, network: &str, success: bool) -> SettlementRecord {
        SettlementRecord {
            tx_hash: tx.into(),
            payer: "0xAbCd".into(),
            pay_to: "recipient".into(),
            amount: 7,
            network: network.into(),
            timestamp_secs: 1,
            success,
            error_reason: None,
        }
    }

    #[test]
    fn duplicate_confirmations_are_counted_once() {
        let ledger = SettlementLedger::new(100);
        ledger.record(record("0xAB", "eip155:2368", true));
        ledger.record(record("0xab", "eip155:2368", true));
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger.summary().total_settled_volume, 7);
    }

    #[test]
    fn transactions_are_scoped_to_network_and_confirmations_do_not_regress() {
        let ledger = SettlementLedger::new(100);
        ledger.record(record("tx", "a", false));
        ledger.record(record("tx", "a", true));
        ledger.record(record("tx", "a", false));
        ledger.record(record("tx", "b", true));
        assert_eq!(ledger.len(), 2);
        assert_eq!(ledger.summary().successful_count, 2);
        assert_eq!(ledger.summary().failed_count, 0);
        assert!(ledger.get_by_tx("tx").is_none());
        assert!(ledger.get_by_network_tx("a", "TX").unwrap().success);
    }

    #[test]
    fn eviction_removes_normalized_payer_indexes_and_summary() {
        let ledger = SettlementLedger::new(100);
        for i in 0..101 {
            ledger.record(record(&format!("tx-{i}"), "a", true));
        }
        assert_eq!(ledger.len(), 100);
        assert_eq!(ledger.find_by_payer("0xABCD").len(), 100);
        assert!(ledger.get_by_tx("tx-0").is_none());
        assert_eq!(ledger.summary().total_settled_volume, 700);
    }

    #[test]
    fn attempts_without_transaction_hashes_remain_independent() {
        let ledger = SettlementLedger::new(100);
        ledger.record(record("", "a", false));
        ledger.record(record("", "a", false));
        assert_eq!(ledger.len(), 2);
        assert_eq!(ledger.summary().failed_count, 2);
        assert!(ledger.get_by_tx("").is_none());
    }
}
