//! In-memory settlement ledger and reconciliation store for x402 payments.
//!
//! Records confirmed on-chain settlements, transaction hashes, amounts, and
//! payer metadata for post-settlement reconciliation and auditing.

use crate::settlement_store::SettlementStore;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
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
    /// Amount in atomic token units as a base-10 uint256, when known.
    pub amount: Option<String>,
    /// Token contract address.
    pub asset: String,
    /// Network identifier (CAIP-2).
    pub network: String,
    /// Unix timestamp in seconds.
    pub timestamp_secs: u64,
    /// Whether the settlement succeeded.
    pub success: bool,
    /// Failure reason, if the settlement failed.
    pub error_reason: Option<String>,
}

/// 无交易哈希时用于查询 Kite 链上付款的 EIP-3009 授权参数。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReconciliation {
    /// 匹配的付款网络（CAIP-2）。
    pub network: String,
    /// Kite 代币合约地址。
    pub asset: String,
    /// 原授权中的付款地址。
    pub payer: String,
    /// 原授权中的收款地址。
    pub pay_to: String,
    /// 原授权中的原子单位金额，表示为十进制 uint256 字符串。
    pub amount_atomic: String,
    /// 原授权中的 32 字节 nonce。
    pub nonce: String,
}

impl fmt::Debug for SettlementReconciliation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SettlementReconciliation")
            .finish_non_exhaustive()
    }
}

/// Total confirmed volume for one network and token contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementVolume {
    /// Network identifier (CAIP-2).
    pub network: String,
    /// Token contract address.
    pub asset: String,
    /// Exact sum of atomic token units as a base-10 string.
    pub amount_atomic: String,
}

/// Aggregate statistics for the records currently retained in the ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerSummary {
    /// Known successful volume grouped separately by network and asset.
    pub volumes: Vec<SettlementVolume>,
    /// Number of successful settlements.
    pub successful_count: u64,
    /// Number of failed or unconfirmed settlements.
    pub failed_count: u64,
}

/// Parses a positive EVM amount and returns its canonical decimal form.
pub(crate) fn decimal_uint256(value: &str) -> Option<String> {
    let digits = value.trim_start_matches('0');
    if digits.is_empty() || digits.len() > 78 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let amount = digits.parse::<BigUint>().ok()?;
    (amount.bits() <= 256).then(|| digits.to_owned())
}

#[derive(Debug)]
struct Inner {
    records: VecDeque<(SettlementRecord, Option<SettlementReconciliation>)>,
    by_tx: HashMap<(String, String), SettlementRecord>,
    by_payer: HashMap<String, Vec<SettlementRecord>>,
    max_records: usize,
}

fn transaction_key(record: &SettlementRecord) -> Option<(String, String)> {
    let tx = record.tx_hash.trim().to_ascii_lowercase();
    (!tx.is_empty()).then(|| (record.network.clone(), tx))
}

fn payer_key(payer: &str) -> String {
    payer.to_lowercase()
}

impl Inner {
    fn remove_indexes(&mut self, record: &SettlementRecord) {
        if let Some(key) = transaction_key(record) {
            self.by_tx.remove(&key);
        }
        let payer = payer_key(&record.payer);
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
    store: Option<Arc<dyn SettlementStore>>,
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
            store: None,
        }
    }

    /// Enables the durable payment path. The synchronous ledger readers keep
    /// their in-memory semantics; durable readers use the selected backend.
    #[must_use]
    pub fn with_store(mut self, store: Arc<dyn SettlementStore>) -> Self {
        self.store = Some(store);
        self
    }

    pub(crate) fn store(&self) -> Option<&dyn SettlementStore> {
        self.store.as_deref()
    }

    /// Records a settlement attempt or confirmed transaction.
    ///
    /// Nonempty transaction hashes are unique per network while retained.
    /// A failed record can be replaced by a confirmation, but a confirmation
    /// is immutable. Attempts without a transaction hash remain independent.
    pub fn record(&self, record: SettlementRecord) {
        self.record_with_reconciliation(record, None);
    }

    pub(crate) fn record_with_reconciliation(
        &self,
        record: SettlementRecord,
        reconciliation: Option<SettlementReconciliation>,
    ) {
        let mut inner = self.inner.lock().expect("settlement ledger mutex poisoned");

        if let Some(key) = transaction_key(&record) {
            if let Some(previous) = inner.by_tx.get(&key).cloned() {
                if previous.success {
                    return;
                }
                if let Some(index) = inner.records.iter().position(|(item, _)| item == &previous) {
                    inner.records.remove(index);
                }
                inner.remove_indexes(&previous);
            }
        }

        // Enforce capacity limit
        if inner.records.len() >= inner.max_records {
            if let Some((evicted, _)) = inner.records.pop_front() {
                inner.remove_indexes(&evicted);
            }
        }

        let payer = payer_key(&record.payer);
        if let Some(key) = transaction_key(&record) {
            inner.by_tx.insert(key, record.clone());
        }
        inner
            .by_payer
            .entry(payer)
            .or_default()
            .push(record.clone());
        inner.records.push_back((record, reconciliation));
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
            .get(&payer_key(payer))
            .cloned()
            .unwrap_or_default()
    }

    /// Returns summary metrics for retained records, excluding evicted history.
    #[must_use]
    pub fn summary(&self) -> LedgerSummary {
        let inner = self.inner.lock().expect("settlement ledger mutex poisoned");
        let mut totals = BTreeMap::<(String, String), BigUint>::new();
        let mut successful_count = 0;
        let mut failed_count = 0;
        for (record, _) in &inner.records {
            if record.success {
                successful_count += 1;
                if let Some(amount) = record.amount.as_deref().and_then(decimal_uint256) {
                    *totals
                        .entry((record.network.clone(), record.asset.to_ascii_lowercase()))
                        .or_default() += amount.parse::<BigUint>().expect("validated amount");
                }
            } else {
                failed_count += 1;
            }
        }
        LedgerSummary {
            volumes: totals
                .into_iter()
                .map(|((network, asset), amount)| SettlementVolume {
                    network,
                    asset,
                    amount_atomic: amount.to_string(),
                })
                .collect(),
            successful_count,
            failed_count,
        }
    }

    /// Returns up to `limit` of the most recently recorded entries, newest
    /// first. Intended for read-only reconciliation views: a caller can look at
    /// the newest attempts (including ones whose outcome is unknown) without
    /// scanning the whole retained history.
    #[must_use]
    pub fn recent(&self, limit: usize) -> Vec<SettlementRecord> {
        let inner = self.inner.lock().expect("settlement ledger mutex poisoned");
        inner
            .records
            .iter()
            .rev()
            .take(limit)
            .map(|(record, _)| record.clone())
            .collect()
    }

    /// 返回最近的结算记录及可用的对账参数，最新记录排在最前。
    #[must_use]
    pub fn recent_with_reconciliation(
        &self,
        limit: usize,
    ) -> Vec<(SettlementRecord, Option<SettlementReconciliation>)> {
        let inner = self.inner.lock().expect("settlement ledger mutex poisoned");
        inner.records.iter().rev().take(limit).cloned().collect()
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
            amount: Some("7".into()),
            asset: "token".into(),
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
        assert_eq!(ledger.summary().volumes[0].amount_atomic, "7");
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
        assert_eq!(ledger.summary().volumes[0].amount_atomic, "700");
    }

    #[test]
    fn volumes_are_exact_and_partitioned_by_network_and_asset() {
        let ledger = SettlementLedger::default();
        let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        for tx in ["first", "second"] {
            ledger.record(SettlementRecord {
                amount: Some(max.into()),
                asset: "TOKEN".into(),
                ..record(tx, "a", true)
            });
        }
        ledger.record(SettlementRecord {
            asset: "other".into(),
            ..record("third", "a", true)
        });
        ledger.record(record("fourth", "b", true));
        ledger.record(record("failed", "b", false));
        let summary = ledger.summary();
        assert_eq!(summary.successful_count, 4);
        assert_eq!(summary.failed_count, 1);
        assert_eq!(summary.volumes.len(), 3);
        assert_eq!(summary.volumes[0].asset, "other");
        assert_eq!(summary.volumes[1].asset, "token");
        assert_eq!(
            summary.volumes[1].amount_atomic,
            "231584178474632390847141970017375815706539969331281128078915168015826259279870"
        );
        assert_eq!(summary.volumes[2].network, "b");
        assert_eq!(summary.volumes[2].amount_atomic, "7");
    }

    #[test]
    fn eviction_removes_payer_records_with_non_ascii_case() {
        let ledger = SettlementLedger::new(100);
        let old = SettlementRecord {
            payer: "PÄYER".into(),
            ..record("old", "a", true)
        };
        ledger.record(old.clone());
        assert_eq!(ledger.find_by_payer("päyer"), vec![old]);

        for i in 0..100 {
            ledger.record(record(&format!("tx-{i}"), "a", true));
        }

        assert!(ledger.get_by_tx("old").is_none());
        assert!(ledger.find_by_payer("päyer").is_empty());
    }

    #[test]
    fn confirmation_replaces_payer_records_with_non_ascii_case() {
        let ledger = SettlementLedger::new(100);
        let failed = SettlementRecord {
            payer: "PÄYER".into(),
            ..record("tx", "a", false)
        };
        let confirmed = SettlementRecord {
            payer: "päyer".into(),
            success: true,
            ..failed.clone()
        };
        ledger.record(failed);
        ledger.record(confirmed.clone());

        assert_eq!(ledger.find_by_payer("PÄYER"), vec![confirmed]);
    }

    #[test]
    fn recent_returns_newest_first_and_respects_the_limit() {
        let ledger = SettlementLedger::new(100);
        assert!(ledger.recent(10).is_empty(), "a new ledger has no history");
        assert!(ledger.recent(0).is_empty(), "a zero limit returns nothing");

        for i in 0..5 {
            ledger.record(record(&format!("tx-{i}"), "a", true));
        }

        let recent = ledger.recent(2);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].tx_hash, "tx-4");
        assert_eq!(recent[1].tx_hash, "tx-3");

        // Asking for more than retained returns the whole history, still newest first.
        assert_eq!(ledger.recent(usize::MAX).len(), 5);
        assert_eq!(ledger.recent(usize::MAX)[0].tx_hash, "tx-4");
    }

    #[test]
    fn recent_reflects_confirmation_replacing_a_failed_attempt() {
        let ledger = SettlementLedger::new(100);
        ledger.record(record("tx", "a", false));
        ledger.record(record("tx", "a", true));

        let recent = ledger.recent(10);
        assert_eq!(recent.len(), 1, "a confirmation replaces its failed record");
        assert!(recent[0].success);
    }

    #[test]
    fn reconciliation_details_follow_their_attempt_through_eviction() {
        let ledger = SettlementLedger::new(100);
        let unconfirmed = record("", "a", false);
        let first = SettlementReconciliation {
            network: unconfirmed.network.clone(),
            asset: "asset".into(),
            payer: unconfirmed.payer.clone(),
            pay_to: unconfirmed.pay_to.clone(),
            amount_atomic: "7".into(),
            nonce: "first".into(),
        };
        let second = SettlementReconciliation {
            nonce: "second".into(),
            ..first.clone()
        };
        ledger.record_with_reconciliation(unconfirmed.clone(), Some(first.clone()));
        ledger.record_with_reconciliation(unconfirmed.clone(), Some(second.clone()));
        assert_eq!(
            ledger.recent_with_reconciliation(2),
            vec![
                (unconfirmed.clone(), Some(second.clone())),
                (unconfirmed.clone(), Some(first))
            ]
        );

        for i in 0..99 {
            ledger.record(record(&format!("tx-{i}"), "a", true));
        }
        let retained = ledger.recent_with_reconciliation(100);
        assert_eq!(retained.last(), Some(&(unconfirmed, Some(second))));
        assert!(retained[..99].iter().all(|(_, details)| details.is_none()));
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
