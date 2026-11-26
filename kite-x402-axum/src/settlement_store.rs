//! Durable authorization fencing and settlement journal interface.

use crate::settlement_ledger::{SettlementReconciliation, SettlementRecord};
use async_trait::async_trait;

/// A durable storage operation failed. Details are available to the server logs.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct SettlementStorageError(#[from] pub Box<dyn std::error::Error + Send + Sync>);

/// Shared store used by the payment gate when durable settlement is enabled.
///
/// All mutations must fence by the reservation ID. A stale verification lease
/// must never authorize upstream execution. Execution and settlement states
/// must survive cancellation and process restarts.
#[async_trait]
pub trait SettlementStore: std::fmt::Debug + Send + Sync {
    /// Reserve an authorization identity before verification. `None`
    /// means another request already owns or consumed that identity.
    async fn reserve(
        &self,
        payment: &SettlementReconciliation,
    ) -> Result<Option<i64>, SettlementStorageError>;

    /// Release an unsuccessful reservation, only while still verifying.
    async fn release(&self, id: i64) -> Result<(), SettlementStorageError>;

    /// Record the chain scan anchor and enter protected execution if the lease is valid.
    async fn begin_execution(
        &self,
        id: i64,
        payment: &SettlementReconciliation,
    ) -> Result<bool, SettlementStorageError>;

    /// Record a completed upstream error while retaining the authorization fence.
    async fn upstream_failed(&self, id: i64) -> Result<(), SettlementStorageError>;

    /// Persist the intent before submitting to the facilitator.
    async fn begin_settlement(&self, id: i64) -> Result<(), SettlementStorageError>;

    /// Persist the facilitator outcome while preserving chain-proven outcomes.
    /// Return `false` if a claimed success conflicts with the stored outcome.
    async fn finish_settlement(
        &self,
        id: i64,
        record: &SettlementRecord,
    ) -> Result<bool, SettlementStorageError>;
}
