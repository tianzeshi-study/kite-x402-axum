//! In-memory atomic telemetry and performance metrics collector for x402 payments.
//!
//! Tracks request volumes, 402 challenge issuances, signature verification results,
//! settlement outcomes, and settlement latency without locks on the fast path.

use serde::{Deserialize, Serialize};
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

/// High-performance thread-safe collector for x402 payment lifecycle events.
#[derive(Debug, Default)]
pub struct PaymentMetrics {
    requests_total: AtomicU64,
    challenges_total: AtomicU64,
    verifications_success: AtomicU64,
    verifications_failed: AtomicU64,
    settlements_success: AtomicU64,
    settlements_failed: AtomicU64,
    total_settlement_latency_ms: AtomicU64,
}

/// Point-in-time snapshot of x402 payment statistics, serializable to JSON.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PaymentMetricsSnapshot {
    /// Total requests seen by the middleware.
    pub requests_total: u64,
    /// Total `402 Payment Required` challenges issued.
    pub challenges_total: u64,
    /// Payments successfully verified.
    pub verifications_success: u64,
    /// Payments that failed verification.
    pub verifications_failed: u64,
    /// Payments successfully settled.
    pub settlements_success: u64,
    /// Settlement attempts that failed.
    pub settlements_failed: u64,
    /// Cumulative settlement latency in milliseconds.
    pub total_settlement_latency_ms: u64,
    /// Mean settlement latency in milliseconds.
    pub avg_settlement_latency_ms: f64,
    /// Fraction of settlements that succeeded, in `0.0..=1.0`.
    pub settlement_success_rate: f64,
}

impl PaymentMetrics {
    /// Creates a new metrics collector with zeroed counters.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an incoming request to an x402-protected route.
    pub fn record_request(&self) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a 402 challenge response sent to a client.
    pub fn record_challenge(&self) {
        self.challenges_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Records facilitator signature verification outcome.
    pub fn record_verification(&self, success: bool) {
        if success {
            self.verifications_success.fetch_add(1, Ordering::Relaxed);
        } else {
            self.verifications_failed.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Records facilitator settlement outcome and execution latency.
    pub fn record_settlement(&self, success: bool, latency: Duration) {
        if success {
            self.settlements_success.fetch_add(1, Ordering::Relaxed);
        } else {
            self.settlements_failed.fetch_add(1, Ordering::Relaxed);
        }
        self.total_settlement_latency_ms
            .fetch_add(latency.as_millis() as u64, Ordering::Relaxed);
    }

    /// Captures a point-in-time snapshot with calculated rates.
    pub fn snapshot(&self) -> PaymentMetricsSnapshot {
        let requests_total = self.requests_total.load(Ordering::Relaxed);
        let challenges_total = self.challenges_total.load(Ordering::Relaxed);
        let verifications_success = self.verifications_success.load(Ordering::Relaxed);
        let verifications_failed = self.verifications_failed.load(Ordering::Relaxed);
        let settlements_success = self.settlements_success.load(Ordering::Relaxed);
        let settlements_failed = self.settlements_failed.load(Ordering::Relaxed);
        let total_settlement_latency_ms = self.total_settlement_latency_ms.load(Ordering::Relaxed);

        let total_settlements = settlements_success + settlements_failed;
        let avg_settlement_latency_ms = if total_settlements > 0 {
            total_settlement_latency_ms as f64 / total_settlements as f64
        } else {
            0.0
        };

        let settlement_success_rate = if total_settlements > 0 {
            settlements_success as f64 / total_settlements as f64
        } else {
            1.0
        };

        PaymentMetricsSnapshot {
            requests_total,
            challenges_total,
            verifications_success,
            verifications_failed,
            settlements_success,
            settlements_failed,
            total_settlement_latency_ms,
            avg_settlement_latency_ms,
            settlement_success_rate,
        }
    }

    /// Resets all counters to zero.
    pub fn reset(&self) {
        self.requests_total.store(0, Ordering::Relaxed);
        self.challenges_total.store(0, Ordering::Relaxed);
        self.verifications_success.store(0, Ordering::Relaxed);
        self.verifications_failed.store(0, Ordering::Relaxed);
        self.settlements_success.store(0, Ordering::Relaxed);
        self.settlements_failed.store(0, Ordering::Relaxed);
        self.total_settlement_latency_ms.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_initial_state() {
        let metrics = PaymentMetrics::new();
        let snap = metrics.snapshot();
        assert_eq!(snap.requests_total, 0);
        assert_eq!(snap.challenges_total, 0);
        assert_eq!(snap.settlements_success, 0);
        assert_eq!(snap.settlements_failed, 0);
        assert_eq!(snap.avg_settlement_latency_ms, 0.0);
        assert_eq!(snap.settlement_success_rate, 1.0);
    }

    #[test]
    fn metrics_record_and_snapshot() {
        let metrics = PaymentMetrics::new();
        metrics.record_request();
        metrics.record_challenge();
        metrics.record_verification(true);
        metrics.record_settlement(true, Duration::from_millis(50));
        metrics.record_settlement(false, Duration::from_millis(150));

        let snap = metrics.snapshot();
        assert_eq!(snap.requests_total, 1);
        assert_eq!(snap.challenges_total, 1);
        assert_eq!(snap.verifications_success, 1);
        assert_eq!(snap.settlements_success, 1);
        assert_eq!(snap.settlements_failed, 1);
        assert_eq!(snap.total_settlement_latency_ms, 200);
        assert_eq!(snap.avg_settlement_latency_ms, 100.0);
        assert_eq!(snap.settlement_success_rate, 0.5);
    }

    #[test]
    fn metrics_reset() {
        let metrics = PaymentMetrics::new();
        metrics.record_request();
        metrics.record_settlement(true, Duration::from_millis(100));
        assert_eq!(metrics.snapshot().requests_total, 1);

        metrics.reset();
        let snap = metrics.snapshot();
        assert_eq!(snap.requests_total, 0);
        assert_eq!(snap.settlements_success, 0);
        assert_eq!(snap.total_settlement_latency_ms, 0);
    }
}
