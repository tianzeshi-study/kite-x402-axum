// Settlement metrics collector for Prometheus exposition
use std::sync::atomic::{AtomicU64, Ordering};

pub struct SettlementMetricsCollector {
    pub total_settlements: AtomicU64,
    pub successful_settlements: AtomicU64,
    pub rejected_settlements: AtomicU64,
    pub total_settled_micro_gwei: AtomicU64,
}

impl SettlementMetricsCollector {
    pub const fn new() -> Self {
        Self {
            total_settlements: AtomicU64::new(0),
            successful_settlements: AtomicU64::new(0),
            rejected_settlements: AtomicU64::new(0),
            total_settled_micro_gwei: AtomicU64::new(0),
        }
    }

    pub fn record_success(&self, micro_gwei: u64) {
        self.total_settlements.fetch_add(1, Ordering::Relaxed);
        self.successful_settlements.fetch_add(1, Ordering::Relaxed);
        self.total_settled_micro_gwei.fetch_add(micro_gwei, Ordering::Relaxed);
    }

    pub fn record_failure(&self) {
        self.total_settlements.fetch_add(1, Ordering::Relaxed);
        self.rejected_settlements.fetch_add(1, Ordering::Relaxed);
    }

    pub fn render_prometheus(&self) -> String {
        format!(
            "# HELP x402_settlements_total Total number of settlement transactions processed.\n             # TYPE x402_settlements_total counter\n             x402_settlements_total {}\n             # HELP x402_settlements_success_total Total successful settlement transactions.\n             # TYPE x402_settlements_success_total counter\n             x402_settlements_success_total {}\n             # HELP x402_settlements_rejected_total Total rejected settlement transactions.\n             # TYPE x402_settlements_rejected_total counter\n             x402_settlements_rejected_total {}\n             # HELP x402_settled_amount_gwei_total Total micro-gwei value settled.\n             # TYPE x402_settled_amount_gwei_total counter\n             x402_settled_amount_gwei_total {}\n",
            self.total_settlements.load(Ordering::Relaxed),
            self.successful_settlements.load(Ordering::Relaxed),
            self.rejected_settlements.load(Ordering::Relaxed),
            self.total_settled_micro_gwei.load(Ordering::Relaxed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_metrics() {
        let collector = SettlementMetricsCollector::new();
        collector.record_success(500);
        collector.record_failure();

        assert_eq!(collector.total_settlements.load(Ordering::Relaxed), 2);
        assert_eq!(collector.successful_settlements.load(Ordering::Relaxed), 1);
        assert_eq!(collector.rejected_settlements.load(Ordering::Relaxed), 1);
        assert!(collector.render_prometheus().contains("x402_settlements_total 2"));
    }
}
