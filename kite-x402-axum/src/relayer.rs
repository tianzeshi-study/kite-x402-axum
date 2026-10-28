use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::{Arc, RwLock};

/// Decision outcome for paymaster sponsorship.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayDecision {
    Approved,
    RejectedAmountExceeded,
    RejectedPayerBlocked,
    RejectedPolicyLimit,
}

/// Configuration for paymaster sponsorship relayer.
#[derive(Debug, Clone)]
pub struct RelayerConfig {
    pub max_sponsored_amount_atomic: u128,
    pub max_daily_relays_per_payer: u32,
    pub blocked_payers: HashSet<String>,
}

impl Default for RelayerConfig {
    fn default() -> Self {
        Self {
            max_sponsored_amount_atomic: 100_000_000, // $100 max
            max_daily_relays_per_payer: 50,
            blocked_payers: HashSet::new(),
        }
    }
}

/// Evaluator that determines whether an authorization can be relayed gasless.
#[derive(Debug, Clone)]
pub struct GaslessRelayer {
    config: RelayerConfig,
    payer_relay_counts: Arc<RwLock<std::collections::HashMap<String, u32>>>,
}

impl GaslessRelayer {
    pub fn new() -> Self {
        Self::with_config(RelayerConfig::default())
    }

    pub fn with_config(config: RelayerConfig) -> Self {
        Self {
            config,
            payer_relay_counts: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Evaluates if a payment payload is eligible for gasless forwarding.
    pub fn evaluate(&self, payer: &str, amount_atomic: u128) -> RelayDecision {
        let payer_lower = payer.to_lowercase();

        if self.config.blocked_payers.contains(&payer_lower) {
            return RelayDecision::RejectedPayerBlocked;
        }

        if amount_atomic > self.config.max_sponsored_amount_atomic {
            return RelayDecision::RejectedAmountExceeded;
        }

        let mut counts = self.payer_relay_counts.write().expect("lock poisoned");
        let count = counts.entry(payer_lower).or_insert(0);
        if *count >= self.config.max_daily_relays_per_payer {
            return RelayDecision::RejectedPolicyLimit;
        }

        *count += 1;
        RelayDecision::Approved
    }

    /// Blocks a payer from receiving future gas sponsorship.
    pub fn block_payer(&mut self, payer: &str) {
        self.config.blocked_payers.insert(payer.to_lowercase());
    }

    /// Clears daily relay counters.
    pub fn reset_counters(&self) {
        let mut counts = self.payer_relay_counts.write().expect("lock poisoned");
        counts.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relayer_evaluation_approval() {
        let relayer = GaslessRelayer::new();
        let decision = relayer.evaluate("0x1234", 1_000_000);
        assert_eq!(decision, RelayDecision::Approved);
    }

    #[test]
    fn test_relayer_max_amount_rejection() {
        let relayer = GaslessRelayer::with_config(RelayerConfig {
            max_sponsored_amount_atomic: 5_000_000,
            ..Default::default()
        });

        let decision = relayer.evaluate("0x1234", 10_000_000);
        assert_eq!(decision, RelayDecision::RejectedAmountExceeded);
    }

    #[test]
    fn test_relayer_quota_limit() {
        let relayer = GaslessRelayer::with_config(RelayerConfig {
            max_daily_relays_per_payer: 2,
            ..Default::default()
        });

        assert_eq!(relayer.evaluate("0xabc", 100), RelayDecision::Approved);
        assert_eq!(relayer.evaluate("0xabc", 100), RelayDecision::Approved);
        assert_eq!(relayer.evaluate("0xabc", 100), RelayDecision::RejectedPolicyLimit);
    }
}
