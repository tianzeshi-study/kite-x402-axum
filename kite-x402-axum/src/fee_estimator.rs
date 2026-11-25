use serde::{Deserialize, Serialize};

/// Gas and settlement fee estimates for Kite blockchain transactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeEstimate {
    pub base_price_atomic: u128,
    pub estimated_gas_overhead_atomic: u128,
    pub recommended_buffer_atomic: u128,
    pub total_recommended_atomic: u128,
    pub validity_window_secs: u64,
}

/// Configuration for the fee estimator.
#[derive(Debug, Clone)]
pub struct FeeEstimatorConfig {
    /// Safety margin percentage added to base price (e.g. 5 for 5%).
    pub safety_margin_pct: u32,
    /// Default validity window for authorization signatures in seconds.
    pub default_validity_secs: u64,
}

impl Default for FeeEstimatorConfig {
    fn default() -> Self {
        Self {
            safety_margin_pct: 5,
            default_validity_secs: 300, // 5 minutes
        }
    }
}

/// Estimator that calculates safe settlement amounts and expiration buffer windows.
#[derive(Debug, Clone)]
pub struct PaymentFeeEstimator {
    config: FeeEstimatorConfig,
}

impl PaymentFeeEstimator {
    pub fn new() -> Self {
        Self::with_config(FeeEstimatorConfig::default())
    }

    pub fn with_config(config: FeeEstimatorConfig) -> Self {
        Self { config }
    }

    /// Computes a fee estimate with safety margin buffers.
    pub fn estimate(&self, base_price_atomic: u128) -> FeeEstimate {
        let recommended_buffer_atomic = (base_price_atomic * self.config.safety_margin_pct as u128) / 100;
        let total_recommended_atomic = base_price_atomic + recommended_buffer_atomic;

        FeeEstimate {
            base_price_atomic,
            estimated_gas_overhead_atomic: 0, // Kite facilitator absorbs or covers gas in EIP-3009 transferWithAuthorization
            recommended_buffer_atomic,
            total_recommended_atomic,
            validity_window_secs: self.config.default_validity_secs,
        }
    }

    /// Formats atomic payment units (6 decimals for USDC) into decimal string format.
    pub fn format_usdc_display(amount_atomic: u128) -> String {
        let whole = amount_atomic / 1_000_000;
        let frac = amount_atomic % 1_000_000;
        format!("${}.{:06}", whole, frac)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fee_estimator_margins() {
        let estimator = PaymentFeeEstimator::with_config(FeeEstimatorConfig {
            safety_margin_pct: 10,
            default_validity_secs: 600,
        });

        let estimate = estimator.estimate(1_000_000); // $1.00
        assert_eq!(estimate.base_price_atomic, 1_000_000);
        assert_eq!(estimate.recommended_buffer_atomic, 100_000); // 10%
        assert_eq!(estimate.total_recommended_atomic, 1_100_000);
        assert_eq!(estimate.validity_window_secs, 600);
    }

    #[test]
    fn test_format_display() {
        assert_eq!(PaymentFeeEstimator::format_usdc_display(1_500_000), "$1.500000");
        assert_eq!(PaymentFeeEstimator::format_usdc_display(250), "$0.000250");
    }
}
