use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Supported fiat or foreign currency symbols for conversion to Kite USDC.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CurrencySymbol {
    Usd,
    Eur,
    Gbp,
    Jpy,
    Eth,
    Kite,
}

/// Dynamic currency rate converter to atomic Kite USDC (6 decimals).
#[derive(Debug, Clone)]
pub struct CurrencyConverter {
    // Rates normalized to USD micro-units (e.g., 1 EUR = 1_080_000 micro-USD)
    rates_micros: Arc<RwLock<HashMap<CurrencySymbol, u64>>>,
}

impl CurrencyConverter {
    pub fn new() -> Self {
        let mut map = HashMap::new();
        map.insert(CurrencySymbol::Usd, 1_000_000);       // 1.00 USD
        map.insert(CurrencySymbol::Eur, 1_080_000);       // 1.08 USD
        map.insert(CurrencySymbol::Gbp, 1_280_000);       // 1.28 USD
        map.insert(CurrencySymbol::Jpy, 6_500);           // 0.0065 USD
        map.insert(CurrencySymbol::Eth, 2_600_000_000);   // 2600.00 USD
        map.insert(CurrencySymbol::Kite, 2_500_000);      // 2.50 USD

        Self {
            rates_micros: Arc::new(RwLock::new(map)),
        }
    }

    /// Converts an amount in currency units to atomic Kite USDC units (6 decimals).
    pub fn to_usdc_atomic(&self, currency: &CurrencySymbol, amount: f64) -> u128 {
        let map = self.rates_micros.read().expect("lock poisoned");
        let rate_micros = map.get(currency).copied().unwrap_or(1_000_000);

        let total_micros = (amount * rate_micros as f64).round() as u128;
        total_micros
    }

    /// Updates or adds a currency exchange rate in USD micro-units.
    pub fn set_rate(&self, currency: CurrencySymbol, rate_in_usd_micros: u64) {
        let mut map = self.rates_micros.write().expect("lock poisoned");
        map.insert(currency, rate_in_usd_micros);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_usd_conversion() {
        let converter = CurrencyConverter::new();
        let atomic = converter.to_usdc_atomic(&CurrencySymbol::Usd, 5.0);
        assert_eq!(atomic, 5_000_000); // 5 USDC
    }

    #[test]
    fn test_eur_conversion() {
        let converter = CurrencyConverter::new();
        // 10 EUR @ 1.08 = $10.80 = 10_800_000 atomic units
        let atomic = converter.to_usdc_atomic(&CurrencySymbol::Eur, 10.0);
        assert_eq!(atomic, 10_800_000);
    }

    #[test]
    fn test_rate_update() {
        let converter = CurrencyConverter::new();
        converter.set_rate(CurrencySymbol::Kite, 3_000_000); // $3.00

        let atomic = converter.to_usdc_atomic(&CurrencySymbol::Kite, 2.0);
        assert_eq!(atomic, 6_000_000);
    }
}
