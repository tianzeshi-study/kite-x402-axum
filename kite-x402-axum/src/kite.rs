//! Kite network constants and the `$0.001`-style price parser.
//!
//! Only the stablecoin that the Kite facilitator settles for each network is
//! listed here: the payer signs an EIP-3009 `transferWithAuthorization`, so
//! the asset must implement EIP-3009 and the EIP-712 domain (name/version)
//! must match the token contract exactly or the facilitator rejects the
//! signature. This mirrors `kite.ts` / `kite.go` field for field — leave it
//! as is.

use serde_json::{json, Value};
use thiserror::Error;

/// Errors from resolving a `KITE_NETWORK` name or parsing a `PRICE_USD` value.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum KiteError {
    /// `KITE_NETWORK` was set to something other than `mainnet` or `testnet`.
    #[error("unknown KITE_NETWORK {0:?} (want mainnet or testnet)")]
    UnknownNetwork(String),
    /// The price string was not a plain positive decimal (no `$`, no
    /// scientific notation, no sign).
    #[error("price must be a positive decimal, got {0:?}")]
    InvalidPrice(String),
    /// The price had more fractional digits than the asset supports.
    #[error("price {price} has more than {decimals} decimals ({symbol})")]
    TooManyDecimals {
        price: String,
        decimals: u32,
        symbol: &'static str,
    },
    /// The price rounded down to zero smallest units of the asset.
    #[error("price {price} is below one unit of {symbol}")]
    BelowOneUnit { price: String, symbol: &'static str },
}

/// One Kite network the wrapper can charge on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KiteChain {
    /// CAIP-2 network identifier, e.g. `eip155:2366`.
    pub network: &'static str,
    pub rpc_url: &'static str,
    /// Stablecoin contract address.
    pub asset_address: &'static str,
    pub asset_symbol: &'static str,
    pub asset_decimals: u32,
    pub eip712_name: &'static str,
    pub eip712_version: &'static str,
}

/// Kite mainnet: Bridged USDC (USDC.e), 6 decimals.
pub const KITE_MAINNET: KiteChain = KiteChain {
    network: "eip155:2366",
    rpc_url: "https://rpc.gokite.ai",
    asset_address: "0x7aB6f3ed87C42eF0aDb67Ed95090f8bF5240149e",
    asset_symbol: "USDC.e",
    asset_decimals: 6,
    eip712_name: "Bridged USDC (Kite AI)",
    eip712_version: "2",
};

/// Kite testnet: pieUSD test stablecoin, 18 decimals. This is what a Kite
/// Passport agent in sandbox mode pays with.
pub const KITE_TESTNET: KiteChain = KiteChain {
    network: "eip155:2368",
    rpc_url: "https://rpc-testnet.gokite.ai",
    asset_address: "0x38129cf4CE5E183eFF248F42A7D345Bb1B47621A",
    asset_symbol: "pieUSD",
    asset_decimals: 18,
    eip712_name: "pieUSD",
    eip712_version: "1",
};

/// The x402 facilitator that verifies and settles payments on both Kite
/// networks. The x402 SDKs append `/verify`, `/settle` and `/supported`, so
/// the `/v2` prefix must stay in the base URL.
pub const FACILITATOR_URL: &str = "https://facilitator.pieverse.io/v2";

/// Resolves the `KITE_NETWORK` environment value (`""`/`"mainnet"` or
/// `"testnet"`) to a [`KiteChain`].
pub fn kite_chain_by_name(name: &str) -> Result<KiteChain, KiteError> {
    match name.trim() {
        "" | "mainnet" => Ok(KITE_MAINNET),
        "testnet" => Ok(KITE_TESTNET),
        other => Err(KiteError::UnknownNetwork(other.to_string())),
    }
}

/// An asset amount ready to go on the x402 wire: an integer token-unit
/// string plus the `extra` metadata (EIP-712 name/version) the facilitator
/// needs to validate the signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetAmount {
    pub asset: String,
    pub amount: String,
    pub extra: Value,
}

impl KiteChain {
    /// Parses a `"0.001"`-or-`"$0.001"`-style USD price into integer token
    /// units for this chain's stablecoin, pinning the EIP-712 domain the
    /// facilitator expects.
    ///
    /// Does integer string math (no floats) to avoid rounding, exactly like
    /// `kite.ts`'s `kiteMoneyParser` and `kite.go`'s `MoneyParser`: at most
    /// [`KiteChain::asset_decimals`] fractional digits, no scientific
    /// notation, no sign, and the result must be at least one smallest unit
    /// of the asset.
    pub fn parse_price(&self, price_usd: &str) -> Result<AssetAmount, KiteError> {
        let trimmed = price_usd.trim();
        let text = trimmed.strip_prefix('$').unwrap_or(trimmed);

        if !is_plain_positive_decimal(text) {
            return Err(KiteError::InvalidPrice(price_usd.to_string()));
        }

        let (whole, frac) = match text.split_once('.') {
            Some((w, f)) => (w, f),
            None => (text, ""),
        };

        if frac.len() as u32 > self.asset_decimals {
            return Err(KiteError::TooManyDecimals {
                price: text.to_string(),
                decimals: self.asset_decimals,
                symbol: self.asset_symbol,
            });
        }

        let pad = self.asset_decimals as usize - frac.len();
        let mut digits = String::with_capacity(whole.len() + frac.len() + pad);
        digits.push_str(whole);
        digits.push_str(frac);
        digits.extend(std::iter::repeat('0').take(pad));

        let units = digits.trim_start_matches('0');
        let units = if units.is_empty() { "0" } else { units };

        if units == "0" {
            return Err(KiteError::BelowOneUnit {
                price: price_usd.to_string(),
                symbol: self.asset_symbol,
            });
        }

        Ok(AssetAmount {
            asset: self.asset_address.to_string(),
            amount: units.to_string(),
            extra: json!({ "name": self.eip712_name, "version": self.eip712_version }),
        })
    }
}

/// `^\d+(\.\d+)?$` without pulling in the `regex` crate: digits, at most one
/// `.`, no leading `.`, no trailing `.`, no sign, no scientific notation.
fn is_plain_positive_decimal(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut seen_dot = false;
    let mut has_digit = false;
    for (i, c) in s.chars().enumerate() {
        if c == '.' {
            if seen_dot || i == 0 {
                return false;
            }
            seen_dot = true;
        } else if c.is_ascii_digit() {
            has_digit = true;
        } else {
            return false;
        }
    }
    has_digit && !s.ends_with('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_known_networks() {
        assert_eq!(kite_chain_by_name("").unwrap(), KITE_MAINNET);
        assert_eq!(kite_chain_by_name("mainnet").unwrap(), KITE_MAINNET);
        assert_eq!(kite_chain_by_name("testnet").unwrap(), KITE_TESTNET);
    }

    #[test]
    fn rejects_unknown_network() {
        let err = kite_chain_by_name("devnet").unwrap_err();
        assert_eq!(err, KiteError::UnknownNetwork("devnet".to_string()));
    }

    #[test]
    fn parses_mainnet_price_to_six_decimals() {
        let amount = KITE_MAINNET.parse_price("0.001").unwrap();
        assert_eq!(amount.amount, "1000");
        assert_eq!(amount.asset, KITE_MAINNET.asset_address);
        assert_eq!(amount.extra["name"], "Bridged USDC (Kite AI)");
        assert_eq!(amount.extra["version"], "2");
    }

    #[test]
    fn parses_dollar_prefixed_price() {
        let amount = KITE_MAINNET.parse_price("$0.05").unwrap();
        assert_eq!(amount.amount, "50000");
    }

    #[test]
    fn parses_testnet_price_to_eighteen_decimals() {
        let amount = KITE_TESTNET.parse_price("0.001").unwrap();
        assert_eq!(amount.amount, "1000000000000000");
        assert_eq!(amount.extra["name"], "pieUSD");
        assert_eq!(amount.extra["version"], "1");
    }

    #[test]
    fn parses_whole_dollar_amount() {
        let amount = KITE_MAINNET.parse_price("2").unwrap();
        assert_eq!(amount.amount, "2000000");
    }

    #[test]
    fn rejects_too_many_decimals() {
        let err = KITE_MAINNET.parse_price("0.0000001").unwrap_err();
        assert!(matches!(err, KiteError::TooManyDecimals { .. }));
    }

    #[test]
    fn rejects_zero() {
        let err = KITE_MAINNET.parse_price("0").unwrap_err();
        assert!(matches!(err, KiteError::BelowOneUnit { .. }));
    }

    #[test]
    fn rejects_amount_below_one_unit() {
        // 0.0000001 has 7 decimals > 6, so this is TooManyDecimals; use an
        // in-range-but-truncates-to-zero case instead: none exists at
        // exactly 6 decimals since any nonzero 6-decimal fraction is >= 1
        // unit. Zero itself is the below-one-unit case, covered above.
        let err = KITE_MAINNET.parse_price("0.000000").unwrap_err();
        assert!(matches!(err, KiteError::BelowOneUnit { .. }));
    }

    #[test]
    fn rejects_negative_and_malformed_input() {
        for bad in ["-1", "1e10", "abc", "1.2.3", ".5", "5.", ""] {
            assert!(
                KITE_MAINNET.parse_price(bad).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }
}
