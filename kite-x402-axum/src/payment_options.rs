//! Multi-option payment requirements: advertise several ways to pay for one
//! resource, then match the client's chosen `accepted` option against them.
//!
//! This module is deliberately **additive**: it does not change
//! [`crate::middleware::PaymentConfig`] or the existing single-option
//! `x402_payment` gate. It provides the data types and the pure matching
//! function needed to let a route accept more than one
//! `(network, asset, amount)` combination — the gap tracked as `TODO.md` item
//! 6. A follow-up can wire `requirements_all()` + `find_matching_requirements`
//! into a multi-option middleware without breaking existing callers.
//!
//! The x402 wire type [`PaymentRequired.accepts`][crate::types::PaymentRequired::accepts]
//! is already a `Vec<PaymentRequirements>`; this module fills that vector with
//! more than one option and supplies the search the current middleware lacks.

use crate::kite::{AssetAmount, KiteChain};
use crate::types::PaymentRequirements;

/// One way to pay for a resource: a Kite network plus a USD price.
///
/// Multiple `PaymentOption`s can be advertised on a single route so a client
/// can choose the network/asset it holds. Prices are parsed with the same
/// integer-only [`KiteChain::parse_price`] the single-option path uses, so
/// there is no floating-point rounding and no behavior drift between the two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentOption {
    /// Kite network this option settles on.
    pub chain: KiteChain,
    /// A `"0.001"`- or `"$0.001"`-style USD price per call.
    pub price_usd: String,
}

impl PaymentOption {
    /// Creates an option for `chain` at `price_usd`.
    pub fn new(chain: KiteChain, price_usd: impl Into<String>) -> Self {
        Self {
            chain,
            price_usd: price_usd.into(),
        }
    }

    /// Renders this option into the on-the-wire `PaymentRequirements` the
    /// client sees in a 402 challenge.
    ///
    /// Returns `Err` with context if the configured price is malformed (same
    /// validation as the single-option path).
    pub fn to_requirements(&self, pay_to: &str) -> Result<PaymentRequirements, String> {
        let asset: AssetAmount = self
            .chain
            .parse_price(&self.price_usd)
            .map_err(|e| format!("invalid PRICE_USD configured for option: {e}"))?;
        Ok(PaymentRequirements {
            scheme: "exact".to_owned(),
            network: self.chain.network.to_owned(),
            amount: asset.amount,
            asset: asset.asset,
            pay_to: pay_to.to_owned(),
            max_timeout_seconds: 60,
            extra: Some(asset.extra),
        })
    }
}

/// Converts every option into its wire representation, preserving order.
///
/// A `pay_to` that receives all options is supplied once. An invalid price in
/// any option fails the whole set — a challenge must never advertise a subset
/// of what it actually accepts.
pub fn requirements_all(
    options: &[PaymentOption],
    pay_to: &str,
) -> Result<Vec<PaymentRequirements>, String> {
    options
        .iter()
        .map(|option| option.to_requirements(pay_to))
        .collect()
}

/// Finds the advertised option the client chose in its `accepted` field.
///
/// Uses the same full-struct equality the current middleware uses
/// (`payload.accepted != requirements`), just applied across a set: a client
/// payment is accepted only if it matches one advertised option exactly. This
/// keeps the single-option behavior identical (a one-element slice is exactly
/// the old `==` check) while enabling a choice when several are advertised.
///
/// Returns `None` when the slice is empty or no option matches; callers should
/// answer `402` with `"No matching payment requirements"` in that case.
#[must_use]
pub fn find_matching_requirements<'a>(
    accepted: &PaymentRequirements,
    options: &'a [PaymentRequirements],
) -> Option<&'a PaymentRequirements> {
    options.iter().find(|candidate| *candidate == accepted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kite::{KITE_MAINNET, KITE_TESTNET};
    use serde_json::json;

    const PAY_TO: &str = "0xPayTo";

    #[test]
    fn option_renders_testnet_requirements() {
        let option = PaymentOption::new(KITE_TESTNET, "0.001");
        let req = option.to_requirements(PAY_TO).unwrap();
        assert_eq!(req.scheme, "exact");
        assert_eq!(req.network, KITE_TESTNET.network);
        assert_eq!(req.asset, KITE_TESTNET.asset_address);
        assert_eq!(req.pay_to, PAY_TO);
        assert_eq!(req.max_timeout_seconds, 60);
        assert!(req.extra.is_some());
    }

    #[test]
    fn option_renders_mainnet_requirements() {
        let option = PaymentOption::new(KITE_MAINNET, "$0.001");
        let req = option.to_requirements(PAY_TO).unwrap();
        assert_eq!(req.network, KITE_MAINNET.network);
        assert_eq!(req.asset, KITE_MAINNET.asset_address);
    }

    #[test]
    fn decimals_are_chain_specific() {
        // 0.001 USDC on mainnet (6 decimals) = 1000 atomic units.
        let main = PaymentOption::new(KITE_MAINNET, "0.001")
            .to_requirements(PAY_TO)
            .unwrap();
        assert_eq!(main.amount, "1000");
        // 0.001 pieUSD on testnet (18 decimals) = 10^15 atomic units.
        let test = PaymentOption::new(KITE_TESTNET, "0.001")
            .to_requirements(PAY_TO)
            .unwrap();
        assert_eq!(test.amount, "1000000000000000");
        assert_ne!(main.amount, test.amount);
    }

    #[test]
    fn invalid_price_in_any_option_fails_the_whole_set() {
        let options = vec![
            PaymentOption::new(KITE_TESTNET, "0.001"),
            PaymentOption::new(KITE_MAINNET, "not-a-price"),
        ];
        let err = requirements_all(&options, PAY_TO).unwrap_err();
        assert!(err.contains("invalid PRICE_USD"), "unexpected: {err}");
    }

    #[test]
    fn requirements_all_preserves_order() {
        let options = vec![
            PaymentOption::new(KITE_TESTNET, "0.001"),
            PaymentOption::new(KITE_MAINNET, "$1.50"),
        ];
        let all = requirements_all(&options, PAY_TO).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].network, KITE_TESTNET.network);
        assert_eq!(all[1].network, KITE_MAINNET.network);
    }

    fn accepted_for(req: &PaymentRequirements) -> PaymentRequirements {
        req.clone()
    }

    #[test]
    fn matches_the_first_of_several_options() {
        let all = requirements_all(
            &[
                PaymentOption::new(KITE_TESTNET, "0.001"),
                PaymentOption::new(KITE_MAINNET, "$1.50"),
            ],
            PAY_TO,
        )
        .unwrap();
        let chosen = accepted_for(&all[0]);
        let matched = find_matching_requirements(&chosen, &all).unwrap();
        assert_eq!(matched, &all[0]);
    }

    #[test]
    fn matches_a_later_option() {
        let all = requirements_all(
            &[
                PaymentOption::new(KITE_TESTNET, "0.001"),
                PaymentOption::new(KITE_MAINNET, "$1.50"),
            ],
            PAY_TO,
        )
        .unwrap();
        let chosen = accepted_for(&all[1]);
        let matched = find_matching_requirements(&chosen, &all).unwrap();
        assert_eq!(matched, &all[1]);
    }

    #[test]
    fn single_option_matches_exactly_like_the_old_equality_check() {
        let all = requirements_all(&[PaymentOption::new(KITE_TESTNET, "0.001")], PAY_TO).unwrap();
        let chosen = accepted_for(&all[0]);
        assert_eq!(find_matching_requirements(&chosen, &all), Some(&all[0]));

        let mut wrong_amount = all[0].clone();
        wrong_amount.amount = "1".to_owned();
        assert_eq!(find_matching_requirements(&wrong_amount, &all), None);
    }

    #[test]
    fn no_match_returns_none() {
        let all = requirements_all(&[PaymentOption::new(KITE_TESTNET, "0.001")], PAY_TO).unwrap();
        let mut foreign = all[0].clone();
        foreign.network = "eip155:1".to_owned();
        assert_eq!(find_matching_requirements(&foreign, &all), None);
    }

    #[test]
    fn empty_options_never_match() {
        let req = PaymentOption::new(KITE_TESTNET, "0.001")
            .to_requirements(PAY_TO)
            .unwrap();
        assert_eq!(find_matching_requirements(&req, &[]), None);
    }

    #[test]
    fn extra_field_is_part_of_the_match() {
        // Full-struct equality means extra (EIP-712 domain metadata) must agree.
        let all = requirements_all(&[PaymentOption::new(KITE_TESTNET, "0.001")], PAY_TO).unwrap();
        let mut chosen = all[0].clone();
        chosen.extra = Some(json!({ "name": "something-else" }));
        assert_eq!(find_matching_requirements(&chosen, &all), None);
    }
}
