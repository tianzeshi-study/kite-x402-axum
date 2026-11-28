//! Read-only Kite JSON-RPC reconciliation of EIP-3009 authorization events.

use std::time::Duration;

use kite_x402_axum::{
    kite::{KITE_MAINNET, KITE_TESTNET},
    settlement_ledger::SettlementReconciliation,
    settlement_store::SettlementStorageError,
};
use reqwest::{Client, Url};
use serde_json::{json, Value};

// Keep the event signatures in sync with the manual reconciliation CLI.
const USED: &str = "0x98de503528ee59b575ef0c0a2576a82497bfc029a5685b209e9ec333479b10a5";
const CANCELED: &str = "0x1cdd46ff242716cdaa72d159d339a485b3438398348d68f09d7c8c0a59353d81";
const TRANSFER: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const CONFIRMATIONS: i64 = 12;
const BLOCKS_PER_SCAN: i64 = 1000;
const MAX_RPC_BODY: usize = 1024 * 1024;

#[derive(Clone)]
pub(crate) struct ChainRpc {
    http: Client,
    mainnet: Url,
    testnet: Url,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ScanResult {
    Wait,
    Advance(i64),
    Resolved {
        state: &'static str,
        transaction: String,
    },
}

pub(crate) fn normalized_hex(value: &str, bytes: usize) -> Option<String> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))?;
    (digits.len() == bytes * 2 && digits.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| format!("0x{}", digits.to_ascii_lowercase()))
}

fn error(message: &'static str) -> SettlementStorageError {
    SettlementStorageError(message.into())
}

fn quantity(value: &Value) -> Option<i64> {
    let digits = value.as_str()?.strip_prefix("0x")?;
    if digits.is_empty()
        || (digits.starts_with('0') && digits.len() > 1)
        || !digits.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }
    i64::from_str_radix(digits, 16).ok()
}

fn hex_field(value: &Value, bytes: usize) -> Option<String> {
    normalized_hex(value.as_str()?, bytes)
}

fn padded_address(value: &str) -> String {
    let digits = value.trim_start_matches("0x");
    format!("0x{digits:0>64}")
}

fn matches_event(log: &Value, asset: &str, topics: &[&str]) -> bool {
    log.get("removed")
        .is_none_or(|removed| removed.as_bool() == Some(false))
        && log["address"]
            .as_str()
            .is_some_and(|address| address.eq_ignore_ascii_case(asset))
        && log["topics"].as_array().is_some_and(|actual| {
            actual.len() == topics.len()
                && actual.iter().zip(topics).all(|(a, b)| {
                    a.as_str()
                        .is_some_and(|topic| topic.eq_ignore_ascii_case(b))
                })
        })
}

impl ChainRpc {
    pub(crate) fn new(mainnet: &str, testnet: &str) -> Result<Self, SettlementStorageError> {
        fn url(value: &str) -> Result<Url, SettlementStorageError> {
            let parsed = Url::parse(value).map_err(|_| error("Invalid reconciliation RPC URL"))?;
            if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
                return Err(error("Reconciliation RPC URL must use HTTP or HTTPS"));
            }
            Ok(parsed)
        }
        Ok(Self {
            http: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(5))
                .build()
                .map_err(|_| error("Could not create reconciliation HTTP client"))?,
            mainnet: url(mainnet)?,
            testnet: url(testnet)?,
        })
    }

    async fn call(
        &self,
        network: &str,
        method: &'static str,
        params: Value,
    ) -> Result<Value, SettlementStorageError> {
        let url = match network {
            n if n == KITE_MAINNET.network => &self.mainnet,
            n if n == KITE_TESTNET.network => &self.testnet,
            _ => return Err(error("Unsupported reconciliation network")),
        };
        let mut response = self
            .http
            .post(url.clone())
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
            .send()
            .await
            .map_err(|_| error("Could not reach reconciliation RPC"))?;
        if !response.status().is_success() {
            return Err(error("Reconciliation RPC returned an HTTP error"));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| error("Incomplete RPC response"))?
        {
            if chunk.len() > MAX_RPC_BODY - bytes.len() {
                return Err(error("Reconciliation RPC response exceeded its size limit"));
            }
            bytes.extend_from_slice(&chunk);
        }
        let mut body: Value =
            serde_json::from_slice(&bytes).map_err(|_| error("Invalid RPC JSON response"))?;
        if body["jsonrpc"] != "2.0" || body["id"] != 1 || body.get("error").is_some() {
            return Err(error("Invalid reconciliation RPC result"));
        }
        body.as_object_mut()
            .and_then(|object| object.remove("result"))
            .ok_or_else(|| error("Missing reconciliation RPC result"))
    }

    pub(crate) async fn head(&self, network: &str) -> Result<i64, SettlementStorageError> {
        let number = self.call(network, "eth_chainId", json!([])).await?;
        let expected = network
            .strip_prefix("eip155:")
            .and_then(|s| s.parse::<i64>().ok());
        if quantity(&number)
            .zip(expected)
            .is_none_or(|(actual, expected)| actual != expected)
        {
            return Err(error("Reconciliation RPC is on the wrong chain"));
        }
        let head = self.call(network, "eth_blockNumber", json!([])).await?;
        quantity(&head).ok_or_else(|| error("Reconciliation RPC returned an invalid block height"))
    }

    pub(crate) async fn scan(
        &self,
        payment: &SettlementReconciliation,
        from: i64,
    ) -> Result<ScanResult, SettlementStorageError> {
        let through = self.head(&payment.network).await? - CONFIRMATIONS;
        let to = through.min(from.saturating_add(BLOCKS_PER_SCAN - 1));
        if to < from {
            return Ok(ScanResult::Wait);
        }
        let payer = padded_address(&payment.payer);
        let logs = self
            .call(
                &payment.network,
                "eth_getLogs",
                json!([{
                    "address": payment.asset,
                    "fromBlock": format!("0x{from:x}"),
                    "toBlock": format!("0x{to:x}"),
                    "topics": [[USED, CANCELED], payer, payment.nonce],
                }]),
            )
            .await?;
        let logs = logs
            .as_array()
            .ok_or_else(|| error("Invalid authorization log list"))?;
        let event = match logs.as_slice() {
            [] => return Ok(ScanResult::Advance(to + 1)),
            [event] => event,
            _ => return Err(error("Inconsistent authorization log list")),
        };
        let used = [USED, payer.as_str(), payment.nonce.as_str()];
        let canceled = [CANCELED, payer.as_str(), payment.nonce.as_str()];
        let is_canceled = matches_event(event, &payment.asset, &canceled);
        if !is_canceled && !matches_event(event, &payment.asset, &used) {
            return Err(error("Authorization event did not match the payment"));
        }
        let block = quantity(&event["blockNumber"]).filter(|block| (from..=to).contains(block));
        let hash = hex_field(&event["blockHash"], 32);
        let index = quantity(&event["logIndex"]);
        let tx = hex_field(&event["transactionHash"], 32);
        let (Some(block), Some(hash), Some(index), Some(transaction)) = (block, hash, index, tx)
        else {
            return Err(error("Invalid authorization event metadata"));
        };
        let receipt = self
            .call(
                &payment.network,
                "eth_getTransactionReceipt",
                json!([transaction]),
            )
            .await?;
        if receipt.is_null() {
            return Ok(ScanResult::Wait);
        }
        if hex_field(&receipt["transactionHash"], 32).as_ref() != Some(&transaction)
            || hex_field(&receipt["blockHash"], 32).as_ref() != Some(&hash)
            || quantity(&receipt["blockNumber"]) != Some(block)
            || quantity(&receipt["status"]) != Some(1)
        {
            return Err(error("Authorization receipt did not match the event"));
        }
        let state = receipt_state(&receipt, payment, &used, &canceled, index, is_canceled)?;
        Ok(ScanResult::Resolved { state, transaction })
    }
}

fn receipt_state(
    receipt: &Value,
    payment: &SettlementReconciliation,
    used: &[&str],
    canceled: &[&str],
    index: i64,
    is_canceled: bool,
) -> Result<&'static str, SettlementStorageError> {
    let logs = receipt["logs"]
        .as_array()
        .ok_or_else(|| error("Invalid receipt logs"))?;
    let mut matching = logs.iter().enumerate().filter(|(_, log)| {
        matches_event(log, &payment.asset, used) || matches_event(log, &payment.asset, canceled)
    });
    let Some((position, log)) = matching.next() else {
        return Err(error("Receipt is missing the authorization event"));
    };
    let expected = if is_canceled { canceled } else { used };
    if matching.next().is_some()
        || quantity(&log["logIndex"]) != Some(index)
        || !matches_event(log, &payment.asset, expected)
    {
        return Err(error("Inconsistent authorization event in receipt"));
    }
    if is_canceled {
        return Ok("canceled");
    }
    let amount = payment
        .amount_atomic
        .parse::<num_bigint::BigUint>()
        .map_err(|_| error("Invalid journal amount"))?;
    let data = format!("0x{amount:064x}");
    let pay_to = padded_address(&payment.pay_to);
    let transfer = [TRANSFER, used[1], pay_to.as_str()];
    // In Kite's EIP-3009 tokens the transfer follows its authorization event.
    if logs.get(position + 1).is_some_and(|next| {
        matches_event(next, &payment.asset, &transfer)
            && hex_field(&next["data"], 32).as_ref() == Some(&data)
    }) {
        Ok("confirmed")
    } else {
        Ok("transfer_mismatch")
    }
}
