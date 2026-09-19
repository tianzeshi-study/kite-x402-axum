//! x402 protocol v2 wire types.
//!
//! Field names and casing match the JSON the TypeScript and Go SDKs put on
//! the wire exactly (`x402Version`, `payTo`, `maxTimeoutSeconds`, ...), so
//! these serialize to and deserialize from the same bytes a Kite Passport
//! agent or the facilitator sends.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Describes the protected resource in a `PaymentRequired` (402) response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceInfo {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(
        rename = "mimeType",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub mime_type: Option<String>,
}

/// One way to pay for a resource: `accepts[i]` in a 402 response, and
/// `accepted` in the client's payment payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PaymentRequirements {
    pub scheme: String,
    pub network: String,
    pub amount: String,
    pub asset: String,
    #[serde(rename = "payTo")]
    pub pay_to: String,
    #[serde(rename = "maxTimeoutSeconds")]
    pub max_timeout_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
}

/// The `402 Payment Required` body, also base64-encoded into the
/// `PAYMENT-REQUIRED` response header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentRequired {
    #[serde(rename = "x402Version")]
    pub x402_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub resource: ResourceInfo,
    pub accepts: Vec<PaymentRequirements>,
}

/// The payment payload a client sends, decoded from the base64
/// `PAYMENT-SIGNATURE` (or legacy `X-PAYMENT`) request header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentPayload {
    #[serde(rename = "x402Version")]
    pub x402_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceInfo>,
    pub accepted: PaymentRequirements,
    pub payload: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Value>,
}

/// The Kite facilitator's `POST /verify` response.
#[derive(Debug, Clone, Deserialize)]
pub struct VerifyResponse {
    #[serde(rename = "isValid")]
    pub is_valid: bool,
    #[serde(rename = "invalidReason", default)]
    pub invalid_reason: Option<String>,
    #[serde(rename = "invalidMessage", default)]
    pub invalid_message: Option<String>,
    #[serde(default)]
    pub payer: Option<String>,
}

/// The Kite facilitator's `POST /settle` response, also base64-encoded into
/// the `PAYMENT-RESPONSE` header on both success and failure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettleResponse {
    pub success: bool,
    #[serde(
        rename = "errorReason",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub error_reason: Option<String>,
    #[serde(
        rename = "errorMessage",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub error_message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    pub transaction: String,
    pub network: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
}
