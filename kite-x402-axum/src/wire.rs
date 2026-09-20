//! base64 encode/decode helpers for the x402 HTTP headers: `PAYMENT-REQUIRED`,
//! `PAYMENT-SIGNATURE` (and legacy `X-PAYMENT`), and `PAYMENT-RESPONSE`.
//! Standard (not URL-safe) base64, matching the TypeScript and Go SDKs.

use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::types::{PaymentPayload, PaymentRequired, SettleResponse};

/// A header value could not be base64-decoded or its JSON did not match the
/// expected x402 shape.
#[derive(Debug, thiserror::Error)]
#[error("invalid x402 header value")]
pub struct WireError;

/// Encodes a `PaymentRequired` body as the `PAYMENT-REQUIRED` header value.
pub fn encode_payment_required(pr: &PaymentRequired) -> String {
    STANDARD.encode(serde_json::to_vec(pr).expect("PaymentRequired always serializes"))
}

/// Decodes the `PAYMENT-SIGNATURE` (or `X-PAYMENT`) header value into a
/// [`PaymentPayload`].
pub fn decode_payment_payload(header_value: &str) -> Result<PaymentPayload, WireError> {
    let bytes = match STANDARD.decode(header_value.trim()) {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!(error = %e, "Failed to base64-decode payment header");
            return Err(WireError);
        }
    };
    match serde_json::from_slice(&bytes) {
        Ok(p) => Ok(p),
        Err(e) => {
            tracing::debug!(error = %e, "Failed to parse JSON payment payload");
            Err(WireError)
        }
    }
}

/// Encodes a `SettleResponse` as the `PAYMENT-RESPONSE` header value.
pub fn encode_settle_response(sr: &SettleResponse) -> String {
    STANDARD.encode(serde_json::to_vec(sr).expect("SettleResponse always serializes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ResourceInfo;
    use serde_json::json;

    #[test]
    fn round_trips_payment_payload() {
        let payload = PaymentPayload {
            x402_version: 2,
            resource: None,
            accepted: crate::types::PaymentRequirements {
                scheme: "exact".into(),
                network: "eip155:2368".into(),
                amount: "1000".into(),
                asset: "0xabc".into(),
                pay_to: "0xdef".into(),
                max_timeout_seconds: 60,
                extra: None,
            },
            payload: json!({"signature": "0x..."}),
            extensions: None,
        };
        let encoded = STANDARD.encode(serde_json::to_vec(&payload).unwrap());
        let decoded = decode_payment_payload(&encoded).unwrap();
        assert_eq!(decoded.accepted.amount, "1000");
    }

    #[test]
    fn rejects_non_base64() {
        assert!(decode_payment_payload("not base64!!").is_err());
    }

    #[test]
    fn encodes_payment_required_as_base64_json() {
        let pr = PaymentRequired {
            x402_version: 2,
            error: None,
            resource: ResourceInfo {
                url: "https://example.com/v1/forecast".into(),
                description: None,
                mime_type: None,
            },
            accepts: vec![],
        };
        let encoded = encode_payment_required(&pr);
        let decoded = STANDARD.decode(encoded).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(value["x402Version"], 2);
    }
}
