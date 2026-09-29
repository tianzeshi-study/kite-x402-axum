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
    use crate::types::{PaymentRequirements, ResourceInfo};
    use serde_json::json;

    fn sample_requirements() -> PaymentRequirements {
        PaymentRequirements {
            scheme: "exact".into(),
            network: "eip155:2368".into(),
            amount: "1000".into(),
            asset: "0xabc".into(),
            pay_to: "0xdef".into(),
            max_timeout_seconds: 60,
            extra: None,
        }
    }

    fn sample_payload() -> PaymentPayload {
        PaymentPayload {
            x402_version: 2,
            resource: None,
            accepted: sample_requirements(),
            payload: json!({"signature": "0x..."}),
            extensions: None,
        }
    }

    fn b64(payload: &PaymentPayload) -> String {
        STANDARD.encode(serde_json::to_vec(payload).unwrap())
    }

    // ---- decode_payment_payload ------------------------------------------

    #[test]
    fn round_trips_payment_payload() {
        let decoded = decode_payment_payload(&b64(&sample_payload())).unwrap();
        assert_eq!(decoded.accepted.amount, "1000");
        assert_eq!(decoded.accepted, sample_requirements());
        assert_eq!(decoded.payload["signature"], "0x...");
    }

    #[test]
    fn rejects_non_base64() {
        assert!(decode_payment_payload("not base64!!").is_err());
    }

    #[test]
    fn decode_tolerates_surrounding_whitespace() {
        let padded = format!("  {}\n", b64(&sample_payload()));
        assert!(decode_payment_payload(&padded).is_ok());
    }

    #[test]
    fn decode_rejects_empty_input() {
        assert!(decode_payment_payload("").is_err());
        assert!(decode_payment_payload("   ").is_err());
    }

    #[test]
    fn decode_rejects_valid_base64_that_is_not_json() {
        assert!(decode_payment_payload(&STANDARD.encode("hello world")).is_err());
    }

    #[test]
    fn decode_rejects_json_of_the_wrong_shape() {
        for body in ["[]", "42", "null", r#"{"x402Version":2}"#, r#"{"accepted":{},"payload":{}}"#] {
            assert!(decode_payment_payload(&STANDARD.encode(body)).is_err(), "{body}");
        }
    }

    /// Payload variants whose standard-base64 form we can inspect.
    fn encodings() -> Vec<String> {
        (0..12)
            .map(|n| {
                let mut p = sample_payload();
                p.extensions = Some(json!({ "pad": format!("{}>>>", "?".repeat(n)) }));
                b64(&p)
            })
            .collect()
    }

    #[test]
    fn decode_rejects_the_url_safe_alphabet() {
        let with_special = encodings()
            .into_iter()
            .find(|e| e.contains('+') || e.contains('/'))
            .expect("some variant must use '+' or '/'");
        assert!(decode_payment_payload(&with_special).is_ok(), "standard form decodes");

        let url_safe = with_special.replace('+', "-").replace('/', "_");
        assert_ne!(url_safe, with_special);
        assert!(decode_payment_payload(&url_safe).is_err());
    }

    #[test]
    fn decode_rejects_missing_padding() {
        let padded = encodings()
            .into_iter()
            .find(|e| e.ends_with('='))
            .expect("some variant must need padding");
        assert!(decode_payment_payload(&padded).is_ok());
        assert!(decode_payment_payload(padded.trim_end_matches('=')).is_err());
    }

    #[test]
    fn decode_ignores_unknown_json_fields() {
        let mut v = serde_json::to_value(sample_payload()).unwrap();
        v["future"] = json!("field");
        assert!(decode_payment_payload(&STANDARD.encode(v.to_string())).is_ok());
    }

    #[test]
    fn decode_keeps_optional_sections() {
        let mut p = sample_payload();
        p.resource = Some(ResourceInfo { url: "/v1/x".into(), description: None, mime_type: None });
        p.extensions = Some(json!({"a": 1}));
        let d = decode_payment_payload(&b64(&p)).unwrap();
        assert_eq!(d.resource.unwrap().url, "/v1/x");
        assert_eq!(d.extensions.unwrap()["a"], 1);
    }

    // ---- encode_payment_required -----------------------------------------

    #[test]
    fn encodes_payment_required_as_base64_json() {
        let pr = PaymentRequired {
            x402_version: 2,
            error: None,
            resource: ResourceInfo { url: "https://example.com/v1/forecast".into(), description: None, mime_type: None },
            accepts: vec![],
        };
        let decoded = STANDARD.decode(encode_payment_required(&pr)).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(value["x402Version"], 2);
    }

    #[test]
    fn encoded_payment_required_uses_padding_and_the_standard_alphabet() {
        let pr = PaymentRequired {
            x402_version: 2,
            error: Some("~~~???>>>".into()), // provokes '+' and '/' in the encoding
            resource: ResourceInfo { url: "/v1/x?a=~~~".into(), description: None, mime_type: None },
            accepts: vec![sample_requirements()],
        };
        let enc = encode_payment_required(&pr);
        assert!(!enc.contains('-') && !enc.contains('_'), "must be standard, not URL-safe: {enc}");
        assert_eq!(enc.len() % 4, 0, "must be padded to a multiple of 4");
        assert!(enc.is_ascii() && !enc.contains(char::is_whitespace));
    }

    #[test]
    fn payment_required_round_trips_through_the_header_encoding() {
        let pr = PaymentRequired {
            x402_version: 2,
            error: Some("Invalid payment signature".into()),
            resource: ResourceInfo {
                url: "/v1/forecast?q=ü".into(),
                description: Some("Paid API access".into()),
                mime_type: Some("application/json".into()),
            },
            accepts: vec![sample_requirements()],
        };
        let back: PaymentRequired = serde_json::from_slice(&STANDARD.decode(encode_payment_required(&pr)).unwrap()).unwrap();
        assert_eq!(back.error.as_deref(), Some("Invalid payment signature"));
        assert_eq!(back.resource.url, "/v1/forecast?q=ü");
        assert_eq!(back.accepts, vec![sample_requirements()]);
    }

    // ---- encode_settle_response ------------------------------------------

    #[test]
    fn settle_response_round_trips_through_the_header_encoding() {
        let sr = SettleResponse {
            success: true,
            error_reason: None,
            error_message: None,
            payer: Some("0xpayer".into()),
            transaction: "0xtx".into(),
            network: "eip155:2368".into(),
            amount: Some("1000".into()),
        };
        let back: SettleResponse = serde_json::from_slice(&STANDARD.decode(encode_settle_response(&sr)).unwrap()).unwrap();
        assert!(back.success);
        assert_eq!(back.transaction, "0xtx");
        assert_eq!(back.amount.as_deref(), Some("1000"));
    }

    #[test]
    fn failed_settle_response_keeps_its_error_fields() {
        let sr = SettleResponse {
            success: false,
            error_reason: Some("nonce_used".into()),
            error_message: Some("already spent".into()),
            payer: None,
            transaction: String::new(),
            network: "n".into(),
            amount: None,
        };
        let v: serde_json::Value = serde_json::from_slice(&STANDARD.decode(encode_settle_response(&sr)).unwrap()).unwrap();
        assert_eq!(v["success"], false);
        assert_eq!(v["errorReason"], "nonce_used");
        assert_eq!(v["errorMessage"], "already spent");
    }

    #[test]
    fn encoded_values_are_valid_header_values() {
        let sr = SettleResponse {
            success: true, error_reason: None, error_message: None, payer: None,
            transaction: "0xtx".into(), network: "n".into(), amount: None,
        };
        assert!(axum::http::HeaderValue::from_str(&encode_settle_response(&sr)).is_ok());
    }

    #[test]
    fn wire_error_has_a_stable_message() {
        assert_eq!(WireError.to_string(), "invalid x402 header value");
    }
}
