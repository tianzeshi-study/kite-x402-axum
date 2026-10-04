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
    #[serde(rename = "mimeType", default, skip_serializing_if = "Option::is_none")]
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn requirements() -> PaymentRequirements {
        PaymentRequirements {
            scheme: "exact".into(),
            network: "eip155:2368".into(),
            amount: "1000".into(),
            asset: "0xAsset".into(),
            pay_to: "0xPayTo".into(),
            max_timeout_seconds: 60,
            extra: Some(json!({ "name": "pieUSD", "version": "1" })),
        }
    }

    // ---- PaymentRequirements ---------------------------------------------

    #[test]
    fn requirements_serialize_with_camel_case_wire_names() {
        let v = serde_json::to_value(requirements()).unwrap();
        assert_eq!(
            v,
            json!({
                "scheme": "exact",
                "network": "eip155:2368",
                "amount": "1000",
                "asset": "0xAsset",
                "payTo": "0xPayTo",
                "maxTimeoutSeconds": 60,
                "extra": { "name": "pieUSD", "version": "1" }
            })
        );
        assert!(v.get("pay_to").is_none() && v.get("max_timeout_seconds").is_none());
    }

    #[test]
    fn requirements_omit_extra_when_none() {
        let mut r = requirements();
        r.extra = None;
        assert!(serde_json::to_value(&r).unwrap().get("extra").is_none());
    }

    #[test]
    fn requirements_deserialize_without_extra() {
        let r: PaymentRequirements = serde_json::from_value(json!({
            "scheme": "exact", "network": "n", "amount": "1", "asset": "a",
            "payTo": "p", "maxTimeoutSeconds": 5
        }))
        .unwrap();
        assert_eq!(r.extra, None);
        assert_eq!(r.max_timeout_seconds, 5);
    }

    #[test]
    fn requirements_reject_missing_required_fields() {
        for missing in [
            "scheme",
            "network",
            "amount",
            "asset",
            "payTo",
            "maxTimeoutSeconds",
        ] {
            let mut v = serde_json::to_value(requirements()).unwrap();
            v.as_object_mut().unwrap().remove(missing);
            assert!(
                serde_json::from_value::<PaymentRequirements>(v).is_err(),
                "missing {missing} must fail"
            );
        }
    }

    #[test]
    fn requirements_reject_wrongly_typed_fields() {
        let mut v = serde_json::to_value(requirements()).unwrap();
        v["amount"] = json!(1000); // must be a string on the wire
        assert!(serde_json::from_value::<PaymentRequirements>(v).is_err());

        let mut v = serde_json::to_value(requirements()).unwrap();
        v["maxTimeoutSeconds"] = json!(-1);
        assert!(serde_json::from_value::<PaymentRequirements>(v).is_err());
    }

    #[test]
    fn requirements_ignore_unknown_fields() {
        let mut v = serde_json::to_value(requirements()).unwrap();
        v["somethingNew"] = json!(true);
        assert_eq!(
            serde_json::from_value::<PaymentRequirements>(v).unwrap(),
            requirements()
        );
    }

    #[test]
    fn requirements_equality_is_field_wise_including_extra() {
        let base = requirements();
        assert_eq!(base, requirements());

        let mut other = requirements();
        other.amount = "1001".into();
        assert_ne!(base, other);

        let mut other = requirements();
        other.extra = Some(json!({ "name": "pieUSD", "version": "2" }));
        assert_ne!(base, other);

        let mut other = requirements();
        other.extra = None;
        assert_ne!(base, other);
    }

    // ---- ResourceInfo / PaymentRequired ----------------------------------

    #[test]
    fn resource_info_uses_mime_type_wire_name_and_skips_none() {
        let full = ResourceInfo {
            url: "/v1/x".into(),
            description: Some("d".into()),
            mime_type: Some("application/json".into()),
        };
        assert_eq!(
            serde_json::to_value(&full).unwrap(),
            json!({ "url": "/v1/x", "description": "d", "mimeType": "application/json" })
        );

        let bare = ResourceInfo {
            url: "/v1/x".into(),
            description: None,
            mime_type: None,
        };
        assert_eq!(
            serde_json::to_value(&bare).unwrap(),
            json!({ "url": "/v1/x" })
        );
    }

    #[test]
    fn payment_required_round_trips() {
        let pr = PaymentRequired {
            x402_version: 2,
            error: Some("nope".into()),
            resource: ResourceInfo {
                url: "/v1/x".into(),
                description: None,
                mime_type: None,
            },
            accepts: vec![requirements()],
        };
        let json = serde_json::to_string(&pr).unwrap();
        assert!(json.contains("\"x402Version\":2"));
        let back: PaymentRequired = serde_json::from_str(&json).unwrap();
        assert_eq!(back.x402_version, 2);
        assert_eq!(back.error.as_deref(), Some("nope"));
        assert_eq!(back.accepts, vec![requirements()]);
    }

    #[test]
    fn payment_required_omits_error_when_none() {
        let pr = PaymentRequired {
            x402_version: 2,
            error: None,
            resource: ResourceInfo {
                url: "u".into(),
                description: None,
                mime_type: None,
            },
            accepts: vec![],
        };
        assert!(serde_json::to_value(&pr).unwrap().get("error").is_none());
    }

    // ---- PaymentPayload ---------------------------------------------------

    #[test]
    fn payload_deserializes_the_shape_a_client_sends() {
        let p: PaymentPayload = serde_json::from_value(json!({
            "x402Version": 2,
            "accepted": serde_json::to_value(requirements()).unwrap(),
            "payload": { "signature": "0xsig", "authorization": { "from": "0xabc" } }
        }))
        .unwrap();
        assert_eq!(p.x402_version, 2);
        assert!(p.resource.is_none() && p.extensions.is_none());
        assert_eq!(p.accepted, requirements());
        assert_eq!(p.payload["authorization"]["from"], "0xabc");
    }

    #[test]
    fn payload_keeps_optional_resource_and_extensions() {
        let p: PaymentPayload = serde_json::from_value(json!({
            "x402Version": 2,
            "resource": { "url": "https://x/v1/y", "mimeType": "text/plain" },
            "accepted": serde_json::to_value(requirements()).unwrap(),
            "payload": {},
            "extensions": { "foo": 1 }
        }))
        .unwrap();
        assert_eq!(p.resource.unwrap().mime_type.as_deref(), Some("text/plain"));
        assert_eq!(p.extensions.unwrap()["foo"], 1);
    }

    #[test]
    fn payload_requires_accepted_and_payload() {
        let accepted = serde_json::to_value(requirements()).unwrap();
        assert!(serde_json::from_value::<PaymentPayload>(
            json!({ "x402Version": 2, "payload": {} })
        )
        .is_err());
        assert!(serde_json::from_value::<PaymentPayload>(
            json!({ "x402Version": 2, "accepted": accepted })
        )
        .is_err());
    }

    // ---- VerifyResponse ---------------------------------------------------

    #[test]
    fn verify_response_minimal_valid() {
        let v: VerifyResponse = serde_json::from_value(json!({ "isValid": true })).unwrap();
        assert!(v.is_valid);
        assert!(v.invalid_reason.is_none() && v.invalid_message.is_none() && v.payer.is_none());
    }

    #[test]
    fn verify_response_full_invalid() {
        let v: VerifyResponse = serde_json::from_value(json!({
            "isValid": false,
            "invalidReason": "insufficient_funds",
            "invalidMessage": "balance too low",
            "payer": "0xabc"
        }))
        .unwrap();
        assert!(!v.is_valid);
        assert_eq!(v.invalid_reason.as_deref(), Some("insufficient_funds"));
        assert_eq!(v.invalid_message.as_deref(), Some("balance too low"));
        assert_eq!(v.payer.as_deref(), Some("0xabc"));
    }

    #[test]
    fn verify_response_accepts_explicit_nulls() {
        let v: VerifyResponse = serde_json::from_value(
            json!({ "isValid": false, "invalidReason": null, "payer": null }),
        )
        .unwrap();
        assert!(v.invalid_reason.is_none() && v.payer.is_none());
    }

    #[test]
    fn verify_response_requires_is_valid() {
        assert!(serde_json::from_value::<VerifyResponse>(json!({ "payer": "0x1" })).is_err());
        assert!(serde_json::from_value::<VerifyResponse>(json!({ "isValid": "yes" })).is_err());
    }

    // ---- SettleResponse ---------------------------------------------------

    #[test]
    fn settle_response_round_trips_and_skips_none() {
        let s = SettleResponse {
            success: true,
            error_reason: None,
            error_message: None,
            payer: Some("0xabc".into()),
            transaction: "0xtx".into(),
            network: "eip155:2368".into(),
            amount: None,
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(
            v,
            json!({ "success": true, "payer": "0xabc", "transaction": "0xtx", "network": "eip155:2368" })
        );
        let back: SettleResponse = serde_json::from_value(v).unwrap();
        assert!(back.success && back.error_reason.is_none());
    }

    #[test]
    fn settle_response_failure_uses_camel_case_error_fields() {
        let s = SettleResponse {
            success: false,
            error_reason: Some("r".into()),
            error_message: Some("m".into()),
            payer: None,
            transaction: String::new(),
            network: "n".into(),
            amount: Some("5".into()),
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["errorReason"], "r");
        assert_eq!(v["errorMessage"], "m");
        assert_eq!(v["amount"], "5");
    }

    #[test]
    fn settle_response_requires_transaction_and_network() {
        assert!(serde_json::from_value::<SettleResponse>(
            json!({ "success": true, "network": "n" })
        )
        .is_err());
        assert!(serde_json::from_value::<SettleResponse>(
            json!({ "success": true, "transaction": "t" })
        )
        .is_err());
    }
}
