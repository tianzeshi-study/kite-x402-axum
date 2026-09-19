//! The x402 payment gate: verify before the protected handler runs, settle
//! only after it answers with a status below 400.
//!
//! See the [crate-level docs][crate] for the deliberate choice to report
//! every verify/settle problem — including the facilitator being
//! unreachable — as `402 Payment Required`, matching the Go SDK rather than
//! the TypeScript SDK's `500`/`502` split.

use std::sync::Arc;

use axum::{
    extract::{OriginalUri, Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use serde_json::json;

use crate::{
    facilitator::FacilitatorClient,
    kite::KiteChain,
    types::{PaymentRequired, PaymentRequirements, ResourceInfo},
    wire::{decode_payment_payload, encode_payment_required, encode_settle_response},
};

/// Shared configuration for the payment gate on a route (or group of
/// routes). Build one and pass it to [`axum::middleware::from_fn_with_state`]
/// wrapped in an [`Arc`].
#[derive(Clone)]
pub struct PaymentConfig {
    /// The Kite wallet address that receives payments.
    pub pay_to: String,
    /// `mainnet` or `testnet`.
    pub chain: KiteChain,
    /// A `"0.001"`-or-`"$0.001"`-style USD price per call.
    pub price_usd: String,
    /// Shown to the buyer as the resource description in the 402 challenge.
    pub description: String,
    /// Client for the Kite facilitator's `/verify` and `/settle`.
    pub facilitator: FacilitatorClient,
}

impl PaymentConfig {
    fn requirements(&self) -> Result<PaymentRequirements, String> {
        let asset = self
            .chain
            .parse_price(&self.price_usd)
            .map_err(|e| format!("invalid PRICE_USD configured on the server: {e}"))?;
        Ok(PaymentRequirements {
            scheme: "exact".to_string(),
            network: self.chain.network.to_string(),
            amount: asset.amount,
            asset: asset.asset,
            pay_to: self.pay_to.clone(),
            max_timeout_seconds: 60,
            extra: Some(asset.extra),
        })
    }
}

fn payment_required_response(
    requirements: PaymentRequirements,
    resource_url: String,
    description: String,
    error: Option<String>,
) -> Response {
    let body = PaymentRequired {
        x402_version: 2,
        error,
        resource: ResourceInfo {
            url: resource_url,
            description: Some(description),
            mime_type: Some("application/json".to_string()),
        },
        accepts: vec![requirements],
    };

    let mut response = (StatusCode::PAYMENT_REQUIRED, Json(json!({}))).into_response();
    let headers = response.headers_mut();
    headers.insert(
        "PAYMENT-REQUIRED",
        HeaderValue::from_str(&encode_payment_required(&body))
            .unwrap_or_else(|_| HeaderValue::from_static("")),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn settlement_failure_response(settle: &crate::types::SettleResponse) -> Response {
    let mut response = (StatusCode::PAYMENT_REQUIRED, Json(json!({}))).into_response();
    let headers = response.headers_mut();
    headers.insert(
        "PAYMENT-RESPONSE",
        HeaderValue::from_str(&encode_settle_response(settle))
            .unwrap_or_else(|_| HeaderValue::from_static("")),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// The x402 payment middleware. Apply with
/// [`axum::middleware::from_fn_with_state`] to the `/v1/*` route group:
///
/// ```ignore
/// let cfg = Arc::new(PaymentConfig { .. });
/// let paid = Router::new()
///     .route("/{*path}", any(proxy))
///     .with_state(upstream_cfg)
///     .layer(middleware::from_fn_with_state(cfg, x402_payment));
/// ```
///
/// Behavior:
/// 1. No `PAYMENT-SIGNATURE` (or legacy `X-PAYMENT`) header → `402` with a
///    `PAYMENT-REQUIRED` header describing how to pay.
/// 2. Header present but doesn't decode, or doesn't match this route's
///    price/network/asset/payTo → `402` with `error` explaining why.
/// 3. Facilitator `/verify` says invalid, or the facilitator could not be
///    reached at all → `402` with `error` set to the reason (see the
///    crate-level docs for why facilitator-unreachable is also a `402`).
/// 4. Verified → the inner handler runs. If it answers `>= 400`, that
///    response is returned unchanged and **no settlement is attempted**.
/// 5. If it answers `< 400`, `/settle` is called. On success, a
///    `PAYMENT-RESPONSE` header is attached and `Cache-Control` gets
///    `private` merged in. On failure, a `402` with `PAYMENT-RESPONSE`
///    (`success: false`) is returned instead of the handler's response.
pub async fn x402_payment(
    State(cfg): State<Arc<PaymentConfig>>,
    req: Request,
    next: Next,
) -> Response {
    // Prefer the pre-`nest()` URI (e.g. `/v1/forecast`) so the 402 challenge
    // describes the path the client actually requested, not the
    // `/v1`-stripped path the proxy handler sees.
    let resource_url = req
        .extensions()
        .get::<OriginalUri>()
        .map(|OriginalUri(uri)| uri.to_string())
        .unwrap_or_else(|| req.uri().to_string());

    let requirements = match cfg.requirements() {
        Ok(r) => r,
        Err(msg) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": msg })))
                .into_response()
        }
    };

    let header_value = req
        .headers()
        .get("PAYMENT-SIGNATURE")
        .or_else(|| req.headers().get("X-PAYMENT"))
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let Some(header_value) = header_value else {
        return payment_required_response(requirements, resource_url, cfg.description.clone(), None);
    };

    let payload = match decode_payment_payload(&header_value) {
        Ok(p) => p,
        Err(_) => {
            return payment_required_response(
                requirements,
                resource_url,
                cfg.description.clone(),
                Some("Invalid payment signature".to_string()),
            );
        }
    };

    if payload.accepted != requirements {
        return payment_required_response(
            requirements,
            resource_url,
            cfg.description.clone(),
            Some("No matching payment requirements".to_string()),
        );
    }

    let verify_outcome = cfg.facilitator.verify(&payload, &requirements).await;
    let verify = match verify_outcome {
        Ok(v) => v,
        Err(e) => {
            // Facilitator unreachable / bad response: 402, not 500/502.
            // See the crate-level docs for why.
            return payment_required_response(
                requirements,
                resource_url,
                cfg.description.clone(),
                Some(format!("facilitator verify unavailable: {e}")),
            );
        }
    };

    if !verify.is_valid {
        let reason = verify
            .invalid_reason
            .unwrap_or_else(|| "Payment invalid".to_string());
        return payment_required_response(
            requirements,
            resource_url,
            cfg.description.clone(),
            Some(reason),
        );
    }

    // Verified: run the protected handler ("authorization" flow — settle
    // happens after, and only on success). This is the rule both official
    // templates call out explicitly: never settle before the upstream call
    // succeeds.
    let response = next.run(req).await;

    if response.status().as_u16() >= 400 {
        return response;
    }

    let settle_outcome = cfg.facilitator.settle(&payload, &requirements).await;
    let settle = match settle_outcome {
        Ok(s) => s,
        Err(e) => {
            let failure = crate::types::SettleResponse {
                success: false,
                error_reason: Some(format!("facilitator settle unavailable: {e}")),
                error_message: None,
                payer: None,
                transaction: String::new(),
                network: cfg.chain.network.to_string(),
                amount: None,
            };
            return settlement_failure_response(&failure);
        }
    };

    if !settle.success {
        return settlement_failure_response(&settle);
    }

    let (mut parts, body) = response.into_parts();
    parts.headers.insert(
        "PAYMENT-RESPONSE",
        HeaderValue::from_str(&encode_settle_response(&settle))
            .unwrap_or_else(|_| HeaderValue::from_static("")),
    );
    let cache_control = match parts.headers.get(header::CACHE_CONTROL).and_then(|v| v.to_str().ok()) {
        Some(existing) if !existing.is_empty() => format!("{existing}, private"),
        _ => "private".to_string(),
    };
    parts.headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_str(&cache_control).unwrap_or_else(|_| HeaderValue::from_static("private")),
    );

    Response::from_parts(parts, body)
}
