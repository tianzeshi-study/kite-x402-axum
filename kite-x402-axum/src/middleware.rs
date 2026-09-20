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
#[derive(Clone, Debug)]
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
    let method = req.method().clone();

    tracing::debug!(
        method = %method,
        uri = %resource_url,
        "Processing request through x402 payment gate"
    );

    let requirements = match cfg.requirements() {
        Ok(r) => r,
        Err(msg) => {
            tracing::error!(
                error = %msg,
                "Failed to compute payment requirements (invalid server configuration)"
            );
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": msg })))
                .into_response();
        }
    };

    let header_value = req
        .headers()
        .get("PAYMENT-SIGNATURE")
        .or_else(|| req.headers().get("X-PAYMENT"))
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let Some(header_value) = header_value else {
        tracing::info!(
            uri = %resource_url,
            "No payment signature header found; returning 402 Payment Required challenge"
        );
        tracing::debug!(
            uri = %resource_url,
            requirements = ?requirements,
            "402 challenge requirements details"
        );
        return payment_required_response(requirements, resource_url, cfg.description.clone(), None);
    };

    tracing::debug!(
        uri = %resource_url,
        "Payment signature header present; decoding payload"
    );

    let payload = match decode_payment_payload(&header_value) {
        Ok(p) => p,
        Err(_) => {
            tracing::warn!(
                uri = %resource_url,
                "Failed to decode payment signature header; returning 402"
            );
            return payment_required_response(
                requirements,
                resource_url,
                cfg.description.clone(),
                Some("Invalid payment signature".to_string()),
            );
        }
    };

    if payload.accepted != requirements {
        tracing::warn!(
            uri = %resource_url,
            expected = ?requirements,
            actual = ?payload.accepted,
            "Payment requirements mismatch; returning 402"
        );
        return payment_required_response(
            requirements,
            resource_url,
            cfg.description.clone(),
            Some("No matching payment requirements".to_string()),
        );
    }

    tracing::debug!(
        uri = %resource_url,
        facilitator = %cfg.facilitator.base_url(),
        network = %requirements.network,
        amount = %requirements.amount,
        pay_to = %requirements.pay_to,
        "Calling facilitator to verify payment signature"
    );

    let verify_outcome = cfg.facilitator.verify(&payload, &requirements).await;
    let verify = match verify_outcome {
        Ok(v) => v,
        Err(e) => {
            // Facilitator unreachable / bad response: 402, not 500/502.
            // See the crate-level docs for why.
            tracing::error!(
                uri = %resource_url,
                error = %e,
                "Facilitator verify unavailable; returning 402"
            );
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
        tracing::warn!(
            uri = %resource_url,
            reason = %reason,
            payer = ?verify.payer,
            "Payment rejected by facilitator; returning 402"
        );
        return payment_required_response(
            requirements,
            resource_url,
            cfg.description.clone(),
            Some(reason),
        );
    }

    tracing::info!(
        uri = %resource_url,
        payer = ?verify.payer,
        "Payment signature verified successfully by facilitator"
    );

    // Verified: run the protected handler ("authorization" flow — settle
    // happens after, and only on success). This is the rule both official
    // templates call out explicitly: never settle before the upstream call
    // succeeds.
    tracing::debug!(
        uri = %resource_url,
        "Running inner handler (forwarding to upstream)"
    );
    let response = next.run(req).await;

    let status = response.status();
    if status.as_u16() >= 400 {
        tracing::warn!(
            uri = %resource_url,
            status = status.as_u16(),
            "Upstream returned HTTP status >= 400; skipping settlement"
        );
        return response;
    }

    tracing::info!(
        uri = %resource_url,
        status = status.as_u16(),
        payer = ?verify.payer,
        "Upstream succeeded; settling payment with facilitator"
    );

    let settle_outcome = cfg.facilitator.settle(&payload, &requirements).await;
    let settle = match settle_outcome {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                uri = %resource_url,
                error = %e,
                "Facilitator settle unavailable"
            );
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
        tracing::error!(
            uri = %resource_url,
            error_reason = ?settle.error_reason,
            error_message = ?settle.error_message,
            "Facilitator settlement failed"
        );
        return settlement_failure_response(&settle);
    }

    tracing::info!(
        uri = %resource_url,
        tx = %settle.transaction,
        network = %settle.network,
        payer = ?settle.payer,
        amount = ?settle.amount,
        "Payment settled successfully on-chain"
    );
    tracing::debug!(
        settle = ?settle,
        "Full settlement response details"
    );

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
