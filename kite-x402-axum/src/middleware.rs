//! The x402 payment gate: verify before the protected handler runs, settle
//! only after it answers with a status below 400.
//!
//! See the [crate-level docs][crate] for the deliberate choice to report
//! every verify/settle problem — including the facilitator being
//! unreachable — as `402 Payment Required`, matching the Go SDK rather than
//! the TypeScript SDK's `500`/`502` split.

/// Opt-in peer-identity resolution helpers.
pub mod header_sanitizer;
/// Backoff calculation only; does not retry payment settlement.
pub mod retry;
/// Borrowed payload inspection without copying bytes.
pub mod zero_copy_decoder;

// Reuse the established implementations rather than publishing duplicate stubs.
pub use crate::{circuit_breaker, security_headers};

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
    /// Optional expiration guard to reject expired or premature authorizations early.
    pub expiration_guard: Option<crate::expiration::ExpirationGuardConfig>,
    /// Optional metrics collector to track payment telemetry.
    pub metrics: Option<Arc<crate::metrics::PaymentMetrics>>,
    /// Optional nonce replay guard to reject duplicate payment signatures before calling facilitator.
    pub nonce_guard: Option<Arc<crate::nonce_guard::PaymentNonceReplayGuard>>,
}

impl PaymentConfig {
    /// Creates a payment config with no optional guards or metrics enabled.
    pub fn new(
        pay_to: impl Into<String>,
        chain: KiteChain,
        price_usd: impl Into<String>,
        description: impl Into<String>,
        facilitator: FacilitatorClient,
    ) -> Self {
        Self {
            pay_to: pay_to.into(),
            chain,
            price_usd: price_usd.into(),
            description: description.into(),
            facilitator,
            expiration_guard: None,
            metrics: None,
            nonce_guard: None,
        }
    }

    /// Enables validation of the authorization's validity window.
    #[must_use]
    pub fn with_expiration_guard(
        mut self,
        guard: crate::expiration::ExpirationGuardConfig,
    ) -> Self {
        self.expiration_guard = Some(guard);
        self
    }

    /// Records payment events into the given metrics collector.
    #[must_use]
    pub fn with_metrics(mut self, metrics: Arc<crate::metrics::PaymentMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Enables replay protection using the given nonce guard.
    #[must_use]
    pub fn with_nonce_guard(
        mut self,
        guard: Arc<crate::nonce_guard::PaymentNonceReplayGuard>,
    ) -> Self {
        self.nonce_guard = Some(guard);
        self
    }

    fn requirements(&self) -> Result<PaymentRequirements, String> {
        let asset = self
            .chain
            .parse_price(&self.price_usd)
            .map_err(|e| format!("invalid PRICE_USD configured on the server: {e}"))?;
        Ok(PaymentRequirements {
            scheme: "exact".to_owned(),
            network: self.chain.network.to_owned(),
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
            mime_type: Some("application/json".to_owned()),
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

    if let Some(metrics) = &cfg.metrics {
        metrics.record_request();
    }

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
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": msg })),
            )
                .into_response();
        }
    };

    let header_value = req
        .headers()
        .get("PAYMENT-SIGNATURE")
        .or_else(|| req.headers().get("X-PAYMENT"))
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

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
        if let Some(metrics) = &cfg.metrics {
            metrics.record_challenge();
        }
        return payment_required_response(
            requirements,
            resource_url,
            cfg.description.clone(),
            None,
        );
    };

    tracing::debug!(
        uri = %resource_url,
        "Payment signature header present; decoding payload"
    );

    let Ok(payload) = decode_payment_payload(&header_value) else {
        tracing::warn!(
            uri = %resource_url,
            "Failed to decode payment signature header; returning 402"
        );
        if let Some(metrics) = &cfg.metrics {
            metrics.record_challenge();
        }
        return payment_required_response(
            requirements,
            resource_url,
            cfg.description.clone(),
            Some("Invalid payment signature".to_owned()),
        );
    };

    if payload.accepted != requirements {
        tracing::warn!(
            uri = %resource_url,
            expected = ?requirements,
            actual = ?payload.accepted,
            "Payment requirements mismatch; returning 402"
        );
        if let Some(metrics) = &cfg.metrics {
            metrics.record_challenge();
        }
        return payment_required_response(
            requirements,
            resource_url,
            cfg.description.clone(),
            Some("No matching payment requirements".to_owned()),
        );
    }

    if let Some(guard) = &cfg.expiration_guard {
        if let Some(auth) = payload.payload.get("authorization") {
            let valid_after = auth.get("validAfter").and_then(|v| {
                v.as_str()
                    .and_then(|s| s.parse::<u64>().ok())
                    .or_else(|| v.as_u64())
            });
            let valid_before = auth.get("validBefore").and_then(|v| {
                v.as_str()
                    .and_then(|s| s.parse::<u64>().ok())
                    .or_else(|| v.as_u64())
            });

            if let (Some(va), Some(vb)) = (valid_after, valid_before) {
                if let Err(e) = guard.validate_now(va, vb) {
                    tracing::warn!(
                        uri = %resource_url,
                        error = %e,
                        "Payment authorization rejected by expiration guard; returning 402"
                    );
                    return payment_required_response(
                        requirements,
                        resource_url,
                        cfg.description.clone(),
                        Some(e.to_string()),
                    );
                }
            }
        }
    }

    let mut reservation = if let Some(guard) = &cfg.nonce_guard {
        match guard.reserve(&payload) {
            Ok(reservation) => Some(reservation),
            Err(crate::nonce_guard::NonceReplayError::CapacityExceeded) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [("cache-control", "no-store"), ("retry-after", "1")],
                    Json(json!({ "error": "payment_replay_capacity_exceeded" })),
                )
                    .into_response();
            }
            Err(error) => {
                tracing::warn!(
                    uri = %resource_url,
                    error = %error,
                    "Payment authorization rejected by nonce replay guard; returning 402"
                );
                if let Some(metrics) = &cfg.metrics {
                    metrics.record_challenge();
                }
                return payment_required_response(
                    requirements,
                    resource_url,
                    cfg.description.clone(),
                    Some(error.to_string()),
                );
            }
        }
    } else {
        None
    };

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
            if let Some(metrics) = &cfg.metrics {
                metrics.record_verification(false);
                metrics.record_challenge();
            }
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
            .unwrap_or_else(|| "Payment invalid".to_owned());
        tracing::warn!(
            uri = %resource_url,
            reason = %reason,
            payer = ?verify.payer,
            "Payment rejected by facilitator; returning 402"
        );
        if let Some(metrics) = &cfg.metrics {
            metrics.record_verification(false);
            metrics.record_challenge();
        }
        return payment_required_response(
            requirements,
            resource_url,
            cfg.description.clone(),
            Some(reason),
        );
    }

    if let Some(metrics) = &cfg.metrics {
        metrics.record_verification(true);
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
    // Cancellation after entering the handler has an uncertain execution outcome.
    // Keep the reservation pending until completion, then retain it conservatively.
    if let Some(reservation) = reservation.as_mut() {
        reservation.retain_on_drop();
    }
    let response = next.run(req).await;

    let status = response.status();
    if status.as_u16() >= 400 {
        // This branch never calls settle, so the authorization is safe to retry.
        if let Some(reservation) = reservation.take() {
            reservation.release();
        }
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

    let settle_start = std::time::Instant::now();
    let settle_outcome = cfg.facilitator.settle(&payload, &requirements).await;
    let settle_duration = settle_start.elapsed();
    let settle = match settle_outcome {
        Ok(s) => {
            if let Some(metrics) = &cfg.metrics {
                metrics.record_settlement(s.success, settle_duration);
            }
            s
        }
        Err(e) => {
            if let Some(metrics) = &cfg.metrics {
                metrics.record_settlement(false, settle_duration);
            }
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
                network: cfg.chain.network.to_owned(),
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
        tracing::warn!(
            target: "kite_x402::audit",
            event = "settlement_failure",
            uri = %resource_url,
            error_reason = ?settle.error_reason,
            "Payment settlement audit: failed"
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
    tracing::info!(
        target: "kite_x402::audit",
        event = "settlement_success",
        uri = %resource_url,
        tx = %settle.transaction,
        network = %settle.network,
        payer = ?settle.payer,
        amount = ?settle.amount,
        "Payment settlement audit: confirmed"
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
    let cache_control = match parts
        .headers
        .get(header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
    {
        Some(existing) if !existing.is_empty() => format!("{existing}, private"),
        _ => "private".to_owned(),
    };
    parts.headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_str(&cache_control)
            .unwrap_or_else(|_| HeaderValue::from_static("private")),
    );

    Response::from_parts(parts, body)
}

#[cfg(test)]
mod tests {
    //! Unit tests for the parts of the gate that do not need a working
    //! facilitator: requirement building, the two response builders, and every
    //! branch that returns before `/verify` is called. The inner service is a
    //! stub so we can prove it is (not) reached. Full verify/settle flows are
    //! covered by `tests/payment_flow.rs`.

    use std::{
        convert::Infallible,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use axum::{body::to_bytes, middleware::from_fn_with_state};
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde_json::{json, Value};
    use tower::{service_fn, util::BoxCloneService, ServiceBuilder, ServiceExt};

    use super::*;
    use crate::{
        kite::{KITE_MAINNET, KITE_TESTNET},
        types::{PaymentPayload, SettleResponse},
    };

    const PAY_TO: &str = "0xC0FFEE0000000000000000000000000000C0FFEE";

    /// Nothing listens on port 1: any facilitator call fails fast with
    /// "connection refused", which is distinguishable from the branches under test.
    fn dead_facilitator() -> FacilitatorClient {
        FacilitatorClient::new("http://127.0.0.1:1")
    }

    fn config(chain: KiteChain, price: &str) -> Arc<PaymentConfig> {
        Arc::new(PaymentConfig {
            pay_to: PAY_TO.to_owned(),
            chain,
            price_usd: price.to_owned(),
            description: "Unit test service".to_owned(),
            facilitator: dead_facilitator(),
            expiration_guard: None,
            metrics: None,
            nonce_guard: None,
        })
    }

    type Svc = BoxCloneService<Request, Response, Infallible>;

    /// The gate wrapped around a stub that counts how often it is reached.
    fn gate(cfg: Arc<PaymentConfig>) -> (Svc, Arc<AtomicUsize>) {
        let reached = Arc::new(AtomicUsize::new(0));
        let counter = reached.clone();
        let svc = ServiceBuilder::new()
            .layer(from_fn_with_state(cfg, x402_payment))
            .service(service_fn(move |_req: Request| {
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, Infallible>((StatusCode::OK, "inner").into_response())
                }
            }))
            .boxed_clone();
        (svc, reached)
    }

    fn request(uri: &str, headers: &[(&str, &str)]) -> Request {
        let mut b = axum::http::Request::builder().uri(uri);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(axum::body::Body::empty()).unwrap()
    }

    fn decode_header(resp: &Response, name: &str) -> Value {
        let raw = resp
            .headers()
            .get(name)
            .unwrap_or_else(|| panic!("no {name} header"))
            .to_str()
            .unwrap();
        serde_json::from_slice(&STANDARD.decode(raw).unwrap()).unwrap()
    }

    fn payload_header(requirements: &PaymentRequirements) -> String {
        let p = PaymentPayload {
            x402_version: 2,
            resource: None,
            accepted: requirements.clone(),
            payload: json!({}),
            extensions: None,
        };
        STANDARD.encode(serde_json::to_vec(&p).unwrap())
    }

    // ---- PaymentConfig::requirements --------------------------------------

    #[test]
    fn requirements_for_testnet() {
        let r = config(KITE_TESTNET, "0.001").requirements().unwrap();
        assert_eq!(r.scheme, "exact");
        assert_eq!(r.network, "eip155:2368");
        assert_eq!(r.amount, "1000000000000000");
        assert_eq!(r.asset, KITE_TESTNET.asset_address);
        assert_eq!(r.pay_to, PAY_TO);
        assert_eq!(r.max_timeout_seconds, 60);
        assert_eq!(r.extra, Some(json!({ "name": "pieUSD", "version": "1" })));
    }

    #[test]
    fn requirements_for_mainnet() {
        let r = config(KITE_MAINNET, "$1.50").requirements().unwrap();
        assert_eq!(r.network, "eip155:2366");
        assert_eq!(r.amount, "1500000");
        assert_eq!(r.asset, KITE_MAINNET.asset_address);
        assert_eq!(r.extra.unwrap()["name"], "Bridged USDC (Kite AI)");
    }

    #[test]
    fn requirements_are_deterministic() {
        let c = config(KITE_TESTNET, "0.25");
        assert_eq!(c.requirements().unwrap(), c.requirements().unwrap());
    }

    #[test]
    fn requirements_report_bad_prices_with_context() {
        for bad in ["", "abc", "-1", "0", "0.0000001", "1e3"] {
            let err = config(KITE_MAINNET, bad).requirements().unwrap_err();
            assert!(
                err.starts_with("invalid PRICE_USD configured on the server: "),
                "{bad:?}: {err}"
            );
        }
    }

    #[test]
    fn config_is_clone_and_debug() {
        let c = config(KITE_TESTNET, "0.001");
        let d = (*c).clone();
        assert_eq!(d.pay_to, PAY_TO);
        assert!(format!("{d:?}").contains("Unit test service"));
    }

    // ---- response builders -------------------------------------------------

    fn requirements() -> PaymentRequirements {
        config(KITE_TESTNET, "0.001").requirements().unwrap()
    }

    #[tokio::test]
    async fn payment_required_response_has_status_headers_and_empty_body() {
        let resp = payment_required_response(requirements(), "/v1/x".into(), "desc".into(), None);
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(resp.headers()[header::CONTENT_TYPE], "application/json");
        assert!(resp.headers().get("PAYMENT-RESPONSE").is_none());

        let challenge = decode_header(&resp, "PAYMENT-REQUIRED");
        assert_eq!(challenge["x402Version"], 2);
        assert!(challenge.get("error").is_none());
        assert_eq!(challenge["resource"]["url"], "/v1/x");
        assert_eq!(challenge["resource"]["description"], "desc");
        assert_eq!(challenge["resource"]["mimeType"], "application/json");
        assert_eq!(challenge["accepts"][0]["payTo"], PAY_TO);

        assert_eq!(
            &to_bytes(resp.into_body(), usize::MAX).await.unwrap()[..],
            b"{}"
        );
    }

    #[test]
    fn payment_required_response_includes_the_error_when_given() {
        let resp = payment_required_response(
            requirements(),
            "/v1/x".into(),
            "d".into(),
            Some("because".into()),
        );
        assert_eq!(decode_header(&resp, "PAYMENT-REQUIRED")["error"], "because");
    }

    #[test]
    fn payment_required_response_survives_unusual_text() {
        // base64 output is always a valid header value, whatever the inputs.
        let resp = payment_required_response(
            requirements(),
            "/v1/ünï?q=\n\t\"x\"".into(),
            "line1\nline2 — \u{1F4B8}".into(),
            Some("err\r\nInjected: header".into()),
        );
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(resp.headers().get("Injected").is_none());
        assert_eq!(
            decode_header(&resp, "PAYMENT-REQUIRED")["error"],
            "err\r\nInjected: header"
        );
    }

    #[tokio::test]
    async fn settlement_failure_response_shape() {
        let settle = SettleResponse {
            success: false,
            error_reason: Some("reverted".into()),
            error_message: None,
            payer: Some("0xp".into()),
            transaction: String::new(),
            network: "eip155:2368".into(),
            amount: None,
        };
        let resp = settlement_failure_response(&settle);

        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
        assert!(resp.headers().get("PAYMENT-REQUIRED").is_none());
        let receipt = decode_header(&resp, "PAYMENT-RESPONSE");
        assert_eq!(receipt["success"], false);
        assert_eq!(receipt["errorReason"], "reverted");
        assert_eq!(receipt["payer"], "0xp");
        assert_eq!(
            &to_bytes(resp.into_body(), usize::MAX).await.unwrap()[..],
            b"{}"
        );
    }

    // ---- branches that return before /verify --------------------------------

    #[tokio::test]
    async fn missing_header_returns_a_plain_challenge_without_reaching_the_inner_service() {
        let (svc, reached) = gate(config(KITE_TESTNET, "0.001"));
        let resp = svc.oneshot(request("/anything", &[])).await.unwrap();

        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(decode_header(&resp, "PAYMENT-REQUIRED")
            .get("error")
            .is_none());
        assert_eq!(reached.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn resource_url_falls_back_to_the_request_uri_without_original_uri() {
        let (svc, _) = gate(config(KITE_TESTNET, "0.001"));
        let resp = svc.oneshot(request("/some/path?x=1", &[])).await.unwrap();
        assert_eq!(
            decode_header(&resp, "PAYMENT-REQUIRED")["resource"]["url"],
            "/some/path?x=1"
        );
    }

    #[tokio::test]
    async fn resource_url_prefers_the_original_uri_extension() {
        let (svc, _) = gate(config(KITE_TESTNET, "0.001"));
        let mut req = request("/stripped", &[]);
        req.extensions_mut()
            .insert(OriginalUri("/v1/stripped?a=b".parse().unwrap()));
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(
            decode_header(&resp, "PAYMENT-REQUIRED")["resource"]["url"],
            "/v1/stripped?a=b"
        );
    }

    #[tokio::test]
    async fn undecodable_header_is_rejected_as_an_invalid_signature() {
        for name in ["PAYMENT-SIGNATURE", "X-PAYMENT"] {
            let (svc, reached) = gate(config(KITE_TESTNET, "0.001"));
            let resp = svc
                .oneshot(request("/x", &[(name, "%%%not-base64%%%")]))
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED, "{name}");
            assert_eq!(
                decode_header(&resp, "PAYMENT-REQUIRED")["error"],
                "Invalid payment signature",
                "{name}"
            );
            assert_eq!(reached.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn requirement_mismatch_is_rejected_before_the_facilitator_is_contacted() {
        // If the gate had called the (dead) facilitator the error would say
        // "facilitator verify unavailable" instead.
        let cfg = config(KITE_TESTNET, "0.001");
        let mut wrong = cfg.requirements().unwrap();
        wrong.amount = "1".into();
        let (svc, reached) = gate(cfg);

        let resp = svc
            .oneshot(request(
                "/x",
                &[("PAYMENT-SIGNATURE", &payload_header(&wrong))],
            ))
            .await
            .unwrap();

        assert_eq!(
            decode_header(&resp, "PAYMENT-REQUIRED")["error"],
            "No matching payment requirements"
        );
        assert_eq!(reached.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn matching_payment_with_dead_facilitator_is_402_unavailable_and_never_runs_the_handler()
    {
        let cfg = config(KITE_TESTNET, "0.001");
        let good = cfg.requirements().unwrap();
        let (svc, reached) = gate(cfg);

        let resp = svc
            .oneshot(request(
                "/x",
                &[("PAYMENT-SIGNATURE", &payload_header(&good))],
            ))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        let err = decode_header(&resp, "PAYMENT-REQUIRED")["error"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(err.starts_with("facilitator verify unavailable: "), "{err}");
        assert_eq!(reached.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn invalid_server_price_is_a_500_json_error_even_when_a_payment_is_attached() {
        let (svc, reached) = gate(config(KITE_TESTNET, "not-a-price"));
        let resp = svc
            .oneshot(request("/x", &[("PAYMENT-SIGNATURE", "whatever")]))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(resp.headers().get("PAYMENT-REQUIRED").is_none());
        let body: Value =
            serde_json::from_slice(&to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap();
        assert!(body["error"]
            .as_str()
            .unwrap()
            .contains("invalid PRICE_USD"));
        assert_eq!(reached.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn header_names_are_case_insensitive() {
        let cfg = config(KITE_TESTNET, "0.001");
        let mut wrong = cfg.requirements().unwrap();
        wrong.pay_to = "0xsomeoneelse".into();
        let (svc, _) = gate(cfg);
        let resp = svc
            .oneshot(request(
                "/x",
                &[("payment-signature", &payload_header(&wrong))],
            ))
            .await
            .unwrap();
        // Read as a payment (and rejected for its content), not ignored as absent.
        assert_eq!(
            decode_header(&resp, "PAYMENT-REQUIRED")["error"],
            "No matching payment requirements"
        );
    }

    #[tokio::test]
    async fn expired_authorization_is_rejected_before_facilitator_call() {
        let guard = crate::expiration::ExpirationGuardConfig::new(5, 5);
        let cfg = Arc::new(
            PaymentConfig::new(
                PAY_TO,
                KITE_TESTNET,
                "0.001",
                "Unit test service",
                dead_facilitator(),
            )
            .with_expiration_guard(guard),
        );
        let reqs = cfg.requirements().unwrap();
        let payload = PaymentPayload {
            x402_version: 2,
            resource: None,
            accepted: reqs,
            payload: json!({
                "authorization": {
                    "validAfter": "0",
                    "validBefore": "1000",
                }
            }),
            extensions: None,
        };
        let encoded = STANDARD.encode(serde_json::to_vec(&payload).unwrap());

        let (svc, reached) = gate(cfg);
        let resp = svc
            .oneshot(request("/v1/data", &[("PAYMENT-SIGNATURE", &encoded)]))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        assert_eq!(reached.load(Ordering::SeqCst), 0);
        let header = decode_header(&resp, "PAYMENT-REQUIRED");
        assert!(header["error"].as_str().unwrap().contains("expired"));
    }

    #[tokio::test]
    async fn middleware_records_metrics_on_unauthenticated_request() {
        let metrics = Arc::new(crate::metrics::PaymentMetrics::new());
        let cfg = Arc::new(
            PaymentConfig::new(
                PAY_TO,
                KITE_TESTNET,
                "0.001",
                "Unit test service",
                dead_facilitator(),
            )
            .with_metrics(metrics.clone()),
        );

        let (svc, _) = gate(cfg);
        let resp = svc.oneshot(request("/v1/data", &[])).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);

        let snap = metrics.snapshot();
        assert_eq!(snap.requests_total, 1);
        assert_eq!(snap.challenges_total, 1);
        assert_eq!(snap.verifications_success, 0);
        assert_eq!(snap.settlements_success, 0);
    }

    #[tokio::test]
    async fn failed_verification_does_not_poison_the_authorization() {
        let guard = Arc::new(crate::nonce_guard::PaymentNonceReplayGuard::new(100, 60));
        let cfg = Arc::new(
            PaymentConfig::new(
                PAY_TO,
                KITE_TESTNET,
                "0.001",
                "Unit test service",
                dead_facilitator(),
            )
            .with_nonce_guard(guard),
        );
        let reqs = cfg.requirements().unwrap();
        let payload = PaymentPayload {
            x402_version: 2,
            resource: None,
            accepted: reqs,
            payload: json!({
                "authorization": {
                    "nonce": "0xreplayed_nonce_123"
                }
            }),
            extensions: None,
        };
        let encoded = STANDARD.encode(serde_json::to_vec(&payload).unwrap());

        let (svc, reached) = gate(cfg);

        // A verification failure must not consume the authorization.
        let resp1 = svc
            .clone()
            .oneshot(request("/v1/data", &[("PAYMENT-SIGNATURE", &encoded)]))
            .await
            .unwrap();
        assert_eq!(resp1.status(), StatusCode::PAYMENT_REQUIRED);
        let header1 = decode_header(&resp1, "PAYMENT-REQUIRED");
        assert!(!header1["error"]
            .as_str()
            .unwrap()
            .contains("already been used"));

        // The same authorization reaches verification again.
        let resp2 = svc
            .oneshot(request("/v1/data", &[("PAYMENT-SIGNATURE", &encoded)]))
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::PAYMENT_REQUIRED);
        assert_eq!(reached.load(Ordering::SeqCst), 0);
        let header2 = decode_header(&resp2, "PAYMENT-REQUIRED");
        assert!(header2["error"]
            .as_str()
            .unwrap()
            .contains("facilitator verify unavailable"));
    }
}
