//! The x402 payment gate: verify before the protected handler runs, settle
//! only after it answers with a status below 400.
//!
//! See the [crate-level docs][crate] for the deliberate choice to report
//! every verify/settle problem — including the facilitator being
//! unreachable — as `402 Payment Required`, matching the Go SDK rather than
//! the TypeScript SDK's `500`/`502` split.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{OriginalUri, Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use serde_json::json;

use crate::{
    facilitator::FacilitatorClient,
    kite::{KiteChain, KITE_MAINNET, KITE_TESTNET},
    settlement_ledger::SettlementReconciliation,
    types::{PaymentPayload, PaymentRequired, PaymentRequirements, ResourceInfo},
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
    /// Optional settlement ledger that retains settle outcomes for
    /// reconciliation. Recording is local to the process, exactly like the
    /// other in-memory guards.
    pub settlement_ledger: Option<Arc<crate::settlement_ledger::SettlementLedger>>,
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
            settlement_ledger: None,
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

    /// Retains settle outcomes in the given ledger for post-settlement
    /// reconciliation and auditing. Attempts whose on-chain outcome is unknown
    /// (a settle transport error) are recorded as failures so an operator can
    /// find and reconcile them; a later confirmation with the same network and
    /// transaction hash replaces that record.
    #[must_use]
    pub fn with_settlement_ledger(
        mut self,
        ledger: Arc<crate::settlement_ledger::SettlementLedger>,
    ) -> Self {
        self.settlement_ledger = Some(ledger);
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
    requirements: &[PaymentRequirements],
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
        accepts: requirements.to_vec(),
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

/// Builds the absolute resource URL advertised in a 402 challenge.
///
/// A request URI that is already absolute is kept. Otherwise the `Host`
/// header and, when it is `http` or `https`, the first `X-Forwarded-Proto`
/// value are used. In-process calls that carry neither stay on the path, so
/// a missing host never invents one.
fn absolute_resource_url(req: &Request, path_and_query: &str) -> String {
    if path_and_query.starts_with("http://") || path_and_query.starts_with("https://") {
        return path_and_query.to_owned();
    }
    if !path_and_query.starts_with('/') {
        return path_and_query.to_owned();
    }
    let Some(host) = req
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .filter(|host| is_resource_host(host))
    else {
        return path_and_query.to_owned();
    };
    let scheme = forwarded_scheme(req).unwrap_or("http");
    format!("{scheme}://{host}{path_and_query}")
}

/// Accepts a host or host:port and rejects anything that could change the URL
/// structure (spaces, slashes, userinfo).
fn is_resource_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 262
        && host
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'/' && b != b'\\' && b != b'@')
}

fn forwarded_scheme(req: &Request) -> Option<&'static str> {
    let value = req
        .headers()
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())?;
    match value.split(',').next()?.trim() {
        scheme if scheme.eq_ignore_ascii_case("https") => Some("https"),
        scheme if scheme.eq_ignore_ascii_case("http") => Some("http"),
        _ => None,
    }
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The settled amount in atomic units, preferring the facilitator's receipt and
/// falling back to the advertised requirement. An unparsable or overflowing
/// value becomes `0` rather than failing the request: ledger volume is a
/// diagnostic, not a money decision.
fn atomic_amount(requirements: &PaymentRequirements, settle: &crate::types::SettleResponse) -> u64 {
    fn parse(value: &str) -> Option<u64> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return None;
        }
        trimmed
            .parse::<u128>()
            .ok()
            .and_then(|value| u64::try_from(value).ok())
    }

    settle
        .amount
        .as_deref()
        .and_then(parse)
        .or_else(|| parse(&requirements.amount))
        .unwrap_or(0)
}

fn reconciliation_details(
    payload: &PaymentPayload,
    requirements: &PaymentRequirements,
) -> Option<SettlementReconciliation> {
    const MAX_UINT256: &str = crate::kite::MAX_UINT256_DECIMAL;

    fn fixed_hex(value: &str, bytes: usize) -> Option<String> {
        let digits = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))?;
        (digits.len() == bytes * 2 && digits.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| format!("0x{}", digits.to_ascii_lowercase()))
    }

    if requirements.scheme != "exact" {
        return None;
    }
    let chain = [KITE_MAINNET, KITE_TESTNET].into_iter().find(|chain| {
        chain.network == requirements.network
            && chain
                .asset_address
                .eq_ignore_ascii_case(&requirements.asset)
    })?;
    let authorization = payload.payload.get("authorization")?;
    let payer = fixed_hex(authorization.get("from")?.as_str()?, 20)?;
    let pay_to = fixed_hex(authorization.get("to")?.as_str()?, 20)?;
    if !pay_to.eq_ignore_ascii_case(&requirements.pay_to) {
        return None;
    }
    let nonce = fixed_hex(authorization.get("nonce")?.as_str()?, 32)?;
    let value = authorization.get("value")?.as_str()?;
    let amount = value.trim_start_matches('0');
    if amount.is_empty()
        || amount.len() > MAX_UINT256.len()
        || !amount.bytes().all(|b| b.is_ascii_digit())
        || (amount.len() == MAX_UINT256.len() && amount > MAX_UINT256)
    {
        return None;
    }

    Some(SettlementReconciliation {
        network: chain.network.to_owned(),
        asset: chain.asset_address.to_ascii_lowercase(),
        payer,
        pay_to,
        amount_atomic: amount.to_owned(),
        nonce,
    })
}

/// 使用买家匹配的付款选项记录结算结果。只有未获得交易哈希时才附上链上对账参数。
fn record_settlement(
    cfg: &PaymentConfig,
    payload: &PaymentPayload,
    requirements: &PaymentRequirements,
    verified_payer: Option<&str>,
    settle: &crate::types::SettleResponse,
) {
    let Some(ledger) = cfg.settlement_ledger.as_ref() else {
        return;
    };
    let payer = settle
        .payer
        .as_deref()
        .filter(|payer| !payer.trim().is_empty())
        .or(verified_payer)
        .unwrap_or_default();
    // Trim before storing: the emptiness check above already treats
    // surrounding whitespace as insignificant, and `transaction_key` uses the
    // network as half of the ledger's identity. Keeping raw padding here would
    // make the same network hash to two different identities.
    let network = if settle.network.trim().is_empty() {
        requirements.network.trim().to_owned()
    } else {
        settle.network.trim().to_owned()
    };
    let record = crate::settlement_ledger::SettlementRecord {
        tx_hash: settle.transaction.clone(),
        payer: payer.to_owned(),
        pay_to: requirements.pay_to.clone(),
        amount: atomic_amount(requirements, settle),
        network,
        timestamp_secs: unix_now_secs(),
        success: settle.success,
        error_reason: settle.error_reason.clone(),
    };
    tracing::debug!(
        tx = %record.tx_hash,
        success = record.success,
        network = %record.network,
        "Recording settlement outcome in ledger"
    );
    let reconciliation = if !record.success && record.tx_hash.trim().is_empty() {
        reconciliation_details(payload, requirements)
    } else {
        None
    };
    ledger.record_with_reconciliation(record, reconciliation);
}

/// Shared gate engine.
///
/// `options` are the wire-level requirements this route accepts; the client's
/// `accepted` must match one of them. Both the single-option and multi-option
/// entry points funnel through here, so verify/settle logic is written once.
async fn payment_gate_inner(
    cfg: &PaymentConfig,
    options: &[PaymentRequirements],
    req: Request,
    next: Next,
) -> Response {
    // Prefer the pre-`nest()` URI (e.g. `/v1/forecast`) so the 402 challenge
    // describes the path the client actually requested, not the
    // `/v1`-stripped path the proxy handler sees. Attach scheme and host when
    // the request has them, matching the absolute `resource.url` the official
    // x402 SDKs put on the wire.
    let path_and_query = req
        .extensions()
        .get::<OriginalUri>()
        .map(|OriginalUri(uri)| uri.to_string())
        .unwrap_or_else(|| req.uri().to_string());
    let resource_url = absolute_resource_url(&req, &path_and_query);
    let method = req.method().clone();

    if let Some(metrics) = &cfg.metrics {
        metrics.record_request();
    }

    tracing::debug!(
        method = %method,
        uri = %resource_url,
        "Processing request through x402 payment gate"
    );

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
            options = ?options,
            "402 challenge requirements details"
        );
        if let Some(metrics) = &cfg.metrics {
            metrics.record_challenge();
        }
        return payment_required_response(options, resource_url, cfg.description.clone(), None);
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
            options,
            resource_url,
            cfg.description.clone(),
            Some("Invalid payment signature".to_owned()),
        );
    };

    // Find which advertised option the client chose. Single-option callers
    // pass a one-element slice, making this equivalent to the old `==` check.
    let Some(requirements) =
        crate::payment_options::find_matching_requirements(&payload.accepted, options)
    else {
        tracing::warn!(
            uri = %resource_url,
            expected = ?options,
            actual = ?payload.accepted,
            "Payment requirements mismatch; returning 402"
        );
        if let Some(metrics) = &cfg.metrics {
            metrics.record_challenge();
        }
        return payment_required_response(
            options,
            resource_url,
            cfg.description.clone(),
            Some("No matching payment requirements".to_owned()),
        );
    };

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

            // An authorization object that carries no usable validity window
            // cannot be checked, so it must not be let through: skipping the
            // guard here would turn a configured expiration check into a no-op
            // for any client that simply omits `validAfter`/`validBefore`
            // (or sends them as non-integers). EIP-3009 requires both fields,
            // so rejecting is the only interpretation that keeps the guard's
            // promise. Payloads without an `authorization` object at all are a
            // different scheme and still skip the guard on purpose.
            let (Some(valid_after), Some(valid_before)) = (valid_after, valid_before) else {
                tracing::warn!(
                    uri = %resource_url,
                    "Payment authorization has a missing or malformed validity window; returning 402"
                );
                if let Some(metrics) = &cfg.metrics {
                    metrics.record_challenge();
                }
                return payment_required_response(
                    options,
                    resource_url,
                    cfg.description.clone(),
                    Some("Payment authorization is missing a valid time window".to_owned()),
                );
            };

            if let Err(e) = guard.validate_now(valid_after, valid_before) {
                tracing::warn!(
                    uri = %resource_url,
                    error = %e,
                    "Payment authorization rejected by expiration guard; returning 402"
                );
                return payment_required_response(
                    options,
                    resource_url,
                    cfg.description.clone(),
                    Some(e.to_string()),
                );
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
                    options,
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

    let verify_outcome = cfg.facilitator.verify(&payload, requirements).await;
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
                options,
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
            options,
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
    let settle_outcome = cfg.facilitator.settle(&payload, requirements).await;
    let settle_duration = settle_start.elapsed();
    let mut settle = match settle_outcome {
        Ok(settle) => settle,
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
                network: requirements.network.clone(),
                amount: None,
            };
            // The settle transport failed, so the on-chain outcome is unknown
            // rather than known-failed. Record it (no transaction hash) so an
            // operator can find and reconcile this attempt instead of only
            // having it in a log line.
            record_settlement(
                cfg,
                &payload,
                requirements,
                verify.payer.as_deref(),
                &failure,
            );
            return settlement_failure_response(&failure);
        }
    };

    if settle.success {
        let receipt_error = if settle.network != requirements.network {
            Some("Settlement receipt network does not match the selected payment option")
        } else if settle.transaction.trim().is_empty() {
            Some("Settlement receipt is missing a transaction ID")
        } else {
            None
        };
        if let Some(message) = receipt_error {
            // Preserve the reported network and transaction for reconciliation.
            settle.success = false;
            settle.error_reason = Some("invalid_settlement_receipt".to_owned());
            settle.error_message =
                Some(format!("{message}. Reconcile the payment before retrying."));
        }
    }
    if let Some(metrics) = &cfg.metrics {
        metrics.record_settlement(settle.success, settle_duration);
    }

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
        record_settlement(
            cfg,
            &payload,
            requirements,
            verify.payer.as_deref(),
            &settle,
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
    record_settlement(
        cfg,
        &payload,
        requirements,
        verify.payer.as_deref(),
        &settle,
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
/// This is the single-option gate: it builds one `PaymentRequirements` from
/// the route's static config (one price/network/asset) and delegates to the
/// shared engine. Existing callers keep working unchanged. Behavior:
///
/// 1. No `PAYMENT-SIGNATURE` (or legacy `X-PAYMENT`) header → `402` with a
///    `PAYMENT-REQUIRED` header describing how to pay.
/// 2. Header present but doesn't decode, or doesn't match this route's
///    price/network/asset/payTo → `402` with `error` explaining why.
/// 3. Facilitator `/verify` says invalid, or the facilitator could not be
///    reached at all → `402` with `error` set to the reason (see the
///    crate-level docs for why facilitator-unreachable is also a `402`).
/// 4. Verified → the inner handler runs. If it answers `>= 400`, that
///    response is returned unchanged and **no settlement is attempted**.
/// 5. If it answers `< 400`, `/settle` is called. A successful receipt must
///    identify the selected network and carry a nonblank transaction ID. It
///    is attached as `PAYMENT-RESPONSE` and `Cache-Control` gets `private`
///    merged in. On failure, a `402` with `PAYMENT-RESPONSE` (`success: false`)
///    is returned instead of the handler's response.
pub async fn x402_payment(
    State(cfg): State<Arc<PaymentConfig>>,
    req: Request,
    next: Next,
) -> Response {
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
    payment_gate_inner(&cfg, std::slice::from_ref(&requirements), req, next).await
}

/// Configuration for the multi-option gate: the shared infrastructure (who
/// receives payment, the facilitator, guards, metrics, description) plus the
/// list of payment options to advertise on this route.
///
/// `PaymentOption` values are rendered into wire requirements at request time
/// using the same integer price parser as the single-option gate.
#[derive(Clone, Debug)]
pub struct MultiPaymentConfig {
    /// Address that receives payments (shared by every option).
    pub pay_to: String,
    /// The payment options advertised on this route.
    pub options: Vec<crate::payment_options::PaymentOption>,
    /// Shown to the buyer in the 402 challenge.
    pub description: String,
    /// Client for the Kite facilitator's `/verify` and `/settle`.
    pub facilitator: FacilitatorClient,
    /// Optional expiration guard.
    pub expiration_guard: Option<crate::expiration::ExpirationGuardConfig>,
    /// Optional metrics collector.
    pub metrics: Option<Arc<crate::metrics::PaymentMetrics>>,
    /// Optional nonce replay guard.
    pub nonce_guard: Option<Arc<crate::nonce_guard::PaymentNonceReplayGuard>>,
    /// Optional settlement ledger shared with the single-option gate.
    pub settlement_ledger: Option<Arc<crate::settlement_ledger::SettlementLedger>>,
}

impl MultiPaymentConfig {
    /// Creates a multi-option config with no optional guards or metrics.
    pub fn new(
        pay_to: impl Into<String>,
        options: Vec<crate::payment_options::PaymentOption>,
        description: impl Into<String>,
        facilitator: FacilitatorClient,
    ) -> Self {
        Self {
            pay_to: pay_to.into(),
            options,
            description: description.into(),
            facilitator,
            expiration_guard: None,
            metrics: None,
            nonce_guard: None,
            settlement_ledger: None,
        }
    }

    /// Retains settle outcomes in the given ledger, like the single-option
    /// [`PaymentConfig::with_settlement_ledger`].
    #[must_use]
    pub fn with_settlement_ledger(
        mut self,
        ledger: Arc<crate::settlement_ledger::SettlementLedger>,
    ) -> Self {
        self.settlement_ledger = Some(ledger);
        self
    }

    /// Builds a `PaymentConfig` view over this config's shared infrastructure.
    /// The gate engine only reads these fields; options are passed separately.
    fn as_base(&self) -> PaymentConfig {
        PaymentConfig {
            pay_to: self.pay_to.clone(),
            // `chain`/`price_usd` are unused by the engine on the multi path
            // (options carry their own chains). Keep them coherent anyway.
            chain: self
                .options
                .first()
                .map(|o| o.chain)
                .unwrap_or(crate::kite::KITE_TESTNET),
            price_usd: String::new(),
            description: self.description.clone(),
            facilitator: self.facilitator.clone(),
            expiration_guard: self.expiration_guard,
            metrics: self.metrics.clone(),
            nonce_guard: self.nonce_guard.clone(),
            settlement_ledger: self.settlement_ledger.clone(),
        }
    }
}

/// Multi-option payment gate. Advertises every configured option in the 402
/// challenge and accepts a client payment matching any one of them. Uses the
/// exact same verify/settle engine as [`x402_payment`].
pub async fn x402_payment_multi(
    State(cfg): State<Arc<MultiPaymentConfig>>,
    req: Request,
    next: Next,
) -> Response {
    let options = match crate::payment_options::requirements_all(&cfg.options, &cfg.pay_to) {
        Ok(o) if !o.is_empty() => o,
        Ok(_) => {
            tracing::error!("MultiPaymentConfig has no payment options configured");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "no payment options configured" })),
            )
                .into_response();
        }
        Err(msg) => {
            tracing::error!(error = %msg, "Failed to compute payment requirements");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": msg })),
            )
                .into_response();
        }
    };
    let base = cfg.as_base();
    payment_gate_inner(&base, &options, req, next).await
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
            settlement_ledger: None,
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
    fn a_price_no_authorization_could_carry_is_reported_not_advertised() {
        // One unit above 2^256 - 1. It is a positive decimal with exactly
        // mainnet's six fractional digits, so nothing else is wrong with it;
        // an EIP-3009 `value` still cannot hold it.
        let max = crate::kite::MAX_UINT256_DECIMAL;
        let fraction = max[max.len() - 6..].parse::<u32>().unwrap() + 1;
        let too_large = format!("{}.{fraction:06}", &max[..max.len() - 6]);
        let err = config(KITE_MAINNET, &too_large).requirements().unwrap_err();
        assert!(
            err.starts_with("invalid PRICE_USD configured on the server: ")
                && err.contains("more than a uint256 can hold"),
            "{err}"
        );
    }

    #[test]
    fn config_is_clone_and_debug() {
        let c = config(KITE_TESTNET, "0.001");
        let d = (*c).clone();
        assert_eq!(d.pay_to, PAY_TO);
        assert!(format!("{d:?}").contains("Unit test service"));
    }

    #[test]
    fn reconciliation_details_require_a_supported_payment_and_valid_authorization() {
        let req = config(KITE_MAINNET, "0.001").requirements().unwrap();
        let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        let payer = "0x11223344556677889900aabbccddeeff00112233";
        let nonce = format!("0x{}", "55".repeat(32));
        let mut payment = PaymentPayload {
            x402_version: 2,
            resource: None,
            accepted: req.clone(),
            payload: json!({
                "authorization": {
                    "from": payer,
                    "to": req.pay_to,
                    "value": format!("0{max}"),
                    "nonce": nonce,
                },
            }),
            extensions: None,
        };
        let details = reconciliation_details(&payment, &req).unwrap();
        assert_eq!(details.network, KITE_MAINNET.network);
        assert_eq!(details.amount_atomic, max);

        let other_asset = PaymentRequirements {
            asset: KITE_TESTNET.asset_address.to_owned(),
            ..req.clone()
        };
        assert!(reconciliation_details(&payment, &other_asset).is_none());
        for invalid in [
            "0",
            "1.5",
            "115792089237316195423570985008687907853269984665640564039457584007913129639936",
        ] {
            payment.payload["authorization"]["value"] = json!(invalid);
            assert!(reconciliation_details(&payment, &req).is_none());
        }
        payment.payload["authorization"]["value"] = json!("1000");
        payment.payload["authorization"]["to"] = json!(payer);
        assert!(reconciliation_details(&payment, &req).is_none());
        payment.payload["authorization"]["to"] = json!(req.pay_to);
        payment.payload["authorization"]["nonce"] = json!("0xabc");
        assert!(reconciliation_details(&payment, &req).is_none());
    }

    #[test]
    fn atomic_amount_rejects_overflow_instead_of_saturating() {
        // The doc contract says an unparsable OR overflowing value becomes 0,
        // because ledger volume is only a diagnostic. A `u64` overflow that is
        // nevertheless a valid `u128` must not be recorded as u64::MAX — that
        // would inject a fake, astronomically large settlement into the ledger
        // and into summary().total_settled_volume.
        let req = requirements();
        let settle = |amount: Option<&str>| SettleResponse {
            success: true,
            error_reason: None,
            error_message: None,
            payer: None,
            transaction: "0xdead".into(),
            network: req.network.clone(),
            amount: amount.map(str::to_owned),
        };

        // A valid u128 that does not fit u64 must NOT become u64::MAX — that
        // would inject a fake, astronomically huge settlement into the ledger.
        // It is unrepresentable, so it falls back to the advertised requirement.
        let overflow = "18446744073709551616"; // 2^64
        let advertised = req.amount.parse::<u64>().unwrap();
        assert_eq!(atomic_amount(&req, &settle(Some(overflow))), advertised);
        assert_ne!(atomic_amount(&req, &settle(Some(overflow))), u64::MAX);
        // When the advertised requirement also overflows, the documented zero
        // is the final fallback — not u64::MAX.
        let mut big_req = req.clone();
        big_req.amount = overflow.into();
        assert_eq!(atomic_amount(&big_req, &settle(None)), 0);
        // Normal values still parse. An unparsable receipt amount also falls
        // back to the advertised requirement (by design).
        assert_eq!(atomic_amount(&req, &settle(Some(" 42 "))), 42);
        assert_eq!(atomic_amount(&req, &settle(Some("1.5"))), advertised);
    }

    #[test]
    fn settle_network_is_trimmed_before_it_becomes_a_ledger_identity() {
        use crate::settlement_ledger::SettlementLedger;
        use std::sync::Arc;

        let ledger = Arc::new(SettlementLedger::new(100));
        let cfg = PaymentConfig {
            pay_to: PAY_TO.to_owned(),
            chain: KITE_TESTNET,
            price_usd: "0.001".to_owned(),
            description: "test".to_owned(),
            facilitator: dead_facilitator(),
            expiration_guard: None,
            metrics: None,
            nonce_guard: None,
            settlement_ledger: Some(ledger.clone()),
        };
        let req = requirements();
        let clean_network = req.network.clone();
        let settle = SettleResponse {
            success: false,
            error_reason: Some("boom".to_owned()),
            error_message: None,
            payer: None,
            transaction: "0xdead".to_owned(),
            // A facilitator echoing the network with stray whitespace. The
            // emptiness check trims, so the value is clearly intended to be
            // whitespace-tolerant — but the raw value is what gets stored as
            // half of the ledger's identity key.
            network: format!("  {clean_network}  "),
            amount: None,
        };
        // `record_settlement` now also takes the decoded payload so it can
        // attach on-chain reconciliation details when a settlement comes back
        // without a transaction hash. This case has a hash, so the payload is
        // only a required argument.
        let payload = PaymentPayload {
            x402_version: 2,
            resource: None,
            accepted: req.clone(),
            payload: serde_json::Value::Null,
            extensions: None,
        };
        record_settlement(&cfg, &payload, &req, Some("0xabc"), &settle);

        assert!(
            ledger.get_by_network_tx(&clean_network, "0xdead").is_some(),
            "a settle network with surrounding whitespace must be stored trimmed, \
             otherwise the same network produces two different ledger identities"
        );
    }

    // ---- response builders -------------------------------------------------

    fn requirements() -> PaymentRequirements {
        config(KITE_TESTNET, "0.001").requirements().unwrap()
    }

    #[tokio::test]
    async fn payment_required_response_has_status_headers_and_empty_body() {
        let resp = payment_required_response(
            std::slice::from_ref(&requirements()),
            "/v1/x".into(),
            "desc".into(),
            None,
        );
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
            std::slice::from_ref(&requirements()),
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
            std::slice::from_ref(&requirements()),
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
    async fn resource_url_is_absolute_when_the_request_has_a_host() {
        let (svc, _) = gate(config(KITE_TESTNET, "0.001"));
        let mut req = request(
            "/v1/forecast?latitude=52.52",
            &[("host", "pay.example:8402")],
        );
        req.headers_mut()
            .insert("x-forwarded-proto", HeaderValue::from_static("https, http"));
        req.extensions_mut()
            .insert(OriginalUri("/v1/forecast?latitude=52.52".parse().unwrap()));
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(
            decode_header(&resp, "PAYMENT-REQUIRED")["resource"]["url"],
            "https://pay.example:8402/v1/forecast?latitude=52.52"
        );
    }

    #[tokio::test]
    async fn resource_url_ignores_a_host_that_could_rewrite_the_url() {
        let (svc, _) = gate(config(KITE_TESTNET, "0.001"));
        let resp = svc
            .oneshot(request("/v1/x", &[("host", "evil.example/other")]))
            .await
            .unwrap();
        assert_eq!(
            decode_header(&resp, "PAYMENT-REQUIRED")["resource"]["url"],
            "/v1/x"
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

    /// Builds a gate whose payload carries `authorization` but an unusable
    /// validity window, and returns the status, the challenge body and how
    /// often the inner service was reached.
    async fn gate_response_for_authorization(authorization: Value) -> (StatusCode, Value, usize) {
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
            payload: json!({ "authorization": authorization }),
            extensions: None,
        };
        let encoded = STANDARD.encode(serde_json::to_vec(&payload).unwrap());

        let (svc, reached) = gate(cfg);
        let resp = svc
            .oneshot(request("/v1/data", &[("PAYMENT-SIGNATURE", &encoded)]))
            .await
            .unwrap();
        let status = resp.status();
        let header = decode_header(&resp, "PAYMENT-REQUIRED");
        (status, header, reached.load(Ordering::SeqCst))
    }

    #[tokio::test]
    async fn authorization_without_validity_window_is_rejected() {
        let (status, header, reached) = gate_response_for_authorization(json!({})).await;

        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        assert_eq!(reached, 0, "the guard must reject before the inner service");
        assert!(
            header["error"]
                .as_str()
                .unwrap()
                .contains("missing a valid time window"),
            "expected an explicit time-window rejection, got {header}"
        );
    }

    #[tokio::test]
    async fn authorization_with_malformed_validity_window_is_rejected() {
        let (status, header, reached) =
            gate_response_for_authorization(json!({ "validAfter": "soon", "validBefore": -1 }))
                .await;

        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        assert_eq!(reached, 0);
        assert!(header["error"]
            .as_str()
            .unwrap()
            .contains("missing a valid time window"));
    }

    /// Positive control: the fail-closed branch must not reject payloads that
    /// do carry a checkable window. With a dead facilitator the next failure
    /// is the verify call, not the guard.
    #[tokio::test]
    async fn authorization_with_a_usable_window_still_reaches_verification() {
        let guard = crate::expiration::ExpirationGuardConfig::new(5, 5);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
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
                    "validAfter": (now - 10).to_string(),
                    "validBefore": (now + 600).to_string(),
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

        let header = decode_header(&resp, "PAYMENT-REQUIRED");
        assert!(
            header["error"]
                .as_str()
                .unwrap()
                .contains("facilitator verify unavailable"),
            "a usable window must pass the guard, got {header}"
        );
        assert_eq!(reached.load(Ordering::SeqCst), 0);
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

    // ---- multi-option gate ------------------------------------------------

    fn multi_gate(options: Vec<crate::payment_options::PaymentOption>) -> Svc {
        let cfg = Arc::new(MultiPaymentConfig::new(
            PAY_TO,
            options,
            "Multi test service",
            dead_facilitator(),
        ));
        ServiceBuilder::new()
            .layer(from_fn_with_state(cfg, x402_payment_multi))
            .service(service_fn(|_req: Request| async {
                Ok::<_, Infallible>((StatusCode::OK, "inner").into_response())
            }))
            .boxed_clone()
    }

    #[tokio::test]
    async fn multi_option_challenge_advertises_every_option() {
        let svc = multi_gate(vec![
            crate::payment_options::PaymentOption::new(KITE_TESTNET, "0.001"),
            crate::payment_options::PaymentOption::new(KITE_MAINNET, "$1.50"),
        ]);

        let resp = svc.oneshot(request("/v1/data", &[])).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        let challenge = decode_header(&resp, "PAYMENT-REQUIRED");
        let accepts = challenge["accepts"].as_array().unwrap();
        assert_eq!(accepts.len(), 2, "challenge must advertise both options");
        assert_eq!(accepts[0]["network"], KITE_TESTNET.network);
        assert_eq!(accepts[1]["network"], KITE_MAINNET.network);
    }

    #[tokio::test]
    async fn multi_option_accepts_a_client_choice_that_matches_one_option() {
        // The chosen option is the second one. A dead facilitator means verify
        // fails, but critically the gate must NOT answer "No matching payment
        // requirements" — proving the match against option #2 succeeded and
        // the request reached the facilitator stage.
        let options = vec![
            crate::payment_options::PaymentOption::new(KITE_TESTNET, "0.001"),
            crate::payment_options::PaymentOption::new(KITE_MAINNET, "$1.50"),
        ];
        let all = crate::payment_options::requirements_all(&options, PAY_TO).unwrap();
        let chosen = payload_header(&all[1]);

        let svc = multi_gate(options);
        let resp = svc
            .oneshot(request("/v1/data", &[("PAYMENT-SIGNATURE", &chosen)]))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        let challenge = decode_header(&resp, "PAYMENT-REQUIRED");
        let error = challenge["error"].as_str().unwrap();
        assert!(
            error.contains("facilitator verify unavailable"),
            "expected verify stage reached, got: {error}"
        );
        assert!(!error.contains("No matching payment requirements"));
    }

    #[tokio::test]
    async fn multi_option_rejects_a_choice_matching_no_option() {
        let options = vec![
            crate::payment_options::PaymentOption::new(KITE_TESTNET, "0.001"),
            crate::payment_options::PaymentOption::new(KITE_MAINNET, "$1.50"),
        ];
        let all = crate::payment_options::requirements_all(&options, PAY_TO).unwrap();
        let mut foreign = all[0].clone();
        foreign.network = "eip155:1".to_owned();
        let chosen = payload_header(&foreign);

        let svc = multi_gate(options);
        let resp = svc
            .oneshot(request("/v1/data", &[("PAYMENT-SIGNATURE", &chosen)]))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        let challenge = decode_header(&resp, "PAYMENT-REQUIRED");
        assert_eq!(challenge["error"], "No matching payment requirements");
    }
}
