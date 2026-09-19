//! Integration tests for the x402 payment gate + proxy, built from public
//! crate API only (as a downstream consumer would use it).
//!
//! Two lightweight mock HTTP servers (a facilitator and an upstream API)
//! are spun up on `127.0.0.1:0` with real `axum::serve`, and the app under
//! test is exercised through `tower::ServiceExt::oneshot` so no extra port
//! is needed for it.

use std::sync::{
    atomic::{AtomicBool, AtomicU32, Ordering},
    Arc,
};

use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{Request, StatusCode},
    middleware,
    response::IntoResponse,
    routing::{any, post},
    Json, Router,
};
use kite_x402_axum::{
    facilitator::FacilitatorClient,
    kite::KITE_TESTNET,
    middleware::{x402_payment, PaymentConfig},
    proxy::{proxy, UpstreamConfig},
    types::{PaymentPayload, PaymentRequirements},
    wire::{decode_payment_payload, encode_payment_required},
};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tower::ServiceExt;

/// Shared state for the mock facilitator so tests can assert what was
/// called and control what it answers.
#[derive(Default)]
struct MockFacilitator {
    verify_valid: AtomicBool,
    verify_reason: std::sync::Mutex<Option<String>>,
    settle_success: AtomicBool,
    settle_calls: AtomicU32,
}

impl MockFacilitator {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            verify_valid: AtomicBool::new(true),
            verify_reason: std::sync::Mutex::new(None),
            settle_success: AtomicBool::new(true),
            settle_calls: AtomicU32::new(0),
        })
    }
}

async fn mock_verify(
    State(state): State<Arc<MockFacilitator>>,
    Json(_body): Json<Value>,
) -> impl IntoResponse {
    let valid = state.verify_valid.load(Ordering::SeqCst);
    let reason = state.verify_reason.lock().unwrap().clone();
    Json(json!({
        "isValid": valid,
        "invalidReason": reason,
        "payer": "0xPayer0000000000000000000000000000000000",
    }))
}

async fn mock_settle(
    State(state): State<Arc<MockFacilitator>>,
    Json(_body): Json<Value>,
) -> impl IntoResponse {
    state.settle_calls.fetch_add(1, Ordering::SeqCst);
    if state.settle_success.load(Ordering::SeqCst) {
        Json(json!({
            "success": true,
            "transaction": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "network": "eip155:2368",
            "payer": "0xPayer0000000000000000000000000000000000",
        }))
    } else {
        Json(json!({
            "success": false,
            "errorReason": "settlement_failed",
            "transaction": "",
            "network": "eip155:2368",
        }))
    }
}

/// Spawns the mock facilitator and returns its base URL and shared state.
async fn spawn_facilitator() -> (String, Arc<MockFacilitator>) {
    let state = MockFacilitator::new();
    let app = Router::new()
        .route("/verify", post(mock_verify))
        .route("/settle", post(mock_settle))
        .with_state(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), state)
}

/// Spawns a mock upstream API. `status` is returned for every request, with
/// body `{"upstream": true}`.
async fn spawn_upstream(status: StatusCode) -> String {
    async fn handler(status: StatusCode) -> impl IntoResponse {
        (status, Json(json!({ "upstream": true })))
    }
    let app = Router::new().route(
        "/forecast",
        any(move || handler(status)),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

/// Builds the app under test: `/v1/{*path}` guarded by the payment
/// middleware and proxied to `upstream_base`, talking to the facilitator at
/// `facilitator_base`. Mirrors how `service/src/main.rs` wires things.
fn build_app(facilitator_base: &str, upstream_base: &str) -> Router {
    let payment_cfg = Arc::new(PaymentConfig {
        pay_to: "0xC0FFEE0000000000000000000000000000C0FFEE".to_string(),
        chain: KITE_TESTNET,
        price_usd: "0.001".to_string(),
        description: "Test wrapper".to_string(),
        facilitator: FacilitatorClient::new(facilitator_base),
    });
    let upstream_cfg = Arc::new(UpstreamConfig {
        http: reqwest::Client::new(),
        base_url: upstream_base.trim_end_matches('/').to_string(),
        auth_header: "Authorization".to_string(),
        auth_value: String::new(),
    });

    let paid = Router::new()
        .route("/{*path}", any(proxy))
        .with_state(upstream_cfg)
        .layer(middleware::from_fn_with_state(payment_cfg, x402_payment));

    Router::new().nest("/v1", paid)
}

/// Builds a matching `PAYMENT-SIGNATURE` header for the given requirements:
/// a v2 payload whose `accepted` field mirrors the server-side requirements
/// exactly, as a real client would produce after reading the 402 challenge.
fn build_payment_header(requirements: &PaymentRequirements) -> String {
    let payload = PaymentPayload {
        x402_version: 2,
        resource: None,
        accepted: requirements.clone(),
        payload: json!({ "signature": "0xsignature" }),
        extensions: None,
    };
    base64_encode_payload(&payload)
}

fn base64_encode_payload(payload: &PaymentPayload) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.encode(serde_json::to_vec(payload).unwrap())
}

/// Extracts the `PaymentRequirements` a 402 response is asking for, by
/// decoding its `PAYMENT-REQUIRED` header.
fn requirements_from_402(headers: &axum::http::HeaderMap) -> PaymentRequirements {
    let header = headers
        .get("PAYMENT-REQUIRED")
        .expect("402 response must carry PAYMENT-REQUIRED")
        .to_str()
        .unwrap();
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let bytes = STANDARD.decode(header).unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    serde_json::from_value(value["accepts"][0].clone()).unwrap()
}

#[tokio::test]
async fn healthz_style_route_outside_v1_is_free() {
    // /v1/* is the only guarded prefix; routes outside it never see the
    // middleware. Verified structurally: the payment layer is only
    // attached to the /v1 sub-router in build_app.
    let (facilitator_base, _state) = spawn_facilitator().await;
    let upstream_base = spawn_upstream(StatusCode::OK).await;
    let app = build_app(&facilitator_base, &upstream_base).route(
        "/healthz",
        axum::routing::get(|| async { Json(json!({ "ok": true })) }),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn unpaid_request_returns_402_with_payment_required_header() {
    let (facilitator_base, _state) = spawn_facilitator().await;
    let upstream_base = spawn_upstream(StatusCode::OK).await;
    let app = build_app(&facilitator_base, &upstream_base);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/forecast")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    let requirements = requirements_from_402(response.headers());
    assert_eq!(requirements.network, "eip155:2368");
    assert_eq!(requirements.amount, "1000000000000000"); // 0.001 * 10^18
    assert_eq!(
        response.headers().get("cache-control").unwrap(),
        "no-store"
    );
}

#[tokio::test]
async fn paid_request_is_verified_settled_and_proxied() {
    let (facilitator_base, facilitator_state) = spawn_facilitator().await;
    let upstream_base = spawn_upstream(StatusCode::OK).await;
    let app = build_app(&facilitator_base, &upstream_base);

    // First hit an unpaid request to learn the exact requirements.
    let probe = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/forecast")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let requirements = requirements_from_402(probe.headers());

    let header = build_payment_header(&requirements);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/forecast")
                .header("PAYMENT-SIGNATURE", header)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key("PAYMENT-RESPONSE"));
    let cache_control = response
        .headers()
        .get("cache-control")
        .map(|v| v.to_str().unwrap().to_string());
    assert!(cache_control.unwrap_or_default().contains("private"));
    assert_eq!(facilitator_state.settle_calls.load(Ordering::SeqCst), 1);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["upstream"], true);
}

#[tokio::test]
async fn upstream_failure_is_not_settled() {
    let (facilitator_base, facilitator_state) = spawn_facilitator().await;
    let upstream_base = spawn_upstream(StatusCode::INTERNAL_SERVER_ERROR).await;
    let app = build_app(&facilitator_base, &upstream_base);

    let probe = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/forecast")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let requirements = requirements_from_402(probe.headers());
    let header = build_payment_header(&requirements);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/forecast")
                .header("PAYMENT-SIGNATURE", header)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // The upstream's own failing status is passed straight through...
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    // ...and settlement must never have been attempted for a failed call.
    assert_eq!(facilitator_state.settle_calls.load(Ordering::SeqCst), 0);
    assert!(!response.headers().contains_key("PAYMENT-RESPONSE"));
}

#[tokio::test]
async fn verify_invalid_returns_402_without_calling_upstream_or_settling() {
    let (facilitator_base, facilitator_state) = spawn_facilitator().await;
    facilitator_state.verify_valid.store(false, Ordering::SeqCst);
    *facilitator_state.verify_reason.lock().unwrap() = Some("insufficient_funds".to_string());
    let upstream_base = spawn_upstream(StatusCode::OK).await;
    let app = build_app(&facilitator_base, &upstream_base);

    let probe = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/forecast")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let requirements = requirements_from_402(probe.headers());
    let header = build_payment_header(&requirements);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/forecast")
                .header("PAYMENT-SIGNATURE", header)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    assert_eq!(facilitator_state.settle_calls.load(Ordering::SeqCst), 0);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap();
    // no accidental peek at the upstream body
    assert!(body.get("upstream").is_none());
}

#[tokio::test]
async fn settlement_failure_returns_402_with_payment_response_header() {
    let (facilitator_base, facilitator_state) = spawn_facilitator().await;
    facilitator_state.settle_success.store(false, Ordering::SeqCst);
    let upstream_base = spawn_upstream(StatusCode::OK).await;
    let app = build_app(&facilitator_base, &upstream_base);

    let probe = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/forecast")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let requirements = requirements_from_402(probe.headers());
    let header = build_payment_header(&requirements);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/forecast")
                .header("PAYMENT-SIGNATURE", header)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    assert!(response.headers().contains_key("PAYMENT-RESPONSE"));
}

#[tokio::test]
async fn facilitator_unreachable_during_verify_returns_402_not_5xx() {
    // Bind then immediately drop the listener: nothing is listening on this
    // port, so any request to it is a connection failure.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = listener.local_addr().unwrap();
    drop(listener);
    let dead_facilitator = format!("http://{dead_addr}");

    let upstream_base = spawn_upstream(StatusCode::OK).await;
    let app = build_app(&dead_facilitator, &upstream_base);

    // We can't probe for exact requirements (that part doesn't need the
    // facilitator), so build requirements straight from the same
    // config this app uses.
    let requirements = PaymentRequirements {
        scheme: "exact".to_string(),
        network: KITE_TESTNET.network.to_string(),
        amount: "1000000000000000".to_string(),
        asset: KITE_TESTNET.asset_address.to_string(),
        pay_to: "0xC0FFEE0000000000000000000000000000C0FFEE".to_string(),
        max_timeout_seconds: 60,
        extra: Some(json!({ "name": KITE_TESTNET.eip712_name, "version": KITE_TESTNET.eip712_version })),
    };
    let header = build_payment_header(&requirements);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/forecast")
                .header("PAYMENT-SIGNATURE", header)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Per the crate's documented contract (matching the Go SDK): a
    // facilitator outage is reported as 402, not 500/502.
    assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    assert!(response.headers().contains_key("PAYMENT-REQUIRED"));
}

#[tokio::test]
async fn malformed_payment_header_returns_402() {
    let (facilitator_base, _state) = spawn_facilitator().await;
    let upstream_base = spawn_upstream(StatusCode::OK).await;
    let app = build_app(&facilitator_base, &upstream_base);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/forecast")
                .header("PAYMENT-SIGNATURE", "not-valid-base64!!")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
}

#[tokio::test]
async fn v1_prefix_is_stripped_before_reaching_upstream() {
    // The mock upstream only serves /forecast (not /v1/forecast), so a
    // 200 here proves the proxy stripped the prefix correctly.
    let (facilitator_base, _state) = spawn_facilitator().await;
    let upstream_base = spawn_upstream(StatusCode::OK).await;
    let app = build_app(&facilitator_base, &upstream_base);

    let probe = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/forecast?latitude=52.52")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let requirements = requirements_from_402(probe.headers());
    let header = build_payment_header(&requirements);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/forecast?latitude=52.52")
                .header("PAYMENT-SIGNATURE", header)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

// Unused-import guard: keep the payload decode helper exercised so the
// public `wire::decode_payment_payload` re-export stays covered here too.
#[test]
fn wire_decode_is_reexported_and_usable() {
    let requirements = PaymentRequirements {
        scheme: "exact".to_string(),
        network: "eip155:2368".to_string(),
        amount: "1".to_string(),
        asset: "0xabc".to_string(),
        pay_to: "0xdef".to_string(),
        max_timeout_seconds: 60,
        extra: None,
    };
    let pr = kite_x402_axum::types::PaymentRequired {
        x402_version: 2,
        error: None,
        resource: kite_x402_axum::types::ResourceInfo {
            url: "https://example.com".to_string(),
            description: None,
            mime_type: None,
        },
        accepts: vec![requirements.clone()],
    };
    let header = encode_payment_required(&pr);
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let decoded: Value = serde_json::from_slice(&STANDARD.decode(header).unwrap()).unwrap();
    assert_eq!(decoded["accepts"][0]["amount"], "1");

    let payload = PaymentPayload {
        x402_version: 2,
        resource: None,
        accepted: requirements,
        payload: json!({}),
        extensions: None,
    };
    let encoded = base64_encode_payload(&payload);
    let decoded = decode_payment_payload(&encoded).unwrap();
    assert_eq!(decoded.accepted.amount, "1");
}
