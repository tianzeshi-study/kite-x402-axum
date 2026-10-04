//! Shared helpers for the integration (and E2E) tests: a recording mock
//! facilitator, a recording mock upstream API, an app builder that mirrors
//! `service/src/main.rs`, and small request/response utilities.
//!
//! Everything here goes through the crate's **public** API only, exactly as a
//! downstream consumer would use it.
//!
//! Each test binary compiles this module separately and uses a different
//! subset of it, hence the blanket `dead_code` allowance.

#![allow(dead_code)]

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{any, get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use kite_x402_axum::{
    facilitator::FacilitatorClient,
    kite::{KiteChain, KITE_TESTNET},
    middleware::{x402_payment, PaymentConfig},
    proxy::{proxy, same_origin_redirect_policy, UpstreamConfig},
    types::{PaymentPayload, PaymentRequirements},
};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tower::ServiceExt;

pub const PAY_TO: &str = "0xC0FFEE0000000000000000000000000000C0FFEE";
pub const PAYER: &str = "0xPayer0000000000000000000000000000000000";
pub const TX_HASH: &str = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

/// Ordered log of which mock was hit, shared by facilitator and upstream so
/// tests can assert `verify -> upstream -> settle`.
pub type Timeline = Arc<Mutex<Vec<String>>>;

// ---------------------------------------------------------------------------
// Mock facilitator
// ---------------------------------------------------------------------------

/// What the mock facilitator answers for `/verify` or `/settle`.
#[derive(Clone, Debug)]
pub enum Reply {
    /// `200` with this JSON body.
    Json(Value),
    /// An arbitrary status with a raw (possibly non-JSON) body.
    Raw { status: u16, body: String },
    /// `200` with this JSON body, after sleeping.
    Delayed(Duration, Value),
}

pub fn verify_ok() -> Reply {
    Reply::Json(json!({ "isValid": true, "payer": PAYER }))
}

pub fn verify_invalid(reason: Option<&str>) -> Reply {
    Reply::Json(json!({ "isValid": false, "invalidReason": reason, "payer": PAYER }))
}

pub fn settle_ok(network: &str) -> Reply {
    Reply::Json(json!({
        "success": true,
        "transaction": TX_HASH,
        "network": network,
        "payer": PAYER,
    }))
}

pub fn settle_failed(reason: &str, network: &str) -> Reply {
    Reply::Json(json!({
        "success": false,
        "errorReason": reason,
        "transaction": "",
        "network": network,
    }))
}

pub struct MockFacilitator {
    pub verify_reply: Mutex<Reply>,
    pub settle_reply: Mutex<Reply>,
    /// Raw JSON bodies received, in order.
    pub verify_requests: Mutex<Vec<Value>>,
    pub settle_requests: Mutex<Vec<Value>>,
    pub timeline: Timeline,
}

impl MockFacilitator {
    pub fn new(timeline: Timeline) -> Arc<Self> {
        Arc::new(Self {
            verify_reply: Mutex::new(verify_ok()),
            settle_reply: Mutex::new(settle_ok(KITE_TESTNET.network)),
            verify_requests: Mutex::new(vec![]),
            settle_requests: Mutex::new(vec![]),
            timeline,
        })
    }

    pub fn set_verify(&self, r: Reply) {
        *self.verify_reply.lock().unwrap() = r;
    }
    pub fn set_settle(&self, r: Reply) {
        *self.settle_reply.lock().unwrap() = r;
    }
    pub fn verify_count(&self) -> usize {
        self.verify_requests.lock().unwrap().len()
    }
    pub fn settle_count(&self) -> usize {
        self.settle_requests.lock().unwrap().len()
    }
}

async fn render(reply: Reply) -> Response {
    match reply {
        Reply::Json(v) => Json(v).into_response(),
        Reply::Raw { status, body } => {
            (StatusCode::from_u16(status).unwrap(), body).into_response()
        }
        Reply::Delayed(d, v) => {
            tokio::time::sleep(d).await;
            Json(v).into_response()
        }
    }
}

async fn verify_handler(
    State(s): State<Arc<MockFacilitator>>,
    Json(body): Json<Value>,
) -> Response {
    s.timeline.lock().unwrap().push("verify".into());
    s.verify_requests.lock().unwrap().push(body);
    let reply = s.verify_reply.lock().unwrap().clone();
    render(reply).await
}

async fn settle_handler(
    State(s): State<Arc<MockFacilitator>>,
    Json(body): Json<Value>,
) -> Response {
    s.timeline.lock().unwrap().push("settle".into());
    s.settle_requests.lock().unwrap().push(body);
    let reply = s.settle_reply.lock().unwrap().clone();
    render(reply).await
}

// ---------------------------------------------------------------------------
// Mock upstream API
// ---------------------------------------------------------------------------

/// One request as the upstream saw it.
#[derive(Clone, Debug)]
pub struct Recorded {
    pub method: String,
    pub path_and_query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Recorded {
    /// First value of a header (case-insensitive), if present.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// All values of a header (case-insensitive).
    pub fn header_all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct UpstreamReply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub delay: Option<Duration>,
}

impl UpstreamReply {
    pub fn json(status: u16) -> Self {
        Self {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body: br#"{"upstream":true}"#.to_vec(),
            delay: None,
        }
    }
}

pub struct MockUpstream {
    pub reply: Mutex<UpstreamReply>,
    pub requests: Mutex<Vec<Recorded>>,
    pub timeline: Timeline,
}

impl MockUpstream {
    pub fn new(timeline: Timeline) -> Arc<Self> {
        Arc::new(Self {
            reply: Mutex::new(UpstreamReply::json(200)),
            requests: Mutex::new(vec![]),
            timeline,
        })
    }

    pub fn set_status(&self, status: u16) {
        self.reply.lock().unwrap().status = status;
    }
    pub fn set_reply(&self, r: UpstreamReply) {
        *self.reply.lock().unwrap() = r;
    }
    pub fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
    /// The most recent request; panics if there was none.
    pub fn last(&self) -> Recorded {
        self.requests
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("upstream received no request")
    }
}

async fn upstream_handler(State(s): State<Arc<MockUpstream>>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let body = to_bytes(body, usize::MAX).await.unwrap().to_vec();
    let recorded = Recorded {
        method: parts.method.to_string(),
        path_and_query: parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_default(),
        headers: parts
            .headers
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_string(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect(),
        body,
    };
    s.timeline.lock().unwrap().push("upstream".into());
    s.requests.lock().unwrap().push(recorded);

    let reply = s.reply.lock().unwrap().clone();
    if let Some(d) = reply.delay {
        tokio::time::sleep(d).await;
    }
    let mut builder = Response::builder().status(reply.status);
    for (k, v) in &reply.headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    builder.body(Body::from(reply.body)).unwrap()
}

// ---------------------------------------------------------------------------
// Servers and the app under test
// ---------------------------------------------------------------------------

/// Serves `app` on `127.0.0.1:<ephemeral>` and returns `http://127.0.0.1:<port>`.
pub async fn serve(app: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

/// A URL nothing is listening on (bind, remember the port, drop the socket).
pub async fn dead_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    format!("http://{addr}")
}

/// Both mock servers plus their shared timeline.
pub struct Mocks {
    pub facilitator: Arc<MockFacilitator>,
    pub upstream: Arc<MockUpstream>,
    pub facilitator_url: String,
    pub upstream_url: String,
    pub timeline: Timeline,
}

impl Mocks {
    pub async fn start() -> Self {
        let timeline: Timeline = Arc::new(Mutex::new(vec![]));
        let facilitator = MockFacilitator::new(timeline.clone());
        let upstream = MockUpstream::new(timeline.clone());

        let facilitator_url = serve(
            Router::new()
                .route("/verify", post(verify_handler))
                .route("/settle", post(settle_handler))
                .with_state(facilitator.clone()),
        )
        .await;
        let upstream_url = serve(
            Router::new()
                .fallback(upstream_handler)
                .with_state(upstream.clone()),
        )
        .await;

        Self {
            facilitator,
            upstream,
            facilitator_url,
            upstream_url,
            timeline,
        }
    }

    pub fn timeline(&self) -> Vec<String> {
        self.timeline.lock().unwrap().clone()
    }

    /// The app under test with default options, wired to these mocks.
    pub fn app(&self) -> Router {
        build_app(
            &self.facilitator_url,
            &self.upstream_url,
            &AppOptions::default(),
        )
    }

    pub fn app_with(&self, opts: &AppOptions) -> Router {
        build_app(&self.facilitator_url, &self.upstream_url, opts)
    }
}

#[derive(Clone)]
pub struct AppOptions {
    pub chain: KiteChain,
    pub price_usd: String,
    pub auth_header: String,
    pub auth_value: String,
    pub facilitator_timeout: Option<Duration>,
    pub upstream_client: Option<reqwest::Client>,
}

impl Default for AppOptions {
    fn default() -> Self {
        Self {
            chain: KITE_TESTNET,
            price_usd: "0.001".into(),
            auth_header: "Authorization".into(),
            auth_value: String::new(),
            facilitator_timeout: None,
            upstream_client: None,
        }
    }
}

/// Mirrors `service/src/main.rs`: a free `/healthz` plus `/v1/*` behind the
/// payment gate and proxied to the upstream.
pub fn build_app(facilitator_url: &str, upstream_url: &str, o: &AppOptions) -> Router {
    let facilitator = match o.facilitator_timeout {
        Some(t) => FacilitatorClient::with_timeout(facilitator_url, t),
        None => FacilitatorClient::new(facilitator_url),
    };
    let payment_cfg = Arc::new(PaymentConfig {
        pay_to: PAY_TO.to_string(),
        chain: o.chain,
        price_usd: o.price_usd.clone(),
        description: "Test wrapper".to_string(),
        facilitator,
    });
    let upstream_cfg = Arc::new(UpstreamConfig {
        http: o.upstream_client.clone().unwrap_or_else(upstream_client),
        base_url: upstream_url.trim_end_matches('/').to_string(),
        auth_header: o.auth_header.clone(),
        auth_value: o.auth_value.clone(),
    });
    let paid = Router::new()
        .route("/{*path}", any(proxy))
        .with_state(upstream_cfg)
        .layer(middleware::from_fn_with_state(payment_cfg, x402_payment));

    Router::new()
        .route(
            "/healthz",
            get(|| async { Json(json!({ "status": "ok" })) }),
        )
        .nest("/v1", paid)
}

/// The proxy alone (no payment gate), nested under `/v1` like the real app.
pub fn build_proxy_only(upstream_cfg: UpstreamConfig) -> Router {
    Router::new().nest(
        "/v1",
        Router::new()
            .route("/{*path}", any(proxy))
            .with_state(Arc::new(upstream_cfg)),
    )
}

/// The HTTP client the service builds for the upstream (see `service/src/main.rs`).
pub fn upstream_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(same_origin_redirect_policy())
        .build()
        .expect("reqwest client")
}

pub fn upstream_cfg(base_url: &str) -> UpstreamConfig {
    UpstreamConfig {
        http: upstream_client(),
        base_url: base_url.trim_end_matches('/').to_string(),
        auth_header: "Authorization".into(),
        auth_value: String::new(),
    }
}

// ---------------------------------------------------------------------------
// Request / response helpers
// ---------------------------------------------------------------------------

pub fn get_req(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

pub fn req_with(method: &str, uri: &str, headers: &[(&str, &str)], body: Vec<u8>) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    b.body(Body::from(body)).unwrap()
}

pub async fn send(app: &Router, req: Request<Body>) -> Response {
    app.clone().oneshot(req).await.unwrap()
}

pub async fn body_bytes(resp: Response) -> Vec<u8> {
    to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec()
}

pub async fn body_json(resp: Response) -> Value {
    serde_json::from_slice(&body_bytes(resp).await).expect("response body is JSON")
}

/// Decodes a base64-JSON header such as `PAYMENT-REQUIRED` / `PAYMENT-RESPONSE`.
pub fn header_json(headers: &HeaderMap, name: &str) -> Value {
    let raw = headers
        .get(name)
        .unwrap_or_else(|| panic!("missing header {name}"))
        .to_str()
        .unwrap();
    serde_json::from_slice(&STANDARD.decode(raw).unwrap()).unwrap()
}

/// `accepts[0]` of a 402 response's `PAYMENT-REQUIRED` header.
pub fn requirements_of(resp: &Response) -> PaymentRequirements {
    let v = header_json(resp.headers(), "PAYMENT-REQUIRED");
    serde_json::from_value(v["accepts"][0].clone()).unwrap()
}

/// Hits `uri` unpaid to learn the exact requirements the server wants.
pub async fn probe_requirements(app: &Router, uri: &str) -> PaymentRequirements {
    let resp = send(app, get_req(uri)).await;
    assert_eq!(
        resp.status(),
        StatusCode::PAYMENT_REQUIRED,
        "probe must be challenged"
    );
    requirements_of(&resp)
}

pub fn payload_for(requirements: &PaymentRequirements) -> PaymentPayload {
    PaymentPayload {
        x402_version: 2,
        resource: None,
        accepted: requirements.clone(),
        payload: json!({ "signature": "0xsignature", "authorization": { "from": PAYER } }),
        extensions: None,
    }
}

pub fn encode_payload(p: &PaymentPayload) -> String {
    STANDARD.encode(serde_json::to_vec(p).unwrap())
}

/// A `PAYMENT-SIGNATURE` header value that matches `requirements`.
pub fn payment_header(requirements: &PaymentRequirements) -> String {
    encode_payload(&payload_for(requirements))
}

/// Probes for the requirements, then sends a correctly "paid" request.
pub async fn pay(app: &Router, method: &str, uri: &str, body: Vec<u8>) -> Response {
    let reqs = probe_requirements(app, uri).await;
    let header = payment_header(&reqs);
    send(
        app,
        req_with(method, uri, &[("PAYMENT-SIGNATURE", &header)], body),
    )
    .await
}

pub async fn pay_get(app: &Router, uri: &str) -> Response {
    pay(app, "GET", uri, vec![]).await
}

pub fn header_value(bytes: &[u8]) -> HeaderValue {
    HeaderValue::from_bytes(bytes).unwrap()
}

pub fn header_name(name: &str) -> HeaderName {
    HeaderName::from_bytes(name.as_bytes()).unwrap()
}
