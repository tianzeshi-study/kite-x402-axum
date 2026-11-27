//! End-to-end tests: launch the **real `kite-x402-service` binary** as a child
//! process, configured purely through environment variables like a
//! deployment, and talk to it over real TCP with a real HTTP client. Behind it
//! sit a mock facilitator and a mock upstream API (also real HTTP servers).
//!
//! What this covers that the in-process tests cannot: environment parsing and
//! defaults, startup failures and exit codes, the listener, and graceful
//! shutdown on SIGTERM.
//!
//! The mock servers are shared with the library's integration tests.

#[path = "../../kite-x402-axum/tests/common/mod.rs"]
mod common;

use std::{
    io::{Read, Write},
    net::{TcpListener as StdListener, TcpStream},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
    Router,
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use common::{
    encode_payload, payload_for, payment_header, settle_failed, settle_ok, verify_invalid, Mocks,
    Reply, UpstreamReply, PAYER, TX_HASH,
};
use kite_x402_axum::{
    types::PaymentRequirements, verify_signature_at, SIGNATURE_HEADER, TIMESTAMP_HEADER,
};
use serde_json::{json, Value};
use tokio::sync::Semaphore;

const BIN: &str = env!("CARGO_BIN_EXE_kite-x402-service");
const PAY_TO: &str = "0xE2E0000000000000000000000000000000000E2E";
const WEBHOOK_SECRET: &str = "fixture-webhook-secret-with-at-least-32-bytes";

#[derive(Clone, Debug)]
struct CapturedWebhook {
    headers: HeaderMap,
    body: Vec<u8>,
}

#[derive(Default)]
struct WebhookReceiver {
    requests: Mutex<Vec<CapturedWebhook>>,
    fail_first_settlement: AtomicBool,
    first_response_gate: Option<Arc<Semaphore>>,
}

async fn capture_webhook(
    State(receiver): State<Arc<WebhookReceiver>>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let payload: Value = serde_json::from_slice(&body).unwrap();
    let fail = payload["event_type"] == "payment_settled"
        && receiver
            .fail_first_settlement
            .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok();
    let first_request = {
        let mut requests = receiver.requests.lock().unwrap();
        let first_request = requests.is_empty();
        requests.push(CapturedWebhook {
            headers,
            body: body.to_vec(),
        });
        first_request
    };
    if let Some(gate) = receiver
        .first_response_gate
        .as_ref()
        .filter(|_| first_request)
    {
        let _permit = gate.acquire().await.unwrap();
    }
    if fail {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::NO_CONTENT
    }
}

async fn start_webhook_receiver(fail_first_settlement: bool) -> (String, Arc<WebhookReceiver>) {
    start_webhook_receiver_with(WebhookReceiver {
        fail_first_settlement: AtomicBool::new(fail_first_settlement),
        ..Default::default()
    })
    .await
}

async fn start_webhook_receiver_with(receiver: WebhookReceiver) -> (String, Arc<WebhookReceiver>) {
    let receiver = Arc::new(receiver);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/events", post(capture_webhook))
        .with_state(Arc::clone(&receiver));
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{address}/events"), receiver)
}

async fn wait_for_webhook_count(receiver: &WebhookReceiver, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        if receiver.requests.lock().unwrap().len() >= count {
            return;
        }
        assert!(Instant::now() < deadline, "timed out waiting for webhooks");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

// ---------------------------------------------------------------------------
// process harness
// ---------------------------------------------------------------------------

fn free_port() -> u16 {
    StdListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A running service process, killed on drop so a failing test never leaks it.
struct Service {
    child: Child,
    port: u16,
    http: reqwest::Client,
    logs: Option<std::thread::JoinHandle<String>>,
}

impl Service {
    /// Environment for a working service pointed at `mocks`.
    fn base_env(mocks: &Mocks, port: u16) -> Vec<(String, String)> {
        vec![
            ("PORT".into(), port.to_string()),
            ("PAY_TO".into(), PAY_TO.into()),
            ("UPSTREAM_URL".into(), mocks.upstream_url.clone()),
            ("FACILITATOR_URL".into(), mocks.facilitator_url.clone()),
            ("KITE_NETWORK".into(), "testnet".into()),
            ("RUST_LOG".into(), "off".into()),
        ]
    }

    fn debug_env(mocks: &Mocks, port: u16) -> Vec<(String, String)> {
        let mut env = Self::base_env(mocks, port);
        env.extend([
            (
                "RUST_LOG".into(),
                "kite_x402_service=debug,kite_x402_axum=debug".into(),
            ),
            ("NO_COLOR".into(), "1".into()),
        ]);
        env
    }

    async fn start(env: Vec<(String, String)>) -> Self {
        let port: u16 = env
            .iter()
            .find(|(k, _)| k == "PORT")
            .map(|(_, v)| v.parse().unwrap())
            .unwrap();
        let mut child = Command::new(BIN)
            .env_clear()
            .envs(env)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn service binary");
        let mut stdout = child.stdout.take().unwrap();
        // Drain logs continuously so DEBUG output cannot block the service on a full pipe.
        let logs = std::thread::spawn(move || {
            let mut output = String::new();
            stdout.read_to_string(&mut output).unwrap();
            output
        });
        let mut svc = Self {
            child,
            port,
            logs: Some(logs),
            // Never follow redirects or use system proxies: we test the service as-is.
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
        };
        svc.wait_until_ready().await;
        svc
    }

    async fn start_with(mocks: &Mocks) -> Self {
        Self::start(Self::base_env(mocks, free_port())).await
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    fn stop_and_read_logs(mut self) -> String {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
        self.logs.take().unwrap().join().unwrap()
    }

    async fn wait_until_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!(
                    "service exited during startup with {status}: {}",
                    self.stderr_so_far()
                );
            }
            if self.http.get(self.url("/healthz")).send().await.is_ok() {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "service did not become ready in 20s"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn stderr_so_far(&mut self) -> String {
        let mut out = String::new();
        if let Some(mut e) = self.child.stderr.take() {
            let _ = e.read_to_string(&mut out);
        }
        out
    }

    async fn get(&self, path: &str) -> reqwest::Response {
        self.http.get(self.url(path)).send().await.unwrap()
    }

    /// Unpaid probe -> requirements, then the paid request with `method`/`body`.
    async fn pay(&self, method: &str, path: &str, body: Option<Vec<u8>>) -> reqwest::Response {
        let reqs = self.requirements(path).await;
        let mut req = self
            .http
            .request(method.parse().unwrap(), self.url(path))
            .header("PAYMENT-SIGNATURE", payment_header(&reqs));
        if let Some(b) = body {
            req = req.body(b);
        }
        req.send().await.unwrap()
    }

    async fn pay_get(&self, path: &str) -> reqwest::Response {
        self.pay("GET", path, None).await
    }

    async fn requirements(&self, path: &str) -> PaymentRequirements {
        let resp = self.get(path).await;
        assert_eq!(resp.status(), 402, "probe of {path} must be challenged");
        let challenge = header_json(&resp, "payment-required");
        serde_json::from_value(challenge["accepts"][0].clone()).unwrap()
    }

    /// Asks the process to stop like a container runtime would and waits for it.
    #[cfg(unix)]
    fn terminate(&mut self) -> ExitStatus {
        let status = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                return s;
            }
            assert!(
                Instant::now() < deadline,
                "service did not stop within 10s of SIGTERM"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(logs) = self.logs.take() {
            let _ = logs.join();
        }
    }
}

fn header_json(resp: &reqwest::Response, name: &str) -> Value {
    let raw = resp
        .headers()
        .get(name)
        .unwrap_or_else(|| panic!("missing {name}"))
        .to_str()
        .unwrap();
    serde_json::from_slice(&STANDARD.decode(raw).unwrap()).unwrap()
}

/// Runs the binary expecting it to fail at startup; returns (status, stderr).
fn run_expecting_failure(env: Vec<(&str, &str)>) -> (ExitStatus, String) {
    let out = Command::new(BIN)
        .env_clear()
        .envs(env)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn service binary");
    (
        out.status,
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

// ===========================================================================
// Payment webhooks
// ===========================================================================

fn webhook_env(mocks: &Mocks, url: String) -> Vec<(String, String)> {
    let mut env = Service::base_env(mocks, free_port());
    env.extend([
        ("WEBHOOK_URLS".into(), url),
        ("WEBHOOK_SIGNING_SECRET".into(), WEBHOOK_SECRET.into()),
    ]);
    env
}

#[tokio::test]
async fn webhook_events_are_signed_retried_and_isolated_from_payment_responses() {
    let mocks = Mocks::start().await;
    let (webhook_url, receiver) = start_webhook_receiver(true).await;
    let svc = Service::start(webhook_env(&mocks, webhook_url)).await;

    let challenge = svc.get("/v1/forecast?private=do-not-forward").await;
    assert_eq!(challenge.status(), 402);
    wait_for_webhook_count(&receiver, 1).await;
    let challenged = svc.pay_get("/v1/forecast").await;
    assert_eq!(challenged.status(), 200);

    wait_for_webhook_count(&receiver, 4).await;
    let requests = receiver.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 4, "settlement should retry once after 503");
    for request in &requests {
        let timestamp: u64 = request.headers[TIMESTAMP_HEADER]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let signature = request.headers[SIGNATURE_HEADER].to_str().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(verify_signature_at(
            WEBHOOK_SECRET,
            timestamp,
            &request.body,
            signature,
            now,
            30,
        ));
    }

    let events: Vec<Value> = requests
        .iter()
        .map(|request| serde_json::from_slice(&request.body).unwrap())
        .collect();
    assert_eq!(events[0]["event_type"], "payment_prompted");
    assert_eq!(events[0]["request_path"], "/v1/forecast");
    assert_eq!(events[1]["event_type"], "payment_prompted");
    assert_eq!(events[2]["event_type"], "payment_settled");
    assert_eq!(events[2]["tx_hash"], TX_HASH);
    assert_eq!(events[2]["payer"], PAYER);
    assert_eq!(events[2]["network"], events[1]["network"]);
    assert_eq!(events[2]["amount_atomic"], events[1]["amount_atomic"]);
    assert_eq!(events[3]["event_id"], events[2]["event_id"]);
    assert_eq!(events[3]["request_path"], "/v1/forecast");
    assert!(events
        .iter()
        .all(|event| event.get("payment_signature").is_none()));
}

#[tokio::test]
async fn webhook_delivers_to_healthy_receivers_while_a_slow_receiver_is_busy() {
    let mocks = Mocks::start().await;
    let gate = Arc::new(Semaphore::new(0));
    let (slow_url, slow) = start_webhook_receiver_with(WebhookReceiver {
        first_response_gate: Some(Arc::clone(&gate)),
        ..Default::default()
    })
    .await;
    let (healthy_url, healthy) = start_webhook_receiver(false).await;
    let svc = Service::start(webhook_env(&mocks, format!("{slow_url},{healthy_url}"))).await;

    let requirements = svc.requirements("/v1/forecast").await;
    wait_for_webhook_count(&slow, 1).await;
    tokio::time::timeout(Duration::from_secs(3), async {
        let paid = svc
            .http
            .get(svc.url("/v1/forecast"))
            .header("PAYMENT-SIGNATURE", payment_header(&requirements))
            .send()
            .await
            .unwrap();
        assert_eq!(paid.status(), 200);
        wait_for_webhook_count(&healthy, 2).await;
    })
    .await
    .expect("the healthy receiver should get the settlement before the slow receiver times out");

    let healthy_event: Value =
        serde_json::from_slice(&healthy.requests.lock().unwrap()[1].body).unwrap();
    assert_eq!(healthy_event["event_type"], "payment_settled");
    assert_eq!(healthy_event["tx_hash"], TX_HASH);
    assert_eq!(slow.requests.lock().unwrap().len(), 1);

    gate.add_permits(1);
    wait_for_webhook_count(&slow, 2).await;
    let slow_event: Value = serde_json::from_slice(&slow.requests.lock().unwrap()[1].body).unwrap();
    assert_eq!(slow_event["event_id"], healthy_event["event_id"]);
}

#[tokio::test]
async fn webhook_skips_requests_rejected_before_the_payment_gate() {
    let mocks = Mocks::start().await;
    let (url, receiver) = start_webhook_receiver(false).await;
    let mut env = webhook_env(&mocks, url);
    env.extend([
        ("RATE_LIMIT_RPS".into(), "0.001".into()),
        ("RATE_LIMIT_BURST".into(), "1".into()),
    ]);
    let svc = Service::start(env).await;

    let response = svc.pay_get("/v1/forecast").await;
    assert_eq!(response.status(), 429);
    assert!(mocks.timeline().is_empty());
    wait_for_webhook_count(&receiver, 1).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let requests = receiver.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let event: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(event["event_type"], "payment_prompted");
}

#[tokio::test]
async fn webhook_reports_verification_when_the_upstream_returns_an_error() {
    let mocks = Mocks::start().await;
    mocks.upstream.set_status(402);
    let (url, receiver) = start_webhook_receiver(false).await;
    let svc = Service::start(webhook_env(&mocks, url)).await;

    let response = svc.pay_get("/v1/forecast").await;
    assert_eq!(response.status(), 402);
    assert_eq!(mocks.facilitator.verify_count(), 1);
    assert_eq!(mocks.facilitator.settle_count(), 0);
    wait_for_webhook_count(&receiver, 2).await;
    let requests = receiver.requests.lock().unwrap();
    let event: Value = serde_json::from_slice(&requests[1].body).unwrap();
    assert_eq!(event["event_type"], "payment_verified");
    assert_eq!(event["payer"], PAYER);
    assert!(event["tx_hash"].is_null());
}

#[tokio::test]
async fn webhook_reports_a_failed_settlement_with_the_verified_payer() {
    let mocks = Mocks::start().await;
    mocks.facilitator.set_settle(settle_failed(
        "settlement declined",
        kite_x402_axum::KITE_TESTNET.network,
    ));
    let (url, receiver) = start_webhook_receiver(false).await;
    let svc = Service::start(webhook_env(&mocks, url)).await;

    let response = svc.pay_get("/v1/forecast").await;
    assert_eq!(response.status(), 402);
    assert_eq!(mocks.facilitator.settle_count(), 1);
    wait_for_webhook_count(&receiver, 2).await;
    let requests = receiver.requests.lock().unwrap();
    let event: Value = serde_json::from_slice(&requests[1].body).unwrap();
    assert_eq!(event["event_type"], "payment_failed");
    assert_eq!(event["payer"], PAYER);
    assert_eq!(event["network"], kite_x402_axum::KITE_TESTNET.network);
    assert!(event["tx_hash"].is_null());
}

#[test]
fn webhooks_require_a_signing_secret_at_startup() {
    let (status, stderr) = run_expecting_failure(vec![
        ("PORT", "0"),
        ("PAY_TO", PAY_TO),
        ("UPSTREAM_URL", "http://127.0.0.1:1"),
        ("WEBHOOK_URLS", "http://127.0.0.1:9000/events"),
        ("RUST_LOG", "off"),
    ]);
    assert!(!status.success());
    assert!(stderr.contains("WEBHOOK_SIGNING_SECRET is required"));
}

// ===========================================================================
// HTTP header privacy
// ===========================================================================

#[tokio::test]
async fn debug_header_logs_protect_credentials_during_paid_requests() {
    let mocks = Mocks::start().await;
    let mut reply = UpstreamReply::json(200);
    reply.headers.extend([
        (
            "set-cookie".into(),
            "session=fixture-session; HttpOnly".into(),
        ),
        (
            "set-cookie".into(),
            "refresh=fixture-refresh; HttpOnly".into(),
        ),
        ("x-response-secret".into(), "fixture-response-secret".into()),
    ]);
    mocks.upstream.set_reply(reply);
    let mut env = Service::debug_env(&mocks, free_port());
    env.extend([
        (
            "UPSTREAM_AUTH_HEADER".into(),
            "X-Upstream-Credential".into(),
        ),
        (
            "UPSTREAM_AUTH_VALUE".into(),
            "fixture-injected-credential".into(),
        ),
    ]);
    let svc = Service::start(env).await;
    let challenge = svc.get("/v1/forecast").await;
    assert_eq!(challenge.status(), 402);
    let required_header = challenge.headers()["payment-required"]
        .to_str()
        .unwrap()
        .to_owned();
    let requirements =
        serde_json::from_value(header_json(&challenge, "payment-required")["accepts"][0].clone())
            .unwrap();
    let signature_header = payment_header(&requirements);
    let mut receipt_header = String::new();

    for payment_name in ["PAYMENT-SIGNATURE", "X-PAYMENT"] {
        let paid = svc
            .http
            .get(svc.url("/v1/forecast"))
            .header(payment_name, &signature_header)
            .header("Authorization", "Bearer fixture-buyer-credential")
            .header("Cookie", "session=fixture-buyer-cookie")
            .header("X-Custom-Credential", "fixture-custom-credential")
            .header("X-Upstream-Credential", "fixture-overridden-credential")
            .header("X-Request-Id", "paid-header-log-test")
            .send()
            .await
            .unwrap();
        assert_eq!(paid.status(), 200);
        assert_eq!(paid.headers()["x-request-id"], "paid-header-log-test");
        assert_eq!(
            paid.headers()["x-response-secret"],
            "fixture-response-secret"
        );
        let cookies: Vec<_> = paid
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            cookies,
            [
                "session=fixture-session; HttpOnly",
                "refresh=fixture-refresh; HttpOnly"
            ]
        );
        receipt_header = paid.headers()["payment-response"]
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(header_json(&paid, "payment-response")["success"], true);
        assert_eq!(
            paid.json::<Value>().await.unwrap(),
            json!({ "upstream": true })
        );

        let seen = mocks.upstream.last();
        assert_eq!(seen.header("x-request-id"), Some("paid-header-log-test"));
        assert_eq!(
            seen.header("authorization"),
            Some("Bearer fixture-buyer-credential")
        );
        assert_eq!(seen.header("cookie"), Some("session=fixture-buyer-cookie"));
        assert_eq!(
            seen.header("x-custom-credential"),
            Some("fixture-custom-credential")
        );
        assert_eq!(
            seen.header("x-upstream-credential"),
            Some("fixture-injected-credential")
        );
        assert_eq!(seen.header("payment-signature"), None);
        assert_eq!(seen.header("x-payment"), None);
    }
    assert_eq!(mocks.facilitator.verify_count(), 2);
    assert_eq!(mocks.upstream.count(), 2);
    assert_eq!(mocks.facilitator.settle_count(), 2);

    let logs = svc.stop_and_read_logs();
    assert!(logs.contains("header_names="));
    assert!(logs.contains("response_header_names="));
    for name in [
        "authorization",
        "cookie",
        "payment-signature",
        "x-payment",
        "set-cookie",
        "x-custom-credential",
        "x-response-secret",
    ] {
        assert!(
            logs.contains(name),
            "missing diagnostic header name: {name}"
        );
    }
    for secret in [
        "fixture-",
        &required_header,
        &signature_header,
        &receipt_header,
    ] {
        assert!(
            !logs.contains(secret),
            "HTTP header value leaked into service logs"
        );
    }
    assert!(logs.contains("status=200"));
    assert!(logs.contains("status=402"));
    assert!(logs.contains("request_id=paid-header-log-test"));
    assert!(logs.contains("Payment settled successfully on-chain"));
}

#[tokio::test]
async fn debug_header_logs_protect_credentials_on_rejected_and_failed_requests() {
    let mocks = Mocks::start().await;
    let svc = Service::start(Service::debug_env(&mocks, free_port())).await;
    for payment_name in ["PAYMENT-SIGNATURE", "X-PAYMENT"] {
        let rejected = svc
            .http
            .get(svc.url("/v1/forecast"))
            .header(payment_name, "fixture-malformed-payment")
            .header("Authorization", "Bearer fixture-rejected-credential")
            .send()
            .await
            .unwrap();
        assert_eq!(rejected.status(), 402);
        assert_eq!(
            header_json(&rejected, "payment-required")["error"],
            "Invalid payment signature"
        );
    }
    assert!(mocks.timeline().is_empty());
    let requirements = svc.requirements("/v1/forecast").await;
    let signature_header = payment_header(&requirements);
    for status in [401, 500] {
        let mut reply = UpstreamReply::json(status);
        reply
            .headers
            .push(("set-cookie".into(), "error=fixture-error-cookie".into()));
        mocks.upstream.set_reply(reply);
        let failed = svc
            .http
            .get(svc.url("/v1/forecast"))
            .header("PAYMENT-SIGNATURE", &signature_header)
            .header("Authorization", "Bearer fixture-failed-credential")
            .send()
            .await
            .unwrap();
        assert_eq!(failed.status().as_u16(), status);
        assert_eq!(failed.headers()["set-cookie"], "error=fixture-error-cookie");
        assert!(failed.headers().get("payment-response").is_none());
        assert_eq!(
            failed.json::<Value>().await.unwrap(),
            json!({ "upstream": true })
        );
    }
    assert_eq!(mocks.facilitator.verify_count(), 2);
    assert_eq!(mocks.upstream.count(), 2);
    assert_eq!(mocks.facilitator.settle_count(), 0);
    let logs = svc.stop_and_read_logs();
    assert!(!logs.contains("fixture-"));
    assert!(!logs.contains(&signature_header));
    for status in [402, 401, 500] {
        assert!(logs.contains(&format!("status={status}")));
    }
    assert!(logs.contains("HTTP request client error"));
    assert!(logs.contains("HTTP request failed (server error)"));
}

#[tokio::test]
async fn debug_header_logs_omit_repeated_and_non_utf8_values() {
    let mocks = Mocks::start().await;
    let mut reply = UpstreamReply::json(200);
    reply.headers.push((
        "x-binary-response".into(),
        "fixture-response-\u{00ff}".into(),
    ));
    mocks.upstream.set_reply(reply);
    let svc = Service::start(Service::debug_env(&mocks, free_port())).await;
    let requirements = svc.requirements("/v1/forecast").await;
    let paid = svc
        .http
        .get(svc.url("/v1/forecast"))
        .header("PAYMENT-SIGNATURE", payment_header(&requirements))
        .header("X-Multiple", "fixture-first-value")
        .header("X-Multiple", "fixture-second-value")
        .header("Proxy-Authorization", "Basic fixture-proxy-credential")
        .header("Content-Type", "application/x-fixture-private-type")
        .header(
            "X-Binary-Request",
            reqwest::header::HeaderValue::from_bytes(b"fixture-request-\xff\xfe").unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(paid.status(), 200);
    assert_eq!(
        paid.headers()["x-binary-response"].as_bytes(),
        b"fixture-response-\xc3\xbf"
    );
    assert_eq!(
        paid.json::<Value>().await.unwrap(),
        json!({ "upstream": true })
    );
    let seen = mocks.upstream.last();
    assert_eq!(
        seen.header_all("x-multiple"),
        ["fixture-first-value", "fixture-second-value"]
    );
    // The shared recording mock decodes request headers with from_utf8_lossy.
    assert_eq!(
        seen.header("x-binary-request"),
        Some("fixture-request-\u{fffd}\u{fffd}")
    );
    assert_eq!(
        seen.header("content-type"),
        Some("application/x-fixture-private-type")
    );
    assert_eq!(mocks.facilitator.verify_count(), 1);
    assert_eq!(mocks.facilitator.settle_count(), 1);
    let logs = svc.stop_and_read_logs();
    assert!(!logs.contains("fixture-"));
    for name in [
        "x-multiple",
        "x-binary-request",
        "x-binary-response",
        "proxy-authorization",
        "content-type",
    ] {
        assert!(
            logs.contains(name),
            "missing diagnostic header name: {name}"
        );
    }
    assert!(logs.contains("status=200"));
}

// ===========================================================================
// the happy path, end to end
// ===========================================================================

#[tokio::test]
async fn healthz_is_free_and_never_contacts_the_backends() {
    let mocks = Mocks::start().await;
    let svc = Service::start_with(&mocks).await;

    let resp = svc.get("/healthz").await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.json::<Value>().await.unwrap(),
        json!({
            "ok": true,
            "network": "eip155:2368",
            "asset": "pieUSD",
            "price": "$0.001",
        })
    );
    assert!(mocks.timeline().is_empty());
}

#[tokio::test]
async fn well_known_x402_publishes_the_payment_surface_without_contacting_the_backends() {
    let mocks = Mocks::start().await;
    let port = free_port();
    let mut env = Service::base_env(&mocks, port);
    env.push(("PRICE_USD".into(), "0.01".into()));
    env.push(("EXTRA_PAYMENT_OPTIONS".into(), "mainnet:$0.002".into()));
    let svc = Service::start(env).await;

    let resp = svc.get("/.well-known/x402").await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("cache-control").unwrap(), "no-store");
    // It sits on the same router as `/healthz`, so it gets the same headers.
    assert_eq!(
        resp.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    assert_eq!(
        resp.json::<Value>().await.unwrap(),
        json!({
            "x402Version": 2,
            "scheme": "exact",
            "networks": ["eip155:2368", "eip155:2366"],
            "assets": [
                {
                    "network": "eip155:2368",
                    "address": "0x38129cf4CE5E183eFF248F42A7D345Bb1B47621A",
                    "symbol": "pieUSD",
                    "decimals": 18,
                    "name": "pieUSD",
                    "version": "1",
                },
                {
                    "network": "eip155:2366",
                    "address": "0x7aB6f3ed87C42eF0aDb67Ed95090f8bF5240149e",
                    "symbol": "USDC.e",
                    "decimals": 6,
                    "name": "Bridged USDC (Kite AI)",
                    "version": "2",
                },
            ],
            "payTo": PAY_TO,
            "price": "$0.01",
            "description": "Paid API access via Kite x402",
            "extraPaymentOptions": [{"network": "eip155:2366", "price": "$0.002"}],
        })
    );
    // Unmetered and off the critical path: neither backend heard anything.
    assert!(mocks.timeline().is_empty());
}

#[tokio::test]
async fn livez_is_free_and_reports_uptime() {
    let mocks = Mocks::start().await;
    let svc = Service::start_with(&mocks).await;

    let resp = svc.get("/livez").await;
    assert_eq!(resp.status(), 200);
    let body = resp.json::<Value>().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert!(body["uptime_seconds"].as_u64().is_some());
    assert!(mocks.timeline().is_empty());
}

#[tokio::test]
async fn metrics_is_free_and_reports_real_activity() {
    let mocks = Mocks::start().await;
    let svc = Service::start_with(&mocks).await;

    let resp = svc.get("/metrics").await;
    assert_eq!(resp.status(), 200);
    let body = resp.json::<Value>().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert!(body["total_requests"].as_u64().unwrap() >= 2);
    assert!(body["successful_requests"].as_u64().unwrap() >= 1);
    assert_eq!(body["server_errors"], 0);
    assert!(mocks.timeline().is_empty());
}

#[tokio::test]
async fn readyz_probes_facilitator_and_returns_status() {
    let mocks = Mocks::start().await;
    let svc = Service::start_with(&mocks).await;

    let resp = svc.get("/readyz").await;
    assert_eq!(resp.status(), 200);
    let body = resp.json::<Value>().await.unwrap();
    assert_eq!(body["status"], "ready");
    assert_eq!(body["facilitator"], "ok");
    assert_eq!(body["network"], "eip155:2368");
    assert_eq!(body["networks"], json!(["eip155:2368"]));
}

#[tokio::test]
async fn readyz_checks_global_extra_networks_in_one_probe() {
    use std::sync::atomic::Ordering;

    let mocks = Mocks::start().await;
    for version in [1, 2] {
        let (facilitator_url, hits) = counting_facilitator(json!([
            {"x402Version": 2, "scheme": "exact", "network": "eip155:2368"},
            {"x402Version": version, "scheme": "exact", "network": "eip155:2366"}
        ]))
        .await;
        let env = env_with(
            Service::base_env(&mocks, free_port()),
            "FACILITATOR_URL",
            &facilitator_url,
        );
        let env = env_with(env, "EXTRA_PAYMENT_OPTIONS", "mainnet:0.002,mainnet:0.003");
        let svc = Service::start(env).await;

        let resp = svc.get("/readyz").await;
        assert_eq!(resp.status(), if version == 2 { 200 } else { 503 });
        let body = resp.json::<Value>().await.unwrap();
        assert_eq!(body["networks"], json!(["eip155:2366", "eip155:2368"]));
        if version == 2 {
            assert_eq!(body["network"], "eip155:2368");
        } else {
            assert!(body["error"].as_str().unwrap().contains("eip155:2366"));
        }
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(svc.get("/healthz").await.status(), 200);
    }
}

#[tokio::test]
async fn readyz_returns_503_when_facilitator_is_down_while_healthz_stays_200() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    for (k, v) in env.iter_mut() {
        if k == "FACILITATOR_URL" {
            *v = "http://127.0.0.1:1".into();
        }
    }
    let svc = Service::start(env).await;

    let healthz = svc.get("/healthz").await;
    assert_eq!(healthz.status(), 200);

    let readyz = svc.get("/readyz").await;
    assert_eq!(readyz.status(), 503);
    let body = readyz.json::<Value>().await.unwrap();
    assert_eq!(body["status"], "not_ready");
    assert_eq!(body["facilitator"], "unreachable");
    assert!(body["error"].as_str().is_some());
}

#[tokio::test]
async fn unknown_routes_outside_v1_are_404_and_free() {
    let mocks = Mocks::start().await;
    let svc = Service::start_with(&mocks).await;

    assert_eq!(svc.get("/nope").await.status(), 404);
    assert_eq!(svc.get("/").await.status(), 404);
    assert!(mocks.timeline().is_empty());
}

#[tokio::test]
async fn full_pay_per_call_flow_over_real_http() {
    let mocks = Mocks::start().await;
    let svc = Service::start_with(&mocks).await;

    // 1. unpaid request -> 402 challenge
    let unpaid = svc.get("/v1/forecast?latitude=52.52&longitude=13.41").await;
    assert_eq!(unpaid.status(), 402);
    assert_eq!(unpaid.headers()["cache-control"], "no-store");
    let challenge = header_json(&unpaid, "payment-required");
    assert_eq!(
        challenge["resource"]["url"],
        svc.url("/v1/forecast?latitude=52.52&longitude=13.41")
    );
    assert_eq!(challenge["accepts"][0]["payTo"], PAY_TO);
    assert_eq!(challenge["accepts"][0]["network"], "eip155:2368");
    assert!(
        mocks.timeline().is_empty(),
        "a challenge must be free of side effects"
    );

    // 2. paid request -> 200 + receipt + upstream body
    let reqs: PaymentRequirements =
        serde_json::from_value(challenge["accepts"][0].clone()).unwrap();
    let paid = svc
        .http
        .get(svc.url("/v1/forecast?latitude=52.52&longitude=13.41"))
        .header("PAYMENT-SIGNATURE", payment_header(&reqs))
        .send()
        .await
        .unwrap();
    assert_eq!(paid.status(), 200);
    assert_eq!(paid.headers()["cache-control"], "private");
    let receipt = header_json(&paid, "payment-response");
    assert_eq!(receipt["success"], true);
    assert_eq!(receipt["transaction"], TX_HASH);
    assert_eq!(receipt["payer"], PAYER);
    assert_eq!(
        paid.json::<Value>().await.unwrap(),
        json!({ "upstream": true })
    );

    // 3. side effects, in the right order, exactly once each
    assert_eq!(mocks.timeline(), vec!["verify", "upstream", "settle"]);
    assert_eq!(
        mocks.upstream.last().path_and_query,
        "/forecast?latitude=52.52&longitude=13.41",
        "/v1 stripped, query preserved"
    );
}

#[test]
fn settlement_queries_refuse_invalid_listener_ports() {
    for port in ["0", "65536", "invalid"] {
        let (status, stderr) = run_expecting_failure(vec![
            ("PAY_TO", PAY_TO),
            ("UPSTREAM_URL", "http://127.0.0.1:1"),
            ("SETTLEMENT_QUERY_PORT", port),
        ]);
        assert!(!status.success(), "accepted invalid port {port}");
        assert!(
            stderr.contains("SETTLEMENT_QUERY_PORT must be an integer"),
            "{stderr}"
        );
    }
}

#[tokio::test]
async fn settlement_queries_are_disabled_on_the_payment_port() {
    let mocks = Mocks::start().await;
    let svc = Service::start_with(&mocks).await;
    assert_eq!(svc.get("/settlements").await.status(), 404);
    assert!(mocks.timeline().is_empty());
}

#[tokio::test]
async fn settlement_queries_show_recent_and_hash_indexed_attempts() {
    let mocks = Mocks::start().await;
    let query_port = free_port();
    let mut public_port = free_port();
    while public_port == query_port {
        public_port = free_port();
    }
    let mut env = Service::base_env(&mocks, public_port);
    env.extend([
        ("SETTLEMENT_QUERY_PORT".into(), query_port.to_string()),
        ("FACILITATOR_TIMEOUT_MS".into(), "500".into()),
        (
            "ROUTE_PRICES_USD".into(),
            r#"[{"method":"GET","path":"/v1/forecast","price":"0.002"}]"#.into(),
        ),
    ]);
    let svc = Service::start(env).await;
    let recent_url = format!("http://127.0.0.1:{query_port}/settlements");
    let tx_url = format!("{recent_url}/eip155:2368/{TX_HASH}");

    assert_eq!(svc.get("/settlements").await.status(), 404);
    let blocked = svc
        .http
        .get(&recent_url)
        .header("host", "merchant.example")
        .send()
        .await
        .unwrap();
    assert_eq!(blocked.status(), 403);
    assert_eq!(blocked.headers()["cache-control"], "no-store");
    let unpaid = svc.get("/v1/forecast").await;
    assert_eq!(unpaid.status(), 402);
    let recent = svc.http.get(&recent_url).send().await.unwrap();
    assert_eq!(recent.status(), 200);
    assert_eq!(recent.headers()["cache-control"], "no-store");
    assert_eq!(recent.json::<Value>().await.unwrap(), json!([]));
    assert_eq!(svc.http.get(&tx_url).send().await.unwrap().status(), 404);
    assert!(mocks.timeline().is_empty());

    assert_eq!(svc.pay_get("/v1/forecast").await.status(), 200);
    let stored = svc.http.get(&tx_url).send().await.unwrap();
    assert_eq!(stored.status(), 200);
    let stored = stored.json::<Value>().await.unwrap();
    assert_eq!(stored["status"], "reported_success");
    assert_eq!(stored["network"], "eip155:2368");
    assert_eq!(stored["transaction"], TX_HASH);
    assert_eq!(stored["payer"], PAYER);
    assert_eq!(stored["pay_to"], PAY_TO);
    assert_eq!(stored["amount_atomic"], "2000000000000000");
    assert!(stored.get("reconciliation").is_none());

    mocks
        .facilitator
        .set_verify(Reply::Json(json!({ "isValid": true })));
    mocks.facilitator.set_settle(Reply::Delayed(
        Duration::from_secs(10),
        json!({ "success": false }),
    ));
    let requirements = svc.requirements("/v1/forecast").await;
    let payer = "0x11223344556677889900AABBCCDDEEFF00112233";
    let nonce = format!("0x{}", "AB".repeat(32));
    let amount = "20000000000000000000";
    let mut payment = payload_for(&requirements);
    payment.payload["authorization"] = json!({
        "from": payer,
        "to": requirements.pay_to,
        "value": amount,
        "nonce": nonce,
    });
    let signed = svc
        .http
        .get(svc.url("/v1/forecast"))
        .header("PAYMENT-SIGNATURE", encode_payload(&payment))
        .send()
        .await
        .unwrap();
    assert_eq!(signed.status(), 402);
    assert!(header_json(&signed, "payment-response")
        .get("reconciliation")
        .is_none());
    let latest = svc
        .http
        .get(format!("{recent_url}?limit=1"))
        .send()
        .await
        .unwrap();
    assert_eq!(latest.status(), 200);
    let latest = latest.json::<Vec<Value>>().await.unwrap();
    assert_eq!(latest.len(), 1);
    assert_eq!(latest[0]["status"], "unconfirmed");
    assert_eq!(latest[0]["transaction"], Value::Null);
    assert_eq!(latest[0]["amount_atomic"], requirements.amount);
    assert!(!latest[0].as_object().unwrap().contains_key("error_reason"));
    assert_eq!(
        latest[0]["reconciliation"],
        json!({
            "network": requirements.network,
            "asset": requirements.asset.to_ascii_lowercase(),
            "payer": payer.to_ascii_lowercase(),
            "pay_to": PAY_TO.to_ascii_lowercase(),
            "amount_atomic": amount,
            "nonce": nonce.to_ascii_lowercase(),
        })
    );
    assert_eq!(
        mocks.timeline(),
        ["verify", "upstream", "settle", "verify", "upstream", "settle"]
    );

    for url in [
        format!("{recent_url}?limit=0"),
        format!("{recent_url}?limit=101"),
        format!("{recent_url}/eip155:2368/bad-hash"),
    ] {
        assert_eq!(svc.http.get(url).send().await.unwrap().status(), 400);
    }
    assert_eq!(mocks.facilitator.settle_count(), 2);

    #[cfg(unix)]
    {
        let mut svc = svc;
        assert!(svc.terminate().success());
        assert!(svc.http.get(&recent_url).send().await.is_err());
    }
}

#[tokio::test]
async fn post_bodies_and_headers_travel_through_the_whole_stack() {
    let mocks = Mocks::start().await;
    let svc = Service::start_with(&mocks).await;

    let reqs = svc.requirements("/v1/orders").await;
    let resp = svc
        .http
        .post(svc.url("/v1/orders"))
        .header("PAYMENT-SIGNATURE", payment_header(&reqs))
        .header("content-type", "application/json")
        .header("x-trace", "e2e-42")
        .body(r#"{"sku":"A1","qty":3}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let seen = mocks.upstream.last();
    assert_eq!(seen.method, "POST");
    assert_eq!(seen.body, br#"{"sku":"A1","qty":3}"#);
    assert_eq!(seen.header("x-trace"), Some("e2e-42"));
    assert_eq!(
        seen.header("payment-signature"),
        None,
        "the payment must not reach the upstream"
    );
}

#[tokio::test]
async fn upstream_response_headers_and_status_survive_the_trip() {
    let mocks = Mocks::start().await;
    let mut reply = UpstreamReply::json(201);
    reply.headers.push(("x-request-id".into(), "up-7".into()));
    reply.headers.push(("location".into(), "/things/7".into()));
    mocks.upstream.set_reply(reply);
    let svc = Service::start_with(&mocks).await;

    let resp = svc.pay("POST", "/v1/things", Some(b"{}".to_vec())).await;
    assert_eq!(resp.status(), 201);
    assert_eq!(resp.headers()["x-request-id"], "up-7");
    assert_eq!(resp.headers()["location"], "/things/7");
    assert!(resp.headers().contains_key("payment-response"));
}

// ===========================================================================
// money-safety rules, end to end
// ===========================================================================

#[tokio::test]
async fn a_failing_upstream_is_passed_through_and_never_charged() {
    for status in [400u16, 404, 429, 500, 503] {
        let mocks = Mocks::start().await;
        mocks.upstream.set_status(status);
        let svc = Service::start_with(&mocks).await;

        let resp = svc.pay_get("/v1/forecast").await;
        assert_eq!(resp.status().as_u16(), status);
        assert!(resp.headers().get("payment-response").is_none());
        assert_eq!(mocks.facilitator.settle_count(), 0, "{status}");
    }
}

#[tokio::test]
async fn an_unreachable_upstream_is_a_502_and_never_charged() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    for (k, v) in env.iter_mut() {
        if k == "UPSTREAM_URL" {
            *v = common::dead_url().await;
        }
    }
    let svc = Service::start(env).await;

    let resp = svc.pay_get("/v1/forecast").await;
    assert_eq!(resp.status(), 502);
    assert_eq!(
        resp.json::<Value>().await.unwrap()["error"],
        "upstream unreachable"
    );
    assert_eq!(mocks.facilitator.settle_count(), 0);
}

#[tokio::test]
async fn a_rejected_payment_is_a_402_and_the_upstream_is_never_called() {
    let mocks = Mocks::start().await;
    mocks
        .facilitator
        .set_verify(verify_invalid(Some("insufficient_funds")));
    let svc = Service::start_with(&mocks).await;

    let resp = svc.pay_get("/v1/forecast").await;
    assert_eq!(resp.status(), 402);
    assert_eq!(
        header_json(&resp, "payment-required")["error"],
        "insufficient_funds"
    );
    assert_eq!(mocks.upstream.count(), 0);
    assert_eq!(mocks.facilitator.settle_count(), 0);
}

#[tokio::test]
async fn a_failed_settlement_withholds_the_upstream_data() {
    let mocks = Mocks::start().await;
    mocks
        .facilitator
        .set_settle(settle_failed("nonce_already_used", "eip155:2368"));
    let svc = Service::start_with(&mocks).await;

    let resp = svc.pay_get("/v1/forecast").await;
    assert_eq!(resp.status(), 402);
    assert_eq!(
        header_json(&resp, "payment-response")["errorReason"],
        "nonce_already_used"
    );
    assert_eq!(resp.json::<Value>().await.unwrap(), json!({}));
}

#[tokio::test]
async fn an_invalid_successful_settlement_receipt_withholds_the_upstream_data() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    env.push(("EXTRA_PAYMENT_OPTIONS".into(), "mainnet:$0.05".into()));
    let svc = Service::start(env).await;
    let challenge = svc.get("/v1/forecast").await;
    let challenge = header_json(&challenge, "payment-required");
    let chosen: PaymentRequirements =
        serde_json::from_value(challenge["accepts"][1].clone()).unwrap();
    let payment = payment_header(&chosen);

    let invalid_receipts = [
        ("", chosen.network.as_str()),
        ("  \t", chosen.network.as_str()),
        (TX_HASH, "eip155:2368"),
    ];
    for (transaction, network) in invalid_receipts {
        mocks.facilitator.set_settle(Reply::Json(json!({
            "success": true,
            "transaction": transaction,
            "network": network,
        })));
        let resp = svc
            .http
            .get(svc.url("/v1/forecast"))
            .header("PAYMENT-SIGNATURE", &payment)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 402, "receipt {transaction:?} on {network}");
        assert_eq!(resp.headers()["cache-control"], "no-store");
        let receipt = header_json(&resp, "payment-response");
        assert_eq!(receipt["success"], false);
        assert_eq!(receipt["errorReason"], "invalid_settlement_receipt");
        assert_eq!(receipt["transaction"], transaction);
        assert_eq!(receipt["network"], network);
        assert_eq!(resp.json::<Value>().await.unwrap(), json!({}));
    }

    let metrics: kite_x402_axum::PaymentMetricsSnapshot =
        svc.get("/metrics/x402").await.json().await.unwrap();
    assert_eq!(metrics.settlements_success, 0);
    assert_eq!(metrics.settlements_failed, invalid_receipts.len() as u64);
    assert_eq!(mocks.upstream.count(), invalid_receipts.len());
    assert_eq!(mocks.facilitator.settle_count(), invalid_receipts.len());
}

#[tokio::test]
async fn an_unreachable_facilitator_is_a_402_and_the_upstream_is_never_called() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    for (k, v) in env.iter_mut() {
        if k == "FACILITATOR_URL" {
            *v = common::dead_url().await;
        }
    }
    let svc = Service::start(env).await;

    let resp = svc.pay_get("/v1/forecast").await;
    assert_eq!(resp.status(), 402);
    assert!(header_json(&resp, "payment-required")["error"]
        .as_str()
        .unwrap()
        .starts_with("facilitator verify unavailable"));
    assert_eq!(mocks.upstream.count(), 0);
}

#[tokio::test]
async fn a_payment_for_the_wrong_amount_is_rejected_without_calling_the_facilitator() {
    let mocks = Mocks::start().await;
    let svc = Service::start_with(&mocks).await;

    let mut reqs = svc.requirements("/v1/forecast").await;
    reqs.amount = "1".into();
    let resp = svc
        .http
        .get(svc.url("/v1/forecast"))
        .header("PAYMENT-SIGNATURE", payment_header(&reqs))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 402);
    assert_eq!(
        header_json(&resp, "payment-required")["error"],
        "No matching payment requirements"
    );
    assert!(mocks.timeline().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_concurrent_buyers_are_each_charged_exactly_once() {
    const N: usize = 20;
    let mocks = Mocks::start().await;
    let svc = std::sync::Arc::new(Service::start_with(&mocks).await);

    let tasks: Vec<_> = (0..N)
        .map(|i| {
            let svc = svc.clone();
            tokio::spawn(async move {
                let resp = svc.pay_get(&format!("/v1/item/{i}")).await;
                assert_eq!(resp.status(), 200);
            })
        })
        .collect();
    for t in tasks {
        t.await.unwrap();
    }
    assert_eq!(mocks.facilitator.settle_count(), N);
    assert_eq!(mocks.upstream.count(), N);
}

// ===========================================================================
// configuration (environment variables)
// ===========================================================================

#[tokio::test]
async fn defaults_are_mainnet_and_one_tenth_of_a_cent() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    env.retain(|(k, _)| k != "KITE_NETWORK"); // rely on the default
    let svc = Service::start(env).await;

    let reqs = svc.requirements("/v1/x").await;
    assert_eq!(reqs.network, "eip155:2366");
    assert_eq!(reqs.amount, "1000"); // $0.001 at 6 decimals
    assert_eq!(reqs.asset, "0x7aB6f3ed87C42eF0aDb67Ed95090f8bF5240149e");
    assert_eq!(reqs.extra.unwrap()["name"], "Bridged USDC (Kite AI)");
}

#[tokio::test]
async fn testnet_uses_eighteen_decimals() {
    let mocks = Mocks::start().await;
    let svc = Service::start_with(&mocks).await;
    assert_eq!(svc.requirements("/v1/x").await.amount, "1000000000000000");
}

#[tokio::test]
async fn price_usd_is_honoured_with_or_without_a_dollar_sign() {
    for (price, expected) in [("0.05", "50000000000000000"), ("$2", "2000000000000000000")] {
        let mocks = Mocks::start().await;
        let mut env = Service::base_env(&mocks, free_port());
        env.push(("PRICE_USD".into(), price.into()));
        let svc = Service::start(env).await;
        assert_eq!(svc.requirements("/v1/x").await.amount, expected, "{price}");
    }
}

#[tokio::test]
async fn blank_optional_variables_fall_back_to_their_defaults() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    env.retain(|(k, _)| k != "KITE_NETWORK");
    env.push(("KITE_NETWORK".into(), "   ".into()));
    env.push(("PRICE_USD".into(), "".into()));
    let svc = Service::start(env).await;

    let reqs = svc.requirements("/v1/x").await;
    assert_eq!(
        (reqs.network.as_str(), reqs.amount.as_str()),
        ("eip155:2366", "1000")
    );
}

#[tokio::test]
async fn service_description_appears_in_the_challenge() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    env.push(("SERVICE_DESCRIPTION".into(), "Weather forecasts".into()));
    let svc = Service::start(env).await;

    let resp = svc.get("/v1/x").await;
    assert_eq!(
        header_json(&resp, "payment-required")["resource"]["description"],
        "Weather forecasts"
    );
}

#[tokio::test]
async fn default_service_description_is_used_when_unset() {
    let mocks = Mocks::start().await;
    let svc = Service::start_with(&mocks).await;
    let resp = svc.get("/v1/x").await;
    assert_eq!(
        header_json(&resp, "payment-required")["resource"]["description"],
        "Paid API access via Kite x402"
    );
}

#[tokio::test]
async fn upstream_credential_is_injected_under_the_configured_header() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    env.push(("UPSTREAM_AUTH_HEADER".into(), "X-Api-Key".into()));
    env.push(("UPSTREAM_AUTH_VALUE".into(), "k-12345".into()));
    let svc = Service::start(env).await;

    let reqs = svc.requirements("/v1/x").await;
    svc.http
        .get(svc.url("/v1/x"))
        .header("PAYMENT-SIGNATURE", payment_header(&reqs))
        .header("x-api-key", "buyer-supplied")
        .send()
        .await
        .unwrap();

    assert_eq!(
        mocks.upstream.last().header_all("x-api-key"),
        vec!["k-12345"]
    );
}

#[tokio::test]
async fn upstream_credential_defaults_to_the_authorization_header() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    env.push(("UPSTREAM_AUTH_VALUE".into(), "Bearer tok".into()));
    let svc = Service::start(env).await;

    svc.pay_get("/v1/x").await;
    assert_eq!(
        mocks.upstream.last().header("authorization"),
        Some("Bearer tok")
    );
}

#[tokio::test]
async fn no_credential_is_injected_when_none_is_configured() {
    let mocks = Mocks::start().await;
    let svc = Service::start_with(&mocks).await;
    svc.pay_get("/v1/x").await;
    assert_eq!(mocks.upstream.last().header("authorization"), None);
}

#[tokio::test]
async fn upstream_url_trailing_slash_is_trimmed() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    for (k, v) in env.iter_mut() {
        if k == "UPSTREAM_URL" {
            v.push('/');
        }
    }
    let svc = Service::start(env).await;

    svc.pay_get("/v1/forecast").await;
    assert_eq!(
        mocks.upstream.last().path_and_query,
        "/forecast",
        "no '//forecast'"
    );
}

#[tokio::test]
async fn facilitator_url_is_used_verbatim_including_its_version_prefix() {
    let mocks = Mocks::start().await;
    // The mock only serves /verify and /settle at the root; pointing the
    // service at a sub-path that does not exist must therefore fail closed.
    let mut env = Service::base_env(&mocks, free_port());
    for (k, v) in env.iter_mut() {
        if k == "FACILITATOR_URL" {
            v.push_str("/v2");
        }
    }
    let svc = Service::start(env).await;

    let resp = svc.pay_get("/v1/forecast").await;
    assert_eq!(
        resp.status(),
        402,
        "a wrong facilitator path must never let a request through"
    );
    assert_eq!(mocks.upstream.count(), 0);
}

#[tokio::test]
async fn an_invalid_price_starts_fine_but_fails_every_metered_request_with_500() {
    // Documents current behaviour: PRICE_USD is validated per request, not at
    // startup, so a typo is only noticed on the first call. /healthz stays green.
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    env.push(("PRICE_USD".into(), "cheap".into()));
    let svc = Service::start(env).await;

    assert_eq!(svc.get("/healthz").await.status(), 200);
    let resp = svc.get("/v1/x").await;
    assert_eq!(resp.status(), 500);
    assert!(resp.json::<Value>().await.unwrap()["error"]
        .as_str()
        .unwrap()
        .contains("invalid PRICE_USD"));
}

#[tokio::test]
async fn a_price_no_authorization_could_carry_is_a_500_not_a_challenge() {
    // One unit above the uint256 an EIP-3009 `value` can hold, written as a
    // USD price with mainnet's six decimals. Nothing is wrong with it as a
    // decimal, so without the bound it went into every challenge: a price no
    // buyer could sign.
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    env.push(("KITE_NETWORK".into(), "mainnet".into()));
    let max = kite_x402_axum::kite::MAX_UINT256_DECIMAL;
    let fraction = max[max.len() - 6..].parse::<u32>().unwrap() + 1;
    env.push((
        "PRICE_USD".into(),
        format!("{}.{fraction:06}", &max[..max.len() - 6]),
    ));
    let svc = Service::start(env).await;

    assert_eq!(svc.get("/healthz").await.status(), 200);
    let resp = svc.get("/v1/x").await;
    assert_eq!(resp.status(), 500);
    let error = resp.json::<Value>().await.unwrap()["error"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        error.contains("invalid PRICE_USD") && error.contains("more than a uint256 can hold"),
        "{error}"
    );
}

#[tokio::test]
async fn route_prices_require_match_rejects_unlisted_requests_before_payment() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    env.extend([
        ("ROUTE_PRICES_REQUIRE_MATCH".into(), "true".into()),
        (
            "ROUTE_PRICES_USD".into(),
            json!([
                {"method": "GET", "path": "/v1/reports/{id}", "price": "0.05"},
                {"method": "GET", "path": "/v1/reports/sample", "price": "0.02"}
            ])
            .to_string(),
        ),
    ]);
    let svc = Service::start(env).await;
    let requirements = svc.requirements("/v1/reports/sample").await;
    let valid_signature = payment_header(&requirements);

    for (method, path) in [
        (reqwest::Method::GET, "/v1/admin"),
        (reqwest::Method::GET, "/v1/reports"),
        (reqwest::Method::GET, "/v1/reports/"),
        (reqwest::Method::GET, "/v1/reports/a/b"),
        (reqwest::Method::POST, "/v1/reports/sample"),
        (reqwest::Method::DELETE, "/v1/reports/42"),
        (reqwest::Method::OPTIONS, "/v1/reports/sample"),
        (reqwest::Method::HEAD, "/v1/reports/sample"),
    ] {
        for signature in [
            None,
            Some("invalid-payment"),
            Some(valid_signature.as_str()),
        ] {
            let mut request = svc.http.request(method.clone(), svc.url(path));
            if let Some(signature) = signature {
                request = request.header("PAYMENT-SIGNATURE", signature);
            }
            let response = request.send().await.unwrap();
            assert_eq!(response.status(), 404, "{method} {path}");
            assert!(!response.headers().contains_key("payment-required"));
            assert!(!response.headers().contains_key("payment-response"));
            if method != reqwest::Method::HEAD {
                assert_eq!(
                    response.json::<Value>().await.unwrap(),
                    json!({"error": "not_found", "message": "route not found"})
                );
            }
        }
    }
    assert!(mocks.timeline().is_empty());
    assert_eq!(mocks.facilitator.verify_count(), 0);
    assert_eq!(mocks.upstream.count(), 0);
    assert_eq!(mocks.facilitator.settle_count(), 0);

    for (path, upstream_path, amount) in [
        (
            "/v1/reports/sample?format=json",
            "/reports/sample?format=json",
            "20000000000000000",
        ),
        (
            "/v1/reports/second%20id",
            "/reports/second%20id",
            "50000000000000000",
        ),
    ] {
        let requirements = svc.requirements(path).await;
        assert_eq!(requirements.amount, amount);
        let response = svc
            .http
            .get(svc.url(path))
            .header("PAYMENT-SIGNATURE", payment_header(&requirements))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(header_json(&response, "payment-response")["success"], true);
        assert_eq!(mocks.upstream.last().path_and_query, upstream_path);
    }
    assert_eq!(mocks.facilitator.verify_count(), 2);
    assert_eq!(mocks.upstream.count(), 2);
    assert_eq!(mocks.facilitator.settle_count(), 2);
    let settlements = mocks.facilitator.settle_requests.lock().unwrap();
    assert_eq!(
        settlements[0]["paymentRequirements"]["amount"],
        "20000000000000000"
    );
    assert_eq!(
        settlements[1]["paymentRequirements"]["amount"],
        "50000000000000000"
    );
}

#[tokio::test]
async fn route_prices_require_match_preserves_cors_and_free_endpoints() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    env.extend([
        ("ROUTE_PRICES_REQUIRE_MATCH".into(), "true".into()),
        ("CORS_ORIGIN".into(), "https://app.example.com".into()),
        (
            "ROUTE_PRICES_USD".into(),
            r#"[{"method":"GET","path":"/v1/data","price":"0.01"}]"#.into(),
        ),
    ]);
    let svc = Service::start(env).await;
    for path in [
        "/healthz",
        "/livez",
        "/metrics",
        "/metrics/x402",
        "/.well-known/x402",
    ] {
        assert_eq!(svc.get(path).await.status(), 200, "{path}");
    }
    for path in ["/v1/data", "/v1/admin"] {
        let preflight = svc
            .http
            .request(reqwest::Method::OPTIONS, svc.url(path))
            .header("Origin", "https://app.example.com")
            .header("Access-Control-Request-Method", "GET")
            .send()
            .await
            .unwrap();
        assert_eq!(preflight.status(), 204);
        assert_eq!(
            preflight.headers()["access-control-allow-origin"],
            "https://app.example.com"
        );
        let response = svc
            .http
            .get(svc.url(path))
            .header("Origin", "https://app.example.com")
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if path == "/v1/data" { 402 } else { 404 }
        );
        assert_eq!(
            response.headers()["access-control-allow-origin"],
            "https://app.example.com"
        );
    }
    assert!(mocks.timeline().is_empty());
}

#[test]
fn route_prices_require_match_rejects_invalid_configuration_at_startup() {
    for (strict, rules, expected) in [
        ("true", "", "requires at least one route rule"),
        ("true", "[]", "requires at least one route rule"),
        ("true", "  ", "requires at least one route rule"),
        (
            "1",
            "[]",
            "ROUTE_PRICES_REQUIRE_MATCH must be true or false",
        ),
        (
            "TRUE",
            "[]",
            "ROUTE_PRICES_REQUIRE_MATCH must be true or false",
        ),
        ("", "[]", "ROUTE_PRICES_REQUIRE_MATCH must be true or false"),
    ] {
        let (status, stderr) = run_expecting_failure(vec![
            ("PAY_TO", PAY_TO),
            ("UPSTREAM_URL", "http://127.0.0.1:1"),
            ("RUST_LOG", "off"),
            ("ROUTE_PRICES_REQUIRE_MATCH", strict),
            ("ROUTE_PRICES_USD", rules),
        ]);
        assert!(!status.success(), "{strict:?} {rules:?}");
        assert!(stderr.contains(expected), "{stderr}");
    }
}

#[tokio::test]
async fn route_prices_control_challenges_and_settlement() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    env.extend([
        ("ROUTE_PRICES_REQUIRE_MATCH".into(), "false".into()),
        ("PRICE_USD".into(), "0.01".into()),
        (
            "ROUTE_PRICES_USD".into(),
            json!([
                {"method": "GET", "path": "/v1/forecast", "price": "0.001"},
                {"method": "POST", "path": "/v1/report", "price": "0.05"},
            ])
            .to_string(),
        ),
    ]);
    let svc = Service::start(env).await;

    let forecast = svc.requirements("/v1/forecast?city=Berlin").await;
    assert_eq!(forecast.amount, "1000000000000000");
    assert_eq!(
        svc.requirements("/v1/report").await.amount,
        "10000000000000000"
    );
    assert_eq!(
        svc.requirements("/v1/forecast/daily").await.amount,
        "10000000000000000"
    );
    let report = svc.http.post(svc.url("/v1/report")).send().await.unwrap();
    assert_eq!(report.status(), 402);
    let report: PaymentRequirements =
        serde_json::from_value(header_json(&report, "payment-required")["accepts"][0].clone())
            .unwrap();
    assert_eq!(report.amount, "50000000000000000");

    let rejected = svc
        .http
        .post(svc.url("/v1/report"))
        .header("PAYMENT-SIGNATURE", payment_header(&forecast))
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 402);
    assert_eq!(
        header_json(&rejected, "payment-required")["accepts"][0]["amount"],
        report.amount
    );
    assert!(mocks.timeline().is_empty());

    for (method, path, requirements) in [
        (reqwest::Method::GET, "/v1/forecast?city=Berlin", &forecast),
        (reqwest::Method::POST, "/v1/report", &report),
    ] {
        let paid = svc
            .http
            .request(method, svc.url(path))
            .header("PAYMENT-SIGNATURE", payment_header(requirements))
            .send()
            .await
            .unwrap();
        assert_eq!(paid.status(), 200);
        assert_eq!(header_json(&paid, "payment-response")["success"], true);
    }
    assert_eq!(mocks.upstream.count(), 2);
    let settlements = mocks.facilitator.settle_requests.lock().unwrap();
    assert_eq!(settlements.len(), 2);
    assert_eq!(
        settlements[0]["paymentRequirements"]["amount"],
        forecast.amount
    );
    assert_eq!(
        settlements[1]["paymentRequirements"]["amount"],
        report.amount
    );
}

#[tokio::test]
async fn route_prices_apply_path_templates_to_challenges_and_settlement() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    env.extend([
        ("PRICE_USD".into(), "0.01".into()),
        (
            "ROUTE_PRICES_USD".into(),
            json!([
                {"method": "GET", "path": "/v1/reports/{id}/result", "price": "0.05"},
                {"method": "GET", "path": "/v1/reports/sample/result", "price": "0.02"},
                {"method": "GET", "path": "/v1/reports/{id}/summary", "price": "0.03"},
                {"method": "POST", "path": "/v1/reports/{id}/result", "price": "0.06"}
            ])
            .to_string(),
        ),
    ]);
    let svc = Service::start(env).await;

    for path in [
        "/v1/reports//result",
        "/v1/reports/a/b/result",
        "/v1/reports/a",
    ] {
        assert_eq!(svc.requirements(path).await.amount, "10000000000000000");
    }
    let sample = svc.requirements("/v1/reports/sample/result").await;
    assert_eq!(sample.amount, "20000000000000000");
    assert_eq!(
        svc.requirements("/v1/reports/first/summary").await.amount,
        "30000000000000000"
    );
    let post = svc
        .http
        .post(svc.url("/v1/reports/first/result"))
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), 402);
    assert_eq!(
        header_json(&post, "payment-required")["accepts"][0]["amount"],
        "60000000000000000"
    );

    let rejected = svc
        .http
        .get(svc.url("/v1/reports/first/result"))
        .header("PAYMENT-SIGNATURE", payment_header(&sample))
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 402);
    assert!(mocks.timeline().is_empty());

    let mut expected_requirements = Vec::new();
    for path in [
        "/reports/first/result?format=json",
        "/reports/second%20id/result",
    ] {
        let public_path = format!("/v1{path}");
        let requirements = svc.requirements(&public_path).await;
        assert_eq!(requirements.amount, "50000000000000000");
        let paid = svc
            .http
            .get(svc.url(&public_path))
            .header("PAYMENT-SIGNATURE", payment_header(&requirements))
            .send()
            .await
            .unwrap();
        assert_eq!(paid.status(), 200);
        assert_eq!(header_json(&paid, "payment-response")["success"], true);
        assert_eq!(mocks.upstream.last().path_and_query, path);
        expected_requirements.push(serde_json::to_value(requirements).unwrap());
    }
    assert_eq!(mocks.upstream.count(), 2);
    for recorded in [
        &mocks.facilitator.verify_requests,
        &mocks.facilitator.settle_requests,
    ] {
        let recorded = recorded.lock().unwrap();
        assert_eq!(recorded.len(), expected_requirements.len());
        for (request, expected) in recorded.iter().zip(&expected_requirements) {
            assert_eq!(&request["paymentRequirements"], expected);
        }
    }
}

#[tokio::test]
async fn route_prices_resolve_extra_payment_options_per_route() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    env.extend([
        ("EXTRA_PAYMENT_OPTIONS".into(), "mainnet:0.002".into()),
        (
            "ROUTE_PRICES_USD".into(),
            json!([
                {"method": "GET", "path": "/v1/forecast", "price": "0.001"},
                {"method": "POST", "path": "/v1/report", "price": "0.05",
                 "extra_payment_options": [{"network": "mainnet", "price": "0.06"}]},
                {"method": "GET", "path": "/v1/private", "price": "0.07",
                 "extra_payment_options": []},
            ])
            .to_string(),
        ),
    ]);
    let svc = Service::start(env).await;

    let forecast = svc.get("/v1/forecast").await;
    let inherited = header_json(&forecast, "payment-required")["accepts"].clone();
    let unmatched = svc.get("/v1/report").await;
    assert_eq!(
        header_json(&unmatched, "payment-required")["accepts"],
        inherited
    );
    assert_eq!(inherited.as_array().unwrap().len(), 2);
    assert_eq!(inherited[1]["network"], "eip155:2366");
    assert_eq!(inherited[1]["amount"], "2000");

    let report = svc.http.post(svc.url("/v1/report")).send().await.unwrap();
    assert_eq!(report.status(), 402);
    let challenge = header_json(&report, "payment-required");
    let accepts = challenge["accepts"].as_array().unwrap();
    assert_eq!(accepts.len(), 2);
    assert_eq!(accepts[0]["network"], "eip155:2368");
    assert_eq!(accepts[0]["amount"], "50000000000000000");
    assert_eq!(accepts[1]["network"], "eip155:2366");
    assert_eq!(accepts[1]["amount"], "60000");

    let cheaper = serde_json::from_value(inherited[1].clone()).unwrap();
    let private = svc.get("/v1/private").await;
    let private_challenge = header_json(&private, "payment-required");
    let private_options = private_challenge["accepts"].as_array().unwrap();
    assert_eq!(private_options.len(), 1);
    assert_eq!(private_options[0]["network"], "eip155:2368");
    assert_eq!(private_options[0]["amount"], "70000000000000000");

    for (method, path) in [
        (reqwest::Method::POST, "/v1/report"),
        (reqwest::Method::GET, "/v1/private"),
    ] {
        let rejected = svc
            .http
            .request(method, svc.url(path))
            .header("PAYMENT-SIGNATURE", payment_header(&cheaper))
            .send()
            .await
            .unwrap();
        assert_eq!(rejected.status(), 402);
    }
    assert!(mocks.timeline().is_empty());

    let alternative: PaymentRequirements = serde_json::from_value(accepts[1].clone()).unwrap();
    mocks
        .facilitator
        .set_settle(settle_ok(&alternative.network));
    let paid = svc
        .http
        .post(svc.url("/v1/report"))
        .header("PAYMENT-SIGNATURE", payment_header(&alternative))
        .send()
        .await
        .unwrap();
    assert_eq!(paid.status(), 200);
    assert_eq!(
        header_json(&paid, "payment-response")["network"],
        alternative.network
    );
    assert_eq!(mocks.timeline(), vec!["verify", "upstream", "settle"]);
    for recorded in [
        &mocks.facilitator.verify_requests,
        &mocks.facilitator.settle_requests,
    ] {
        let recorded = recorded.lock().unwrap();
        assert_eq!(recorded[0]["paymentRequirements"], accepts[1]);
    }
}

#[tokio::test]
async fn route_prices_reject_upstream_redirects_without_settling() {
    let mocks = Mocks::start().await;
    let mut redirect = UpstreamReply::json(307);
    redirect.headers.push(("location".into(), "/report".into()));
    mocks.upstream.set_reply(redirect);
    let mut env = Service::base_env(&mocks, free_port());
    env.push((
        "ROUTE_PRICES_USD".into(),
        r#"[{"method":"GET","path":"/v1/reports/{id}","price":"0.05"}]"#.into(),
    ));
    let svc = Service::start(env).await;

    let paid = svc.pay_get("/v1/reports/first").await;
    assert_eq!(paid.status(), 502);
    assert!(!paid.headers().contains_key("payment-response"));
    assert_eq!(mocks.upstream.count(), 1);
    assert_eq!(mocks.facilitator.settle_count(), 0);
}

#[tokio::test]
async fn route_prices_require_encoded_paths() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    env.push((
        "ROUTE_PRICES_USD".into(),
        r#"[{"method":"GET","path":"/v1/report%7Bdraft%7D","price":"0.05"}]"#.into(),
    ));
    let svc = Service::start(env).await;
    let requirements = svc.requirements("/v1/report%7Bdraft%7D").await;
    assert_eq!(requirements.amount, "50000000000000000");

    let mut socket = TcpStream::connect(("127.0.0.1", svc.port)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket
        .write_all(
            b"GET /v1/report{draft} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
    let mut raw_response = String::new();
    socket.read_to_string(&mut raw_response).unwrap();
    assert!(raw_response.starts_with("HTTP/1.1 400 "));
    assert!(raw_response.contains("request path must use URL encoding"));
    assert!(mocks.timeline().is_empty());
}

#[test]
fn route_prices_reject_invalid_configuration_at_startup() {
    let rule = json!({"method": "GET", "path": "/v1/forecast", "price": "0.001"});
    let with_extras = |extras| {
        let mut rule = rule.clone();
        rule["extra_payment_options"] = extras;
        json!([rule]).to_string()
    };
    for (rules, expected_error) in [
        ("{".into(), "invalid ROUTE_PRICES_USD"),
        (with_extras(json!(null)), "expected a sequence"),
        (
            with_extras(json!([{"network": "", "price": "0.002"}])),
            "extra_payment_options entry 1 needs a network",
        ),
        (
            with_extras(json!([{"network": "unknown", "price": "0.002"}])),
            "extra_payment_options entry 1: unknown KITE_NETWORK",
        ),
        (
            with_extras(json!([{"network": "mainnet", "price": "0.0000001"}])),
            "extra_payment_options entry 1 has an invalid USD price",
        ),
        (
            with_extras(json!([{"network": "mainnet", "price": "0.001"}])),
            "rule 1 payment options option 2 duplicates an earlier payment option",
        ),
        (
            json!([&rule, &rule]).to_string(),
            "duplicates a method and path",
        ),
        (
            json!([{"method":"NOT A METHOD","path":"/v1/forecast","price":"0.001"}]).to_string(),
            "invalid HTTP method",
        ),
        (
            json!([{"method":"GET","path":"/healthz","price":"0.001"}]).to_string(),
            "a valid path under /v1/",
        ),
        (
            json!([{"method":"GET","path":"/v1/{*path}","price":"0.001"}]).to_string(),
            "a valid path under /v1/",
        ),
        (
            json!([{"method":"GET","path":"/v1/reports/item-{id}","price":"0.001"}]).to_string(),
            "a valid path under /v1/",
        ),
        (
            json!([{"method":"GET","path":"/v1/reports/{id}/%2e%2E","price":"0.001"}]).to_string(),
            "a valid path under /v1/",
        ),
        (
            json!([
                {"method":"GET","path":"/v1/reports/{id}","price":"0.001"},
                {"method":"GET","path":"/v1/reports/{name}","price":"0.002"}
            ])
            .to_string(),
            "rule 2 overlaps an earlier path template",
        ),
        (
            json!([
                {"method":"GET","path":"/v1/reports/{id}/result","price":"0.001"},
                {"method":"GET","path":"/v1/reports/latest/{view}","price":"0.002"}
            ])
            .to_string(),
            "rule 2 overlaps an earlier path template",
        ),
        (
            json!([{"method":"GET","path":"/v1/forecast?city=Berlin","price":"0.001"}]).to_string(),
            "a valid path under /v1/",
        ),
        (
            json!([{"method":"GET","path":"/v1/forecast%xyz","price":"0.001"}]).to_string(),
            "a valid path under /v1/",
        ),
        (
            json!([{"method":"GET","path":"/v1/forecast","price":"cheap"}]).to_string(),
            "invalid USD price",
        ),
    ] {
        // A reserved port makes the test exit even if validation regresses.
        let listener = StdListener::bind("0.0.0.0:0").unwrap();
        let port = listener.local_addr().unwrap().port().to_string();
        let (status, stderr) = run_expecting_failure(vec![
            ("PORT", &port),
            ("PAY_TO", PAY_TO),
            ("UPSTREAM_URL", "http://localhost:1"),
            ("RUST_LOG", "off"),
            ("ROUTE_PRICES_USD", &rules),
        ]);
        assert!(!status.success());
        assert!(stderr.contains("invalid ROUTE_PRICES_USD"), "{stderr}");
        assert!(stderr.contains(expected_error), "{stderr}");
    }
}

// ===========================================================================
// startup failures
// ===========================================================================

#[test]
fn refuses_to_start_without_pay_to() {
    let (status, stderr) = run_expecting_failure(vec![
        ("UPSTREAM_URL", "http://localhost:1"),
        ("RUST_LOG", "off"),
    ]);
    assert!(!status.success());
    assert!(stderr.contains("PAY_TO is required"), "{stderr}");
}

#[test]
fn refuses_a_pay_to_that_is_not_an_address() {
    let (status, stderr) = run_expecting_failure(vec![
        ("PAY_TO", "0x123"),
        ("UPSTREAM_URL", "http://localhost:1"),
        ("RUST_LOG", "off"),
    ]);
    assert!(!status.success());
    assert!(
        stderr.contains("PAY_TO must be a 0x-prefixed 40-character hex address"),
        "{stderr}"
    );
}

#[test]
fn refuses_to_start_without_upstream_url() {
    let (status, stderr) = run_expecting_failure(vec![("PAY_TO", PAY_TO), ("RUST_LOG", "off")]);
    assert!(!status.success());
    assert!(stderr.contains("UPSTREAM_URL is required"), "{stderr}");
}

#[test]
fn refuses_an_unknown_network() {
    let (status, stderr) = run_expecting_failure(vec![
        ("PAY_TO", PAY_TO),
        ("UPSTREAM_URL", "http://localhost:1"),
        ("KITE_NETWORK", "devnet"),
        ("RUST_LOG", "off"),
    ]);
    assert!(!status.success());
    assert!(stderr.contains("invalid KITE_NETWORK"), "{stderr}");
}

#[test]
fn refuses_a_non_numeric_port() {
    // (A blank PORT falls back to the default and would start serving
    // forever, so it is deliberately excluded from this list.)
    for bad in ["abc", "-1", "70000"] {
        let (status, stderr) = run_expecting_failure(vec![
            ("PAY_TO", PAY_TO),
            ("UPSTREAM_URL", "http://localhost:1"),
            ("PORT", bad),
            ("RUST_LOG", "off"),
        ]);
        assert!(!status.success(), "PORT={bad:?}");
        assert!(
            stderr.contains("PORT must be a number"),
            "PORT={bad:?}: {stderr}"
        );
    }
}

#[test]
fn refuses_to_start_when_the_port_is_already_taken() {
    let taken = StdListener::bind("0.0.0.0:0").unwrap();
    let port = taken.local_addr().unwrap().port().to_string();
    let (status, stderr) = run_expecting_failure(vec![
        ("PAY_TO", PAY_TO),
        ("UPSTREAM_URL", "http://localhost:1"),
        ("PORT", &port),
        ("RUST_LOG", "off"),
    ]);
    assert!(!status.success());
    assert!(stderr.contains("could not bind"), "{stderr}");
}

#[test]
fn refuses_negative_and_non_finite_rate_limits() {
    for key in ["RATE_LIMIT_RPS", "RATE_LIMIT_BURST"] {
        for value in ["-5", "NaN", "inf", "-inf", "1e999"] {
            let (status, stderr) = run_expecting_failure(vec![
                ("PAY_TO", PAY_TO),
                ("UPSTREAM_URL", "http://localhost:1"),
                (key, value),
                ("RUST_LOG", "off"),
            ]);
            assert!(!status.success(), "{key}={value} must fail startup");
            assert!(
                stderr.contains(&format!("{key} must be a finite non-negative number")),
                "{key}={value}: {stderr}"
            );
        }
    }
}

#[tokio::test]
async fn rate_limiting_protects_service_without_charging() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    env.push(("RATE_LIMIT_RPS".into(), "1".into()));
    env.push(("RATE_LIMIT_BURST".into(), "1".into()));
    let svc = Service::start(env).await;

    // First request reaches gate / 402 challenge
    let res1 = svc.get("/v1/test").await;
    assert_eq!(res1.status(), 402);

    // Second immediate request from same client is rate limited to 429
    let res2 = svc.get("/v1/test").await;
    assert_eq!(res2.status(), 429);
    assert_eq!(res2.headers()["retry-after"], "1");
    assert_eq!(res2.headers()["cache-control"], "no-store");
    // Crucial: rate limit rejection happens before payment verification, zero facilitator calls
    assert!(mocks.timeline().is_empty());
}

#[tokio::test]
async fn untrusted_forwarding_headers_cannot_reset_rate_limits() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    env.extend([
        ("RATE_LIMIT_RPS".into(), "0.001".into()),
        ("RATE_LIMIT_BURST".into(), "1".into()),
    ]);
    let svc = Service::start(env).await;
    assert_eq!(svc.get("/v1/test").await.status(), 402);
    for (name, value) in [
        ("X-Forwarded-For", "192.0.2.1"),
        ("X-Forwarded-For", "192.0.2.2"),
        ("X-Real-IP", "203.0.113.1"),
        ("X-Forwarded-For", "invalid"),
    ] {
        assert_eq!(
            svc.http
                .get(svc.url("/v1/test"))
                .header(name, value)
                .send()
                .await
                .unwrap()
                .status(),
            429
        );
    }
    assert_eq!(svc.get("/healthz").await.status(), 200);
    assert!(mocks.timeline().is_empty());
}

#[tokio::test]
async fn trusted_proxy_chains_keep_client_quotas_isolated() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    env.extend([
        ("RATE_LIMIT_RPS".into(), "0.001".into()),
        ("RATE_LIMIT_BURST".into(), "1".into()),
        ("RATE_LIMIT_TRUSTED_PROXIES".into(), "127.0.0.0/8".into()),
    ]);
    let svc = Service::start(env).await;
    for (value, status) in [
        ("192.0.2.1, 198.51.100.1, 127.0.0.2", 402),
        ("192.0.2.2, 198.51.100.1, 127.0.0.2", 429),
        ("198.51.100.2, 127.0.0.2", 402),
        ("198.51.100.3, bad", 400),
    ] {
        assert_eq!(
            svc.http
                .get(svc.url("/v1/test"))
                .header("X-Forwarded-For", value)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16(),
            status,
            "{value}"
        );
    }
    assert_eq!(
        svc.http
            .get(svc.url("/v1/test"))
            .header("X-Real-IP", "198.51.100.3")
            .send()
            .await
            .unwrap()
            .status(),
        402
    );
    assert_eq!(
        svc.http
            .get(svc.url("/v1/test"))
            .header("X-Forwarded-For", "198.51.100.3")
            .send()
            .await
            .unwrap()
            .status(),
        429
    );
    assert!(mocks.timeline().is_empty());
}

#[test]
fn refuses_invalid_trusted_proxy_configuration() {
    for value in ["*", "127.0.0.1/33", "::/129", "127.0.0.1,", "not-an-ip"] {
        let (status, stderr) = run_expecting_failure(vec![
            ("PAY_TO", PAY_TO),
            ("UPSTREAM_URL", "http://localhost:1"),
            ("RATE_LIMIT_TRUSTED_PROXIES", value),
            ("RUST_LOG", "off"),
        ]);
        assert!(!status.success());
        assert!(stderr.contains("RATE_LIMIT_TRUSTED_PROXIES"), "{stderr}");
    }
}

#[test]
fn refuses_invalid_rate_limit_cache_configuration() {
    for (key, values) in [
        (
            "RATE_LIMIT_MAX_CLIENTS",
            ["0", "-1", "1000001", "NaN", "1.5"],
        ),
        (
            "RATE_LIMIT_IDLE_TIMEOUT_SECS",
            ["0", "-1", "86401", "inf", "1.5"],
        ),
    ] {
        for value in values {
            let (status, stderr) = run_expecting_failure(vec![
                ("PAY_TO", PAY_TO),
                ("UPSTREAM_URL", "http://localhost:1"),
                (key, value),
                ("RUST_LOG", "off"),
            ]);
            assert!(!status.success(), "{key}={value} must fail startup");
            assert!(stderr.contains(key), "{key}={value}: {stderr}");
        }
    }
}

#[tokio::test]
async fn rate_limit_capacity_rejects_new_clients_before_payment_work() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    env.extend([
        ("RATE_LIMIT_RPS".into(), "0.001".into()),
        ("RATE_LIMIT_BURST".into(), "1".into()),
        ("RATE_LIMIT_MAX_CLIENTS".into(), "1".into()),
        ("RATE_LIMIT_IDLE_TIMEOUT_SECS".into(), "1".into()),
        ("RATE_LIMIT_TRUSTED_PROXIES".into(), "127.0.0.1".into()),
    ]);
    let svc = Service::start(env).await;
    let challenge = svc
        .http
        .get(svc.url("/v1/test"))
        .header("x-forwarded-for", "192.0.2.1")
        .send()
        .await
        .unwrap();
    assert_eq!(challenge.status(), 402);
    let requirements =
        serde_json::from_value(header_json(&challenge, "payment-required")["accepts"][0].clone())
            .unwrap();
    let payment = payment_header(&requirements);
    for (ip, status, error) in [
        ("192.0.2.1", 429, "rate_limit_exceeded"),
        ("192.0.2.2", 503, "rate_limit_capacity_exceeded"),
    ] {
        let response = svc
            .http
            .get(svc.url("/v1/test"))
            .header("x-forwarded-for", ip)
            .header("payment-signature", &payment)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), status);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert!(response.headers().contains_key("retry-after"));
        assert_eq!(response.json::<Value>().await.unwrap()["error"], error);
    }
    for path in ["/healthz", "/livez", "/metrics"] {
        assert_eq!(svc.get(path).await.status(), 200);
    }
    assert!(mocks.timeline().is_empty());
}

#[tokio::test]
async fn rate_limit_capacity_recovers_after_idle_clients_expire() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    env.extend([
        ("RATE_LIMIT_RPS".into(), "10".into()),
        ("RATE_LIMIT_BURST".into(), "1".into()),
        ("RATE_LIMIT_MAX_CLIENTS".into(), "1".into()),
        ("RATE_LIMIT_IDLE_TIMEOUT_SECS".into(), "1".into()),
        ("RATE_LIMIT_TRUSTED_PROXIES".into(), "127.0.0.1".into()),
    ]);
    let svc = Service::start(env).await;
    assert_eq!(
        svc.http
            .get(svc.url("/v1/test"))
            .header("x-forwarded-for", "192.0.2.1")
            .send()
            .await
            .unwrap()
            .status(),
        402
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut observed_capacity = false;
    loop {
        let response = svc
            .http
            .get(svc.url("/v1/test"))
            .header("x-forwarded-for", "192.0.2.2")
            .send()
            .await
            .unwrap();
        match response.status().as_u16() {
            402 => break,
            503 => observed_capacity = true,
            status => panic!("unexpected status: {status}"),
        }
        assert!(Instant::now() < deadline, "idle client was not reclaimed");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(observed_capacity);
    assert!(mocks.timeline().is_empty());
}

#[test]
fn refuses_invalid_timeout_configurations() {
    let (status, stderr) = run_expecting_failure(vec![
        ("PAY_TO", PAY_TO),
        ("UPSTREAM_URL", "http://localhost:1"),
        ("UPSTREAM_TIMEOUT_MS", "50"),
        ("RUST_LOG", "off"),
    ]);
    assert!(!status.success());
    assert!(
        stderr.contains("UPSTREAM_TIMEOUT_MS must be between 100 and 300000 ms"),
        "{stderr}"
    );

    let (status2, stderr2) = run_expecting_failure(vec![
        ("PAY_TO", PAY_TO),
        ("UPSTREAM_URL", "http://localhost:1"),
        ("FACILITATOR_TIMEOUT_MS", "500000"),
        ("RUST_LOG", "off"),
    ]);
    assert!(!status2.success());
    assert!(
        stderr2.contains("FACILITATOR_TIMEOUT_MS must be between 100 and 300000 ms"),
        "{stderr2}"
    );
}

#[test]
fn refuses_unsafe_or_invalid_facilitator_retry_configuration() {
    for (key, value) in [
        ("FACILITATOR_SETTLE_RETRIES", "2"),
        ("FACILITATOR_SETTLE_RETRIES", "oops"),
        ("FACILITATOR_VERIFY_RETRIES", "6"),
        ("FACILITATOR_VERIFY_BACKOFF_MS", "0"),
    ] {
        let (status, stderr) = run_expecting_failure(vec![
            ("PAY_TO", PAY_TO),
            ("UPSTREAM_URL", "http://localhost:1"),
            ("RUST_LOG", "off"),
            (key, value),
        ]);
        assert!(!status.success());
        assert!(stderr.contains(key), "{stderr}");
    }
}
// ===========================================================================
// shutdown
// ===========================================================================

#[cfg(unix)]
#[tokio::test]
async fn sigterm_shuts_the_service_down_gracefully_with_exit_code_zero() {
    let mocks = Mocks::start().await;
    let mut svc = Service::start_with(&mocks).await;
    assert_eq!(svc.get("/healthz").await.status(), 200);

    let status = svc.terminate();
    assert!(status.success(), "expected a clean exit, got {status}");
    assert!(
        svc.http.get(svc.url("/healthz")).send().await.is_err(),
        "the port must be closed"
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_in_flight_paid_request_completes_before_shutdown() {
    let mocks = Mocks::start().await;
    let mut reply = UpstreamReply::json(200);
    reply.delay = Some(Duration::from_millis(700));
    mocks.upstream.set_reply(reply);
    let mut svc = Service::start_with(&mocks).await;

    let reqs = svc.requirements("/v1/slow").await;
    let client = svc.http.clone();
    let url = svc.url("/v1/slow");
    let in_flight = tokio::spawn(async move {
        client
            .get(url)
            .header("PAYMENT-SIGNATURE", payment_header(&reqs))
            .send()
            .await
            .unwrap()
    });

    // Wait until the upstream has the request, then ask the service to stop.
    let deadline = Instant::now() + Duration::from_secs(5);
    while mocks.upstream.count() == 0 {
        assert!(
            Instant::now() < deadline,
            "request never reached the upstream"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let status = svc.terminate();

    let resp = in_flight.await.unwrap();
    assert_eq!(
        resp.status(),
        200,
        "graceful shutdown must let the paid request finish"
    );
    assert!(
        resp.headers().contains_key("payment-response"),
        "and settle it"
    );
    assert_eq!(mocks.facilitator.settle_count(), 1);
    assert!(status.success());
}

#[tokio::test]
async fn unknown_routes_return_structured_json_404_with_request_id() {
    let mocks = Mocks::start().await;
    let svc = Service::start_with(&mocks).await;

    let resp = svc.get("/unknown-route").await;
    assert_eq!(resp.status(), 404);
    assert!(resp.headers().contains_key("x-request-id"));
    assert_eq!(
        resp.json::<Value>().await.unwrap(),
        json!({
            "error": "not_found",
            "message": "route not found"
        })
    );
}

#[tokio::test]
async fn request_id_is_echoed_and_forwarded_upstream() {
    let mocks = Mocks::start().await;
    let svc = Service::start_with(&mocks).await;

    // Custom valid request ID.
    let reqs = svc.requirements("/v1/items").await;
    let resp = svc
        .http
        .get(svc.url("/v1/items"))
        .header("PAYMENT-SIGNATURE", payment_header(&reqs))
        .header("X-Request-Id", "trace-client-abc-123")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("x-request-id")
            .unwrap()
            .to_str()
            .unwrap(),
        "trace-client-abc-123"
    );
    assert_eq!(
        mocks.upstream.last().header("x-request-id"),
        Some("trace-client-abc-123")
    );

    // Missing request ID gets auto-generated.
    let health = svc.get("/healthz").await;
    assert_eq!(health.status(), 200);
    let auto_id = health
        .headers()
        .get("x-request-id")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(auto_id.starts_with("req-"));
}

#[tokio::test]
async fn cors_wildcard_handles_preflight_and_exposes_headers() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    env.push(("CORS_ORIGIN".into(), "*".into()));
    let svc = Service::start(env).await;

    // 1. Preflight OPTIONS request on /v1/data.
    let preflight = svc
        .http
        .request(reqwest::Method::OPTIONS, svc.url("/v1/data"))
        .header("Origin", "https://app.kiteai.com")
        .send()
        .await
        .unwrap();
    assert_eq!(preflight.status(), 204);
    assert_eq!(
        preflight
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        "*"
    );
    assert!(preflight
        .headers()
        .contains_key("access-control-allow-methods"));
    assert!(preflight
        .headers()
        .contains_key("access-control-allow-headers"));

    // 2. Unpaid GET challenge on /v1/data includes exposed headers.
    let challenge = svc
        .http
        .get(svc.url("/v1/data"))
        .header("Origin", "https://app.kiteai.com")
        .send()
        .await
        .unwrap();
    assert_eq!(challenge.status(), 402);
    assert_eq!(
        challenge
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        "*"
    );
    let expose = challenge
        .headers()
        .get("access-control-expose-headers")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(expose.contains("Payment-Required"));
    assert!(expose.contains("Payment-Response"));
}

#[tokio::test]
async fn cors_origin_matching_and_vary() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    env.push((
        "CORS_ORIGIN".into(),
        "https://app.example.com,http://localhost:3000".into(),
    ));
    let svc = Service::start(env).await;

    // Matching origin.
    let preflight = svc
        .http
        .request(reqwest::Method::OPTIONS, svc.url("/v1/data"))
        .header("Origin", "https://app.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(preflight.status(), 204);
    assert_eq!(
        preflight
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        "https://app.example.com"
    );
    assert_eq!(preflight.headers().get("vary").unwrap(), "Origin");

    // Unmatched origin.
    let unmatched = svc
        .http
        .request(reqwest::Method::OPTIONS, svc.url("/v1/data"))
        .header("Origin", "https://unauthorized.org")
        .send()
        .await
        .unwrap();
    assert_eq!(unmatched.status(), 204);
    assert!(!unmatched
        .headers()
        .contains_key("access-control-allow-origin"));
}

fn expired_payment_header(requirements: &PaymentRequirements) -> String {
    let payload = kite_x402_axum::types::PaymentPayload {
        x402_version: 2,
        resource: None,
        accepted: requirements.clone(),
        payload: json!({
            "signature": "0xfixture",
            "authorization": {
                "from": PAYER,
                "to": PAY_TO,
                "value": requirements.amount,
                "validAfter": "0",
                "validBefore": "1000",
                "nonce": format!("0x{:064x}", 42),
            }
        }),
        extensions: None,
    };
    STANDARD.encode(serde_json::to_vec(&payload).unwrap())
}

#[tokio::test]
async fn expired_payment_signature_is_rejected_without_calling_facilitator() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    env.push(("PAYMENT_CLOCK_DRIFT_SECS".into(), "10".into()));
    let svc = Service::start(env).await;

    let reqs = svc.requirements("/v1/forecast").await;
    let resp = svc
        .http
        .get(svc.url("/v1/forecast"))
        .header("PAYMENT-SIGNATURE", expired_payment_header(&reqs))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 402);
    let challenge = header_json(&resp, "payment-required");
    assert!(challenge["error"].as_str().unwrap().contains("expired"));
    assert_eq!(mocks.facilitator.verify_count(), 0);
    assert_eq!(mocks.upstream.count(), 0);
}

#[tokio::test]
async fn metrics_endpoint_tracks_unpaid_challenge_and_settlement() {
    let mocks = Mocks::start().await;
    let svc = Service::start_with(&mocks).await;

    // Check initial metrics
    let resp = svc.get("/metrics/x402").await;
    assert_eq!(resp.status(), 200);
    let init_snap: kite_x402_axum::PaymentMetricsSnapshot = resp.json().await.unwrap();
    assert_eq!(init_snap.requests_total, 0);
    assert_eq!(init_snap.challenges_total, 0);
    assert_eq!(init_snap.settlements_success, 0);

    // Make an unpaid probe (returns 402 challenge)
    let probe = svc.get("/v1/forecast").await;
    assert_eq!(probe.status(), 402);

    // Make a paid request that settles
    let paid = svc.pay_get("/v1/forecast").await;
    assert_eq!(paid.status(), 200);

    // Verify metrics updated
    let resp2 = svc.get("/metrics/x402").await;
    assert_eq!(resp2.status(), 200);
    let after_snap: kite_x402_axum::PaymentMetricsSnapshot = resp2.json().await.unwrap();
    assert!(after_snap.requests_total >= 2);
    assert!(after_snap.challenges_total >= 1);
    assert_eq!(after_snap.settlements_success, 1);
    assert_eq!(after_snap.settlement_success_rate, 1.0);
}

#[tokio::test]
async fn response_carries_security_headers_by_default() {
    let mocks = Mocks::start().await;
    let svc = Service::start_with(&mocks).await;

    let res = svc.http.get(svc.url("/healthz")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.headers()["x-content-type-options"], "nosniff");
    assert_eq!(res.headers()["x-frame-options"], "DENY");
    assert_eq!(res.headers()["x-xss-protection"], "0");
    assert_eq!(
        res.headers()["referrer-policy"],
        "strict-origin-when-cross-origin"
    );
    assert_eq!(
        res.headers()["content-security-policy"],
        "default-src 'none'; frame-ancestors 'none'"
    );

    let res = svc.http.get(svc.url("/v1/forecast")).send().await.unwrap();
    assert_eq!(res.status(), 402);
    assert_eq!(res.headers()["x-content-type-options"], "nosniff");
    assert_eq!(res.headers()["x-frame-options"], "DENY");
}

#[tokio::test]
async fn security_headers_can_be_disabled_via_env() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    env.push(("SECURITY_HEADERS_ENABLED".into(), "false".into()));
    let svc = Service::start(env).await;

    let res = svc.http.get(svc.url("/healthz")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert!(!res.headers().contains_key("x-content-type-options"));
    assert!(!res.headers().contains_key("x-frame-options"));
    assert!(!res.headers().contains_key("content-security-policy"));
}

#[tokio::test]
async fn replay_guard_retries_known_failures_and_blocks_completed_payments() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    env.push(("PAYMENT_REPLAY_CACHE_SIZE".into(), "1".into()));
    let svc = Service::start(env).await;
    let requirements = svc.requirements("/v1/items").await;
    let payment = payment_header(&requirements);
    mocks.facilitator.set_verify(Reply::Raw {
        status: 503,
        body: "temporary outage".into(),
    });
    let rejected = svc
        .http
        .get(svc.url("/v1/items"))
        .header("PAYMENT-SIGNATURE", &payment)
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 402);
    assert!(header_json(&rejected, "payment-required")["error"]
        .as_str()
        .unwrap()
        .contains("facilitator verify unavailable"));
    assert_eq!(mocks.upstream.count(), 0);

    mocks.facilitator.set_verify(common::verify_ok());
    mocks.upstream.set_reply(UpstreamReply::json(503));
    let rejected = svc
        .http
        .get(svc.url("/v1/items"))
        .header("X-PAYMENT", &payment)
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 503);
    assert_eq!(mocks.facilitator.settle_count(), 0);

    mocks.upstream.set_reply(UpstreamReply::json(200));
    let completed = svc
        .http
        .get(svc.url("/v1/items"))
        .header("PAYMENT-SIGNATURE", &payment)
        .send()
        .await
        .unwrap();
    assert_eq!(completed.status(), 200);
    assert!(completed.headers().contains_key("payment-response"));
    let duplicate = svc
        .http
        .get(svc.url("/v1/items"))
        .header("X-PAYMENT", &payment)
        .send()
        .await
        .unwrap();
    assert_eq!(duplicate.status(), 402);
    assert!(header_json(&duplicate, "payment-required")["error"]
        .as_str()
        .unwrap()
        .contains("already been used"));
    assert_eq!(mocks.facilitator.verify_count(), 3);
    assert_eq!(mocks.upstream.count(), 2);
    assert_eq!(mocks.facilitator.settle_count(), 1);
}

#[test]
fn refuses_invalid_replay_cache_configuration() {
    for value in ["0", "-1", "1000001", "NaN", "1.5", "18446744073709551616"] {
        let (status, stderr) = run_expecting_failure(vec![
            ("PAY_TO", PAY_TO),
            ("UPSTREAM_URL", "http://localhost:1"),
            ("PAYMENT_REPLAY_CACHE_SIZE", value),
            ("RUST_LOG", "off"),
        ]);
        assert!(!status.success(), "PAYMENT_REPLAY_CACHE_SIZE={value}");
        assert!(
            stderr.contains("PAYMENT_REPLAY_CACHE_SIZE must be an integer between 1 and 1000000"),
            "{stderr}"
        );
    }
}

#[tokio::test]
async fn blank_replay_configuration_keeps_protection_disabled() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    env.push(("PAYMENT_REPLAY_CACHE_SIZE".into(), "  ".into()));
    let svc = Service::start(env).await;
    let payment = payment_header(&svc.requirements("/v1/items").await);
    for _ in 0..2 {
        let response = svc
            .http
            .get(svc.url("/v1/items"))
            .header("PAYMENT-SIGNATURE", &payment)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }
    assert_eq!(mocks.facilitator.verify_count(), 2);
    assert_eq!(mocks.facilitator.settle_count(), 2);
}

#[cfg(unix)]
#[test]
fn refuses_non_unicode_replay_cache_configuration() {
    use std::os::unix::ffi::OsStringExt;

    let output = Command::new(BIN)
        .env_clear()
        .env("PAY_TO", PAY_TO)
        .env("UPSTREAM_URL", "http://localhost:1")
        .env("RUST_LOG", "off")
        .env(
            "PAYMENT_REPLAY_CACHE_SIZE",
            std::ffi::OsString::from_vec(vec![0xff]),
        )
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("PAYMENT_REPLAY_CACHE_SIZE must be an integer between 1 and 1000000"));
}

#[tokio::test]
async fn replay_guard_capacity_preserves_records_and_keeps_health_routes_free() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    env.push(("PAYMENT_REPLAY_CACHE_SIZE".into(), "1".into()));
    let svc = Service::start(env).await;
    let requirements = svc.requirements("/v1/items").await;
    let encode = |nonce: &str| {
        STANDARD.encode(serde_json::to_vec(&json!({
        "x402Version": 2,
        "accepted": requirements,
        "payload": {"signature":"test-signature", "authorization":{"from":PAYER, "nonce":nonce}}
    })).unwrap())
    };
    let first = encode("0xaaaa");
    let second = encode("0xbbbb");
    let completed = svc
        .http
        .get(svc.url("/v1/items"))
        .header("PAYMENT-SIGNATURE", &first)
        .send()
        .await
        .unwrap();
    assert_eq!(completed.status(), 200);
    let saturated = svc
        .http
        .get(svc.url("/v1/items"))
        .header("PAYMENT-SIGNATURE", &second)
        .send()
        .await
        .unwrap();
    assert_eq!(saturated.status(), 503);
    assert_eq!(saturated.headers()["cache-control"], "no-store");
    assert_eq!(saturated.headers()["retry-after"], "1");
    assert_eq!(
        saturated.json::<Value>().await.unwrap()["error"],
        "payment_replay_capacity_exceeded"
    );
    assert_eq!(
        svc.http
            .get(svc.url("/v1/items"))
            .header("PAYMENT-SIGNATURE", &first)
            .send()
            .await
            .unwrap()
            .status(),
        402
    );
    for path in ["/healthz", "/livez", "/metrics"] {
        assert_eq!(svc.get(path).await.status(), 200);
    }
    assert_eq!(mocks.facilitator.verify_count(), 1);
    assert_eq!(mocks.upstream.count(), 1);
    assert_eq!(mocks.facilitator.settle_count(), 1);
}

#[tokio::test]
async fn replay_guard_retains_authorization_after_uncertain_settlement() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    env.extend([
        ("PAYMENT_REPLAY_CACHE_SIZE".into(), "1".into()),
        ("FACILITATOR_TIMEOUT_MS".into(), "200".into()),
        ("FACILITATOR_SETTLE_RETRIES".into(), "0".into()),
    ]);
    let svc = Service::start(env).await;
    let payment = payment_header(&svc.requirements("/v1/items").await);
    mocks
        .facilitator
        .set_settle(Reply::Delayed(Duration::from_secs(60), json!({})));
    let uncertain = svc
        .http
        .get(svc.url("/v1/items"))
        .header("PAYMENT-SIGNATURE", &payment)
        .send()
        .await
        .unwrap();
    assert_eq!(uncertain.status(), 402);
    assert_eq!(
        header_json(&uncertain, "payment-response")["success"],
        false
    );
    let duplicate = svc
        .http
        .get(svc.url("/v1/items"))
        .header("PAYMENT-SIGNATURE", &payment)
        .send()
        .await
        .unwrap();
    assert_eq!(duplicate.status(), 402);
    assert!(header_json(&duplicate, "payment-required")["error"]
        .as_str()
        .unwrap()
        .contains("already been used"));
    assert_eq!(mocks.facilitator.verify_count(), 1);
    assert_eq!(mocks.upstream.count(), 1);
    assert_eq!(mocks.facilitator.settle_count(), 1);
}

#[tokio::test]
async fn replayed_payment_signature_is_rejected_on_second_request() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    env.push(("PAYMENT_REPLAY_CACHE_SIZE".into(), "100".into()));
    let svc = Service::start(env).await;

    let reqs = svc.requirements("/v1/forecast").await;
    let header_val = payment_header(&reqs);

    let resp1 = svc
        .http
        .get(svc.url("/v1/forecast"))
        .header("PAYMENT-SIGNATURE", &header_val)
        .send()
        .await
        .unwrap();
    assert_eq!(resp1.status(), 200);
    assert_eq!(mocks.facilitator.verify_count(), 1);

    let resp2 = svc
        .http
        .get(svc.url("/v1/forecast"))
        .header("PAYMENT-SIGNATURE", &header_val)
        .send()
        .await
        .unwrap();
    assert_eq!(resp2.status(), 402);
    let challenge = header_json(&resp2, "payment-required");
    assert!(challenge["error"]
        .as_str()
        .unwrap()
        .contains("already been used"));
    assert_eq!(mocks.facilitator.verify_count(), 1);
}

#[tokio::test]
async fn concurrency_overflow_rejects_with_503_before_payment_and_releases_after() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    env.push(("MAX_CONCURRENT_REQUESTS".into(), "1".into()));
    let mut reply = UpstreamReply::json(200);
    reply.delay = Some(Duration::from_millis(600));
    mocks.upstream.set_reply(reply);
    let svc = Service::start(env).await;

    let reqs = svc.requirements("/v1/items").await;
    let client = svc.http.clone();
    let url = svc.url("/v1/items");
    let sig = payment_header(&reqs);

    // In-flight request #1 takes the 1 available slot
    let in_flight = tokio::spawn({
        let client = client.clone();
        let url = url.clone();
        let sig = sig.clone();
        async move {
            client
                .get(url)
                .header("PAYMENT-SIGNATURE", sig)
                .send()
                .await
                .unwrap()
        }
    });

    // Wait for request #1 to reach upstream
    let deadline = Instant::now() + Duration::from_secs(5);
    while mocks.upstream.count() == 0 {
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Request #2 arrives while capacity is saturated: must be rejected with 503
    let overflow = client.get(&url).send().await.unwrap();
    assert_eq!(overflow.status(), 503);
    assert_eq!(
        overflow
            .headers()
            .get("retry-after")
            .unwrap()
            .to_str()
            .unwrap(),
        "1"
    );
    assert_eq!(
        overflow
            .headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap(),
        "no-store"
    );
    assert_eq!(
        overflow.json::<Value>().await.unwrap(),
        json!({ "error": "service_busy" })
    );

    // Healthz is outside /v1 and remains accessible during saturation
    let health = svc.get("/healthz").await;
    assert_eq!(health.status(), 200);

    // Let in-flight request finish
    let resp1 = in_flight.await.unwrap();
    assert_eq!(resp1.status(), 200);

    // Reset reply delay to zero
    mocks.upstream.set_reply(UpstreamReply::json(200));

    // Request #3 after slot release succeeds
    let resp3 = client.get(&url).send().await.unwrap();
    assert_eq!(
        resp3.status(),
        402,
        "Challenge issued after permit released"
    );
}

#[test]
fn refuses_invalid_max_concurrent_requests() {
    for invalid in ["0", "-1", "not_a_number", "10001"] {
        let (status, stderr) = run_expecting_failure(vec![
            ("PAY_TO", PAY_TO),
            ("UPSTREAM_URL", "http://localhost:1"),
            ("MAX_CONCURRENT_REQUESTS", invalid),
            ("RUST_LOG", "off"),
        ]);
        assert!(
            !status.success(),
            "MAX_CONCURRENT_REQUESTS={invalid} must cause startup failure"
        );
        assert!(
            stderr.contains("MAX_CONCURRENT_REQUESTS"),
            "stderr should mention MAX_CONCURRENT_REQUESTS: {stderr}"
        );
    }
}

#[test]
fn refuses_an_invalid_shutdown_timeout() {
    for bad in ["abc", "-1", "0", "86401", "18446744073709551615"] {
        let (status, stderr) = run_expecting_failure(vec![
            ("PAY_TO", PAY_TO),
            ("UPSTREAM_URL", "http://localhost:1"),
            ("SHUTDOWN_TIMEOUT_SECONDS", bad),
            ("RUST_LOG", "off"),
        ]);
        assert!(!status.success(), "SHUTDOWN_TIMEOUT_SECONDS={bad:?}");
        assert!(
            stderr.contains("SHUTDOWN_TIMEOUT_SECONDS must be an integer between 1 and 86400"),
            "SHUTDOWN_TIMEOUT_SECONDS={bad:?}: {stderr}"
        );
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_timeout_forces_exit_when_exceeded() {
    let mocks = Mocks::start().await;
    let mut reply = UpstreamReply::json(200);
    // Upstream delay is 5s, but shutdown timeout is 1s
    reply.delay = Some(Duration::from_millis(5000));
    mocks.upstream.set_reply(reply);

    let mut env = Service::base_env(&mocks, free_port());
    env.push(("SHUTDOWN_TIMEOUT_SECONDS".into(), "1".into()));
    let mut svc = Service::start(env).await;

    let reqs = svc.requirements("/v1/stuck").await;
    let client = svc.http.clone();
    let url = svc.url("/v1/stuck");
    tokio::spawn(async move {
        let _ = client
            .get(url)
            .header("PAYMENT-SIGNATURE", payment_header(&reqs))
            .send()
            .await;
    });

    let deadline = Instant::now() + Duration::from_secs(5);
    while mocks.upstream.count() == 0 {
        assert!(
            Instant::now() < deadline,
            "request never reached the upstream"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let start = Instant::now();
    let status = svc.terminate();
    let elapsed = start.elapsed();

    // The shutdown timeout was 1s, so the process must exit well before the 5s upstream delay
    assert!(
        elapsed < Duration::from_millis(3500),
        "shutdown should have timed out and terminated within ~1-2s, took {elapsed:?}"
    );
    assert!(status.success());
    assert_eq!(
        mocks.facilitator.settle_count(),
        0,
        "unfinished responses must not settle"
    );
}

#[tokio::test]
async fn shutdown_timeout_does_not_limit_server_uptime() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    env.push(("SHUTDOWN_TIMEOUT_SECONDS".into(), "1".into()));
    let svc = Service::start(env).await;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(svc.get("/healthz").await.status(), 200);
}

// Keep the import used on non-unix targets too.
#[allow(dead_code)]
fn _unused(_: Reply) {}

// ---------------------------------------------------------------------------
// background facilitator health probe (FACILITATOR_HEALTH_INTERVAL_SECS)
// ---------------------------------------------------------------------------

/// A facilitator whose `/supported` endpoint counts how often it is hit.
async fn counting_facilitator(
    kinds: Value,
) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::{atomic::Ordering, Arc};

    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    let app = axum::Router::new().route(
        "/supported",
        axum::routing::get(move || {
            let counter = Arc::clone(&counter);
            let kinds = kinds.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                axum::Json(json!({"kinds": kinds}))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), hits)
}

fn env_with(mut env: Vec<(String, String)>, key: &str, value: &str) -> Vec<(String, String)> {
    env.retain(|(k, _)| k != key);
    env.push((key.into(), value.into()));
    env
}

#[tokio::test]
async fn background_probe_startup_does_not_fall_back_to_live_requests() {
    use std::sync::{atomic::Ordering, Arc};

    let mocks = Mocks::start().await;
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let app = axum::Router::new().route(
        "/supported",
        axum::routing::get({
            let hits = Arc::clone(&hits);
            let release = Arc::clone(&release);
            move || {
                let hits = Arc::clone(&hits);
                let release = Arc::clone(&release);
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    // Hold the initial probe open without relying on a slow timer.
                    release.acquire().await.unwrap().forget();
                    axum::Json(json!({"kinds": [
                        {"x402Version": 2, "scheme": "exact", "network": "eip155:2368"}
                    ]}))
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let env = env_with(
        Service::base_env(&mocks, free_port()),
        "FACILITATOR_URL",
        &format!("http://{addr}"),
    );
    let env = env_with(env, "FACILITATOR_HEALTH_INTERVAL_SECS", "86400");
    let svc = Service::start(env).await;

    let deadline = Instant::now() + Duration::from_secs(10);
    while hits.load(Ordering::SeqCst) == 0 {
        assert!(Instant::now() < deadline, "initial probe never started");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    for _ in 0..10 {
        let resp = tokio::time::timeout(Duration::from_secs(2), svc.get("/readyz"))
            .await
            .expect("readiness must not wait for the initial facilitator probe");
        assert_eq!(resp.status(), 503);
        let body = resp.json::<Value>().await.unwrap();
        assert_eq!(body["status"], "not_ready");
        assert_eq!(body["facilitator"], "pending");
        assert!(body.get("checked_at").is_none());
    }
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert_eq!(svc.get("/healthz").await.status(), 200);

    release.add_permits(1);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let resp = svc.get("/readyz").await;
        if resp.status() == 200 {
            let body = resp.json::<Value>().await.unwrap();
            assert_eq!(body["facilitator"], "ok");
            assert!(body["checked_at"].as_u64().unwrap() > 0);
            break;
        }
        assert_eq!(resp.status(), 503);
        assert!(
            Instant::now() < deadline,
            "initial result never reached the cache"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert!(
        mocks.timeline().is_empty(),
        "health polling must not invoke payment or upstream work"
    );
    server.abort();
}

#[tokio::test]
async fn background_probe_serves_readyz_from_cache_instead_of_probing_per_request() {
    use std::sync::atomic::Ordering;

    let mocks = Mocks::start().await;
    let (facilitator_url, hits) = counting_facilitator(json!([
        {"x402Version": 2, "scheme": "exact", "network": "eip155:2368"}
    ]))
    .await;
    let env = env_with(
        Service::base_env(&mocks, free_port()),
        "FACILITATOR_URL",
        &facilitator_url,
    );
    let env = env_with(env, "FACILITATOR_HEALTH_INTERVAL_SECS", "30");
    let svc = Service::start(env).await;

    // The first probe runs right at startup; wait until it has landed.
    let deadline = Instant::now() + Duration::from_secs(10);
    while hits.load(Ordering::SeqCst) == 0 {
        assert!(Instant::now() < deadline, "no background probe within 10s");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let before = hits.load(Ordering::SeqCst);

    for _ in 0..10 {
        let resp = svc.get("/readyz").await;
        assert_eq!(resp.status(), 200);
        let body = resp.json::<Value>().await.unwrap();
        assert_eq!(body["status"], "ready");
        assert!(body["checked_at"].as_u64().unwrap() > 0);
    }
    assert_eq!(
        hits.load(Ordering::SeqCst),
        before,
        "/readyz must not contact the facilitator when the background probe is on"
    );
}

#[tokio::test]
async fn background_probe_checks_route_specific_networks() {
    use std::sync::atomic::Ordering;

    let mocks = Mocks::start().await;
    let (facilitator_url, hits) = counting_facilitator(json!([
        {"x402Version": 2, "scheme": "exact", "network": "eip155:2368"}
    ]))
    .await;
    let env = env_with(
        Service::base_env(&mocks, free_port()),
        "FACILITATOR_URL",
        &facilitator_url,
    );
    let env = env_with(env, "FACILITATOR_HEALTH_INTERVAL_SECS", "86400");
    let env = env_with(
        env,
        "ROUTE_PRICES_USD",
        r#"[{"method":"GET","path":"/v1/reports/{id}","price":"0.05","extra_payment_options":[{"network":"mainnet","price":"0.06"}]}]"#,
    );
    let svc = Service::start(env).await;

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let resp = svc.get("/readyz").await;
        let status = resp.status();
        let body = resp.json::<Value>().await.unwrap();
        if body.get("checked_at").is_some() {
            assert_eq!(status, 503);
            assert_eq!(body["networks"], json!(["eip155:2366", "eip155:2368"]));
            assert!(body["error"].as_str().unwrap().contains("eip155:2366"));
            break;
        }
        assert!(Instant::now() < deadline, "no cached result within 10s");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(svc.get("/readyz").await.status(), 503);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn background_probe_reports_an_unreachable_facilitator_as_503_with_check_time() {
    let mocks = Mocks::start().await;
    let env = env_with(
        Service::base_env(&mocks, free_port()),
        "FACILITATOR_URL",
        "http://127.0.0.1:1",
    );
    let env = env_with(env, "FACILITATOR_HEALTH_INTERVAL_SECS", "30");
    let svc = Service::start(env).await;

    // Readiness stays 503 while the initial probe is pending and after it
    // fails; only a completed probe has `checked_at`.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let resp = svc.get("/readyz").await;
        assert_eq!(resp.status(), 503);
        let body = resp.json::<Value>().await.unwrap();
        assert_eq!(body["status"], "not_ready");
        if body.get("checked_at").is_some() {
            assert_eq!(body["facilitator"], "unreachable");
            return;
        }
        assert!(Instant::now() < deadline, "no cached result within 10s");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[test]
fn refuses_invalid_facilitator_health_interval() {
    for value in ["abc", "-1", "1.5", "86401"] {
        let (status, stderr) = run_expecting_failure(vec![
            ("PAY_TO", PAY_TO),
            ("UPSTREAM_URL", "http://localhost:1"),
            ("FACILITATOR_HEALTH_INTERVAL_SECS", value),
            ("RUST_LOG", "off"),
        ]);
        assert!(!status.success(), "{value} must fail startup");
        assert!(
            stderr.contains("FACILITATOR_HEALTH_INTERVAL_SECS"),
            "{value}: {stderr}"
        );
    }
}

// ---------------------------------------------------------------------------
// EXTRA_PAYMENT_OPTIONS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn extra_payment_options_are_advertised_after_the_primary() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    env.push(("EXTRA_PAYMENT_OPTIONS".into(), "mainnet:$0.05".into()));
    let svc = Service::start(env).await;

    let resp = svc.get("/v1/forecast").await;
    assert_eq!(resp.status(), 402);
    let challenge = header_json(&resp, "payment-required");
    let accepts = challenge["accepts"].as_array().unwrap();
    assert_eq!(accepts.len(), 2, "primary plus one extra option");

    // Primary first: testnet pieUSD, 18 decimals.
    assert_eq!(accepts[0]["network"], "eip155:2368");
    assert_eq!(accepts[0]["amount"], "1000000000000000");
    // The extra option follows in configured order: mainnet USDC.e, 6 decimals.
    assert_eq!(accepts[1]["network"], "eip155:2366");
    assert_eq!(accepts[1]["amount"], "50000");
    assert_eq!(accepts[1]["payTo"], PAY_TO);

    // Paying the extra option settles against that option's requirements.
    let chosen: PaymentRequirements = serde_json::from_value(accepts[1].clone()).unwrap();
    mocks.facilitator.set_settle(settle_ok(&chosen.network));
    let resp = svc
        .http
        .get(svc.url("/v1/forecast"))
        .header("PAYMENT-SIGNATURE", payment_header(&chosen))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        header_json(&resp, "payment-response")["network"],
        chosen.network
    );
    assert_eq!(
        mocks.timeline(),
        vec!["verify", "upstream", "settle"],
        "the extra option must verify and settle like the primary"
    );
    let sent = mocks.facilitator.verify_requests.lock().unwrap()[0].clone();
    assert_eq!(
        sent["paymentRequirements"]["network"], "eip155:2366",
        "the facilitator must see the option the client chose"
    );
}

#[tokio::test]
async fn extra_payment_options_keep_the_single_option_shape_when_unset() {
    let mocks = Mocks::start().await;
    let svc = Service::start_with(&mocks).await;

    let resp = svc.get("/v1/forecast").await;
    assert_eq!(resp.status(), 402);
    let challenge = header_json(&resp, "payment-required");
    assert_eq!(
        challenge["accepts"].as_array().unwrap().len(),
        1,
        "no EXTRA_PAYMENT_OPTIONS means exactly the primary option"
    );
}

#[test]
fn refuses_malformed_extra_payment_options() {
    for value in ["no-colon-here", "devnet:0.01"] {
        let (status, stderr) = run_expecting_failure(vec![
            ("PAY_TO", PAY_TO),
            ("UPSTREAM_URL", "http://localhost:1"),
            ("EXTRA_PAYMENT_OPTIONS", value),
            ("RUST_LOG", "off"),
        ]);
        assert!(!status.success(), "{value} must fail startup");
        assert!(
            stderr.contains("EXTRA_PAYMENT_OPTIONS"),
            "{value}: {stderr}"
        );
    }
}

#[test]
fn refuses_duplicate_extra_payment_options() {
    for (value, expected_error) in [
        (
            "mainnet:0.001",
            "default payment options option 2 duplicates an earlier payment option",
        ),
        (
            "mainnet:0.05,mainnet:$0.05",
            "default payment options option 3 duplicates an earlier payment option",
        ),
    ] {
        let (status, stderr) = run_expecting_failure(vec![
            ("PAY_TO", PAY_TO),
            ("UPSTREAM_URL", "http://localhost:1"),
            ("EXTRA_PAYMENT_OPTIONS", value),
            ("RUST_LOG", "off"),
        ]);
        assert!(!status.success(), "{value} must fail startup");
        assert!(stderr.contains(expected_error), "{value}: {stderr}");
    }
}
