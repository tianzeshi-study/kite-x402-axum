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
    io::Read,
    net::TcpListener as StdListener,
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use common::{
    payment_header, settle_failed, verify_invalid, Mocks, Reply, UpstreamReply, PAYER, TX_HASH,
};
use kite_x402_axum::types::PaymentRequirements;
use serde_json::{json, Value};

const BIN: &str = env!("CARGO_BIN_EXE_kite-x402-service");
const PAY_TO: &str = "0xE2E0000000000000000000000000000000000E2E";

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
        json!({ "status": "ok" })
    );
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
        "/v1/forecast?latitude=52.52&longitude=13.41"
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

// Keep the import used on non-unix targets too.
#[allow(dead_code)]
fn _unused(_: Reply) {}
