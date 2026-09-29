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
    StdListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// A running service process, killed on drop so a failing test never leaks it.
struct Service {
    child: Child,
    port: u16,
    http: reqwest::Client,
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

    async fn start(env: Vec<(String, String)>) -> Service {
        let port: u16 = env.iter().find(|(k, _)| k == "PORT").map(|(_, v)| v.parse().unwrap()).unwrap();
        let child = Command::new(BIN)
            .env_clear()
            .envs(env)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn service binary");
        let mut svc = Service {
            child,
            port,
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

    async fn start_with(mocks: &Mocks) -> Service {
        Self::start(Self::base_env(mocks, free_port())).await
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    async fn wait_until_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!("service exited during startup with {status}: {}", self.stderr_so_far());
            }
            if self.http.get(self.url("/healthz")).send().await.is_ok() {
                return;
            }
            assert!(Instant::now() < deadline, "service did not become ready in 20s");
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
        let status = Command::new("kill").args(["-TERM", &self.child.id().to_string()]).status().unwrap();
        assert!(status.success());
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                return s;
            }
            assert!(Instant::now() < deadline, "service did not stop within 10s of SIGTERM");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn header_json(resp: &reqwest::Response, name: &str) -> Value {
    let raw = resp.headers().get(name).unwrap_or_else(|| panic!("missing {name}")).to_str().unwrap();
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
    (out.status, String::from_utf8_lossy(&out.stderr).into_owned())
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
    assert_eq!(resp.json::<Value>().await.unwrap(), json!({ "status": "ok" }));
    assert!(mocks.timeline().is_empty());
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
    assert_eq!(challenge["resource"]["url"], "/v1/forecast?latitude=52.52&longitude=13.41");
    assert_eq!(challenge["accepts"][0]["payTo"], PAY_TO);
    assert_eq!(challenge["accepts"][0]["network"], "eip155:2368");
    assert!(mocks.timeline().is_empty(), "a challenge must be free of side effects");

    // 2. paid request -> 200 + receipt + upstream body
    let reqs: PaymentRequirements = serde_json::from_value(challenge["accepts"][0].clone()).unwrap();
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
    assert_eq!(paid.json::<Value>().await.unwrap(), json!({ "upstream": true }));

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
    assert_eq!(seen.header("payment-signature"), None, "the payment must not reach the upstream");
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
    assert_eq!(resp.json::<Value>().await.unwrap()["error"], "upstream unreachable");
    assert_eq!(mocks.facilitator.settle_count(), 0);
}

#[tokio::test]
async fn a_rejected_payment_is_a_402_and_the_upstream_is_never_called() {
    let mocks = Mocks::start().await;
    mocks.facilitator.set_verify(verify_invalid(Some("insufficient_funds")));
    let svc = Service::start_with(&mocks).await;

    let resp = svc.pay_get("/v1/forecast").await;
    assert_eq!(resp.status(), 402);
    assert_eq!(header_json(&resp, "payment-required")["error"], "insufficient_funds");
    assert_eq!(mocks.upstream.count(), 0);
    assert_eq!(mocks.facilitator.settle_count(), 0);
}

#[tokio::test]
async fn a_failed_settlement_withholds_the_upstream_data() {
    let mocks = Mocks::start().await;
    mocks.facilitator.set_settle(settle_failed("nonce_already_used", "eip155:2368"));
    let svc = Service::start_with(&mocks).await;

    let resp = svc.pay_get("/v1/forecast").await;
    assert_eq!(resp.status(), 402);
    assert_eq!(header_json(&resp, "payment-response")["errorReason"], "nonce_already_used");
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
    assert_eq!(header_json(&resp, "payment-required")["error"], "No matching payment requirements");
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
    assert_eq!((reqs.network.as_str(), reqs.amount.as_str()), ("eip155:2366", "1000"));
}

#[tokio::test]
async fn service_description_appears_in_the_challenge() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    env.push(("SERVICE_DESCRIPTION".into(), "Weather forecasts".into()));
    let svc = Service::start(env).await;

    let resp = svc.get("/v1/x").await;
    assert_eq!(header_json(&resp, "payment-required")["resource"]["description"], "Weather forecasts");
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

    assert_eq!(mocks.upstream.last().header_all("x-api-key"), vec!["k-12345"]);
}

#[tokio::test]
async fn upstream_credential_defaults_to_the_authorization_header() {
    let mocks = Mocks::start().await;
    let mut env = Service::base_env(&mocks, free_port());
    env.push(("UPSTREAM_AUTH_VALUE".into(), "Bearer tok".into()));
    let svc = Service::start(env).await;

    svc.pay_get("/v1/x").await;
    assert_eq!(mocks.upstream.last().header("authorization"), Some("Bearer tok"));
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
    assert_eq!(mocks.upstream.last().path_and_query, "/forecast", "no '//forecast'");
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
    assert_eq!(resp.status(), 402, "a wrong facilitator path must never let a request through");
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
    assert!(resp.json::<Value>().await.unwrap()["error"].as_str().unwrap().contains("invalid PRICE_USD"));
}

// ===========================================================================
// startup failures
// ===========================================================================

#[test]
fn refuses_to_start_without_pay_to() {
    let (status, stderr) = run_expecting_failure(vec![("UPSTREAM_URL", "http://localhost:1"), ("RUST_LOG", "off")]);
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
        assert!(stderr.contains("PORT must be a number"), "PORT={bad:?}: {stderr}");
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
    assert!(svc.http.get(svc.url("/healthz")).send().await.is_err(), "the port must be closed");
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
        assert!(Instant::now() < deadline, "request never reached the upstream");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let status = svc.terminate();

    let resp = in_flight.await.unwrap();
    assert_eq!(resp.status(), 200, "graceful shutdown must let the paid request finish");
    assert!(resp.headers().contains_key("payment-response"), "and settle it");
    assert_eq!(mocks.facilitator.settle_count(), 1);
    assert!(status.success());
}

// Keep the import used on non-unix targets too.
#[allow(dead_code)]
fn _unused(_: Reply) {}
