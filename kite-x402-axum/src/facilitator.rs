//! A small HTTP client for the Kite facilitator's `/verify` and `/settle`
//! endpoints. Mirrors the request/response shape the TypeScript and Go
//! SDKs put on the wire: `POST {base}/verify` and `POST {base}/settle`
//! with `{x402Version, paymentPayload, paymentRequirements}`, JSON in,
//! JSON out.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::types::{PaymentPayload, PaymentRequirements, SettleResponse, VerifyResponse};

/// Default per-request timeout for facilitator HTTP calls.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Retry policy for verification only. Settlement outcomes may be unknown after
/// a transport or server error, so settlement is never automatically repeated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum retries for transient verification failures. 0 disables retries.
    pub max_retries: u32,
    /// Initial backoff delay for the first retry.
    pub initial_backoff: Duration,
    /// Upper bound for exponential backoff delay.
    pub max_backoff: Duration,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 0,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(2),
        }
    }
}

impl RetryConfig {
    /// Creates a new retry configuration.
    #[must_use]
    pub fn new(max_retries: u32, initial_backoff: Duration, max_backoff: Duration) -> Self {
        Self {
            max_retries,
            initial_backoff,
            max_backoff,
        }
    }

    /// Calculates backoff duration for the given 0-indexed attempt using exponential backoff.
    #[must_use]
    pub fn calculate_backoff(&self, attempt: u32) -> Duration {
        let factor = 2u32.saturating_pow(attempt);
        let backoff = self.initial_backoff.saturating_mul(factor);
        std::cmp::min(backoff, self.max_backoff)
    }
}

/// A facilitator call failed at the transport or protocol level (the
/// facilitator was unreachable, timed out, or returned something that
/// isn't a valid verify/settle response). This is distinct from the
/// facilitator successfully answering "payment invalid" or "settlement
/// failed", which are ordinary [`VerifyResponse`]/[`SettleResponse`]
/// values, not errors.
#[derive(Debug, Error)]
pub enum FacilitatorError {
    /// The HTTP request to the facilitator failed (network, TLS, timeout, or decoding error).
    #[error("facilitator request failed: {0}")]
    Request(#[from] reqwest::Error),
    /// The facilitator answered with a non-success status or an unparseable body.
    #[error("facilitator {op} returned {status}: {body}")]
    BadResponse {
        /// The operation being performed (e.g. `verify` or `settle`).
        op: &'static str,
        /// HTTP status code returned by the facilitator.
        status: u16,
        /// Response body returned by the facilitator.
        body: String,
    },
}

/// HTTP client for one facilitator base URL (e.g.
/// `https://facilitator.pieverse.io/v2`, keeping the `/v2`: the facilitator
/// appends `/verify` and `/settle` to whatever base URL it is given).
#[derive(Clone, Debug)]
pub struct FacilitatorClient {
    http: reqwest::Client,
    base_url: String,
    retry_config: RetryConfig,
}

#[derive(Serialize)]
struct FacilitatorRequest<'a> {
    #[serde(rename = "x402Version")]
    x402_version: u32,
    #[serde(rename = "paymentPayload")]
    payment_payload: &'a PaymentPayload,
    #[serde(rename = "paymentRequirements")]
    payment_requirements: &'a PaymentRequirements,
}

impl FacilitatorClient {
    /// Returns the facilitator base URL.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Returns the active retry configuration.
    #[must_use]
    pub fn retry_config(&self) -> RetryConfig {
        self.retry_config
    }

    /// Sets retry configuration using a builder pattern.
    #[must_use]
    pub fn with_retry_config(mut self, config: RetryConfig) -> Self {
        self.retry_config = config;
        self
    }

    /// Sets retry configuration in-place.
    pub fn set_retry_config(&mut self, config: RetryConfig) {
        self.retry_config = config;
    }

    /// Builds a client for `base_url` with [`DEFAULT_TIMEOUT`].
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::with_timeout(base_url, DEFAULT_TIMEOUT)
    }

    /// Builds a client for `base_url` with a custom per-request timeout.
    pub fn with_timeout(base_url: impl Into<String>, timeout: Duration) -> Self {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .expect("reqwest client with default TLS backend");
        Self {
            http,
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            retry_config: RetryConfig::default(),
        }
    }

    /// Builds a client for `base_url` with custom timeout and retry configuration.
    pub fn with_retry(
        base_url: impl Into<String>,
        timeout: Duration,
        retry_config: RetryConfig,
    ) -> Self {
        Self::with_timeout(base_url, timeout).with_retry_config(retry_config)
    }

    /// Calls `POST {base_url}/verify`.
    pub async fn verify(
        &self,
        payload: &PaymentPayload,
        requirements: &PaymentRequirements,
    ) -> Result<VerifyResponse, FacilitatorError> {
        self.call("verify", payload, requirements).await
    }

    /// Calls `POST {base_url}/settle`.
    pub async fn settle(
        &self,
        payload: &PaymentPayload,
        requirements: &PaymentRequirements,
    ) -> Result<SettleResponse, FacilitatorError> {
        self.call("settle", payload, requirements).await
    }

    /// Checks connectivity to the facilitator. Returns `Ok(())` if the facilitator
    /// responds with status < 500, or a [`FacilitatorError`] on connection failure or 5xx.
    pub async fn probe(&self) -> Result<(), FacilitatorError> {
        let url = format!("{}/supported", self.base_url);
        tracing::debug!(url = %url, "Probing facilitator readiness");

        let response = match self.http.get(&url).send().await {
            Ok(resp) => resp,
            Err(err) => {
                let base_resp = self.http.get(&self.base_url).send().await;
                match base_resp {
                    Ok(r) if r.status().as_u16() < 500 => return Ok(()),
                    _ => {
                        tracing::error!(url = %url, error = %err, "Facilitator probe failed");
                        return Err(FacilitatorError::Request(err));
                    }
                }
            }
        };

        let status = response.status();
        if status.as_u16() < 500 {
            Ok(())
        } else {
            let body = response.text().await.unwrap_or_default();
            Err(FacilitatorError::BadResponse {
                op: "probe",
                status: status.as_u16(),
                body,
            })
        }
    }

    async fn call<T: serde::de::DeserializeOwned>(
        &self,
        op: &'static str,
        payload: &PaymentPayload,
        requirements: &PaymentRequirements,
    ) -> Result<T, FacilitatorError> {
        let max_retries = if op == "verify" {
            self.retry_config.max_retries
        } else {
            0
        };

        let mut attempt = 0;
        loop {
            match self.send_single(op, payload, requirements).await {
                Ok(resp) => return Ok(resp),
                Err(err) => {
                    let is_transient = match &err {
                        FacilitatorError::Request(error) => {
                            error.is_connect() || error.is_timeout()
                        }
                        FacilitatorError::BadResponse { status, .. } => {
                            *status >= 500 && *status < 600
                        }
                    };

                    if attempt < max_retries && is_transient {
                        let backoff = self.retry_config.calculate_backoff(attempt);
                        tracing::warn!(
                            op = %op,
                            attempt = attempt + 1,
                            max_retries = max_retries,
                            backoff_ms = backoff.as_millis(),
                            error = %err,
                            "Transient facilitator failure, retrying with backoff"
                        );
                        tokio::time::sleep(backoff).await;
                        attempt += 1;
                    } else {
                        return Err(err);
                    }
                }
            }
        }
    }

    async fn send_single<T: serde::de::DeserializeOwned>(
        &self,
        op: &'static str,
        payload: &PaymentPayload,
        requirements: &PaymentRequirements,
    ) -> Result<T, FacilitatorError> {
        let body = FacilitatorRequest {
            x402_version: payload.x402_version,
            payment_payload: payload,
            payment_requirements: requirements,
        };

        let url = format!("{}/{op}", self.base_url);
        tracing::debug!(op = %op, url = %url, "Sending HTTP request to facilitator");

        let response = match self.http.post(&url).json(&body).send().await {
            Ok(resp) => resp,
            Err(err) => {
                tracing::error!(op = %op, url = %url, error = %err, "Facilitator HTTP request failed");
                return Err(FacilitatorError::Request(err));
            }
        };

        let status = response.status();
        let text = response.text().await.unwrap_or_default();

        if !status.is_success() {
            tracing::warn!(
                op = %op,
                url = %url,
                status = status.as_u16(),
                body = %text,
                "Facilitator returned non-success HTTP status"
            );
            return Err(FacilitatorError::BadResponse {
                op,
                status: status.as_u16(),
                body: text,
            });
        }

        tracing::debug!(
            op = %op,
            url = %url,
            status = status.as_u16(),
            "Facilitator returned success HTTP status"
        );

        serde_json::from_str(&text).map_err(|e| {
            tracing::error!(
                op = %op,
                url = %url,
                status = status.as_u16(),
                error = %e,
                body = %text,
                "Failed to parse facilitator JSON response"
            );
            FacilitatorError::BadResponse {
                op,
                status: status.as_u16(),
                body: format!("could not parse facilitator {op} response: {e}"),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use axum::{
        body::to_bytes,
        extract::{Request, State},
        http::{header, StatusCode},
        response::{IntoResponse, Response},
        Router,
    };
    use serde_json::{json, Value};
    use tokio::net::TcpListener;

    /// One request as the fake facilitator saw it.
    #[derive(Clone, Debug)]
    struct Seen {
        path: String,
        content_type: Option<String>,
        body: Value,
    }

    /// A minimal fake facilitator: records requests, answers every `/verify`
    /// and `/settle` (under any prefix) with a canned `(status, body)`.
    struct Fake {
        verify: Mutex<(u16, String)>,
        settle: Mutex<(u16, String)>,
        settle_sequence: Mutex<Vec<(u16, String)>>,
        delay: Mutex<Option<Duration>>,
        seen: Mutex<Vec<Seen>>,
    }

    impl Fake {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                verify: Mutex::new((200, json!({ "isValid": true }).to_string())),
                settle: Mutex::new((
                    200,
                    json!({ "success": true, "transaction": "0xtx", "network": "eip155:2368" })
                        .to_string(),
                )),
                settle_sequence: Mutex::new(vec![]),
                delay: Mutex::new(None),
                seen: Mutex::new(vec![]),
            })
        }
        fn set_verify(&self, status: u16, body: &str) {
            *self.verify.lock().unwrap() = (status, body.to_owned());
        }
        fn set_settle(&self, status: u16, body: &str) {
            *self.settle.lock().unwrap() = (status, body.to_owned());
        }
        fn set_settle_sequence(&self, responses: Vec<(u16, String)>) {
            *self.settle_sequence.lock().unwrap() = responses;
        }
        fn seen(&self) -> Vec<Seen> {
            self.seen.lock().unwrap().clone()
        }
    }

    async fn handler(State(fake): State<Arc<Fake>>, req: Request) -> Response {
        let (parts, body) = req.into_parts();
        let bytes = to_bytes(body, usize::MAX).await.unwrap();
        let path = parts.uri.path().to_owned();
        fake.seen.lock().unwrap().push(Seen {
            path: path.clone(),
            content_type: parts
                .headers
                .get(header::CONTENT_TYPE)
                .map(|v| v.to_str().unwrap().to_owned()),
            body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        });
        let delay = *fake.delay.lock().unwrap();
        if let Some(d) = delay {
            tokio::time::sleep(d).await;
        }
        let (status, body) = if path.ends_with("/verify") {
            fake.verify.lock().unwrap().clone()
        } else {
            let mut seq = fake.settle_sequence.lock().unwrap();
            if !seq.is_empty() {
                seq.remove(0)
            } else {
                fake.settle.lock().unwrap().clone()
            }
        };
        (StatusCode::from_u16(status).unwrap(), body).into_response()
    }

    async fn start() -> (String, Arc<Fake>) {
        let fake = Fake::new();
        let app = Router::new().fallback(handler).with_state(fake.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), fake)
    }

    fn requirements() -> PaymentRequirements {
        PaymentRequirements {
            scheme: "exact".into(),
            network: "eip155:2368".into(),
            amount: "1000".into(),
            asset: "0xasset".into(),
            pay_to: "0xpayto".into(),
            max_timeout_seconds: 60,
            extra: None,
        }
    }

    fn payload() -> PaymentPayload {
        PaymentPayload {
            x402_version: 2,
            resource: None,
            accepted: requirements(),
            payload: json!({ "signature": "0xsig" }),
            extensions: None,
        }
    }

    // ---- construction ------------------------------------------------------

    #[test]
    fn default_timeout_is_thirty_seconds() {
        assert_eq!(DEFAULT_TIMEOUT, Duration::from_secs(30));
    }

    #[test]
    fn base_url_has_trailing_slashes_trimmed_but_keeps_the_version_prefix() {
        assert_eq!(
            FacilitatorClient::new("https://f.example/v2").base_url(),
            "https://f.example/v2"
        );
        assert_eq!(
            FacilitatorClient::new("https://f.example/v2/").base_url(),
            "https://f.example/v2"
        );
        assert_eq!(
            FacilitatorClient::new("https://f.example/v2///").base_url(),
            "https://f.example/v2"
        );
        assert_eq!(
            FacilitatorClient::new(String::from("http://x")).base_url(),
            "http://x"
        );
    }

    #[test]
    fn client_is_clone_and_debug() {
        let c = FacilitatorClient::with_timeout("http://x/v2", Duration::from_secs(1));
        let d = c.clone();
        assert_eq!(c.base_url(), d.base_url());
        assert!(format!("{c:?}").contains("http://x/v2"));
    }

    // ---- request shape -----------------------------------------------------

    #[tokio::test]
    async fn verify_posts_json_to_slash_verify() {
        let (url, fake) = start().await;
        FacilitatorClient::new(&url)
            .verify(&payload(), &requirements())
            .await
            .unwrap();

        let seen = fake.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].path, "/verify");
        assert!(seen[0]
            .content_type
            .as_deref()
            .unwrap()
            .starts_with("application/json"));
        assert_eq!(seen[0].body["x402Version"], 2);
        assert_eq!(
            seen[0].body["paymentPayload"]["payload"]["signature"],
            "0xsig"
        );
        assert_eq!(
            seen[0].body["paymentPayload"]["accepted"]["payTo"],
            "0xpayto"
        );
        assert_eq!(seen[0].body["paymentRequirements"]["amount"], "1000");
        assert_eq!(
            seen[0].body.as_object().unwrap().len(),
            3,
            "exactly three top-level keys"
        );
    }

    #[tokio::test]
    async fn settle_posts_json_to_slash_settle() {
        let (url, fake) = start().await;
        FacilitatorClient::new(&url)
            .settle(&payload(), &requirements())
            .await
            .unwrap();

        let seen = fake.seen();
        assert_eq!(seen[0].path, "/settle");
        assert_eq!(
            seen[0].body["paymentRequirements"]["network"],
            "eip155:2368"
        );
    }

    #[tokio::test]
    async fn the_version_prefix_in_the_base_url_is_kept_and_trailing_slash_is_not_doubled() {
        let (url, fake) = start().await;
        let client = FacilitatorClient::new(format!("{url}/v2/"));
        client.verify(&payload(), &requirements()).await.unwrap();
        client.settle(&payload(), &requirements()).await.unwrap();

        let paths: Vec<_> = fake.seen().into_iter().map(|s| s.path).collect();
        assert_eq!(paths, vec!["/v2/verify", "/v2/settle"]);
    }

    #[tokio::test]
    async fn x402_version_on_the_wire_comes_from_the_payload() {
        let (url, fake) = start().await;
        let mut p = payload();
        p.x402_version = 1;
        FacilitatorClient::new(&url)
            .verify(&p, &requirements())
            .await
            .unwrap();
        assert_eq!(fake.seen()[0].body["x402Version"], 1);
    }

    #[tokio::test]
    async fn optional_fields_that_are_none_are_not_sent() {
        let (url, fake) = start().await;
        FacilitatorClient::new(&url)
            .verify(&payload(), &requirements())
            .await
            .unwrap();
        let body = &fake.seen()[0].body;
        assert!(body["paymentRequirements"].get("extra").is_none());
        assert!(body["paymentPayload"].get("resource").is_none());
        assert!(body["paymentPayload"].get("extensions").is_none());
    }

    // ---- response parsing --------------------------------------------------

    #[tokio::test]
    async fn verify_parses_a_valid_answer() {
        let (url, fake) = start().await;
        fake.set_verify(200, r#"{"isValid":true,"payer":"0xabc"}"#);
        let v = FacilitatorClient::new(&url)
            .verify(&payload(), &requirements())
            .await
            .unwrap();
        assert!(v.is_valid);
        assert_eq!(v.payer.as_deref(), Some("0xabc"));
    }

    #[tokio::test]
    async fn an_invalid_payment_is_an_ok_value_not_an_error() {
        let (url, fake) = start().await;
        fake.set_verify(
            200,
            r#"{"isValid":false,"invalidReason":"expired","invalidMessage":"too late"}"#,
        );
        let v = FacilitatorClient::new(&url)
            .verify(&payload(), &requirements())
            .await
            .unwrap();
        assert!(!v.is_valid);
        assert_eq!(v.invalid_reason.as_deref(), Some("expired"));
        assert_eq!(v.invalid_message.as_deref(), Some("too late"));
    }

    #[tokio::test]
    async fn a_failed_settlement_is_an_ok_value_not_an_error() {
        let (url, fake) = start().await;
        fake.set_settle(
            200,
            r#"{"success":false,"errorReason":"reverted","errorMessage":"boom","transaction":"","network":"eip155:2368"}"#,
        );
        let s = FacilitatorClient::new(&url)
            .settle(&payload(), &requirements())
            .await
            .unwrap();
        assert!(!s.success);
        assert_eq!(s.error_reason.as_deref(), Some("reverted"));
        assert_eq!(s.error_message.as_deref(), Some("boom"));
    }

    #[tokio::test]
    async fn settle_parses_a_success_receipt() {
        let (url, fake) = start().await;
        fake.set_settle(
            200,
            r#"{"success":true,"transaction":"0xhash","network":"eip155:2368","payer":"0xp","amount":"1000"}"#,
        );
        let s = FacilitatorClient::new(&url)
            .settle(&payload(), &requirements())
            .await
            .unwrap();
        assert!(s.success);
        assert_eq!(
            (s.transaction.as_str(), s.amount.as_deref()),
            ("0xhash", Some("1000"))
        );
    }

    // ---- error mapping -----------------------------------------------------

    #[tokio::test]
    async fn non_success_status_becomes_bad_response_with_op_status_and_body() {
        for status in [400u16, 401, 404, 429, 500, 502, 503] {
            let (url, fake) = start().await;
            fake.set_verify(status, "upstream said no");
            fake.set_settle(status, "settle said no");
            let client = FacilitatorClient::new(&url);

            match client
                .verify(&payload(), &requirements())
                .await
                .unwrap_err()
            {
                FacilitatorError::BadResponse {
                    op,
                    status: s,
                    body,
                } => {
                    assert_eq!(
                        (op, s, body.as_str()),
                        ("verify", status, "upstream said no")
                    );
                }
                other @ FacilitatorError::Request(_) => {
                    panic!("expected BadResponse, got {other:?}")
                }
            }
            match client
                .settle(&payload(), &requirements())
                .await
                .unwrap_err()
            {
                FacilitatorError::BadResponse {
                    op,
                    status: s,
                    body,
                } => {
                    assert_eq!((op, s, body.as_str()), ("settle", status, "settle said no"));
                }
                other @ FacilitatorError::Request(_) => {
                    panic!("expected BadResponse, got {other:?}")
                }
            }
        }
    }

    #[tokio::test]
    async fn unparseable_success_body_becomes_bad_response() {
        let (url, fake) = start().await;
        for body in [
            "",
            "<html>hi</html>",
            "null",
            "[]",
            r#"{"isValid":"yes"}"#,
            r#"{"other":1}"#,
        ] {
            fake.set_verify(200, body);
            let err = FacilitatorClient::new(&url)
                .verify(&payload(), &requirements())
                .await
                .unwrap_err();
            match err {
                FacilitatorError::BadResponse {
                    op: "verify",
                    status: 200,
                    body,
                } => {
                    assert!(
                        body.starts_with("could not parse facilitator verify response"),
                        "{body}"
                    );
                }
                other => panic!("expected BadResponse for {body:?}, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn settle_body_missing_required_fields_becomes_bad_response() {
        let (url, fake) = start().await;
        fake.set_settle(200, r#"{"success":true}"#); // no transaction / network
        let err = FacilitatorClient::new(&url)
            .settle(&payload(), &requirements())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            FacilitatorError::BadResponse {
                op: "settle",
                status: 200,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn connection_refused_becomes_a_request_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let err = FacilitatorClient::new(format!("http://{addr}"))
            .verify(&payload(), &requirements())
            .await
            .unwrap_err();
        match err {
            FacilitatorError::Request(e) => assert!(e.is_connect(), "{e}"),
            other @ FacilitatorError::BadResponse { .. } => {
                panic!("expected Request, got {other:?}")
            }
        }
    }

    #[tokio::test]
    async fn slow_facilitator_becomes_a_timeout_request_error() {
        let (url, fake) = start().await;
        *fake.delay.lock().unwrap() = Some(Duration::from_millis(600));

        let client = FacilitatorClient::with_timeout(&url, Duration::from_millis(80));
        let started = std::time::Instant::now();
        let err = client
            .settle(&payload(), &requirements())
            .await
            .unwrap_err();

        assert!(started.elapsed() < Duration::from_millis(500));
        match err {
            FacilitatorError::Request(e) => assert!(e.is_timeout(), "{e}"),
            other @ FacilitatorError::BadResponse { .. } => {
                panic!("expected Request, got {other:?}")
            }
        }
    }

    #[tokio::test]
    async fn a_facilitator_that_is_fast_enough_is_not_timed_out() {
        let (url, fake) = start().await;
        *fake.delay.lock().unwrap() = Some(Duration::from_millis(50));
        let client = FacilitatorClient::with_timeout(&url, Duration::from_secs(5));
        assert!(client.verify(&payload(), &requirements()).await.is_ok());
    }

    #[test]
    fn error_messages_name_the_operation_status_and_body() {
        let e = FacilitatorError::BadResponse {
            op: "verify",
            status: 503,
            body: "down".into(),
        };
        assert_eq!(e.to_string(), "facilitator verify returned 503: down");
    }

    #[tokio::test]
    async fn request_errors_display_with_a_prefix() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let err = FacilitatorClient::new(format!("http://{addr}"))
            .verify(&payload(), &requirements())
            .await
            .unwrap_err();
        assert!(
            err.to_string().starts_with("facilitator request failed:"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn cloned_clients_can_be_used_concurrently() {
        let (url, fake) = start().await;
        let client = FacilitatorClient::new(&url);
        let tasks: Vec<_> = (0..20)
            .map(|_| {
                let c = client.clone();
                tokio::spawn(async move {
                    c.verify(&payload(), &requirements())
                        .await
                        .unwrap()
                        .is_valid
                })
            })
            .collect();
        for t in tasks {
            assert!(t.await.unwrap());
        }
        assert_eq!(fake.seen().len(), 20);
    }

    #[tokio::test]
    async fn probe_returns_ok_when_facilitator_is_reachable() {
        let (url, _) = start().await;
        let client = FacilitatorClient::new(&url);
        assert!(client.probe().await.is_ok());
    }

    #[tokio::test]
    async fn probe_fails_when_facilitator_is_unreachable() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let client = FacilitatorClient::new(format!("http://{addr}"));
        assert!(client.probe().await.is_err());
    }

    #[test]
    fn retry_config_calculates_exponential_backoff_and_caps_at_maximum() {
        let config = RetryConfig::new(3, Duration::from_millis(50), Duration::from_millis(300));
        assert_eq!(config.calculate_backoff(0), Duration::from_millis(50));
        assert_eq!(config.calculate_backoff(1), Duration::from_millis(100));
        assert_eq!(config.calculate_backoff(2), Duration::from_millis(200));
        assert_eq!(config.calculate_backoff(3), Duration::from_millis(300));
        assert_eq!(config.calculate_backoff(4), Duration::from_millis(300));
    }

    #[tokio::test]
    async fn settle_does_not_repeat_an_indeterminate_503() {
        let (url, fake) = start().await;
        fake.set_settle_sequence(vec![
            (503, "Service Unavailable".into()),
            (
                200,
                json!({ "success": true, "transaction": "0xretry_tx", "network": "eip155:2368" })
                    .to_string(),
            ),
        ]);

        let retry = RetryConfig::new(2, Duration::from_millis(10), Duration::from_millis(50));
        let client = FacilitatorClient::new(&url).with_retry_config(retry);

        assert!(client.settle(&payload(), &requirements()).await.is_err());
        assert_eq!(fake.seen().len(), 1);
    }

    #[tokio::test]
    async fn settle_does_not_retry_non_transient_400() {
        let (url, fake) = start().await;
        fake.set_settle(400, "Bad Request");

        let retry = RetryConfig::new(3, Duration::from_millis(10), Duration::from_millis(50));
        let client = FacilitatorClient::new(&url).with_retry_config(retry);

        let err = client
            .settle(&payload(), &requirements())
            .await
            .unwrap_err();
        match err {
            FacilitatorError::BadResponse { status, .. } => assert_eq!(status, 400),
            other @ FacilitatorError::Request(_) => {
                panic!("expected BadResponse 400, got: {other:?}")
            }
        }
        assert_eq!(fake.seen().len(), 1);
    }

    #[tokio::test]
    async fn verification_retries_are_bounded_and_explicit() {
        let (url, fake) = start().await;
        fake.set_verify(503, "Facilitator Unavailable");

        let retry = RetryConfig::new(3, Duration::from_millis(10), Duration::from_millis(50));
        let client = FacilitatorClient::new(&url).with_retry_config(retry);

        let err = client
            .verify(&payload(), &requirements())
            .await
            .unwrap_err();
        match err {
            FacilitatorError::BadResponse { status, .. } => assert_eq!(status, 503),
            other @ FacilitatorError::Request(_) => {
                panic!("expected BadResponse 503, got: {other:?}")
            }
        }
        assert_eq!(fake.seen().len(), 4);
    }

    #[tokio::test]
    async fn settlement_timeout_is_not_retried_even_with_a_retry_policy() {
        let (url, fake) = start().await;
        *fake.delay.lock().unwrap() = Some(Duration::from_millis(100));
        let client =
            FacilitatorClient::with_timeout(url, Duration::from_millis(20)).with_retry_config(
                RetryConfig::new(3, Duration::from_millis(1), Duration::from_millis(2)),
            );
        assert!(client.settle(&payload(), &requirements()).await.is_err());
        assert_eq!(fake.seen().len(), 1);
    }
}
