//! Integration tests for the reverse-proxy handler on its own (no payment
//! gate), mounted under `/v1` exactly like the real app: what the upstream
//! receives, and what the client gets back.

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::*;
use kite_x402_axum::proxy::UpstreamConfig;
use serde_json::Value;

async fn proxied(cfg_tweak: impl FnOnce(&mut UpstreamConfig)) -> (Mocks, axum::Router) {
    let mocks = Mocks::start().await;
    let mut cfg = upstream_cfg(&mocks.upstream_url);
    cfg_tweak(&mut cfg);
    let app = build_proxy_only(cfg);
    (mocks, app)
}

// ---------------------------------------------------------------------------
// request line: method, path, query, body
// ---------------------------------------------------------------------------

#[tokio::test]
async fn forwards_path_and_query_with_v1_prefix_stripped() {
    let (mocks, app) = proxied(|_| {}).await;
    let resp = send(&app, get_req("/v1/forecast?latitude=52.52&longitude=13.41")).await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        mocks.upstream.last().path_and_query,
        "/forecast?latitude=52.52&longitude=13.41"
    );
}

#[tokio::test]
async fn forwards_deep_paths_trailing_slashes_and_encoded_characters_untouched() {
    let cases = [
        ("/v1/a/b/c", "/a/b/c"),
        ("/v1/forecast/", "/forecast/"),
        ("/v1/a%20b/c", "/a%20b/c"),
        (
            "/v1/search?q=a%20b&x=%E2%9C%93",
            "/search?q=a%20b&x=%E2%9C%93",
        ),
        ("/v1/list?tag=a&tag=b", "/list?tag=a&tag=b"),
    ];
    for (incoming, expected) in cases {
        let (mocks, app) = proxied(|_| {}).await;
        send(&app, get_req(incoming)).await;
        assert_eq!(mocks.upstream.last().path_and_query, expected, "{incoming}");
    }
}

#[tokio::test]
async fn forwards_every_common_method() {
    for method in ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] {
        let (mocks, app) = proxied(|_| {}).await;
        let resp = send(&app, req_with(method, "/v1/thing", &[], vec![])).await;
        assert_eq!(resp.status(), StatusCode::OK, "{method}");
        assert_eq!(mocks.upstream.last().method, method);
    }
}

#[tokio::test]
async fn forwards_head_and_returns_no_body() {
    let (mocks, app) = proxied(|_| {}).await;
    let resp = send(&app, req_with("HEAD", "/v1/thing", &[], vec![])).await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(mocks.upstream.last().method, "HEAD");
    assert!(body_bytes(resp).await.is_empty());
}

#[tokio::test]
async fn forwards_request_bodies_byte_for_byte() {
    let (mocks, app) = proxied(|_| {}).await;
    let binary: Vec<u8> = (0..=255u8).cycle().take(10_000).collect();
    send(
        &app,
        req_with(
            "POST",
            "/v1/upload",
            &[("content-type", "application/octet-stream")],
            binary.clone(),
        ),
    )
    .await;

    let seen = mocks.upstream.last();
    assert_eq!(seen.body, binary);
    assert_eq!(
        seen.header("content-type"),
        Some("application/octet-stream")
    );
    assert_eq!(seen.header("content-length"), Some("10000"));
}

#[tokio::test]
async fn forwards_json_post_bodies() {
    let (mocks, app) = proxied(|_| {}).await;
    send(
        &app,
        req_with(
            "POST",
            "/v1/echo",
            &[("content-type", "application/json")],
            br#"{"a":[1,2,3]}"#.to_vec(),
        ),
    )
    .await;
    let seen: Value = serde_json::from_slice(&mocks.upstream.last().body).unwrap();
    assert_eq!(seen["a"][2], 3);
}

#[tokio::test]
async fn base_url_with_a_path_prefix_is_respected() {
    let mocks = Mocks::start().await;
    let app = build_proxy_only(upstream_cfg(&format!("{}/api/v3/", mocks.upstream_url)));
    send(&app, get_req("/v1/forecast?x=1")).await;
    assert_eq!(mocks.upstream.last().path_and_query, "/api/v3/forecast?x=1");
}

// ---------------------------------------------------------------------------
// request headers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn forwards_ordinary_headers_including_multi_valued_ones() {
    let (mocks, app) = proxied(|_| {}).await;
    let mut req = req_with(
        "GET",
        "/v1/x",
        &[
            ("accept", "application/json"),
            ("x-custom", "one"),
            ("user-agent", "tester/1.0"),
        ],
        vec![],
    );
    req.headers_mut().append("x-multi", header_value(b"a"));
    req.headers_mut().append("x-multi", header_value(b"b"));
    send(&app, req).await;

    let seen = mocks.upstream.last();
    assert_eq!(seen.header("accept"), Some("application/json"));
    assert_eq!(seen.header("x-custom"), Some("one"));
    assert_eq!(seen.header("user-agent"), Some("tester/1.0"));
    assert_eq!(seen.header_all("x-multi"), vec!["a", "b"]);
}

#[tokio::test]
async fn strips_hop_by_hop_headers_and_rewrites_host() {
    let (mocks, app) = proxied(|_| {}).await;
    let upstream_authority = mocks.upstream_url.trim_start_matches("http://").to_string();
    send(
        &app,
        req_with(
            "GET",
            "/v1/x",
            &[
                ("host", "client.example"),
                ("connection", "close"),
                ("keep-alive", "timeout=5"),
                ("te", "trailers"),
                ("trailer", "x-checksum"),
                ("upgrade", "websocket"),
            ],
            vec![],
        ),
    )
    .await;

    let seen = mocks.upstream.last();
    for h in ["connection", "keep-alive", "te", "trailer", "upgrade"] {
        assert_eq!(seen.header(h), None, "{h} must not be forwarded");
    }
    assert_eq!(seen.header("host"), Some(upstream_authority.as_str()));
}

#[tokio::test]
async fn never_forwards_the_payment_signature_header() {
    let (mocks, app) = proxied(|_| {}).await;
    send(
        &app,
        req_with(
            "GET",
            "/v1/x",
            &[("PAYMENT-SIGNATURE", "secret-signed-payload")],
            vec![],
        ),
    )
    .await;

    let seen = mocks.upstream.last();
    assert_eq!(seen.header("payment-signature"), None);
    assert!(!seen
        .headers
        .iter()
        .any(|(_, v)| v.contains("secret-signed-payload")));
}

#[tokio::test]
async fn client_authorization_is_forwarded_when_no_upstream_credential_is_configured() {
    let (mocks, app) = proxied(|_| {}).await;
    send(
        &app,
        req_with(
            "GET",
            "/v1/x",
            &[("authorization", "Bearer client-token")],
            vec![],
        ),
    )
    .await;
    assert_eq!(
        mocks.upstream.last().header("authorization"),
        Some("Bearer client-token")
    );
}

#[tokio::test]
async fn configured_upstream_credential_is_injected() {
    let (mocks, app) = proxied(|c| {
        c.auth_header = "X-Api-Key".into();
        c.auth_value = "upstream-secret".into();
    })
    .await;
    send(&app, get_req("/v1/x")).await;
    assert_eq!(
        mocks.upstream.last().header("x-api-key"),
        Some("upstream-secret")
    );
}

#[tokio::test]
async fn configured_upstream_credential_overrides_a_client_supplied_one() {
    let (mocks, app) = proxied(|c| {
        c.auth_value = "Bearer upstream-secret".into();
    })
    .await;
    send(
        &app,
        req_with(
            "GET",
            "/v1/x",
            &[("Authorization", "Bearer evil-client")],
            vec![],
        ),
    )
    .await;

    let seen = mocks.upstream.last();
    assert_eq!(
        seen.header_all("authorization"),
        vec!["Bearer upstream-secret"]
    );
}

#[tokio::test]
async fn empty_credential_injects_nothing() {
    let (mocks, app) = proxied(|c| c.auth_header = "X-Api-Key".into()).await;
    send(&app, get_req("/v1/x")).await;
    assert_eq!(mocks.upstream.last().header("x-api-key"), None);
}

#[tokio::test]
async fn unusable_credential_configuration_does_not_break_proxying() {
    // Neither an invalid header name nor a value with a newline may panic.
    for (name, value) in [("not a header name", "v"), ("X-Api-Key", "line1\nline2")] {
        let (mocks, app) = proxied(|c| {
            c.auth_header = name.into();
            c.auth_value = value.into();
        })
        .await;
        let resp = send(&app, get_req("/v1/x")).await;
        assert_eq!(resp.status(), StatusCode::OK, "{name:?}");
        assert_eq!(mocks.upstream.count(), 1);
    }
}

// ---------------------------------------------------------------------------
// response passthrough
// ---------------------------------------------------------------------------

#[tokio::test]
async fn passes_status_and_body_through_for_any_upstream_status() {
    for status in [200u16, 201, 204, 301, 400, 404, 418, 429, 500, 503] {
        let mocks = Mocks::start().await;
        let mut reply = UpstreamReply::json(status);
        if status == 204 {
            reply.body.clear();
        }
        mocks.upstream.set_reply(reply.clone());
        // Redirect statuses are exercised in known_issues.rs; keep the client
        // from following the 301 here.
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let mut cfg = upstream_cfg(&mocks.upstream_url);
        cfg.http = client;
        let app = build_proxy_only(cfg);

        let resp = send(&app, get_req("/v1/x")).await;
        assert_eq!(resp.status().as_u16(), status);
        assert_eq!(body_bytes(resp).await, reply.body, "{status}");
    }
}

#[tokio::test]
async fn passes_response_headers_through_including_repeated_ones() {
    let (mocks, app) = proxied(|_| {}).await;
    let mut reply = UpstreamReply::json(200);
    reply
        .headers
        .push(("x-ratelimit-remaining".into(), "41".into()));
    reply
        .headers
        .push(("set-cookie".into(), "a=1; Path=/".into()));
    reply
        .headers
        .push(("set-cookie".into(), "b=2; Path=/".into()));
    mocks.upstream.set_reply(reply);

    let resp = send(&app, get_req("/v1/x")).await;
    assert_eq!(resp.headers()["x-ratelimit-remaining"], "41");
    assert_eq!(resp.headers()["content-type"], "application/json");
    let cookies: Vec<_> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();
    assert_eq!(cookies, vec!["a=1; Path=/", "b=2; Path=/"]);
}

#[tokio::test]
async fn strips_hop_by_hop_headers_from_the_response() {
    let (mocks, app) = proxied(|_| {}).await;
    let mut reply = UpstreamReply::json(200);
    reply
        .headers
        .push(("keep-alive".into(), "timeout=5".into()));
    reply.headers.push(("x-kept".into(), "yes".into()));
    mocks.upstream.set_reply(reply);

    let resp = send(&app, get_req("/v1/x")).await;
    assert!(resp.headers().get("keep-alive").is_none());
    assert_eq!(resp.headers()["x-kept"], "yes");
}

#[tokio::test]
async fn streams_large_response_bodies_intact() {
    let (mocks, app) = proxied(|_| {}).await;
    let big: Vec<u8> = (0..1_500_000u32).map(|i| (i % 251) as u8).collect();
    let mut reply = UpstreamReply::json(200);
    reply.headers = vec![("content-type".into(), "application/octet-stream".into())];
    reply.body = big.clone();
    mocks.upstream.set_reply(reply);

    let resp = send(&app, get_req("/v1/big")).await;
    assert_eq!(body_bytes(resp).await, big);
}

// ---------------------------------------------------------------------------
// failure modes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unreachable_upstream_is_a_502_with_a_json_error() {
    let dead = dead_url().await;
    let app = build_proxy_only(upstream_cfg(&dead));
    let resp = send(&app, get_req("/v1/x")).await;

    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    let body = body_json(resp).await;
    assert_eq!(body["error"], "upstream unreachable");
    assert!(!body["detail"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn slow_upstream_hits_the_client_timeout_and_is_a_502() {
    let mocks = Mocks::start().await;
    let mut reply = UpstreamReply::json(200);
    reply.delay = Some(Duration::from_millis(800));
    mocks.upstream.set_reply(reply);

    let mut cfg = upstream_cfg(&mocks.upstream_url);
    cfg.http = reqwest::Client::builder()
        .timeout(Duration::from_millis(100))
        .build()
        .unwrap();
    let app = build_proxy_only(cfg);

    let resp = send(&app, get_req("/v1/x")).await;
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(body_json(resp).await["error"], "upstream unreachable");
}

#[tokio::test]
async fn oversized_request_body_is_a_413_and_never_reaches_upstream() {
    let (mocks, app) = proxied(|_| {}).await;
    let too_big = vec![0u8; 16 * 1024 * 1024 + 1];
    let resp = send(&app, req_with("POST", "/v1/upload", &[], too_big)).await;

    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        body_json(resp).await["error"],
        "request body too large to proxy"
    );
    assert_eq!(mocks.upstream.count(), 0);
}

#[tokio::test]
async fn request_body_at_the_limit_is_still_proxied() {
    let (mocks, app) = proxied(|_| {}).await;
    let at_limit = vec![7u8; 16 * 1024 * 1024];
    let resp = send(&app, req_with("POST", "/v1/upload", &[], at_limit)).await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(mocks.upstream.last().body.len(), 16 * 1024 * 1024);
}
