//! Tests for behaviour that looks wrong today. Each one asserts the
//! **desired** behaviour and is `#[ignore]`d so the normal suite stays green.
//!
//! Run them with:
//!
//! ```bash
//! cargo test -p kite-x402-axum --test known_issues -- --ignored
//! ```
//!
//! Once an issue is fixed, delete its `#[ignore]` so it becomes a normal
//! regression test.

mod common;

use axum::http::StatusCode;
use common::*;

/// `proxy` strips a leading `/v1` from the path it sees. But the router has
/// already stripped the `nest("/v1", ..)` prefix, so a request for
/// `/v1/v1/orders` reaches the handler as `/v1/orders`, and the handler strips
/// a *second* `/v1`: the upstream is asked for `/orders`, the wrong resource.
#[tokio::test]
#[ignore = "known issue: proxy strips /v1 twice for /v1/v1/... (upstream gets /orders instead of /v1/orders)"]
async fn upstream_paths_that_start_with_v1_are_preserved() {
    let mocks = Mocks::start().await;
    let app = build_proxy_only(upstream_cfg(&mocks.upstream_url));

    send(&app, get_req("/v1/v1/orders?id=1")).await;

    assert_eq!(mocks.upstream.last().path_and_query, "/v1/orders?id=1");
}

/// The proxy removes `content-encoding` from the response but the body is
/// streamed exactly as received (reqwest is built without gzip/brotli, so
/// nothing decodes it). A client that sent `Accept-Encoding: gzip` (curl
/// --compressed, browsers and Python `requests` all do) is handed compressed
/// bytes with no header saying so.
#[tokio::test]
#[ignore = "known issue: content-encoding is stripped although the body is still encoded"]
async fn encoded_upstream_bodies_keep_their_content_encoding_header() {
    let mocks = Mocks::start().await;
    let mut reply = UpstreamReply::json(200);
    reply.headers.push(("content-encoding".into(), "gzip".into()));
    reply.body = vec![0x1f, 0x8b, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef]; // gzip magic + junk
    mocks.upstream.set_reply(reply.clone());
    let app = build_proxy_only(upstream_cfg(&mocks.upstream_url));

    let resp = send(&app, req_with("GET", "/v1/x", &[("accept-encoding", "gzip")], vec![])).await;

    let header = resp.headers().get("content-encoding").cloned();
    let body = body_bytes(resp).await;
    assert!(
        header.as_ref().map(|h| h == "gzip").unwrap_or(false) || body != reply.body,
        "body is still gzip-encoded ({body:?}) but content-encoding is {header:?}"
    );
}

/// The gate accepts the legacy `X-PAYMENT` header, but the proxy only drops
/// `PAYMENT-SIGNATURE`, so the buyer's signed payment authorization is
/// forwarded to the upstream API.
#[tokio::test]
#[ignore = "known issue: legacy X-PAYMENT header is forwarded to the upstream"]
async fn legacy_x_payment_header_is_not_leaked_to_the_upstream() {
    let mocks = Mocks::start().await;
    let app = mocks.app();
    let header = payment_header(&probe_requirements(&app, "/v1/forecast").await);

    let resp = send(&app, req_with("GET", "/v1/forecast", &[("X-PAYMENT", &header)], vec![])).await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(mocks.upstream.last().header("x-payment"), None);
}

/// The proxy's `reqwest::Client` follows redirects, and reqwest only strips
/// the standard `Authorization`/`Cookie` headers on a cross-host hop. A custom
/// credential header (`UPSTREAM_AUTH_HEADER=X-Api-Key`) would therefore be
/// sent to whatever host the upstream redirects to.
#[tokio::test]
#[ignore = "known issue: injected upstream credential follows cross-host redirects"]
async fn injected_credential_does_not_follow_redirects_to_other_hosts() {
    let other_host = Mocks::start().await; // stands in for "somewhere else"
    let mocks = Mocks::start().await;
    let mut reply = UpstreamReply::json(302);
    reply
        .headers
        .push(("location".into(), format!("{}/collect", other_host.upstream_url)));
    mocks.upstream.set_reply(reply);

    let mut cfg = upstream_cfg(&mocks.upstream_url);
    cfg.auth_header = "X-Api-Key".into();
    cfg.auth_value = "upstream-secret".into();
    let app = build_proxy_only(cfg);

    send(&app, get_req("/v1/x")).await;

    if other_host.upstream.count() > 0 {
        assert_eq!(
            other_host.upstream.last().header("x-api-key"),
            None,
            "the upstream credential reached a different host"
        );
    }
}
