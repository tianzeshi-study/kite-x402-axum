//! Regression tests for defects that were found in the reverse proxy and
//! have since been fixed. Each test names the failure it guards against.

mod common;

use std::sync::Arc;

use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Redirect},
    routing::{any, get},
    Router,
};
use common::*;
use kite_x402_axum::proxy::proxy;

// ---------------------------------------------------------------------------
// `/v1` is removed exactly once
// ---------------------------------------------------------------------------

/// The router's `nest("/v1", ..)` already strips the prefix, so the handler
/// used to strip a *second* `/v1`: `/v1/v1/orders` reached the upstream as
/// `/orders` instead of `/v1/orders`.
#[tokio::test]
async fn upstream_paths_that_start_with_v1_are_preserved() {
    let mocks = Mocks::start().await;
    let app = build_proxy_only(upstream_cfg(&mocks.upstream_url));

    send(&app, get_req("/v1/v1/orders?id=1")).await;

    assert_eq!(mocks.upstream.last().path_and_query, "/v1/orders?id=1");
}

/// Lookalike segments such as `/v1beta/..` are ordinary paths, not a prefix.
#[tokio::test]
async fn paths_that_merely_resemble_v1_are_preserved() {
    for (incoming, expected) in [
        ("/v1/v1beta/x", "/v1beta/x"),
        ("/v1/v10", "/v10"),
        ("/v1/v1", "/v1"),
    ] {
        let mocks = Mocks::start().await;
        let app = build_proxy_only(upstream_cfg(&mocks.upstream_url));
        send(&app, get_req(incoming)).await;
        assert_eq!(mocks.upstream.last().path_and_query, expected, "{incoming}");
    }
}

/// Mounted under a prefix other than `/v1`, the router's prefix is stripped
/// and nothing else is: a `/v1` after it belongs to the upstream.
#[tokio::test]
async fn nesting_under_another_prefix_forwards_the_rest_untouched() {
    for (incoming, expected) in [("/api/orders", "/orders"), ("/api/v1/orders", "/v1/orders")] {
        let mocks = Mocks::start().await;
        let state = Arc::new(upstream_cfg(&mocks.upstream_url));
        let app = Router::new().nest(
            "/api",
            Router::new()
                .route("/{*path}", any(proxy))
                .with_state(state),
        );
        send(&app, get_req(incoming)).await;
        assert_eq!(mocks.upstream.last().path_and_query, expected, "{incoming}");
    }
}

/// Without `Router::nest` nothing strips the prefix before the handler runs,
/// so the handler still removes one leading `/v1` itself.
#[tokio::test]
async fn un_nested_routes_still_get_one_v1_stripped() {
    let cases = [
        ("/v1/orders?id=1", "/orders?id=1"),
        ("/v1/v1/orders", "/v1/orders"),
        ("/orders", "/orders"),
        ("/v1beta/orders", "/v1beta/orders"),
    ];
    for (incoming, expected) in cases {
        let mocks = Mocks::start().await;
        let state = Arc::new(upstream_cfg(&mocks.upstream_url));
        let app = Router::new()
            .route("/{*path}", any(proxy))
            .with_state(state);
        send(&app, get_req(incoming)).await;
        assert_eq!(mocks.upstream.last().path_and_query, expected, "{incoming}");
    }
}

// ---------------------------------------------------------------------------
// the path cannot climb out of the upstream base URL
// ---------------------------------------------------------------------------

/// The path is appended to `base_url` and URL parsing resolves `..` *after*
/// that, so with `UPSTREAM_URL=https://host/public` a request for
/// `/v1/../secret` used to be forwarded to `/secret` — outside the configured
/// base path, with the injected credential attached.
#[tokio::test]
async fn dot_segments_cannot_escape_the_upstream_base_path() {
    let cases = [
        "/v1/../secret",
        "/v1/a/../../secret",
        "/v1/%2e%2e/secret",
        "/v1/%2E%2E/secret",
        "/v1/.%2e/secret",
        "/v1/./x",
        "/v1/%2e/x",
        "/v1/x/..",
        "/v1/..?q=1",
    ];
    for incoming in cases {
        let mocks = Mocks::start().await;
        let mut cfg = upstream_cfg(&format!("{}/public", mocks.upstream_url));
        cfg.auth_value = "upstream-secret".into();
        let app = build_proxy_only(cfg);

        let resp = send(&app, get_req(incoming)).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{incoming}");
        assert_eq!(
            mocks.upstream.count(),
            0,
            "{incoming} must not reach the upstream"
        );
    }
}

/// Look-alikes that are *not* dot segments keep working.
#[tokio::test]
async fn dots_inside_a_segment_are_fine() {
    for (incoming, expected) in [
        ("/v1/file.json", "/public/file.json"),
        ("/v1/a..b/c", "/public/a..b/c"),
        ("/v1/...", "/public/..."),
        ("/v1/x?next=../y", "/public/x?next=../y"),
    ] {
        let mocks = Mocks::start().await;
        let app = build_proxy_only(upstream_cfg(&format!("{}/public", mocks.upstream_url)));
        let resp = send(&app, get_req(incoming)).await;
        assert_eq!(resp.status(), StatusCode::OK, "{incoming}");
        assert_eq!(mocks.upstream.last().path_and_query, expected, "{incoming}");
    }
}

/// A rejected path is a `400`, so the payment gate must not settle it.
#[tokio::test]
async fn a_rejected_path_is_not_charged() {
    let mocks = Mocks::start().await;
    let app = mocks.app();
    let header = payment_header(&probe_requirements(&app, "/v1/forecast").await);

    let resp = send(
        &app,
        req_with(
            "GET",
            "/v1/../secret",
            &[("PAYMENT-SIGNATURE", &header)],
            vec![],
        ),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(mocks.facilitator.settle_count(), 0);
    assert_eq!(mocks.upstream.count(), 0);
}

// ---------------------------------------------------------------------------
// response headers
// ---------------------------------------------------------------------------

/// The proxy used to drop the response's `content-encoding` header while
/// streaming the body unchanged (nothing decodes it), so a client that sent
/// `Accept-Encoding: gzip` got compressed bytes with no header saying so.
#[tokio::test]
async fn encoded_upstream_bodies_keep_their_content_encoding_header() {
    let mocks = Mocks::start().await;
    let mut reply = UpstreamReply::json(200);
    reply
        .headers
        .push(("content-encoding".into(), "gzip".into()));
    reply.body = vec![0x1f, 0x8b, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef]; // gzip magic + junk
    mocks.upstream.set_reply(reply.clone());
    let app = build_proxy_only(upstream_cfg(&mocks.upstream_url));

    let resp = send(
        &app,
        req_with("GET", "/v1/x", &[("accept-encoding", "gzip")], vec![]),
    )
    .await;

    assert_eq!(
        resp.headers().get("content-encoding").map(|h| h.as_bytes()),
        Some(&b"gzip"[..])
    );
    assert_eq!(
        body_bytes(resp).await,
        reply.body,
        "the body must pass through byte for byte"
    );
    assert_eq!(
        mocks.upstream.last().header("accept-encoding"),
        Some("gzip")
    );
}

// ---------------------------------------------------------------------------
// request headers
// ---------------------------------------------------------------------------

/// The gate accepts the legacy `X-PAYMENT` header, but the proxy used to drop
/// only `PAYMENT-SIGNATURE`, forwarding the buyer's signed payment
/// authorization to the upstream API.
#[tokio::test]
async fn legacy_x_payment_header_is_not_leaked_to_the_upstream() {
    let mocks = Mocks::start().await;
    let app = mocks.app();
    let header = payment_header(&probe_requirements(&app, "/v1/forecast").await);

    let resp = send(
        &app,
        req_with("GET", "/v1/forecast", &[("X-PAYMENT", &header)], vec![]),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(mocks.upstream.last().header("x-payment"), None);
    assert_eq!(mocks.upstream.last().header("payment-signature"), None);
}

// ---------------------------------------------------------------------------
// redirects
// ---------------------------------------------------------------------------

/// A client with reqwest's default redirect policy only strips the standard
/// `Authorization` / `Cookie` headers on a cross-host hop, so a custom
/// credential header (`UPSTREAM_AUTH_HEADER=X-Api-Key`) was sent to whatever
/// host the upstream redirected to. The policy the service uses stops there
/// and hands the `3xx` back to the buyer instead.
#[tokio::test]
async fn injected_credential_does_not_follow_redirects_to_other_hosts() {
    let other_host = Mocks::start().await; // stands in for "somewhere else"
    let mocks = Mocks::start().await;
    let target = format!("{}/collect", other_host.upstream_url);
    let mut reply = UpstreamReply::json(302);
    reply.headers.push(("location".into(), target.clone()));
    mocks.upstream.set_reply(reply);

    let mut cfg = upstream_cfg(&mocks.upstream_url);
    cfg.auth_header = "X-Api-Key".into();
    cfg.auth_value = "upstream-secret".into();
    let app = build_proxy_only(cfg);

    let resp = send(&app, get_req("/v1/x")).await;

    assert_eq!(
        other_host.upstream.count(),
        0,
        "the redirect must not be followed"
    );
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(resp.headers()[header::LOCATION], target.as_str());
    assert_eq!(mocks.upstream.count(), 1);
}

/// Redirects that stay on the upstream's own origin are still followed, so
/// e.g. a trailing-slash redirect keeps working — and the credential is
/// re-sent, which is fine because it is the same origin.
#[tokio::test]
async fn same_origin_redirects_are_followed() {
    let upstream = Router::new()
        .route("/start", get(|| async { Redirect::temporary("/final") }))
        .route(
            "/final",
            get(|headers: axum::http::HeaderMap| async move {
                let key = headers
                    .get("x-api-key")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("-")
                    .to_string();
                (StatusCode::OK, format!("done:{key}")).into_response()
            }),
        );
    let upstream_url = serve(upstream).await;
    let mut cfg = upstream_cfg(&upstream_url);
    cfg.auth_header = "X-Api-Key".into();
    cfg.auth_value = "k".into();
    let app = build_proxy_only(cfg);

    let resp = send(&app, get_req("/v1/start")).await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_bytes(resp).await, b"done:k");
}

/// An endless same-origin redirect loop ends in a `502` (which is never
/// settled) rather than hanging.
#[tokio::test]
async fn redirect_loops_end_in_a_bad_gateway() {
    let upstream = Router::new().route("/loop", get(|| async { Redirect::temporary("/loop") }));
    let upstream_url = serve(upstream).await;
    let app = build_proxy_only(upstream_cfg(&upstream_url));

    let resp = send(&app, get_req("/v1/loop")).await;

    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}
