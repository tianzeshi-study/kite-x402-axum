//! Integration tests for the x402 payment gate wired to the proxy and a real
//! (mock) facilitator over HTTP. Only the crate's public API is used.
//!
//! Layout:
//! - `challenge_*`   — what an unpaid / badly paid request gets back
//! - `validation_*`  — decoding and matching of the client's payment header
//! - `verify_*`      — how facilitator `/verify` outcomes map to responses
//! - `settle_*`      — when and how `/settle` happens
//! - `concurrency_*` — many paid requests at once

mod common;

use axum::http::{header, StatusCode};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use common::*;
use kite_x402_axum::kite::{KITE_MAINNET, KITE_TESTNET};
use serde_json::json;
use std::time::Duration;

// ===========================================================================
// challenge
// ===========================================================================

#[tokio::test]
async fn challenge_has_expected_status_headers_and_empty_json_body() {
    let mocks = Mocks::start().await;
    let resp = send(&mocks.app(), get_req("/v1/forecast?lat=1")).await;

    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(resp.headers()[header::CONTENT_TYPE], "application/json");
    assert!(resp.headers().get("PAYMENT-RESPONSE").is_none());
    assert_eq!(body_json(resp).await, json!({}));
}

#[tokio::test]
async fn challenge_payload_describes_resource_and_single_payment_option() {
    let mocks = Mocks::start().await;
    let resp = send(&mocks.app(), get_req("/v1/forecast?lat=1")).await;
    let challenge = header_json(resp.headers(), "PAYMENT-REQUIRED");

    assert_eq!(challenge["x402Version"], 2);
    assert!(
        challenge.get("error").is_none(),
        "a plain challenge carries no error"
    );

    // The resource URL is the *original* URI (with /v1 and the query), not the
    // prefix-stripped one the proxy handler sees.
    assert_eq!(challenge["resource"]["url"], "/v1/forecast?lat=1");
    assert_eq!(challenge["resource"]["description"], "Test wrapper");
    assert_eq!(challenge["resource"]["mimeType"], "application/json");

    let accepts = challenge["accepts"].as_array().unwrap();
    assert_eq!(accepts.len(), 1);
    let a = &accepts[0];
    assert_eq!(a["scheme"], "exact");
    assert_eq!(a["network"], KITE_TESTNET.network);
    assert_eq!(a["amount"], "1000000000000000"); // 0.001 * 10^18
    assert_eq!(a["asset"], KITE_TESTNET.asset_address);
    assert_eq!(a["payTo"], PAY_TO);
    assert_eq!(a["maxTimeoutSeconds"], 60);
    assert_eq!(a["extra"], json!({ "name": "pieUSD", "version": "1" }));
}

#[tokio::test]
async fn challenge_follows_configured_chain_and_price() {
    let mocks = Mocks::start().await;
    let app = mocks.app_with(&AppOptions {
        chain: KITE_MAINNET,
        price_usd: "$0.05".into(),
        ..AppOptions::default()
    });
    let reqs = probe_requirements(&app, "/v1/x").await;

    assert_eq!(reqs.network, KITE_MAINNET.network);
    assert_eq!(reqs.asset, KITE_MAINNET.asset_address);
    assert_eq!(reqs.amount, "50000"); // 0.05 * 10^6
    assert_eq!(reqs.extra.unwrap()["name"], "Bridged USDC (Kite AI)");
}

#[tokio::test]
async fn challenge_is_issued_for_every_method_and_depth_under_v1() {
    let mocks = Mocks::start().await;
    let app = mocks.app();
    for method in ["GET", "POST", "PUT", "PATCH", "DELETE"] {
        let resp = send(&app, req_with(method, "/v1/a/b/c/d", &[], vec![])).await;
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED, "{method}");
    }
    assert_eq!(mocks.upstream.count(), 0);
    assert_eq!(mocks.facilitator.verify_count(), 0);
}

#[tokio::test]
async fn challenge_never_touches_facilitator_or_upstream() {
    let mocks = Mocks::start().await;
    let _ = send(&mocks.app(), get_req("/v1/forecast")).await;
    assert!(mocks.timeline().is_empty());
}

#[tokio::test]
async fn challenge_invalid_server_price_is_a_500_not_a_402() {
    let mocks = Mocks::start().await;
    let app = mocks.app_with(&AppOptions {
        price_usd: "free".into(),
        ..AppOptions::default()
    });
    let resp = send(&app, get_req("/v1/forecast")).await;

    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = body_json(resp).await;
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("invalid PRICE_USD"));
    assert!(mocks.timeline().is_empty());
}

#[tokio::test]
async fn routes_outside_v1_are_never_gated() {
    let mocks = Mocks::start().await;
    let resp = send(&mocks.app(), get_req("/healthz")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(mocks.timeline().is_empty());
}

// ===========================================================================
// validation of the client's header
// ===========================================================================

/// Asserts a `402` whose challenge carries `error == expected`, and that
/// neither the facilitator nor the upstream was contacted.
async fn assert_rejected_before_facilitator(
    mocks: &Mocks,
    resp: axum::response::Response,
    expected: &str,
) {
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    let challenge = header_json(resp.headers(), "PAYMENT-REQUIRED");
    assert_eq!(challenge["error"], expected);
    assert!(
        mocks.timeline().is_empty(),
        "nothing downstream may be called: {:?}",
        mocks.timeline()
    );
}

#[tokio::test]
async fn validation_undecodable_headers_are_rejected_as_invalid_signature() {
    let mocks = Mocks::start().await;
    let app = mocks.app();

    let not_json_b64 = STANDARD.encode("this is not json");
    let wrong_shape_b64 = STANDARD.encode(r#"{"x402Version":2}"#);
    let cases = [
        "not-valid-base64!!",
        "",
        not_json_b64.as_str(),
        wrong_shape_b64.as_str(),
    ];
    for bad in cases {
        let resp = send(
            &app,
            req_with("GET", "/v1/forecast", &[("PAYMENT-SIGNATURE", bad)], vec![]),
        )
        .await;
        assert_rejected_before_facilitator(&mocks, resp, "Invalid payment signature").await;
    }
}

#[tokio::test]
async fn validation_non_utf8_header_is_treated_as_absent() {
    let mocks = Mocks::start().await;
    let mut req = get_req("/v1/forecast");
    req.headers_mut()
        .insert("PAYMENT-SIGNATURE", header_value(b"\xff\xfe"));
    let resp = send(&mocks.app(), req).await;

    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    let challenge = header_json(resp.headers(), "PAYMENT-REQUIRED");
    assert!(challenge.get("error").is_none());
}

#[tokio::test]
async fn validation_any_mismatch_with_server_requirements_is_rejected() {
    /// One named way of tampering with the requirements the server issued.
    type Mutation = (
        &'static str,
        Box<dyn Fn(&mut kite_x402_axum::types::PaymentRequirements)>,
    );

    let mocks = Mocks::start().await;
    let app = mocks.app();
    let good = probe_requirements(&app, "/v1/forecast").await;

    let mutations: Vec<Mutation> = vec![
        ("scheme", Box::new(|r| r.scheme = "upto".into())),
        (
            "network",
            Box::new(|r| r.network = KITE_MAINNET.network.into()),
        ),
        ("amount (cheaper)", Box::new(|r| r.amount = "1".into())),
        (
            "asset",
            Box::new(|r| r.asset = "0x0000000000000000000000000000000000000001".into()),
        ),
        (
            "payTo",
            Box::new(|r| r.pay_to = "0xAttacker000000000000000000000000000000".into()),
        ),
        (
            "maxTimeoutSeconds",
            Box::new(|r| r.max_timeout_seconds = 3600),
        ),
        ("extra dropped", Box::new(|r| r.extra = None)),
        (
            "extra domain",
            Box::new(|r| r.extra = Some(json!({ "name": "evil", "version": "1" }))),
        ),
    ];

    for (what, mutate) in mutations {
        let mut tampered = good.clone();
        mutate(&mut tampered);
        let header = payment_header(&tampered);
        let resp = send(
            &app,
            req_with(
                "GET",
                "/v1/forecast",
                &[("PAYMENT-SIGNATURE", &header)],
                vec![],
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED, "{what}");
        let challenge = header_json(resp.headers(), "PAYMENT-REQUIRED");
        assert_eq!(
            challenge["error"], "No matching payment requirements",
            "{what}"
        );
        // The rejection re-issues the *correct* requirements.
        assert_eq!(challenge["accepts"][0]["amount"], good.amount, "{what}");
    }
    assert!(mocks.timeline().is_empty());
}

#[tokio::test]
async fn validation_legacy_x_payment_header_is_accepted() {
    let mocks = Mocks::start().await;
    let app = mocks.app();
    let header = payment_header(&probe_requirements(&app, "/v1/forecast").await);

    let resp = send(
        &app,
        req_with("GET", "/v1/forecast", &[("X-PAYMENT", &header)], vec![]),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(mocks.facilitator.settle_count(), 1);
}

#[tokio::test]
async fn validation_payment_signature_takes_precedence_over_x_payment() {
    let mocks = Mocks::start().await;
    let app = mocks.app();
    let good = payment_header(&probe_requirements(&app, "/v1/forecast").await);

    // Valid PAYMENT-SIGNATURE + garbage X-PAYMENT -> paid.
    let resp = send(
        &app,
        req_with(
            "GET",
            "/v1/forecast",
            &[("PAYMENT-SIGNATURE", &good), ("X-PAYMENT", "garbage")],
            vec![],
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Garbage PAYMENT-SIGNATURE + valid X-PAYMENT -> rejected.
    let resp = send(
        &app,
        req_with(
            "GET",
            "/v1/forecast",
            &[("PAYMENT-SIGNATURE", "garbage"), ("X-PAYMENT", &good)],
            vec![],
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
}

// ===========================================================================
// verify
// ===========================================================================

#[tokio::test]
async fn verify_receives_the_payload_and_the_server_requirements() {
    let mocks = Mocks::start().await;
    let app = mocks.app();
    let reqs = probe_requirements(&app, "/v1/forecast").await;
    let payload = payload_for(&reqs);
    let header = encode_payload(&payload);

    send(
        &app,
        req_with(
            "GET",
            "/v1/forecast",
            &[("PAYMENT-SIGNATURE", &header)],
            vec![],
        ),
    )
    .await;

    let sent = mocks.facilitator.verify_requests.lock().unwrap()[0].clone();
    assert_eq!(sent["x402Version"], 2);
    assert_eq!(
        sent["paymentPayload"],
        serde_json::to_value(&payload).unwrap()
    );
    assert_eq!(
        sent["paymentRequirements"],
        serde_json::to_value(&reqs).unwrap()
    );
}

#[tokio::test]
async fn verify_invalid_with_reason_puts_the_reason_in_the_challenge() {
    let mocks = Mocks::start().await;
    mocks
        .facilitator
        .set_verify(verify_invalid(Some("insufficient_funds")));
    let resp = pay_get(&mocks.app(), "/v1/forecast").await;

    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    assert!(resp.headers().get("PAYMENT-RESPONSE").is_none());
    let challenge = header_json(resp.headers(), "PAYMENT-REQUIRED");
    assert_eq!(challenge["error"], "insufficient_funds");
    assert_eq!(challenge["accepts"].as_array().unwrap().len(), 1);

    assert_eq!(mocks.timeline(), vec!["verify"]);
    assert_eq!(mocks.upstream.count(), 0);
    assert_eq!(mocks.facilitator.settle_count(), 0);
}

#[tokio::test]
async fn verify_invalid_without_reason_uses_a_generic_message() {
    let mocks = Mocks::start().await;
    mocks.facilitator.set_verify(verify_invalid(None));
    let resp = pay_get(&mocks.app(), "/v1/forecast").await;

    let challenge = header_json(resp.headers(), "PAYMENT-REQUIRED");
    assert_eq!(challenge["error"], "Payment invalid");
}

#[tokio::test]
async fn verify_invalid_response_body_hides_upstream_data() {
    let mocks = Mocks::start().await;
    mocks.facilitator.set_verify(verify_invalid(Some("bad")));
    let resp = pay_get(&mocks.app(), "/v1/forecast").await;
    assert_eq!(body_json(resp).await, json!({}));
}

#[tokio::test]
async fn verify_facilitator_errors_are_402_with_unavailable_message() {
    let cases: Vec<(&str, Reply)> = vec![
        (
            "http 500",
            Reply::Raw {
                status: 500,
                body: "boom".into(),
            },
        ),
        (
            "http 502",
            Reply::Raw {
                status: 502,
                body: "bad gateway".into(),
            },
        ),
        (
            "http 503",
            Reply::Raw {
                status: 503,
                body: "".into(),
            },
        ),
        (
            "http 404",
            Reply::Raw {
                status: 404,
                body: "no route".into(),
            },
        ),
        (
            "200 but not json",
            Reply::Raw {
                status: 200,
                body: "<html>oops</html>".into(),
            },
        ),
        ("200 but wrong shape", Reply::Json(json!({ "ok": true }))),
    ];
    for (what, reply) in cases {
        let mocks = Mocks::start().await;
        mocks.facilitator.set_verify(reply);
        let resp = pay_get(&mocks.app(), "/v1/forecast").await;

        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED, "{what}");
        let challenge = header_json(resp.headers(), "PAYMENT-REQUIRED");
        let err = challenge["error"].as_str().unwrap();
        assert!(
            err.starts_with("facilitator verify unavailable"),
            "{what}: {err}"
        );
        assert_eq!(mocks.upstream.count(), 0, "{what}");
        assert_eq!(mocks.facilitator.settle_count(), 0, "{what}");
    }
}

#[tokio::test]
async fn verify_http_error_includes_status_and_body_in_the_message() {
    let mocks = Mocks::start().await;
    mocks.facilitator.set_verify(Reply::Raw {
        status: 503,
        body: "maintenance window".into(),
    });
    let resp = pay_get(&mocks.app(), "/v1/forecast").await;

    let err = header_json(resp.headers(), "PAYMENT-REQUIRED")["error"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(err.contains("503"), "{err}");
    assert!(err.contains("maintenance window"), "{err}");
}

#[tokio::test]
async fn verify_unreachable_facilitator_is_402() {
    let mocks = Mocks::start().await;
    let dead = dead_url().await;
    let app = build_app(&dead, &mocks.upstream_url, &AppOptions::default());
    let resp = pay_get(&app, "/v1/forecast").await;

    // The probe itself does not need the facilitator, so `pay_get` gets as far
    // as verify and lands here.
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    let err = header_json(resp.headers(), "PAYMENT-REQUIRED")["error"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(err.starts_with("facilitator verify unavailable"), "{err}");
    assert_eq!(mocks.upstream.count(), 0);
}

#[tokio::test]
async fn verify_slow_facilitator_times_out_as_402() {
    let mocks = Mocks::start().await;
    mocks.facilitator.set_verify(Reply::Delayed(
        Duration::from_millis(800),
        json!({ "isValid": true }),
    ));
    let app = mocks.app_with(&AppOptions {
        facilitator_timeout: Some(Duration::from_millis(100)),
        ..AppOptions::default()
    });
    let started = std::time::Instant::now();
    let resp = pay_get(&app, "/v1/forecast").await;

    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    assert!(
        started.elapsed() < Duration::from_millis(700),
        "must not wait for the slow reply"
    );
    assert_eq!(mocks.upstream.count(), 0);
}

// ===========================================================================
// settle
// ===========================================================================

#[tokio::test]
async fn settle_happy_path_orders_verify_upstream_settle() {
    let mocks = Mocks::start().await;
    let resp = pay_get(&mocks.app(), "/v1/forecast?x=1").await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(mocks.timeline(), vec!["verify", "upstream", "settle"]);

    let receipt = header_json(resp.headers(), "PAYMENT-RESPONSE");
    assert_eq!(receipt["success"], true);
    assert_eq!(receipt["transaction"], TX_HASH);
    assert_eq!(receipt["network"], KITE_TESTNET.network);
    assert_eq!(receipt["payer"], PAYER);
    assert!(receipt.get("errorReason").is_none());

    assert_eq!(body_json(resp).await, json!({ "upstream": true }));
}

#[tokio::test]
async fn settle_receives_the_same_payload_and_requirements_as_verify() {
    let mocks = Mocks::start().await;
    pay_get(&mocks.app(), "/v1/forecast").await;

    let verify = mocks.facilitator.verify_requests.lock().unwrap()[0].clone();
    let settle = mocks.facilitator.settle_requests.lock().unwrap()[0].clone();
    assert_eq!(verify, settle);
}

#[tokio::test]
async fn settle_adds_private_to_cache_control() {
    let mocks = Mocks::start().await;
    let resp = pay_get(&mocks.app(), "/v1/forecast").await;
    assert_eq!(resp.headers()[header::CACHE_CONTROL], "private");
}

#[tokio::test]
async fn settle_appends_private_to_an_existing_cache_control() {
    let mocks = Mocks::start().await;
    let mut reply = UpstreamReply::json(200);
    reply
        .headers
        .push(("cache-control".into(), "public, max-age=60".into()));
    mocks.upstream.set_reply(reply);

    let resp = pay_get(&mocks.app(), "/v1/forecast").await;
    assert_eq!(
        resp.headers()[header::CACHE_CONTROL],
        "public, max-age=60, private"
    );
}

#[tokio::test]
async fn settle_keeps_upstream_headers_alongside_payment_response() {
    let mocks = Mocks::start().await;
    let mut reply = UpstreamReply::json(200);
    reply
        .headers
        .push(("x-request-id".into(), "abc-123".into()));
    mocks.upstream.set_reply(reply);

    let resp = pay_get(&mocks.app(), "/v1/forecast").await;
    assert_eq!(resp.headers()["x-request-id"], "abc-123");
    assert!(resp.headers().contains_key("PAYMENT-RESPONSE"));
}

#[tokio::test]
async fn settle_happens_for_every_status_below_400() {
    for status in [200u16, 201, 202, 204, 206, 304] {
        let mocks = Mocks::start().await;
        mocks.upstream.set_status(status);
        let resp = pay_get(&mocks.app(), "/v1/forecast").await;

        assert_eq!(resp.status().as_u16(), status);
        assert!(resp.headers().contains_key("PAYMENT-RESPONSE"), "{status}");
        assert_eq!(mocks.facilitator.settle_count(), 1, "{status}");
    }
}

#[tokio::test]
async fn settle_never_happens_for_status_400_and_above() {
    for status in [400u16, 401, 403, 404, 418, 429, 500, 502, 503, 504] {
        let mocks = Mocks::start().await;
        mocks.upstream.set_status(status);
        let resp = pay_get(&mocks.app(), "/v1/forecast").await;

        assert_eq!(
            resp.status().as_u16(),
            status,
            "upstream status passes through"
        );
        assert!(!resp.headers().contains_key("PAYMENT-RESPONSE"), "{status}");
        assert_eq!(mocks.facilitator.settle_count(), 0, "{status}");
        assert_eq!(
            body_json(resp).await,
            json!({ "upstream": true }),
            "{status}"
        );
    }
}

#[tokio::test]
async fn settle_is_skipped_when_upstream_is_unreachable() {
    let mocks = Mocks::start().await;
    let dead = dead_url().await;
    let app = build_app(&mocks.facilitator_url, &dead, &AppOptions::default());
    let resp = pay_get(&app, "/v1/forecast").await;

    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(mocks.facilitator.verify_count(), 1);
    assert_eq!(mocks.facilitator.settle_count(), 0);
}

#[tokio::test]
async fn settle_rejected_by_facilitator_yields_402_with_failed_receipt() {
    let mocks = Mocks::start().await;
    mocks
        .facilitator
        .set_settle(settle_failed("nonce_already_used", KITE_TESTNET.network));
    let resp = pay_get(&mocks.app(), "/v1/forecast").await;

    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
    assert!(resp.headers().get("PAYMENT-REQUIRED").is_none());
    let receipt = header_json(resp.headers(), "PAYMENT-RESPONSE");
    assert_eq!(receipt["success"], false);
    assert_eq!(receipt["errorReason"], "nonce_already_used");
    // The buyer must not receive the upstream data they were not charged for.
    assert_eq!(body_json(resp).await, json!({}));
    assert_eq!(
        mocks.upstream.count(),
        1,
        "upstream was called before settlement"
    );
}

#[tokio::test]
async fn settle_facilitator_errors_yield_402_with_unavailable_receipt() {
    let cases: Vec<(&str, Reply)> = vec![
        (
            "http 500",
            Reply::Raw {
                status: 500,
                body: "settle exploded".into(),
            },
        ),
        (
            "200 not json",
            Reply::Raw {
                status: 200,
                body: "nope".into(),
            },
        ),
        ("200 wrong shape", Reply::Json(json!({ "hello": "world" }))),
    ];
    for (what, reply) in cases {
        let mocks = Mocks::start().await;
        mocks.facilitator.set_settle(reply);
        let resp = pay_get(&mocks.app(), "/v1/forecast").await;

        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED, "{what}");
        let receipt = header_json(resp.headers(), "PAYMENT-RESPONSE");
        assert_eq!(receipt["success"], false, "{what}");
        assert!(
            receipt["errorReason"]
                .as_str()
                .unwrap()
                .starts_with("facilitator settle unavailable"),
            "{what}: {receipt}"
        );
        assert_eq!(receipt["transaction"], "", "{what}");
        assert_eq!(receipt["network"], KITE_TESTNET.network, "{what}");
    }
}

#[tokio::test]
async fn settle_receipt_uses_the_configured_chain_when_facilitator_is_down() {
    let mocks = Mocks::start().await;
    mocks.facilitator.set_settle(Reply::Raw {
        status: 500,
        body: "x".into(),
    });
    let app = mocks.app_with(&AppOptions {
        chain: KITE_MAINNET,
        ..AppOptions::default()
    });
    let resp = pay_get(&app, "/v1/forecast").await;

    let receipt = header_json(resp.headers(), "PAYMENT-RESPONSE");
    assert_eq!(receipt["network"], KITE_MAINNET.network);
}

#[tokio::test]
async fn settle_receipt_is_passed_through_verbatim_including_amount() {
    let mocks = Mocks::start().await;
    mocks.facilitator.set_settle(Reply::Json(json!({
        "success": true,
        "transaction": "0xabc",
        "network": KITE_TESTNET.network,
        "payer": PAYER,
        "amount": "1000000000000000",
    })));
    let resp = pay_get(&mocks.app(), "/v1/forecast").await;

    let receipt = header_json(resp.headers(), "PAYMENT-RESPONSE");
    assert_eq!(receipt["transaction"], "0xabc");
    assert_eq!(receipt["amount"], "1000000000000000");
}

#[tokio::test]
async fn settle_each_paid_request_gets_its_own_verify_and_settle() {
    let mocks = Mocks::start().await;
    let app = mocks.app();
    for _ in 0..3 {
        assert_eq!(pay_get(&app, "/v1/forecast").await.status(), StatusCode::OK);
    }
    assert_eq!(mocks.facilitator.verify_count(), 3);
    assert_eq!(mocks.facilitator.settle_count(), 3);
    assert_eq!(mocks.upstream.count(), 3);
}

#[tokio::test]
async fn settle_works_for_post_with_a_body() {
    let mocks = Mocks::start().await;
    let resp = pay(&mocks.app(), "POST", "/v1/echo", br#"{"q":1}"#.to_vec()).await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(mocks.upstream.last().method, "POST");
    assert_eq!(mocks.upstream.last().body, br#"{"q":1}"#);
    assert_eq!(mocks.facilitator.settle_count(), 1);
}

// ===========================================================================
// concurrency
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrency_many_paid_requests_are_each_settled_exactly_once() {
    const N: usize = 25;
    let mocks = Mocks::start().await;
    let app = mocks.app();

    let mut tasks = Vec::new();
    for i in 0..N {
        let app = app.clone();
        tasks.push(tokio::spawn(async move {
            let uri = format!("/v1/item/{i}");
            let resp = pay_get(&app, &uri).await;
            (
                resp.status(),
                resp.headers().contains_key("PAYMENT-RESPONSE"),
            )
        }));
    }
    for t in tasks {
        let (status, has_receipt) = t.await.unwrap();
        assert_eq!(status, StatusCode::OK);
        assert!(has_receipt);
    }

    assert_eq!(mocks.facilitator.verify_count(), N);
    assert_eq!(mocks.facilitator.settle_count(), N);
    assert_eq!(mocks.upstream.count(), N);

    // Every path reached the upstream exactly once (no cross-talk).
    let mut paths: Vec<String> = mocks
        .upstream
        .requests
        .lock()
        .unwrap()
        .iter()
        .map(|r| r.path_and_query.clone())
        .collect();
    paths.sort();
    let mut expected: Vec<String> = (0..N).map(|i| format!("/item/{i}")).collect();
    expected.sort();
    assert_eq!(paths, expected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrency_failing_upstream_never_settles_any_request() {
    let mocks = Mocks::start().await;
    mocks.upstream.set_status(500);
    let app = mocks.app();

    let tasks: Vec<_> = (0..15)
        .map(|_| {
            let app = app.clone();
            tokio::spawn(async move { pay_get(&app, "/v1/forecast").await.status() })
        })
        .collect();
    for t in tasks {
        assert_eq!(t.await.unwrap(), StatusCode::INTERNAL_SERVER_ERROR);
    }
    assert_eq!(mocks.facilitator.settle_count(), 0);
}
