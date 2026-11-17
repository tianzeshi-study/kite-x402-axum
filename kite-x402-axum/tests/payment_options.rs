//! Integration tests for multi-option payment configuration (issue: support
//! multiple `PaymentRequirements` options per route,
//! `findMatchingRequirements`-style matching).
//!
//! Everything goes through the crate's public API only: the 402 challenge
//! must advertise every configured option, a client may pay with any of
//! them, and verification/settlement must then use the option the client
//! chose rather than blindly the primary one.

mod common;

use axum::http::StatusCode;
use common::*;
use kite_x402_axum::kite::{KITE_MAINNET, KITE_TESTNET};
use serde_json::json;

/// The default app plus two extra options: mainnet USDC at $0.05 and a
/// second testnet tier at $0.002.
fn multi_option_app(mocks: &Mocks) -> axum::Router {
    mocks.app_with(&AppOptions {
        extra_payment_options: vec![
            (KITE_MAINNET, "$0.05".into()),
            (KITE_TESTNET, "0.002".into()),
        ],
        ..AppOptions::default()
    })
}

/// All advertised options, decoded from a 402 challenge's `PAYMENT-REQUIRED`
/// header.
async fn advertised_options(app: &axum::Router, uri: &str) -> serde_json::Value {
    let resp = send(app, get_req(uri)).await;
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    header_json(resp.headers(), "PAYMENT-REQUIRED")["accepts"].clone()
}

// ===========================================================================
// challenge
// ===========================================================================

#[tokio::test]
async fn challenge_advertises_all_options_in_configuration_order() {
    let mocks = Mocks::start().await;
    let accepts = advertised_options(&multi_option_app(&mocks), "/v1/forecast").await;

    let accepts = accepts.as_array().unwrap();
    assert_eq!(accepts.len(), 3);

    // Primary first: testnet pieUSD, 18 decimals.
    assert_eq!(accepts[0]["network"], json!(KITE_TESTNET.network));
    assert_eq!(accepts[0]["amount"], json!("1000000000000000"));

    // Then mainnet USDC, 6 decimals.
    assert_eq!(accepts[1]["network"], json!(KITE_MAINNET.network));
    assert_eq!(accepts[1]["amount"], json!("50000"));
    assert_eq!(accepts[1]["payTo"], json!(PAY_TO));

    // Then the second testnet tier.
    assert_eq!(accepts[2]["network"], json!(KITE_TESTNET.network));
    assert_eq!(accepts[2]["amount"], json!("2000000000000000"));

    // A single-option config still advertises exactly one option.
    let single = advertised_options(&mocks.app(), "/v1/forecast").await;
    assert_eq!(single.as_array().unwrap().len(), 1);
}

// ===========================================================================
// paying with an advertised option
// ===========================================================================

#[tokio::test]
async fn paying_with_a_non_primary_option_settles_that_option() {
    let mocks = Mocks::start().await;
    let app = multi_option_app(&mocks);

    let accepts = advertised_options(&app, "/v1/forecast").await;
    let chosen: kite_x402_axum::types::PaymentRequirements =
        serde_json::from_value(accepts[1].clone()).unwrap(); // the mainnet option
    let payload = payload_for(&chosen);
    let header = encode_payload(&payload);

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

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get("PAYMENT-RESPONSE").is_some());
    assert_eq!(mocks.timeline(), vec!["verify", "upstream", "settle"]);

    // Both facilitator calls must carry the option the client chose, not the
    // primary testnet requirements.
    let verify = mocks.facilitator.verify_requests.lock().unwrap()[0].clone();
    assert_eq!(
        verify["paymentRequirements"],
        serde_json::to_value(&chosen).unwrap()
    );
    let settle = mocks.facilitator.settle_requests.lock().unwrap()[0].clone();
    assert_eq!(
        settle["paymentRequirements"],
        serde_json::to_value(&chosen).unwrap()
    );
    assert_eq!(settle["paymentRequirements"]["network"], "eip155:2366");
}

#[tokio::test]
async fn paying_with_the_primary_option_still_works() {
    let mocks = Mocks::start().await;
    let app = multi_option_app(&mocks);
    let resp = pay_get(&app, "/v1/forecast").await; // probes and pays accepts[0]

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(mocks.timeline(), vec!["verify", "upstream", "settle"]);
}

#[tokio::test]
async fn matching_tolerates_a_smaller_client_timeout() {
    // findMatchingRequirements-style matching ignores maxTimeoutSeconds: a
    // client capping the validity window below the server's suggestion must
    // still be accepted for verification.
    let mocks = Mocks::start().await;
    let app = multi_option_app(&mocks);

    let accepts = advertised_options(&app, "/v1/forecast").await;
    let mut chosen: kite_x402_axum::types::PaymentRequirements =
        serde_json::from_value(accepts[2].clone()).unwrap();
    chosen.max_timeout_seconds = 5;
    chosen.extra = None;
    let header = payment_header(&chosen);

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

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(mocks.timeline(), vec!["verify", "upstream", "settle"]);
}

// ===========================================================================
// rejection
// ===========================================================================

#[tokio::test]
async fn an_amount_matching_no_option_is_rejected_and_all_options_readvertised() {
    let mocks = Mocks::start().await;
    let app = multi_option_app(&mocks);

    let accepts = advertised_options(&app, "/v1/forecast").await;
    let mut bogus: kite_x402_axum::types::PaymentRequirements =
        serde_json::from_value(accepts[0].clone()).unwrap();
    bogus.amount = "123".into();
    let header = payment_header(&bogus);

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

    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    let challenge = header_json(resp.headers(), "PAYMENT-REQUIRED");
    assert_eq!(
        challenge["error"],
        json!("No matching payment requirements")
    );
    assert_eq!(challenge["accepts"].as_array().unwrap().len(), 3);
    // Rejected before the facilitator was contacted.
    assert!(mocks.facilitator.verify_requests.lock().unwrap().is_empty());
    assert_eq!(mocks.upstream.count(), 0);
}

#[tokio::test]
async fn an_invalid_extra_option_price_fails_fast_with_a_500() {
    let mocks = Mocks::start().await;
    let app = mocks.app_with(&AppOptions {
        extra_payment_options: vec![(KITE_MAINNET, "not-a-price".into())],
        ..AppOptions::default()
    });

    let resp = send(&app, get_req("/v1/forecast")).await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(resp.headers().get("PAYMENT-REQUIRED").is_none());
    let body = body_json(resp).await;
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("extra payment option #0"),
        "{}",
        body
    );
}
