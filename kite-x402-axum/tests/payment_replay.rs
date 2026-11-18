//! Replay lifecycle tests through the public payment middleware and real HTTP mocks.

mod common;

use std::{sync::Arc, time::Duration};

use axum::{http::StatusCode, middleware, routing::any, Router};
use common::*;
use kite_x402_axum::{
    kite::KITE_TESTNET, x402_payment, FacilitatorClient, PaymentConfig, PaymentNonceReplayGuard,
    UpstreamConfig,
};
use serde_json::json;

fn app(mocks: &Mocks, guard: Arc<PaymentNonceReplayGuard>, timeout: Duration) -> Router {
    let config = PaymentConfig::new(
        PAY_TO,
        KITE_TESTNET,
        "0.001",
        "Replay tests",
        FacilitatorClient::with_timeout(&mocks.facilitator_url, timeout),
    )
    .with_nonce_guard(guard);
    let upstream = Arc::new(UpstreamConfig {
        http: upstream_client(),
        base_url: mocks.upstream_url.clone(),
        auth_header: "Authorization".into(),
        auth_value: String::new(),
    });
    Router::new().nest(
        "/v1",
        Router::new()
            .route("/{*path}", any(kite_x402_axum::proxy))
            .with_state(upstream)
            .layer(middleware::from_fn_with_state(
                Arc::new(config),
                x402_payment,
            )),
    )
}

async fn signature(app: &Router, payer: &str, nonce: &str) -> String {
    let requirements = probe_requirements(app, "/v1/items").await;
    let mut payload = payload_for(&requirements);
    payload.payload["authorization"]["from"] = json!(payer);
    payload.payload["authorization"]["nonce"] = json!(nonce);
    encode_payload(&payload)
}

fn paid_request(signature: &str) -> axum::extract::Request {
    req_with(
        "GET",
        "/v1/items",
        &[("PAYMENT-SIGNATURE", signature)],
        vec![],
    )
}

async fn wait_for(condition: impl Fn() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("payment phase was not reached");
}

#[tokio::test]
async fn verification_failures_release_reservations_for_the_same_authorization() {
    for reply in [
        verify_invalid(Some("invalid signature")),
        Reply::Raw {
            status: 503,
            body: "unavailable".into(),
        },
        Reply::Raw {
            status: 200,
            body: "not-json".into(),
        },
        Reply::Delayed(Duration::from_secs(60), json!({"isValid":true})),
    ] {
        let mocks = Mocks::start().await;
        let guard = Arc::new(PaymentNonceReplayGuard::new(1, 60));
        let app = app(&mocks, guard.clone(), Duration::from_millis(200));
        let header = signature(&app, "0x1111", "0xabcd").await;
        mocks.facilitator.set_verify(reply);
        assert_eq!(send(&app, paid_request(&header)).await.status(), 402);
        assert!(guard.is_empty());
        assert_eq!(mocks.upstream.count(), 0);
        assert_eq!(mocks.facilitator.settle_count(), 0);
        mocks.facilitator.set_verify(verify_ok());
        assert_eq!(send(&app, paid_request(&header)).await.status(), 200);
        assert_eq!(mocks.facilitator.verify_count(), 2);
        assert_eq!(mocks.facilitator.settle_count(), 1);
    }
}

#[tokio::test]
async fn known_upstream_failures_release_without_settlement() {
    for status in [400, 429, 500, 503] {
        let mocks = Mocks::start().await;
        let guard = Arc::new(PaymentNonceReplayGuard::new(1, 60));
        let app = app(&mocks, guard.clone(), Duration::from_secs(5));
        let header = signature(&app, "0x1111", "0xabcd").await;
        mocks.upstream.set_reply(UpstreamReply::json(status));
        assert_eq!(
            send(&app, paid_request(&header)).await.status().as_u16(),
            status
        );
        assert!(guard.is_empty());
        assert_eq!(mocks.facilitator.settle_count(), 0);
        mocks.upstream.set_reply(UpstreamReply::json(200));
        assert_eq!(send(&app, paid_request(&header)).await.status(), 200);
        assert_eq!(mocks.facilitator.verify_count(), 2);
        assert_eq!(mocks.facilitator.settle_count(), 1);
    }
}

#[tokio::test]
async fn all_settlement_attempts_retain_authorization_protection() {
    for (reply, expected_status) in [
        (settle_ok(KITE_TESTNET.network), 200),
        (
            settle_failed("nonce_already_used", KITE_TESTNET.network),
            402,
        ),
        (
            Reply::Raw {
                status: 503,
                body: "unavailable".into(),
            },
            402,
        ),
        (
            Reply::Raw {
                status: 200,
                body: "not-json".into(),
            },
            402,
        ),
        (Reply::Delayed(Duration::from_secs(60), json!({})), 402),
    ] {
        let mocks = Mocks::start().await;
        let guard = Arc::new(PaymentNonceReplayGuard::new(1, 60));
        let app = app(&mocks, guard.clone(), Duration::from_millis(200));
        let header = signature(&app, "0x1111", "0xabcd").await;
        mocks.facilitator.set_settle(reply);
        assert_eq!(
            send(&app, paid_request(&header)).await.status().as_u16(),
            expected_status
        );
        assert_eq!(guard.len(), 1);
        let duplicate = send(&app, paid_request(&header)).await;
        assert_eq!(duplicate.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(
            header_json(duplicate.headers(), "payment-required")["error"]
                .as_str()
                .unwrap()
                .contains("already been used")
        );
        assert_eq!(mocks.facilitator.verify_count(), 1);
        assert_eq!(mocks.upstream.count(), 1);
        assert_eq!(mocks.facilitator.settle_count(), 1);
    }
}

#[tokio::test]
async fn duplicates_are_blocked_in_every_pending_phase_and_cancellation_is_safe() {
    for phase in ["verify", "upstream", "settle"] {
        let mocks = Mocks::start().await;
        match phase {
            "verify" => mocks.facilitator.set_verify(Reply::Delayed(
                Duration::from_secs(60),
                json!({"isValid":true}),
            )),
            "upstream" => {
                let mut reply = UpstreamReply::json(200);
                reply.delay = Some(Duration::from_secs(60));
                mocks.upstream.set_reply(reply);
            }
            "settle" => mocks
                .facilitator
                .set_settle(Reply::Delayed(Duration::from_secs(60), json!({}))),
            _ => unreachable!(),
        }
        let guard = Arc::new(PaymentNonceReplayGuard::new(1, 1));
        let app = app(&mocks, guard.clone(), Duration::from_secs(120));
        let header = signature(&app, "0x1111", "0xabcd").await;
        let pending_app = app.clone();
        let pending_header = header.clone();
        let pending =
            tokio::spawn(async move { send(&pending_app, paid_request(&pending_header)).await });
        wait_for(|| match phase {
            "verify" => mocks.facilitator.verify_count() == 1,
            "upstream" => mocks.upstream.count() == 1,
            "settle" => mocks.facilitator.settle_count() == 1,
            _ => false,
        })
        .await;
        assert_eq!(send(&app, paid_request(&header)).await.status(), 402);
        assert_eq!(mocks.facilitator.verify_count(), 1);
        pending.abort();
        assert!(pending.await.unwrap_err().is_cancelled());
        if phase == "verify" {
            assert!(guard.is_empty());
            mocks.facilitator.set_verify(verify_ok());
            assert_eq!(send(&app, paid_request(&header)).await.status(), 200);
            assert_eq!(mocks.facilitator.verify_count(), 2);
        } else {
            assert_eq!(guard.len(), 1);
            assert_eq!(send(&app, paid_request(&header)).await.status(), 402);
            assert_eq!(mocks.facilitator.verify_count(), 1);
        }
    }
}

#[tokio::test]
async fn different_payers_can_use_the_same_nonce_but_duplicates_stay_blocked() {
    let mocks = Mocks::start().await;
    let guard = Arc::new(PaymentNonceReplayGuard::new(10, 60));
    let app = app(&mocks, guard, Duration::from_secs(5));
    let first = signature(&app, "0xAAAA", "0xABCD").await;
    let second = signature(&app, "0xBBBB", "0xabcd").await;
    let alias = signature(&app, "0xaaaa", "0xabcd").await;
    for header in [&first, &second] {
        assert_eq!(send(&app, paid_request(header)).await.status(), 200);
    }
    assert_eq!(send(&app, paid_request(&alias)).await.status(), 402);
    assert_eq!(mocks.facilitator.verify_count(), 2);
    assert_eq!(mocks.facilitator.settle_count(), 2);
}

#[tokio::test]
async fn capacity_rejects_new_authorizations_without_backend_side_effects() {
    let mocks = Mocks::start().await;
    let guard = Arc::new(PaymentNonceReplayGuard::new(1, 60));
    let app = app(&mocks, guard, Duration::from_secs(5));
    let first = signature(&app, "0x1111", "0xaaaa").await;
    let other = signature(&app, "0x1111", "0xbbbb").await;
    assert_eq!(send(&app, paid_request(&first)).await.status(), 200);
    let saturated = send(&app, paid_request(&other)).await;
    assert_eq!(saturated.status(), 503);
    assert_eq!(saturated.headers()["cache-control"], "no-store");
    assert_eq!(saturated.headers()["retry-after"], "1");
    assert_eq!(
        body_json(saturated).await["error"],
        "payment_replay_capacity_exceeded"
    );
    assert_eq!(send(&app, paid_request(&first)).await.status(), 402);
    assert_eq!(mocks.facilitator.verify_count(), 1);
    assert_eq!(mocks.upstream.count(), 1);
    assert_eq!(mocks.facilitator.settle_count(), 1);
}
