//! Integration tests for webhook events emitted by the payment gate.
//!
//! The gate is driven through its public API against a mock facilitator and
//! upstream; assertions read the events queued on the same
//! `WebhookDispatcher` an operator would run a delivery worker for.

mod common;

use std::sync::Arc;

use axum::http::StatusCode;
use common::*;
use kite_x402_axum::kite::KITE_TESTNET;
use kite_x402_axum::{WebhookConfig, WebhookDispatcher, WebhookEventType};

fn dispatcher(max_queue_size: usize) -> Arc<WebhookDispatcher> {
    Arc::new(WebhookDispatcher::new(WebhookConfig {
        target_urls: vec!["https://hooks.example/kite".into()],
        max_queue_size,
        ..Default::default()
    }))
}

fn options_with(hooks: &Arc<WebhookDispatcher>) -> AppOptions {
    AppOptions {
        webhooks: Some(Arc::clone(hooks)),
        ..AppOptions::default()
    }
}

#[tokio::test]
async fn successful_payment_queues_a_payment_settled_event() {
    let mocks = Mocks::start().await;
    let hooks = dispatcher(100);
    let app = build_app(
        &mocks.facilitator_url,
        &mocks.upstream_url,
        &options_with(&hooks),
    );

    let resp = pay_get(&app, "/v1/forecast").await;
    assert_eq!(resp.status(), StatusCode::OK);

    assert_eq!(hooks.pending_count(), 1);
    let queued = hooks.next_due(u64::MAX).expect("one queued delivery");
    let payload = queued.payload;
    assert_eq!(payload.event_type, WebhookEventType::PaymentSettled);
    assert_eq!(payload.payer.as_deref(), Some(PAYER));
    assert_eq!(payload.tx_hash.as_deref(), Some(TX_HASH));
    assert_eq!(payload.network.as_deref(), Some(KITE_TESTNET.network));
    assert!(payload.amount_atomic.unwrap().parse::<u64>().unwrap() > 0);
    assert_eq!(queued.target_url, "https://hooks.example/kite");
}

#[tokio::test]
async fn rejected_settlement_queues_a_payment_failed_event() {
    let mocks = Mocks::start().await;
    mocks
        .facilitator
        .set_settle(settle_failed("nonce_already_used", KITE_TESTNET.network));
    let hooks = dispatcher(100);
    let app = build_app(
        &mocks.facilitator_url,
        &mocks.upstream_url,
        &options_with(&hooks),
    );

    let resp = pay_get(&app, "/v1/forecast").await;
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);

    assert_eq!(hooks.pending_count(), 1);
    let payload = hooks.next_due(u64::MAX).unwrap().payload;
    assert_eq!(payload.event_type, WebhookEventType::PaymentFailed);
    assert_eq!(
        payload.payer.as_deref(),
        Some(PAYER),
        "falls back to the verified payer"
    );
}

#[tokio::test]
async fn challenges_and_failed_verifications_queue_nothing() {
    let mocks = Mocks::start().await;
    let hooks = dispatcher(100);
    let app = build_app(
        &mocks.facilitator_url,
        &mocks.upstream_url,
        &options_with(&hooks),
    );

    let unpaid = send(&app, get_req("/v1/forecast")).await;
    assert_eq!(unpaid.status(), StatusCode::PAYMENT_REQUIRED);

    mocks
        .facilitator
        .set_verify(verify_invalid(Some("insufficient_funds")));
    let rejected = pay_get(&app, "/v1/forecast").await;
    assert_eq!(rejected.status(), StatusCode::PAYMENT_REQUIRED);

    assert_eq!(mocks.facilitator.settle_count(), 0);
    assert_eq!(hooks.pending_count(), 0, "no settle attempt means no event");
}

#[tokio::test]
async fn a_full_or_zero_capacity_queue_never_affects_the_response() {
    let mocks = Mocks::start().await;
    let hooks = dispatcher(0);
    let app = build_app(
        &mocks.facilitator_url,
        &mocks.upstream_url,
        &options_with(&hooks),
    );

    let resp = pay_get(&app, "/v1/forecast").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(hooks.pending_count(), 0);
}

#[tokio::test]
async fn every_paid_call_queues_its_own_event() {
    let mocks = Mocks::start().await;
    let hooks = dispatcher(100);
    let app = build_app(
        &mocks.facilitator_url,
        &mocks.upstream_url,
        &options_with(&hooks),
    );

    for _ in 0..3 {
        assert_eq!(pay_get(&app, "/v1/forecast").await.status(), StatusCode::OK);
    }
    assert_eq!(hooks.pending_count(), 3);
}
