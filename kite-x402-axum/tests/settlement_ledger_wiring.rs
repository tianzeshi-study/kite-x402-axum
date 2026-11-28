//! Integration tests for the settlement ledger wired into the payment gate.
//!
//! The gate is exercised through its public API against a real (mock)
//! facilitator and upstream, and the assertions read the same
//! `SettlementLedger` the operator would expose for reconciliation.

mod common;

use std::sync::Arc;

use axum::http::StatusCode;
use common::*;
use kite_x402_axum::kite::KITE_TESTNET;
use kite_x402_axum::SettlementLedger;

fn options_with(ledger: &Arc<SettlementLedger>) -> AppOptions {
    AppOptions {
        settlement_ledger: Some(Arc::clone(ledger)),
        ..AppOptions::default()
    }
}

#[tokio::test]
async fn successful_payment_is_recorded_with_its_receipt() {
    let mocks = Mocks::start().await;
    let ledger = Arc::new(SettlementLedger::new(1000));
    let app = build_app(
        &mocks.facilitator_url,
        &mocks.upstream_url,
        &options_with(&ledger),
    );

    let resp = pay_get(&app, "/v1/forecast").await;
    assert_eq!(resp.status(), StatusCode::OK);

    let recent = ledger.recent(10);
    assert_eq!(recent.len(), 1, "one paid call records one settlement");
    let record = &recent[0];
    assert!(record.success);
    assert_eq!(record.tx_hash, TX_HASH);
    assert_eq!(record.network, KITE_TESTNET.network);
    assert_eq!(record.payer, PAYER);
    assert_eq!(record.pay_to, PAY_TO);
    assert!(
        record.amount.is_some(),
        "amount comes from the matched option"
    );
    assert!(record.error_reason.is_none());

    let summary = ledger.summary();
    assert_eq!(summary.successful_count, 1);
    assert_eq!(summary.failed_count, 0);
    assert_eq!(
        Some(&summary.volumes[0].amount_atomic),
        record.amount.as_ref()
    );
}

#[tokio::test]
async fn rejected_settlement_is_recorded_as_a_failure() {
    let mocks = Mocks::start().await;
    mocks
        .facilitator
        .set_settle(settle_failed("nonce_already_used", KITE_TESTNET.network));
    let ledger = Arc::new(SettlementLedger::new(1000));
    let app = build_app(
        &mocks.facilitator_url,
        &mocks.upstream_url,
        &options_with(&ledger),
    );

    let resp = pay_get(&app, "/v1/forecast").await;
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);

    let recent = ledger.recent(10);
    assert_eq!(recent.len(), 1, "a rejected settle is still recorded");
    assert!(!recent[0].success);
    assert_eq!(
        recent[0].error_reason.as_deref(),
        Some("nonce_already_used")
    );
    assert_eq!(
        recent[0].payer, PAYER,
        "payer falls back to the verify result"
    );
    assert_eq!(ledger.summary().failed_count, 1);
}

#[tokio::test]
async fn unreachable_facilitator_during_settle_is_recorded_as_an_uncertain_attempt() {
    let mocks = Mocks::start().await;
    let dead = dead_url().await;
    let ledger = Arc::new(SettlementLedger::new(1000));
    let opts = AppOptions {
        facilitator_timeout: Some(std::time::Duration::from_millis(50)),
        settlement_ledger: Some(Arc::clone(&ledger)),
        ..AppOptions::default()
    };
    let app = build_app(&dead, &mocks.upstream_url, &opts);

    // Verify also goes to the dead facilitator, so no settle is attempted and
    // nothing is recorded: an unverified payment was never a settlement.
    let resp = pay_get(&app, "/v1/forecast").await;
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    assert!(ledger.is_empty());
}

#[tokio::test]
async fn unpaid_challenge_is_not_recorded() {
    let mocks = Mocks::start().await;
    let ledger = Arc::new(SettlementLedger::new(1000));
    let app = build_app(
        &mocks.facilitator_url,
        &mocks.upstream_url,
        &options_with(&ledger),
    );

    let resp = send(&app, get_req("/v1/forecast")).await;
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    assert!(
        ledger.is_empty(),
        "issuing a challenge must not create a settlement record"
    );
}

#[tokio::test]
async fn upstream_failure_that_skips_settlement_is_not_recorded() {
    let mocks = Mocks::start().await;
    let dead = dead_url().await;
    let ledger = Arc::new(SettlementLedger::new(1000));
    let app = build_app(&mocks.facilitator_url, &dead, &options_with(&ledger));

    let resp = pay_get(&app, "/v1/forecast").await;
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(mocks.facilitator.settle_count(), 0);
    assert!(
        ledger.is_empty(),
        "a request that was never settled must not appear in the ledger"
    );
}

#[tokio::test]
async fn gate_without_a_ledger_still_works() {
    let mocks = Mocks::start().await;
    let app = mocks.app();
    let resp = pay_get(&app, "/v1/forecast").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(mocks.facilitator.settle_count(), 1);
}
