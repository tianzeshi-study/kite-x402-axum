//! Direct tests for the facilitator readiness probes (`probe` and
//! `probe_network`), which decide what `/readyz` reports.

use axum::{http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use kite_x402_axum::{FacilitatorClient, FacilitatorError};
use serde_json::{json, Value};
use tokio::net::TcpListener;

const NETWORK: &str = "eip155:2368";

/// Serves `GET /supported` with a canned status and body; returns the base URL.
async fn facilitator_with(status: u16, body: &'static str) -> String {
    let app = Router::new().route(
        "/supported",
        get(move || async move {
            (
                StatusCode::from_u16(status).unwrap(),
                [("content-type", "application/json")],
                body,
            )
                .into_response()
        }),
    );
    serve(app).await
}

async fn facilitator_advertising(kinds: Value) -> String {
    let app = Router::new().route(
        "/supported",
        get(move || {
            let kinds = kinds.clone();
            async move { Json(json!({ "kinds": kinds })) }
        }),
    );
    serve(app).await
}

async fn serve(app: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

fn bad_response_body(err: FacilitatorError) -> String {
    let FacilitatorError::BadResponse { op, body, .. } = err else {
        panic!("expected BadResponse, got {err:?}");
    };
    assert_eq!(op, "probe");
    body
}

#[tokio::test]
async fn probe_network_accepts_a_matching_v2_exact_kind() {
    let url = facilitator_advertising(json!([
        {"x402Version": 2, "scheme": "exact", "network": "eip155:1"},
        {"x402Version": 2, "scheme": "exact", "network": NETWORK},
    ]))
    .await;
    FacilitatorClient::new(url)
        .probe_network(NETWORK)
        .await
        .unwrap();
}

#[tokio::test]
async fn probe_without_a_network_accepts_any_v2_exact_kind() {
    let url = facilitator_advertising(json!([
        {"x402Version": 2, "scheme": "exact", "network": "eip155:1"},
    ]))
    .await;
    FacilitatorClient::new(url).probe().await.unwrap();
}

#[tokio::test]
async fn probe_network_rejects_a_facilitator_that_does_not_offer_the_network() {
    let url = facilitator_advertising(json!([
        {"x402Version": 2, "scheme": "exact", "network": "eip155:1"},
    ]))
    .await;
    let err = FacilitatorClient::new(url)
        .probe_network(NETWORK)
        .await
        .unwrap_err();
    assert!(bad_response_body(err).contains("not offered"));
}

#[tokio::test]
async fn probe_rejects_kinds_that_are_not_v2_exact() {
    for kinds in [
        json!([]),
        json!([{"x402Version": 1, "scheme": "exact", "network": NETWORK}]),
        json!([{"x402Version": 2, "scheme": "upto", "network": NETWORK}]),
        json!([{"x402Version": 2, "scheme": "exact", "network": ""}]),
    ] {
        let url = facilitator_advertising(kinds.clone()).await;
        let err = FacilitatorClient::new(url).probe().await.unwrap_err();
        assert!(
            bad_response_body(err).contains("not offered"),
            "{kinds} must not count as ready"
        );
    }
}

#[tokio::test]
async fn probe_reports_non_success_statuses_with_the_status_code() {
    for status in [404u16, 500, 503] {
        let url = facilitator_with(status, "{}").await;
        let err = FacilitatorClient::new(url).probe().await.unwrap_err();
        let FacilitatorError::BadResponse {
            op, status: got, ..
        } = err
        else {
            panic!("expected BadResponse for {status}, got {err:?}");
        };
        assert_eq!(op, "probe");
        assert_eq!(got, status);
    }
}

#[tokio::test]
async fn probe_treats_an_unparseable_success_body_as_an_error() {
    for body in ["", "not json", "{\"kinds\": 5}", "{}"] {
        let url = facilitator_with(200, body).await;
        let result = FacilitatorClient::new(url).probe().await;
        assert!(result.is_err(), "body {body:?} must not count as ready");
    }
}

#[tokio::test]
async fn probe_fails_when_the_facilitator_is_unreachable() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let err = FacilitatorClient::new(format!("http://{addr}"))
        .probe()
        .await
        .unwrap_err();
    assert!(matches!(err, FacilitatorError::Request(_)), "{err:?}");
}
