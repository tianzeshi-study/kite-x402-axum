//! The facilitator client sends the buyer's signed payment authorization in
//! the request body. These tests pin down which redirects it will follow, so
//! that signature can never be replayed to a host the facilitator chose.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{
    body::to_bytes,
    extract::Request,
    http::{header, StatusCode},
    response::IntoResponse,
    routing::any,
    Router,
};
use kite_x402_axum::{
    facilitator::{FacilitatorClient, FacilitatorError},
    types::{PaymentPayload, PaymentRequirements},
};

/// Records every request body that reaches it.
#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<String>>>);

/// Builds a handler that records every body it receives.
fn sink_app(sink: Sink) -> Router {
    Router::new().route(
        "/{*path}",
        any(move |req: Request| {
            let sink = sink.clone();
            async move {
                let body = to_bytes(req.into_body(), 1 << 20).await.unwrap_or_default();
                sink.0
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&body).into_owned());
                (
                    StatusCode::OK,
                    axum::Json(serde_json::json!({
                        "isValid": true,
                        "success": true,
                        "transaction": "0xsettled",
                        "network": "eip155:2368",
                    })),
                )
                    .into_response()
            }
        }),
    )
}

async fn serve(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("127.0.0.1:{}", addr.port())
}

fn request_pair() -> (PaymentPayload, PaymentRequirements) {
    let requirements = PaymentRequirements {
        scheme: "exact".into(),
        network: "eip155:2368".into(),
        amount: "1000".into(),
        asset: "0xusdc".into(),
        pay_to: "0xrecipient".into(),
        max_timeout_seconds: 60,
        extra: None,
    };
    let payload = PaymentPayload {
        x402_version: 2,
        resource: None,
        accepted: requirements.clone(),
        payload: serde_json::json!({ "signature": "0xSECRETSIGNATURE" }),
        extensions: None,
    };
    (payload, requirements)
}

#[tokio::test]
async fn a_cross_host_redirect_never_receives_the_signed_payload() {
    let sink = Sink::default();
    let sink_addr = serve(sink_app(sink.clone())).await;

    // `localhost` vs `127.0.0.1` is a different host, so this must not be followed.
    let sink_port = sink_addr.rsplit(':').next().expect("host:port");
    let target = format!("http://localhost:{sink_port}/stolen");
    let facilitator =
        serve(Router::new().route(
            "/{*path}",
            any(move || {
                let target = target.clone();
                async move {
                    (StatusCode::TEMPORARY_REDIRECT, [(header::LOCATION, target)]).into_response()
                }
            }),
        ))
        .await;

    let client =
        FacilitatorClient::with_timeout(format!("http://{facilitator}"), Duration::from_secs(5));
    let (payload, requirements) = request_pair();
    let result = client.settle(&payload, &requirements).await;

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        sink.0.lock().unwrap().is_empty(),
        "a cross-origin redirect delivered the request body to another host"
    );
    match result {
        Err(FacilitatorError::BadResponse { status, .. }) => assert_eq!(status, 307),
        other => panic!("expected the 307 to surface as a bad response, got {other:?}"),
    }
}

#[tokio::test]
async fn a_same_origin_redirect_is_still_followed() {
    // A relative Location keeps the hop on the same origin.
    let app = Router::new()
        .route(
            "/settle",
            any(|| async {
                (
                    StatusCode::TEMPORARY_REDIRECT,
                    [(header::LOCATION, "/settle-final")],
                )
                    .into_response()
            }),
        )
        .route(
            "/settle-final",
            any(|req: Request| async move {
                let body = to_bytes(req.into_body(), 1 << 20).await.unwrap_or_default();
                (
                    StatusCode::OK,
                    axum::Json(serde_json::json!({
                        "success": true,
                        "transaction": "0xsettled",
                        "network": "eip155:2368",
                        "echo_len": body.len(),
                    })),
                )
                    .into_response()
            }),
        );
    let facilitator = serve(app).await;

    let client =
        FacilitatorClient::with_timeout(format!("http://{facilitator}"), Duration::from_secs(5));
    let (payload, requirements) = request_pair();
    let response = client
        .settle(&payload, &requirements)
        .await
        .expect("a same-origin redirect must still be followed");

    assert!(response.success);
    assert_eq!(response.transaction, "0xsettled");
}
