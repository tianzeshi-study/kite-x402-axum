//! HTTP delivery of webhooks: signing, retry scheduling, redirects and
//! error hygiene, against a real local receiver.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use kite_x402_axum::{
    verify_signature_at, DeliveryStatus, WebhookConfig, WebhookDispatcher, WebhookEventType,
    SIGNATURE_HEADER, TIMESTAMP_HEADER,
};
use tokio::net::TcpListener;

#[derive(Clone, Default)]
struct Receiver {
    /// Status codes to answer with, in order; 200 once exhausted.
    script: Arc<Mutex<Vec<u16>>>,
    /// (headers, body) of every request received.
    seen: Arc<Mutex<Vec<(HeaderMap, Vec<u8>)>>>,
}

async fn hook(State(rx): State<Receiver>, headers: HeaderMap, body: Bytes) -> Response {
    rx.seen.lock().unwrap().push((headers, body.to_vec()));
    let status = {
        let mut script = rx.script.lock().unwrap();
        if script.is_empty() {
            200
        } else {
            script.remove(0)
        }
    };
    StatusCode::from_u16(status).unwrap().into_response()
}

async fn serve(app: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

async fn receiver(script: &[u16]) -> (String, Receiver) {
    let rx = Receiver {
        script: Arc::new(Mutex::new(script.to_vec())),
        ..Default::default()
    };
    let url = serve(
        Router::new()
            .route("/hook", post(hook))
            .with_state(rx.clone()),
    )
    .await;
    (format!("{url}/hook"), rx)
}

fn dispatcher(url: &str, secret: Option<&str>, max_retries: u32) -> WebhookDispatcher {
    WebhookDispatcher::new(WebhookConfig {
        target_urls: vec![url.to_owned()],
        max_retries,
        initial_backoff: Duration::from_secs(10),
        max_queue_size: 100,
        signing_secret: secret.map(str::to_owned),
    })
}

fn enqueue(d: &WebhookDispatcher) -> u64 {
    d.enqueue_event(
        WebhookEventType::PaymentSettled,
        Some("0xpayer".into()),
        Some("eip155:2368".into()),
        Some("1000".into()),
        Some("0xtx".into()),
        Some("/v1/data".into()),
    )[0]
}

fn client() -> reqwest::Client {
    kite_x402_axum::webhook::delivery_client().unwrap()
}

const T0: u64 = 1_700_000_000_000;

#[tokio::test]
async fn delivers_signed_json_and_marks_the_record_delivered() {
    let (url, rx) = receiver(&[]).await;
    let d = dispatcher(&url, Some("whsec"), 3);
    let id = enqueue(&d);

    let record = d.deliver_next_at(&client(), T0).await.expect("due");
    assert_eq!(record.delivery_id, id);
    assert_eq!(record.status, DeliveryStatus::Delivered);
    assert_eq!(record.last_status_code, Some(200));
    assert_eq!(d.pending_count(), 0);

    let seen = rx.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    let (headers, body) = &seen[0];
    assert_eq!(headers["content-type"], "application/json");
    assert_eq!(headers["x-kite-delivery-id"], id.to_string().as_str());
    let timestamp: u64 = headers[TIMESTAMP_HEADER].to_str().unwrap().parse().unwrap();
    assert_eq!(timestamp, T0 / 1000);
    assert!(verify_signature_at(
        "whsec",
        timestamp,
        body,
        headers[SIGNATURE_HEADER].to_str().unwrap(),
        T0 / 1000,
        300,
    ));
    let json: serde_json::Value = serde_json::from_slice(body).unwrap();
    assert_eq!(json["event_type"], "payment_settled");
    assert_eq!(json["tx_hash"], "0xtx");
    assert_eq!(
        headers["x-kite-event-id"],
        json["event_id"].as_str().unwrap()
    );
}

#[tokio::test]
async fn omits_the_signature_when_no_secret_is_configured() {
    let (url, rx) = receiver(&[]).await;
    let d = dispatcher(&url, None, 3);
    enqueue(&d);
    d.deliver_next_at(&client(), T0).await.unwrap();
    let seen = rx.seen.lock().unwrap();
    assert!(seen[0].0.get(SIGNATURE_HEADER).is_none());
    assert!(seen[0].0.get(TIMESTAMP_HEADER).is_some());
}

#[tokio::test]
async fn a_failed_attempt_is_retried_only_after_the_backoff_elapses() {
    let (url, rx) = receiver(&[503, 200]).await;
    let d = dispatcher(&url, None, 3);
    enqueue(&d);

    let first = d.deliver_next_at(&client(), T0).await.unwrap();
    assert_eq!(first.status, DeliveryStatus::Failed);
    assert_eq!(first.last_status_code, Some(503));
    assert_eq!(
        first.last_error.as_deref(),
        Some("HTTP 503 Service Unavailable")
    );

    // 9.999 s later: still backing off, nothing is sent.
    assert!(d.deliver_next_at(&client(), T0 + 9_999).await.is_none());
    assert_eq!(rx.seen.lock().unwrap().len(), 1);

    // Exactly the initial backoff later: due again, and this time it succeeds.
    let second = d.deliver_next_at(&client(), T0 + 10_000).await.unwrap();
    assert_eq!(second.status, DeliveryStatus::Delivered);
    assert_eq!(second.attempts, 2);
    assert_eq!(rx.seen.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn backoff_doubles_between_consecutive_failures() {
    let (url, _rx) = receiver(&[500, 500, 200]).await;
    let d = dispatcher(&url, None, 5);
    enqueue(&d);

    d.deliver_next_at(&client(), T0).await.unwrap(); // fails, wait 10 s
    d.deliver_next_at(&client(), T0 + 10_000).await.unwrap(); // fails, wait 20 s
    assert!(d.deliver_next_at(&client(), T0 + 29_999).await.is_none());
    let done = d.deliver_next_at(&client(), T0 + 30_000).await.unwrap();
    assert_eq!(done.status, DeliveryStatus::Delivered);
}

#[tokio::test]
async fn a_delivery_is_abandoned_once_retries_are_exhausted() {
    let (url, rx) = receiver(&[500, 500, 500, 500]).await;
    let d = dispatcher(&url, None, 1);
    enqueue(&d);

    d.deliver_next_at(&client(), T0).await.unwrap();
    let last = d.deliver_next_at(&client(), T0 + 10_000).await.unwrap();
    assert_eq!(last.status, DeliveryStatus::Abandoned);
    assert_eq!(d.pending_count(), 0);
    assert!(d.deliver_next_at(&client(), T0 + 1_000_000).await.is_none());
    assert_eq!(rx.seen.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let (elsewhere, hits) = receiver(&[]).await;
    let target = elsewhere.clone();
    let app = Router::new().route(
        "/hook",
        post(move || {
            let target = target.clone();
            async move { (StatusCode::TEMPORARY_REDIRECT, [("location", target)]) }
        }),
    );
    let url = format!("{}/hook", serve(app).await);
    let d = dispatcher(&url, None, 3);
    enqueue(&d);

    let record = d.deliver_next_at(&client(), T0).await.unwrap();
    assert_eq!(record.status, DeliveryStatus::Failed);
    assert_eq!(record.last_status_code, Some(307));
    assert!(
        hits.seen.lock().unwrap().is_empty(),
        "redirect target was contacted"
    );
}

#[tokio::test]
async fn transport_errors_are_recorded_without_leaking_the_url() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let url = format!("http://{addr}/hook?token=SUPERSECRET");
    let d = dispatcher(&url, None, 3);
    enqueue(&d);

    let record = d.deliver_next_at(&client(), T0).await.unwrap();
    assert_eq!(record.status, DeliveryStatus::Failed);
    assert_eq!(record.last_status_code, None);
    let error = record.last_error.unwrap();
    assert!(!error.contains("SUPERSECRET"), "{error}");
    assert!(!error.contains(&addr.to_string()), "{error}");
}

#[tokio::test]
async fn deliveries_go_out_oldest_first_and_only_due_ones() {
    let (url, rx) = receiver(&[500]).await;
    let d = dispatcher(&url, None, 3);
    let a = enqueue(&d);
    let b = enqueue(&d);

    // First call fails `a`; `b` is still never-attempted, so it is next.
    assert_eq!(
        d.deliver_next_at(&client(), T0).await.unwrap().delivery_id,
        a
    );
    assert_eq!(
        d.deliver_next_at(&client(), T0).await.unwrap().delivery_id,
        b
    );
    // Nothing else is due until `a` has backed off.
    assert!(d.deliver_next_at(&client(), T0 + 1).await.is_none());
    assert_eq!(rx.seen.lock().unwrap().len(), 2);
    assert_eq!(d.next_due(T0 + 10_000).unwrap().delivery_id, a);
}
