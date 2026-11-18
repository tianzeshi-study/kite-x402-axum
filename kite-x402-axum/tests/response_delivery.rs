//! A successful status line alone must not authorize settlement.
mod common;

use common::*;
use std::{
    io::{Read, Write},
    net::TcpListener,
    time::Duration,
};

fn upstream(bytes: &'static [u8], hold: Duration) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = [0; 4096];
        let _ = socket.read(&mut request);
        let _ = socket.write_all(bytes);
        let _ = socket.flush();
        std::thread::sleep(hold);
    });
    format!("http://{address}")
}

#[tokio::test]
async fn truncated_and_stalled_success_bodies_are_not_settled() {
    for hold in [Duration::ZERO, Duration::from_millis(150)] {
        let mocks = Mocks::start().await;
        let url = upstream(
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\npartial",
            hold,
        );
        let options = AppOptions {
            upstream_client: Some(
                reqwest::Client::builder()
                    .timeout(Duration::from_millis(50))
                    .build()
                    .unwrap(),
            ),
            ..AppOptions::default()
        };
        let app = build_app(&mocks.facilitator_url, &url, &options);
        let response = pay_get(&app, "/v1/data").await;
        assert_eq!(response.status(), 502);
        assert_eq!(mocks.facilitator.verify_count(), 1);
        assert_eq!(mocks.facilitator.settle_count(), 0);
        assert!(!response.headers().contains_key("payment-response"));
    }
}

#[tokio::test]
async fn oversized_success_body_is_not_settled() {
    let mocks = Mocks::start().await;
    let mut reply = UpstreamReply::json(200);
    reply.body = vec![b'x'; 16 * 1024 * 1024 + 1];
    mocks.upstream.set_reply(reply);
    let app = build_app(
        &mocks.facilitator_url,
        &mocks.upstream_url,
        &AppOptions::default(),
    );
    assert_eq!(pay_get(&app, "/v1/data").await.status(), 502);
    assert_eq!(mocks.facilitator.settle_count(), 0);
}

#[tokio::test]
async fn complete_body_is_preserved_before_settlement() {
    let mocks = Mocks::start().await;
    let app = build_app(
        &mocks.facilitator_url,
        &mocks.upstream_url,
        &AppOptions::default(),
    );
    let response = pay_get(&app, "/v1/data").await;
    assert_eq!(response.status(), 200);
    assert_eq!(mocks.facilitator.settle_count(), 1);
    assert_eq!(body_bytes(response).await, br#"{"upstream":true}"#);
}
