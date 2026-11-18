//! Payment versions are validated locally for both supported header names.

mod common;

use axum::http::{header, StatusCode};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use common::*;
use kite_x402_axum::types::ResourceInfo;
use serde_json::json;

#[tokio::test]
async fn invalid_versions_are_rejected_before_any_downstream_call() {
    let mocks = Mocks::start().await;
    let app = mocks.app();
    let requirements = probe_requirements(&app, "/v1/forecast").await;

    let versions = [
        Some(json!(0)),
        Some(json!(1)),
        Some(json!(3)),
        Some(json!(u32::MAX)),
        None,
        Some(json!(null)),
        Some(json!("2")),
        Some(json!(2.5)),
        Some(json!(-1)),
        Some(json!(u64::from(u32::MAX) + 1)),
    ];
    for header_name in ["PAYMENT-SIGNATURE", "X-PAYMENT"] {
        for version in &versions {
            let mut payload = serde_json::to_value(payload_for(&requirements)).unwrap();
            let fields = payload.as_object_mut().unwrap();
            match version {
                Some(version) => {
                    fields.insert("x402Version".into(), version.clone());
                }
                None => {
                    fields.remove("x402Version");
                }
            }
            let encoded = STANDARD.encode(serde_json::to_vec(&payload).unwrap());
            let response = send(
                &app,
                req_with("GET", "/v1/forecast", &[(header_name, &encoded)], vec![]),
            )
            .await;

            assert_eq!(
                response.status(),
                StatusCode::PAYMENT_REQUIRED,
                "{header_name}: x402Version {version:?}"
            );
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert!(response.headers().get("PAYMENT-RESPONSE").is_none());
            let challenge = header_json(response.headers(), "PAYMENT-REQUIRED");
            assert_eq!(challenge["x402Version"], 2);
            assert_eq!(challenge["error"], "Invalid payment signature");
            assert_eq!(requirements_of(&response), requirements);
            assert_eq!(body_json(response).await, json!({}));
            assert_eq!(mocks.facilitator.verify_count(), 0);
            assert_eq!(mocks.upstream.count(), 0);
            assert_eq!(mocks.facilitator.settle_count(), 0);
            assert!(mocks.timeline().is_empty());
        }
    }
}

#[tokio::test]
async fn version_two_completes_payment_flow_with_either_header_name() {
    for header_name in ["PAYMENT-SIGNATURE", "X-PAYMENT"] {
        let mocks = Mocks::start().await;
        let app = mocks.app();
        let requirements = probe_requirements(&app, "/v1/forecast").await;
        let mut payload = payload_for(&requirements);
        payload.resource = Some(ResourceInfo {
            url: "/v1/forecast".into(),
            description: Some("Weather forecast".into()),
            mime_type: Some("application/json".into()),
        });
        payload.extensions = Some(json!({ "client": { "version": 1 } }));
        let encoded = encode_payload(&payload);
        let response = send(
            &app,
            req_with("GET", "/v1/forecast", &[(header_name, &encoded)], vec![]),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK, "{header_name}");
        let receipt = header_json(response.headers(), "PAYMENT-RESPONSE");
        assert_eq!(receipt["success"], true);
        assert_eq!(receipt["transaction"], TX_HASH);
        assert_eq!(body_json(response).await, json!({ "upstream": true }));
        assert_eq!(mocks.facilitator.verify_count(), 1);
        assert_eq!(mocks.upstream.count(), 1);
        assert_eq!(mocks.facilitator.settle_count(), 1);
        assert_eq!(mocks.timeline(), vec!["verify", "upstream", "settle"]);
        let expected_payload = serde_json::to_value(&payload).unwrap();
        assert_eq!(
            mocks.facilitator.verify_requests.lock().unwrap()[0]["paymentPayload"],
            expected_payload
        );
        assert_eq!(
            mocks.facilitator.settle_requests.lock().unwrap()[0]["paymentPayload"],
            expected_payload
        );
    }
}

#[tokio::test]
async fn invalid_preferred_header_does_not_fall_back_to_valid_legacy_payment() {
    let mocks = Mocks::start().await;
    let app = mocks.app();
    let requirements = probe_requirements(&app, "/v1/forecast").await;
    let mut unsupported = payload_for(&requirements);
    unsupported.x402_version = 3;
    let preferred = encode_payload(&unsupported);
    let legacy = payment_header(&requirements);
    let response = send(
        &app,
        req_with(
            "GET",
            "/v1/forecast",
            &[("PAYMENT-SIGNATURE", &preferred), ("X-PAYMENT", &legacy)],
            vec![],
        ),
    )
    .await;

    assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    assert_eq!(
        header_json(response.headers(), "PAYMENT-REQUIRED")["error"],
        "Invalid payment signature"
    );
    assert!(mocks.timeline().is_empty());
}

#[tokio::test]
async fn valid_preferred_header_ignores_unsupported_legacy_payment() {
    let mocks = Mocks::start().await;
    let app = mocks.app();
    let requirements = probe_requirements(&app, "/v1/forecast").await;
    let preferred = payment_header(&requirements);
    let mut unsupported = payload_for(&requirements);
    unsupported.x402_version = 1;
    let legacy = encode_payload(&unsupported);
    let response = send(
        &app,
        req_with(
            "GET",
            "/v1/forecast",
            &[("PAYMENT-SIGNATURE", &preferred), ("X-PAYMENT", &legacy)],
            vec![],
        ),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        header_json(response.headers(), "PAYMENT-RESPONSE")["success"],
        true
    );
    assert_eq!(body_json(response).await, json!({ "upstream": true }));
    assert_eq!(mocks.timeline(), vec!["verify", "upstream", "settle"]);
}
