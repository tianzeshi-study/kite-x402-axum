//! Public module integration and explicit telemetry semantics.
use kite_x402_axum::{
    middleware::{
        header_sanitizer::{HeaderSanitizer, HeaderSanitizerConfig},
        retry::RetryPolicy,
        zero_copy_decoder::ZeroCopySlice,
    },
    telemetry::{
        audit_trail::AuditTrailStore, pool_metrics::PoolMetrics, readiness_checker::ReadinessProbe,
        span_tracer::RequestSpan,
    },
};
use std::{net::IpAddr, time::Duration};

#[test]
fn borrowed_payload_and_reused_security_headers_are_public() {
    let bytes = b"payment";
    let view = ZeroCopySlice::new(bytes);
    assert_eq!(view.as_str().unwrap().as_ptr(), bytes.as_ptr());
    assert!(view.starts_with(b"pay"));
    assert!(!view.is_empty());
    assert_eq!(view.len(), bytes.len());
    assert!(ZeroCopySlice::new(&[255]).as_str().is_err());
    let mut headers = axum::http::HeaderMap::new();
    kite_x402_axum::middleware::security_headers::SecurityHeadersConfig::default()
        .apply(&mut headers);
    assert_eq!(
        headers["cache-control"],
        "no-store, no-cache, must-revalidate"
    );
    let _: Option<kite_x402_axum::middleware::circuit_breaker::CircuitBreaker> = None;
}

#[test]
fn forwarded_headers_require_an_explicit_trusted_peer() {
    let peer: IpAddr = "127.0.0.1".parse().unwrap();
    let config = HeaderSanitizerConfig::default();
    assert_eq!(
        HeaderSanitizer::resolve_client_ip(peer, Some("203.0.113.4"), None, &config),
        peer
    );
    let config = HeaderSanitizerConfig {
        trusted_proxies: vec![peer],
    };
    assert_eq!(
        HeaderSanitizer::resolve_client_ip(peer, Some("203.0.113.4"), None, &config),
        "203.0.113.4".parse::<IpAddr>().unwrap()
    );
}

#[test]
fn audit_snapshots_are_bounded_and_isolated() {
    let audit = AuditTrailStore::new(2);
    audit.append("one", "tx1", 1);
    audit.append("two", "tx2", 2);
    audit.append("three", "tx3", 3);
    let mut events = audit.snapshot();
    assert_eq!(
        events.iter().map(|e| e.timestamp_ms).collect::<Vec<_>>(),
        [2, 3]
    );
    events[0].event_type = "changed".to_owned();
    assert_eq!(audit.snapshot()[0].event_type, "two");
    let disabled = AuditTrailStore::new(0);
    disabled.append("one", "tx", 1);
    assert!(disabled.snapshot().is_empty());
}

#[test]
fn readiness_and_correlation_have_explicit_local_semantics() {
    for probe in [ReadinessProbe::new(), ReadinessProbe::default()] {
        assert!(!probe.is_ready());
        probe.set_rpc_status(true);
        assert!(!probe.is_ready());
        probe.set_facilitator_status(true);
        assert!(probe.is_ready());
    }
    let span = RequestSpan::new("GET", "/v1/test", Some("request-1".to_owned()));
    assert_eq!(span.correlation_id, "request-1");
    assert!(RequestSpan::new("GET", "/", None)
        .correlation_id
        .starts_with("trace-"));
}

#[tokio::test]
async fn pool_drain_is_bounded_and_empty_decrement_cannot_wrap() {
    let pool = PoolMetrics::new();
    pool.dec_active();
    assert_eq!(pool.snapshot().0, 0);
    assert!(pool.wait_for_drain(Duration::ZERO).await);
    pool.inc_active();
    assert!(!pool.wait_for_drain(Duration::from_millis(1)).await);
    pool.dec_active();
    assert!(pool.wait_for_drain(Duration::ZERO).await);
}

#[test]
fn retry_delay_calculation_stays_bounded_without_executing_an_operation() {
    let policy = RetryPolicy::new(4, Duration::from_millis(10), Duration::from_millis(25));
    for attempt in 0..10 {
        assert!(policy.calculate_backoff(attempt) <= policy.max_delay);
    }
    let zero = RetryPolicy::new(1, Duration::ZERO, Duration::ZERO);
    assert_eq!(zero.calculate_backoff(0), Duration::ZERO);
}
