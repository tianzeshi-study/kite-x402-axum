//! Integration tests for the sliding-window rate limiter.

use kite_x402_axum::sliding_limiter::{SlidingWindowConfig, SlidingWindowLimiter};
use std::time::Duration;

#[test]
fn test_sliding_window_allows_under_limit() {
    let limiter = SlidingWindowLimiter::new(SlidingWindowConfig {
        max_requests: 3,
        window_duration: Duration::from_secs(10),
    });

    assert!(limiter.check_and_record("client_1").is_ok());
    assert!(limiter.check_and_record("client_1").is_ok());
    let remaining = limiter.check_and_record("client_1").unwrap();
    assert_eq!(remaining, 0);

    // 4th request rejected
    assert!(limiter.check_and_record("client_1").is_err());
    // different client allowed
    assert!(limiter.check_and_record("client_2").is_ok());
}

#[test]
fn test_sliding_window_reset() {
    let limiter = SlidingWindowLimiter::new(SlidingWindowConfig {
        max_requests: 1,
        window_duration: Duration::from_secs(10),
    });

    assert!(limiter.check_and_record("client_reset").is_ok());
    assert!(limiter.check_and_record("client_reset").is_err());

    limiter.reset("client_reset");
    assert!(limiter.check_and_record("client_reset").is_ok());
}
