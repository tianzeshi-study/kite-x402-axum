//! Integration tests for the CORS security guard.

use kite_x402_axum::cors_guard::CorsSecurityGuard;

#[test]
fn test_cors_origin_allowlist() {
    let guard = CorsSecurityGuard::new(vec!["https://app.gokite.ai", "http://localhost:3000"]);

    assert!(guard.is_origin_allowed("https://app.gokite.ai"));
    assert!(guard.is_origin_allowed("http://localhost:3000"));
    assert!(!guard.is_origin_allowed("https://malicious-site.com"));

    let headers = guard.get_cors_headers("https://app.gokite.ai");
    assert!(headers.is_some());
}
