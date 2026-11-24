//! Integration tests for the CORS security guard.

use kite_x402_axum::cors_guard::{CorsGuardConfig, CorsSecurityGuard};

#[test]
fn test_cors_origin_allowlist() {
    let guard = CorsSecurityGuard::new(vec!["https://app.gokite.ai", "http://localhost:3000"]);

    assert!(guard.is_origin_allowed("https://app.gokite.ai"));
    assert!(guard.is_origin_allowed("http://localhost:3000"));
    assert!(!guard.is_origin_allowed("https://malicious-site.com"));

    let headers = guard.get_cors_headers("https://app.gokite.ai");
    assert!(headers.is_some());
}

/// The default config advertises `allow_credentials: true`. A browser sends
/// `Authorization` (the default x402 payment header) as a credentialed request,
/// and discards the response unless this header is present. Without it the
/// guard's own default promise is broken for every caller of `new()`.
#[test]
fn default_guard_emits_allow_credentials_header() {
    let guard = CorsSecurityGuard::new(vec!["https://app.gokite.ai"]);
    let headers = guard.get_cors_headers("https://app.gokite.ai").unwrap();

    let credentials = headers
        .iter()
        .find(|(name, _)| *name == "Access-Control-Allow-Credentials")
        .map(|(_, value)| value.as_str());
    assert_eq!(
        credentials,
        Some("true"),
        "allow_credentials defaults to true, but the header was never emitted"
    );
}

/// The header must only be attached for origins that passed the allow-list —
/// otherwise a rejected origin would still learn that credentialed access is
/// configured, and an upstream that forgot to gate on `get_cors_headers`'s
/// `None` could leak it to anyone.
#[test]
fn headers_are_absent_for_a_rejected_origin() {
    let guard = CorsSecurityGuard::new(vec!["https://app.gokite.ai"]);
    assert!(guard.get_cors_headers("https://evil.example").is_none());
}

/// `with_config` is the only way to turn credentials off; before it existed
/// the public `allow_credentials` field could not be set to `false` at all.
#[test]
fn credentials_header_is_omitted_when_disabled() {
    let config = CorsGuardConfig {
        allowed_origins: ["https://app.gokite.ai".to_owned()].into_iter().collect(),
        allow_credentials: false,
        max_age_secs: 600,
    };
    let guard = CorsSecurityGuard::with_config(config);
    let headers = guard.get_cors_headers("https://app.gokite.ai").unwrap();

    assert!(
        headers
            .iter()
            .all(|(name, _)| *name != "Access-Control-Allow-Credentials"),
        "credentials were disabled in config"
    );
    // The rest of the policy must survive the new constructor unchanged.
    assert!(headers
        .iter()
        .any(|(name, value)| *name == "Access-Control-Max-Age" && value == "600"));
}

/// A wildcard allow-list must answer with a literal `*` and no
/// `Allow-Credentials`, even though `allow_credentials` defaults to `true`.
/// Echoing the caller's origin (the old behaviour) combined with the credentials
/// header let any site read authenticated responses, which is exactly what
/// browsers forbid for `*`.
#[test]
fn wildcard_does_not_reflect_origin_or_grant_credentials() {
    let guard = CorsSecurityGuard::new(vec!["*"]);
    let headers = guard.get_cors_headers("https://evil.example").unwrap();

    let allow_origin = headers
        .iter()
        .find(|(name, _)| *name == "Access-Control-Allow-Origin")
        .map(|(_, value)| value.as_str());
    assert_eq!(allow_origin, Some("*"));
    assert!(
        headers
            .iter()
            .all(|(_, value)| value != "https://evil.example"),
        "the wildcard must not echo the request origin"
    );
    assert!(
        headers
            .iter()
            .all(|(name, _)| *name != "Access-Control-Allow-Credentials"),
        "credentials cannot be combined with a wildcard origin"
    );
}

/// The same wildcard rule holds when credentials are configured explicitly.
#[test]
fn wildcard_stays_credentialless_with_explicit_config() {
    let config = CorsGuardConfig {
        allowed_origins: ["*".to_owned()].into_iter().collect(),
        allow_credentials: true,
        max_age_secs: 60,
    };
    let guard = CorsSecurityGuard::with_config(config);
    let headers = guard.get_cors_headers("https://app.gokite.ai").unwrap();

    assert_eq!(
        headers
            .iter()
            .find(|(name, _)| *name == "Access-Control-Allow-Origin")
            .map(|(_, value)| value.as_str()),
        Some("*")
    );
    assert!(headers
        .iter()
        .all(|(name, _)| *name != "Access-Control-Allow-Credentials"));
}
