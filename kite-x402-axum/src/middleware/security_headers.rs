use axum::{
    http::{HeaderMap, HeaderValue},
    middleware::Next,
    response::Response,
};

pub struct SecurityHeadersPolicy {
    pub hsts_enabled: bool,
    pub frame_options: &'static str,
    pub content_type_options: &'static str,
}

impl Default for SecurityHeadersPolicy {
    fn default() -> Self {
        Self {
            hsts_enabled: true,
            frame_options: "DENY",
            content_type_options: "nosniff",
        }
    }
}

pub fn apply_security_headers(headers: &mut HeaderMap, policy: &SecurityHeadersPolicy) {
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static(policy.content_type_options),
    );
    headers.insert(
        "x-frame-options",
        HeaderValue::from_static(policy.frame_options),
    );
    headers.insert(
        "referrer-policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    if policy.hsts_enabled {
        headers.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
}
