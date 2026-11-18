//! Hardened HTTP security response headers for x402 payment APIs.
//!
//! Applies defense-in-depth protection including anti-MIME sniffing, clickjacking
//! mitigation, and strict cache prevention on sensitive payment signatures and receipt tokens.

use axum::http::{header, HeaderMap, HeaderValue};

/// Configuration options for HTTP security response headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityHeadersConfig {
    /// Applies `X-Content-Type-Options: nosniff`.
    pub content_type_options: bool,
    /// Value for `X-Frame-Options` (e.g. `Some("DENY")` or `Some("SAMEORIGIN")`).
    pub frame_options: Option<String>,
    /// Value for `X-XSS-Protection` (e.g. `Some("0")`).
    pub xss_protection: Option<String>,
    /// Value for `Referrer-Policy` (e.g. `Some("no-referrer")`).
    pub referrer_policy: Option<String>,
    /// Max age in seconds for `Strict-Transport-Security`.
    pub hsts_max_age_secs: Option<u64>,
    /// Injects `Cache-Control: no-store` on paid or 402 responses.
    pub prevent_receipt_caching: bool,
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self {
            content_type_options: true,
            frame_options: Some("DENY".to_owned()),
            xss_protection: Some("0".to_owned()),
            referrer_policy: Some("no-referrer".to_owned()),
            hsts_max_age_secs: Some(31_536_000), // 1 year
            prevent_receipt_caching: true,
        }
    }
}

impl SecurityHeadersConfig {
    /// Injects configured security headers into an outgoing HTTP header map.
    pub fn apply(&self, headers: &mut HeaderMap) {
        if self.content_type_options {
            headers.insert(
                header::HeaderName::from_static("x-content-type-options"),
                HeaderValue::from_static("nosniff"),
            );
        }

        if let Some(ref val) = self.frame_options {
            if let Ok(hv) = HeaderValue::from_str(val) {
                headers.insert(header::HeaderName::from_static("x-frame-options"), hv);
            }
        }

        if let Some(ref val) = self.xss_protection {
            if let Ok(hv) = HeaderValue::from_str(val) {
                headers.insert(header::HeaderName::from_static("x-xss-protection"), hv);
            }
        }

        if let Some(ref val) = self.referrer_policy {
            if let Ok(hv) = HeaderValue::from_str(val) {
                headers.insert(header::REFERRER_POLICY, hv);
            }
        }

        if let Some(max_age) = self.hsts_max_age_secs {
            let val = format!("max-age={max_age}; includeSubDomains");
            if let Ok(hv) = HeaderValue::from_str(&val) {
                headers.insert(header::STRICT_TRANSPORT_SECURITY, hv);
            }
        }

        if self.prevent_receipt_caching {
            headers.insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("no-store, no-cache, must-revalidate"),
            );
            headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
        }
    }
}
