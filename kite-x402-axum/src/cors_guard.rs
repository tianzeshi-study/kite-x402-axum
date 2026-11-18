//! CORS origin validation and security policy guard for Kite x402 Axum routes.

use std::collections::HashSet;

/// Configuration for the CORS security guard.
#[derive(Debug, Clone)]
pub struct CorsGuardConfig {
    /// Origins permitted to make cross-origin requests.
    pub allowed_origins: HashSet<String>,
    /// Whether credentials (cookies, authorization headers) are allowed.
    pub allow_credentials: bool,
    /// Value for `Access-Control-Max-Age`, in seconds.
    pub max_age_secs: u64,
}

impl Default for CorsGuardConfig {
    fn default() -> Self {
        Self {
            allowed_origins: HashSet::new(),
            allow_credentials: true,
            max_age_secs: 86400,
        }
    }
}

/// Origin allow-list guard that produces CORS response headers.
#[derive(Debug)]
pub struct CorsSecurityGuard {
    config: CorsGuardConfig,
}

impl CorsSecurityGuard {
    /// Creates a guard that allows exactly the given origins.
    #[must_use]
    pub fn new(allowed_origins: Vec<impl Into<String>>) -> Self {
        let mut origins = HashSet::new();
        for o in allowed_origins {
            origins.insert(o.into());
        }
        Self {
            config: CorsGuardConfig {
                allowed_origins: origins,
                ..Default::default()
            },
        }
    }

    /// Returns `true` if `origin` is on the allow-list.
    #[must_use]
    pub fn is_origin_allowed(&self, origin: &str) -> bool {
        if self.config.allowed_origins.contains("*") {
            return true;
        }
        self.config.allowed_origins.contains(origin)
    }

    /// Returns the CORS headers to attach for `origin`, or `None` if it is not allowed.
    #[must_use]
    pub fn get_cors_headers(&self, origin: &str) -> Option<Vec<(&'static str, String)>> {
        if !self.is_origin_allowed(origin) {
            return None;
        }

        Some(vec![
            ("Access-Control-Allow-Origin", origin.to_owned()),
            (
                "Access-Control-Allow-Methods",
                "GET, POST, OPTIONS".to_owned(),
            ),
            (
                "Access-Control-Allow-Headers",
                "Content-Type, Authorization, PAYMENT-SIGNATURE".to_owned(),
            ),
            (
                "Access-Control-Expose-Headers",
                "PAYMENT-REQUIRED, PAYMENT-RESPONSE".to_owned(),
            ),
            (
                "Access-Control-Max-Age",
                self.config.max_age_secs.to_string(),
            ),
        ])
    }
}
