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
    /// Creates a guard that allows exactly the given origins, with the
    /// remaining settings at their defaults (`allow_credentials = true`).
    #[must_use]
    pub fn new(allowed_origins: Vec<impl Into<String>>) -> Self {
        let mut origins = HashSet::new();
        for o in allowed_origins {
            origins.insert(o.into());
        }
        Self::with_config(CorsGuardConfig {
            allowed_origins: origins,
            ..Default::default()
        })
    }

    /// Creates a guard from an explicit configuration.
    ///
    /// Use this when credentials must be disabled or the preflight max-age
    /// needs to change — [`Self::new`] can only produce the default values.
    #[must_use]
    pub fn with_config(config: CorsGuardConfig) -> Self {
        Self { config }
    }

    /// Returns `true` if `origin` is on the allow-list.
    #[must_use]
    pub fn is_origin_allowed(&self, origin: &str) -> bool {
        if self.config.allowed_origins.contains("*") {
            return true;
        }
        self.config.allowed_origins.contains(origin)
    }

    /// Whether the allow-list is the `*` wildcard.
    #[must_use]
    fn is_wildcard(&self) -> bool {
        self.config.allowed_origins.contains("*")
    }

    /// Returns the CORS headers to attach for `origin`, or `None` if it is not allowed.
    ///
    /// With the `*` wildcard the response carries a literal
    /// `Access-Control-Allow-Origin: *` and never `Access-Control-Allow-Credentials`,
    /// even when credentials are enabled in the config. Echoing the request
    /// origin back instead would let any site read credentialed responses
    /// (the browser accepts a specific origin together with
    /// `Allow-Credentials: true`), so the two settings cannot be combined.
    #[must_use]
    pub fn get_cors_headers(&self, origin: &str) -> Option<Vec<(&'static str, String)>> {
        if !self.is_origin_allowed(origin) {
            return None;
        }

        let wildcard = self.is_wildcard();
        let mut headers = vec![
            (
                "Access-Control-Allow-Origin",
                if wildcard {
                    "*".to_owned()
                } else {
                    origin.to_owned()
                },
            ),
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
        ];
        // Without this header the browser drops any response to a request
        // carrying `Authorization` — the default way an x402 client pays.
        // `allow_credentials` was previously never read, so the default
        // `true` was a promise the emitted headers did not keep.
        //
        // It is deliberately skipped for the wildcard: browsers reject
        // `*` plus credentials, and echoing the caller's origin instead turns
        // the wildcard into "any origin may read authenticated responses".
        if self.config.allow_credentials && !wildcard {
            headers.push(("Access-Control-Allow-Credentials", "true".to_owned()));
        }
        Some(headers)
    }
}
