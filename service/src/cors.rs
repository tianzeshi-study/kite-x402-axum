//! Configurable Cross-Origin Resource Sharing (CORS) middleware for browser callers.
//!
//! Enables browser-based agents, sandboxes, and web frontends to call the x402
//! payment gate and read payment challenges (`PAYMENT-REQUIRED`) and receipts
//! (`PAYMENT-RESPONSE`).
//!
//! Configured via `CORS_ORIGIN`:
//! - Unset or empty: CORS is disabled (default).
//! - `*`: Allows all origins.
//! - Comma-separated list (e.g. `https://app.example.com,http://localhost:3000`):
//!   Matches against the incoming `Origin` header and reflects the matched origin.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

/// CORS configuration for the service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CorsConfig {
    /// CORS disabled (default).
    Disabled,
    /// Allow any origin (`*`).
    Wildcard,
    /// Allow a specific set of origins.
    Origins(Vec<String>),
}

impl CorsConfig {
    /// Parse `CORS_ORIGIN` environment variable into a [`CorsConfig`].
    pub(crate) fn from_env(value: Option<&str>) -> Self {
        let val = match value {
            Some(v) if !v.trim().is_empty() => v.trim(),
            _ => return Self::Disabled,
        };

        if val == "*" {
            Self::Wildcard
        } else {
            let origins: Vec<String> = val
                .split(',')
                .map(|s| s.trim().trim_end_matches('/').to_owned())
                .filter(|s| !s.is_empty())
                .collect();
            if origins.is_empty() {
                Self::Disabled
            } else {
                Self::Origins(origins)
            }
        }
    }

    /// Check if the incoming request origin is allowed.
    pub(crate) fn match_origin(&self, origin: &str) -> Option<String> {
        match self {
            Self::Disabled => None,
            Self::Wildcard => Some("*".to_owned()),
            Self::Origins(allowed) => {
                let trimmed = origin.trim_end_matches('/');
                if allowed.iter().any(|o| o == trimmed) {
                    Some(origin.to_owned())
                } else {
                    None
                }
            }
        }
    }

    /// Whether CORS is enabled.
    pub(crate) fn is_enabled(&self) -> bool {
        !matches!(self, Self::Disabled)
    }
}

fn vary_origin(headers: &mut HeaderMap) {
    let present = headers.get_all(header::VARY).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value.split(',').any(|token| {
                let token = token.trim();
                token == "*" || token.eq_ignore_ascii_case("origin")
            })
        })
    });
    if !present {
        headers.append(header::VARY, HeaderValue::from_static("Origin"));
    }
}

/// Axum middleware for handling CORS preflights and attaching access control headers.
pub(crate) async fn cors_middleware(
    State(cors): State<Arc<CorsConfig>>,
    req: Request,
    next: Next,
) -> Response {
    if !cors.is_enabled() {
        return next.run(req).await;
    }

    let origin_header = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned());

    let is_options = req.method() == Method::OPTIONS;
    let matched_origin = origin_header.as_deref().and_then(|o| cors.match_origin(o));

    // Handle browser CORS preflight requests (OPTIONS with Origin header)
    if is_options && origin_header.is_some() {
        let mut response = StatusCode::NO_CONTENT.into_response();
        if matches!(cors.as_ref(), CorsConfig::Origins(_)) {
            vary_origin(response.headers_mut());
        }
        if let Some(ref origin) = matched_origin {
            let headers = response.headers_mut();
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_ORIGIN,
                HeaderValue::from_str(origin).unwrap_or_else(|_| HeaderValue::from_static("*")),
            );
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_METHODS,
                HeaderValue::from_static("GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS"),
            );
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                HeaderValue::from_static(
                    "Content-Type, Authorization, Payment-Signature, X-Payment, X-Requested-With, X-Request-ID",
                ),
            );
            headers.insert(
                header::ACCESS_CONTROL_MAX_AGE,
                HeaderValue::from_static("86400"),
            );
        }
        return response;
    }

    let mut response = next.run(req).await;
    // A cache must distinguish allowed, denied and absent Origin requests.
    if matches!(cors.as_ref(), CorsConfig::Origins(_)) {
        vary_origin(response.headers_mut());
    }

    // Attach CORS response headers if origin is permitted
    if let Some(ref origin) = matched_origin {
        let headers = response.headers_mut();
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_str(origin).unwrap_or_else(|_| HeaderValue::from_static("*")),
        );
        headers.insert(
            header::ACCESS_CONTROL_EXPOSE_HEADERS,
            HeaderValue::from_static(
                "Payment-Required, Payment-Response, X-Payment, Payment-Signature, Retry-After, X-Request-ID",
            ),
        );
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserve_and_deduplicate_existing_variation() {
        for existing in ["Accept-Encoding", "Accept-Encoding, oRiGiN", "*"] {
            let mut headers = HeaderMap::new();
            headers.append(header::VARY, HeaderValue::from_str(existing).unwrap());
            vary_origin(&mut headers);
            vary_origin(&mut headers);
            let values: Vec<_> = headers.get_all(header::VARY).iter().collect();
            assert_eq!(values[0], existing);
            assert_eq!(
                values.len(),
                if existing == "Accept-Encoding" { 2 } else { 1 }
            );
        }
    }

    #[tokio::test]
    async fn variation_is_preserved_for_allowed_denied_and_absent_origins() {
        for origin in [
            Some("https://app.example.com"),
            Some("https://denied.example"),
            None,
        ] {
            let cfg = Arc::new(CorsConfig::Origins(vec!["https://app.example.com".into()]));
            let app = Router::new()
                .route(
                    "/",
                    get(|| async { ([(header::VARY, "Accept-Encoding")], "ok") }),
                )
                .layer(axum_mw::from_fn_with_state(cfg, cors_middleware));
            let mut req = Request::builder().uri("/");
            if let Some(origin) = origin {
                req = req.header(header::ORIGIN, origin);
            }
            let res = app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
            let values: Vec<_> = res
                .headers()
                .get_all(header::VARY)
                .iter()
                .map(|v| v.to_str().unwrap())
                .collect();
            assert_eq!(values, ["Accept-Encoding", "Origin"]);
            assert_eq!(
                res.headers()
                    .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN),
                origin == Some("https://app.example.com")
            );
        }
    }

    #[test]
    fn parse_disabled() {
        assert_eq!(CorsConfig::from_env(None), CorsConfig::Disabled);
        assert_eq!(CorsConfig::from_env(Some("")), CorsConfig::Disabled);
        assert_eq!(CorsConfig::from_env(Some("   ")), CorsConfig::Disabled);
    }

    #[test]
    fn parse_wildcard() {
        assert_eq!(CorsConfig::from_env(Some("*")), CorsConfig::Wildcard);
        assert_eq!(CorsConfig::from_env(Some("  *  ")), CorsConfig::Wildcard);
    }

    #[test]
    fn parse_specific_origins() {
        let cfg = CorsConfig::from_env(Some(
            "https://app.example.com, http://localhost:3000/,  https://dashboard.io  ",
        ));
        assert_eq!(
            cfg,
            CorsConfig::Origins(vec![
                "https://app.example.com".into(),
                "http://localhost:3000".into(),
                "https://dashboard.io".into(),
            ])
        );
    }

    #[test]
    fn match_origin_rules() {
        let disabled = CorsConfig::Disabled;
        assert_eq!(disabled.match_origin("https://foo.com"), None);

        let wildcard = CorsConfig::Wildcard;
        assert_eq!(
            wildcard.match_origin("https://foo.com"),
            Some("*".to_owned())
        );

        let specific = CorsConfig::Origins(vec![
            "https://app.example.com".into(),
            "http://localhost:3000".into(),
        ]);
        assert_eq!(
            specific.match_origin("https://app.example.com"),
            Some("https://app.example.com".to_owned())
        );
        assert_eq!(
            specific.match_origin("http://localhost:3000/"),
            Some("http://localhost:3000/".to_owned())
        );
        assert_eq!(specific.match_origin("https://unauthorized.org"), None);
    }

    use axum::{body::Body, middleware as axum_mw, routing::get, Router};
    use tower::ServiceExt;

    #[tokio::test]
    async fn preflight_wildcard_returns_204_and_headers() {
        let cfg = Arc::new(CorsConfig::Wildcard);
        let app = Router::new()
            .route("/v1/data", get(|| async { "payload" }))
            .layer(axum_mw::from_fn_with_state(cfg, cors_middleware));

        let res = app
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/v1/data")
                    .header(header::ORIGIN, "https://client.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            res.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "*"
        );
        assert!(res
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_METHODS)
            .is_some());
        assert!(res
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
            .is_some());
        assert_eq!(
            res.headers().get(header::ACCESS_CONTROL_MAX_AGE).unwrap(),
            "86400"
        );
    }

    #[tokio::test]
    async fn preflight_specific_origin_returns_204_and_vary() {
        let cfg = Arc::new(CorsConfig::Origins(vec!["https://app.example.com".into()]));
        let app = Router::new()
            .route("/v1/data", get(|| async { "payload" }))
            .layer(axum_mw::from_fn_with_state(cfg, cors_middleware));

        let res = app
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/v1/data")
                    .header(header::ORIGIN, "https://app.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            res.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "https://app.example.com"
        );
        assert_eq!(res.headers().get(header::VARY).unwrap(), "Origin");
    }

    #[tokio::test]
    async fn preflight_unmatched_origin_does_not_set_allow_origin() {
        let cfg = Arc::new(CorsConfig::Origins(vec!["https://app.example.com".into()]));
        let app = Router::new()
            .route("/v1/data", get(|| async { "payload" }))
            .layer(axum_mw::from_fn_with_state(cfg, cors_middleware));

        let res = app
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/v1/data")
                    .header(header::ORIGIN, "https://evil.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        assert_eq!(res.headers().get(header::VARY).unwrap(), "Origin");
        assert!(res
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none());
    }

    #[tokio::test]
    async fn get_request_exposes_payment_headers() {
        let cfg = Arc::new(CorsConfig::Wildcard);
        let app = Router::new()
            .route("/v1/data", get(|| async { "ok" }))
            .layer(axum_mw::from_fn_with_state(cfg, cors_middleware));

        let res = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/v1/data")
                    .header(header::ORIGIN, "https://client.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "*"
        );
        let expose = res
            .headers()
            .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(expose.contains("Payment-Required"));
        assert!(expose.contains("Payment-Response"));
    }

    #[tokio::test]
    async fn request_without_origin_has_no_cors_headers() {
        let cfg = Arc::new(CorsConfig::Wildcard);
        let app = Router::new()
            .route("/v1/data", get(|| async { "ok" }))
            .layer(axum_mw::from_fn_with_state(cfg, cors_middleware));

        let res = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/v1/data")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        assert!(res
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none());
    }
}
