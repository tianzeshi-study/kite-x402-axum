//! A minimal reverse proxy for paid requests: strips the `/v1` prefix,
//! drops the buyer's payment headers (`PAYMENT-SIGNATURE` / legacy
//! `X-PAYMENT`), injects an upstream credential if configured, and forwards
//! everything else to `UPSTREAM_URL` as-is.

use std::sync::Arc;

use axum::{
    body::{to_bytes, Body},
    extract::{NestedPath, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

/// Request headers that must never be blindly forwarded between hops.
/// Matches the Express template's `HOP_BY_HOP` set.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "host",
    "content-length",
];

/// Request headers that carry the buyer's signed payment authorization. The
/// gate accepts both (`X-PAYMENT` is the legacy x402 v1 name), so the proxy
/// must drop both: the upstream API has no business seeing a payment payload.
const PAYMENT_HEADERS: &[&str] = &["payment-signature", "x-payment"];

/// Maximum number of same-origin redirects [`same_origin_redirect_policy`]
/// will follow.
const MAX_REDIRECTS: usize = 10;

/// Cap on how much of the incoming request body the proxy will buffer
/// before forwarding it upstream (16 MiB). Large uploads are rare for a
/// metered API wrapper; this bound exists so a misbehaving client can't
/// exhaust memory.
const MAX_REQUEST_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Configuration for forwarding a paid request to the wrapped API.
#[derive(Clone)]
pub struct UpstreamConfig {
    /// HTTP client used to call the upstream.
    ///
    /// Build it with `.redirect(`[`same_origin_redirect_policy()`]`)`: reqwest
    /// only strips the standard `Authorization` / `Cookie` headers when a
    /// redirect leaves the host, so with its default policy a custom
    /// credential header (`UPSTREAM_AUTH_HEADER=X-Api-Key`) would be sent to
    /// whatever host the upstream redirects to.
    pub http: reqwest::Client,
    /// Upstream origin with no trailing slash, e.g. `https://api.example.com`.
    pub base_url: String,
    /// Header to inject with `auth_value`, e.g. `Authorization`.
    pub auth_header: String,
    /// Credential value injected upstream and never forwarded to the buyer.
    /// Empty means "inject nothing".
    pub auth_value: String,
}

impl std::fmt::Debug for UpstreamConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamConfig")
            .field("base_url", &self.base_url)
            .field("auth_header", &self.auth_header)
            .field(
                "auth_value",
                &if self.auth_value.is_empty() {
                    "[empty]"
                } else {
                    "[redacted]"
                },
            )
            .finish()
    }
}

/// A redirect policy that is safe to use together with an injected upstream
/// credential: it follows redirects that stay on the same origin (e.g. a
/// trailing-slash redirect, or an `http` → `https` upgrade of the same host)
/// and stops at any other. When it stops, the upstream's `3xx` response is
/// handed back to the buyer unchanged, so the credential never leaves the
/// host it was configured for.
pub fn same_origin_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS {
            return attempt.error("too many redirects");
        }
        let follow = attempt
            .previous()
            .last()
            .is_some_and(|from| is_same_origin_hop(from, attempt.url()));
        if follow {
            attempt.follow()
        } else {
            attempt.stop()
        }
    })
}

/// `true` if a redirect from `from` to `to` keeps the request on the same
/// origin (scheme, host and port), or merely upgrades `http` to `https` on
/// the same host. Never true for a downgrade or for a different host/port.
fn is_same_origin_hop(from: &reqwest::Url, to: &reqwest::Url) -> bool {
    if from.host_str() != to.host_str() {
        return false;
    }
    let upgrade = from.scheme() == "http" && to.scheme() == "https";
    let same_origin =
        from.scheme() == to.scheme() && from.port_or_known_default() == to.port_or_known_default();
    same_origin || upgrade
}

/// Strips one leading `/v1` path segment from `path_and_query`, but only
/// when it really is a whole segment (`/v1`, `/v1/..`, `/v1?..`) — never
/// from `/v1beta/..` or `/v10`.
fn strip_v1_prefix(path_and_query: &str) -> &str {
    match path_and_query.strip_prefix("/v1") {
        Some(rest) if rest.is_empty() || rest.starts_with(['/', '?']) => rest,
        _ => path_and_query,
    }
}

/// `true` if the path (query string excluded) has a `.` or `..` segment,
/// including percent-encoded (`%2e`) and backslash-separated forms, which
/// URL parsers normalize just like the plain ones.
///
/// Such a path would be resolved *after* it was appended to `base_url`, so
/// `/v1/../admin` could climb out of an upstream base path like
/// `https://host/public` — with the injected credential attached.
fn has_dot_segment(path_and_query: &str) -> bool {
    let path = path_and_query.split('?').next().unwrap_or_default();
    path.split(['/', '\\']).any(|segment| {
        let decoded = segment.replace("%2e", ".").replace("%2E", ".");
        decoded == "." || decoded == ".."
    })
}

/// Reverse-proxies a request to `cfg.base_url`, without the `/v1` prefix the
/// route matched under. Use as the handler behind the `/v1/{*path}` route,
/// inside the group guarded by [`crate::middleware::x402_payment`].
///
/// The prefix is removed exactly once, whichever way the route is mounted:
///
/// - **Nested** (`Router::nest("/v1", ..)`, as in `service/`): axum has
///   already removed the prefix before the handler runs, so the path is
///   forwarded as it arrives. (`/v1/v1/orders` reaches the upstream as
///   `/v1/orders`.)
/// - **Not nested** (`.route("/v1/{*path}", ..)` or `.route("/{*path}", ..)`):
///   one leading `/v1` segment is stripped here.
///
/// Requests whose path contains a `.` / `..` segment (also when written
/// `%2e` / `%2E`) are rejected with `400`: they would otherwise be resolved
/// after being appended to `base_url` and could leave the upstream's base
/// path. A `400` is never settled by the payment gate, so the buyer is not
/// charged for it.
pub async fn proxy(State(cfg): State<Arc<UpstreamConfig>>, req: Request) -> Response {
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();

    if has_dot_segment(&path_and_query) {
        tracing::warn!(path = %path_and_query, "Rejected request with dot segments in the path");
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({ "error": "invalid request path" })),
        )
            .into_response();
    }

    // `Router::nest` records the prefix it stripped as `NestedPath`; its
    // presence means the `/v1` is already gone from `req.uri()`.
    let already_stripped = req.extensions().get::<NestedPath>().is_some();
    let forwarded = if already_stripped {
        path_and_query.as_str()
    } else {
        strip_v1_prefix(&path_and_query)
    };
    let forwarded = if forwarded.starts_with('/') {
        forwarded.to_string()
    } else {
        format!("/{forwarded}")
    };

    let url = format!("{}{}", cfg.base_url, forwarded);

    tracing::debug!(
        original_path = %path_and_query,
        forwarded_url = %url,
        "Proxying request to upstream"
    );

    let (parts, body) = req.into_parts();
    let body_bytes = match to_bytes(body, MAX_REQUEST_BODY_BYTES).await {
        Ok(b) => b,
        Err(err) => {
            tracing::warn!(
                max_bytes = MAX_REQUEST_BODY_BYTES,
                error = %err,
                "Request body too large to proxy"
            );
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                axum::Json(json!({ "error": "request body too large to proxy" })),
            )
                .into_response();
        }
    };

    // Method/header conversion goes through `.as_str()` / byte parsing
    // rather than assuming axum's and reqwest's `http` crate versions are
    // identical types — cheap, and robust to either crate bumping independently.
    let method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())
        .unwrap_or(reqwest::Method::GET);

    let mut out_headers = reqwest::header::HeaderMap::new();
    for (name, value) in parts.headers.iter() {
        let lower = name.as_str().to_ascii_lowercase();
        if HOP_BY_HOP.contains(&lower.as_str()) || PAYMENT_HEADERS.contains(&lower.as_str()) {
            continue;
        }
        if let (Ok(hn), Ok(hv)) = (
            reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()),
            reqwest::header::HeaderValue::from_bytes(value.as_bytes()),
        ) {
            out_headers.append(hn, hv);
        }
    }
    if !cfg.auth_value.is_empty() {
        if let (Ok(hn), Ok(hv)) = (
            reqwest::header::HeaderName::from_bytes(cfg.auth_header.as_bytes()),
            reqwest::header::HeaderValue::from_str(&cfg.auth_value),
        ) {
            out_headers.insert(hn, hv);
            tracing::trace!(auth_header = %cfg.auth_header, "Injected upstream auth header");
        }
    }

    tracing::debug!(
        method = %method,
        url = %url,
        body_len = body_bytes.len(),
        "Dispatching request to upstream API"
    );

    let upstream_response = cfg
        .http
        .request(method, &url)
        .headers(out_headers)
        .body(body_bytes)
        .send()
        .await;

    let upstream_response = match upstream_response {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(
                url = %url,
                error = %e,
                "Upstream API request failed (unreachable or timed out)"
            );
            // >= 400, so the payment middleware will not settle this call.
            return (
                StatusCode::BAD_GATEWAY,
                axum::Json(json!({ "error": "upstream unreachable", "detail": e.to_string() })),
            )
                .into_response();
        }
    };

    let status = StatusCode::from_u16(upstream_response.status().as_u16())
        .unwrap_or(StatusCode::BAD_GATEWAY);

    tracing::debug!(
        url = %url,
        status = status.as_u16(),
        "Received response from upstream API"
    );

    // `content-encoding` is deliberately passed through: the body below is
    // streamed exactly as received (the client is not expected to decompress),
    // so the header is the only thing telling the buyer how to decode it.
    let mut builder = Response::builder().status(status);
    for (name, value) in upstream_response.headers().iter() {
        let lower = name.as_str().to_ascii_lowercase();
        if HOP_BY_HOP.contains(&lower.as_str()) {
            continue;
        }
        if let (Ok(hn), Ok(hv)) = (
            axum::http::HeaderName::from_bytes(name.as_str().as_bytes()),
            axum::http::HeaderValue::from_bytes(value.as_bytes()),
        ) {
            builder = builder.header(hn, hv);
        }
    }

    let stream = upstream_response.bytes_stream();
    builder
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
}

#[cfg(test)]
mod tests {
    //! Unit tests for `proxy` that need no network: the request never leaves
    //! the process when the upstream is a refused port, so we can check the
    //! early-return branches, the `Debug` redaction and the constants.
    //! Forwarding behaviour against a live upstream is in
    //! `tests/proxy_forwarding.rs`.

    use super::*;
    use axum::{body::Body, routing::any, Router};
    use tower::ServiceExt;

    fn cfg(auth_value: &str) -> UpstreamConfig {
        UpstreamConfig {
            http: reqwest::Client::new(),
            base_url: "http://127.0.0.1:1".to_string(), // nothing listens here
            auth_header: "X-Api-Key".to_string(),
            auth_value: auth_value.to_string(),
        }
    }

    fn app(cfg: UpstreamConfig) -> Router {
        Router::new()
            .route("/{*path}", any(proxy))
            .with_state(Arc::new(cfg))
    }

    #[test]
    fn hop_by_hop_list_is_lowercase_and_complete() {
        for h in [
            "connection",
            "keep-alive",
            "transfer-encoding",
            "te",
            "trailer",
            "upgrade",
            "host",
            "content-length",
        ] {
            assert!(HOP_BY_HOP.contains(&h), "{h}");
        }
        assert!(HOP_BY_HOP.iter().all(|h| *h == h.to_ascii_lowercase()));
    }

    #[test]
    fn payment_headers_cover_the_current_and_the_legacy_name() {
        assert_eq!(PAYMENT_HEADERS, ["payment-signature", "x-payment"]);
        assert!(PAYMENT_HEADERS.iter().all(|h| *h == h.to_ascii_lowercase()));
    }

    #[test]
    fn strip_v1_prefix_removes_only_a_whole_leading_segment() {
        for (input, expected) in [
            ("/v1/orders", "/orders"),
            ("/v1/orders?a=1", "/orders?a=1"),
            ("/v1/v1/orders", "/v1/orders"),
            ("/v1", ""),
            ("/v1?a=1", "?a=1"),
            ("/v1beta/orders", "/v1beta/orders"),
            ("/v10", "/v10"),
            ("/orders/v1", "/orders/v1"),
            ("/", "/"),
        ] {
            assert_eq!(strip_v1_prefix(input), expected, "{input}");
        }
    }

    #[test]
    fn dot_segments_are_detected_in_every_spelling() {
        for bad in [
            "/..",
            "/.",
            "/a/../b",
            "/a/./b",
            "/a/..",
            "/%2e%2e/x",
            "/%2E%2E/x",
            "/.%2e/x",
            "/%2e./x",
            "/%2e/x",
            "/a\\..\\b",
            "/..?q=1",
            "/a/%2e%2E/b",
        ] {
            assert!(has_dot_segment(bad), "{bad}");
        }
        for ok in [
            "/",
            "/a/b",
            "/a.b",
            "/a..b",
            "/...",
            "/.hidden",
            "/file.json",
            "/x?next=../y",
            "/x?a=%2e%2e",
            "/a%2fb",
            "/..a",
            "/a..",
        ] {
            assert!(!has_dot_segment(ok), "{ok}");
        }
    }

    #[test]
    fn redirect_hops_stay_on_the_same_origin() {
        let u = |s: &str| reqwest::Url::parse(s).unwrap();
        // same origin
        assert!(is_same_origin_hop(
            &u("https://api.example.com/a"),
            &u("https://api.example.com/b?x=1")
        ));
        assert!(is_same_origin_hop(
            &u("http://127.0.0.1:8080/a"),
            &u("http://127.0.0.1:8080/b")
        ));
        // an upgrade of the same host is fine, whatever the ports
        assert!(is_same_origin_hop(
            &u("http://api.example.com/a"),
            &u("https://api.example.com/a")
        ));
        // everything else is a different origin
        assert!(!is_same_origin_hop(
            &u("https://api.example.com/a"),
            &u("http://api.example.com/a")
        )); // downgrade
        assert!(!is_same_origin_hop(
            &u("https://api.example.com/a"),
            &u("https://evil.example.net/a")
        ));
        assert!(!is_same_origin_hop(
            &u("https://api.example.com/a"),
            &u("https://api.example.com.evil.net/a")
        ));
        assert!(!is_same_origin_hop(
            &u("https://api.example.com/a"),
            &u("https://sub.api.example.com/a")
        ));
        assert!(!is_same_origin_hop(
            &u("http://127.0.0.1:8080/a"),
            &u("http://127.0.0.1:9090/a")
        ));
    }

    #[test]
    fn request_body_cap_is_sixteen_mebibytes() {
        assert_eq!(MAX_REQUEST_BODY_BYTES, 16 * 1024 * 1024);
    }

    #[test]
    fn debug_never_prints_the_credential() {
        let dbg = format!("{:?}", cfg("s3cr3t-value"));
        assert!(!dbg.contains("s3cr3t-value"));
        assert!(
            dbg.contains("[redacted]") && dbg.contains("X-Api-Key") && dbg.contains("127.0.0.1:1")
        );
        assert!(format!("{:?}", cfg("")).contains("[empty]"));
    }

    #[test]
    fn config_is_cloneable() {
        let c = cfg("v");
        let d = c.clone();
        assert_eq!(
            (d.base_url, d.auth_header, d.auth_value),
            (c.base_url, c.auth_header, c.auth_value)
        );
    }

    #[tokio::test]
    async fn refused_upstream_is_a_502_with_error_and_detail() {
        let resp = app(cfg(""))
            .oneshot(
                axum::http::Request::get("/v1/x")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap();
        assert_eq!(body["error"], "upstream unreachable");
        assert!(body["detail"].is_string());
    }

    #[tokio::test]
    async fn oversized_body_is_rejected_with_413_before_any_upstream_call() {
        // A refused upstream would give 502; getting 413 proves the body cap
        // is enforced first.
        let req = axum::http::Request::post("/v1/x")
            .body(Body::from(vec![0u8; MAX_REQUEST_BODY_BYTES + 1]))
            .unwrap();
        let resp = app(cfg("")).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn unknown_methods_do_not_panic() {
        let req = axum::http::Request::builder()
            .method("PURGE")
            .uri("/v1/x")
            .body(Body::empty())
            .unwrap();
        let resp = app(cfg("")).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY); // reached the (refused) upstream
    }
}
