//! A minimal reverse proxy for paid requests: strips the `/v1` prefix,
//! drops the `PAYMENT-SIGNATURE` header, injects an upstream credential if
//! configured, and forwards everything else to `UPSTREAM_URL` as-is.

use std::sync::Arc;

use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
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

/// Cap on how much of the incoming request body the proxy will buffer
/// before forwarding it upstream (16 MiB). Large uploads are rare for a
/// metered API wrapper; this bound exists so a misbehaving client can't
/// exhaust memory.
const MAX_REQUEST_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Configuration for forwarding a paid request to the wrapped API.
#[derive(Clone)]
pub struct UpstreamConfig {
    /// HTTP client used to call the upstream.
    pub http: reqwest::Client,
    /// Upstream origin with no trailing slash, e.g. `https://api.example.com`.
    pub base_url: String,
    /// Header to inject with `auth_value`, e.g. `Authorization`.
    pub auth_header: String,
    /// Credential value injected upstream and never forwarded to the buyer.
    /// Empty means "inject nothing".
    pub auth_value: String,
}

/// Reverse-proxies a request to `cfg.base_url`, stripping the `/v1` prefix
/// the route matched under. Use as the handler behind the `/v1/{*path}`
/// route, inside the group guarded by [`crate::middleware::x402_payment`].
pub async fn proxy(State(cfg): State<Arc<UpstreamConfig>>, req: Request) -> Response {
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();

    let forwarded = path_and_query
        .strip_prefix("/v1")
        .unwrap_or(&path_and_query)
        .to_string();
    let forwarded = if forwarded.starts_with('/') {
        forwarded
    } else {
        format!("/{forwarded}")
    };

    let url = format!("{}{}", cfg.base_url, forwarded);

    let (parts, body) = req.into_parts();
    let body_bytes = match to_bytes(body, MAX_REQUEST_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => {
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
        if HOP_BY_HOP.contains(&lower.as_str()) || lower == "payment-signature" {
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
        }
    }

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
            // >= 400, so the payment middleware will not settle this call.
            return (
                StatusCode::BAD_GATEWAY,
                axum::Json(json!({ "error": "upstream unreachable", "detail": e.to_string() })),
            )
                .into_response();
        }
    };

    let status =
        StatusCode::from_u16(upstream_response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);

    let mut builder = Response::builder().status(status);
    for (name, value) in upstream_response.headers().iter() {
        let lower = name.as_str().to_ascii_lowercase();
        if HOP_BY_HOP.contains(&lower.as_str()) || lower == "content-encoding" {
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
