//! Runnable example wrapper service, equivalent to `main.go` /
//! `src/index.ts` in the other two templates: reads configuration from the
//! environment, exposes a free `/healthz`, and protects `/v1/*` with the
//! x402 payment gate before proxying to `UPSTREAM_URL`.
//!
//! See `.env.example` for every variable this reads, and the top-level
//! README in this directory for how to run it.

use std::{env, sync::Arc, time::Duration};

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::{self, Next},
    response::Response,
    routing::any,
    Json, Router,
};
use kite_x402_axum::{
    facilitator::FacilitatorClient,
    kite::{kite_chain_by_name, FACILITATOR_URL},
    middleware::{x402_payment, PaymentConfig},
    proxy::{proxy, UpstreamConfig},
};
use serde_json::json;

#[tokio::main]
async fn main() {
    // Load .env file automatically if present (does not override existing env vars)
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    tracing::info!("Starting kite-x402 wrapper service");

    let port: u16 = env_or("PORT", "8402")
        .parse()
        .expect("PORT must be a number");

    let pay_to = env::var("PAY_TO").expect("PAY_TO is required (the wallet that receives payment)");
    let upstream_url = env::var("UPSTREAM_URL")
        .expect("UPSTREAM_URL is required (the API being wrapped)")
        .trim_end_matches('/')
        .to_string();
    let price_usd = env_or("PRICE_USD", "0.001");
    let network_name = env_or("KITE_NETWORK", "mainnet");
    let chain = kite_chain_by_name(&network_name)
        .unwrap_or_else(|e| panic!("invalid KITE_NETWORK={network_name:?}: {e}"));
    let facilitator_url = env_or("FACILITATOR_URL", FACILITATOR_URL);
    let description = env_or("SERVICE_DESCRIPTION", "Paid API access via Kite x402");
    let upstream_auth_header = env_or("UPSTREAM_AUTH_HEADER", "Authorization");
    let upstream_auth_value = env_or("UPSTREAM_AUTH_VALUE", "");

    tracing::info!(
        port = port,
        network = %network_name,
        chain_id = %chain.network,
        asset = %chain.asset_symbol,
        price_usd = %price_usd,
        pay_to = %pay_to,
        upstream_url = %upstream_url,
        facilitator_url = %facilitator_url,
        auth_injected = !upstream_auth_value.is_empty(),
        "Configured kite-x402 wrapper"
    );

    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("reqwest client");

    let payment_cfg = Arc::new(PaymentConfig {
        pay_to,
        chain,
        price_usd,
        description,
        facilitator: FacilitatorClient::new(facilitator_url),
    });
    let upstream_cfg = Arc::new(UpstreamConfig {
        http: http_client,
        base_url: upstream_url,
        auth_header: upstream_auth_header,
        auth_value: upstream_auth_value,
    });

    // Everything under /v1 is metered: verify before the handler runs,
    // proxy to the upstream, settle only on a < 400 response.
    let paid = Router::new()
        .route("/{*path}", any(proxy))
        .with_state(upstream_cfg)
        .layer(middleware::from_fn_with_state(payment_cfg, x402_payment));

    let app = Router::new()
        .route("/healthz", axum::routing::get(healthz))
        .nest("/v1", paid)
        .layer(middleware::from_fn(http_request_logger));

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .unwrap_or_else(|e| panic!("could not bind 0.0.0.0:{port}: {e}"));
    tracing::info!(
        port = port,
        network = %network_name,
        "kite-x402 wrapper listening on 0.0.0.0:{port} (network={network_name})"
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server error");

    tracing::info!("Server shut down gracefully");
}

async fn http_request_logger(req: Request, next: Next) -> Response {
    let start = std::time::Instant::now();
    let method = req.method().clone();
    let uri = req.uri().clone();

    tracing::debug!(
        method = %method,
        uri = %uri,
        headers = ?req.headers(),
        "--> Incoming HTTP request"
    );

    let response = next.run(req).await;

    let latency = start.elapsed();
    let status = response.status();

    if status.is_server_error() {
        tracing::error!(
            method = %method,
            uri = %uri,
            status = status.as_u16(),
            latency = ?latency,
            "<-- HTTP request failed (server error)"
        );
    } else if status == StatusCode::PAYMENT_REQUIRED {
        tracing::info!(
            method = %method,
            uri = %uri,
            status = status.as_u16(),
            latency = ?latency,
            "<-- HTTP request requires payment (402 challenge issued)"
        );
    } else if status.is_client_error() {
        tracing::warn!(
            method = %method,
            uri = %uri,
            status = status.as_u16(),
            latency = ?latency,
            "<-- HTTP request client error"
        );
    } else {
        tracing::info!(
            method = %method,
            uri = %uri,
            status = status.as_u16(),
            latency = ?latency,
            "<-- HTTP request completed successfully"
        );
    }

    tracing::debug!(
        method = %method,
        uri = %uri,
        status = status.as_u16(),
        latency = ?latency,
        response_headers = ?response.headers(),
        "<-- HTTP response details"
    );

    response
}

async fn healthz() -> Json<serde_json::Value> {
    tracing::debug!("Handling /healthz request");
    Json(json!({ "status": "ok" }))
}

fn env_or(key: &str, fallback: &str) -> String {
    match env::var(key) {
        Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => fallback.to_string(),
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C, initiating graceful shutdown");
        },
        _ = terminate => {
            tracing::info!("Received SIGTERM, initiating graceful shutdown");
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, extract::Request, routing::get, Router};
    use tower::ServiceExt;

    #[tokio::test]
    async fn healthz_returns_ok() {
        let app = Router::new()
            .route("/healthz", get(healthz))
            .layer(middleware::from_fn(http_request_logger));

        let res = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn logger_handles_404() {
        let app = Router::new()
            .route("/healthz", get(healthz))
            .layer(middleware::from_fn(http_request_logger));

        let res = app
            .oneshot(
                Request::builder()
                    .uri("/not_found")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }
}
