//! Runnable example wrapper service, equivalent to `main.go` /
//! `src/index.ts` in the other two templates: reads configuration from the
//! environment, exposes a free `/healthz`, and protects `/v1/*` with the
//! x402 payment gate before proxying to `UPSTREAM_URL`.
//!
//! See `.env.example` for every variable this reads, and the top-level
//! README in this directory for how to run it.

use std::{
    env,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{
        atomic::{AtomicI64, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::any,
    Json, Router,
};
use kite_x402_axum::{
    facilitator::{FacilitatorClient, RetryConfig},
    kite::{kite_chain_by_name, KiteChain, FACILITATOR_URL, KITE_MAINNET, KITE_TESTNET},
    middleware::PaymentConfig,
    payment_options::PaymentOption,
    proxy::{proxy, same_origin_redirect_policy, UpstreamConfig},
    PaymentMetrics, PaymentMetricsSnapshot, SettlementLedger, WebhookDispatcher,
};
use serde_json::json;

mod chain_reconciliation;
mod cors;
mod durable_settlement;
mod health;
mod rate_limit;
mod route_prices;
mod settlement_query;
mod webhooks;
use cors::{cors_middleware, CorsConfig};
use health::ReadinessState;
use rate_limit::{
    rate_limit_middleware, RateLimiterConfig, TokenBucketRateLimiter, TrustedProxies,
};
use route_prices::{route_payment, validate_payment_options, RoutePrices};

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

    let pay_to = require_pay_to(&env::var("PAY_TO").unwrap_or_default());
    let upstream_url = env::var("UPSTREAM_URL")
        .expect("UPSTREAM_URL is required (the API being wrapped)")
        .trim_end_matches('/')
        .to_owned();
    let price_usd = env_or("PRICE_USD", "0.001");
    let network_name = env_or("KITE_NETWORK", "mainnet");
    let chain = kite_chain_by_name(&network_name)
        .unwrap_or_else(|e| panic!("invalid KITE_NETWORK={network_name:?}: {e}"));
    let facilitator_url = env_or("FACILITATOR_URL", FACILITATOR_URL);
    let extra_payment_options = parse_extra_payment_options(&env_or("EXTRA_PAYMENT_OPTIONS", ""));
    if !extra_payment_options.is_empty() {
        let primary_payment_option = PaymentOption::new(chain, price_usd.clone());
        validate_payment_options(
            &primary_payment_option,
            &extra_payment_options,
            "default payment options",
        )
        .unwrap_or_else(|err| panic!("invalid EXTRA_PAYMENT_OPTIONS: {err}"));
    }
    let description = env_or("SERVICE_DESCRIPTION", "Paid API access via Kite x402");
    let upstream_auth_header = env_or("UPSTREAM_AUTH_HEADER", "Authorization");
    let upstream_auth_value = env_or("UPSTREAM_AUTH_VALUE", "");
    let shutdown_timeout_secs: u64 = env_or("SHUTDOWN_TIMEOUT_SECONDS", "30")
        .parse()
        .expect("SHUTDOWN_TIMEOUT_SECONDS must be an integer between 1 and 86400");
    assert!(
        (1..=86_400).contains(&shutdown_timeout_secs),
        "SHUTDOWN_TIMEOUT_SECONDS must be an integer between 1 and 86400"
    );
    let rate_limit_rps: f64 = env_or("RATE_LIMIT_RPS", "0")
        .parse()
        .expect("RATE_LIMIT_RPS must be a number");
    if !rate_limit_rps.is_finite() || rate_limit_rps < 0.0 {
        panic!("RATE_LIMIT_RPS must be a finite non-negative number");
    }
    let rate_limit_burst: f64 = env_or("RATE_LIMIT_BURST", &rate_limit_rps.to_string())
        .parse()
        .expect("RATE_LIMIT_BURST must be a number");
    if !rate_limit_burst.is_finite() || rate_limit_burst < 0.0 {
        panic!("RATE_LIMIT_BURST must be a finite non-negative number");
    }

    let trusted_proxies = TrustedProxies::parse(&env_or("RATE_LIMIT_TRUSTED_PROXIES", ""))
        .unwrap_or_else(|message| panic!("{message}"));
    let max_clients: usize = env_or("RATE_LIMIT_MAX_CLIENTS", "10000")
        .parse()
        .expect("RATE_LIMIT_MAX_CLIENTS must be an integer between 1 and 1000000");
    if !(1..=1_000_000).contains(&max_clients) {
        panic!("RATE_LIMIT_MAX_CLIENTS must be an integer between 1 and 1000000");
    }
    let idle_timeout_secs: u64 = env_or("RATE_LIMIT_IDLE_TIMEOUT_SECS", "300")
        .parse()
        .expect("RATE_LIMIT_IDLE_TIMEOUT_SECS must be an integer between 1 and 86400");
    if !(1..=86_400).contains(&idle_timeout_secs) {
        panic!("RATE_LIMIT_IDLE_TIMEOUT_SECS must be an integer between 1 and 86400");
    }
    let rate_limiter: Arc<Option<TokenBucketRateLimiter>> = Arc::new(if rate_limit_rps > 0.0 {
        Some(TokenBucketRateLimiter::new(RateLimiterConfig {
            rps: rate_limit_rps,
            burst: rate_limit_burst.max(1.0),
            trusted_proxies,
            max_clients,
            idle_timeout: Duration::from_secs(idle_timeout_secs),
        }))
    } else {
        None
    });

    let upstream_timeout_ms: u64 = env_or("UPSTREAM_TIMEOUT_MS", "10000")
        .parse()
        .expect("UPSTREAM_TIMEOUT_MS must be a number");
    if !(100..=300000).contains(&upstream_timeout_ms) {
        panic!("UPSTREAM_TIMEOUT_MS must be between 100 and 300000 ms");
    }
    let facilitator_timeout_ms: u64 = env_or("FACILITATOR_TIMEOUT_MS", "30000")
        .parse()
        .expect("FACILITATOR_TIMEOUT_MS must be a number");
    if !(100..=300000).contains(&facilitator_timeout_ms) {
        panic!("FACILITATOR_TIMEOUT_MS must be between 100 and 300000 ms");
    }
    let max_concurrent: usize = env_or("MAX_CONCURRENT_REQUESTS", "64")
        .parse()
        .expect("MAX_CONCURRENT_REQUESTS must be a number");
    if !(1..=10000).contains(&max_concurrent) {
        panic!("MAX_CONCURRENT_REQUESTS must be between 1 and 10000");
    }
    let concurrency_semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrent));

    let settle_retries: u32 = env_or("FACILITATOR_SETTLE_RETRIES", "0")
        .parse()
        .expect("FACILITATOR_SETTLE_RETRIES must be 0");
    let verify_backoff_ms: u64 = env_or("FACILITATOR_VERIFY_BACKOFF_MS", "150")
        .parse()
        .expect("FACILITATOR_VERIFY_BACKOFF_MS must be an integer");
    assert!(
        (1..=3000).contains(&verify_backoff_ms),
        "FACILITATOR_VERIFY_BACKOFF_MS must be between 1 and 3000"
    );

    assert_eq!(settle_retries, 0, "FACILITATOR_SETTLE_RETRIES must be 0; reconcile unknown settlements instead of retrying them");
    let verify_retries: u32 = env_or("FACILITATOR_VERIFY_RETRIES", "0")
        .parse()
        .expect("FACILITATOR_VERIFY_RETRIES must be an integer");
    assert!(
        verify_retries <= 5,
        "FACILITATOR_VERIFY_RETRIES must be between 0 and 5"
    );
    let retry_cfg = RetryConfig::new(
        verify_retries,
        Duration::from_millis(verify_backoff_ms),
        Duration::from_secs(3),
    );

    let cors_origin = env_or("CORS_ORIGIN", "");
    let cors_cfg = Arc::new(CorsConfig::from_env(Some(&cors_origin)));

    tracing::info!(
        port = port,
        network = %network_name,
        chain_id = %chain.network,
        asset = %chain.asset_symbol,
        price_usd = %price_usd,
        pay_to = %pay_to,
        upstream_url = %upstream_url,
        facilitator_url = %facilitator_url,
        rate_limit_rps = rate_limit_rps,
        rate_limit_burst = rate_limit_burst,
        upstream_timeout_ms = upstream_timeout_ms,
        facilitator_timeout_ms = facilitator_timeout_ms,
        max_concurrent_requests = max_concurrent,
        cors_origin = %cors_origin,
        cors_enabled = cors_cfg.is_enabled(),
        auth_injected = !upstream_auth_value.is_empty(),
        shutdown_timeout_secs,
        "Configured kite-x402 wrapper"
    );

    let clock_drift_secs =
        parse_clock_drift_secs(env::var("PAYMENT_CLOCK_DRIFT_SECS").ok().as_deref())
            .unwrap_or_else(|message| panic!("{message}"));
    let expiration_guard =
        clock_drift_secs.map(|drift| kite_x402_axum::ExpirationGuardConfig::new(drift, 5));

    let metrics = Arc::new(PaymentMetrics::new());
    let replay_cache_size = env::var_os("PAYMENT_REPLAY_CACHE_SIZE")
        .map(|value| {
            value.into_string().unwrap_or_else(|_| {
                panic!("PAYMENT_REPLAY_CACHE_SIZE must be an integer between 1 and 1000000")
            })
        })
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            let capacity: usize = value
                .trim()
                .parse()
                .expect("PAYMENT_REPLAY_CACHE_SIZE must be an integer between 1 and 1000000");
            if !(1..=1_000_000).contains(&capacity) {
                panic!("PAYMENT_REPLAY_CACHE_SIZE must be an integer between 1 and 1000000");
            }
            capacity
        });
    let nonce_guard = replay_cache_size
        .map(|cap| Arc::new(kite_x402_axum::PaymentNonceReplayGuard::new(cap, 3600)));

    let health_interval =
        health::parse_interval(env::var("FACILITATOR_HEALTH_INTERVAL_SECS").ok().as_deref())
            .unwrap_or_else(|message| panic!("{message}"));
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let settlement_port = settlement_query::configured_port().unwrap_or_else(|err| panic!("{err}"));
    let durable_store = if env_or("SETTLEMENT_DATABASE_URL", "").is_empty() {
        None
    } else {
        let rpc = chain_reconciliation::ChainRpc::new(
            &env_or("SETTLEMENT_MAINNET_RPC_URL", KITE_MAINNET.rpc_url),
            &env_or("SETTLEMENT_TESTNET_RPC_URL", KITE_TESTNET.rpc_url),
        )
        .unwrap_or_else(|error| panic!("Invalid settlement RPC configuration: {error}"));
        let database_url = env_or("SETTLEMENT_DATABASE_URL", "");
        let store = durable_settlement::DurableStore::connect(&database_url, rpc)
            .await
            .unwrap_or_else(|_| {
                panic!("Could not connect to or initialize the settlement database")
            });
        tracing::info!("Using shared PostgreSQL settlement journal");
        Some(Arc::new(store))
    };
    let settlement_ledger = match &durable_store {
        Some(store) => Some(Arc::new(
            SettlementLedger::default().with_store(store.clone()),
        )),
        None => settlement_port.map(|_| Arc::new(SettlementLedger::default())),
    };
    let settlement_query_source = match &durable_store {
        Some(store) => Some(settlement_query::Source::Durable(store.clone())),
        None => settlement_ledger
            .clone()
            .map(settlement_query::Source::Local),
    };
    if let Some(store) = durable_store {
        tokio::spawn((*store).clone().run(shutdown_rx.clone()));
    }

    let health = health_info(chain, &price_usd);
    let webhook_settings = webhooks::WebhookSettings::from_lookup(|key| env::var(key).ok())
        .unwrap_or_else(|message| panic!("{message}"));
    let webhook_dispatcher = webhook_settings.map(|settings| {
        if settings.insecure_targets() > 0 {
            tracing::warn!(
                count = settings.insecure_targets(),
                "WEBHOOK_URLS has plain-http targets on non-loopback hosts; \
                 payment events (payer address, amount) will cross the network unencrypted"
            );
        }
        if settings.secret.is_none() {
            tracing::warn!("WEBHOOK_SECRET is not set; webhook deliveries are not signed");
        }
        tracing::info!(targets = settings.urls.len(), "Webhook delivery enabled");
        Arc::new(kite_x402_axum::WebhookDispatcher::new(
            settings.into_config(),
        ))
    });

    let payment_cfg = Arc::new(PaymentConfig {
        pay_to,
        chain,
        price_usd,
        description,
        facilitator: FacilitatorClient::with_timeout(
            facilitator_url,
            Duration::from_millis(facilitator_timeout_ms),
        )
        .with_retry_config(retry_cfg),
        expiration_guard,
        metrics: Some(Arc::clone(&metrics)),
        nonce_guard,
        settlement_ledger: settlement_ledger.clone(),
        webhooks: webhook_dispatcher.clone(),
    });
    let discovery = DiscoveryInfo {
        primary: chain,
        price_usd: payment_cfg.price_usd.clone(),
        extra_payment_options: extra_payment_options.clone(),
        pay_to: payment_cfg.pay_to.clone(),
        description: payment_cfg.description.clone(),
    };
    let route_prices_env = env::var_os("ROUTE_PRICES_USD")
        .map(|value| {
            value
                .into_string()
                .expect("ROUTE_PRICES_USD must be valid UTF-8")
        })
        .unwrap_or_default();
    let route_prices_require_match = env::var_os("ROUTE_PRICES_REQUIRE_MATCH")
        .map(|value| {
            value
                .into_string()
                .expect("ROUTE_PRICES_REQUIRE_MATCH must be valid UTF-8")
                .parse::<bool>()
                .expect("ROUTE_PRICES_REQUIRE_MATCH must be true or false")
        })
        .unwrap_or(false);
    let route_prices = RoutePrices::parse(
        &route_prices_env,
        route_prices_require_match,
        Arc::clone(&payment_cfg),
        extra_payment_options,
    )
    .unwrap_or_else(|err| panic!("invalid ROUTE_PRICES_USD: {err}"));

    // Redirects can move a verified request to a differently priced route.
    let redirect_policy = if route_prices.has_overrides() {
        reqwest::redirect::Policy::custom(|attempt| {
            attempt.error("upstream redirects are disabled with ROUTE_PRICES_USD")
        })
    } else {
        same_origin_redirect_policy()
    };
    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_millis(upstream_timeout_ms))
        .redirect(redirect_policy)
        .build()
        .expect("reqwest client");

    let upstream_cfg = Arc::new(UpstreamConfig {
        http: http_client,
        base_url: upstream_url,
        auth_header: upstream_auth_header,
        auth_value: upstream_auth_value,
    });

    let advertised_networks = route_prices.advertised_networks();

    // Everything under /v1 is metered: verify before the handler runs,
    // proxy to the upstream, settle only on a < 400 response.
    let paid = Router::new()
        .route("/{*path}", any(proxy))
        .with_state(upstream_cfg)
        .layer(middleware::from_fn_with_state(
            Arc::new(route_prices),
            route_payment,
        ))
        .layer(middleware::from_fn_with_state(
            rate_limiter.clone(),
            rate_limit_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            concurrency_semaphore,
            concurrency_limiter,
        ));

    if let Some(dispatcher) = &webhook_dispatcher {
        let client = kite_x402_axum::webhook::delivery_client()
            .expect("failed to build the webhook HTTP client");
        tokio::spawn(kite_x402_axum::run_delivery_worker(
            (**dispatcher).clone(),
            client,
            Duration::from_millis(500),
            shutdown_rx.clone(),
        ));
    }
    let readyz_state = Arc::new(ReadyzState {
        payment_cfg,
        networks: advertised_networks,
        cached: health_interval.map(|_| ReadinessState::new()),
    });
    if let (Some(interval), Some(cached)) = (health_interval, &readyz_state.cached) {
        let readyz = Arc::clone(&readyz_state);
        tokio::spawn(health::run_probe_loop(
            cached.clone(),
            interval,
            shutdown_rx.clone(),
            move || {
                let readyz = Arc::clone(&readyz);
                async move { readyz.probe().await.map_err(|e| e.to_string()) }
            },
        ));
        tracing::info!(
            interval_secs = interval.as_secs(),
            "Background facilitator health probe enabled"
        );
    }

    let service_metrics = Arc::new(ServiceMetrics::new());

    let metrics_router = Router::new()
        .route("/metrics/x402", axum::routing::get(metrics_x402_handler))
        .with_state(Arc::clone(&metrics));

    let metrics_state = Arc::new(MetricsEndpointState {
        service: Arc::clone(&service_metrics),
        webhooks: webhook_dispatcher.clone(),
    });
    let diag_router = Router::new()
        .route(
            "/livez",
            axum::routing::get(livez).with_state(Arc::clone(&service_metrics)),
        )
        .route(
            "/metrics",
            axum::routing::get(metrics_endpoint).with_state(metrics_state),
        );

    let security_enabled = match env::var("SECURITY_HEADERS_ENABLED") {
        Ok(v) => v.trim() != "0" && !v.trim().eq_ignore_ascii_case("false"),
        Err(_) => true,
    };
    let security_csp = env_or("SECURITY_CSP", "default-src 'none'; frame-ancestors 'none'");
    let security_referrer_policy = env_or(
        "SECURITY_REFERRER_POLICY",
        "strict-origin-when-cross-origin",
    );

    let security_cfg = Arc::new(SecurityHeadersConfig {
        enabled: security_enabled,
        csp: security_csp,
        referrer_policy: security_referrer_policy,
    });

    tracing::info!(
        security_headers_enabled = security_enabled,
        "Configured security headers middleware"
    );

    let mut app = Router::new()
        .route("/healthz", axum::routing::get(healthz).with_state(health))
        .route(
            "/readyz",
            axum::routing::get(readyz).with_state(readyz_state),
        )
        .route(
            "/.well-known/x402",
            axum::routing::get(well_known_x402).with_state(discovery),
        )
        .merge(metrics_router)
        .merge(diag_router)
        .nest("/v1", paid)
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(
            security_cfg,
            security_headers_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            service_metrics.clone(),
            http_request_logger,
        ));

    if cors_cfg.is_enabled() {
        app = app.layer(middleware::from_fn_with_state(cors_cfg, cors_middleware));
    }

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .unwrap_or_else(|e| panic!("could not bind 0.0.0.0:{port}: {e}"));
    tracing::info!(
        port = port,
        network = %network_name,
        "kite-x402 wrapper listening on 0.0.0.0:{port} (network={network_name})"
    );

    let settlement_listener = if let Some(port) = settlement_port {
        let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .unwrap_or_else(|e| panic!("could not bind settlement query listener at {addr}: {e}"));
        tracing::info!(%addr, "Settlement query listener ready");
        Some((listener, addr))
    } else {
        None
    };

    let (signal_tx, signal_rx) = tokio::sync::oneshot::channel();
    let (settlement_shutdown_tx, mut settlement_shutdown_rx) = tokio::sync::watch::channel(false);
    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown_signal().await;
        // Dependency probes are not needed while existing requests drain.
        let _ = shutdown_tx.send(true);
        let _ = settlement_shutdown_tx.send(true);
        let _ = signal_tx.send(());
    });
    let settlement_server = async move {
        if let Some(((listener, addr), ledger)) = settlement_listener.zip(settlement_query_source) {
            axum::serve(listener, settlement_query::router(ledger, addr))
                .with_graceful_shutdown(async move {
                    let _ = settlement_shutdown_rx.wait_for(|stopping| *stopping).await;
                })
                .await?;
        }
        Ok::<(), std::io::Error>(())
    };

    tokio::select! {
        res = async { tokio::try_join!(async { server.await }, settlement_server) } => {
            res.expect("server error");
            tracing::info!("Server shut down gracefully");
        }
        _ = async {
            if signal_rx.await.is_ok() {
                tokio::time::sleep(Duration::from_secs(shutdown_timeout_secs)).await;
            } else {
                std::future::pending::<()>().await;
            }
        } => {
            tracing::warn!(
                timeout_secs = shutdown_timeout_secs,
                "Graceful shutdown timeout exceeded; forcing exit"
            );
        }
    }
    tracing::info!("Server shut down gracefully");
}

static REQUEST_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn is_valid_request_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'~' || b == b'-')
}

fn generate_request_id() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let count = REQUEST_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("req-{now:x}-{count:08x}")
}

async fn not_found() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "error": "not_found",
            "message": "route not found"
        })),
    )
}

async fn metrics_x402_handler(
    axum::extract::State(metrics): axum::extract::State<Arc<PaymentMetrics>>,
) -> Json<PaymentMetricsSnapshot> {
    tracing::debug!("Handling /metrics/x402 request");
    Json(metrics.snapshot())
}

#[derive(Clone)]
struct MetricsEndpointState {
    service: Arc<ServiceMetrics>,
    webhooks: Option<Arc<WebhookDispatcher>>,
}

/// Process-wide request counters exposed on the metrics endpoint.
#[derive(Debug)]
pub struct ServiceMetrics {
    start_time: Instant,
    total_requests: AtomicU64,
    paid_challenges: AtomicU64,
    successful_requests: AtomicU64,
    server_errors: AtomicU64,
    active_requests: AtomicI64,
}

impl Default for ServiceMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceMetrics {
    /// Creates metrics with all counters at zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            total_requests: AtomicU64::new(0),
            paid_challenges: AtomicU64::new(0),
            successful_requests: AtomicU64::new(0),
            server_errors: AtomicU64::new(0),
            active_requests: AtomicI64::new(0),
        }
    }

    /// Returns a JSON snapshot of the current counters.
    pub fn snapshot(&self) -> serde_json::Value {
        json!({
            "status": "ok",
            "uptime_seconds": self.start_time.elapsed().as_secs(),
            "total_requests": self.total_requests.load(Ordering::SeqCst),
            "active_requests": self.active_requests.load(Ordering::SeqCst).max(0),
            "paid_challenges": self.paid_challenges.load(Ordering::SeqCst),
            "successful_requests": self.successful_requests.load(Ordering::SeqCst),
            "server_errors": self.server_errors.load(Ordering::SeqCst),
        })
    }
}

/// RAII guard that tracks an in-flight request in [`ServiceMetrics`].
#[derive(Debug)]
pub struct ActiveRequestGuard(Arc<ServiceMetrics>);

impl ActiveRequestGuard {
    /// Increments the active-request gauge; it is decremented when the guard is dropped.
    pub fn new(metrics: Arc<ServiceMetrics>) -> Self {
        metrics.active_requests.fetch_add(1, Ordering::SeqCst);
        Self(metrics)
    }
}

impl Drop for ActiveRequestGuard {
    fn drop(&mut self) {
        self.0.active_requests.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn http_request_logger(
    State(metrics): State<Arc<ServiceMetrics>>,
    mut req: Request,
    next: Next,
) -> Response {
    let _guard = ActiveRequestGuard::new(metrics.clone());
    metrics.total_requests.fetch_add(1, Ordering::SeqCst);

    let start = std::time::Instant::now();
    let method = req.method().clone();
    let uri = req.uri().clone();

    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .filter(|s| is_valid_request_id(s))
        .map(|s| s.to_owned())
        .unwrap_or_else(generate_request_id);

    if let Ok(val) = axum::http::HeaderValue::from_str(&request_id) {
        req.headers_mut().insert("x-request-id", val);
    }

    // Custom headers can carry credentials too, so log names only.
    tracing::debug!(
        request_id = %request_id,
        method = %method,
        uri = %uri,
        header_names = ?req.headers().keys().collect::<Vec<_>>(),
        "--> Incoming HTTP request"
    );

    let mut response = next.run(req).await;

    if !response.headers().contains_key("x-request-id") {
        if let Ok(val) = axum::http::HeaderValue::from_str(&request_id) {
            response.headers_mut().insert("x-request-id", val);
        }
    }

    let latency = start.elapsed();
    let status = response.status();

    if status.is_server_error() {
        metrics.server_errors.fetch_add(1, Ordering::SeqCst);
        tracing::error!(
            request_id = %request_id,
            method = %method,
            uri = %uri,
            status = status.as_u16(),
            latency = ?latency,
            "<-- HTTP request failed (server error)"
        );
    } else if status == StatusCode::PAYMENT_REQUIRED {
        metrics.paid_challenges.fetch_add(1, Ordering::SeqCst);
        tracing::info!(
            request_id = %request_id,
            method = %method,
            uri = %uri,
            status = status.as_u16(),
            latency = ?latency,
            "<-- HTTP request requires payment (402 challenge issued)"
        );
    } else if status.is_client_error() {
        tracing::warn!(
            request_id = %request_id,
            method = %method,
            uri = %uri,
            status = status.as_u16(),
            latency = ?latency,
            "<-- HTTP request client error"
        );
    } else {
        metrics.successful_requests.fetch_add(1, Ordering::SeqCst);
        tracing::info!(
            request_id = %request_id,
            method = %method,
            uri = %uri,
            status = status.as_u16(),
            latency = ?latency,
            "<-- HTTP request completed successfully"
        );
    }

    tracing::debug!(
        request_id = %request_id,
        method = %method,
        uri = %uri,
        status = status.as_u16(),
        latency = ?latency,
        response_header_names = ?response.headers().keys().collect::<Vec<_>>(),
        "<-- HTTP response details"
    );

    response
}

/// Configuration for the security-headers middleware.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityHeadersConfig {
    /// Whether security headers are added to responses.
    pub enabled: bool,
    /// Value of the `Content-Security-Policy` header.
    pub csp: String,
    /// Value of the `Referrer-Policy` header.
    pub referrer_policy: String,
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            csp: "default-src 'none'; frame-ancestors 'none'".to_owned(),
            referrer_policy: "strict-origin-when-cross-origin".to_owned(),
        }
    }
}

/// Axum middleware that adds standard security headers to every response.
pub async fn security_headers_middleware(
    axum::extract::State(cfg): axum::extract::State<Arc<SecurityHeadersConfig>>,
    req: Request,
    next: Next,
) -> Response {
    let mut response = next.run(req).await;
    if !cfg.enabled {
        return response;
    }

    let headers = response.headers_mut();
    headers.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        axum::http::header::X_FRAME_OPTIONS,
        axum::http::HeaderValue::from_static("DENY"),
    );
    headers.insert(
        axum::http::header::X_XSS_PROTECTION,
        axum::http::HeaderValue::from_static("0"),
    );
    if let Ok(val) = axum::http::HeaderValue::from_str(&cfg.referrer_policy) {
        headers.insert(axum::http::header::REFERRER_POLICY, val);
    }
    if let Ok(val) = axum::http::HeaderValue::from_str(&cfg.csp) {
        headers.insert(axum::http::header::CONTENT_SECURITY_POLICY, val);
    }

    response
}

async fn livez(State(metrics): State<Arc<ServiceMetrics>>) -> Json<serde_json::Value> {
    tracing::debug!("Handling /livez request");
    Json(json!({
        "status": "ok",
        "uptime_seconds": metrics.start_time.elapsed().as_secs(),
    }))
}

async fn metrics_endpoint(
    State(state): State<Arc<MetricsEndpointState>>,
) -> Json<serde_json::Value> {
    tracing::debug!("Handling /metrics request");
    let mut snapshot = state.service.snapshot();
    let webhook = state
        .webhooks
        .as_ref()
        .map(|dispatcher| dispatcher.metrics_snapshot());
    snapshot["webhooks"] = match webhook {
        Some(metrics) => json!({
            "enabled": true,
            "queued": metrics.queued,
            "in_flight": metrics.in_flight,
            "attempts_total": metrics.attempts_total,
            "delivered_total": metrics.delivered_total,
            "failed_attempts_total": metrics.failed_attempts_total,
            "abandoned_total": metrics.abandoned_total,
        }),
        None => json!({
            "enabled": false,
            "queued": 0,
            "in_flight": 0,
            "attempts_total": 0,
            "delivered_total": 0,
            "failed_attempts_total": 0,
            "abandoned_total": 0,
        }),
    };
    Json(snapshot)
}

async fn concurrency_limiter(
    axum::extract::State(semaphore): axum::extract::State<Arc<tokio::sync::Semaphore>>,
    req: Request,
    next: Next,
) -> Response {
    let Ok(permit) = semaphore.try_acquire() else {
        tracing::warn!("Max concurrency capacity reached, rejecting request with 503");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [
                (axum::http::header::RETRY_AFTER, "1"),
                (axum::http::header::CACHE_CONTROL, "no-store"),
            ],
            Json(json!({ "error": "service_busy" })),
        )
            .into_response();
    };

    let response = next.run(req).await;
    drop(permit);
    response
}

/// Public identity reported by `/healthz`, matching the TypeScript and Go
/// templates: CAIP-2 network, asset symbol, and the `$`-prefixed price.
#[derive(Clone)]
struct HealthInfo {
    network: String,
    asset: String,
    price: String,
}

fn health_info(chain: KiteChain, price_usd: &str) -> HealthInfo {
    HealthInfo {
        network: chain.network.to_owned(),
        asset: chain.asset_symbol.to_owned(),
        price: display_price(price_usd),
    }
}

/// Templates advertise the configured price with a leading `$`.
fn display_price(price_usd: &str) -> String {
    let trimmed = price_usd.trim();
    if trimmed.starts_with('$') {
        trimmed.to_owned()
    } else {
        format!("${trimmed}")
    }
}

/// What `/.well-known/x402` publishes: the payment surface an agent needs
/// before it requests a paid route — the protocol, every network and asset
/// the service accepts, the payee and the prices. It is built once from the
/// configuration and holds nothing the service does not already put in its
/// 402 challenges.
///
/// Two things are left out on purpose. Per-route prices (`ROUTE_PRICES_USD`)
/// would list the metered routes at an unmetered URL, and the facilitator URL
/// is server-side infrastructure that a buyer never contacts.
#[derive(Clone)]
struct DiscoveryInfo {
    primary: KiteChain,
    price_usd: String,
    extra_payment_options: Vec<PaymentOption>,
    pay_to: String,
    description: String,
}

impl DiscoveryInfo {
    /// The document served for `/.well-known/x402`. Where it and the 402
    /// challenge both carry a field, the key is the same (`x402Version`,
    /// `scheme`, `payTo`).
    fn document(&self) -> serde_json::Value {
        let mut networks = vec![self.primary.network];
        let mut assets = vec![asset_info(self.primary)];
        for option in &self.extra_payment_options {
            if !networks.contains(&option.chain.network) {
                networks.push(option.chain.network);
                assets.push(asset_info(option.chain));
            }
        }
        let mut document = json!({
            "x402Version": 2,
            "scheme": "exact",
            "networks": networks,
            "assets": assets,
            "payTo": &self.pay_to,
            "price": display_price(&self.price_usd),
            "description": &self.description,
        });
        if !self.extra_payment_options.is_empty() {
            let extras: Vec<serde_json::Value> = self
                .extra_payment_options
                .iter()
                .map(|option| {
                    json!({
                        "network": option.chain.network,
                        "price": display_price(&option.price_usd),
                    })
                })
                .collect();
            document["extraPaymentOptions"] = json!(extras);
        }
        document
    }
}

/// The `assets` entry for one network: what a client needs to show the token
/// and to reproduce the EIP-712 domain the facilitator checks.
fn asset_info(chain: KiteChain) -> serde_json::Value {
    json!({
        "network": chain.network,
        "address": chain.asset_address,
        "symbol": chain.asset_symbol,
        "decimals": chain.asset_decimals,
        "name": chain.eip712_name,
        "version": chain.eip712_version,
    })
}

/// `GET /.well-known/x402`: unmetered discovery for autonomous agents, so a
/// client can learn what the service accepts without requesting a paid route
/// first. Reads configuration only; it never calls the facilitator or the
/// upstream.
async fn well_known_x402(State(info): State<DiscoveryInfo>) -> impl IntoResponse {
    tracing::debug!("Handling /.well-known/x402 request");
    ([(header::CACHE_CONTROL, "no-store")], Json(info.document()))
}

/// `PAY_TO` must be present and be the 20-byte address the facilitator will
/// settle to. The catalog schema uses the same `0x` + 40 hex pattern.
fn require_pay_to(raw: &str) -> String {
    let pay_to = raw.trim().to_owned();
    if pay_to.is_empty() {
        panic!("PAY_TO is required (the wallet that receives payment)");
    }
    let Some(hex) = pay_to.strip_prefix("0x") else {
        panic!("PAY_TO must be a 0x-prefixed 40-character hex address, got {pay_to:?}");
    };
    if hex.len() != 40 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        panic!("PAY_TO must be a 0x-prefixed 40-character hex address, got {pay_to:?}");
    }
    pay_to
}

async fn healthz(State(info): State<HealthInfo>) -> Json<serde_json::Value> {
    tracing::debug!("Handling /healthz request");
    Json(json!({
        "ok": true,
        "network": info.network,
        "asset": info.asset,
        "price": info.price,
    }))
}

/// State behind `/readyz`: the payment config for a live probe, plus the
/// cached result of the background probe when one is enabled.
struct ReadyzState {
    payment_cfg: Arc<PaymentConfig>,
    networks: Vec<&'static str>,
    cached: Option<ReadinessState>,
}

impl ReadyzState {
    async fn probe(&self) -> Result<(), kite_x402_axum::facilitator::FacilitatorError> {
        self.payment_cfg
            .facilitator
            .probe_networks(&self.networks)
            .await
    }
}

async fn readyz(
    State(state): State<Arc<ReadyzState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    tracing::debug!("Handling /readyz request");
    let network = state.payment_cfg.chain.network;
    let networks = &state.networks;

    // Background mode never probes from a request, including while the first
    // result is pending, so startup polling cannot amplify facilitator load.
    if let Some(cached) = &state.cached {
        let Some(latest) = cached.latest() else {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "status": "not_ready",
                    "facilitator": "pending",
                    "networks": networks,
                })),
            ));
        };
        return if latest.healthy {
            Ok(Json(json!({
                "status": "ready",
                "facilitator": "ok",
                "network": network,
                "networks": networks,
                "checked_at": latest.checked_at,
            })))
        } else {
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "status": "not_ready",
                    "facilitator": "unreachable",
                    "networks": networks,
                    "error": latest.error,
                    "checked_at": latest.checked_at,
                })),
            ))
        };
    }

    match state.probe().await {
        Ok(()) => Ok(Json(json!({
            "status": "ready",
            "facilitator": "ok",
            "network": network,
                "networks": networks,
        }))),
        Err(err) => {
            tracing::warn!(error = %err, "Facilitator readiness probe failed");
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "status": "not_ready",
                    "facilitator": "unreachable",
                    "networks": networks,
                    "error": err.to_string(),
                })),
            ))
        }
    }
}

fn env_or(key: &str, fallback: &str) -> String {
    match env::var(key) {
        Ok(v) if !v.trim().is_empty() => v.trim().to_owned(),
        _ => fallback.to_owned(),
    }
}

/// Parses `PAYMENT_CLOCK_DRIFT_SECS` from a raw environment value.
///
/// `None` and blank mean the guard is not configured (`Ok(None)`); a value
/// must be a non-negative `u64`. A present-but-invalid value is an error
/// rather than a silent `None`, so a typo cannot quietly disable the drift
/// tolerance (which would reject legitimate payments from slow client clocks).
/// Callers treat `Err` as a startup failure, matching the other numeric
/// settings in this service.
fn parse_clock_drift_secs(raw: Option<&str>) -> Result<Option<u64>, String> {
    let Some(raw) = raw.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    raw.parse::<u64>()
        .map(Some)
        .map_err(|_| "PAYMENT_CLOCK_DRIFT_SECS must be a non-negative integer".to_owned())
}

/// Parses `EXTRA_PAYMENT_OPTIONS` — a comma-separated list of
/// `<network>:<price>` entries, e.g. `"testnet:0.002,mainnet:$0.05"`.
/// These are advertised in the 402 challenge after the primary
/// `KITE_NETWORK`/`PRICE_USD` pair. Unknown networks abort startup; prices
/// are validated at request time like the primary price.
fn parse_extra_payment_options(spec: &str) -> Vec<PaymentOption> {
    let mut options = Vec::new();
    for entry in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let Some((network, price)) = entry.split_once(':') else {
            panic!("invalid EXTRA_PAYMENT_OPTIONS entry {entry:?}: want <network>:<price>");
        };
        let chain = kite_chain_by_name(network.trim())
            .unwrap_or_else(|e| panic!("invalid EXTRA_PAYMENT_OPTIONS entry {entry:?}: {e}"));
        options.push(PaymentOption::new(chain, price.trim()));
    }
    options
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
        let metrics = Arc::new(ServiceMetrics::new());
        let app = Router::new()
            .route(
                "/healthz",
                get(healthz).with_state(health_info(kite_x402_axum::kite::KITE_TESTNET, "0.001")),
            )
            .layer(middleware::from_fn_with_state(metrics, http_request_logger));

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
        let metrics = Arc::new(ServiceMetrics::new());
        let app = Router::new()
            .route(
                "/healthz",
                get(healthz).with_state(health_info(kite_x402_axum::kite::KITE_TESTNET, "0.001")),
            )
            .layer(middleware::from_fn_with_state(metrics, http_request_logger));

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

    // ---- env_or -------------------------------------------------------------
    // Each test uses its own variable name so parallel tests cannot interfere.

    #[test]
    fn env_or_returns_the_fallback_when_unset() {
        assert_eq!(env_or("KITE_TEST_ENV_OR_UNSET", "fallback"), "fallback");
    }

    #[test]
    fn env_or_returns_the_trimmed_value_when_set() {
        env::set_var("KITE_TEST_ENV_OR_SET", "  value \n");
        assert_eq!(env_or("KITE_TEST_ENV_OR_SET", "fallback"), "value");
    }

    #[test]
    fn env_or_treats_blank_values_as_unset() {
        for (i, blank) in ["", "   ", "\t\n"].into_iter().enumerate() {
            let key = format!("KITE_TEST_ENV_OR_BLANK_{i}");
            env::set_var(&key, blank);
            assert_eq!(env_or(&key, "fallback"), "fallback");
        }
    }

    #[test]
    fn env_or_does_not_trim_the_fallback() {
        assert_eq!(env_or("KITE_TEST_ENV_OR_UNSET_2", " padded "), " padded ");
    }

    // ---- http_request_logger --------------------------------------------------

    #[tokio::test]
    async fn logger_passes_every_status_class_through_unchanged() {
        for status in [200u16, 204, 302, 402, 404, 500, 503] {
            let metrics = Arc::new(ServiceMetrics::new());
            let app = Router::new()
                .route(
                    "/s",
                    get(move || async move { StatusCode::from_u16(status).unwrap() }),
                )
                .layer(middleware::from_fn_with_state(metrics, http_request_logger));
            let res = app
                .oneshot(Request::builder().uri("/s").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(res.status().as_u16(), status);
        }
    }

    #[tokio::test]
    async fn logger_does_not_alter_headers_or_body() {
        let metrics = Arc::new(ServiceMetrics::new());
        let app = Router::new()
            .route("/h", get(|| async { ([("x-thing", "1")], "payload") }))
            .layer(middleware::from_fn_with_state(metrics, http_request_logger));
        let res = app
            .oneshot(Request::builder().uri("/h").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.headers()["x-thing"], "1");
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&bytes[..], b"payload");
    }

    #[tokio::test]
    async fn healthz_body_reports_network_asset_and_price() {
        let Json(v) = healthz(State(health_info(
            kite_x402_axum::kite::KITE_TESTNET,
            "0.001",
        )))
        .await;
        assert_eq!(
            v,
            json!({
                "ok": true,
                "network": "eip155:2368",
                "asset": "pieUSD",
                "price": "$0.001",
            })
        );
    }

    #[test]
    fn display_price_adds_a_single_dollar_prefix() {
        assert_eq!(display_price("0.001"), "$0.001");
        assert_eq!(display_price("$0.001"), "$0.001");
        assert_eq!(display_price("  0.05"), "$0.05");
    }

    fn discovery_info(extras: Vec<PaymentOption>) -> DiscoveryInfo {
        DiscoveryInfo {
            primary: kite_x402_axum::kite::KITE_TESTNET,
            price_usd: "0.01".into(),
            extra_payment_options: extras,
            pay_to: "0xE2E0000000000000000000000000000000000E2E".into(),
            description: "Test wrapper".into(),
        }
    }

    #[test]
    fn well_known_x402_reports_the_primary_option_and_nothing_else_by_default() {
        // Compared whole: no `extraPaymentOptions` key appears unconfigured,
        // and neither does a facilitator URL or a per-route price table.
        let document = discovery_info(Vec::new()).document();
        assert_eq!(
            document,
            json!({
                "x402Version": 2,
                "scheme": "exact",
                "networks": ["eip155:2368"],
                "assets": [{
                    "network": "eip155:2368",
                    "address": "0x38129cf4CE5E183eFF248F42A7D345Bb1B47621A",
                    "symbol": "pieUSD",
                    "decimals": 18,
                    "name": "pieUSD",
                    "version": "1",
                }],
                "payTo": "0xE2E0000000000000000000000000000000000E2E",
                "price": "$0.01",
                "description": "Test wrapper",
            })
        );
    }

    #[test]
    fn well_known_x402_lists_each_advertised_network_once_with_its_asset() {
        // Two prices on one network are a valid configuration: only options
        // identical on the wire are rejected at startup.
        let extras = vec![
            PaymentOption::new(kite_x402_axum::kite::KITE_MAINNET, "$0.002"),
            PaymentOption::new(kite_x402_axum::kite::KITE_MAINNET, "0.05"),
        ];
        let document = discovery_info(extras).document();
        assert_eq!(document["networks"], json!(["eip155:2368", "eip155:2366"]));
        let assets = document["assets"].as_array().unwrap();
        assert_eq!(assets.len(), 2);
        assert_eq!(
            assets[1]["address"],
            "0x7aB6f3ed87C42eF0aDb67Ed95090f8bF5240149e"
        );
        assert_eq!(assets[1]["decimals"], 6);
        assert_eq!(
            document["extraPaymentOptions"],
            json!([
                {"network": "eip155:2366", "price": "$0.002"},
                {"network": "eip155:2366", "price": "$0.05"},
            ])
        );
    }

    #[tokio::test]
    async fn well_known_x402_answers_uncached() {
        let response = well_known_x402(State(discovery_info(Vec::new())))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }

    #[test]
    fn pay_to_must_be_a_20_byte_hex_address() {
        assert_eq!(
            require_pay_to("  0xE2E0000000000000000000000000000000000E2E  "),
            "0xE2E0000000000000000000000000000000000E2E"
        );
        for bad in [
            "",
            "   ",
            "0x123",
            "not-an-address",
            "0xZZZZ000000000000000000000000000000000000",
        ] {
            let result = std::panic::catch_unwind(|| require_pay_to(bad));
            assert!(result.is_err(), "{bad} should be rejected");
        }
    }

    #[tokio::test]
    async fn livez_body_contains_ok_and_uptime() {
        let metrics = Arc::new(ServiceMetrics::new());
        let Json(v) = livez(State(metrics)).await;
        assert_eq!(v["status"], "ok");
        assert!(v["uptime_seconds"].as_u64().is_some());
    }

    #[tokio::test]
    async fn metrics_endpoint_reports_aggregate_webhook_state_without_payloads() {
        let service = Arc::new(ServiceMetrics::new());
        let disabled = metrics_endpoint(State(Arc::new(MetricsEndpointState {
            service: Arc::clone(&service),
            webhooks: None,
        })))
        .await
        .0;
        assert_eq!(disabled["webhooks"]["enabled"], false);
        assert_eq!(disabled["webhooks"]["queued"], 0);

        let dispatcher = Arc::new(WebhookDispatcher::new(kite_x402_axum::WebhookConfig {
            target_urls: vec!["https://private.example/hook".into()],
            ..Default::default()
        }));
        let _ = dispatcher.enqueue_event(
            kite_x402_axum::WebhookEventType::PaymentSettled,
            Some("0xprivate-payer".into()),
            Some("eip155:2368".into()),
            Some("100".into()),
            Some("0xprivate-hash".into()),
            Some("/v1/private".into()),
        );
        let enabled = metrics_endpoint(State(Arc::new(MetricsEndpointState {
            service,
            webhooks: Some(dispatcher),
        })))
        .await
        .0;
        assert_eq!(enabled["webhooks"]["enabled"], true);
        assert_eq!(enabled["webhooks"]["queued"], 1);
        assert_eq!(enabled["webhooks"]["in_flight"], 0);
        assert_eq!(enabled["webhooks"]["abandoned_total"], 0);
        let body = enabled.to_string();
        assert!(!body.contains("private.example"));
        assert!(!body.contains("private-payer"));
        assert!(!body.contains("private-hash"));
        assert!(!body.contains("/v1/private"));
    }

    #[tokio::test]
    async fn metrics_endpoint_tracks_and_reports_requests() {
        let metrics = Arc::new(ServiceMetrics::new());
        let app = Router::new()
            .route(
                "/healthz",
                get(healthz).with_state(health_info(kite_x402_axum::kite::KITE_TESTNET, "0.001")),
            )
            .route(
                "/metrics",
                get(metrics_endpoint).with_state(Arc::new(MetricsEndpointState {
                    service: metrics.clone(),
                    webhooks: None,
                })),
            )
            .layer(middleware::from_fn_with_state(
                metrics.clone(),
                http_request_logger,
            ));

        // Initial snapshot
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(res.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["total_requests"], 1);
        assert_eq!(body["active_requests"], 1);

        // Another request to /healthz
        let res2 = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res2.status(), StatusCode::OK);

        let Json(snapshot) = metrics_endpoint(State(Arc::new(MetricsEndpointState {
            service: metrics.clone(),
            webhooks: None,
        })))
        .await;
        assert_eq!(snapshot["total_requests"], 2);
        assert_eq!(snapshot["successful_requests"], 2);
        assert_eq!(metrics.active_requests.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn clock_drift_config_is_disabled_only_when_absent_or_blank() {
        // Absent / blank keeps the existing "guard not configured" behaviour.
        assert_eq!(parse_clock_drift_secs(None), Ok(None));
        assert_eq!(parse_clock_drift_secs(Some("")), Ok(None));
        assert_eq!(parse_clock_drift_secs(Some("   ")), Ok(None));

        // Valid values are accepted, with surrounding whitespace trimmed.
        assert_eq!(parse_clock_drift_secs(Some("45")), Ok(Some(45)));
        assert_eq!(parse_clock_drift_secs(Some(" 30 ")), Ok(Some(30)));
        assert_eq!(parse_clock_drift_secs(Some("0")), Ok(Some(0)));

        // A present but malformed value must be rejected, not silently turn
        // into Ok(None) and disable the drift tolerance.
        for bad in ["abc", "-1", "1.5", "18446744073709551616"] {
            assert!(
                parse_clock_drift_secs(Some(bad)).is_err(),
                "{bad} must be rejected instead of disabling the guard"
            );
        }
    }

    #[tokio::test]
    async fn security_headers_applied_by_default() {
        use axum::{body::Body, routing::get};
        use tower::ServiceExt;

        let cfg = Arc::new(SecurityHeadersConfig::default());
        let app = Router::new().route("/test", get(|| async { "ok" })).layer(
            middleware::from_fn_with_state(cfg, security_headers_middleware),
        );

        let res = app
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers()["x-content-type-options"], "nosniff");
        assert_eq!(res.headers()["x-frame-options"], "DENY");
        assert_eq!(res.headers()["x-xss-protection"], "0");
        assert_eq!(
            res.headers()["referrer-policy"],
            "strict-origin-when-cross-origin"
        );
        assert_eq!(
            res.headers()["content-security-policy"],
            "default-src 'none'; frame-ancestors 'none'"
        );
    }

    #[tokio::test]
    async fn security_headers_disabled_when_flag_false() {
        use axum::{body::Body, routing::get};
        use tower::ServiceExt;

        let cfg = Arc::new(SecurityHeadersConfig {
            enabled: false,
            ..Default::default()
        });
        let app = Router::new().route("/test", get(|| async { "ok" })).layer(
            middleware::from_fn_with_state(cfg, security_headers_middleware),
        );

        let res = app
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        assert!(!res.headers().contains_key("x-content-type-options"));
        assert!(!res.headers().contains_key("x-frame-options"));
        assert!(!res.headers().contains_key("content-security-policy"));
    }

    #[tokio::test]
    async fn security_headers_custom_csp_and_referrer() {
        use axum::{body::Body, routing::get};
        use tower::ServiceExt;

        let cfg = Arc::new(SecurityHeadersConfig {
            enabled: true,
            csp: "default-src 'self'".to_owned(),
            referrer_policy: "no-referrer".to_owned(),
        });
        let app = Router::new().route("/test", get(|| async { "ok" })).layer(
            middleware::from_fn_with_state(cfg, security_headers_middleware),
        );

        let res = app
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(
            res.headers()["content-security-policy"],
            "default-src 'self'"
        );
        assert_eq!(res.headers()["referrer-policy"], "no-referrer");
    }
}
