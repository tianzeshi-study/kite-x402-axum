# kite-x402-axum

Axum building blocks for wrapping an HTTP API behind [x402](https://www.x402.org)
payments settled on the [Kite](https://gokite.ai) chain: a `402 Payment
Required` challenge, verify-then-settle against the Kite facilitator, and a
reverse proxy to your upstream API.

This is the library half of the Rust/Axum template in
[`kite-x402-services`](https://github.com/gokite-ai/kite-x402-services) — the
same repository that has the TypeScript/Express and Go/Gin templates this
crate is meant to behave like. For a ready-to-run example service built on
this crate, see `templates/rust-axum/service` in that repository.

## What it does

```text
agent (Kite Passport)                 your wrapper                      upstream API
────────────────────                 ─────────────                     ────────────
GET /v1/forecast ───────────────────► 402 + PAYMENT-REQUIRED
                                       (network, asset, amount, payTo)
sign EIP-3009 authorization
GET /v1/forecast
  PAYMENT-SIGNATURE: … ─────────────► facilitator /verify ✓
                                       GET /forecast ──────────────────► 200 JSON
                                       facilitator /settle ✓ (on-chain)
◄──────────────────────────────────── 200 JSON + PAYMENT-RESPONSE (tx hash)
```

## Quick start

```rust,ignore
use std::sync::Arc;
use axum::{middleware, routing::any, Router};
use kite_x402_axum::{
    facilitator::FacilitatorClient,
    kite::{kite_chain_by_name, FACILITATOR_URL},
    middleware::{x402_payment, PaymentConfig},
    proxy::{proxy, same_origin_redirect_policy, UpstreamConfig},
};

let payment_cfg = Arc::new(PaymentConfig::new(
    "0xYourWallet",
    kite_chain_by_name("testnet").unwrap(),
    "0.001",
    "Paid API access",
    FacilitatorClient::new(FACILITATOR_URL),
));
// Don't follow redirects to other hosts: the injected credential would go along.
let http = reqwest::Client::builder()
    .redirect(same_origin_redirect_policy())
    .build()
    .unwrap();
let upstream_cfg = Arc::new(UpstreamConfig {
    http,
    base_url: "https://api.example.com".to_string(),
    auth_header: "Authorization".to_string(),
    auth_value: String::new(),
});

let paid = Router::new()
    .route("/{*path}", any(proxy))
    .with_state(upstream_cfg)
    .layer(middleware::from_fn_with_state(payment_cfg, x402_payment));

let app: Router = Router::new().nest("/v1", paid);
```

## Environment variables

The `service` example binary (and any service you build on this crate)
reads the same variable names as the Go and TypeScript templates:
`PAY_TO`, `KITE_NETWORK`, `UPSTREAM_URL`, `PRICE_USD`,
`UPSTREAM_AUTH_HEADER`, `UPSTREAM_AUTH_VALUE`, `FACILITATOR_URL`,
`SERVICE_DESCRIPTION`, `PORT`.

## Optional replay guard

Configure `PaymentConfig::with_nonce_guard(Arc<PaymentNonceReplayGuard>)` to enable
atomic authorization reservations in `x402_payment`. The default has no guard.
`PaymentNonceReplayGuard::new(capacity, ttl_seconds)` bounds pending and retained
authorizations. Pending operations never expire; retention TTL starts when an
operation finishes. Capacity rejects new authorizations instead of evicting live
records. EIP-3009 keys isolate authorizers, networks and assets and normalize EVM
hex casing. Other payloads use complete payment data and requirements as an opaque
identity. Resource and extension metadata are excluded from authorization identity.

Verification failures release reservations. Protected handlers returning >= 400
also release, since the middleware skips settlement. Any settlement attempt retains
protection, including timeouts and negative responses. Cancellation after entering
the protected handler retains protection conservatively. Duplicate payments still
receive `402`; cache saturation returns `503` with a no-store JSON error before
backend work. See the root README for the full outcome table and deployment limits.

For custom flows, `reserve(&payload)` returns a `PaymentNonceReservation`. Keep it
alive throughout the operation; an unprotected drop releases it. Call
`retain_on_drop()` before entering work whose outcome could become uncertain. A
known safe failure can consume it with `release()`. Never release an uncertain
settlement. Clearing the guard is an administrative reset that removes even pending
protection; old handles cannot change replacement entries.

**Compatibility:** `extract_nonce_key` and `check_and_record` keep their signatures
and legacy raw-key behavior; the middleware now uses scoped reservations.
`check_and_record` immediately retains a key and cannot roll back failed work.
Legacy raw keys are not interchangeable with the middleware's scoped identities;
custom flows sharing its guard should use `reserve(&payload)`.
`NonceReplayError` adds `CapacityExceeded`, so exhaustive downstream matches must
handle that variant. Full caches now reject admission rather than evicting old keys.
Replay errors from `reserve` redact authorization identifiers; diagnostics do not
include opaque key contents. Protection remains process-local and TTL-bounded,
without a distributed or exactly-once guarantee.

## Logging

This crate emits structured diagnostics via [`tracing`](https://crates.io/crates/tracing) at `info`, `debug`, `warn`, and `error` levels. Consumers can attach any `tracing-subscriber` (e.g. `tracing-subscriber::fmt::init()`), and configure levels via `RUST_LOG` (such as `RUST_LOG=kite_x402_axum=debug` or `RUST_LOG=debug`) to inspect the full x402 payment flow.

## Multiple payment options per route

By default `x402_payment` accepts exactly one payment option per route (one
price / network / asset). `x402_payment_multi` lets a route advertise several
`PaymentOption`s and accept a client payment matching any one of them — e.g.
pricing the same resource on both Kite testnet and mainnet, or offering
multiple price tiers. It shares the exact same verify/settle engine as the
single-option gate.

```rust
use std::sync::Arc;
use axum::{middleware, routing::any, Router};
use kite_x402_axum::{
    kite::{KITE_TESTNET, KITE_MAINNET},
    payment_options::PaymentOption,
    x402_payment_multi, FacilitatorClient, MultiPaymentConfig,
};

let config = Arc::new(MultiPaymentConfig::new(
    pay_to,
    vec![
        PaymentOption::new(KITE_TESTNET, "0.001"),
        PaymentOption::new(KITE_MAINNET, "$1.50"),
    ],
    "Paid API",
    FacilitatorClient::new(facilitator_url),
));

let app = Router::new()
    .route("/{*path}", any(proxy))
    .layer(middleware::from_fn_with_state(config, x402_payment_multi));
```

The 402 challenge's `accepts` array now lists every configured option. A
client picks one and sends it back as `accepted`; the gate matches it with
`find_matching_requirements` and verifies/settles against that specific
option. Prices use the same integer-only parser as the single-option path,
so per-chain decimals (6 for mainnet USDC, 18 for testnet pieUSD) are handled
identically.

This addition is fully additive: `PaymentConfig` and `x402_payment` are
unchanged, so existing single-option services keep working as before.

## Error semantics — please read

The payment gate accepts only payloads with `x402Version: 2`, through either
`PAYMENT-SIGNATURE` or the legacy `X-PAYMENT` header name. The legacy name
does not add support for the v1 payload format. Unsupported, missing, or
malformed versions receive the existing `402` challenge with
`error: "Invalid payment signature"` before any facilitator or upstream
call. `PAYMENT-SIGNATURE` takes precedence when both headers are present;
an invalid preferred header does not fall back to the legacy header.

The TypeScript and Go x402 SDKs disagree with each other on the HTTP
status used when the **facilitator itself** is unreachable (as opposed to
the facilitator answering "payment invalid"). This crate deliberately
follows the Go SDK's simpler, uniform `402` contract rather than the
TypeScript SDK's `500`/`502` split. See the crate's top-level documentation
(`cargo doc --open`, or `src/lib.rs`) for the full reasoning.

## License

Apache-2.0, matching the rest of `kite-x402-services`.

### Settlement ledger amounts

`SettlementRecord::amount` is an `Option<String>` containing the exact
base-10 atomic amount. Each record carries the token contract as `asset`.
`LedgerSummary::volumes` groups successful volume by `network` and `asset`.
Use `SettlementLedger::with_store` to supply the optional durable payment
store. Database-backed reads are provided by the backend implementation.
