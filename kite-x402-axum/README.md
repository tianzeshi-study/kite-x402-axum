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
    proxy::{proxy, UpstreamConfig},
};

let payment_cfg = Arc::new(PaymentConfig {
    pay_to: "0xYourWallet".to_string(),
    chain: kite_chain_by_name("testnet").unwrap(),
    price_usd: "0.001".to_string(),
    description: "Paid API access".to_string(),
    facilitator: FacilitatorClient::new(FACILITATOR_URL),
});
let upstream_cfg = Arc::new(UpstreamConfig {
    http: reqwest::Client::new(),
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

## Error semantics — please read

The TypeScript and Go x402 SDKs disagree with each other on the HTTP
status used when the **facilitator itself** is unreachable (as opposed to
the facilitator answering "payment invalid"). This crate deliberately
follows the Go SDK's simpler, uniform `402` contract rather than the
TypeScript SDK's `500`/`502` split. See the crate's top-level documentation
(`cargo doc --open`, or `src/lib.rs`) for the full reasoning.

## License

Apache-2.0, matching the rest of `kite-x402-services`.
