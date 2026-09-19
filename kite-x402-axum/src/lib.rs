//! Axum building blocks for wrapping an HTTP API behind [x402](https://www.x402.org)
//! payments settled on the [Kite](https://gokite.ai) chain.
//!
//! This crate is the Rust/Axum counterpart to the TypeScript/Express and
//! Go/Gin templates in
//! [`kite-x402-services`](https://github.com/gokite-ai/kite-x402-services):
//! it answers `402 Payment Required`, verifies and settles payment through
//! the Kite facilitator, and proxies paid requests to your upstream. It
//! reads the same environment variables and protects the same `/v1/*`
//! route prefix as the other two templates — see
//! `templates/rust-axum/service` in that repository for a ready-to-run
//! example service built on this crate.
//!
//! ```text
//! agent (Kite Passport)                 your wrapper                      upstream API
//! ────────────────────                 ─────────────                     ────────────
//! GET /v1/forecast ───────────────────► 402 + PAYMENT-REQUIRED
//!                                        (network, asset, amount, payTo)
//! sign EIP-3009 authorization
//! GET /v1/forecast
//!   PAYMENT-SIGNATURE: … ─────────────► facilitator /verify ✓
//!                                        GET /forecast ──────────────────► 200 JSON
//!                                        facilitator /settle ✓ (on-chain)
//! ◄──────────────────────────────────── 200 JSON + PAYMENT-RESPONSE (tx hash)
//! ```
//!
//! # Modules
//!
//! - [`kite`] — the two Kite networks (mainnet/testnet), their stablecoin,
//!   and the `$0.001`-style price parser. Mirrors `kite.ts` / `kite.go` —
//!   you should not need to touch it.
//! - [`types`] — the x402 v2 wire types (`PaymentRequirements`,
//!   `PaymentRequired`, `PaymentPayload`, `VerifyResponse`,
//!   `SettleResponse`).
//! - [`wire`] — base64 header encode/decode helpers for the
//!   `PAYMENT-REQUIRED` / `PAYMENT-SIGNATURE` / `PAYMENT-RESPONSE` headers.
//! - [`facilitator`] — a small HTTP client for the Kite facilitator's
//!   `/verify` and `/settle` endpoints.
//! - [`middleware`] — the [`axum::middleware::from_fn_with_state`]-shaped
//!   payment gate: verify before the handler runs, settle only after a
//!   successful (`< 400`) response.
//! - [`proxy`] — a minimal reverse-proxy handler that forwards a paid
//!   request to `UPSTREAM_URL` with the `/v1` prefix stripped and an
//!   upstream credential injected.
//!
//! # Error semantics (please read)
//!
//! The official TypeScript and Go SDKs disagree with each other on the
//! HTTP status used when the **facilitator itself** cannot be reached
//! (as opposed to the facilitator answering "payment invalid"): the
//! TypeScript SDK surfaces a `502` (or occasionally a bare `500`)
//! depending on which internal error type was thrown, while the Go SDK
//! uniformly reports a `402` for any verify or settle failure, facilitator
//! outage included, with the reason in the response body. This crate
//! deliberately follows the **Go SDK's uniform-402 contract**: any problem
//! verifying or settling a payment — whether the payment is invalid or the
//! facilitator is unreachable — is reported as `402 Payment Required` with
//! the reason in `error` (verify) or `PAYMENT-RESPONSE`'s `errorReason`
//! (settle), never a `500`/`502`. This keeps the contract simple and
//! predictable for callers: any `402` is retryable, nothing else needs
//! special-casing. What both official SDKs agree on — and what this crate
//! also guarantees — is untouched: a request is only settled after the
//! upstream responds with a status below 400.

pub mod facilitator;
pub mod kite;
pub mod middleware;
pub mod proxy;
pub mod types;
pub mod wire;

pub use facilitator::{FacilitatorClient, FacilitatorError};
pub use kite::{kite_chain_by_name, KiteChain, KiteError, KITE_MAINNET, KITE_TESTNET};
pub use middleware::{x402_payment, PaymentConfig};
pub use proxy::{proxy, UpstreamConfig};
