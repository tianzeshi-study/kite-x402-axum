# Rust + Axum template

A ready-to-deploy reverse proxy that charges x402 payments on the Kite chain
for every request under `/v1/*` and forwards paid requests to `UPSTREAM_URL`.

```bash
cd service
cp .env.example .env        # fill PAY_TO, UPSTREAM_URL, PRICE_USD
set -a && source .env && set +a
cargo run
curl -i "localhost:8402/v1/forecast?latitude=52.52&longitude=13.41&current=temperature_2m"
# HTTP/1.1 402 Payment Required + PAYMENT-REQUIRED header
```

Two crates:

- `kite-x402-axum/` — the reusable library: Kite network constants and the
  `$0.001`-style price parser (`kite.rs`), x402 v2 wire types (`types.rs`),
  header encode/decode (`wire.rs`), the facilitator HTTP client
  (`facilitator.rs`), the payment-gate middleware (`middleware.rs`), and
  the reverse proxy handler (`proxy.rs`). Published to crates.io as
  [`kite-x402-axum`](https://crates.io/crates/kite-x402-axum); leave as is
  unless you're changing the wrapper's protocol behavior.
- `service/` — configuration, routing, wiring. Edit this: `src/main.rs`
  reads the environment and assembles the two crates above into a running
  server, the same shape as `main.go` / `src/index.ts` in the other two
  templates.

The payment middleware verifies the signature before your upstream is called
and settles only when the upstream responded with a status below 400, so a
failed upstream call never charges the buyer. See
[`kite-x402-axum`'s crate docs](kite-x402-axum/src/lib.rs) for the one place
this template's behavior is a deliberate choice rather than a direct port:
what happens when the facilitator itself can't be reached.

## Running the tests

```bash
cargo test --workspace
```

23 tests (13 unit + 10 integration) cover: unpaid requests get a `402` with
a valid `PAYMENT-REQUIRED` header; a correctly paid request is verified,
proxied, settled, and gets a `PAYMENT-RESPONSE` header with
`Cache-Control: private`; an upstream failure is passed through untouched
and **never settled**; an invalid payment or an unreachable facilitator both
return `402` (see the error-semantics note above) without ever reaching the
upstream; a malformed payment header is rejected; and the `/v1` prefix is
stripped before the request reaches the upstream. See
`kite-x402-axum/tests/middleware.rs`.

See [`TODO.md`](TODO.md) for known follow-ups (dependency versions pinned
for this sandbox's Rust 1.75, an upstream SDK-disagreement decision that may
need revisiting, etc.) intentionally deferred out of this first pass.

See the repository [README](../../README.md) for the full flow and how to
test with a Kite Passport agent.
