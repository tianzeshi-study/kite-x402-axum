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

## Logging

The service and library use [`tracing`](https://crates.io/crates/tracing) for structured diagnostic and protocol logging.

The log level is configured via the standard `RUST_LOG` environment variable (defaults to `info` if unset):

```bash
# Standard informational logs
RUST_LOG=info cargo run

# Enable detailed protocol and payment flow logs
RUST_LOG=debug cargo run

# Scope debug logs to kite-x402 crates specifically
RUST_LOG=kite_x402_service=debug,kite_x402_axum=debug cargo run
```

- **`INFO`**: High-level lifecycle events (server startup, listening address, network/chain configuration, 402 challenge issuance, payment verification success, on-chain settlement success with transaction hash, graceful shutdown).
- **`DEBUG`**: Detailed diagnostic traces (payment requirements comparison, facilitator `/verify` and `/settle` requests, upstream proxy path and headers, round-trip timings and status codes).
- **`WARN` / `ERROR`**: Client errors, payment signature decode failures, requirement mismatches, upstream errors, facilitator connectivity issues or settlement rejections.
- **Sensitive data protection**: Secret tokens such as `UPSTREAM_AUTH_VALUE` are automatically redacted from logs.

## Running the tests

```bash
cargo test --workspace
```

219 tests pass (plus 4 intentionally `#[ignore]`d regression tests, see
below), organized in three layers:

- **Unit tests** (116), inside `src/` next to the code they cover, `#[cfg(test)]`:
  - `kite-x402-axum/src/kite.rs` — network constants and the `$0.001`-style
    price parser (decimal edge cases, decimals-per-asset limits, integer
    math has no float rounding error).
  - `kite-x402-axum/src/types.rs` / `wire.rs` — x402 wire-type
    (de)serialization (camelCase field names, optional fields, rejecting
    malformed JSON) and the base64 header encode/decode round trip
    (URL-safe alphabet and missing padding are both rejected).
  - `kite-x402-axum/src/facilitator.rs` — the facilitator HTTP client
    against an in-process fake server: request shape, response parsing,
    non-200 status and unparseable-body error mapping, connection-refused
    and timeout behavior.
  - `kite-x402-axum/src/middleware.rs` — every branch that returns
    *before* the facilitator is called (missing header, undecodable
    header, requirements mismatch, invalid `PRICE_USD`), proven by
    wrapping the gate around a counting stub inner service.
  - `kite-x402-axum/src/proxy.rs` — the request-body size cap, hop-by-hop
    header list, and credential redaction in `Debug` output.
  - `service/src/main.rs` — `env_or`'s trimming/blank/fallback behavior
    and the request logger passing every response through unchanged.
- **Integration tests** (72), in `kite-x402-axum/tests/`, exercising the
  library's public API against real (mock) HTTP servers over localhost —
  no part of the request path is stubbed out:
  - `middleware.rs` *(pre-existing)* — the original core-flow checks.
  - `payment_flow.rs` — the full challenge → verify → settle contract:
    header/requirements validation (every field of a tampered
    `PaymentRequirements` is individually checked), every facilitator
    verify/settle outcome (invalid, down, slow/timeout, malformed body),
    that settlement only ever follows a sub-400 upstream response, and
    concurrent-request safety (25 simultaneous paid requests are each
    settled exactly once).
  - `proxy_forwarding.rs` — what the upstream actually receives (method,
    path, query, headers, body, byte-for-byte) and what the client gets
    back (status, headers, large/streamed bodies), hop-by-hop stripping,
    credential injection and override, and failure modes (unreachable/slow
    upstream, oversized request body).
  - `known_issues.rs` — see below.
- **End-to-end tests** (31), in `service/tests/e2e.rs`, spawning the
  **actual `kite-x402-service` binary** as a child process (configured
  purely through environment variables, as in a real deployment) and
  talking to it over real TCP with a real HTTP client: the full pay-per-call
  flow, every money-safety rule (no charge on a failed upstream, rejected
  payment, or failed settlement), environment-variable parsing and
  defaults, startup failures (`PAY_TO`/`UPSTREAM_URL` missing, bad
  `KITE_NETWORK`, unparseable or taken `PORT`) with their exit codes, and
  graceful shutdown on `SIGTERM` (an in-flight paid request is allowed to
  finish, and settle, before the process exits).

For a faster inner loop, run just the library's unit + integration tests
(skips compiling and spawning the service binary that `service/tests/e2e.rs`
needs):

```bash
cargo test -p kite-x402-axum
```

### Known-issue regression tests

`kite-x402-axum/tests/known_issues.rs` documents four suspected defects as
`#[ignore]`d tests asserting the *desired* behavior, so they don't fail the
normal suite but are one command away from proving whether a fix works:

```bash
cargo test -p kite-x402-axum --test known_issues -- --ignored
```

1. `proxy` strips a leading `/v1` from the path it forwards, but the path it
   sees has *already* had the router's `nest("/v1", ..)` prefix stripped —
   so a request for `/v1/v1/orders` (an upstream resource that itself starts
   with `/v1`) loses both, and the upstream receives `/orders` instead of
   `/v1/orders`.
2. The proxy drops the response's `content-encoding` header, but its
   `reqwest::Client` has no decompression feature enabled, so the body is
   still gzip/br-encoded — a client that sent `Accept-Encoding: gzip` (curl
   `--compressed`, most browsers, Python `requests`) gets encoded bytes with
   no header saying so.
3. The gate accepts the legacy `X-PAYMENT` header (for compatibility with
   older x402 clients), but the proxy only strips `PAYMENT-SIGNATURE` before
   forwarding — a buyer's signed payment payload sent as `X-PAYMENT` reaches
   the upstream API.
4. The proxy's `reqwest::Client` follows redirects by default, and reqwest
   only strips the *standard* `Authorization`/`Cookie` headers on a
   cross-host redirect — a custom credential header set via
   `UPSTREAM_AUTH_HEADER` (e.g. `X-Api-Key`) would still be sent to
   whatever host the upstream redirects to.

None of these are exploitable from the buyer's side of the payment gate
(they're all upstream-facing), and none change what gets settled — hence
"known issue" rather than "blocker" — but items 1 and 3 in particular are
worth fixing before this template is used with an upstream API that has
`/v1`-prefixed resources or with clients still sending `X-PAYMENT`.

See [`TODO.md`](TODO.md) for other known follow-ups (dependency versions pinned
for this sandbox's Rust 1.75, an upstream SDK-disagreement decision that may
need revisiting, etc.) intentionally deferred out of this first pass.

See the repository [README](../../README.md) for the full flow and how to
test with a Kite Passport agent.
