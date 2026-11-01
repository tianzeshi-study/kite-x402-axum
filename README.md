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

## Rate Limiting

The service includes an in-memory token-bucket rate limiter that guards `/v1/*`
before payment verification. It is disabled by default and stores quotas separately
in each service process; restarting a process resets its buckets. Multiple replicas
do not share a global quota.

| Variable | Default | Description |
| --- | --- | --- |
| `RATE_LIMIT_RPS` | `0` | Finite, non-negative refill rate in requests per second; `0` disables limiting. Fractional rates are supported. |
| `RATE_LIMIT_BURST` | `RATE_LIMIT_RPS` | Finite, non-negative burst capacity, with an effective minimum of one token when enabled. |
| `RATE_LIMIT_TRUSTED_PROXIES` | Empty | Comma-separated proxy IP addresses or CIDRs (IPv4 or IPv6). Forwarding headers from other peers are ignored. |
| `RATE_LIMIT_MAX_CLIENTS` | `10000` | Maximum cached client IPs, an integer from `1` to `1000000`. |
| `RATE_LIMIT_IDLE_TIMEOUT_SECS` | `300` | Minimum idle time before a bucket can expire, an integer from `1` to `86400` seconds. |

All settings are validated at startup, including when limiting is disabled.

**Client identity and proxy migration.** By default, the client is the TCP peer IP;
changing `X-Forwarded-For` or `X-Real-IP` cannot create a new quota. Deployments that
previously relied on forwarding headers must explicitly trust their proxy addresses.
For example, when the service is reachable through a local reverse proxy:

```bash
RATE_LIMIT_RPS=10 RATE_LIMIT_BURST=20 \
  RATE_LIMIT_TRUSTED_PROXIES=127.0.0.1,::1 cargo run -p kite-x402-service
```

Only trust proxies you control, and configure them to append the actual connecting
peer to `X-Forwarded-For`, or overwrite the header with authoritative client data.
When the TCP peer is trusted, the service reads `X-Forwarded-For` from right to left,
across repeated header fields, stopping at the first untrusted address. Values to
its left cannot select the quota. `X-Real-IP` is used only when `X-Forwarded-For` is
absent and the TCP peer is trusted. Malformed trusted forwarding metadata returns
`400` with `{"error":"invalid_forwarded_ip"}` and `Cache-Control: no-store`; it
does not fall back to another header. IPv4-mapped IPv6 addresses share the matching
IPv4 quota.

**Capacity and expiry.** Both the client cache and its expiry index are bounded by
`RATE_LIMIT_MAX_CLIENTS`. A bucket expires only after the idle timeout **and** enough
time to refill completely, so a short timeout cannot reset a low-rate quota early.
Expired entries are reclaimed on requests, at most 64 per request. When the cache
is full, unknown clients receive `503` with
`{"error":"rate_limit_capacity_exceeded"}`, `Retry-After: 1`, and
`Cache-Control: no-store`. This retry value is a retry hint, not a guarantee that
capacity will be available in one second. Existing clients retain their quotas.

Clients exceeding their quota receive `429 Too Many Requests` with
`Retry-After: <seconds>`, `X-RateLimit-Limit`, `X-RateLimit-Remaining: 0`, and
`Cache-Control: no-store`. Successful admission also sets `X-RateLimit-Limit` and
`X-RateLimit-Remaining` on the response, including a payment challenge.
Rejected requests never contact the facilitator or upstream and incur no payment.
`/healthz`, `/livez`, and `/metrics` remain free and outside this limiter.

## Payment replay protection

Set `PAYMENT_REPLAY_CACHE_SIZE=10000` to enable process-local authorization replay
protection. Unset or blank values keep it disabled; configured values must be
integers from `1` to `1000000`, otherwise startup fails. The service retains
completed or uncertain authorizations for one hour after the operation ends.

The guard reserves an authorization atomically before verification. Concurrent
copies receive the existing `402` payment challenge without reaching the facilitator
or upstream. EIP-3009 identity includes the network, asset, authorizer and nonce,
so different payers can use the same nonce. Hex casing, signature variants, and
resource/extension metadata do not create a fresh structured authorization.
Payloads without this structure use their complete payment data and requirements
as an opaque identity instead of a bare nonce or signature.

| Outcome | Replay protection |
| --- | --- |
| Verification rejection, error, timeout, or cancellation | Release; the same authorization can be retried. |
| Protected handler returns a status >= 400 | Release; settlement is never attempted. |
| Any settlement attempt, including rejection, malformed response, or timeout | Retain conservatively; the authorization is not automatically reusable. |
| Cancellation or unwinding after entering the protected handler | Retain; the execution outcome may be unknown. |

Pending reservations never expire or get evicted. At cache capacity, new
authorizations receive `503`, `Cache-Control: no-store`, `Retry-After: 1`, and
`{"error":"payment_replay_capacity_exceeded"}` before any backend work. Existing
duplicates still receive `402`. Unpaid challenges and free health/diagnostic routes
remain available. The retry header is a hint, not a guarantee that a slot becomes
available after one second. Expired retained entries are reclaimed on admissions,
at most 64 per admission; both storage and the expiry index are capacity-bounded.

This protection is local to one process, resets on restart, and ends after the
retention TTL. It does not replace on-chain authorization checks, provide a shared
cache across replicas, or guarantee exactly-once business effects. Transport errors
can leave an upstream operation's result unknown even when no settlement occurs.
Use a new authorization or reconcile an uncertain settlement rather than clearing
the guard to retry it blindly. Settlement is sent once: a timeout, malformed reply,
or server error can conceal a successful charge. Reconcile the original payment
before issuing another authorization. `FACILITATOR_SETTLE_RETRIES` must be 0;
nonzero legacy settings fail startup. `FACILITATOR_VERIFY_RETRIES` optionally
enables 0–5 bounded retries for transient verification failures (default 0).
The library's `RetryConfig` now applies only to verification.

## Health, Liveness & Diagnostics

The service exposes endpoints outside `/v1/*` that are unmetered (free) and never invoke payment verification or settlement:

- **`GET /healthz`**: Standard readiness check; returns `{"status": "ok"}` when the HTTP listener is operational.
- **`GET /livez`**: Liveness probe; returns `{"status": "ok", "uptime_seconds": ...}`.
- **`GET /metrics`**: Operational diagnostics; returns a JSON snapshot of atomic counters:
  - `total_requests`: Lifetime total requests received.
  - `active_requests`: Currently in-flight concurrent requests.
  - `paid_challenges`: Count of `402 Payment Required` challenges issued.
  - `successful_requests`: Requests returning status < 400.
  - `server_errors`: Requests returning status >= 500.
  - `uptime_seconds`: Seconds elapsed since service startup.

## Timeouts & Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `PAY_TO` | Required | Receiving wallet address on Kite. |
| `UPSTREAM_URL` | Required | Protected upstream origin URL. |
| `KITE_NETWORK` | `mainnet` | `mainnet` or `testnet`. |
| `PRICE_USD` | `0.001` | Price per call in USD. |
| `PORT` | `8402` | Port for the reverse proxy service. |
| `FACILITATOR_URL` | `https://facilitator.pieverse.io/v2` | Kite facilitator URL (retaining `/v2`). |
| `UPSTREAM_TIMEOUT_MS` | `10000` | Upstream request timeout in milliseconds (100..=300000). |
| `FACILITATOR_TIMEOUT_MS` | `30000` | Facilitator verification/settlement timeout in milliseconds (100..=300000). |
| `UPSTREAM_AUTH_HEADER` | `Authorization` | Credential header injected into upstream calls. |
| `UPSTREAM_AUTH_VALUE` | Empty | Upstream secret credential (redacted from logs). |

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
- **`DEBUG`**: Detailed diagnostic traces (payment requirements comparison, facilitator `/verify` and `/settle` requests, upstream proxy paths, HTTP header names, round-trip timings and status codes).
- **`WARN` / `ERROR`**: Client errors, payment signature decode failures, requirement mismatches, upstream errors, facilitator connectivity issues or settlement rejections.
- **HTTP header privacy**: The service's request and response header diagnostics record names only. Values are omitted for every header, including `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, all x402 payment headers, and custom credential headers. Repeated and binary header values receive the same protection. The request and response headers sent over HTTP are preserved.
- **Log fields**: Request diagnostics use `header_names`; response diagnostics use `response_header_names`. These replace the previous `headers` and `response_headers` fields containing full header maps. Method, URI, request ID, status, and latency remain available. This protection applies to HTTP header diagnostics; it does not sanitize URIs or facilitator response bodies logged elsewhere.
- **`X-Request-Id` tracing**: Every request receives an `x-request-id` correlation identifier (echoing incoming alphanumeric headers or generating a unique `req-<timestamp>-<counter>` identifier). The request ID is attached to all outbound responses (including 402 challenges and error responses) and forwarded to the upstream API. Its value is logged separately as `request_id` for correlation.

## Security headers

The service wraps all responses (including `/healthz`, `/v1/*`, and 402 payment challenge responses) with defensive HTTP security headers to protect clients and webviews against MIME-sniffing, clickjacking, and XSS:

| Header | Default Value | Description |
| --- | --- | --- |
| `X-Content-Type-Options` | `nosniff` | Blocks MIME-type sniffing |
| `X-Frame-Options` | `DENY` | Prevents iframe embedding / clickjacking |
| `X-XSS-Protection` | `0` | Disables legacy buggy XSS auditor |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Protects referrer leakage across origins |
| `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'` | Restricts executable resource loading |

Security headers are enabled by default and can be configured via environment variables:
- `SECURITY_HEADERS_ENABLED=false` to disable the middleware.
- `SECURITY_CSP="..."` to override the default Content-Security-Policy.
- `SECURITY_REFERRER_POLICY="..."` to configure a custom Referrer-Policy.


## Error Responses

The service emits structured JSON error bodies:

- **`404 Not Found`**: Returns `{"error": "not_found", "message": "route not found"}` for unknown paths outside `/v1/*` and `/healthz`.
- **`402 Payment Required`**: Issues standard x402 challenge with `PAYMENT-REQUIRED` headers.
- **`502 Bad Gateway`**: Emitted when the upstream fails, with protected data withheld.

## Health and Readiness Probes

The service exposes lightweight Kubernetes-compatible health endpoints outside the metered `/v1/*` namespace:

- **`GET /healthz`** (Liveness probe): Returns `200 OK` (`"ok"`) immediately without contacting backends. Free and unmetered.
- **`GET /readyz`** (Readiness probe): Probes downstream dependencies by pinging the configured Kite facilitator `/verify` endpoint with a zero-budget probe.
  - Returns `200 OK` with JSON `{"status":"ok","facilitator":"ok"}` when the facilitator is reachable and operational.
  - Returns `503 Service Unavailable` with JSON `{"status":"unavailable","facilitator":"error","error":"..."}` if the facilitator cannot be reached. Useful for load balancers and orchestrators to avoid routing traffic before the settlement gateway is operational.
## Browser CORS support

The wrapper service supports Cross-Origin Resource Sharing (CORS) for web frontends, browser-based agents, and sandbox environments:

- **Configuration**: Set `CORS_ORIGIN="*"` to allow any origin, or provide a comma-separated list of allowed origins (e.g. `https://app.kiteai.com,http://localhost:3000`).
- **Zero overhead when disabled**: When `CORS_ORIGIN` is unset (default), CORS middleware is not registered, ensuring zero overhead and complete backward compatibility.
- **Safe preflight handling**: Browser preflight `OPTIONS` requests receive `204 No Content` with appropriate allow headers without triggering 402 challenges or charging buyers.
- **Header exposure**: Automatically exposes `Payment-Required`, `Payment-Response`, `X-Payment`, `Payment-Signature`, and `Retry-After` via `Access-Control-Expose-Headers`, allowing browser `fetch()` calls to read 402 challenge parameters and settlement receipts.

## Concurrency Admission Control

The service provides built-in concurrency admission control for metered `/v1/*` requests using a semaphore:

- Configured via the `MAX_CONCURRENT_REQUESTS` environment variable (defaults to `64`, accepts integers from `1` to `10000`).
- If inbound concurrency exceeds the limit, incoming metered requests are immediately rejected with `503 Service Unavailable`, `Retry-After: 1`, `Cache-Control: no-store`, and JSON `{"error": "service_busy"}` before any facilitator verification or upstream proxying takes place.
- Requests outside `/v1/*` (such as `/healthz`) do not consume concurrency slots and remain accessible during load spikes.

## Running the tests

```bash
cargo test --workspace
```

235 tests pass, organized in three layers:

- **Unit tests** (120), inside `src/` next to the code they cover, `#[cfg(test)]`:
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
- **Integration tests** (84), in `kite-x402-axum/tests/`, exercising the
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
  - `proxy_regressions.rs` — see below.
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

### Proxy regression tests

`kite-x402-axum/tests/proxy_regressions.rs` pins down defects that were found
in the reverse proxy and then fixed; each test's doc comment says what used to
go wrong:

1. **`/v1` was stripped twice.** The router's `nest("/v1", ..)` already removes
   the prefix, so `/v1/v1/orders` reached the upstream as `/orders`. The proxy
   now strips nothing itself when it runs under `Router::nest` (it checks for
   axum's `NestedPath`), and strips exactly one whole `/v1` segment otherwise.
2. **`content-encoding` was dropped from a still-encoded body.** The header is
   now passed through, since nothing in the proxy decompresses.
3. **The legacy `X-PAYMENT` header reached the upstream.** Both payment
   headers are now removed before forwarding.
4. **An injected credential followed cross-host redirects.** The service builds
   its upstream client with `proxy::same_origin_redirect_policy()`, which
   follows same-origin redirects and returns any other `3xx` to the buyer.
   If you supply your own `reqwest::Client`, build it the same way.
5. **Dot segments could climb out of the upstream base path.** With
   `UPSTREAM_URL=https://host/public`, a request for `/v1/../secret` (or
   `%2e%2e`) used to be forwarded to `/secret` with the credential attached.
   Such paths are now rejected with `400`, which the payment gate never settles.

See [`TODO.md`](TODO.md) for other known follow-ups (an upstream
SDK-disagreement decision that may need revisiting, a live testnet run, etc.).

## Continuous integration

`.github/workflows/ci.yml` runs on every push to `main` and every pull
request; the same commands work locally:

| Job | Command |
| --- | --- |
| rustfmt | `cargo fmt --all -- --check` |
| clippy | `cargo clippy --workspace --all-targets --locked -- -D warnings` |
| test | `cargo test --workspace --locked` |
| msrv | `cargo check --workspace --all-targets --locked` on Rust 1.88 |
| rustdoc | `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked` |
| package | `cargo package -p kite-x402-axum --locked` |
| scripts | `python -m py_compile service/scripts/kite_x402_client.py` |

Mark **CI success** as the required check in branch protection; it passes only
if all of the jobs above pass. `.github/workflows/audit.yml` checks
`Cargo.lock` against the RustSec advisory database weekly and whenever
dependencies change, and Dependabot proposes cargo and GitHub Actions updates
weekly. `Cargo.lock` is committed (the workspace ships a binary), so CI builds
use the exact dependency versions you have tested. The minimum supported Rust
version is 1.88, set by the dependency tree (`icu_*` via `reqwest`); keep
`rust-version` in `Cargo.toml` and the `msrv` job in step.

See the repository [README](../../README.md) for the full flow and how to
test with a Kite Passport agent.

## Running with Docker

You can package and deploy the service using the provided multi-stage `Dockerfile`:

```bash
# Build the production container image
docker build -t kite-x402-axum-service .

# Run with environment variables
docker run -d --name kite-service \
  -p 8402:8402 \
  -e PAY_TO=0xYourWalletAddress \
  -e UPSTREAM_URL=https://api.example.com \
  -e KITE_NETWORK=testnet \
  kite-x402-axum-service
```

Or deploy via Docker Compose:

```bash
docker compose up -d
```


## Contributing

Contributions are welcome! Please follow these guidelines when submitting a pull request.

### Before Submitting a Pull Request

1. **Format your code.** Run `cargo fmt` before creating a pull request to ensure consistent code formatting.
2. **Add tests.** New features and improvements must include corresponding tests to verify their behavior.
3. **Run tests.** Run `cargo test` and ensure all tests pass before submitting your changes.

### Pull Request Guidelines

- Keep pull requests focused and clearly describe the changes.
- Explain the motivation behind new features or improvements.
- Include relevant test coverage for all new functionality and behavior changes.
- Ensure your changes do not introduce unnecessary regressions.

Thank you for contributing!

Add the project’s required checksExplain how to open a pull request
