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

## Pricing by route

Set `ROUTE_PRICES_USD` in the service environment to charge different prices
from the same proxy. The value is a JSON array of rules.

```dotenv
PRICE_USD=0.01
ROUTE_PRICES_USD='[{"method":"GET","path":"/v1/forecast","price":"0.001"},{"method":"GET","path":"/v1/reports/{id}","price":"0.05"}]'
```

Each rule matches the exact HTTP method and the full, case-sensitive URL path
under `/v1/`. Write methods in uppercase (`GET`, `POST`, …): HTTP methods are
case-sensitive and lowercase rules are rejected at startup, because such a rule
could never match a request and would silently leave the route at the default
price. A `{name}` placeholder matches one nonempty path segment, so
`GET /v1/reports/42` and `GET /v1/reports/43` both cost `$0.05` in this example.
Use ASCII letters, digits and underscores in placeholder names, starting with a
letter or underscore. Placeholders must fill the entire segment. Paths are
matched as URL-encoded strings, so a literal brace must be encoded as `%7B` or
`%7D`. Query strings do not affect pricing.

An exact path rule takes priority over a matching template for the same method.
Invalid rules, duplicate exact rules, and overlapping templates for the same
method fail at startup. Unmatched metered requests use `PRICE_USD`, as do all
metered requests when the array is empty or unset.

Use `extra_payment_options` in a rule to set the alternatives for that route.
Omit the field to inherit `EXTRA_PAYMENT_OPTIONS`, use `[]` to offer only the
primary option, or provide an array of `{"network":"mainnet","price":"0.06"}`
objects to replace the defaults. The primary option stays first. Each extra uses
`mainnet` or `testnet` and a positive USD amount valid for that network's token.
An invalid local list prevents the service from starting. Unmatched routes use
`PRICE_USD` and `EXTRA_PAYMENT_OPTIONS`.

```dotenv
EXTRA_PAYMENT_OPTIONS=mainnet:0.002
ROUTE_PRICES_USD='[{"method":"GET","path":"/v1/forecast","price":"0.001"},{"method":"POST","path":"/v1/report","price":"0.05","extra_payment_options":[{"network":"mainnet","price":"0.06"}]}]'
```

With `KITE_NETWORK=testnet`, this example offers the forecast for `$0.001` on
testnet or `$0.002` on mainnet. The report costs `$0.05` on testnet or `$0.06`
on mainnet.

Configure the same price for each public path or method your upstream treats as
an alias of the same operation. With at least one pricing rule, the proxy rejects
upstream redirects it would otherwise follow with HTTP `502` and skips settlement.
Use the upstream's final URL so each payment applies to the requested route.

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

The server returns paid content only when a successful settlement receipt
matches the selected payment network and includes a nonblank transaction ID.
A receipt that fails either check returns `402` with `success: false` and
`errorReason: invalid_settlement_receipt` in `PAYMENT-RESPONSE`. The reported
network and transaction are kept for reconciliation before signing again.

Use the final endpoint URL with the Python client. A `3xx` response stops
it at either request. If the signed request returns `3xx`, run the printed
reconciliation command before retrying.

The [Python test client](service/scripts/kite_x402_client.py) exits with `0`
only after receiving a payment challenge and a successful HTTP response with a
settlement receipt for the requested network and a nonempty transaction ID.
When the client reports an unconfirmed settlement, reconcile the original
payment before signing another authorization.

With `EXTRA_PAYMENT_OPTIONS` or `ROUTE_PRICES_USD` the challenge can offer
several payment options. The Python test client pays the first one unless
`--network <CAIP-2>` names another (for example `--network eip155:2368` for
Kite testnet); a network the challenge does not offer stops the client
before it signs. No single payment may cost more than **$1** unless you
raise the limit with `--max-usd` (or `X402_MAX_PAYMENT_USD`); `--max-usd 0`
removes it. A pricier challenge is refused before anything is signed, and
so is one on a network whose token decimals the client does not know.

### Reconcile an uncertain Kite payment

Before sending `PAYMENT-SIGNATURE`, the Python client prints a reconciliation
command to stderr with the original authorization's nonce and expected payment
details. Save that line and run the printed command if the signed request times
out or the settlement receipt is missing. It queries Kite RPC using public chain
data, without a private key or a new signature. To build the command manually:

```sh
python service/scripts/kite_x402_reconcile.py \
  --network eip155:2368 --asset 0x38129cf4CE5E183eFF248F42A7D345Bb1B47621A \
  --payer "$PAYER" --pay-to "$PAY_TO" --amount "$ATOMIC_AMOUNT" --nonce "$NONCE"
```

Use the original payer, recipient, nonce, and amount in atomic token units.
`--transaction <hash>` checks a known transaction directly. Otherwise the tool
searches the last 1,000 blocks by nonce. Use `--blocks` to change that window
(1–10,000), subject to provider limits. Kite's default mainnet endpoint does
not serve `eth_getLogs`. For mainnet nonce searches, set `--rpc-url` to a Kite
RPC endpoint that supports it. The command supports the USDC.e and pieUSD
contracts configured for this service.

| JSON `status` | Exit code | Meaning |
| --- | --- | --- |
| `confirmed` | 0 | A successful receipt pairs the nonce's authorization event with a transfer matching the token, payer, recipient, and amount. |
| `canceled` | 2 | A successful receipt contains the nonce's cancellation event. |
| `consumed_unverified` | 2 | The contract marks the nonce as consumed, but the query could not prove the expected payment or a cancellation. |
| `not_observed` | 2 | The contract has not consumed the nonce at `observed_block`. A pending settlement can still land. |

RPC errors exit with code 1 and print a diagnostic to stderr. Results depend
on the RPC's chain view and can change after a reorganization. A missing match
does not establish that it is safe to pay again. A confirmed transfer proves the
payment only. It does not show whether the upstream service fulfilled the request.

## Health, Liveness & Diagnostics

The service exposes endpoints outside `/v1/*` that are unmetered (free) and never invoke payment verification or settlement:

- **`GET /healthz`**: Liveness check; returns `{"ok": true, "network", "asset", "price"}` when the HTTP listener is operational. `network` is the CAIP-2 id, `asset` is the stablecoin symbol, and `price` is the configured USD price with a leading `$`.
- **`GET /livez`**: Liveness probe; returns `{"status": "ok", "uptime_seconds": ...}`.
- **`GET /metrics`**: Operational diagnostics; returns a JSON snapshot of atomic counters:
  - `total_requests`: Lifetime total requests received.
  - `active_requests`: Currently in-flight concurrent requests.
  - `paid_challenges`: Count of `402 Payment Required` challenges issued.
  - `successful_requests`: Requests returning status < 400.
  - `server_errors`: Requests returning status >= 500.
  - `uptime_seconds`: Seconds elapsed since service startup.

## Payment webhooks

The example service can asynchronously notify configured merchant endpoints of
payment challenges, verified authorizations, successful settlements, and
failed verification or settlement. Webhooks are disabled unless
`WEBHOOK_URLS` is set. Configure comma-separated absolute HTTP(S) endpoints and
a shared signing secret of at least 32 bytes:

```dotenv
WEBHOOK_URLS=https://merchant.example.com/kite-events
WEBHOOK_SIGNING_SECRET=replace-with-at-least-32-random-bytes
```

Generate a secret with `openssl rand -hex 32`. Each POST body is the serialized
JSON event. `X-Kite-Timestamp` contains its Unix timestamp in seconds, and
`X-Kite-Signature` is `v1=<hex HMAC-SHA256>` over the exact bytes
`<timestamp>.<body>`. Receivers should verify the signature and reject
timestamps outside a short tolerance using the shared secret. The event payload
contains `event_id`, `event_type`, `timestamp_ms`, and optional `payer`,
`network`, `amount_atomic`, `tx_hash`, and query-free `request_path`. It never
contains the payment signature.

Only 2xx responses count as delivered. The service retries failures up to three
times with exponential backoff starting at 500 ms, disables redirects, and
times out each attempt after five seconds. A bounded in-memory queue holds up
to 1,000 deliveries; if it fills, the oldest pending delivery is marked
abandoned. Queue contents are process-local and are lost on restart, so webhooks
provide best-effort notification rather than durable delivery. A webhook
failure never changes the buyer's payment response.

## Timeouts & Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `PAY_TO` | Required | Receiving wallet address on Kite (`0x` plus 40 hex characters). |
| `UPSTREAM_URL` | Required | Protected upstream origin URL. |
| `KITE_NETWORK` | `mainnet` | `mainnet` or `testnet`. |
| `PRICE_USD` | `0.001` | Default price per call in USD. |
| `ROUTE_PRICES_USD` | Empty | Optional JSON array of [route price overrides](#pricing-by-route). |
| `EXTRA_PAYMENT_OPTIONS` | *(unset)* | Comma-separated default alternatives, e.g. `testnet:0.002,mainnet:$0.05`. A route rule can replace or disable them. |
| `PORT` | `8402` | Port for the reverse proxy service. |
| `FACILITATOR_URL` | `https://facilitator.pieverse.io/v2` | Kite facilitator URL (retaining `/v2`). |
| `UPSTREAM_TIMEOUT_MS` | `10000` | Upstream request timeout in milliseconds (100..=300000). |
| `FACILITATOR_TIMEOUT_MS` | `30000` | Facilitator verification/settlement timeout in milliseconds (100..=300000). |
| `UPSTREAM_AUTH_HEADER` | `Authorization` | Credential header injected into upstream calls. |
| `UPSTREAM_AUTH_VALUE` | Empty | Upstream secret credential (redacted from logs). |
| `SERVICE_DESCRIPTION` | `Paid API access via Kite x402` | Resource description shown in the 402 challenge. |
| `SHUTDOWN_TIMEOUT_SECONDS` | `30` | Bounded graceful-shutdown window in seconds (1..=86400). |
| `CORS_ORIGIN` | Empty (disabled) | `*` for any origin, or a comma-separated allowlist; see [Browser CORS support](#browser-cors-support). |
| `RATE_LIMIT_RPS` | `0` (off) | Per-client requests per second. |
| `RATE_LIMIT_BURST` | `=RATE_LIMIT_RPS` | Token-bucket burst size. |
| `RATE_LIMIT_TRUSTED_PROXIES` | Empty | Comma-separated proxy IPs/CIDRs whose `X-Forwarded-For` is trusted for client identification. |
| `RATE_LIMIT_MAX_CLIENTS` | `10000` | Tracked client buckets (1..=1000000). |
| `RATE_LIMIT_IDLE_TIMEOUT_SECS` | `300` | Idle client bucket retention in seconds. |
| `MAX_CONCURRENT_REQUESTS` | `64` | Concurrency admission cap; excess requests queue. |
| `FACILITATOR_VERIFY_RETRIES` | `0` | Retries for facilitator verify on transient failures. |
| `FACILITATOR_VERIFY_BACKOFF_MS` | `150` | Backoff between verify retries in milliseconds. |
| `FACILITATOR_SETTLE_RETRIES` | `0` | Must be 0 — settlement is never retried (indeterminate outcomes stay visible). |
| `SETTLEMENT_QUERY_PORT` | Empty (off) | Enables [local settlement queries](#merchant-settlement-queries) on a separate IPv4 loopback port. |
| `WEBHOOK_URLS` | Empty (off) | Comma-separated HTTP(S) payment event endpoints; requires `WEBHOOK_SIGNING_SECRET`. |
| `WEBHOOK_SIGNING_SECRET` | Required when webhooks are enabled | At least 32 bytes shared with receivers to verify HMAC signatures. |
| `FACILITATOR_HEALTH_INTERVAL_SECS` | Empty (off) | Background facilitator probe interval; 60..=86400 enables. |
| `PAYMENT_CLOCK_DRIFT_SECS` | Empty (off) | Enables the expiration guard with this clock-drift tolerance. |
| `PAYMENT_REPLAY_CACHE_SIZE` | Empty (off) | Enables nonce replay protection with this cache capacity (1..=1000000). |
| `SECURITY_CSP` | `default-src 'none'; frame-ancestors 'none'` | Content-Security-Policy header value. |
| `SECURITY_REFERRER_POLICY` | `strict-origin-when-cross-origin` | Referrer-Policy header value. |
| `SECURITY_HEADERS_ENABLED` | `true` | Set `false` to drop the security-header layer. |

Facilitator response bodies from verification, settlement, and readiness checks
are limited to 64 KiB, including HTTP error responses. The limit is enforced
while reading, even without a Content-Length header. Oversized responses are not
automatically retried; body transport errors are preserved. An unreadable settlement
response may conceal a successful charge: reconcile the original payment before
issuing another authorization. The library exposes this new failure as
`FacilitatorError::ResponseTooLarge`; exhaustive error matches must handle it.

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
- **`502 Bad Gateway`**: Emitted when the upstream fails, with protected data withheld. An unreachable upstream returns `{"error": "upstream unreachable"}`; the transport error stays in the service log.

## Health and Readiness Probes

Paid proxy responses are finite and buffered up to 16 MiB before settlement.
An incomplete, oversized, or timed-out upstream body returns 502 without a
settlement call. Configure the upstream client's timeout to bound body reads.
This template does not support indefinite/SSE streams. Buffering verifies upstream
completion; it cannot guarantee that a disconnected buyer receives every byte.

The service exposes lightweight Kubernetes-compatible health endpoints outside the metered `/v1/*` namespace:

- **`GET /healthz`** (Liveness probe): Returns `200 OK` with `{"ok": true, "network", "asset", "price"}` immediately without contacting backends. Free and unmetered.
- **`GET /readyz`** checks x402 v2 `exact` support for every network advertised by the service. Each probe uses a single facilitator `/supported` request and checks the primary network plus all global and route-specific alternatives. The `networks` field lists the configured networks without duplicates. On success, `network` still identifies the primary network.
  - Returns `200` when all configured networks are supported, or `503` when the response is unsuccessful, malformed, or missing support for a configured network. This checks advertised capabilities only. Confirm funded settlements separately.
  - By default, each readiness request runs a live check. Set `FACILITATOR_HEALTH_INTERVAL_SECS` (1 to 86400) to probe in the background and return the cached result with its Unix `checked_at` timestamp. Until the first probe completes, `/readyz` returns `503` with `status` set to `not_ready` and `facilitator` set to `pending`. `/healthz` remains available during this wait.

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

## Bounded graceful shutdown

`SHUTDOWN_TIMEOUT_SECONDS` bounds draining after `SIGTERM` or Ctrl+C (default
`30`, valid range `1..=86400` seconds). It does not limit normal server uptime.
The server stops accepting connections and lets in-flight requests finish their
upstream processing and settlement. If the deadline expires, the process exits
without waiting indefinitely. A completed response is still required before
settlement; a timeout does not authorize a charge. Termination during a settlement
can leave its outcome unknown: reconcile it instead of automatically retrying.

Security headers continue to use the existing configurable middleware described
above; no duplicate response-header layer is installed.

## Running the tests

```bash
cargo test --workspace
```

409 tests pass at the time of writing (the suite grows with every feature PR), organized in three layers:

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

### Merchant settlement queries

Set `SETTLEMENT_QUERY_PORT=8412` to record settlement attempts and enable the
query listener on `127.0.0.1:8412`. Use the numeric address in requests. The
listener only accepts the configured loopback address and port as the HTTP
host. In a container, run the query from within its network namespace. Local
processes that can reach the listener can read the records. Enable this port
only in a trusted network namespace.

```sh
curl --fail-with-body 'http://127.0.0.1:8412/settlements?limit=20'
curl --fail-with-body "http://127.0.0.1:8412/settlements/eip155:2368/$TX_HASH"
```

`GET /settlements` returns a JSON array, newest entries first. `limit` defaults
to 20 and accepts 1 through 100. `GET /settlements/{network}/{transaction}`
returns one record for an `eip155` chain ID and a 32-byte `0x` transaction hash.
Invalid input returns `400`, an unrecognized host returns `403`, and a missing
record returns `404`. Responses use `Cache-Control: no-store`.

Each record contains `network`, `transaction`, `payer`, `pay_to`,
`amount_atomic`, `timestamp_secs`, and `status`. `transaction` is `null` if
the facilitator supplied no hash. Amounts are decimal strings, or `null` if
the amount is unknown or reached the ledger's `u64` limit. `reported_success`
means the service accepted a successful receipt. `unconfirmed` covers
rejections, incomplete receipts, and unknown outcomes such as timeouts.

When a Kite EIP-3009 attempt is `unconfirmed` and has no transaction hash,
`GET /settlements` includes a `reconciliation` object if the service has all
the original authorization details. It contains `network`, `asset`, `payer`,
`pay_to`, `amount_atomic`, and `nonce`. The nested amount is the full decimal
amount from the signed authorization, including amounts above the ledger's
`u64` limit. The object carries no payment signature. It is omitted if the
original authorization is incomplete or uses a different payment format.

Select the attempt you want to check and copy its `reconciliation` fields into
this command to check the observed chain state by nonce. See [reconciliation
results](#reconcile-an-uncertain-kite-payment) for the possible outcomes.
Reconcile an unknown outcome before retrying.

```sh
python service/scripts/kite_x402_reconcile.py \
  --network "$NETWORK" --asset "$ASSET" --payer "$PAYER" \
  --pay-to "$PAY_TO" --amount "$AMOUNT_ATOMIC" --nonce "$NONCE"
```

The ledger retains up to 5,000 entries per process and clears on restart.
Requests that never reach settlement create no record. To disable recording
and querying, unset the port and restart the service.

### Paying the service end to end, no Passport agent needed

TODO item 2 tracks a run against a live Kite Passport agent, which needs a
funded wallet. For everything short of on-chain settlement you can pay the
real service binary locally with any x402 client. The
[kx402](https://github.com/wilsonqc223/kite-x402-client) toolkit ships a
one-command harness that starts a mock facilitator and upstream, launches
this service exactly as a deployment would (pure env vars), and pays it
with a real EIP-3009 signature:

```bash
git clone https://github.com/wilsonqc223/kite-x402-client
cd kite-x402-client
go run ./examples/e2e-axum-service -bin ../kite-x402-axum/target/release/kite-x402-service
```

The signature format is the same one the live facilitator at
`facilitator.pieverse.io/v2` verifies (see that repo's
`examples/facilitator-livecheck`), so a green run here means only the
on-chain funds transfer is left untested.

### Verify a payment on Kite testnet

The manual smoke test sends one paid GET through the live Kite facilitator.
Use a dedicated testnet payer with at least `0.001` pieUSD and a different
recipient address that you control. Set `PAY_TO` to that recipient in the
service and client shells. Pass the payer's key via `X402_PRIVATE_KEY` in the
client shell only.

From the repository root, serve a deterministic upstream fixture in one shell:

```sh
fixture_dir=$(mktemp -d)
printf '%s\n' '{"status":"paid"}' > "$fixture_dir/smoke.json"
python -m http.server 8403 --bind 127.0.0.1 --directory "$fixture_dir"
```

Start the service in another shell using the real facilitator:

```sh
KITE_NETWORK=testnet PRICE_USD=0.001 PAY_TO="$PAY_TO" PORT=8402 \
  UPSTREAM_URL=http://127.0.0.1:8403 FACILITATOR_URL=https://facilitator.pieverse.io/v2 \
  cargo run -p kite-x402-service --locked
```

Run the smoke test from the client shell:

```sh
python -m pip install eth-account requests
python service/scripts/kite_x402_testnet_smoke.py \
  --url http://127.0.0.1:8402/v1/smoke.json --pay-to "$PAY_TO" \
  --amount 1000000000000000 --expect-json '{"status":"paid"}'
```

The script checks the challenge and payer's pieUSD balance before signing.
Exit code `0` and `upstream_verified: true` mean the paid HTTP response matched
the fixture and the transaction in `PAYMENT-RESPONSE` proved the expected
transfer on Kite testnet. Save the transaction hash from the JSON output as
evidence. Once the script prints the nonce to stderr, reconcile that nonce
before rerunning after an uncertain outcome. Only the read-only receipt lookup
is retried. The automated tests mock the network and use no funded wallet.

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
| scripts | Compile the Python client and run its settlement regression tests with `python -m unittest discover -s service/scripts`. Install `eth-account` and `requests` first. |
| scripts | `python -m py_compile service/scripts/kite_x402_client.py` |
| kx402 client contract | Builds the service, then pays it end to end with the [kx402](https://github.com/wilsonqc223/kite-x402-client) reference client (pinned tag, mock facilitator) — the server↔client wire contract in CI. |
| scripts | Compile the client, reconciliation, and testnet smoke scripts with `python -m py_compile` and run their offline tests with `python -m unittest discover -s service/scripts -p 'test_kite_x402_*.py'`. Install `eth-account` and `requests` first. |
| Docker Compose smoke test | Checks required settings, builds and starts the image, then verifies `/healthz` and the unsigned payment challenge. |

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

For Docker Compose, create a `.env` file in the repository root. Replace the
example values with your receiving wallet address and the base URL of your API.

```dotenv
PAY_TO=0xYourWalletAddress
UPSTREAM_URL=https://api.example.com
```

You can also export these variables in your shell. Exported values take
precedence over `.env`. Compose requires both values to be nonempty. The
Compose service uses Kite testnet by default. To set [route prices](#pricing-by-route),
add `ROUTE_PRICES_USD` to the same `.env` file or export it in your shell.

```bash
docker compose up --build -d
curl -fsS http://localhost:8402/healthz
curl -i http://localhost:8402/v1/example
```

`/healthz` returns HTTP 200 once the service is up. The unsigned `/v1/example`
request returns HTTP 402 with the `PAYMENT-REQUIRED` header.


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
