# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `service`: optional `ROUTE_PRICES_REQUIRE_MATCH=true` limits paid proxy access
  to the methods and paths configured in `ROUTE_PRICES_USD`. Unmatched requests
  return `404` before verification, forwarding or settlement. Empty rule lists
  are rejected at startup when enabled.

- `kite-x402-axum`: `IdempotencyCache::acquire_lease` returns an
  `IdempotencyLease` whose `complete`/`release` only act while the caller still
  owns the key. The key-only `acquire`/`complete`/`release` cannot tell a holder
  whose lease expired and was reclaimed from the holder that owns it now, so a
  late call could cancel the live lease and let a third request execute the same
  payment twice. The old methods stay for single-holder callers and now document
  that limitation.
- `service`: `FACILITATOR_HEALTH_INTERVAL_SECS` starts a background facilitator
  probe; `/readyz` then answers from the latest result and reports `checked_at`.
- CI: `cargo-deny` (licenses, bans, sources) and a Docker build + smoke test.
- Release workflow that verifies the tag against the crate version and creates
  a GitHub release.

### Changed

- `kite-x402-axum`: `cors_guard`, `cache_store` and `sliding_limiter` types are
  re-exported by name instead of through glob re-exports. The set of exported
  names is unchanged.

### Fixed

- `service` now declares the workspace license.
- `kite-x402-axum`: `CorsSecurityGuard` now advertises the legacy `X-PAYMENT`
  header in `Access-Control-Allow-Headers`, and sends `Vary: Origin` whenever it
  echoes the caller's origin.

### Removed

- Unreferenced files that were never part of the build: the top-level `src/`
  tree, `kite-x402-axum/src/middleware/` and `kite-x402-axum/src/telemetry/`.
