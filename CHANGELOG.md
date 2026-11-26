# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
