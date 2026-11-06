# Optional helper modules

The crate now compiles and exposes middleware::header_sanitizer, middleware::retry, middleware::zero_copy_decoder and telemetry::{audit_trail,pool_metrics,readiness_checker,span_tracer}. External integration tests use these paths so files cannot silently fall outside the module graph again.

middleware::circuit_breaker and middleware::security_headers reuse the existing root modules. The duplicate, previously unreachable stubs are removed. No payment route behavior or default settlement retry policy changes. Concurrency admission is outside this patch.

These helpers are opt-in building blocks. RetryPolicy calculates delays and never retries transactions. ZeroCopySlice is a borrowed byte view, not a settlement schema validator. Readiness starts false and needs actual caller observations; the flags do not probe dependencies. RequestSpan creates local metadata, not an exporter. AuditTrailStore is a bounded in-memory ring with copied snapshots, not a durable or tamper-evident audit log. PoolMetrics requires the caller to update connection counts.

Forwarding headers are ignored by default. Explicitly trust only socket peers that overwrite client-supplied identity headers; this helper does not authenticate headers or validate proxy chains. Operators must still redact telemetry and restrict access to it.
