//! Opt-in telemetry helpers. Stores are bounded process memory, not durable audit logs.

/// A bounded ring of copied audit events.
pub mod audit_trail;
/// Connection counts and a bounded drain wait.
pub mod pool_metrics;
/// Explicit health flags; readiness starts false until both are established.
pub mod readiness_checker;
/// Local request correlation metadata.
pub mod span_tracer;
