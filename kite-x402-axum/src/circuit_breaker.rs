//! Circuit breaker protection for Kite facilitator RPC calls.
//!
//! Provides automatic failure detection, fast-failure when the remote facilitator
//! is degraded or unreachable, and graceful recovery probing to prevent cascading
//! latency and connection resource exhaustion.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;

/// Error returned when an operation is rejected because the circuit is open.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CircuitBreakerError {
    #[error("facilitator circuit breaker is open (cooling down for {retry_after_secs}s)")]
    /// The circuit is open and calls are being rejected.
    CircuitOpen {
        /// Seconds remaining until the breaker may transition to half-open.
        retry_after_secs: u64,
    },
}

/// The three states of the circuit breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CircuitState {
    /// Normal operation: requests are allowed through.
    Closed,
    /// Failing operation: requests are rejected immediately.
    Open,
    /// Trial operation: a limited number of requests are permitted to test recovery.
    HalfOpen,
}

/// Configuration parameters for the circuit breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CircuitBreakerConfig {
    /// Consecutive failures required to transition from Closed to Open.
    pub failure_threshold: u32,
    /// Amount of time to wait in the Open state before trying HalfOpen.
    pub recovery_timeout: Duration,
    /// Number of consecutive successes required in HalfOpen to transition back to Closed.
    pub half_open_success_threshold: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            recovery_timeout: Duration::from_secs(30),
            half_open_success_threshold: 2,
        }
    }
}

#[derive(Debug)]
struct Inner {
    state: CircuitState,
    consecutive_failures: u32,
    consecutive_successes: u32,
    last_state_change: Instant,
    total_rejected: u64,
    total_trips: u64,
}

impl Inner {
    /// Advance Open -> HalfOpen once the cooldown has elapsed.
    ///
    /// Every public observer calls this so the state a caller sees cannot
    /// depend on which method it happened to use.
    fn advance(&mut self, config: &CircuitBreakerConfig, now: Instant) {
        if self.state != CircuitState::Open {
            return;
        }
        if now.duration_since(self.last_state_change) >= config.recovery_timeout {
            self.state = CircuitState::HalfOpen;
            self.consecutive_successes = 0;
            self.last_state_change = now;
        }
    }
}

/// Thread-safe circuit breaker wrapper.
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    inner: Arc<Mutex<Inner>>,
}

/// Snapshot of circuit breaker runtime metrics.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CircuitBreakerSnapshot {
    /// Current breaker state.
    pub state: CircuitState,
    /// Number of consecutive failures recorded.
    pub consecutive_failures: u32,
    /// Number of consecutive successes recorded.
    pub consecutive_successes: u32,
    /// Total number of calls rejected while the circuit was open.
    pub total_rejected: u64,
    /// Total number of times the breaker has tripped open.
    pub total_trips: u64,
}

impl CircuitBreaker {
    /// Creates a new circuit breaker with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(CircuitBreakerConfig::default())
    }

    /// Creates a new circuit breaker with custom settings.
    #[must_use]
    pub fn with_config(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            inner: Arc::new(Mutex::new(Inner {
                state: CircuitState::Closed,
                consecutive_failures: 0,
                consecutive_successes: 0,
                last_state_change: Instant::now(),
                total_rejected: 0,
                total_trips: 0,
            })),
        }
    }

    /// Checks if a request can be executed.
    ///
    /// If in Open state and cooldown has elapsed, automatically advances to HalfOpen.
    /// Returns `Err(CircuitBreakerError::CircuitOpen)` if calls are blocked.
    pub fn can_execute(&self) -> Result<(), CircuitBreakerError> {
        let mut inner = self.inner.lock().expect("circuit breaker mutex poisoned");
        let now = Instant::now();
        inner.advance(&self.config, now);

        match inner.state {
            CircuitState::Closed | CircuitState::HalfOpen => Ok(()),
            CircuitState::Open => {
                inner.total_rejected += 1;
                let elapsed = now.duration_since(inner.last_state_change);
                let remaining = self.config.recovery_timeout.saturating_sub(elapsed);
                Err(CircuitBreakerError::CircuitOpen {
                    retry_after_secs: remaining.as_secs().max(1),
                })
            }
        }
    }

    /// Records a successful operation.
    pub fn record_success(&self) {
        let mut inner = self.inner.lock().expect("circuit breaker mutex poisoned");
        inner.consecutive_failures = 0;

        if inner.state == CircuitState::HalfOpen {
            inner.consecutive_successes += 1;
            if inner.consecutive_successes >= self.config.half_open_success_threshold {
                inner.state = CircuitState::Closed;
                inner.consecutive_successes = 0;
                inner.last_state_change = Instant::now();
            }
        }
    }

    /// Records a failed operation.
    pub fn record_failure(&self) {
        let mut inner = self.inner.lock().expect("circuit breaker mutex poisoned");
        inner.consecutive_failures += 1;
        inner.consecutive_successes = 0;

        match inner.state {
            CircuitState::Closed => {
                if inner.consecutive_failures >= self.config.failure_threshold {
                    inner.state = CircuitState::Open;
                    inner.total_trips += 1;
                    inner.last_state_change = Instant::now();
                }
            }
            CircuitState::HalfOpen => {
                // Any failure in HalfOpen immediately re-opens the circuit
                inner.state = CircuitState::Open;
                inner.total_trips += 1;
                inner.last_state_change = Instant::now();
            }
            CircuitState::Open => {}
        }
    }

    /// Current circuit state.
    #[must_use]
    pub fn state(&self) -> CircuitState {
        let mut inner = self.inner.lock().expect("circuit breaker mutex poisoned");
        inner.advance(&self.config, Instant::now());
        inner.state
    }

    /// Takes a snapshot of current metrics.
    #[must_use]
    pub fn snapshot(&self) -> CircuitBreakerSnapshot {
        let mut inner = self.inner.lock().expect("circuit breaker mutex poisoned");
        inner.advance(&self.config, Instant::now());
        CircuitBreakerSnapshot {
            state: inner.state,
            consecutive_failures: inner.consecutive_failures,
            consecutive_successes: inner.consecutive_successes,
            total_rejected: inner.total_rejected,
            total_trips: inner.total_trips,
        }
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A breaker that trips on the first failure. Passing a zero cooldown makes
    /// the Open -> HalfOpen transition deterministic without sleeping.
    fn breaker_with_cooldown(recovery_timeout: Duration) -> CircuitBreaker {
        CircuitBreaker::with_config(CircuitBreakerConfig {
            failure_threshold: 1,
            recovery_timeout,
            half_open_success_threshold: 1,
        })
    }

    #[test]
    fn snapshot_advances_after_cooldown_like_state_does() {
        let breaker = breaker_with_cooldown(Duration::ZERO);
        breaker.record_failure();

        // Both `state()` and `can_execute()` advance Open -> HalfOpen once the
        // cooldown has elapsed. A metrics read at the same instant must not
        // keep reporting Open forever: a dashboard polling only `snapshot()`
        // would never see the recovery that the request path already observes.
        assert_eq!(
            breaker.snapshot().state,
            CircuitState::HalfOpen,
            "snapshot never advances the state machine after cooldown"
        );
        assert_eq!(breaker.state(), CircuitState::HalfOpen);
    }

    #[test]
    fn snapshot_keeps_open_while_the_cooldown_is_running() {
        let breaker = breaker_with_cooldown(Duration::from_secs(3600));
        breaker.record_failure();

        assert_eq!(breaker.snapshot().state, CircuitState::Open);
        assert!(matches!(
            breaker.can_execute(),
            Err(CircuitBreakerError::CircuitOpen { .. })
        ));
        // Reading metrics must not shorten a cooldown the request path still
        // honours.
        assert_eq!(breaker.snapshot().state, CircuitState::Open);
    }

    #[test]
    fn snapshot_and_state_agree_when_state_drove_the_transition() {
        let breaker = breaker_with_cooldown(Duration::ZERO);
        breaker.record_failure();

        assert_eq!(breaker.state(), CircuitState::HalfOpen);
        // Guard the shared-state behaviour: once anything has advanced the
        // machine, both observers must report the same thing.
        assert_eq!(breaker.snapshot().state, breaker.state());
    }

    #[test]
    fn repeated_snapshots_are_stable() {
        let breaker = breaker_with_cooldown(Duration::ZERO);
        breaker.record_failure();
        let first = breaker.snapshot();
        let second = breaker.snapshot();
        assert_eq!(first, second, "reading metrics must not itself cause churn");
    }
}
