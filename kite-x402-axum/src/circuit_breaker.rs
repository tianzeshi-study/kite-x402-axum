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

        match inner.state {
            CircuitState::Closed | CircuitState::HalfOpen => Ok(()),
            CircuitState::Open => {
                let elapsed = now.duration_since(inner.last_state_change);
                if elapsed >= self.config.recovery_timeout {
                    inner.state = CircuitState::HalfOpen;
                    inner.consecutive_successes = 0;
                    inner.last_state_change = now;
                    Ok(())
                } else {
                    inner.total_rejected += 1;
                    let remaining = self.config.recovery_timeout.saturating_sub(elapsed);
                    Err(CircuitBreakerError::CircuitOpen {
                        retry_after_secs: remaining.as_secs().max(1),
                    })
                }
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
        if inner.state == CircuitState::Open {
            let elapsed = Instant::now().duration_since(inner.last_state_change);
            if elapsed >= self.config.recovery_timeout {
                inner.state = CircuitState::HalfOpen;
                inner.consecutive_successes = 0;
                inner.last_state_change = Instant::now();
            }
        }
        inner.state
    }

    /// Takes a snapshot of current metrics.
    #[must_use]
    pub fn snapshot(&self) -> CircuitBreakerSnapshot {
        let inner = self.inner.lock().expect("circuit breaker mutex poisoned");
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
