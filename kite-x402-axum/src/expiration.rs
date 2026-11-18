//! Validation guard for EIP-3009 payment authorization validity timestamps.
//!
//! Validates `validAfter` and `validBefore` against current server time
//! taking clock drift tolerance and minimum remaining validity into account.

use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Errors produced when validating a payment authorization's time window.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExpirationError {
    #[error("payment authorization has expired (validBefore: {valid_before}, now: {now})")]
    /// The authorization's `validBefore` timestamp has passed.
    Expired {
        /// The `validBefore` timestamp (Unix seconds).
        valid_before: u64,
        /// The current time (Unix seconds).
        now: u64,
    },
    #[error("payment authorization is not yet active (validAfter: {valid_after}, now: {now})")]
    /// The authorization's `validAfter` timestamp has not been reached yet.
    NotYetValid {
        /// The `validAfter` timestamp (Unix seconds).
        valid_after: u64,
        /// The current time (Unix seconds).
        now: u64,
    },
    #[error("payment authorization validity window is inverted (validAfter: {valid_after} > validBefore: {valid_before})")]
    /// `validAfter` is later than `validBefore`, so the window is empty.
    InvertedWindow {
        /// The `validAfter` timestamp (Unix seconds).
        valid_after: u64,
        /// The `validBefore` timestamp (Unix seconds).
        valid_before: u64,
    },
    #[error("payment authorization expires too soon for settlement (remaining: {remaining}s < min: {min_required}s)")]
    /// The authorization will expire before settlement can reasonably complete.
    InsufficientRemainingValidity {
        /// Seconds of validity remaining.
        remaining: u64,
        /// Minimum number of seconds required.
        min_required: u64,
    },
}

/// Configuration options for validating payment authorization timestamps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExpirationGuardConfig {
    /// Maximum allowable clock drift between buyer and server in seconds.
    /// Default: 30 seconds.
    pub max_drift_seconds: u64,
    /// Minimum remaining validity seconds required before settlement.
    /// Default: 5 seconds.
    pub min_remaining_validity_seconds: u64,
}

impl Default for ExpirationGuardConfig {
    fn default() -> Self {
        Self {
            max_drift_seconds: 30,
            min_remaining_validity_seconds: 5,
        }
    }
}

impl ExpirationGuardConfig {
    /// Creates a config with the given clock-drift tolerance and minimum remaining validity, both in seconds.
    #[must_use]
    pub fn new(max_drift_seconds: u64, min_remaining_validity_seconds: u64) -> Self {
        Self {
            max_drift_seconds,
            min_remaining_validity_seconds,
        }
    }

    /// Validates `valid_after` and `valid_before` against `now_secs`.
    pub fn validate(
        &self,
        valid_after: u64,
        valid_before: u64,
        now_secs: u64,
    ) -> Result<(), ExpirationError> {
        if valid_after > valid_before {
            return Err(ExpirationError::InvertedWindow {
                valid_after,
                valid_before,
            });
        }

        // Check if not yet valid with clock drift tolerance
        let earliest_allowed = now_secs.saturating_add(self.max_drift_seconds);
        if valid_after > earliest_allowed {
            return Err(ExpirationError::NotYetValid {
                valid_after,
                now: now_secs,
            });
        }

        // Check if expired with clock drift tolerance
        let latest_allowed = now_secs.saturating_sub(self.max_drift_seconds);
        if valid_before < latest_allowed {
            return Err(ExpirationError::Expired {
                valid_before,
                now: now_secs,
            });
        }

        // Check minimum remaining validity
        if now_secs > valid_before {
            return Err(ExpirationError::Expired {
                valid_before,
                now: now_secs,
            });
        }

        let remaining = valid_before.saturating_sub(now_secs);
        if remaining < self.min_remaining_validity_seconds {
            return Err(ExpirationError::InsufficientRemainingValidity {
                remaining,
                min_required: self.min_remaining_validity_seconds,
            });
        }

        Ok(())
    }

    /// Validates against the current system time.
    pub fn validate_now(&self, valid_after: u64, valid_before: u64) -> Result<(), ExpirationError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.validate(valid_after, valid_before, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_authorization_window() {
        let guard = ExpirationGuardConfig::default();
        let now = 1_700_000_000;
        let valid_after = now - 100;
        let valid_before = now + 3600;
        assert!(guard.validate(valid_after, valid_before, now).is_ok());
    }

    #[test]
    fn rejects_inverted_window() {
        let guard = ExpirationGuardConfig::default();
        let res = guard.validate(2000, 1000, 1500);
        assert_eq!(
            res,
            Err(ExpirationError::InvertedWindow {
                valid_after: 2000,
                valid_before: 1000,
            })
        );
    }

    #[test]
    fn rejects_expired_authorization() {
        let guard = ExpirationGuardConfig::default();
        let now = 10_000;
        let valid_after = 1000;
        let valid_before = 5000;
        let res = guard.validate(valid_after, valid_before, now);
        assert_eq!(
            res,
            Err(ExpirationError::Expired {
                valid_before: 5000,
                now: 10_000,
            })
        );
    }

    #[test]
    fn rejects_premature_authorization() {
        let guard = ExpirationGuardConfig::default();
        let now = 1000;
        let valid_after = 1200; // 200s in future > 30s drift
        let valid_before = 5000;
        let res = guard.validate(valid_after, valid_before, now);
        assert_eq!(
            res,
            Err(ExpirationError::NotYetValid {
                valid_after: 1200,
                now: 1000,
            })
        );
    }

    #[test]
    fn rejects_insufficient_remaining_validity() {
        let guard = ExpirationGuardConfig::new(10, 5);
        let now = 1000;
        let valid_after = 500;
        let valid_before = 1003; // only 3s remaining < 5s min
        let res = guard.validate(valid_after, valid_before, now);
        assert_eq!(
            res,
            Err(ExpirationError::InsufficientRemainingValidity {
                remaining: 3,
                min_required: 5,
            })
        );
    }
}
