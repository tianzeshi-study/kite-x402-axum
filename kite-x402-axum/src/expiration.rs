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

        // `latest_allowed` above is the single expiry decision. An earlier
        // unconditional `now > valid_before` check made the drift tolerance
        // unreachable: anything inside `[now - drift, now]` passed the
        // tolerance check and was then rejected by that second check with the
        // identical `Expired` error. A buyer whose clock runs behind the
        // server would have every authorization refused at the boundary.
        //
        // Remaining validity is a separate, stricter gate below: it uses a
        // saturating subtraction so an authorization inside the drift window
        // reports 0 remaining and is accepted only when the configured
        // minimum is also 0.
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

    /// A buyer whose clock is 20s behind the server signs an authorization with
    /// `validBefore = buyer_now + 40`. On the server, `validBefore` is 20s in
    /// the past — inside the 30s drift tolerance, so this is exactly the case
    /// `max_drift_seconds` exists to accept. With no minimum-remaining
    /// requirement, the drift-aware expiry check accepts it.
    #[test]
    fn accepts_an_authorization_inside_the_expiry_drift_window() {
        let guard = ExpirationGuardConfig::new(30, 0);
        let now = 10_000;
        // validBefore is 20s before server now, within the 30s tolerance.
        assert_eq!(guard.validate(now - 100, now - 20, now), Ok(()));
    }

    /// The same drift window must still fail once the configured minimum
    /// remaining validity is non-zero: remaining is 0 after saturating, which
    /// is below the 5s floor. This is the independent settlement-safety gate,
    /// not the drift check.
    #[test]
    fn drift_window_still_respects_minimum_remaining_validity() {
        let guard = ExpirationGuardConfig::new(30, 5);
        let now = 10_000;
        assert_eq!(
            guard.validate(now - 100, now - 20, now),
            Err(ExpirationError::InsufficientRemainingValidity {
                remaining: 0,
                min_required: 5,
            })
        );
    }

    #[test]
    fn not_yet_valid_boundary_is_inclusive_of_the_drift_allowance() {
        let guard = ExpirationGuardConfig::new(30, 0);
        let now = 1_000;
        assert!(guard.validate(now + 30, now + 3600, now).is_ok());
        assert_eq!(
            guard.validate(now + 31, now + 3600, now),
            Err(ExpirationError::NotYetValid {
                valid_after: now + 31,
                now,
            })
        );
    }

    #[test]
    fn minimum_remaining_validity_boundary_is_inclusive() {
        let guard = ExpirationGuardConfig::new(30, 5);
        let now = 1_000;
        assert!(guard.validate(0, now + 5, now).is_ok());
        assert_eq!(
            guard.validate(0, now + 4, now),
            Err(ExpirationError::InsufficientRemainingValidity {
                remaining: 4,
                min_required: 5,
            })
        );
    }

    /// Pin the production default: with the shipped `min_remaining = 5`, an
    /// authorization in the drift window is still refused. The drift-aware
    /// expiry check passes, but the independent settlement-safety gate rejects
    /// the authorization because no validity remains according to server time.
    #[test]
    fn default_config_still_rejects_inside_the_drift_window() {
        let guard = ExpirationGuardConfig::default();
        let now = 10_000;
        assert_eq!(
            guard.validate(now - 100, now - 20, now),
            Err(ExpirationError::InsufficientRemainingValidity {
                remaining: 0,
                min_required: 5,
            })
        );
    }

    /// Beyond the drift tolerance the authorization is expired regardless of
    /// the minimum-remaining setting.
    #[test]
    fn rejects_authorization_past_the_expiry_drift_window() {
        let guard = ExpirationGuardConfig::new(30, 0);
        let now = 10_000;
        assert_eq!(
            guard.validate(now - 100, now - 31, now),
            Err(ExpirationError::Expired {
                valid_before: now - 31,
                now,
            })
        );
    }

    #[test]
    fn valid_before_equal_to_now_is_accepted_only_without_a_minimum() {
        let now = 1_000;
        assert!(ExpirationGuardConfig::new(30, 0)
            .validate(0, now, now)
            .is_ok());
        assert_eq!(
            ExpirationGuardConfig::new(30, 1).validate(0, now, now),
            Err(ExpirationError::InsufficientRemainingValidity {
                remaining: 0,
                min_required: 1,
            })
        );
    }

    #[test]
    fn extreme_timestamps_do_not_overflow() {
        let guard = ExpirationGuardConfig::new(u64::MAX, u64::MAX);
        assert!(guard.validate(u64::MAX, u64::MAX, u64::MAX).is_err());

        let guard = ExpirationGuardConfig::new(30, 0);
        assert!(guard.validate(0, u64::MAX, 0).is_ok());
        assert!(guard.validate(0, 0, u64::MAX).is_err());
    }
}
