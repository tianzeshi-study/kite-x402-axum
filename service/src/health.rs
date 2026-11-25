//! Background facilitator health probing.
//!
//! `/readyz` normally probes the facilitator on every request, which lets any
//! orchestrator (or caller) multiply load on a dependency that is already
//! struggling. When `FACILITATOR_HEALTH_INTERVAL_SECS` is set, a single
//! background task probes at a fixed interval instead and `/readyz` serves the
//! most recent result.

use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::sync::watch;

/// Upper bound accepted for the probe interval (one day).
pub(crate) const MAX_INTERVAL_SECS: u64 = 86_400;

/// Outcome of the most recent probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProbeResult {
    /// Whether the dependency answered successfully.
    pub(crate) healthy: bool,
    /// Error text of the failed probe, if any.
    pub(crate) error: Option<String>,
    /// Unix timestamp (seconds) at which the probe finished.
    pub(crate) checked_at: u64,
}

/// Shared, cheaply clonable holder of the latest [`ProbeResult`].
#[derive(Debug, Clone, Default)]
pub(crate) struct ReadinessState {
    inner: Arc<Mutex<Option<ProbeResult>>>,
}

impl ReadinessState {
    /// Creates a state that has not been probed yet.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Returns the latest result, or `None` before the first probe finishes.
    pub(crate) fn latest(&self) -> Option<ProbeResult> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Records the outcome of a probe.
    pub(crate) fn record(&self, outcome: Result<(), String>) {
        let result = ProbeResult {
            healthy: outcome.is_ok(),
            error: outcome.err(),
            checked_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        };
        *self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(result);
    }
}

/// Parses `FACILITATOR_HEALTH_INTERVAL_SECS`.
///
/// `None`, blank and `0` all mean "disabled". Anything else must be an
/// integer in `1..=86400`.
pub(crate) fn parse_interval(raw: Option<&str>) -> Result<Option<Duration>, String> {
    let Some(raw) = raw.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let secs: u64 = raw.parse().map_err(|_| {
        format!(
            "FACILITATOR_HEALTH_INTERVAL_SECS must be an integer between 0 and {MAX_INTERVAL_SECS}"
        )
    })?;
    match secs {
        0 => Ok(None),
        1..=MAX_INTERVAL_SECS => Ok(Some(Duration::from_secs(secs))),
        _ => Err(format!(
            "FACILITATOR_HEALTH_INTERVAL_SECS must be an integer between 0 and {MAX_INTERVAL_SECS}"
        )),
    }
}

/// Probes immediately, then once per `interval`, until `shutdown` flips to
/// `true` (or its sender is dropped).
pub(crate) async fn run_probe_loop<F, Fut>(
    state: ReadinessState,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
    mut probe: F,
) where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tokio::select! {
        biased;
        _ = shutdown.wait_for(|stopping| *stopping) => {
            tracing::debug!("Background facilitator probe stopped");
        }
        _ = async {
            loop {
                ticker.tick().await;
                let outcome = probe().await;
                if let Err(error) = &outcome {
                    tracing::warn!(%error, "Background facilitator probe failed");
                }
                state.record(outcome);
            }
        } => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn interval_parsing_accepts_disabled_and_valid_values() {
        assert_eq!(parse_interval(None), Ok(None));
        assert_eq!(parse_interval(Some("  ")), Ok(None));
        assert_eq!(parse_interval(Some("0")), Ok(None));
        assert_eq!(
            parse_interval(Some(" 30 ")),
            Ok(Some(Duration::from_secs(30)))
        );
        assert_eq!(
            parse_interval(Some("86400")),
            Ok(Some(Duration::from_secs(MAX_INTERVAL_SECS)))
        );
    }

    #[test]
    fn interval_parsing_rejects_garbage_and_out_of_range() {
        for bad in ["abc", "-1", "1.5", "86401", "99999999999999999999"] {
            assert!(
                parse_interval(Some(bad)).is_err(),
                "{bad} should be rejected"
            );
        }
    }

    #[test]
    fn state_is_empty_until_first_record() {
        let state = ReadinessState::new();
        assert!(state.latest().is_none());
        state.record(Err("boom".into()));
        let latest = state.latest().unwrap();
        assert!(!latest.healthy);
        assert_eq!(latest.error.as_deref(), Some("boom"));
        state.record(Ok(()));
        let latest = state.latest().unwrap();
        assert!(latest.healthy);
        assert!(latest.error.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn loop_probes_immediately_then_every_interval_and_tracks_transitions() {
        let state = ReadinessState::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = watch::channel(false);

        let task = tokio::spawn({
            let state = state.clone();
            let calls = Arc::clone(&calls);
            async move {
                run_probe_loop(state, Duration::from_secs(10), rx, move || {
                    let n = calls.fetch_add(1, Ordering::SeqCst);
                    // First two probes fail, later ones succeed.
                    async move {
                        if n < 2 {
                            Err(format!("down #{n}"))
                        } else {
                            Ok(())
                        }
                    }
                })
                .await;
            }
        });

        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1, "probes right away");
        assert!(!state.latest().unwrap().healthy);

        tokio::time::sleep(Duration::from_secs(10)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(state.latest().unwrap().error.as_deref(), Some("down #1"));

        tokio::time::sleep(Duration::from_secs(10)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert!(
            state.latest().unwrap().healthy,
            "recovers once the probe succeeds"
        );

        tx.send(true).unwrap();
        task.await.unwrap();
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 3, "no probes after shutdown");
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_cancels_an_in_flight_probe() {
        let state = ReadinessState::new();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let mut started_tx = Some(started_tx);
        let task = tokio::spawn(run_probe_loop(
            state.clone(),
            Duration::from_secs(30),
            shutdown_rx,
            move || {
                started_tx.take().unwrap().send(()).unwrap();
                std::future::pending()
            },
        ));

        started_rx.await.unwrap();
        shutdown_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("probe loop must stop without waiting for the probe")
            .unwrap();
        assert!(
            state.latest().is_none(),
            "no outcome from a cancelled probe"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn loop_stops_when_the_shutdown_sender_is_dropped() {
        let (tx, rx) = watch::channel(false);
        let task = tokio::spawn(run_probe_loop(
            ReadinessState::new(),
            Duration::from_secs(5),
            rx,
            || async { Ok(()) },
        ));
        drop(tx);
        task.await.unwrap();
    }
}
