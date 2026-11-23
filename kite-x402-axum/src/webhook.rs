use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Webhook event trigger type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookEventType {
    /// A payment challenge (402) was issued.
    PaymentPrompted,
    /// A payment was verified.
    PaymentVerified,
    /// A payment was settled on-chain.
    PaymentSettled,
    /// A payment failed verification or settlement.
    PaymentFailed,
}

/// A dispatched webhook event payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    /// Unique identifier of the event.
    pub event_id: String,
    /// Kind of event.
    pub event_type: WebhookEventType,
    /// Event time in Unix milliseconds.
    pub timestamp_ms: u64,
    /// Address of the payer, if known.
    pub payer: Option<String>,
    /// Network identifier (CAIP-2), if known.
    pub network: Option<String>,
    /// Amount in atomic token units, if known.
    pub amount_atomic: Option<String>,
    /// Settlement transaction hash, if any.
    pub tx_hash: Option<String>,
    /// Path of the request that triggered the event.
    pub request_path: Option<String>,
}

/// Delivery status of a webhook invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    /// Waiting for its first or next delivery attempt.
    Pending,
    /// Delivered successfully.
    Delivered,
    /// The latest attempt failed; a retry may follow.
    Failed,
    /// Retries exhausted; delivery was given up.
    Abandoned,
}

/// Record of an external webhook delivery attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookDeliveryRecord {
    /// Unique identifier of this delivery.
    pub delivery_id: u64,
    /// Endpoint the payload is delivered to.
    pub target_url: String,
    /// The payload being delivered.
    pub payload: WebhookPayload,
    /// Number of attempts made so far.
    pub attempts: u32,
    /// Maximum number of retries allowed.
    pub max_retries: u32,
    /// Current delivery status.
    pub status: DeliveryStatus,
    /// HTTP status code of the last attempt, if any.
    pub last_status_code: Option<u16>,
    /// Error message of the last attempt, if any.
    pub last_error: Option<String>,
    /// Time of the last attempt in Unix milliseconds.
    pub last_attempt_ms: Option<u64>,
}

/// Configuration for webhook dispatcher.
#[derive(Debug, Clone)]
pub struct WebhookConfig {
    /// Endpoints to deliver events to.
    pub target_urls: Vec<String>,
    /// Maximum number of retries per delivery.
    pub max_retries: u32,
    /// Delay before the first retry; later retries back off from this.
    pub initial_backoff: Duration,
    /// Maximum number of queued deliveries retained.
    pub max_queue_size: usize,
    /// Optional secret used to sign delivery payloads.
    pub signing_secret: Option<String>,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            target_urls: Vec::new(),
            max_retries: 3,
            initial_backoff: Duration::from_millis(500),
            max_queue_size: 1000,
            signing_secret: None,
        }
    }
}

/// Thread-safe webhook queue and dispatcher.
#[derive(Debug, Clone)]
pub struct WebhookDispatcher {
    config: WebhookConfig,
    state: Arc<RwLock<WebhookState>>,
}

#[derive(Debug)]
struct WebhookState {
    next_delivery_id: u64,
    queue: VecDeque<WebhookDeliveryRecord>,
    history: VecDeque<WebhookDeliveryRecord>,
}

impl WebhookDispatcher {
    /// Creates a dispatcher with the given configuration.
    #[must_use]
    pub fn new(config: WebhookConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(WebhookState {
                next_delivery_id: 1,
                queue: VecDeque::new(),
                history: VecDeque::new(),
            })),
        }
    }

    /// Enqueues a payment lifecycle event for all registered webhook targets.
    #[must_use]
    pub fn enqueue_event(
        &self,
        event_type: WebhookEventType,
        payer: Option<String>,
        network: Option<String>,
        amount_atomic: Option<String>,
        tx_hash: Option<String>,
        request_path: Option<String>,
    ) -> Vec<u64> {
        // A zero-capacity queue must schedule nothing. Without this guard the
        // check below is `0 >= 0` on an empty queue, `pop_front()` is a no-op,
        // and the `push_back` still leaves one pending delivery: the caller
        // gets a delivery id that silently ignores the configured bound.
        if self.config.max_queue_size == 0 {
            return Vec::new();
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let event_id = format!("evt_{}_{}", now, fastrand_hex(8));
        let payload = WebhookPayload {
            event_id,
            event_type,
            timestamp_ms: now,
            payer,
            network,
            amount_atomic,
            tx_hash,
            request_path,
        };

        let mut delivery_ids = Vec::new();
        let mut state = self.state.write().expect("lock poisoned");

        for target in &self.config.target_urls {
            let delivery_id = state.next_delivery_id;
            state.next_delivery_id += 1;

            let record = WebhookDeliveryRecord {
                delivery_id,
                target_url: target.clone(),
                payload: payload.clone(),
                attempts: 0,
                max_retries: self.config.max_retries,
                status: DeliveryStatus::Pending,
                last_status_code: None,
                last_error: None,
                last_attempt_ms: None,
            };

            if state.queue.len() >= self.config.max_queue_size {
                if let Some(evicted) = state.queue.pop_front() {
                    // The caller was handed this delivery_id by an earlier
                    // enqueue_event call and will never receive a result for
                    // it: dropping it without a trace loses the notification
                    // entirely. Park it in history as abandoned so the loss is
                    // observable. Reuse `Abandoned` rather than adding an enum
                    // variant, which would break downstream exhaustive matches.
                    let mut evicted = evicted;
                    evicted.status = DeliveryStatus::Abandoned;
                    evicted.last_error = Some("evicted: webhook queue full".into());
                    if state.history.len() >= self.config.max_queue_size {
                        state.history.pop_front();
                    }
                    state.history.push_back(evicted);
                }
            }
            state.queue.push_back(record);
            delivery_ids.push(delivery_id);
        }

        delivery_ids
    }

    /// Records the result of a delivery attempt.
    #[must_use]
    pub fn record_attempt_result(
        &self,
        delivery_id: u64,
        success: bool,
        status_code: Option<u16>,
        error_msg: Option<String>,
    ) -> Option<WebhookDeliveryRecord> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let mut state = self.state.write().expect("lock poisoned");
        if let Some(pos) = state
            .queue
            .iter()
            .position(|r| r.delivery_id == delivery_id)
        {
            let mut record = state.queue.remove(pos).unwrap();
            record.attempts += 1;
            record.last_attempt_ms = Some(now);
            record.last_status_code = status_code;
            record.last_error = error_msg;

            if success {
                record.status = DeliveryStatus::Delivered;
                if state.history.len() >= self.config.max_queue_size {
                    state.history.pop_front();
                }
                state.history.push_back(record.clone());
                Some(record)
            } else if record.attempts > record.max_retries {
                record.status = DeliveryStatus::Abandoned;
                if state.history.len() >= self.config.max_queue_size {
                    state.history.pop_front();
                }
                state.history.push_back(record.clone());
                Some(record)
            } else {
                record.status = DeliveryStatus::Failed;
                state.queue.push_back(record.clone());
                Some(record)
            }
        } else {
            None
        }
    }

    /// Number of pending deliveries in queue.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        let state = self.state.read().expect("lock poisoned");
        state.queue.len()
    }

    /// Number of completed deliveries in history.
    #[must_use]
    pub fn history_count(&self) -> usize {
        let state = self.state.read().expect("lock poisoned");
        state.history.len()
    }

    /// Completed and abandoned deliveries, oldest first.
    ///
    /// Includes deliveries abandoned because a full queue evicted them, so a
    /// caller holding an old `delivery_id` can find out what happened to it.
    #[must_use]
    pub fn history(&self) -> Vec<WebhookDeliveryRecord> {
        let state = self.state.read().expect("lock poisoned");
        state.history.iter().cloned().collect()
    }
}

fn fastrand_hex(len: usize) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    SystemTime::now().hash(&mut hasher);
    let val = hasher.finish();
    format!("{val:016x}")[..len.min(16)].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webhook_enqueue_and_delivery() {
        let config = WebhookConfig {
            target_urls: vec!["https://example.com/webhook".into()],
            max_retries: 2,
            initial_backoff: Duration::from_millis(100),
            max_queue_size: 50,
            signing_secret: Some("secret-key".into()),
        };

        let dispatcher = WebhookDispatcher::new(config);
        let ids = dispatcher.enqueue_event(
            WebhookEventType::PaymentSettled,
            Some("0x1234".into()),
            Some("kite-mainnet".into()),
            Some("5000000".into()),
            Some("0xabc...".into()),
            Some("/v1/data".into()),
        );

        assert_eq!(ids.len(), 1);
        assert_eq!(dispatcher.pending_count(), 1);

        let delivery = dispatcher.record_attempt_result(ids[0], true, Some(200), None);
        assert!(delivery.is_some());
        assert_eq!(delivery.unwrap().status, DeliveryStatus::Delivered);
        assert_eq!(dispatcher.pending_count(), 0);
        assert_eq!(dispatcher.history_count(), 1);
    }

    #[test]
    fn test_webhook_retry_and_abandonment() {
        let config = WebhookConfig {
            target_urls: vec!["https://example.com/webhook".into()],
            max_retries: 1,
            ..Default::default()
        };

        let dispatcher = WebhookDispatcher::new(config);
        let ids = dispatcher.enqueue_event(
            WebhookEventType::PaymentFailed,
            None,
            None,
            None,
            None,
            None,
        );

        // First attempt fails -> requeued
        let d1 =
            dispatcher.record_attempt_result(ids[0], false, Some(500), Some("Server error".into()));
        assert_eq!(d1.unwrap().status, DeliveryStatus::Failed);
        assert_eq!(dispatcher.pending_count(), 1);

        // Second attempt fails (exceeds max_retries = 1) -> Abandoned
        let d2 =
            dispatcher.record_attempt_result(ids[0], false, Some(500), Some("Server error".into()));
        assert_eq!(d2.unwrap().status, DeliveryStatus::Abandoned);
        assert_eq!(dispatcher.pending_count(), 0);
        assert_eq!(dispatcher.history_count(), 1);
    }

    #[test]
    fn zero_queue_capacity_never_schedules_a_delivery() {
        let dispatcher = WebhookDispatcher::new(WebhookConfig {
            target_urls: vec!["https://example.com/webhook".into()],
            max_queue_size: 0,
            ..Default::default()
        });

        let ids = dispatcher.enqueue_event(
            WebhookEventType::PaymentSettled,
            None,
            None,
            Some("1000".into()),
            None,
            None,
        );

        assert!(
            ids.is_empty(),
            "a queue configured with zero capacity must not hand out delivery ids"
        );
        assert_eq!(
            dispatcher.pending_count(),
            0,
            "max_queue_size = 0 was silently exceeded"
        );
        assert_eq!(dispatcher.history_count(), 0);
    }

    #[test]
    fn evicting_a_pending_delivery_leaves_an_audit_record() {
        let dispatcher = WebhookDispatcher::new(WebhookConfig {
            target_urls: vec!["https://example.com/webhook".into()],
            max_queue_size: 1,
            max_retries: 3,
            ..Default::default()
        });

        let first = dispatcher.enqueue_event(
            WebhookEventType::PaymentPrompted,
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(dispatcher.pending_count(), 1);

        // The first delivery id was already returned to the caller. Evicting it
        // must not erase every trace of it.
        let _second = dispatcher.enqueue_event(
            WebhookEventType::PaymentSettled,
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(dispatcher.pending_count(), 1);
        assert_eq!(
            dispatcher.history_count(),
            1,
            "the evicted delivery disappeared without any audit record"
        );

        let history = dispatcher.history();
        let evicted = history
            .iter()
            .find(|record| record.delivery_id == first[0])
            .expect("the evicted delivery must be inspectable in history");
        assert_eq!(evicted.status, DeliveryStatus::Abandoned);
        assert_eq!(evicted.attempts, 0);
        assert!(
            evicted
                .last_error
                .as_deref()
                .is_some_and(|error| error.contains("queue")),
            "the reason for abandoning it must be recorded"
        );
    }

    fn dispatcher(targets: &[&str], max_retries: u32, max_queue_size: usize) -> WebhookDispatcher {
        WebhookDispatcher::new(WebhookConfig {
            target_urls: targets.iter().map(|target| (*target).to_owned()).collect(),
            max_retries,
            max_queue_size,
            ..Default::default()
        })
    }

    fn enqueue(dispatcher: &WebhookDispatcher) -> Vec<u64> {
        dispatcher.enqueue_event(
            WebhookEventType::PaymentSettled,
            None,
            None,
            None,
            None,
            None,
        )
    }

    #[test]
    fn one_event_fans_out_to_every_target_with_distinct_delivery_ids() {
        let dispatcher = dispatcher(&["https://a.example/hook", "https://b.example/hook"], 3, 10);
        let ids = enqueue(&dispatcher);
        assert_eq!(ids.len(), 2);
        assert_ne!(ids[0], ids[1]);
        assert_eq!(dispatcher.pending_count(), 2);

        let first = dispatcher
            .record_attempt_result(ids[0], true, Some(200), None)
            .unwrap();
        let second = dispatcher
            .record_attempt_result(ids[1], true, Some(204), None)
            .unwrap();
        assert_eq!(first.target_url, "https://a.example/hook");
        assert_eq!(second.target_url, "https://b.example/hook");
        assert_eq!(
            first.payload.event_id, second.payload.event_id,
            "one event, two deliveries"
        );
    }

    #[test]
    fn no_targets_means_nothing_is_queued() {
        let dispatcher = dispatcher(&[], 3, 10);
        assert!(enqueue(&dispatcher).is_empty());
        assert_eq!(dispatcher.pending_count(), 0);
    }

    #[test]
    fn unknown_or_finished_delivery_ids_are_ignored() {
        let dispatcher = dispatcher(&["https://a.example/hook"], 3, 10);
        assert!(dispatcher
            .record_attempt_result(999, true, Some(200), None)
            .is_none());

        let id = enqueue(&dispatcher)[0];
        assert!(dispatcher
            .record_attempt_result(id, true, Some(200), None)
            .is_some());
        assert!(
            dispatcher
                .record_attempt_result(id, true, Some(200), None)
                .is_none(),
            "a delivered record must not be accepted twice"
        );
        assert_eq!(dispatcher.history_count(), 1);
    }

    #[test]
    fn attempt_results_are_recorded_and_cleared_on_success() {
        let dispatcher = dispatcher(&["https://a.example/hook"], 3, 10);
        let id = enqueue(&dispatcher)[0];

        let failed = dispatcher
            .record_attempt_result(id, false, Some(503), Some("unavailable".into()))
            .unwrap();
        assert_eq!(failed.status, DeliveryStatus::Failed);
        assert_eq!(failed.attempts, 1);
        assert_eq!(failed.last_status_code, Some(503));
        assert_eq!(failed.last_error.as_deref(), Some("unavailable"));
        assert!(failed.last_attempt_ms.is_some());

        let delivered = dispatcher
            .record_attempt_result(id, true, Some(200), None)
            .unwrap();
        assert_eq!(delivered.status, DeliveryStatus::Delivered);
        assert_eq!(delivered.attempts, 2);
        assert_eq!(delivered.last_status_code, Some(200));
        assert!(
            delivered.last_error.is_none(),
            "stale error must not survive a success"
        );
    }

    #[test]
    fn a_delivery_is_abandoned_after_max_retries_plus_the_first_attempt() {
        let dispatcher = dispatcher(&["https://a.example/hook"], 2, 10);
        let id = enqueue(&dispatcher)[0];
        for expected in [
            DeliveryStatus::Failed,
            DeliveryStatus::Failed,
            DeliveryStatus::Abandoned,
        ] {
            let record = dispatcher
                .record_attempt_result(id, false, Some(500), None)
                .unwrap();
            assert_eq!(record.status, expected);
        }
        assert_eq!(dispatcher.pending_count(), 0);
        assert_eq!(dispatcher.history_count(), 1);
    }

    #[test]
    fn a_full_queue_drops_the_oldest_pending_delivery() {
        let dispatcher = dispatcher(&["https://a.example/hook"], 3, 2);
        let first = enqueue(&dispatcher)[0];
        let second = enqueue(&dispatcher)[0];
        let third = enqueue(&dispatcher)[0];
        assert_eq!(dispatcher.pending_count(), 2);
        assert!(dispatcher
            .record_attempt_result(first, true, Some(200), None)
            .is_none());
        assert!(dispatcher
            .record_attempt_result(second, true, Some(200), None)
            .is_some());
        assert!(dispatcher
            .record_attempt_result(third, true, Some(200), None)
            .is_some());
    }

    #[test]
    fn history_is_bounded_and_keeps_the_newest_records() {
        let dispatcher = dispatcher(&["https://a.example/hook"], 0, 2);
        let mut delivered_ids = Vec::new();
        for _ in 0..5 {
            let id = enqueue(&dispatcher)[0];
            assert!(dispatcher
                .record_attempt_result(id, true, Some(200), None)
                .is_some());
            delivered_ids.push(id);
        }

        assert_eq!(dispatcher.history_count(), 2);
        let history = dispatcher.history();
        assert_eq!(history[0].delivery_id, delivered_ids[3]);
        assert_eq!(history[1].delivery_id, delivered_ids[4]);
    }
}
