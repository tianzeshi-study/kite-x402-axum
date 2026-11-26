use std::{
    env,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::{OriginalUri, Request, State},
    middleware::Next,
    response::Response,
};
use kite_x402_axum::{
    sign_payload, webhook::PaymentEvent, DeliveryStatus, WebhookConfig, WebhookDispatcher,
    SIGNATURE_HEADER, TIMESTAMP_HEADER,
};
use tokio::{
    sync::{watch, Notify},
    task::JoinHandle,
    time::sleep,
};

const TARGETS_ENV: &str = "WEBHOOK_URLS";
const SECRET_ENV: &str = "WEBHOOK_SIGNING_SECRET";
const MAX_TARGETS: usize = 16;
const MAX_QUEUE_SIZE: usize = 1000;
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct WebhookRuntime {
    dispatcher: Arc<WebhookDispatcher>,
    client: reqwest::Client,
    secret: String,
    notify: Arc<Notify>,
}

impl WebhookRuntime {
    pub(crate) fn from_env() -> Result<Option<Arc<Self>>, String> {
        let targets = env::var(TARGETS_ENV).unwrap_or_default();
        let targets = targets
            .split(',')
            .map(str::trim)
            .filter(|target| !target.is_empty())
            .map(validate_target)
            .collect::<Result<Vec<_>, _>>()?;
        if targets.is_empty() {
            return Ok(None);
        }
        if targets.len() > MAX_TARGETS {
            return Err(format!(
                "{TARGETS_ENV} supports at most {MAX_TARGETS} endpoints"
            ));
        }

        let secret = env::var(SECRET_ENV)
            .map_err(|_| format!("{SECRET_ENV} is required when {TARGETS_ENV} is configured"))?;
        if secret.trim().len() < 32 {
            return Err(format!(
                "{SECRET_ENV} must contain at least 32 non-whitespace bytes"
            ));
        }

        let dispatcher = WebhookDispatcher::new(WebhookConfig {
            target_urls: targets,
            max_retries: 3,
            initial_backoff: Duration::from_millis(500),
            max_queue_size: MAX_QUEUE_SIZE,
            signing_secret: Some(secret.clone()),
        });
        let client = reqwest::Client::builder()
            .timeout(DELIVERY_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| "could not create webhook HTTP client".to_owned())?;

        Ok(Some(Arc::new(Self {
            dispatcher: Arc::new(dispatcher),
            client,
            secret,
            notify: Arc::new(Notify::new()),
        })))
    }

    pub(crate) fn spawn_worker(
        self: Arc<Self>,
        mut shutdown: watch::Receiver<bool>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                if *shutdown.borrow() {
                    break;
                }
                if let Some(delivery) = self.dispatcher.claim_next_pending() {
                    self.deliver(delivery).await;
                    continue;
                }

                let delay = self
                    .dispatcher
                    .next_retry_delay()
                    .unwrap_or(Duration::from_secs(3600));
                tokio::select! {
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            break;
                        }
                    }
                    _ = self.notify.notified() => {}
                    _ = sleep(delay) => {}
                }
            }
        })
    }

    async fn deliver(&self, delivery: kite_x402_axum::WebhookDeliveryRecord) {
        let body = serde_json::to_vec(&delivery.payload)
            .expect("webhook payload serialization cannot fail");
        let timestamp = unix_time_secs();
        let signature = sign_payload(&self.secret, timestamp, &body);
        let response = self
            .client
            .post(&delivery.target_url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(SIGNATURE_HEADER, signature)
            .header(TIMESTAMP_HEADER, timestamp.to_string())
            .body(body)
            .send()
            .await;

        let (success, status, error) = match response {
            Ok(response) => {
                let status = response.status().as_u16();
                if response.status().is_success() {
                    (true, Some(status), None)
                } else {
                    (
                        false,
                        Some(status),
                        Some("webhook endpoint returned a non-success status".to_owned()),
                    )
                }
            }
            Err(_) => (false, None, Some("webhook request failed".to_owned())),
        };
        let result =
            self.dispatcher
                .record_attempt_result(delivery.delivery_id, success, status, error);
        if let Some(result) = result {
            match result.status {
                DeliveryStatus::Delivered => tracing::info!(
                    delivery_id = result.delivery_id,
                    attempts = result.attempts,
                    "Webhook delivered"
                ),
                DeliveryStatus::Abandoned => tracing::warn!(
                    delivery_id = result.delivery_id,
                    attempts = result.attempts,
                    "Webhook delivery abandoned"
                ),
                DeliveryStatus::Failed => tracing::warn!(
                    delivery_id = result.delivery_id,
                    attempts = result.attempts,
                    "Webhook delivery attempt failed"
                ),
                DeliveryStatus::Pending => {}
            }
        }
    }
}

pub(crate) async fn observe_payment_events(
    State(runtime): State<Arc<WebhookRuntime>>,
    OriginalUri(uri): OriginalUri,
    request: Request,
    next: Next,
) -> Response {
    let path = uri.path().to_owned();
    let mut response = next.run(request).await;
    if let Some(event) = response.extensions_mut().remove::<PaymentEvent>() {
        let delivery_ids = runtime.dispatcher.enqueue_event(
            event.event_type,
            event.payer,
            event.network,
            event.amount_atomic,
            event.tx_hash,
            Some(path),
        );
        if !delivery_ids.is_empty() {
            runtime.notify.notify_one();
        }
    }
    response
}

fn validate_target(target: &str) -> Result<String, String> {
    let url = reqwest::Url::parse(target)
        .map_err(|_| format!("{TARGETS_ENV} contains an invalid URL"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(format!(
            "{TARGETS_ENV} endpoints must be absolute HTTP(S) URLs without credentials or fragments"
        ));
    }
    Ok(target.to_owned())
}

fn unix_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_targets_require_absolute_http_urls_without_credentials() {
        assert!(validate_target("https://hooks.example.com/events").is_ok());
        assert!(validate_target("http://127.0.0.1:9000/events").is_ok());
        assert!(validate_target("file:///tmp/hook").is_err());
        assert!(validate_target("https://user:pass@hooks.example.com/events").is_err());
        assert!(validate_target("https://hooks.example.com/events#fragment").is_err());
    }
}
