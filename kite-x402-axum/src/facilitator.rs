//! A small HTTP client for the Kite facilitator's `/verify` and `/settle`
//! endpoints. Mirrors the request/response shape the TypeScript and Go
//! SDKs put on the wire: `POST {base}/verify` and `POST {base}/settle`
//! with `{x402Version, paymentPayload, paymentRequirements}`, JSON in,
//! JSON out.

use std::time::Duration;

use serde::Serialize;
use thiserror::Error;

use crate::types::{PaymentPayload, PaymentRequirements, SettleResponse, VerifyResponse};

/// Default per-request timeout for facilitator HTTP calls.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// A facilitator call failed at the transport or protocol level (the
/// facilitator was unreachable, timed out, or returned something that
/// isn't a valid verify/settle response). This is distinct from the
/// facilitator successfully answering "payment invalid" or "settlement
/// failed", which are ordinary [`VerifyResponse`]/[`SettleResponse`]
/// values, not errors.
#[derive(Debug, Error)]
pub enum FacilitatorError {
    #[error("facilitator request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("facilitator {op} returned {status}: {body}")]
    BadResponse {
        op: &'static str,
        status: u16,
        body: String,
    },
}

/// HTTP client for one facilitator base URL (e.g.
/// `https://facilitator.pieverse.io/v2`, keeping the `/v2`: the facilitator
/// appends `/verify` and `/settle` to whatever base URL it is given).
#[derive(Clone, Debug)]
pub struct FacilitatorClient {
    http: reqwest::Client,
    base_url: String,
}

#[derive(Serialize)]
struct FacilitatorRequest<'a> {
    #[serde(rename = "x402Version")]
    x402_version: u32,
    #[serde(rename = "paymentPayload")]
    payment_payload: &'a PaymentPayload,
    #[serde(rename = "paymentRequirements")]
    payment_requirements: &'a PaymentRequirements,
}

impl FacilitatorClient {
    /// Returns the facilitator base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Builds a client for `base_url` with [`DEFAULT_TIMEOUT`].
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::with_timeout(base_url, DEFAULT_TIMEOUT)
    }

    /// Builds a client for `base_url` with a custom per-request timeout.
    pub fn with_timeout(base_url: impl Into<String>, timeout: Duration) -> Self {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .expect("reqwest client with default TLS backend");
        Self {
            http,
            base_url: base_url.into().trim_end_matches('/').to_string(),
        }
    }

    /// Calls `POST {base_url}/verify`.
    pub async fn verify(
        &self,
        payload: &PaymentPayload,
        requirements: &PaymentRequirements,
    ) -> Result<VerifyResponse, FacilitatorError> {
        self.call("verify", payload, requirements).await
    }

    /// Calls `POST {base_url}/settle`.
    pub async fn settle(
        &self,
        payload: &PaymentPayload,
        requirements: &PaymentRequirements,
    ) -> Result<SettleResponse, FacilitatorError> {
        self.call("settle", payload, requirements).await
    }

    async fn call<T: serde::de::DeserializeOwned>(
        &self,
        op: &'static str,
        payload: &PaymentPayload,
        requirements: &PaymentRequirements,
    ) -> Result<T, FacilitatorError> {
        let body = FacilitatorRequest {
            x402_version: payload.x402_version,
            payment_payload: payload,
            payment_requirements: requirements,
        };

        let url = format!("{}/{op}", self.base_url);
        tracing::debug!(op = %op, url = %url, "Sending HTTP request to facilitator");

        let response = match self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(err) => {
                tracing::error!(op = %op, url = %url, error = %err, "Facilitator HTTP request failed");
                return Err(FacilitatorError::Request(err));
            }
        };

        let status = response.status();
        let text = response.text().await.unwrap_or_default();

        if !status.is_success() {
            tracing::warn!(
                op = %op,
                url = %url,
                status = status.as_u16(),
                body = %text,
                "Facilitator returned non-success HTTP status"
            );
            return Err(FacilitatorError::BadResponse {
                op,
                status: status.as_u16(),
                body: text,
            });
        }

        tracing::debug!(
            op = %op,
            url = %url,
            status = status.as_u16(),
            "Facilitator returned success HTTP status"
        );

        serde_json::from_str(&text).map_err(|e| {
            tracing::error!(
                op = %op,
                url = %url,
                status = status.as_u16(),
                error = %e,
                body = %text,
                "Failed to parse facilitator JSON response"
            );
            FacilitatorError::BadResponse {
                op,
                status: status.as_u16(),
                body: format!("could not parse facilitator {op} response: {e}"),
            }
        })
    }
}
