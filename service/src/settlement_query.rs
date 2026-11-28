use std::{net::SocketAddrV4, sync::Arc};

use axum::{
    extract::{Path, Query, Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use kite_x402_axum::{
    settlement_ledger::LedgerSummary, SettlementLedger, SettlementReconciliation, SettlementRecord,
};

use crate::durable_settlement::{Attempt, DurableStore};
use serde::{Deserialize, Serialize};

pub(crate) fn configured_port() -> Result<Option<u16>, &'static str> {
    const INVALID: &str = "SETTLEMENT_QUERY_PORT must be an integer between 1 and 65535";
    let Some(value) = std::env::var_os("SETTLEMENT_QUERY_PORT") else {
        return Ok(None);
    };
    let value = value.to_str().ok_or(INVALID)?.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let port = value.parse::<u16>().map_err(|_| INVALID)?;
    if port == 0 {
        return Err(INVALID);
    }
    Ok(Some(port))
}

#[derive(Clone)]
pub(crate) enum Source {
    Local(Arc<SettlementLedger>),
    Durable(Arc<DurableStore>),
}

pub(crate) fn router(source: Source, addr: SocketAddrV4) -> Router {
    Router::new()
        .route("/settlements", get(recent))
        .route("/settlements/summary", get(summary))
        .route("/settlements/{network}/{transaction}", get(by_transaction))
        .with_state(source)
        .layer(middleware::from_fn_with_state(addr.to_string(), local_host))
}

async fn local_host(State(host): State<String>, request: Request, next: Next) -> Response {
    // 要求使用数字地址，防止浏览器通过 DNS 重绑定读取账本。
    let allowed = request.headers().get(header::HOST).is_some_and(|value| {
        value.as_bytes() == host.as_bytes()
            && request.headers().get_all(header::HOST).iter().count() == 1
    }) && request
        .uri()
        .authority()
        .is_none_or(|value| value.as_str() == host);
    let mut response = if allowed {
        next.run(request).await
    } else {
        StatusCode::FORBIDDEN.into_response()
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[derive(Serialize)]
struct Entry {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<i64>,
    network: String,
    asset: String,
    transaction: Option<String>,
    payer: String,
    pay_to: String,
    amount_atomic: Option<String>,
    timestamp_secs: u64,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reconciliation: Option<SettlementReconciliation>,
}

impl From<SettlementRecord> for Entry {
    fn from(record: SettlementRecord) -> Self {
        let transaction = record.tx_hash.trim();
        Self {
            id: None,
            network: record.network,
            asset: record.asset,
            transaction: (!transaction.is_empty()).then(|| transaction.to_owned()),
            payer: record.payer,
            pay_to: record.pay_to,
            amount_atomic: record.amount,
            timestamp_secs: record.timestamp_secs,
            status: if record.success {
                "reported_success"
            } else {
                "unconfirmed"
            }
            .to_owned(),
            reconciliation: None,
        }
    }
}

impl From<Attempt> for Entry {
    fn from(attempt: Attempt) -> Self {
        let payment = attempt.payment;
        Self {
            id: Some(attempt.id),
            network: payment.network.clone(),
            asset: payment.asset.clone(),
            transaction: attempt.transaction,
            payer: payment.payer.clone(),
            pay_to: payment.pay_to.clone(),
            amount_atomic: Some(payment.amount_atomic.clone()),
            timestamp_secs: u64::try_from(attempt.timestamp_secs).unwrap_or_default(),
            reconciliation: (attempt.state == "settling").then_some(payment),
            status: attempt.state,
        }
    }
}

fn query_error(error: &sqlx::Error) -> StatusCode {
    tracing::error!(%error, "Settlement journal query failed");
    StatusCode::SERVICE_UNAVAILABLE
}

async fn summary(State(source): State<Source>) -> Result<Json<LedgerSummary>, StatusCode> {
    match source {
        Source::Local(ledger) => Ok(Json(ledger.summary())),
        Source::Durable(store) => store
            .summary()
            .await
            .map(Json)
            .map_err(|error| query_error(&error)),
    }
}

#[derive(Deserialize)]
struct RecentQuery {
    limit: Option<usize>,
}

async fn recent(
    State(source): State<Source>,
    Query(query): Query<RecentQuery>,
) -> Result<Json<Vec<Entry>>, StatusCode> {
    let limit = query.limit.unwrap_or(20);
    if !(1..=100).contains(&limit) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let entries = match source {
        Source::Local(ledger) => ledger
            .recent_with_reconciliation(limit)
            .into_iter()
            .map(|(record, reconciliation)| Entry {
                reconciliation,
                ..Entry::from(record)
            })
            .collect(),
        Source::Durable(store) => store
            .recent(i64::try_from(limit).expect("validated limit"))
            .await
            .map_err(|error| query_error(&error))?
            .into_iter()
            .map(Entry::from)
            .collect(),
    };
    Ok(Json(entries))
}

async fn by_transaction(
    State(source): State<Source>,
    Path((network, transaction)): Path<(String, String)>,
) -> Result<Json<Entry>, StatusCode> {
    let network_valid = network.strip_prefix("eip155:").is_some_and(|chain_id| {
        (1..=32).contains(&chain_id.len()) && chain_id.bytes().all(|b| b.is_ascii_digit())
    });
    let transaction_valid = transaction
        .strip_prefix("0x")
        .or_else(|| transaction.strip_prefix("0X"))
        .is_some_and(|hash| hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()));
    if !network_valid || !transaction_valid {
        return Err(StatusCode::BAD_REQUEST);
    }
    let entry = match source {
        Source::Local(ledger) => ledger
            .get_by_network_tx(&network, &transaction)
            .map(Entry::from),
        Source::Durable(store) => store
            .by_transaction(&network, &transaction)
            .await
            .map_err(|error| query_error(&error))?
            .map(Entry::from),
    };
    entry.map(Json).ok_or(StatusCode::NOT_FOUND)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_preserves_amounts_above_u64_max() {
        let entry = Entry::from(SettlementRecord {
            tx_hash: "0xabc".into(),
            payer: "0xp".into(),
            pay_to: "0xq".into(),
            amount: Some("20000000000000000000".into()),
            asset: "0xtest".into(),
            network: "eip155:2368".into(),
            timestamp_secs: 1,
            success: true,
            error_reason: None,
        });
        assert_eq!(entry.amount_atomic.as_deref(), Some("20000000000000000000"));
    }
}
