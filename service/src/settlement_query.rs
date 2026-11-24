use std::{net::SocketAddrV4, sync::Arc};

use axum::{
    extract::{Path, Query, Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use kite_x402_axum::{SettlementLedger, SettlementRecord};
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

pub(crate) fn router(ledger: Arc<SettlementLedger>, addr: SocketAddrV4) -> Router {
    Router::new()
        .route("/settlements", get(recent))
        .route("/settlements/{network}/{transaction}", get(by_transaction))
        .with_state(ledger)
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
    network: String,
    transaction: Option<String>,
    payer: String,
    pay_to: String,
    amount_atomic: Option<String>,
    timestamp_secs: u64,
    status: &'static str,
}

impl From<SettlementRecord> for Entry {
    fn from(record: SettlementRecord) -> Self {
        let transaction = record.tx_hash.trim();
        Self {
            network: record.network,
            transaction: (!transaction.is_empty()).then(|| transaction.to_owned()),
            payer: record.payer,
            pay_to: record.pay_to,
            // 账本将未知金额记作 0，并将超出范围的金额截为 u64::MAX。
            amount_atomic: (1..u64::MAX)
                .contains(&record.amount)
                .then(|| record.amount.to_string()),
            timestamp_secs: record.timestamp_secs,
            status: if record.success {
                "reported_success"
            } else {
                "unconfirmed"
            },
        }
    }
}

#[derive(Deserialize)]
struct RecentQuery {
    limit: Option<usize>,
}

async fn recent(
    State(ledger): State<Arc<SettlementLedger>>,
    Query(query): Query<RecentQuery>,
) -> Result<Json<Vec<Entry>>, StatusCode> {
    let limit = query.limit.unwrap_or(20);
    if !(1..=100).contains(&limit) {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(Json(
        ledger.recent(limit).into_iter().map(Entry::from).collect(),
    ))
}

async fn by_transaction(
    State(ledger): State<Arc<SettlementLedger>>,
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
    ledger
        .get_by_network_tx(&network, &transaction)
        .map(|record| Json(Entry::from(record)))
        .ok_or(StatusCode::NOT_FOUND)
}
