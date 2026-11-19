use std::{collections::HashMap, sync::Arc};

use axum::{
    extract::{OriginalUri, Request, State},
    http::{uri::PathAndQuery, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use kite_x402_axum::middleware::{x402_payment, PaymentConfig};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    method: String,
    path: String,
    price: String,
}

#[derive(Debug)]
pub(super) struct RoutePrices {
    default: Arc<PaymentConfig>,
    overrides: HashMap<String, HashMap<Method, Arc<PaymentConfig>>>,
}

impl RoutePrices {
    pub(super) fn parse(value: &str, default: Arc<PaymentConfig>) -> Result<Self, String> {
        let mut overrides: HashMap<String, HashMap<Method, Arc<PaymentConfig>>> = HashMap::new();
        if !value.trim().is_empty() {
            let rules: Vec<Rule> = serde_json::from_str(value).map_err(|err| err.to_string())?;
            for (index, rule) in rules.into_iter().enumerate() {
                let method = Method::from_bytes(rule.method.as_bytes())
                    .map_err(|_| format!("rule {} has an invalid HTTP method", index + 1))?;
                if rule.method == "*" || !is_paid_path(&rule.path) {
                    return Err(format!(
                        "rule {} must specify an exact HTTP method and path under /v1/",
                        index + 1
                    ));
                }
                default
                    .chain
                    .parse_price(&rule.price)
                    .map_err(|err| format!("rule {} has an invalid USD price: {err}", index + 1))?;

                let config = Arc::new(PaymentConfig {
                    price_usd: rule.price,
                    ..default.as_ref().clone()
                });
                if overrides
                    .entry(rule.path)
                    .or_default()
                    .insert(method, config)
                    .is_some()
                {
                    return Err(format!("rule {} duplicates a method and path", index + 1));
                }
            }
        }
        Ok(Self { default, overrides })
    }

    pub(super) fn has_overrides(&self) -> bool {
        !self.overrides.is_empty()
    }
}

fn is_paid_path(path: &str) -> bool {
    path.strip_prefix("/v1/")
        .is_some_and(|suffix| !suffix.is_empty())
        && is_encoded_path(path)
        && !path.contains('*')
        && path.parse::<PathAndQuery>().is_ok()
        && !path.split('/').any(|segment| {
            let decoded = segment.replace("%2e", ".").replace("%2E", ".");
            matches!(decoded.as_str(), "." | "..")
        })
}

fn is_encoded_path(path: &str) -> bool {
    // Reject characters that URL parsing would encode, strip, or treat as delimiters.
    path.bytes().all(|byte| {
        byte.is_ascii_graphic()
            && !matches!(
                byte,
                b'"' | b'<' | b'>' | b'`' | b'{' | b'}' | b'\\' | b'?' | b'#'
            )
    }) && path.match_indices('%').all(|(index, _)| {
        path.as_bytes()
            .get(index + 1..index + 3)
            .is_some_and(|digits| digits.iter().all(u8::is_ascii_hexdigit))
    })
}

pub(super) async fn route_payment(
    State(prices): State<Arc<RoutePrices>>,
    OriginalUri(uri): OriginalUri,
    req: Request,
    next: Next,
) -> Response {
    // Reject raw paths the proxy would rewrite before forwarding.
    if prices.has_overrides() && !is_encoded_path(uri.path()) {
        return (
            StatusCode::BAD_REQUEST,
            "request path must use URL encoding",
        )
            .into_response();
    }
    // Match the full public path before Axum strips the /v1 prefix.
    let config = prices
        .overrides
        .get(uri.path())
        .and_then(|methods| methods.get(req.method()))
        .unwrap_or(&prices.default);
    x402_payment(State(Arc::clone(config)), req, next).await
}
