use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
};

use axum::{
    extract::{OriginalUri, Request, State},
    http::{uri::PathAndQuery, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use kite_x402_axum::{
    kite::kite_chain_by_name,
    middleware::{x402_payment, x402_payment_multi, MultiPaymentConfig, PaymentConfig},
    payment_options::PaymentOption,
};
use serde::{Deserialize, Deserializer};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    method: String,
    path: String,
    price: String,
    #[serde(default, deserialize_with = "deserialize_extra_options")]
    extra_payment_options: Option<Vec<ExtraOption>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExtraOption {
    network: String,
    price: String,
}

fn deserialize_extra_options<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<ExtraOption>>, D::Error> {
    // An omitted field inherits defaults. Require an explicit array when present.
    Vec::deserialize(deserializer).map(Some)
}

#[derive(Debug)]
struct RoutePrice {
    primary: Arc<PaymentConfig>,
    extras: Option<Vec<PaymentOption>>,
}

#[derive(Debug)]
pub(super) struct RoutePrices {
    default: Arc<PaymentConfig>,
    overrides: HashMap<String, HashMap<Method, RoutePrice>>,
    /// Default extras for routes without an explicit list.
    extras: Vec<PaymentOption>,
}

impl RoutePrices {
    pub(super) fn parse(
        value: &str,
        default: Arc<PaymentConfig>,
        extras: Vec<PaymentOption>,
    ) -> Result<Self, String> {
        let mut overrides: HashMap<String, HashMap<Method, RoutePrice>> = HashMap::new();
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

                let extras = rule
                    .extra_payment_options
                    .map(|extras| parse_extra_options(extras, index + 1))
                    .transpose()?;
                let price = RoutePrice {
                    primary: Arc::new(PaymentConfig {
                        price_usd: rule.price,
                        ..default.as_ref().clone()
                    }),
                    extras,
                };
                if overrides
                    .entry(rule.path)
                    .or_default()
                    .insert(method, price)
                    .is_some()
                {
                    return Err(format!("rule {} duplicates a method and path", index + 1));
                }
            }
        }
        Ok(Self {
            default,
            overrides,
            extras,
        })
    }

    pub(super) fn advertised_networks(&self) -> Vec<&'static str> {
        // Unmatched routes always retain the default options.
        let route_extras = self
            .overrides
            .values()
            .flat_map(HashMap::values)
            .filter_map(|route| route.extras.as_deref())
            .flatten();
        let networks: BTreeSet<_> = std::iter::once(self.default.chain.network)
            .chain(
                self.extras
                    .iter()
                    .chain(route_extras)
                    .map(|option| option.chain.network),
            )
            .collect();
        networks.into_iter().collect()
    }

    pub(super) fn has_overrides(&self) -> bool {
        !self.overrides.is_empty()
    }
}

fn parse_extra_options(
    extras: Vec<ExtraOption>,
    rule: usize,
) -> Result<Vec<PaymentOption>, String> {
    extras
        .into_iter()
        .enumerate()
        .map(|(index, extra)| {
            let network = extra.network.trim();
            let location = || format!("rule {rule} extra_payment_options entry {}", index + 1);
            if network.is_empty() {
                return Err(format!("{} needs a network", location()));
            }
            let chain =
                kite_chain_by_name(network).map_err(|err| format!("{}: {err}", location()))?;
            chain
                .parse_price(&extra.price)
                .map_err(|err| format!("{} has an invalid USD price: {err}", location()))?;
            Ok(PaymentOption::new(chain, extra.price))
        })
        .collect()
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
    let route = prices
        .overrides
        .get(uri.path())
        .and_then(|methods| methods.get(req.method()));
    let config = route.map_or(&prices.default, |route| &route.primary);
    let extras = route
        .and_then(|route| route.extras.as_deref())
        .unwrap_or(&prices.extras);
    if extras.is_empty() {
        return x402_payment(State(Arc::clone(config)), req, next).await;
    }
    // Use the same route options for the challenge, verification and settlement.
    let mut options = vec![PaymentOption::new(config.chain, config.price_usd.clone())];
    options.extend_from_slice(extras);
    let multi = Arc::new(MultiPaymentConfig {
        pay_to: config.pay_to.clone(),
        options,
        description: config.description.clone(),
        facilitator: config.facilitator.clone(),
        expiration_guard: config.expiration_guard,
        metrics: config.metrics.clone(),
        nonce_guard: config.nonce_guard.clone(),
        settlement_ledger: config.settlement_ledger.clone(),
    });
    x402_payment_multi(State(multi), req, next).await
}
