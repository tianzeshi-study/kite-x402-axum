use std::{
    collections::{BTreeSet, HashMap, HashSet},
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
struct RoutePattern {
    segments: Vec<Option<String>>,
    price: RoutePrice,
}

impl RoutePattern {
    fn matches(&self, path: &str) -> bool {
        let mut segments = path.split('/');
        self.segments.iter().all(|expected| {
            segments.next().is_some_and(|actual| match expected {
                Some(literal) => literal == actual,
                None => !actual.is_empty(),
            })
        }) && segments.next().is_none()
    }

    fn overlaps(&self, segments: &[Option<String>]) -> bool {
        self.segments.len() == segments.len()
            && self
                .segments
                .iter()
                .zip(segments)
                .all(|(left, right)| match (left, right) {
                    (Some(left), Some(right)) => left == right,
                    (Some(literal), None) | (None, Some(literal)) => !literal.is_empty(),
                    (None, None) => true,
                })
    }
}

#[derive(Debug)]
pub(super) struct RoutePrices {
    default: Arc<PaymentConfig>,
    require_match: bool,
    overrides: HashMap<String, HashMap<Method, RoutePrice>>,
    patterns: HashMap<Method, Vec<RoutePattern>>,
    /// Default extras for routes without an explicit list.
    extras: Vec<PaymentOption>,
}

impl RoutePrices {
    pub(super) fn parse(
        value: &str,
        require_match: bool,
        default: Arc<PaymentConfig>,
        default_extras: Vec<PaymentOption>,
    ) -> Result<Self, String> {
        if !default_extras.is_empty() {
            let default_option = PaymentOption::new(default.chain, default.price_usd.clone());
            validate_payment_options(&default_option, &default_extras, "default payment options")?;
        }

        let mut overrides: HashMap<String, HashMap<Method, RoutePrice>> = HashMap::new();
        let mut patterns: HashMap<Method, Vec<RoutePattern>> = HashMap::new();
        if !value.trim().is_empty() {
            let rules: Vec<Rule> = serde_json::from_str(value).map_err(|err| err.to_string())?;
            for (index, rule) in rules.into_iter().enumerate() {
                // HTTP methods are case-sensitive and this router only ever sees
                // the canonical uppercase tokens, so a lowercase rule can never
                // match a request: it would silently fall back to the default
                // price. Reject it at parse time instead of mispricing traffic.
                if rule.method != rule.method.to_ascii_uppercase() {
                    return Err(format!(
                        "rule {} method must be an uppercase HTTP method token",
                        index + 1
                    ));
                }
                let method = Method::from_bytes(rule.method.as_bytes())
                    .map_err(|_| format!("rule {} has an invalid HTTP method", index + 1))?;
                let invalid_path = || {
                    format!(
                        "rule {} must specify a concrete HTTP method and a valid path under /v1/",
                        index + 1
                    )
                };
                if rule.method == "*" {
                    return Err(invalid_path());
                }
                let segments = if rule.path.contains(['{', '}']) {
                    Some(parse_path_pattern(&rule.path).ok_or_else(invalid_path)?)
                } else {
                    if !is_paid_path(&rule.path) {
                        return Err(invalid_path());
                    }
                    None
                };
                default
                    .chain
                    .parse_price(&rule.price)
                    .map_err(|err| format!("rule {} has an invalid USD price: {err}", index + 1))?;

                let extras = rule
                    .extra_payment_options
                    .map(|extras| parse_extra_options(extras, index + 1))
                    .transpose()?;
                let primary = Arc::new(PaymentConfig {
                    price_usd: rule.price,
                    ..default.as_ref().clone()
                });
                let effective_extras = extras.as_deref().unwrap_or(&default_extras);
                if !effective_extras.is_empty() {
                    let primary_option =
                        PaymentOption::new(primary.chain, primary.price_usd.clone());
                    validate_payment_options(
                        &primary_option,
                        effective_extras,
                        &format!("rule {} payment options", index + 1),
                    )?;
                }
                let price = RoutePrice { primary, extras };
                if let Some(segments) = segments {
                    let method_patterns = patterns.entry(method).or_default();
                    if method_patterns
                        .iter()
                        .any(|pattern| pattern.overlaps(&segments))
                    {
                        return Err(format!(
                            "rule {} overlaps an earlier path template for the same HTTP method",
                            index + 1
                        ));
                    }
                    method_patterns.push(RoutePattern { segments, price });
                } else if overrides
                    .entry(rule.path)
                    .or_default()
                    .insert(method, price)
                    .is_some()
                {
                    return Err(format!("rule {} duplicates a method and path", index + 1));
                }
            }
        }
        let prices = Self {
            default,
            require_match,
            overrides,
            patterns,
            extras: default_extras,
        };
        if require_match && !prices.has_overrides() {
            return Err("ROUTE_PRICES_REQUIRE_MATCH=true requires at least one route rule".into());
        }
        Ok(prices)
    }

    pub(super) fn advertised_networks(&self) -> Vec<&'static str> {
        // Routes can inherit default payment options, so include their networks.
        let route_extras = self
            .overrides
            .values()
            .flat_map(HashMap::values)
            .chain(
                self.patterns
                    .values()
                    .flatten()
                    .map(|pattern| &pattern.price),
            )
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
        !self.overrides.is_empty() || !self.patterns.is_empty()
    }

    fn price_for(&self, method: &Method, path: &str) -> Option<&RoutePrice> {
        self.overrides
            .get(path)
            .and_then(|methods| methods.get(method))
            .or_else(|| {
                let path = path.strip_prefix("/v1/")?;
                self.patterns
                    .get(method)?
                    .iter()
                    .find(|pattern| pattern.matches(path))
                    .map(|pattern| &pattern.price)
            })
    }
}

/// Reject duplicate wire-level payment requirements before serving a 402 challenge.
///
/// Prices are normalized to asset units so equivalent values such as `"0.05"`
/// and `"$0.05"` cannot appear as separate choices. Invalid prices are left to
/// the request-time validation used by the existing payment middleware.
pub(super) fn validate_payment_options(
    primary: &PaymentOption,
    extras: &[PaymentOption],
    context: &str,
) -> Result<(), String> {
    let mut seen = HashSet::new();
    for (index, option) in std::iter::once(primary).chain(extras.iter()).enumerate() {
        let Ok(amount) = option.chain.parse_price(&option.price_usd) else {
            continue;
        };
        let key = (option.chain.network, amount.asset, amount.amount);
        if !seen.insert(key) {
            return Err(format!(
                "{context} option {} duplicates an earlier payment option",
                index + 1
            ));
        }
    }
    Ok(())
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

fn parse_path_pattern(path: &str) -> Option<Vec<Option<String>>> {
    let mut validation_path = String::from("/v1");
    let mut segments = Vec::new();
    for segment in path.strip_prefix("/v1/")?.split('/') {
        validation_path.push('/');
        if let Some(name) = segment
            .strip_prefix('{')
            .and_then(|part| part.strip_suffix('}'))
        {
            let mut bytes = name.bytes();
            if !bytes
                .next()
                .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
                || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            {
                return None;
            }
            validation_path.push('x');
            segments.push(None);
        } else {
            validation_path.push_str(segment);
            segments.push(Some(segment.to_owned()));
        }
    }
    is_paid_path(&validation_path).then_some(segments)
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
    let route = prices.price_for(req.method(), uri.path());
    if prices.require_match && route.is_none() {
        return super::not_found().await.into_response();
    }
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
        webhooks: config.webhooks.clone(),
    });
    x402_payment_multi(State(multi), req, next).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> Arc<PaymentConfig> {
        Arc::new(PaymentConfig {
            pay_to: "0x2222222222222222222222222222222222222222".into(),
            chain: kite_chain_by_name("testnet").expect("testnet chain"),
            price_usd: "0.01".into(),
            description: "test".into(),
            facilitator: kite_x402_axum::facilitator::FacilitatorClient::new("http://127.0.0.1:9"),
            expiration_guard: None,
            metrics: None,
            nonce_guard: None,
            settlement_ledger: None,
        })
    }

    fn parse(rules: &str) -> Result<RoutePrices, String> {
        RoutePrices::parse(rules, false, default_config(), Vec::new())
    }

    #[test]
    fn uppercase_methods_keep_their_override() {
        let prices = parse(r#"[{"method":"GET","path":"/v1/premium","price":"0.05"}]"#)
            .expect("uppercase rule parses");
        let matched = prices
            .price_for(&Method::GET, "/v1/premium")
            .expect("GET /v1/premium has a rule");
        assert_eq!(matched.primary.price_usd, "0.05");
    }

    /// `Method::from_bytes` accepts any token, so `"get"` used to parse into a
    /// method no real request can carry: the rule silently never matched and
    /// the route was charged the default price. Fail at startup instead.
    #[test]
    fn lowercase_methods_are_rejected_instead_of_never_matching() {
        for method in ["get", "Get", "pOsT", "delete"] {
            let rules = format!(r#"[{{"method":"{method}","path":"/v1/premium","price":"0.05"}}]"#);
            let error = parse(&rules).expect_err(method);
            assert!(error.contains("uppercase HTTP method"), "{method}: {error}");
        }
    }

    /// The uppercase check must not reject the tokens that are already valid.
    #[test]
    fn standard_and_extension_methods_still_parse() {
        let rules = r#"[
            {"method":"POST","path":"/v1/jobs","price":"0.05"},
            {"method":"PURGE","path":"/v1/cache","price":"0.05"}
        ]"#;
        let prices = parse(rules).expect("uppercase methods parse");
        assert!(prices.price_for(&Method::POST, "/v1/jobs").is_some());
        assert!(prices
            .price_for(&Method::from_bytes(b"PURGE").unwrap(), "/v1/cache")
            .is_some());
    }
}
