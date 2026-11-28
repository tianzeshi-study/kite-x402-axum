//! Environment configuration for webhook delivery.
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `WEBHOOK_URLS` | unset (off) | Comma-separated `http(s)` endpoints that receive payment events. |
//! | `WEBHOOK_SECRET` | unset | HMAC-SHA256 signing secret, at least 16 characters. |
//! | `WEBHOOK_MAX_RETRIES` | `5` | Retries after the first attempt, `0..=20`. |

use kite_x402_axum::WebhookConfig;

/// Most webhook targets accepted, to bound per-event queue fan-out.
const MAX_TARGETS: usize = 16;
const MIN_SECRET_LEN: usize = 16;
const MAX_RETRIES_LIMIT: u32 = 20;
const DEFAULT_MAX_RETRIES: u32 = 5;

/// Validated webhook settings.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct WebhookSettings {
    pub(crate) urls: Vec<String>,
    pub(crate) secret: Option<String>,
    pub(crate) max_retries: u32,
}

impl WebhookSettings {
    /// Reads and validates the settings through `lookup` (normally the process
    /// environment). `Ok(None)` means webhooks are off. Any present-but-invalid
    /// value is an error rather than being ignored, so a typo cannot silently
    /// disable delivery or weaken signing.
    pub(crate) fn from_lookup(
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<Option<Self>, String> {
        let get = |key: &str| {
            lookup(key)
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        };

        let Some(raw_urls) = get("WEBHOOK_URLS") else {
            for key in ["WEBHOOK_SECRET", "WEBHOOK_MAX_RETRIES"] {
                if get(key).is_some() {
                    return Err(format!("{key} is set but WEBHOOK_URLS is not"));
                }
            }
            return Ok(None);
        };

        let mut urls: Vec<String> = Vec::new();
        for entry in raw_urls.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let parsed = reqwest::Url::parse(entry)
                .map_err(|_| "WEBHOOK_URLS must contain valid http(s) URLs".to_owned())?;
            if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
                return Err("WEBHOOK_URLS must contain valid http(s) URLs".into());
            }
            let normalized = parsed.to_string();
            if !urls.contains(&normalized) {
                urls.push(normalized);
            }
        }
        if urls.is_empty() {
            return Err("WEBHOOK_URLS must contain at least one URL".into());
        }
        if urls.len() > MAX_TARGETS {
            return Err(format!("WEBHOOK_URLS accepts at most {MAX_TARGETS} URLs"));
        }

        let secret = get("WEBHOOK_SECRET");
        if let Some(secret) = &secret {
            if secret.chars().count() < MIN_SECRET_LEN {
                return Err(format!(
                    "WEBHOOK_SECRET must be at least {MIN_SECRET_LEN} characters"
                ));
            }
        }

        let max_retries = match get("WEBHOOK_MAX_RETRIES") {
            None => DEFAULT_MAX_RETRIES,
            Some(raw) => raw
                .parse::<u32>()
                .ok()
                .filter(|n| *n <= MAX_RETRIES_LIMIT)
                .ok_or_else(|| {
                    format!(
                        "WEBHOOK_MAX_RETRIES must be an integer between 0 and {MAX_RETRIES_LIMIT}"
                    )
                })?,
        };

        Ok(Some(Self {
            urls,
            secret,
            max_retries,
        }))
    }

    /// URLs that use plain `http` towards a non-loopback host: events would
    /// cross the network unencrypted. Reported as a startup warning.
    pub(crate) fn insecure_targets(&self) -> usize {
        self.urls
            .iter()
            .filter_map(|u| reqwest::Url::parse(u).ok())
            .filter(|u| {
                u.scheme() == "http"
                    && !matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
            })
            .count()
    }

    pub(crate) fn into_config(self) -> WebhookConfig {
        WebhookConfig {
            target_urls: self.urls,
            max_retries: self.max_retries,
            signing_secret: self.secret,
            ..WebhookConfig::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn parse(pairs: &[(&str, &str)]) -> Result<Option<WebhookSettings>, String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        WebhookSettings::from_lookup(|k| map.get(k).cloned())
    }

    #[test]
    fn unset_or_blank_means_off() {
        assert_eq!(parse(&[]), Ok(None));
        assert_eq!(parse(&[("WEBHOOK_URLS", "  ")]), Ok(None));
    }

    #[test]
    fn urls_are_split_trimmed_normalized_and_deduplicated() {
        let s = parse(&[(
            "WEBHOOK_URLS",
            " https://a.example/hook , https://a.example/hook,https://b.example ",
        )])
        .unwrap()
        .unwrap();
        assert_eq!(s.urls, ["https://a.example/hook", "https://b.example/"]);
        assert_eq!(s.max_retries, 5);
        assert_eq!(s.secret, None);
    }

    #[test]
    fn invalid_urls_are_rejected_without_echoing_them() {
        for bad in [
            "nope",
            "ftp://a.example",
            "file:///etc/passwd",
            "https://",
            "a.example/hook",
        ] {
            let err = parse(&[("WEBHOOK_URLS", &format!("https://ok.example,{bad}"))]).unwrap_err();
            assert_eq!(err, "WEBHOOK_URLS must contain valid http(s) URLs", "{bad}");
        }
        let err = parse(&[("WEBHOOK_URLS", "https://u:SECRET@x.example, nope")]).unwrap_err();
        assert!(!err.contains("SECRET"));
    }

    #[test]
    fn a_comma_only_list_is_an_error_and_the_target_count_is_bounded() {
        assert!(parse(&[("WEBHOOK_URLS", " , ,")]).is_err());
        let many = (0..17)
            .map(|i| format!("https://h{i}.example"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(parse(&[("WEBHOOK_URLS", &many)])
            .unwrap_err()
            .contains("at most 16"));
        let ok = (0..16)
            .map(|i| format!("https://h{i}.example"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            parse(&[("WEBHOOK_URLS", &ok)]).unwrap().unwrap().urls.len(),
            16
        );
    }

    #[test]
    fn secret_must_be_long_enough_and_is_never_echoed() {
        let short = "short-secret";
        let err = parse(&[
            ("WEBHOOK_URLS", "https://a.example"),
            ("WEBHOOK_SECRET", short),
        ])
        .unwrap_err();
        assert!(err.contains("at least 16"));
        assert!(!err.contains(short));
        let ok = parse(&[
            ("WEBHOOK_URLS", "https://a.example"),
            ("WEBHOOK_SECRET", "0123456789abcdef"),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(ok.secret.as_deref(), Some("0123456789abcdef"));
    }

    #[test]
    fn max_retries_accepts_zero_to_twenty_only() {
        for (raw, ok) in [
            ("0", true),
            ("20", true),
            ("21", false),
            ("-1", false),
            ("x", false),
            ("1.5", false),
        ] {
            let r = parse(&[
                ("WEBHOOK_URLS", "https://a.example"),
                ("WEBHOOK_MAX_RETRIES", raw),
            ]);
            assert_eq!(r.is_ok(), ok, "{raw}");
        }
    }

    #[test]
    fn options_without_urls_are_a_configuration_error() {
        for key in ["WEBHOOK_SECRET", "WEBHOOK_MAX_RETRIES"] {
            let err = parse(&[(key, "0123456789abcdef")]).unwrap_err();
            assert_eq!(err, format!("{key} is set but WEBHOOK_URLS is not"));
        }
    }

    #[test]
    fn plain_http_to_remote_hosts_is_counted_but_loopback_is_not() {
        let s = parse(&[(
            "WEBHOOK_URLS",
            "http://localhost:9/h,http://127.0.0.1:9/h,http://[::1]:9/h,http://hooks.internal/h,https://ok.example",
        )])
        .unwrap()
        .unwrap();
        assert_eq!(s.insecure_targets(), 1);
    }

    #[test]
    fn settings_convert_to_a_dispatcher_config() {
        let cfg = parse(&[
            ("WEBHOOK_URLS", "https://a.example"),
            ("WEBHOOK_SECRET", "0123456789abcdef"),
            ("WEBHOOK_MAX_RETRIES", "2"),
        ])
        .unwrap()
        .unwrap()
        .into_config();
        assert_eq!(cfg.target_urls, ["https://a.example/"]);
        assert_eq!(cfg.max_retries, 2);
        assert_eq!(cfg.signing_secret.as_deref(), Some("0123456789abcdef"));
    }
}
