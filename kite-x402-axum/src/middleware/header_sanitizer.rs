use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct HeaderSanitizerConfig {
    pub trusted_proxies: Vec<IpAddr>,
}

impl Default for HeaderSanitizerConfig {
    fn default() -> Self {
        Self {
            trusted_proxies: vec![
                "127.0.0.1".parse().unwrap(),
                "::1".parse().unwrap(),
            ],
        }
    }
}

pub struct HeaderSanitizer;

impl HeaderSanitizer {
    /// Resolves the actual client IP from request headers if the remote peer is trusted
    pub fn resolve_client_ip(
        peer_addr: IpAddr,
        forwarded_for: Option<&str>,
        cf_ip: Option<&str>,
        config: &HeaderSanitizerConfig,
    ) -> IpAddr {
        if !config.trusted_proxies.contains(&peer_addr) {
            return peer_addr;
        }

        if let Some(cf) = cf_ip {
            if let Ok(ip) = cf.trim().parse::<IpAddr>() {
                return ip;
            }
        }

        if let Some(xff) = forwarded_for {
            if let Some(first) = xff.split(',').next() {
                if let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }

        peer_addr
    }
}
