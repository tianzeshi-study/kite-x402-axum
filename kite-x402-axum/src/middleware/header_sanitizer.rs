//! Explicit trusted-peer identity resolution. Configure proxies to overwrite identity headers.
use std::net::IpAddr;

/// Explicit peers allowed to supply sanitized forwarding headers.
#[derive(Debug, Clone, Default)]
pub struct HeaderSanitizerConfig {
    /// Proxy socket addresses. Empty means trust no forwarding headers.
    pub trusted_proxies: Vec<IpAddr>,
}

/// Resolves identities only from explicitly trusted peers.
#[derive(Debug)]
pub struct HeaderSanitizer;

impl HeaderSanitizer {
    /// Resolves the actual client IP from request headers if the remote peer is trusted
    #[must_use]
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
