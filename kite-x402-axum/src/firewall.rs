//! IP access control and firewall protection for x402 payment services.
//!
//! Provides allowlist and denylist enforcement with exact IP and CIDR prefix
//! matching to protect upstream resources and facilitator endpoints from malicious callers.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, RwLock};

/// The outcome of an IP firewall evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IpFilterAction {
    /// The IP is allowed through.
    Allow,
    /// The IP is denied.
    Deny,
}

/// A single firewall filtering rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallRule {
    /// Matches an exact IPv4 or IPv6 address.
    Exact(IpAddr),
    /// Matches an IPv4 CIDR subnet (network address and prefix length 0..=32).
    SubnetV4 {
        /// Network address of the subnet.
        network: Ipv4Addr,
        /// Prefix length (0..=32).
        prefix: u8,
    },
}

impl FirewallRule {
    /// Creates a CIDR subnet rule for IPv4.
    #[must_use]
    pub fn subnet_v4(network: Ipv4Addr, prefix: u8) -> Self {
        Self::SubnetV4 {
            network,
            prefix: prefix.min(32),
        }
    }

    /// Checks if a client IP matches this rule.
    #[must_use]
    pub fn matches(&self, client_ip: &IpAddr) -> bool {
        match (self, client_ip) {
            (Self::Exact(rule_ip), ip) => rule_ip == ip,
            (Self::SubnetV4 { network, prefix }, IpAddr::V4(client_v4)) => {
                if *prefix == 0 {
                    return true;
                }
                let mask = !((1u32 << (32 - *prefix)) - 1);
                let net_u32 = u32::from(*network) & mask;
                let client_u32 = u32::from(*client_v4) & mask;
                net_u32 == client_u32
            }
            _ => false,
        }
    }
}

/// Configuration settings for the IP firewall.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpFirewallConfig {
    /// Default action when an IP matches neither allowlist nor denylist.
    pub default_action: IpFilterAction,
    /// Allow rules. Takes precedence over denylist when present.
    pub allow_rules: Vec<FirewallRule>,
    /// Deny rules.
    pub deny_rules: Vec<FirewallRule>,
}

impl Default for IpFirewallConfig {
    fn default() -> Self {
        Self {
            default_action: IpFilterAction::Allow,
            allow_rules: Vec::new(),
            deny_rules: Vec::new(),
        }
    }
}

/// Thread-safe IP firewall evaluator.
#[derive(Debug, Clone)]
pub struct IpFirewall {
    config: Arc<RwLock<IpFirewallConfig>>,
}

impl IpFirewall {
    /// Creates a new firewall with the given configuration.
    #[must_use]
    pub fn new(config: IpFirewallConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
        }
    }

    /// Evaluates whether an incoming IP is allowed or denied.
    #[must_use]
    pub fn evaluate(&self, ip: &IpAddr) -> IpFilterAction {
        let config = self.config.read().expect("firewall rwlock poisoned");

        // 1. Explicit deny rules always take immediate precedence
        for rule in &config.deny_rules {
            if rule.matches(ip) {
                return IpFilterAction::Deny;
            }
        }

        // 2. If allow rules exist, IP must match at least one allow rule
        if !config.allow_rules.is_empty() {
            for rule in &config.allow_rules {
                if rule.matches(ip) {
                    return IpFilterAction::Allow;
                }
            }
            return IpFilterAction::Deny;
        }

        // 3. Fall back to default policy
        config.default_action
    }

    /// Helper that returns true if the IP is allowed.
    #[must_use]
    pub fn is_allowed(&self, ip: &IpAddr) -> bool {
        self.evaluate(ip) == IpFilterAction::Allow
    }

    /// Adds a rule to the denylist.
    pub fn deny(&self, rule: FirewallRule) {
        let mut config = self.config.write().expect("firewall rwlock poisoned");
        config.deny_rules.push(rule);
    }

    /// Adds a rule to the allowlist.
    pub fn allow(&self, rule: FirewallRule) {
        let mut config = self.config.write().expect("firewall rwlock poisoned");
        config.allow_rules.push(rule);
    }
}

impl Default for IpFirewall {
    fn default() -> Self {
        Self::new(IpFirewallConfig::default())
    }
}
