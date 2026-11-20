//! Regression coverage for public IPv4 firewall rule construction.

use std::net::{IpAddr, Ipv4Addr};

use kite_x402_axum::{FirewallRule, IpFilterAction, IpFirewall, IpFirewallConfig};

#[test]
fn direct_subnet_rules_clamp_oversized_prefixes_to_single_hosts() {
    let network = Ipv4Addr::new(192, 0, 2, 1);
    let same = IpAddr::V4(network);
    let other = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
    for prefix in [33, 64, u8::MAX] {
        let rule = FirewallRule::SubnetV4 { network, prefix };
        assert!(rule.matches(&same), "prefix {prefix} must match its host");
        assert!(
            !rule.matches(&other),
            "prefix {prefix} must not widen access"
        );
        assert!(!rule.matches(&IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)));
    }
}

#[test]
fn oversized_prefixes_preserve_firewall_policy_and_shared_lock() {
    let host = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let neighbor = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
    let rule = FirewallRule::SubnetV4 {
        network: Ipv4Addr::new(192, 0, 2, 1),
        prefix: u8::MAX,
    };
    let firewall = IpFirewall::new(IpFirewallConfig {
        allow_rules: vec![rule.clone()],
        ..Default::default()
    });
    let shared = firewall.clone();
    assert_eq!(firewall.evaluate(&host), IpFilterAction::Allow);
    assert_eq!(shared.evaluate(&neighbor), IpFilterAction::Deny);
    shared.deny(rule);
    assert_eq!(firewall.evaluate(&host), IpFilterAction::Deny);
}

#[test]
fn valid_subnet_boundaries_keep_their_matching_behavior() {
    let network = Ipv4Addr::new(192, 0, 2, 1);
    let same = IpAddr::V4(network);
    let adjacent = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0));
    let outside = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    for prefix in [0, 1, 24, 31, 32] {
        let rule = FirewallRule::SubnetV4 { network, prefix };
        assert!(rule.matches(&same));
        assert_eq!(rule.matches(&adjacent), prefix != 32);
        assert_eq!(rule.matches(&outside), prefix <= 1);
    }
}
