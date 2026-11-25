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

/// A dual-stack listener reports IPv4 callers as `::ffff:a.b.c.d`. An
/// allow-list written with plain IPv4 addresses must still match them, in both
/// directions, or binding `[::]` silently denies every allowed client.
#[test]
fn ipv4_mapped_peers_match_ipv4_rules() {
    let v4: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();
    let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();

    assert!(FirewallRule::Exact(v4).matches(&mapped));
    assert!(FirewallRule::Exact(mapped).matches(&v4));
    assert!(FirewallRule::subnet_v4(Ipv4Addr::new(127, 0, 0, 0), 8).matches(&mapped));

    let firewall = IpFirewall::new(IpFirewallConfig {
        allow_rules: vec![FirewallRule::Exact(v4)],
        ..Default::default()
    });
    assert_eq!(firewall.evaluate(&mapped), IpFilterAction::Allow);
}

/// Mapping only collapses `::ffff:0:0/96`; native IPv6 addresses must stay
/// distinct from IPv4, otherwise an IPv4 allow rule would admit `::1`.
#[test]
fn native_ipv6_is_not_treated_as_ipv4() {
    let loopback_v6 = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
    let firewall = IpFirewall::new(IpFirewallConfig {
        allow_rules: vec![FirewallRule::Exact(Ipv4Addr::LOCALHOST.into())],
        ..Default::default()
    });
    assert_eq!(firewall.evaluate(&loopback_v6), IpFilterAction::Deny);
    assert!(!FirewallRule::Exact(Ipv4Addr::LOCALHOST.into()).matches(&loopback_v6));
}
