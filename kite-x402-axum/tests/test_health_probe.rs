use kite_x402_axum::health_probe::{DependencyCheck, HealthProbeMonitor, HealthStatus};

#[test]
fn test_health_probe_evaluation() {
    let mut monitor = HealthProbeMonitor::new("kite-x402-service", "0.2.0");

    monitor.register_probe("facilitator_rpc", || DependencyCheck {
        name: "facilitator_rpc".to_string(),
        status: HealthStatus::Healthy,
        latency_ms: 12,
        details: Some("Connected to Kite Testnet".to_string()),
    });

    let report = monitor.evaluate();
    assert_eq!(report.status, HealthStatus::Healthy);
    assert_eq!(report.service, "kite-x402-service");
    assert_eq!(report.dependencies.len(), 1);
}

#[test]
fn test_health_probe_degraded_state() {
    let mut monitor = HealthProbeMonitor::new("kite-x402-service", "0.2.0");

    monitor.register_probe("db_cache", || DependencyCheck {
        name: "db_cache".to_string(),
        status: HealthStatus::Degraded,
        latency_ms: 450,
        details: Some("High latency response".to_string()),
    });

    let report = monitor.evaluate();
    assert_eq!(report.status, HealthStatus::Degraded);
}
