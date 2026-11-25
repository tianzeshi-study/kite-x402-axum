//! Health check monitor and readiness probe for Kite x402 Axum services.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyCheck {
    pub name: String,
    pub status: HealthStatus,
    pub latency_ms: u64,
    pub details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    pub service: String,
    pub version: String,
    pub status: HealthStatus,
    pub uptime_secs: u64,
    pub dependencies: Vec<DependencyCheck>,
}

#[derive(Debug)]
pub struct HealthProbeMonitor {
    service_name: String,
    version: String,
    started_at: Instant,
    probes: HashMap<String, Box<dyn Fn() -> DependencyCheck + Send + Sync>>,
}

impl HealthProbeMonitor {
    pub fn new(service_name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            version: version.into(),
            started_at: Instant::now(),
            probes: HashMap::new(),
        }
    }

    pub fn register_probe<F>(&mut self, name: impl Into<String>, probe: F)
    where
        F: Fn() -> DependencyCheck + Send + Sync + 'static,
    {
        self.probes.insert(name.into(), Box::new(probe));
    }

    pub fn evaluate(&self) -> HealthReport {
        let mut overall_status = HealthStatus::Healthy;
        let mut checks = Vec::new();

        for probe in self.probes.values() {
            let check = probe();
            match check.status {
                HealthStatus::Unhealthy => overall_status = HealthStatus::Unhealthy,
                HealthStatus::Degraded if overall_status != HealthStatus::Unhealthy => {
                    overall_status = HealthStatus::Degraded;
                }
                _ => {}
            }
            checks.push(check);
        }

        HealthReport {
            service: self.service_name.clone(),
            version: self.version.clone(),
            status: overall_status,
            uptime_secs: self.started_at.elapsed().as_secs(),
            dependencies: checks,
        }
    }
}
