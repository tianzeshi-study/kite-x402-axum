use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Health status of an individual facilitator node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStats {
    pub url: String,
    pub status: NodeStatus,
    pub total_requests: u64,
    pub total_successes: u64,
    pub consecutive_failures: u32,
    pub last_latency_ms: u64,
}

struct NodeState {
    url: String,
    status: NodeStatus,
    total_requests: u64,
    total_successes: u64,
    consecutive_failures: u32,
    last_latency_ms: u64,
    unhealthy_until: Option<Instant>,
}

/// Configuration for multi-node facilitator failover pool.
#[derive(Debug, Clone)]
pub struct FacilitatorPoolConfig {
    pub max_consecutive_failures: u32,
    pub recovery_cooldown: Duration,
}

impl Default for FacilitatorPoolConfig {
    fn default() -> Self {
        Self {
            max_consecutive_failures: 3,
            recovery_cooldown: Duration::from_secs(30),
        }
    }
}

/// Round-robin and failover pool across multiple Kite facilitator endpoints.
#[derive(Debug, Clone)]
pub struct FacilitatorPool {
    nodes: Arc<RwLock<Vec<NodeState>>>,
    index: Arc<AtomicUsize>,
    config: FacilitatorPoolConfig,
}

impl FacilitatorPool {
    /// Creates a new facilitator pool from a list of base URLs.
    pub fn new(urls: Vec<String>) -> Self {
        Self::with_config(urls, FacilitatorPoolConfig::default())
    }

    /// Creates a pool with custom failover and recovery configuration.
    pub fn with_config(urls: Vec<String>, config: FacilitatorPoolConfig) -> Self {
        let node_states = urls
            .into_iter()
            .map(|url| NodeState {
                url,
                status: NodeStatus::Healthy,
                total_requests: 0,
                total_successes: 0,
                consecutive_failures: 0,
                last_latency_ms: 0,
                unhealthy_until: None,
            })
            .collect();

        Self {
            nodes: Arc::new(RwLock::new(node_states)),
            index: Arc::new(AtomicUsize::new(0)),
            config,
        }
    }

    /// Selects the next available healthy facilitator endpoint.
    pub fn select_node(&self) -> Option<String> {
        let now = Instant::now();
        let mut nodes = self.nodes.write().expect("lock poisoned");
        if nodes.is_empty() {
            return None;
        }

        // Check if any unhealthy nodes have completed their recovery cooldown
        for node in nodes.iter_mut() {
            if node.status == NodeStatus::Unhealthy {
                if let Some(until) = node.unhealthy_until {
                    if now >= until {
                        node.status = NodeStatus::Degraded;
                        node.consecutive_failures = 0;
                        node.unhealthy_until = None;
                    }
                }
            }
        }

        let total = nodes.len();
        let start_idx = self.index.fetch_add(1, Ordering::Relaxed) % total;

        // Try to find a healthy or degraded node
        for i in 0..total {
            let candidate_idx = (start_idx + i) % total;
            if nodes[candidate_idx].status != NodeStatus::Unhealthy {
                return Some(nodes[candidate_idx].url.clone());
            }
        }

        // If all nodes are unhealthy, fallback to first node to attempt recovery
        Some(nodes[start_idx].url.clone())
    }

    /// Records the execution outcome for a node.
    pub fn record_result(&self, url: &str, success: bool, latency: Duration) {
        let now = Instant::now();
        let mut nodes = self.nodes.write().expect("lock poisoned");

        if let Some(node) = nodes.iter_mut().find(|n| n.url == url) {
            node.total_requests += 1;
            node.last_latency_ms = latency.as_millis() as u64;

            if success {
                node.total_successes += 1;
                node.consecutive_failures = 0;
                node.status = NodeStatus::Healthy;
                node.unhealthy_until = None;
            } else {
                node.consecutive_failures += 1;
                if node.consecutive_failures >= self.config.max_consecutive_failures {
                    node.status = NodeStatus::Unhealthy;
                    node.unhealthy_until = Some(now + self.config.recovery_cooldown);
                } else {
                    node.status = NodeStatus::Degraded;
                }
            }
        }
    }

    /// Retrieves a snapshot of all node metrics.
    pub fn get_stats(&self) -> Vec<NodeStats> {
        let nodes = self.nodes.read().expect("lock poisoned");
        nodes
            .iter()
            .map(|n| NodeStats {
                url: n.url.clone(),
                status: n.status.clone(),
                total_requests: n.total_requests,
                total_successes: n.total_successes,
                consecutive_failures: n.consecutive_failures,
                last_latency_ms: n.last_latency_ms,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_robin_selection() {
        let urls = vec![
            "https://facilitator-1.gokite.ai".to_string(),
            "https://facilitator-2.gokite.ai".to_string(),
        ];
        let pool = FacilitatorPool::new(urls.clone());

        let node1 = pool.select_node().unwrap();
        let node2 = pool.select_node().unwrap();
        let node3 = pool.select_node().unwrap();

        assert_eq!(node1, urls[0]);
        assert_eq!(node2, urls[1]);
        assert_eq!(node3, urls[0]);
    }

    #[test]
    fn test_failover_when_node_becomes_unhealthy() {
        let urls = vec![
            "https://f1.gokite.ai".to_string(),
            "https://f2.gokite.ai".to_string(),
        ];
        let pool = FacilitatorPool::with_config(
            urls.clone(),
            FacilitatorPoolConfig {
                max_consecutive_failures: 2,
                recovery_cooldown: Duration::from_millis(50),
            },
        );

        // Fail node 1 twice
        pool.record_result(&urls[0], false, Duration::from_millis(100));
        pool.record_result(&urls[0], false, Duration::from_millis(100));

        let stats = pool.get_stats();
        assert_eq!(stats[0].status, NodeStatus::Unhealthy);
        assert_eq!(stats[1].status, NodeStatus::Healthy);

        // Subsequent selections should skip f1 and return f2
        for _ in 0..3 {
            assert_eq!(pool.select_node().unwrap(), urls[1]);
        }
    }
}
