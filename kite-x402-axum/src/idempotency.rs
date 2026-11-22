//! In-memory idempotency cache for x402 payment and upstream responses.
//!
//! Prevents duplicate payment settlements and redundant upstream API calls
//! when clients retry identical requests with an `Idempotency-Key` header.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Configuration for the idempotency cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdempotencyConfig {
    /// Time-to-live for cached responses before eviction.
    pub ttl: Duration,
    /// Maximum number of cached keys retained in memory.
    pub max_entries: usize,
    /// Lock timeout for in-progress operations before treating as abandoned.
    pub in_progress_timeout: Duration,
}

impl Default for IdempotencyConfig {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(300),
            max_entries: 5000,
            in_progress_timeout: Duration::from_secs(60),
        }
    }
}

/// A cached HTTP response recorded for an idempotency key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedResponse {
    /// HTTP status code of the cached response.
    pub status: u16,
    /// Response headers as name/value pairs.
    pub headers: Vec<(String, String)>,
    /// Raw response body bytes.
    pub body: Vec<u8>,
}

#[derive(Debug)]
enum Entry {
    InProgress {
        started_at: Instant,
    },
    Completed {
        response: CachedResponse,
        cached_at: Instant,
    },
}

impl Entry {
    /// When this entry was recorded; used to pick the oldest one for eviction.
    fn timestamp(&self) -> Instant {
        match self {
            Self::InProgress { started_at } => *started_at,
            Self::Completed { cached_at, .. } => *cached_at,
        }
    }

    /// Whether the entry is still within its TTL / in-progress window.
    fn is_live(&self, now: Instant, config: &IdempotencyConfig) -> bool {
        match self {
            Self::InProgress { started_at } => {
                now.duration_since(*started_at) < config.in_progress_timeout
            }
            Self::Completed { cached_at, .. } => now.duration_since(*cached_at) < config.ttl,
        }
    }
}

/// Outcome of attempting to acquire an idempotency key slot.
#[derive(Debug, PartialEq, Eq)]
pub enum AcquireResult {
    /// Key slot acquired; caller should proceed to verify, process, and complete.
    Acquired,
    /// A concurrent request with this key is already executing.
    InProgress,
    /// Response already cached from a previous completed execution.
    Cached(CachedResponse),
    /// The cache is full of live execution leases and no completed entry can
    /// be evicted. Callers must retry later, never proceed: admitting another
    /// key by evicting a live lease would hand the same payment two leases and
    /// risk a duplicate settlement. The sibling `PaymentNonceReplayGuard`
    /// applies the same fail-at-capacity policy to pending reservations.
    CapacityBusy,
}

/// Thread-safe idempotency cache.
#[derive(Debug, Clone)]
pub struct IdempotencyCache {
    config: IdempotencyConfig,
    entries: Arc<Mutex<HashMap<String, Entry>>>,
}

impl IdempotencyCache {
    /// Creates a cache with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(IdempotencyConfig::default())
    }

    /// Creates a cache with custom configuration.
    #[must_use]
    pub fn with_config(config: IdempotencyConfig) -> Self {
        // A zero bound would evict every key immediately; clamp like the sibling
        // `NonceGuard` does so a misconfigured cache still holds one entry.
        let config = IdempotencyConfig {
            max_entries: config.max_entries.max(1),
            ..config
        };
        Self {
            config,
            entries: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Attempts to acquire an execution lease for the given idempotency key.
    #[must_use]
    pub fn acquire(&self, key: &str) -> AcquireResult {
        let mut entries = self.entries.lock().expect("idempotency cache poisoned");
        let now = Instant::now();

        if let Some(entry) = entries.get(key) {
            match entry {
                Entry::InProgress { started_at } => {
                    if now.duration_since(*started_at) < self.config.in_progress_timeout {
                        return AcquireResult::InProgress;
                    }
                    // In-progress entry expired/timed out; allow re-acquisition.
                }
                Entry::Completed {
                    response,
                    cached_at,
                } => {
                    if now.duration_since(*cached_at) < self.config.ttl {
                        return AcquireResult::Cached(response.clone());
                    }
                    // TTL expired; allow re-acquisition.
                }
            }
        }

        // Clean up expired entries if reaching capacity limit
        if entries.len() >= self.config.max_entries {
            entries.retain(|_, entry| entry.is_live(now, &self.config));
        }

        // Make room for the new key without ever evicting a live execution
        // lease. A `Completed` entry can be dropped early under memory
        // pressure: worst case a client re-drives a request and the response is
        // recomputed, but the facilitator/nonce guard still prevent a second
        // settlement. An `InProgress` entry is different — it is the only
        // thing stopping a concurrent retry of the *same* key from settling
        // again. Evicting one would hand out a second lease for one payment.
        //
        // So evict only the oldest `Completed` entries. If the cache is full of
        // live leases there is nothing safe to remove: fail at capacity (same
        // policy as `PaymentNonceReplayGuard`) and let the caller retry rather
        // than break the idempotency guarantee to preserve the memory bound.
        while entries.len() >= self.config.max_entries {
            let oldest_completed = entries
                .iter()
                .filter(|(_, entry)| matches!(entry, Entry::Completed { .. }))
                .min_by_key(|(_, entry)| entry.timestamp())
                .map(|(key, _)| key.clone());
            let Some(oldest_completed) = oldest_completed else {
                return AcquireResult::CapacityBusy;
            };
            entries.remove(&oldest_completed);
        }

        entries.insert(key.to_owned(), Entry::InProgress { started_at: now });
        AcquireResult::Acquired
    }

    /// Marks an idempotency key as completed and stores the response.
    pub fn complete(&self, key: &str, status: u16, headers: Vec<(String, String)>, body: Vec<u8>) {
        let mut entries = self.entries.lock().expect("idempotency cache poisoned");
        entries.insert(
            key.to_owned(),
            Entry::Completed {
                response: CachedResponse {
                    status,
                    headers,
                    body,
                },
                cached_at: Instant::now(),
            },
        );
    }

    /// Releases an in-progress idempotency key if an operation fails or was aborted.
    pub fn release(&self, key: &str) {
        let mut entries = self.entries.lock().expect("idempotency cache poisoned");
        if let Some(Entry::InProgress { .. }) = entries.get(key) {
            entries.remove(key);
        }
    }

    /// Returns the number of tracked entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .expect("idempotency cache poisoned")
            .len()
    }

    /// Returns whether the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for IdempotencyCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_entries_is_a_hard_bound() {
        let cache = IdempotencyCache::with_config(IdempotencyConfig {
            max_entries: 3,
            ttl: Duration::from_secs(300),
            in_progress_timeout: Duration::from_secs(60),
        });

        // Every entry is still a live lease, so nothing is eligible for TTL
        // pruning and there is no Completed entry to evict. The bound must
        // hold by rejecting new keys, not by evicting a live lease.
        for i in 0..3 {
            assert_eq!(cache.acquire(&format!("key-{i}")), AcquireResult::Acquired);
        }
        for i in 3..10 {
            assert_eq!(
                cache.acquire(&format!("key-{i}")),
                AcquireResult::CapacityBusy,
                "a full cache of live leases must reject, not evict"
            );
        }

        assert!(
            cache.len() <= 3,
            "cache grew past max_entries: {}",
            cache.len()
        );
        // The original leases were never evicted.
        for i in 0..3 {
            assert_eq!(
                cache.acquire(&format!("key-{i}")),
                AcquireResult::InProgress
            );
        }
    }

    #[test]
    fn completed_response_is_still_returned_under_capacity() {
        let cache = IdempotencyCache::new();
        assert_eq!(cache.acquire("k"), AcquireResult::Acquired);
        cache.complete("k", 200, Vec::new(), b"ok".to_vec());

        match cache.acquire("k") {
            AcquireResult::Cached(response) => {
                assert_eq!(response.status, 200);
                assert_eq!(response.body, b"ok");
            }
            other => panic!("expected a cached response, got {other:?}"),
        }
    }

    #[test]
    fn live_in_progress_lease_is_not_evicted_under_capacity_pressure() {
        // A live InProgress entry is an execution lease: another request with
        // the same key must see InProgress, not be handed a second lease and
        // settle the same payment twice. Capacity eviction must never remove
        // one — the sibling `PaymentNonceReplayGuard` already treats pending
        // reservations as non-evictable and fails admission at capacity.
        let cache = IdempotencyCache::with_config(IdempotencyConfig {
            max_entries: 2,
            ..IdempotencyConfig::default()
        });
        assert_eq!(cache.acquire("a"), AcquireResult::Acquired);
        assert_eq!(cache.acquire("b"), AcquireResult::Acquired);

        // Admitting "c" fills the cache. Whatever it does, "a" is still live
        // (in_progress_timeout is 60s, no time has passed) so its lease must
        // survive; re-acquiring it must still report InProgress.
        let _ = cache.acquire("c");
        assert_eq!(
            cache.acquire("a"),
            AcquireResult::InProgress,
            "a live in-progress lease was evicted under capacity pressure"
        );
    }

    #[test]
    fn oldest_completed_entry_is_evicted_first() {
        let cache = IdempotencyCache::with_config(IdempotencyConfig {
            max_entries: 2,
            ..IdempotencyConfig::default()
        });
        // "a" completes first, so it is the oldest evictable entry. "b" stays
        // a live lease and must survive capacity pressure.
        assert_eq!(cache.acquire("a"), AcquireResult::Acquired);
        cache.complete("a", 200, Vec::new(), b"a".to_vec());
        assert_eq!(cache.acquire("b"), AcquireResult::Acquired);

        assert_eq!(cache.acquire("c"), AcquireResult::Acquired);
        assert!(cache.len() <= 2);
        // The live lease survived; the oldest completed response was evicted.
        assert_eq!(cache.acquire("b"), AcquireResult::InProgress);
        // "a" is gone, and what remains are two live leases, so a fresh
        // acquire is refused rather than served from a resurrected cache.
        assert_eq!(cache.acquire("a"), AcquireResult::CapacityBusy);
    }
}
