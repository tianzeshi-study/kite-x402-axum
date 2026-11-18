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

/// Outcome of attempting to acquire an idempotency key slot.
#[derive(Debug, PartialEq, Eq)]
pub enum AcquireResult {
    /// Key slot acquired; caller should proceed to verify, process, and complete.
    Acquired,
    /// A concurrent request with this key is already executing.
    InProgress,
    /// Response already cached from a previous completed execution.
    Cached(CachedResponse),
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
            entries.retain(|_, entry| match entry {
                Entry::InProgress { started_at } => {
                    now.duration_since(*started_at) < self.config.in_progress_timeout
                }
                Entry::Completed { cached_at, .. } => {
                    now.duration_since(*cached_at) < self.config.ttl
                }
            });
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
