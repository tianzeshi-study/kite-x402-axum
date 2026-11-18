//! In-memory TTL payment verification cache store for Kite x402 services.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A cached payment verification result.
#[derive(Debug, Clone)]
pub struct CachedVerification {
    /// Whether the cached verification succeeded.
    pub is_valid: bool,
    /// Address of the payer.
    pub payer: String,
    /// Payment amount in atomic token units.
    pub amount: String,
    /// When the entry was inserted into the cache.
    pub cached_at: Instant,
    /// How long the entry stays valid after `cached_at`.
    pub ttl: Duration,
}

/// In-memory verification cache with per-entry time-to-live.
#[derive(Debug)]
pub struct VerificationCacheStore {
    default_ttl: Duration,
    entries: Mutex<HashMap<String, CachedVerification>>,
}

impl VerificationCacheStore {
    /// Creates a cache whose entries expire after `default_ttl` unless overridden on insert.
    #[must_use]
    pub fn new(default_ttl: Duration) -> Self {
        Self {
            default_ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Returns the cached verification for `signature_hash`, if present and not expired.
    pub fn get(&self, signature_hash: &str) -> Option<CachedVerification> {
        let mut map = self.entries.lock().unwrap();
        if let Some(entry) = map.get(signature_hash) {
            if entry.cached_at.elapsed() < entry.ttl {
                return Some(entry.clone());
            } else {
                map.remove(signature_hash);
            }
        }
        None
    }

    /// Stores a verification result under `signature_hash`, using `custom_ttl` or the default TTL.
    pub fn insert(
        &self,
        signature_hash: &str,
        is_valid: bool,
        payer: &str,
        amount: &str,
        custom_ttl: Option<Duration>,
    ) {
        let mut map = self.entries.lock().unwrap();
        let ttl = custom_ttl.unwrap_or(self.default_ttl);
        map.insert(
            signature_hash.to_owned(),
            CachedVerification {
                is_valid,
                payer: payer.to_owned(),
                amount: amount.to_owned(),
                cached_at: Instant::now(),
                ttl,
            },
        );
    }

    /// Removes every entry from the cache.
    pub fn clear(&self) {
        let mut map = self.entries.lock().unwrap();
        map.clear();
    }
}
