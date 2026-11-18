//! Atomic, process-local replay protection for payment authorizations.
//!
//! Pending reservations are never expired or evicted. Known failures can release
//! them; completed or uncertain operations retain protection for the configured TTL.

use std::{
    collections::{BTreeSet, HashMap},
    fmt,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use thiserror::Error;

use crate::types::PaymentPayload;

/// Errors produced by the payment nonce replay guard.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum NonceReplayError {
    #[error("payment signature/nonce has already been used: {nonce}")]
    /// The authorization was already used (the nonce is redacted in errors).
    ReplayDetected {
        /// Redacted identifier of the replayed nonce.
        nonce: String,
    },
    #[error("payment replay protection cache is full")]
    /// The replay-protection cache has no room for another authorization.
    CapacityExceeded,
}

struct NonceEntry {
    generation: Arc<()>,
}

#[derive(Default)]
struct NonceStore {
    entries: HashMap<String, NonceEntry>,
    expirations: BTreeSet<(Instant, String)>,
}

impl NonceStore {
    fn expire(&mut self, now: Instant) {
        // Bound admission work even when many retained authorizations expire together.
        for _ in 0..64 {
            match self.expirations.first().cloned() {
                Some((deadline, key)) if deadline <= now => {
                    self.expirations.pop_first();
                    self.entries.remove(&key);
                }
                _ => break,
            }
        }
    }
}

/// Thread-safe, bounded replay protection for one service process.
///
/// Admission fails at capacity instead of evicting unexpired authorizations.
/// Pending reservations do not expire. Retention TTL begins when an operation ends.
pub struct PaymentNonceReplayGuard {
    max_capacity: usize,
    ttl: Duration,
    store: Mutex<NonceStore>,
}

impl fmt::Debug for PaymentNonceReplayGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaymentNonceReplayGuard")
            .field("max_capacity", &self.max_capacity)
            .field("ttl", &self.ttl)
            .field("len", &self.len())
            .finish()
    }
}

/// An exclusive reservation for an authorization.
///
/// Dropping a new reservation releases it. Call [`Self::retain_on_drop`] before
/// starting work whose outcome could become uncertain; dropping it then retains
/// replay protection for the guard's TTL. An explicitly known safe failure can
/// still call [`Self::release`]. No lock is held while the reservation is alive.
#[must_use = "keep the reservation alive until the protected operation finishes"]
pub struct PaymentNonceReservation<'a> {
    guard: &'a PaymentNonceReplayGuard,
    key: String,
    generation: Arc<()>,
    retain: bool,
}

impl PaymentNonceReservation<'_> {
    /// Retains protection on completion, cancellation, or unwinding.
    ///
    /// Call this before an operation that must not be repeated if its outcome
    /// becomes unknown, and keep this handle alive until that operation finishes.
    pub fn retain_on_drop(&mut self) {
        self.retain = true;
    }

    /// Releases the authorization after a failure known to be safe to retry.
    /// Never use this after an uncertain settlement.
    pub fn release(mut self) {
        self.retain = false;
    }
}

// Manual `Debug` so the replay key (derived from the payment authorization)
// is never written to logs.
impl std::fmt::Debug for PaymentNonceReservation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PaymentNonceReservation")
            .field("retain", &self.retain)
            .finish_non_exhaustive()
    }
}

impl Drop for PaymentNonceReservation<'_> {
    fn drop(&mut self) {
        let mut store = self.guard.store.lock().unwrap();
        // A handle predating clear() must not mutate a replacement reservation.
        if !store
            .entries
            .get(&self.key)
            .is_some_and(|entry| Arc::ptr_eq(&entry.generation, &self.generation))
        {
            return;
        }
        if self.retain {
            // An unrepresentable deadline stays protected and remains capacity-bounded.
            if let Some(deadline) = Instant::now().checked_add(self.guard.ttl) {
                store.expirations.insert((deadline, self.key.clone()));
            }
        } else {
            store.entries.remove(&self.key);
        }
    }
}

impl Default for PaymentNonceReplayGuard {
    fn default() -> Self {
        Self::new(10_000, 3600)
    }
}

impl PaymentNonceReplayGuard {
    /// Creates a guard holding up to `max_capacity` authorizations, each retained for `ttl_seconds`.
    #[must_use]
    pub fn new(max_capacity: usize, ttl_seconds: u64) -> Self {
        Self {
            max_capacity: max_capacity.max(1),
            ttl: Duration::from_secs(ttl_seconds.max(1)),
            store: Mutex::new(NonceStore::default()),
        }
    }

    /// Atomically reserves a payment authorization before verification.
    ///
    /// EIP-3009 nonces are scoped by scheme, network, asset and authorizer, with
    /// EVM hex casing normalized. Other payloads use their complete payment data
    /// and requirements as an opaque key. Resource and extension metadata do not
    /// identify the authorization. Errors never include the generated key.
    pub fn reserve(
        &self,
        payload: &PaymentPayload,
    ) -> Result<PaymentNonceReservation<'_>, NonceReplayError> {
        self.reserve_key(Self::authorization_key(payload), Instant::now())
            .map_err(|error| match error {
                NonceReplayError::ReplayDetected { .. } => NonceReplayError::ReplayDetected {
                    nonce: "[redacted]".to_owned(),
                },
                other @ NonceReplayError::CapacityExceeded => other,
            })
    }

    fn authorization_key(payload: &PaymentPayload) -> String {
        let requirements = &payload.accepted;
        if requirements.scheme == "exact" && requirements.network.starts_with("eip155:") {
            if let Some(auth) = payload.payload.get("authorization") {
                if let (Some(from), Some(nonce)) = (
                    auth.get("from")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty()),
                    auth.get("nonce")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty()),
                ) {
                    return serde_json::to_string(&(
                        "eip3009",
                        payload.x402_version,
                        &requirements.scheme,
                        &requirements.network,
                        requirements.asset.to_ascii_lowercase(),
                        from.to_ascii_lowercase(),
                        nonce.to_ascii_lowercase(),
                    ))
                    .expect("authorization identity serializes");
                }
            }
        }
        serde_json::to_string(&(
            "opaque",
            payload.x402_version,
            requirements,
            &payload.payload,
        ))
        .expect("payment payload serializes")
    }

    fn reserve_key(
        &self,
        key: String,
        now: Instant,
    ) -> Result<PaymentNonceReservation<'_>, NonceReplayError> {
        let mut store = self.store.lock().unwrap();
        store.expire(now);
        if store.entries.contains_key(&key) {
            return Err(NonceReplayError::ReplayDetected { nonce: key });
        }
        if store.entries.len() >= self.max_capacity {
            return Err(NonceReplayError::CapacityExceeded);
        }
        let generation = Arc::new(());
        store.entries.insert(
            key.clone(),
            NonceEntry {
                generation: generation.clone(),
            },
        );
        Ok(PaymentNonceReservation {
            guard: self,
            key,
            generation,
            retain: false,
        })
    }

    /// Extracts the legacy raw nonce/signature key, preserving the existing API.
    ///
    /// This method does not scope nonces by payer or network. Prefer [`Self::reserve`]
    /// when protecting complete payment authorizations.
    pub fn extract_nonce_key(&self, payload: &PaymentPayload) -> String {
        if let Some(auth) = payload.payload.get("authorization") {
            if let Some(nonce) = auth.get("nonce") {
                if let Some(s) = nonce.as_str() {
                    return s.to_owned();
                }
                return nonce.to_string();
            }
        }
        if let Some(nonce) = payload.payload.get("nonce") {
            if let Some(s) = nonce.as_str() {
                return s.to_owned();
            }
            return nonce.to_string();
        }
        if let Some(sig) = payload.payload.get("signature") {
            if let Some(s) = sig.as_str() {
                return s.to_owned();
            }
        }
        payload.payload.to_string()
    }

    /// Immediately records a caller-supplied legacy key for the retention TTL.
    ///
    /// Unlike [`Self::reserve`], this API cannot release known failed operations.
    /// Returns [`NonceReplayError::CapacityExceeded`] rather than evicting a live key.
    pub fn check_and_record(&self, nonce: &str) -> Result<(), NonceReplayError> {
        let mut reservation = self.reserve_key(nonce.to_owned(), Instant::now())?;
        reservation.retain_on_drop();
        Ok(())
    }

    /// Number of pending and retained authorizations, including idle expired entries
    /// not yet reclaimed by a subsequent admission.
    pub fn len(&self) -> usize {
        self.store.lock().unwrap().entries.len()
    }

    /// Returns `true` if the guard holds no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clears all protection, including pending reservations.
    ///
    /// This is an explicit administrative reset: using it during active requests
    /// permits overlapping admissions. Existing handles cannot change replacement entries.
    pub fn clear(&self) {
        let mut store = self.store.lock().unwrap();
        store.entries.clear();
        store.expirations.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PaymentRequirements;
    use serde_json::json;

    fn sample_requirements() -> PaymentRequirements {
        PaymentRequirements {
            scheme: "exact".into(),
            network: "eip155:2368".into(),
            amount: "1000".into(),
            asset: "0x0000000000000000000000000000000000000000".into(),
            pay_to: "0x1111111111111111111111111111111111111111".into(),
            max_timeout_seconds: 60,
            extra: None,
        }
    }

    #[test]
    fn records_new_nonce_successfully() {
        let guard = PaymentNonceReplayGuard::new(100, 60);
        assert_eq!(guard.len(), 0);
        assert!(guard.check_and_record("nonce-1").is_ok());
        assert_eq!(guard.len(), 1);
    }

    #[test]
    fn rejects_replayed_nonce() {
        let guard = PaymentNonceReplayGuard::new(100, 60);
        assert!(guard.check_and_record("nonce-repeat").is_ok());
        let err = guard.check_and_record("nonce-repeat").unwrap_err();
        assert_eq!(
            err,
            NonceReplayError::ReplayDetected {
                nonce: "nonce-repeat".into()
            }
        );
    }

    #[test]
    fn isolates_distinct_nonces() {
        let guard = PaymentNonceReplayGuard::new(100, 60);
        assert!(guard.check_and_record("nonce-a").is_ok());
        assert!(guard.check_and_record("nonce-b").is_ok());
        assert!(guard.check_and_record("nonce-c").is_ok());
        assert_eq!(guard.len(), 3);
    }

    #[test]
    fn extracts_nonce_from_authorization_subfield() {
        let guard = PaymentNonceReplayGuard::default();
        let payload = PaymentPayload {
            x402_version: 2,
            resource: None,
            accepted: sample_requirements(),
            payload: json!({
                "authorization": {
                    "nonce": "0xdeadbeef1234"
                }
            }),
            extensions: None,
        };
        assert_eq!(guard.extract_nonce_key(&payload), "0xdeadbeef1234");
    }

    #[test]
    fn extracts_nonce_from_top_level_payload() {
        let guard = PaymentNonceReplayGuard::default();
        let payload = PaymentPayload {
            x402_version: 2,
            resource: None,
            accepted: sample_requirements(),
            payload: json!({
                "nonce": "0x5678"
            }),
            extensions: None,
        };
        assert_eq!(guard.extract_nonce_key(&payload), "0x5678");
    }

    fn payment() -> PaymentPayload {
        PaymentPayload {
            x402_version: 2,
            resource: None,
            accepted: sample_requirements(),
            payload: json!({
                "signature": "private-signature",
                "authorization": { "from": "0xAbC1", "nonce": "0xDeAd" }
            }),
            extensions: None,
        }
    }

    #[test]
    fn capacity_never_evicts_unexpired_legacy_keys() {
        let guard = PaymentNonceReplayGuard::new(2, 60);
        guard.check_and_record("nonce-1").unwrap();
        guard.check_and_record("nonce-2").unwrap();
        assert_eq!(
            guard.check_and_record("nonce-3"),
            Err(NonceReplayError::CapacityExceeded)
        );
        assert_eq!(guard.len(), 2);
        assert!(matches!(
            guard.check_and_record("nonce-1"),
            Err(NonceReplayError::ReplayDetected { .. })
        ));
        assert!(matches!(
            guard.check_and_record("nonce-2"),
            Err(NonceReplayError::ReplayDetected { .. })
        ));
    }

    #[test]
    fn dropping_an_unprotected_reservation_releases_capacity() {
        let guard = PaymentNonceReplayGuard::new(1, 60);
        for _ in 0..1000 {
            let reservation = guard.reserve(&payment()).unwrap();
            assert_eq!(guard.len(), 1);
            drop(reservation);
            assert!(guard.is_empty());
            assert!(guard.store.lock().unwrap().expirations.is_empty());
        }
    }

    #[test]
    fn protected_drop_retains_but_known_failure_can_release() {
        let guard = PaymentNonceReplayGuard::new(1, 60);
        let mut reservation = guard.reserve(&payment()).unwrap();
        reservation.retain_on_drop();
        reservation.release();
        assert!(guard.is_empty());
        let mut reservation = guard.reserve(&payment()).unwrap();
        reservation.retain_on_drop();
        drop(reservation);
        assert!(matches!(
            guard.reserve(&payment()),
            Err(NonceReplayError::ReplayDetected { .. })
        ));
        assert_eq!(guard.store.lock().unwrap().expirations.len(), 1);
    }

    #[test]
    fn pending_authorizations_do_not_expire_or_get_evicted() {
        let guard = PaymentNonceReplayGuard::new(1, 1);
        let now = Instant::now();
        let reservation = guard.reserve_key("pending".into(), now).unwrap();
        let later = now + Duration::from_secs(3600);
        assert!(matches!(
            guard.reserve_key("pending".into(), later),
            Err(NonceReplayError::ReplayDetected { .. })
        ));
        assert!(matches!(
            guard.reserve_key("other".into(), later),
            Err(NonceReplayError::CapacityExceeded)
        ));
        drop(reservation);
        assert!(guard.reserve_key("other".into(), later).is_ok());
    }

    #[test]
    fn retained_authorizations_expire_and_recover_capacity() {
        let guard = PaymentNonceReplayGuard::new(1, 60);
        guard.check_and_record("completed").unwrap();
        let deadline = guard.store.lock().unwrap().expirations.first().unwrap().0;
        assert!(matches!(
            guard.reserve_key("other".into(), deadline - Duration::from_nanos(1)),
            Err(NonceReplayError::CapacityExceeded)
        ));
        let next = guard.reserve_key("other".into(), deadline).unwrap();
        assert_eq!(guard.len(), 1);
        assert!(guard.store.lock().unwrap().expirations.is_empty());
        drop(next);
    }

    #[test]
    fn stale_handles_cannot_release_or_retain_replacement_entries() {
        for retain in [false, true] {
            let guard = PaymentNonceReplayGuard::new(1, 60);
            let mut old = guard.reserve(&payment()).unwrap();
            if retain {
                old.retain_on_drop();
            }
            guard.clear();
            let replacement = guard.reserve(&payment()).unwrap();
            drop(old);
            assert_eq!(guard.len(), 1);
            assert!(guard.store.lock().unwrap().expirations.is_empty());
            drop(replacement);
            assert!(guard.is_empty());
        }
    }

    #[test]
    fn authorizations_are_isolated_by_payer_asset_and_network() {
        let guard = PaymentNonceReplayGuard::new(10, 60);
        let original = payment();
        let _first = guard.reserve(&original).unwrap();
        for field in ["payer", "asset", "network"] {
            let mut other = original.clone();
            match field {
                "payer" => other.payload["authorization"]["from"] = json!("0xOtherPayer"),
                "asset" => other.accepted.asset = "0xOtherAsset".into(),
                "network" => other.accepted.network = "eip155:2369".into(),
                _ => unreachable!(),
            }
            assert!(guard.reserve(&other).is_ok(), "{field}");
        }
    }

    #[test]
    fn hex_case_signatures_and_metadata_do_not_bypass_authorization_identity() {
        let guard = PaymentNonceReplayGuard::new(10, 60);
        let mut original = payment();
        original.accepted.asset = "0xAbCd".into();
        let _first = guard.reserve(&original).unwrap();
        let mut alias = original.clone();
        alias.accepted.asset = "0xabcd".into();
        alias.payload["authorization"]["from"] = json!("0xabc1");
        alias.payload["authorization"]["nonce"] = json!("0xdead");
        alias.payload["signature"] = json!("different-signature");
        alias.extensions = Some(json!({"custom":true}));
        alias.resource = Some(crate::types::ResourceInfo {
            url: "/other".into(),
            description: None,
            mime_type: None,
        });
        assert!(matches!(
            guard.reserve(&alias),
            Err(NonceReplayError::ReplayDetected { .. })
        ));
    }

    #[test]
    fn opaque_fallback_uses_complete_payload_instead_of_a_bare_nonce() {
        let guard = PaymentNonceReplayGuard::new(10, 60);
        let mut first = payment();
        first.payload = json!({"nonce":"same", "signature":"first"});
        let _reserved = guard.reserve(&first).unwrap();
        let mut other = first.clone();
        other.payload["signature"] = json!("second");
        assert!(guard.reserve(&other).is_ok());
        assert!(matches!(
            guard.reserve(&first),
            Err(NonceReplayError::ReplayDetected { .. })
        ));
    }

    #[test]
    fn replay_errors_and_guard_debug_do_not_expose_authorization_data() {
        let guard = PaymentNonceReplayGuard::new(10, 60);
        let mut payload = payment();
        payload.payload = json!({"signature":"private-signature"});
        let _first = guard.reserve(&payload).unwrap();
        let Err(error) = guard.reserve(&payload) else {
            panic!("duplicate accepted");
        };
        for text in [
            error.to_string(),
            format!("{error:?}"),
            format!("{guard:?}"),
        ] {
            assert!(!text.contains("private-signature"));
        }
    }

    #[test]
    fn concurrent_duplicates_admit_one_pending_reservation() {
        let guard = PaymentNonceReplayGuard::new(10, 60);
        let barrier = std::sync::Barrier::new(32);
        let admitted: usize = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..32)
                .map(|_| {
                    scope.spawn(|| {
                        let reservation = guard.reserve(&payment());
                        let admitted = reservation.is_ok();
                        barrier.wait();
                        drop(reservation);
                        usize::from(admitted)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .sum()
        });
        assert_eq!(admitted, 1);
        assert!(guard.is_empty());
    }

    #[test]
    fn expiry_index_is_bounded_by_retained_entries() {
        let guard = PaymentNonceReplayGuard::new(130, 60);
        for index in 0..130 {
            guard.check_and_record(&format!("{index}")).unwrap();
        }
        let later = guard.store.lock().unwrap().expirations.last().unwrap().0;
        let reservation = guard.reserve_key("replacement".into(), later).unwrap();
        let store = guard.store.lock().unwrap();
        assert_eq!(store.entries.len(), 67);
        assert_eq!(store.expirations.len(), 66);
        drop(store);
        drop(reservation);
        assert_eq!(guard.store.lock().unwrap().entries.len(), 66);
    }
}
