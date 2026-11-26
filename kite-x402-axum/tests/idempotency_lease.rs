//! A stale lease holder must not cancel or overwrite the current holder.
//!
//! `acquire` hands out an execution lease that stops a concurrent retry of the
//! same key from settling one payment twice. That guarantee rests on the lease
//! surviving for as long as it is live. `in_progress_timeout` exists so a
//! crashed holder does not block the key forever: once it elapses, the next
//! acquire takes the key over.
//!
//! The hand-over creates two holders for one key in sequence. The original
//! holder can still come back — its upstream call failed late, or its task was
//! only polled after the timeout — and release or complete. Matching on the key
//! alone would cancel the *new* holder's lease, so the next acquire is granted
//! while that request is still running: one payment, two executions.
//!
//! `IdempotencyLease` carries the generation of the entry it created and
//! compares it, the same way `PaymentNonceReservation::drop` does.

use kite_x402_axum::{
    AcquireResult, IdempotencyCache, IdempotencyConfig, IdempotencyLease, LeaseAcquire,
};
use std::time::Duration;

/// A lease long enough that the assertions after a reclaim cannot race it.
///
/// The timeout has to be short enough to wait out, but the window is also the
/// time the reclaimed holder stays live. A 20 ms timeout left only 20 ms for
/// every assertion that follows, so the suite passed alone and failed under
/// parallel load. 400 ms of slack after a 500 ms sleep keeps the test about a
/// half second per case without depending on scheduler timing.
const LEASE_TIMEOUT: Duration = Duration::from_millis(400);
const PAST_TIMEOUT: Duration = Duration::from_millis(500);

fn cache_with_short_lease() -> IdempotencyCache {
    IdempotencyCache::with_config(IdempotencyConfig {
        ttl: Duration::from_secs(300),
        max_entries: 10,
        in_progress_timeout: LEASE_TIMEOUT,
    })
}

fn lease<'a>(cache: &'a IdempotencyCache, key: &str) -> IdempotencyLease<'a> {
    match cache.acquire_lease(key) {
        LeaseAcquire::Acquired(lease) => lease,
        other => panic!("expected a lease for {key}, got {other:?}"),
    }
}

#[test]
fn a_release_from_an_expired_holder_keeps_the_current_lease() {
    let cache = cache_with_short_lease();

    let stale = lease(&cache, "pay-1");
    std::thread::sleep(PAST_TIMEOUT);

    // A retry takes the expired lease over and is now the live holder.
    let current = lease(&cache, "pay-1");
    assert_eq!(cache.len(), 1, "the reclaimed key is still one entry");

    assert!(
        !stale.release(),
        "a holder whose lease expired must not be able to release the key"
    );
    assert_eq!(
        cache.len(),
        1,
        "a stale release removed the current holder's lease"
    );
    assert!(
        matches!(cache.acquire_lease("pay-1"), LeaseAcquire::InProgress),
        "a stale release let a third request acquire a key that is still executing"
    );

    assert!(current.release(), "the current holder still owns the key");
    assert_eq!(cache.len(), 0);
}

#[test]
fn a_stale_complete_does_not_overwrite_the_current_holder() {
    let cache = cache_with_short_lease();

    let stale = lease(&cache, "pay-2");
    std::thread::sleep(PAST_TIMEOUT);
    let current = lease(&cache, "pay-2");

    assert!(
        !stale.complete(200, Vec::new(), b"stale".to_vec()),
        "an expired holder must not publish its result"
    );
    assert!(
        matches!(cache.acquire_lease("pay-2"), LeaseAcquire::InProgress),
        "a stale completion cleared the live lease"
    );

    assert!(current.complete(200, Vec::new(), b"fresh".to_vec()));
    match cache.acquire("pay-2") {
        AcquireResult::Cached(response) => assert_eq!(response.body, b"fresh"),
        other => panic!("expected the current holder's response, got {other:?}"),
    }
}

#[test]
fn dropping_a_lease_releases_it_while_the_holder_still_owns_it() {
    let cache = cache_with_short_lease();
    {
        let held = lease(&cache, "pay-3");
        assert_eq!(held.key(), "pay-3");
        assert_eq!(cache.len(), 1);
    }
    assert_eq!(cache.len(), 0, "dropping a lease must release the key");

    assert_eq!(cache.acquire("pay-3"), AcquireResult::Acquired);
}
