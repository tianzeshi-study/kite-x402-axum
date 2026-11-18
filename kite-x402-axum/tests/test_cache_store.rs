//! Integration tests for the verification cache store.

use kite_x402_axum::cache_store::VerificationCacheStore;
use std::time::Duration;

#[test]
fn test_verification_cache_get_and_insert() {
    let cache = VerificationCacheStore::new(Duration::from_secs(60));
    cache.insert("sig_hash_01", true, "0xPayer", "10.00", None);

    let res = cache.get("sig_hash_01");
    assert!(res.is_some());
    let entry = res.unwrap();
    assert!(entry.is_valid);
    assert_eq!(entry.payer, "0xPayer");
}

#[test]
fn test_verification_cache_expiration() {
    let cache = VerificationCacheStore::new(Duration::from_millis(10));
    cache.insert(
        "sig_hash_exp",
        true,
        "0xPayer",
        "10.00",
        Some(Duration::from_millis(10)),
    );

    std::thread::sleep(Duration::from_millis(25));
    assert!(cache.get("sig_hash_exp").is_none());
}
