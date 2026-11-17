//! Public permit lifecycle and concurrent admission regressions.
use kite_x402_axum::concurrency_limiter::ConcurrencyLimiter;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Barrier,
};

#[test]
fn capacity_returns_on_drop_and_early_return() {
    let limiter = ConcurrencyLimiter::new(1);
    let permit = limiter.try_acquire().unwrap();
    assert!(limiter.try_acquire().is_none());
    drop(permit);
    assert_eq!(limiter.active_requests(), 0);
    let operation = || {
        let _permit = limiter.try_acquire().unwrap();
        Err::<(), _>("cancelled")
    };
    assert!(operation().is_err());
    assert!(limiter.try_acquire().is_some());
    assert_eq!(limiter.active_requests(), 0);
}

#[test]
fn zero_limit_never_admits_a_request() {
    let limiter = ConcurrencyLimiter::new(0);
    assert!(limiter.try_acquire().is_none());
    assert_eq!(limiter.active_requests(), 0);
}

#[test]
fn simultaneous_acquisitions_respect_the_bound() {
    const THREADS: usize = 32;
    const ROUNDS: usize = 300;
    let limiter = Arc::new(ConcurrencyLimiter::new(1));
    let barrier = Arc::new(Barrier::new(THREADS));
    let admitted = Arc::new(AtomicUsize::new(0));
    let violations = Arc::new(AtomicUsize::new(0));
    std::thread::scope(|scope| {
        for id in 0..THREADS {
            let (limiter, barrier, admitted, violations) = (
                limiter.clone(),
                barrier.clone(),
                admitted.clone(),
                violations.clone(),
            );
            scope.spawn(move || {
                for _ in 0..ROUNDS {
                    barrier.wait();
                    let permit = limiter.try_acquire();
                    if permit.is_some() {
                        admitted.fetch_add(1, Ordering::SeqCst);
                    }
                    barrier.wait();
                    if id == 0 && admitted.load(Ordering::SeqCst) != 1 {
                        violations.fetch_add(1, Ordering::SeqCst);
                    }
                    drop(permit);
                    barrier.wait();
                    if id == 0 {
                        admitted.store(0, Ordering::SeqCst);
                    }
                    barrier.wait();
                }
            });
        }
    });
    assert_eq!(limiter.active_requests(), 0);
    assert_eq!(violations.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn aborting_a_task_releases_its_permit() {
    let limiter = Arc::new(ConcurrencyLimiter::new(1));
    let owned = limiter.clone();
    let (ready, wait) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        let _permit = owned.try_acquire().unwrap();
        ready.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    wait.await.unwrap();
    assert!(limiter.try_acquire().is_none());
    handle.abort();
    assert!(handle.await.unwrap_err().is_cancelled());
    assert_eq!(limiter.active_requests(), 0);
}
