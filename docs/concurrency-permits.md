# In-flight permits

Use concurrency_limiter::ConcurrencyLimiter as process-local admission control. try_acquire returns an Option guard: reject or defer when it is None, and retain the guard until the work completes. Dropping the guard releases capacity, including error returns and cancellation. There is no unpaired release operation.

The limiter is opt-in and is not automatically installed on paid routes. It does not choose an identity, queue requests, reserve a payment nonce, or retry a settlement. Apply a deliberate identity and payment/cancellation policy in the caller. A zero limit closes admission.
