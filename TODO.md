# Known issues / follow-ups

Deliberately deferred out of the first working version so the template
lands and passes its acceptance tests now. Listed here instead of blocking
on them.

## 1. Dependency versions were pinned down for this sandbox's Rust 1.75

The container this template was developed in only has `rustc`/`cargo`
1.75 available via `apt` (no network access to `rustup.rs` to install a
newer toolchain). Several transitive dependencies of `axum` 0.8 / `reqwest`
0.12 (`litemap`, `zeroize`, `idna_adapter`, the `quinn`/`rand` stack used by
reqwest's HTTP/3 support) now require Rust 1.81+ or the unstable
`edition2024` feature in their newest published versions, which 1.75
cannot build. To get a working, testable build in this sandbox, the
generated `Cargo.lock` pins those crates down to their latest
1.75-compatible versions, and `reqwest` is pinned to `=0.12.9` (last
version before it started requiring a newer `idna`/`quinn` chain).

**This should not carry forward as-is.** `Cargo.lock` is `.gitignore`d for
exactly this reason — a contributor with a current Rust toolchain should
get fresh, current dependency versions, not this sandbox's downgraded set.
Before merging:

- Confirm the crate builds cleanly on current stable Rust with an
  unconstrained `cargo update`.
- Reconsider whether `reqwest`'s exact pin (`=0.12.9`) is still needed, or
  whether it can go back to a normal `"0.12"` range once building outside
  this sandbox.
- Decide the crate's real MSRV (this template's `Cargo.toml` currently
  claims `rust-version = "1.75"` to match the sandbox; verify that's
  actually still true for the *unpinned* dependency tree, or raise it).

## 2. TypeScript and Go SDKs disagree on facilitator-unreachable status codes

Documented in `kite-x402-axum/src/lib.rs` and inline in `middleware.rs`,
repeated here because it's a real behavioral choice, not just an
implementation detail:

- The **TypeScript** SDK (`@x402/core`'s `x402HTTPResourceServer` +
  `@x402/express`) throws when the facilitator can't be reached or returns
  something unparseable, and the Express adapter turns that into `502` for
  a small subset of error types (`FacilitatorResponseError`, mostly
  malformed-200 or facilitator-timeout) and a plain `500` for everything
  else (including a raw connection failure).
- The **Go** SDK (`x402-foundation/x402/go`'s gin/http server) treats
  *any* verify or settle failure — invalid payment or facilitator
  completely down — uniformly as a `402`, with the reason in the response
  body.

This template follows Go's uniform-`402` contract on the reasoning that
it's simpler and more predictable for callers (any `402` is retryable,
nothing needs special-casing), and because both wrapper templates already
agree on the part that matters operationally (never settle on a failed
upstream call). If KiteAI's actual production facilitator/agent ecosystem
expects the TypeScript SDK's `500`/`502` split instead, this is a
one-function change (`middleware.rs`'s two `Err(e) => ...` arms) and should
be revisited with someone who has visibility into what real Kite Passport
agents expect.

## 3. `cargo clippy` has not been run

The sandbox's apt-installed Rust 1.75 doesn't have `clippy` available (no
`rustup component add`). The code has been written clippy-conscious (no
obvious `.clone()`-happy patterns, `?`-propagation, etc.) but hasn't
actually been linted. The CI job added in this change (`template-rust` in
`.github/workflows/ci.yml`) runs `cargo clippy -- -D warnings` on a real
GitHub Actions Rust toolchain, so the first CI run against this PR will
either confirm it's clean or surface what needs fixing.

## 4. No `services/` manifest entry

`services/README.md` describes onboarding a *deployed* wrapper service
(with a real `service.yaml` manifest, a live `PAY_TO`, etc.) built from one
of the templates — analogous to `services/open-meteo-weather`, which is
built from `templates/typescript-express`. This change only adds the
*template* (library + example service), matching what `templates/go-gin`
and `templates/typescript-express` themselves are — neither of those has a
matching `services/` entry either. Adding a deployed service on top of this
template (its own `service.yaml`, a real upstream, a real wallet) is a
separate follow-up, not part of "add a Rust/Axum template."

## 5. Payment-requirements matching is single-option only

`x402_payment` compares the client's `accepted` field against exactly one
`PaymentRequirements` built from this route's static config (one price, one
network, one asset) — there's no `findMatchingRequirements`-style search
over multiple accepted options. This matches what both official wrapper
templates actually do today (one price per route), so it's not a gap
relative to them, but it means this crate alone isn't a drop-in replacement
for the full `x402ResourceServer` if a future wrapper template needs
multiple simultaneous price/network options on one route.
