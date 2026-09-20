# Known issues / follow-ups

Deliberately deferred out of the first working version so the template
lands and passes its acceptance tests now. Listed here instead of blocking
on them.

## 1. ~~Dependency versions were pinned down for this sandbox's Rust 1.75~~ — resolved

**Update:** confirmed on a real (current) Rust toolchain — `cargo update` and
`cargo clippy` both ran clean outside this sandbox. `Cargo.toml` no longer
pins `reqwest` to an exact version (`reqwest = "0.12"`, a normal range);
that pin was only ever a workaround for building in this container. The
`Cargo.lock` this sandbox generates locally (quinn/rand/idna_adapter/etc.
downgraded to versions Rust 1.75 can compile) stays out of git — a
contributor with a current toolchain gets normal, current dependency
resolution.

Original context, kept for the record:

The container this template was developed in only has `rustc`/`cargo`
1.75 available via `apt` (no network access to `rustup.rs` to install a
newer toolchain). Several transitive dependencies of `axum` 0.8 / `reqwest`
0.12 (`litemap`, `zeroize`, `idna_adapter`, the `quinn`/`rand` stack used by
reqwest's HTTP/3 support) now require Rust 1.81+ or the unstable
`edition2024` feature in their newest published versions, which 1.75
cannot build. `Cargo.lock` is (and stays) `.gitignore`d for exactly this
reason.

## 2. Real testnet settlement against a live Kite Passport agent — not yet run

Everything up to the facilitator boundary is covered by the 23 automated
tests (mock facilitator + mock upstream). Nobody has yet run this template
against the **real** Kite testnet facilitator with a real `kpass` sandbox
agent end to end (the `## Test with a Kite Passport agent` section in the
root README). That requires a live wallet and network access this
development environment doesn't have, so it's left for whoever deploys
this template to confirm before merging/going live — same as any new
service onboarding per `CONTRIBUTING.md`.

## 3. ~~TypeScript and Go SDKs disagree on facilitator-unreachable status codes~~ — decision kept

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

## 4. ~~`cargo clippy` has not been run~~ — resolved

Ran clean on a real Rust toolchain (see item 1's update). The CI job added
in this change (`template-rust` in `.github/workflows/ci.yml`) runs
`cargo clippy --workspace --all-targets -- -D warnings` on every PR going
forward so this doesn't silently regress.

## 5. No `services/` manifest entry

`services/README.md` describes onboarding a *deployed* wrapper service
(with a real `service.yaml` manifest, a live `PAY_TO`, etc.) built from one
of the templates — analogous to `services/open-meteo-weather`, which is
built from `templates/typescript-express`. This change only adds the
*template* (library + example service), matching what `templates/go-gin`
and `templates/typescript-express` themselves are — neither of those has a
matching `services/` entry either. Adding a deployed service on top of this
template (its own `service.yaml`, a real upstream, a real wallet) is a
separate follow-up, not part of "add a Rust/Axum template."

## 6. Payment-requirements matching is single-option only

`x402_payment` compares the client's `accepted` field against exactly one
`PaymentRequirements` built from this route's static config (one price, one
network, one asset) — there's no `findMatchingRequirements`-style search
over multiple accepted options. This matches what both official wrapper
templates actually do today (one price per route), so it's not a gap
relative to them, but it means this crate alone isn't a drop-in replacement
for the full `x402ResourceServer` if a future wrapper template needs
multiple simultaneous price/network options on one route.
