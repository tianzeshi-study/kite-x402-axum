# syntax=docker/dockerfile:1
FROM rust:1.88-slim-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY kite-x402-axum/Cargo.toml kite-x402-axum/
COPY service/Cargo.toml service/

# Pre-build dependencies for caching
RUN mkdir -p kite-x402-axum/src service/src \
    && echo "pub fn dummy() {}" > kite-x402-axum/src/lib.rs \
    && echo "fn main() {}" > service/src/main.rs \
    && cargo build --release --workspace \
    && rm -rf kite-x402-axum/src service/src

# Copy real sources and build the service binary
COPY kite-x402-axum/src kite-x402-axum/src
COPY service/src service/src
RUN touch kite-x402-axum/src/lib.rs service/src/main.rs \
    && cargo build --release --bin kite-x402-service --locked

# Minimal production runtime image
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1001 -s /bin/bash appuser

WORKDIR /home/appuser/app
COPY --from=builder /app/target/release/kite-x402-service /usr/local/bin/kite-x402-service

USER appuser

EXPOSE 8402

HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
  CMD curl -f http://127.0.0.1:8402/healthz || exit 1

ENTRYPOINT ["kite-x402-service"]
