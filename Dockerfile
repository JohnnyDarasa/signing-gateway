# ── Build ─────────────────────────────────────────────────────────────────────
FROM rust:1.78-slim AS builder
WORKDIR /build

# Cache deps layer
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main(){}" > src/main.rs
RUN cargo build --release --features hsm-cluster 2>/dev/null || true
RUN rm -f target/release/signing-gateway

COPY . .
RUN cargo build --release --features hsm-cluster

# ── Runtime ───────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Non-root service user
RUN useradd -r -s /bin/false signing-gw
RUN mkdir -p /var/signing-gateway/keys \
    && chown signing-gw:signing-gw /var/signing-gateway/keys \
    && chmod 700 /var/signing-gateway/keys

COPY --from=builder /build/target/release/signing-gateway /usr/local/bin/
COPY config.toml /etc/signing-gateway/config.toml

# Mount vendor PKCS#11 library from host:
#   docker run -v /usr/lib/libCryptoki2_64.so:/usr/lib/libCryptoki2_64.so ...
# Or for AWS CloudHSM, mount the entire /opt/cloudhsm directory.

USER signing-gw
EXPOSE 8080 50051 9090
ENTRYPOINT ["/usr/local/bin/signing-gateway"]
