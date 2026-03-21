FROM rust:1.94.0-bookworm AS builder
WORKDIR /app

# Cache dependencies - copy manifests first, build with dummy source
COPY Cargo.toml Cargo.lock ./
COPY bridge/Cargo.toml bridge/Cargo.toml
COPY vwb/Cargo.toml vwb/Cargo.toml
RUN mkdir -p bridge/src vwb/src \
    && echo "fn main() {}" > bridge/src/main.rs \
    && echo "" > bridge/src/lib.rs \
    && echo "fn main() {}" > vwb/src/main.rs \
    && cargo build --release -p vaultwarden-bridge 2>/dev/null || true \
    && rm -rf bridge/src vwb/src

# Now copy real source and build (deps already cached)
COPY . .
RUN cargo build --release -p vaultwarden-bridge

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /app/target/release/vaultwarden-bridge /usr/local/bin/vaultwarden-bridge
COPY --from=builder /app/bridge/templates /app/templates
COPY --from=builder /app/bridge/migrations /app/migrations

WORKDIR /app
ENV RUST_LOG=info
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["vaultwarden-bridge"]
