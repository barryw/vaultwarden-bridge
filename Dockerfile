FROM rust:1.94.0-bookworm AS builder
WORKDIR /app
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
