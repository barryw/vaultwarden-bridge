FROM rust:1.94.0-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim AS bw-fetch
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl unzip ca-certificates \
    && curl -fsSL "https://vault.bitwarden.com/download/?app=cli&platform=linux" -o /tmp/bw.zip \
    && unzip /tmp/bw.zip -d /tmp \
    && chmod +x /tmp/bw \
    && rm -rf /var/lib/apt/lists/*

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=bw-fetch /tmp/bw /usr/local/bin/bw
COPY --from=builder /app/target/release/vaultwarden-bridge /usr/local/bin/vaultwarden-bridge
COPY --from=builder /app/templates /app/templates
COPY --from=builder /app/migrations /app/migrations

WORKDIR /app
ENV RUST_LOG=info
ENV BITWARDENCLI_APPDATA_DIR=/tmp/bw-data
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["vaultwarden-bridge"]
