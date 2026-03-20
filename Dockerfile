FROM rust:1.85-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates curl unzip && rm -rf /var/lib/apt/lists/*

# Install Bitwarden CLI
RUN curl -fsSL "https://vault.bitwarden.com/download/?app=cli&platform=linux" -o /tmp/bw.zip \
    && unzip /tmp/bw.zip -d /usr/local/bin \
    && chmod +x /usr/local/bin/bw \
    && rm /tmp/bw.zip

COPY --from=builder /app/target/release/vaultwarden-bridge /usr/local/bin/vaultwarden-bridge
COPY --from=builder /app/templates /app/templates
COPY --from=builder /app/migrations /app/migrations

WORKDIR /app
ENV RUST_LOG=info
EXPOSE 8080
CMD ["vaultwarden-bridge"]
