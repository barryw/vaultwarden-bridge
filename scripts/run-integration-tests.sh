#!/usr/bin/env bash
set -euo pipefail

# Run integration tests locally with ephemeral Vaultwarden + Postgres.
# Usage: ./scripts/run-integration-tests.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

BRIDGE_PID=""
BW_APPDATA="$ROOT_DIR/.cache/bw-appdata"

cleanup() {
    echo "==> Cleaning up..."
    [ -n "$BRIDGE_PID" ] && kill "$BRIDGE_PID" 2>/dev/null || true
    # Kill any leftover bw serve on 8087
    lsof -ti:8087 2>/dev/null | xargs kill 2>/dev/null || true
    docker compose -f docker-compose.test.yml down -v 2>/dev/null || true
    rm -rf "$BW_APPDATA"
}
trap cleanup EXIT

# Clean slate
cleanup 2>/dev/null || true

echo "==> Starting Postgres and Vaultwarden..."
docker compose -f docker-compose.test.yml up -d

echo "==> Waiting for Postgres..."
for i in $(seq 1 30); do
    pg_isready -h localhost -p 5433 -U bridge > /dev/null 2>&1 && break
    [ "$i" -eq 30 ] && echo "Postgres not ready" && exit 1
    sleep 1
done
echo "==> Postgres is ready"

echo "==> Waiting for Vaultwarden..."
for i in $(seq 1 30); do
    curl -sf http://localhost:8088/alive > /dev/null 2>&1 && break
    [ "$i" -eq 30 ] && echo "Vaultwarden not ready" && exit 1
    sleep 1
done
echo "==> Vaultwarden is ready"

echo "==> Setting up bw CLI v2024.4.0..."
BW_CLI_DIR="$ROOT_DIR/.cache/bw-cli"
if [ ! -x "$BW_CLI_DIR/bw" ]; then
    mkdir -p "$BW_CLI_DIR"
    if [ "$(uname)" = "Darwin" ]; then
        BW_PLATFORM="macos"
    else
        BW_PLATFORM="linux"
    fi
    curl -fsSL "https://github.com/bitwarden/clients/releases/download/cli-v2024.4.0/bw-${BW_PLATFORM}-2024.4.0.zip" -o /tmp/bw-test.zip
    unzip -o /tmp/bw-test.zip -d "$BW_CLI_DIR"
    chmod +x "$BW_CLI_DIR/bw"
    rm /tmp/bw-test.zip
fi
export PATH="$BW_CLI_DIR:$PATH"

# Isolate bw CLI state so it doesn't conflict with user's real vault
mkdir -p "$BW_APPDATA"
export BITWARDENCLI_APPDATA_DIR="$BW_APPDATA"

echo "==> Building workspace..."
cargo build --workspace --release

echo "==> Seeding Vaultwarden..."
VAULTWARDEN_URL=http://localhost:8088 \
TEST_EMAIL=bridge-test@example.com \
TEST_PASSWORD=TestPassword123! \
BW_NOINTERACTION=true \
    node scripts/register-vaultwarden.js

echo "==> Starting bridge..."
DATABASE_URL=postgres://bridge:bridge@localhost:5433/vaultwarden_bridge \
BW_SERVER_URL=http://localhost:8088 \
BW_EMAIL=bridge-test@example.com \
BW_PASSWORD=TestPassword123! \
BW_SERVE_PORT=8087 \
BW_SERVE_EXTERNAL=false \
BRIDGE_ADMIN_USERNAME=admin \
BRIDGE_ADMIN_PASSWORD=testadmin123 \
BRIDGE_UI_ALLOW_CIDRS=0.0.0.0/0 \
BRIDGE_API_ALLOW_CIDRS=0.0.0.0/0 \
BRIDGE_LISTEN_PORT=9090 \
RUST_LOG=info \
BW_NOINTERACTION=true \
BITWARDENCLI_APPDATA_DIR="$BW_APPDATA" \
    ./target/release/vaultwarden-bridge &
BRIDGE_PID=$!

echo "==> Waiting for bridge..."
for i in $(seq 1 60); do
    curl -sf http://127.0.0.1:9090/api/v1/health > /dev/null 2>&1 && break
    [ "$i" -eq 60 ] && echo "Bridge not ready" && kill $BRIDGE_PID && exit 1
    sleep 1
done
echo "==> Bridge is ready"

export DATABASE_URL=postgres://bridge:bridge@localhost:5433/vaultwarden_bridge
export TEST_BRIDGE_URL=http://127.0.0.1:9090

echo "==> Creating vwb test key..."
VWB_TEST_TOKEN=$(./target/release/vwb-test-setup)
export VWB_TEST_TOKEN

echo "==> Running bridge integration tests..."
cargo test -p vaultwarden-bridge --test integration -- --test-threads=1

echo "==> Running vwb integration tests..."
cargo test -p vwb --test integration -- --test-threads=1

echo ""
echo "==> All integration tests passed!"
