#!/usr/bin/env bash
set -euo pipefail

# Seed a Vaultwarden instance with a test account and items.
# Requires: bw CLI, VAULTWARDEN_URL, TEST_EMAIL, TEST_PASSWORD env vars.

VAULTWARDEN_URL="${VAULTWARDEN_URL:?VAULTWARDEN_URL is required}"
TEST_EMAIL="${TEST_EMAIL:-bridge-test@example.com}"
TEST_PASSWORD="${TEST_PASSWORD:-TestPassword123!}"

echo "==> Waiting for Vaultwarden to be ready..."
for i in $(seq 1 30); do
    if curl -sf "${VAULTWARDEN_URL}/alive" > /dev/null 2>&1; then
        echo "==> Vaultwarden is ready"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "ERROR: Vaultwarden did not become ready in 30s"
        exit 1
    fi
    sleep 1
done

echo "==> Configuring bw CLI for ${VAULTWARDEN_URL}"
bw config server "${VAULTWARDEN_URL}"

echo "==> Creating test account"
# Vaultwarden exposes /api/accounts/register for account creation
curl -sf -X POST "${VAULTWARDEN_URL}/api/accounts/register" \
    -H "Content-Type: application/json" \
    -d "{
        \"email\": \"${TEST_EMAIL}\",
        \"masterPasswordHash\": \"$(echo -n "${TEST_PASSWORD}" | bw encode)\",
        \"masterPasswordHint\": \"test\",
        \"name\": \"Bridge Test\",
        \"key\": \"$(bw encode <<< 'test-key')\"
    }" 2>/dev/null || echo "Account may already exist, continuing..."

echo "==> Logging in"
export BW_NOINTERACTION=true
bw login "${TEST_EMAIL}" "${TEST_PASSWORD}" --raw > /dev/null 2>&1 || true
SESSION=$(bw unlock "${TEST_PASSWORD}" --raw)
export BW_SESSION="${SESSION}"

echo "==> Creating test items"

# Create several test login items with predictable names
bw create item "$(bw encode <<< '{
    "type": 1,
    "name": "prod/db/password",
    "login": {
        "username": "db_admin",
        "password": "super-secret-db-password"
    }
}')" > /dev/null

bw create item "$(bw encode <<< '{
    "type": 1,
    "name": "prod/api/token",
    "login": {
        "username": "api-service",
        "password": "api-token-12345"
    }
}')" > /dev/null

bw create item "$(bw encode <<< '{
    "type": 1,
    "name": "staging/db/password",
    "login": {
        "username": "db_staging",
        "password": "staging-db-password"
    }
}')" > /dev/null

bw create item "$(bw encode <<< '{
    "type": 1,
    "name": "denied-secret",
    "login": {
        "username": "nope",
        "password": "you-shall-not-pass"
    }
}')" > /dev/null

bw sync

echo "==> Seed complete. Created 4 test items."
echo "    - prod/db/password"
echo "    - prod/api/token"
echo "    - staging/db/password"
echo "    - denied-secret"
