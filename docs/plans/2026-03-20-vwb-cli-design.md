# vwb CLI — Design Document

## Overview

`vwb` is a single-purpose CLI that fetches one secret from a Vaultwarden Bridge instance and prints it to stdout. Designed for CI pipelines where secrets need to be pulled at runtime rather than stored in the CI system's secret store.

## Usage

```bash
vwb get <key>
```

**Example in CI:**
```bash
export DB_PASSWORD=$(vwb get prod/db/password)
export API_TOKEN=$(vwb get prod/api/token)
terraform apply -var="db_password=$(vwb get prod/db/password)"
```

## Configuration

Environment variables only — no config files, no flags for credentials.

| Env Var | Required | Description |
|---------|----------|-------------|
| `VWB_ADDR` | Yes | Bridge URL (e.g. `https://vault-bridge.lan`) |
| `VWB_TOKEN` | Yes | Machine API key |

## Behavior

- Calls `GET {VWB_ADDR}/api/v1/secret/{key}` with `Authorization: Bearer {VWB_TOKEN}`
- Prints the secret value to stdout (no trailing newline)
- Sends `User-Agent: vwb/<version>` for audit trail
- Exit 0 on success
- Exit 1 with clear error on stderr for: missing env vars, HTTP errors (401/403/404/5xx), network failures
- Never writes to disk

## Project Structure

Second binary in the `vaultwarden-bridge` Cargo workspace. No shared code with the bridge — it's too small to need it.

Dependencies: `reqwest` (blocking client), `serde_json`, `std::env`.

## Distribution

Single static binary per platform, downloadable from GitHub releases:

```bash
curl -fsSL https://github.com/barryw/vaultwarden-bridge/releases/download/v0.1.0/vwb-linux-amd64 -o /usr/local/bin/vwb
```
