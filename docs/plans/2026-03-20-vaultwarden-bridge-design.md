# Vaultwarden Bridge — Design Document

## Overview

**vaultwarden-bridge** is a Rust service that enables machine-to-machine secret retrieval from Vaultwarden, with a companion Terraform provider for consumption. It brings Bitwarden Secrets Manager-like capabilities to self-hosted Vaultwarden.

### Components

1. **Bridge server** (Rust) — single binary containing:
   - REST API for secret retrieval (Terraform provider calls this)
   - Web UI for managing machine keys and access policies (Askama + HTMX)
   - `bw serve` subprocess manager
   - Postgres-backed state (SQLx)

2. **Terraform provider** (Go) — minimal provider with one data source: `vaultwarden_secret`

### Deployment Model

One bridge instance per Vaultwarden account. Need multiple vaults? Deploy multiple bridges.

### Data Flow

```
Terraform --> Provider --> Bridge API --> bw serve --> Vaultwarden
                             |
                          Postgres
                       (keys, policies, audit log)
```

Secrets are never stored in Postgres — they always flow through `bw serve` at retrieval time. Postgres holds machine keys, access policies, and audit logs only.

---

## Tech Stack

| Component        | Choice                          |
|------------------|---------------------------------|
| Language         | Rust                            |
| Web framework    | Axum                            |
| Database         | PostgreSQL via SQLx (raw queries)|
| Templates        | Askama + HTMX                   |
| Terraform provider | Go (terraform-plugin-framework)|

---

## Authentication

### API (machine-to-machine)

API keys — cryptographically random, 256-bit+ entropy.

- Presented as `Authorization: Bearer <api-key>`
- Shown once at creation, only argon2 hash stored
- Scoped to access policies (zero access by default)
- Support mandatory expiry with rotation
- Immediately revocable
- Every use audit-logged

### Web UI

- Separate admin credentials configured via environment variables
- Session cookie with configurable expiry
- No self-registration — single admin user for v1

---

## Data Model

### Machine Keys

| Field        | Type      | Notes                              |
|--------------|-----------|------------------------------------|
| id           | UUID      | Primary key                        |
| name         | String    | Human-readable label               |
| key_hash     | String    | Argon2 hash (plaintext never stored)|
| expires_at   | Timestamp | Optional                           |
| enabled      | Boolean   |                                    |
| created_at   | Timestamp |                                    |
| updated_at   | Timestamp |                                    |

### Access Policies

| Field          | Type   | Notes                                     |
|----------------|--------|-------------------------------------------|
| id             | UUID   | Primary key                               |
| machine_key_id | UUID   | FK to machine keys                        |
| target_type    | Enum   | `item`, `collection`, `glob`              |
| target_value   | String | Item ID, collection ID, or glob pattern   |
| created_at     | Timestamp |                                          |

Policies are additive. A machine key has zero access by default. Policies can target:
- Specific items by ID/name
- Entire collections
- Glob patterns against item names (e.g. `prod/db/*`)

### Audit Log

| Field            | Type      | Notes                                  |
|------------------|-----------|----------------------------------------|
| id               | UUID      | Primary key                            |
| machine_key_id   | UUID      | FK to machine keys                     |
| action           | Enum      | `secret_retrieved`, `secret_not_found`, `access_denied`, `ip_denied` |
| target_requested | String    | What the caller asked for              |
| target_resolved  | String    | What it matched to (nullable)          |
| source_ip        | String    |                                        |
| client_version   | String    | From User-Agent header (nullable)      |
| timestamp        | Timestamp |                                        |

Audit logs capture denials too, not just successes.

---

## Bridge API

All API endpoints require `Authorization: Bearer <api-key>`.

### Retrieve Secret

```
GET /api/v1/secret/{key}
```

- Evaluates caller's access policies against the requested key
- If allowed, fetches from `bw serve`, returns the secret value
- If denied, returns 403
- Every call is audit-logged

**Response:**
```json
{
  "key": "prod/db/password",
  "value": "s3cret",
  "updated_at": "2026-03-18T12:00:00Z"
}
```

### Health

```
GET /api/v1/health
```

Returns bridge status and `bw serve` connectivity. No auth required.

---

## `bw serve` Management

### Startup Sequence

1. Bridge starts, reads config (Vaultwarden URL, account credentials from env vars)
2. Spawns `bw serve` on localhost-only port (e.g. `127.0.0.1:8087`)
3. Polls `bw serve` health endpoint until ready
4. Bridge marks itself healthy

### Credential Handling

- Vaultwarden login credentials provided via environment variables
- Bridge runs `bw unlock` and holds the session key in memory
- Session key never written to disk or Postgres

### Resilience

- Bridge monitors the `bw serve` process — if it dies, restart and re-authenticate
- Requests during recovery get 503 with `Retry-After` header
- Health endpoint reflects `bw serve` status for load balancer integration

### Secret Resolution

When a request arrives for key `prod/db/password`:

1. Check access policies — deny fast if no match
2. Call `bw serve` search endpoints to find matching items
3. For glob policies, match the requested key against stored patterns
4. Return the secret value from the matched item

### Caching

None. Every retrieval hits `bw serve` fresh. Secrets should never be stale.

---

## IP CIDR Filtering

Two separate allow-lists, enforced as Axum middleware before auth:

| Scope   | Env Var                  | Controls                |
|---------|--------------------------|-------------------------|
| Web UI  | `BRIDGE_UI_ALLOW_CIDRS`  | Access to `/ui/*` routes|
| API     | `BRIDGE_API_ALLOW_CIDRS` | Access to `/api/*` routes|

- Comma-separated CIDRs (e.g. `10.0.0.0/8,192.168.1.0/24`)
- If unset, deny all (secure by default)
- Env vars seed the initial config on first startup
- Manageable from the web UI after initial setup (stored in Postgres)
- Rejected requests return 403 and are audit-logged with action `ip_denied`

---

## Web UI

Server-rendered with Askama templates and HTMX for interactivity.

### Pages

**Dashboard** — machine key overview, recent audit activity, `bw serve` health status

**Machine Keys**
- List all keys (name, created, expires, enabled/disabled)
- Create key: generates API key, displays once, stores hash
- Revoke/disable key
- Set/update expiry

**Access Policies**
- Per-key policy editor
- Add policy: pick type (item, collection, glob) and enter target value
- Items/collections: typeahead search against `bw serve` for valid targets
- Globs: free text with preview of current matches
- Remove policy

**Audit Log**
- Filterable table: by machine key, action type, date range
- Columns: timestamp, machine key name, action, target requested, target resolved, source IP, client version
- Export to CSV

---

## Terraform Provider

Minimal Go provider using `terraform-plugin-framework`.

### Configuration

```hcl
provider "vaultwarden" {
  address = "https://bridge.internal:8443"
  api_key = var.vaultwarden_api_key
}
```

### Data Source

```hcl
data "vaultwarden_secret" "db_password" {
  key = "prod/db/password"
}

resource "some_resource" "example" {
  password = data.vaultwarden_secret.db_password.value
}
```

### Attributes

| Attribute    | Type   | Notes                              |
|--------------|--------|------------------------------------|
| key          | String | Required — secret identifier       |
| value        | String | Sensitive — redacted in plan output|
| updated_at   | String | Last modified in Vaultwarden       |

### Behavior

- Sends `User-Agent: terraform-provider-vaultwarden/<version>`
- Marks `value` as sensitive for Terraform redaction
- Clear error messages: 403 (access denied) vs 404 (not found)

---

## Security

### TLS
- Run behind a reverse proxy (nginx, Caddy) or accept TLS cert/key pair for standalone
- `bw serve` binds to `127.0.0.1` only — never exposed externally

### Secret Hygiene
- API keys shown once at creation, only hash stored
- Vaultwarden credentials only in env vars, never Postgres
- `bw serve` session key held in memory only
- Secret values pass through the bridge but are never logged or persisted

---

## Operations

### Logging
- Structured JSON logging via `tracing` crate
- Log levels configurable via env var
- Secret values excluded from all log output

### Audit Forwarding
- Optional external sink via webhook or syslog
- Postgres for immediate access, sink for long-term retention

### Health
- `/api/v1/health` for load balancer integration
- Reflects `bw serve` subprocess status

### Graceful Shutdown
- Drain in-flight requests
- Terminate `bw serve` subprocess

### Docker
- Single Dockerfile, minimal image
- `bw` CLI bundled in the image
- All configuration via environment variables
- Postgres connection string via env var
