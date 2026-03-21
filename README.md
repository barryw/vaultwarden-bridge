# Vaultwarden Bridge

[![Build Status](https://ci.barrywalker.io/api/badges/50/status.svg)](https://ci.barrywalker.io/repos/50)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.94%2B-orange.svg)](https://www.rust-lang.org/)

**Machine-to-machine secret retrieval from Vaultwarden, for Terraform and CI pipelines.**

---

## The Problem

You self-host [Vaultwarden](https://github.com/dani-garcia/vaultwarden). Your team stores credentials there. Now you need those credentials in Terraform runs, CI/CD pipelines, and automated workflows — but Vaultwarden has no machine API. Bitwarden Secrets Manager exists, but only for Bitwarden Cloud.

## The Solution

Vaultwarden Bridge sits between your automation and Vaultwarden. It wraps `bw serve` (the Bitwarden CLI's local REST API) and exposes a simple, authenticated API for retrieving secrets by name.

- **Machine API keys** with argon2-hashed storage and per-key access policies
- **Glob-based access control** — grant a key access to `prod/**`, `staging/db/*`, or specific items
- **Full audit trail** — every access attempt logged with key, IP, client version, and result
- **Web UI** for managing keys, policies, and viewing audit logs
- **`vwb` CLI** for pulling secrets in CI pipelines
- **Terraform provider** ([terraform-provider-vaultwarden-bridge](https://github.com/barryw/terraform-provider-vaultwarden-bridge)) for native HCL integration

```
Terraform/CI  -->  vwb CLI / Provider  -->  Bridge API  -->  bw serve  -->  Vaultwarden
                                               |
                                           PostgreSQL
                                        (keys, policies, audit)
```

## Quick Start

### Docker Compose

```bash
git clone https://github.com/barryw/vaultwarden-bridge.git
cd vaultwarden-bridge
cp .env.example .env
# Edit .env with your Vaultwarden URL, email, password, and admin password
docker compose up
```

Open `http://localhost:8080` to access the web UI.

### Kubernetes

See the [`k8s/`](k8s/) directory for deployment manifests. The bridge runs as a pod with a `bw-serve` sidecar container that handles Vaultwarden authentication.

## Configuration

All configuration is via environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes* | — | PostgreSQL connection string |
| `DB_HOST` | Yes* | — | PostgreSQL host (alternative to DATABASE_URL) |
| `DB_NAME` | No | `vaultwarden_bridge` | Database name |
| `DB_USERNAME` | Yes* | — | Database user |
| `DB_PASSWORD` | Yes* | — | Database password |
| `BW_SERVER_URL` | Yes | — | Vaultwarden URL (e.g. `https://vault.lan`) |
| `BW_EMAIL` | Yes** | — | Vaultwarden account email |
| `BW_PASSWORD` | Yes** | — | Vaultwarden master password |
| `BW_SERVE_PORT` | No | `8087` | Port for `bw serve` |
| `BW_SERVE_HOST` | No | `127.0.0.1` | Host for `bw serve` (use service name for Docker Compose) |
| `BW_SERVE_EXTERNAL` | No | `false` | Skip managed `bw serve`, connect to external sidecar |
| `BRIDGE_ADMIN_USERNAME` | Yes | — | Web UI admin username |
| `BRIDGE_ADMIN_PASSWORD` | Yes | — | Web UI admin password |
| `BRIDGE_UI_ALLOW_CIDRS` | No | *(deny all)* | Comma-separated CIDRs for web UI access |
| `BRIDGE_API_ALLOW_CIDRS` | No | *(deny all)* | Comma-separated CIDRs for API access |
| `BRIDGE_LISTEN_PORT` | No | `8080` | HTTP listen port |
| `RUST_LOG` | No | `info` | Log level |

\* Either `DATABASE_URL` or `DB_HOST`/`DB_USERNAME`/`DB_PASSWORD` is required.
\*\* Not required when `BW_SERVE_EXTERNAL=true`.

## Usage

### 1. Create a Machine Key

Log into the web UI and go to **Machine Keys**. Create a key — the API key is shown once. Copy it.

### 2. Add Access Policies

Click **Policies** on the key. Add policies to control which secrets the key can access:

| Type | Example | Description |
|------|---------|-------------|
| **Item** | `prod/db/password` | Exact item name match |
| **Glob** | `prod/**` | Glob pattern against item names |
| **Collection** | `uuid-here` | All items in a Vaultwarden collection |

A key with no policies has zero access. Policies are additive.

### 3. Retrieve Secrets

#### API

```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  https://vault-bridge.lan/api/v1/secret/prod/db/password
```

```json
{
  "key": "prod/db/password",
  "value": "s3cret",
  "updated_at": "2026-03-18T12:00:00Z"
}
```

#### vwb CLI

Install:

```bash
curl -fsSL https://github.com/barryw/vaultwarden-bridge/releases/latest/download/vwb-linux-amd64 \
  -o /usr/local/bin/vwb && chmod +x /usr/local/bin/vwb
```

Use:

```bash
export VWB_ADDR=https://vault-bridge.lan
export VWB_TOKEN=your-api-key

# Fetch a secret
export DB_PASSWORD=$(vwb get prod/db/password)

# Use inline
docker login -u admin -p $(vwb get registry/password) ghcr.io
```

| Variable | Required | Description |
|----------|----------|-------------|
| `VWB_ADDR` | Yes | Bridge server URL |
| `VWB_TOKEN` | Yes | Machine API key |
| `VWB_CA_CERT` | No | Path to custom CA certificate PEM file |

#### Terraform Provider

```hcl
provider "vaultwarden-bridge" {
  address = "https://vault-bridge.lan"
  api_key = var.bridge_api_key
}

data "vaultwarden-bridge_secret" "db_password" {
  key = "prod/db/password"
}

resource "postgresql_database" "app" {
  name     = "myapp"
  password = data.vaultwarden-bridge_secret.db_password.value
}
```

See [terraform-provider-vaultwarden-bridge](https://github.com/barryw/terraform-provider-vaultwarden-bridge) for full documentation.

#### Woodpecker CI

```yaml
steps:
  - name: deploy
    image: alpine
    environment:
      VWB_ADDR:
        from_secret: vwb_addr
      VWB_TOKEN:
        from_secret: vwb_token
    commands:
      - curl -fsSL https://github.com/barryw/vaultwarden-bridge/releases/latest/download/vwb-linux-amd64 -o /usr/local/bin/vwb && chmod +x /usr/local/bin/vwb
      - export DB_PASSWORD=$(vwb get prod/db/password)
      - ./deploy.sh
```

## Security

- **API keys** are argon2-hashed with a fast-lookup prefix index — plaintext is never stored
- **CIDR filtering** on both UI and API endpoints (deny-all by default)
- **Session auth** with HMAC-SHA256 signed cookies (HttpOnly, Secure, SameSite=Strict)
- **Rate limiting** on the secrets API (60 burst, 30/s sustained per IP)
- **Audit logging** of every access attempt (success, denied, not found)
- **IP-based audit trail** using real socket address (not spoofable headers)
- **Secrets never stored** in the bridge database — they flow through `bw serve` on every request
- **Distroless runtime** container with non-root user, dropped capabilities

## Architecture

```
┌─────────────────────────────────────────────────────┐
│ Kubernetes Pod                                       │
│                                                      │
│  ┌──────────────────┐     ┌──────────────────────┐  │
│  │ vaultwarden-bridge│────▶│ bw-serve (sidecar)   │  │
│  │ (Rust/Axum)      │:8087│ (Node.js)            │  │
│  │                  │     │                      │  │
│  │ - REST API       │     │ - Bitwarden CLI      │  │
│  │ - Web UI (HTMX)  │     │ - Vault auth/unlock  │  │
│  │ - Auth/policies  │     │ - Item search        │  │
│  │ - Audit logging  │     └──────────────────────┘  │
│  │ - Rate limiting  │                                │
│  └────────┬─────────┘                                │
│           │                                          │
└───────────┼──────────────────────────────────────────┘
            │
     ┌──────▼──────┐          ┌──────────────────┐
     │ PostgreSQL   │          │ Vaultwarden      │
     │ (CNPG)      │          │ (self-hosted)    │
     │             │          │                  │
     │ - Keys      │          │ - Vault items    │
     │ - Policies  │          │ - Collections    │
     │ - Audit log │          │ - User accounts  │
     │ - CIDRs     │          │                  │
     └─────────────┘          └──────────────────┘
```

## Development

### Prerequisites

- Rust 1.94+ (pinned via `rust-toolchain.toml`)
- Docker & Docker Compose
- Node.js 18+ (for Vaultwarden seeding scripts)
- PostgreSQL client (`pg_isready`)

### Run Tests

```bash
# Unit tests (no external services needed)
cargo test --workspace --lib
cargo test -p vwb --bin vwb

# Integration tests (spins up Postgres + Vaultwarden in Docker)
./scripts/run-integration-tests.sh
```

### Project Structure

```
vaultwarden-bridge/
├── bridge/              # Main Rust service (Axum)
│   ├── src/
│   │   ├── api/         # REST API (secret retrieval, health)
│   │   ├── ui/          # Web UI handlers (Askama + HTMX)
│   │   ├── db/          # Database access (SQLx, raw queries)
│   │   ├── auth.rs      # API key generation/verification
│   │   ├── bw.rs        # bw serve client & manager
│   │   ├── policy.rs    # Access policy evaluation (glob matching)
│   │   ├── middleware.rs # CIDR filtering
│   │   └── audit.rs     # Audit logging
│   ├── templates/       # Askama HTML templates
│   └── migrations/      # SQLx database migrations
├── vwb/                 # CLI tool (single binary)
├── test-setup/          # Test helper (creates CI test keys)
├── k8s/                 # Kubernetes deployment manifests
├── scripts/             # CI seeding & local test runner
├── .woodpecker/         # CI/CD pipelines
├── Dockerfile           # Bridge container (distroless)
└── Dockerfile.bw-serve  # bw-serve sidecar container
```

## License

MIT
