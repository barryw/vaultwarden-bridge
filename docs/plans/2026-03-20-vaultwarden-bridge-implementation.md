# Vaultwarden Bridge Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Rust bridge service that enables Terraform to retrieve secrets from Vaultwarden via machine API keys with access policies, plus a companion Go Terraform provider.

**Architecture:** Axum web server wrapping a `bw serve` subprocess. Postgres stores machine keys (argon2 hashed), access policies (item/collection/glob), and audit logs. Web UI via Askama+HTMX. Terraform provider is a separate Go module with a single data source.

**Tech Stack:** Rust (Axum 0.8, SQLx 0.8, Askama 0.13, askama_web 0.14, argon2 0.5, tracing), Go (terraform-plugin-framework 1.19), PostgreSQL, HTMX 1.10

---

## Task 1: Rust Project Scaffolding

**Files:**
- Create: `Cargo.toml`
- Create: `src/main.rs`
- Create: `src/lib.rs`
- Create: `.env.example`
- Create: `.gitignore`

**Step 1: Create `.gitignore`**

```gitignore
/target
.env
*.swp
*.swo
```

**Step 2: Create `Cargo.toml`**

```toml
[package]
name = "vaultwarden-bridge"
version = "0.1.0"
edition = "2024"

[dependencies]
axum = "0.8"
askama = "0.13"
askama_web = { version = "0.14", features = ["axum-0.8"] }
tokio = { version = "1", features = ["full"] }
tower = "0.5"
tower-http = { version = "0.6", features = ["trace", "fs"] }
sqlx = { version = "0.8", features = ["runtime-tokio-rustls", "postgres", "uuid", "chrono"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
uuid = { version = "1", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
argon2 = "0.5"
rand = "0.9"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["json", "env-filter"] }
glob-match = "0.2"
ipnet = "2"
thiserror = "2"
dotenvy = "0.15"

[dev-dependencies]
reqwest = { version = "0.12", features = ["json"] }
```

**Step 3: Create `src/lib.rs`**

```rust
pub mod config;
pub mod db;
pub mod bw;
pub mod auth;
pub mod middleware;
pub mod api;
pub mod ui;
pub mod audit;
pub mod error;
```

**Step 4: Create `src/main.rs`**

```rust
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    tracing::info!("starting vaultwarden-bridge");

    let config = vaultwarden_bridge::config::Config::from_env()?;
    let pool = sqlx::PgPool::connect(&config.database_url).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;

    let app = vaultwarden_bridge::app(pool, config).await?;

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    tracing::info!(%addr, "listening");
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
```

**Step 5: Create `.env.example`**

```
DATABASE_URL=postgres://bridge:bridge@localhost:5432/vaultwarden_bridge
BW_SERVER_URL=https://vault.example.com
BW_EMAIL=bridge@example.com
BW_PASSWORD=changeme
BW_SERVE_PORT=8087
BRIDGE_ADMIN_USERNAME=admin
BRIDGE_ADMIN_PASSWORD=changeme
BRIDGE_UI_ALLOW_CIDRS=0.0.0.0/0
BRIDGE_API_ALLOW_CIDRS=0.0.0.0/0
RUST_LOG=info
```

**Step 6: Add `anyhow` to Cargo.toml dependencies**

Add `anyhow = "1"` to `[dependencies]`.

**Step 7: Verify it compiles**

Run: `cargo check`
Expected: Compilation errors for missing modules — that's fine, scaffolding is in place.

**Step 8: Commit**

```bash
git add Cargo.toml src/main.rs src/lib.rs .env.example .gitignore
git commit -m "feat: project scaffolding with dependencies"
```

---

## Task 2: Configuration Module

**Files:**
- Create: `src/config.rs`
- Test: `src/config.rs` (inline tests)

**Step 1: Write the failing test**

In `src/config.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cidrs_valid() {
        let cidrs = parse_cidrs("10.0.0.0/8,192.168.1.0/24").unwrap();
        assert_eq!(cidrs.len(), 2);
    }

    #[test]
    fn test_parse_cidrs_empty_denies_all() {
        let cidrs = parse_cidrs("").unwrap();
        assert!(cidrs.is_empty());
    }

    #[test]
    fn test_parse_cidrs_invalid() {
        assert!(parse_cidrs("not-a-cidr").is_err());
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --lib config`
Expected: FAIL — `parse_cidrs` not defined.

**Step 3: Write the implementation**

```rust
use ipnet::IpNet;
use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub bw_server_url: String,
    pub bw_email: String,
    pub bw_password: String,
    pub bw_serve_port: u16,
    pub admin_username: String,
    pub admin_password: String,
    pub ui_allow_cidrs: Vec<IpNet>,
    pub api_allow_cidrs: Vec<IpNet>,
    pub listen_port: u16,
}

pub fn parse_cidrs(s: &str) -> Result<Vec<IpNet>, ipnet::AddrParseError> {
    if s.trim().is_empty() {
        return Ok(vec![]);
    }
    s.split(',')
        .map(|c| c.trim().parse::<IpNet>())
        .collect()
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            database_url: env::var("DATABASE_URL")?,
            bw_server_url: env::var("BW_SERVER_URL")?,
            bw_email: env::var("BW_EMAIL")?,
            bw_password: env::var("BW_PASSWORD")?,
            bw_serve_port: env::var("BW_SERVE_PORT")
                .unwrap_or_else(|_| "8087".to_string())
                .parse()?,
            admin_username: env::var("BRIDGE_ADMIN_USERNAME")?,
            admin_password: env::var("BRIDGE_ADMIN_PASSWORD")?,
            ui_allow_cidrs: parse_cidrs(
                &env::var("BRIDGE_UI_ALLOW_CIDRS").unwrap_or_default(),
            )?,
            api_allow_cidrs: parse_cidrs(
                &env::var("BRIDGE_API_ALLOW_CIDRS").unwrap_or_default(),
            )?,
            listen_port: env::var("BRIDGE_LISTEN_PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()?,
        })
    }
}
```

**Step 4: Run tests**

Run: `cargo test --lib config`
Expected: PASS

**Step 5: Commit**

```bash
git add src/config.rs
git commit -m "feat: configuration module with CIDR parsing"
```

---

## Task 3: Error Types

**Files:**
- Create: `src/error.rs`

**Step 1: Write error types**

```rust
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden")]
    Forbidden,

    #[error("not found: {0}")]
    NotFound(String),

    #[error("access denied")]
    AccessDenied,

    #[error("ip denied")]
    IpDenied,

    #[error("service unavailable: {0}")]
    ServiceUnavailable(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match &self {
            AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            AppError::Forbidden | AppError::AccessDenied | AppError::IpDenied => {
                StatusCode::FORBIDDEN
            }
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let body = serde_json::json!({ "error": self.to_string() });
        (status, axum::Json(body)).into_response()
    }
}
```

**Step 2: Verify it compiles**

Run: `cargo check`

**Step 3: Commit**

```bash
git add src/error.rs
git commit -m "feat: application error types"
```

---

## Task 4: Database Schema & Migrations

**Files:**
- Create: `migrations/20260320000001_create_machine_keys.up.sql`
- Create: `migrations/20260320000001_create_machine_keys.down.sql`
- Create: `migrations/20260320000002_create_access_policies.up.sql`
- Create: `migrations/20260320000002_create_access_policies.down.sql`
- Create: `migrations/20260320000003_create_audit_log.up.sql`
- Create: `migrations/20260320000003_create_audit_log.down.sql`
- Create: `migrations/20260320000004_create_cidr_rules.up.sql`
- Create: `migrations/20260320000004_create_cidr_rules.down.sql`

**Step 1: Create machine_keys migration (up)**

```sql
CREATE TABLE machine_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    key_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

**Step 2: Create machine_keys migration (down)**

```sql
DROP TABLE machine_keys;
```

**Step 3: Create access_policies migration (up)**

```sql
CREATE TYPE target_type AS ENUM ('item', 'collection', 'glob');

CREATE TABLE access_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    machine_key_id UUID NOT NULL REFERENCES machine_keys(id) ON DELETE CASCADE,
    target_type target_type NOT NULL,
    target_value TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_access_policies_key_id ON access_policies(machine_key_id);
```

**Step 4: Create access_policies migration (down)**

```sql
DROP TABLE access_policies;
DROP TYPE target_type;
```

**Step 5: Create audit_log migration (up)**

```sql
CREATE TYPE audit_action AS ENUM (
    'secret_retrieved',
    'secret_not_found',
    'access_denied',
    'ip_denied'
);

CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    machine_key_id UUID REFERENCES machine_keys(id) ON DELETE SET NULL,
    action audit_action NOT NULL,
    target_requested TEXT NOT NULL,
    target_resolved TEXT,
    source_ip TEXT NOT NULL,
    client_version TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_log_key_id ON audit_log(machine_key_id);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at);
```

**Step 6: Create audit_log migration (down)**

```sql
DROP TABLE audit_log;
DROP TYPE audit_action;
```

**Step 7: Create cidr_rules migration (up)**

```sql
CREATE TYPE cidr_scope AS ENUM ('ui', 'api');

CREATE TABLE cidr_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope cidr_scope NOT NULL,
    cidr TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

**Step 8: Create cidr_rules migration (down)**

```sql
DROP TABLE cidr_rules;
DROP TYPE cidr_scope;
```

**Step 9: Verify migrations compile with SQLx**

Run: `cargo check`
Expected: PASS (migrations will run at startup)

**Step 10: Commit**

```bash
git add migrations/
git commit -m "feat: database schema migrations"
```

---

## Task 5: Database Access Layer

**Files:**
- Create: `src/db.rs`
- Create: `src/db/machine_keys.rs`
- Create: `src/db/access_policies.rs`
- Create: `src/db/audit.rs`
- Create: `src/db/cidr_rules.rs`

**Step 1: Create `src/db.rs` as module root**

```rust
pub mod machine_keys;
pub mod access_policies;
pub mod audit;
pub mod cidr_rules;
```

**Step 2: Create `src/db/machine_keys.rs`**

```rust
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MachineKey {
    pub id: Uuid,
    pub name: String,
    pub key_hash: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub async fn create(pool: &PgPool, name: &str, key_hash: &str) -> Result<MachineKey, sqlx::Error> {
    sqlx::query_as::<_, MachineKey>(
        "INSERT INTO machine_keys (name, key_hash) VALUES ($1, $2) RETURNING *",
    )
    .bind(name)
    .bind(key_hash)
    .fetch_one(pool)
    .await
}

pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<MachineKey>, sqlx::Error> {
    sqlx::query_as::<_, MachineKey>("SELECT * FROM machine_keys WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn list(pool: &PgPool) -> Result<Vec<MachineKey>, sqlx::Error> {
    sqlx::query_as::<_, MachineKey>("SELECT * FROM machine_keys ORDER BY created_at DESC")
        .fetch_all(pool)
        .await
}

pub async fn find_all_enabled(pool: &PgPool) -> Result<Vec<MachineKey>, sqlx::Error> {
    sqlx::query_as::<_, MachineKey>(
        "SELECT * FROM machine_keys WHERE enabled = true AND (expires_at IS NULL OR expires_at > now())",
    )
    .fetch_all(pool)
    .await
}

pub async fn set_enabled(pool: &PgPool, id: Uuid, enabled: bool) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE machine_keys SET enabled = $1, updated_at = now() WHERE id = $2")
        .bind(enabled)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn set_expires(
    pool: &PgPool,
    id: Uuid,
    expires_at: Option<DateTime<Utc>>,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE machine_keys SET expires_at = $1, updated_at = now() WHERE id = $2")
        .bind(expires_at)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM machine_keys WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}
```

**Step 3: Create `src/db/access_policies.rs`**

```rust
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::Type)]
#[sqlx(type_name = "target_type", rename_all = "lowercase")]
pub enum TargetType {
    Item,
    Collection,
    Glob,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AccessPolicy {
    pub id: Uuid,
    pub machine_key_id: Uuid,
    pub target_type: TargetType,
    pub target_value: String,
    pub created_at: DateTime<Utc>,
}

pub async fn create(
    pool: &PgPool,
    machine_key_id: Uuid,
    target_type: TargetType,
    target_value: &str,
) -> Result<AccessPolicy, sqlx::Error> {
    sqlx::query_as::<_, AccessPolicy>(
        "INSERT INTO access_policies (machine_key_id, target_type, target_value) VALUES ($1, $2, $3) RETURNING *",
    )
    .bind(machine_key_id)
    .bind(&target_type)
    .bind(target_value)
    .fetch_one(pool)
    .await
}

pub async fn list_for_key(
    pool: &PgPool,
    machine_key_id: Uuid,
) -> Result<Vec<AccessPolicy>, sqlx::Error> {
    sqlx::query_as::<_, AccessPolicy>(
        "SELECT * FROM access_policies WHERE machine_key_id = $1 ORDER BY created_at",
    )
    .bind(machine_key_id)
    .fetch_all(pool)
    .await
}

pub async fn delete(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM access_policies WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}
```

**Step 4: Create `src/db/audit.rs`**

```rust
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::Type)]
#[sqlx(type_name = "audit_action", rename_all = "snake_case")]
pub enum AuditAction {
    SecretRetrieved,
    SecretNotFound,
    AccessDenied,
    IpDenied,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuditEntry {
    pub id: Uuid,
    pub machine_key_id: Option<Uuid>,
    pub action: AuditAction,
    pub target_requested: String,
    pub target_resolved: Option<String>,
    pub source_ip: String,
    pub client_version: Option<String>,
    pub created_at: DateTime<Utc>,
}

pub struct NewAuditEntry<'a> {
    pub machine_key_id: Option<Uuid>,
    pub action: AuditAction,
    pub target_requested: &'a str,
    pub target_resolved: Option<&'a str>,
    pub source_ip: &'a str,
    pub client_version: Option<&'a str>,
}

pub async fn insert(pool: &PgPool, entry: &NewAuditEntry<'_>) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_log (machine_key_id, action, target_requested, target_resolved, source_ip, client_version) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(entry.machine_key_id)
    .bind(&entry.action)
    .bind(entry.target_requested)
    .bind(entry.target_resolved)
    .bind(entry.source_ip)
    .bind(entry.client_version)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_recent(pool: &PgPool, limit: i64) -> Result<Vec<AuditEntry>, sqlx::Error> {
    sqlx::query_as::<_, AuditEntry>(
        "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await
}

pub async fn list_filtered(
    pool: &PgPool,
    machine_key_id: Option<Uuid>,
    action: Option<AuditAction>,
    since: Option<DateTime<Utc>>,
    until: Option<DateTime<Utc>>,
    limit: i64,
    offset: i64,
) -> Result<Vec<AuditEntry>, sqlx::Error> {
    sqlx::query_as::<_, AuditEntry>(
        "SELECT * FROM audit_log \
         WHERE ($1::uuid IS NULL OR machine_key_id = $1) \
         AND ($2::audit_action IS NULL OR action = $2) \
         AND ($3::timestamptz IS NULL OR created_at >= $3) \
         AND ($4::timestamptz IS NULL OR created_at <= $4) \
         ORDER BY created_at DESC LIMIT $5 OFFSET $6",
    )
    .bind(machine_key_id)
    .bind(action)
    .bind(since)
    .bind(until)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
}
```

**Step 5: Create `src/db/cidr_rules.rs`**

```rust
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::Type)]
#[sqlx(type_name = "cidr_scope", rename_all = "lowercase")]
pub enum CidrScope {
    Ui,
    Api,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CidrRule {
    pub id: Uuid,
    pub scope: CidrScope,
    pub cidr: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

pub async fn list_by_scope(pool: &PgPool, scope: CidrScope) -> Result<Vec<CidrRule>, sqlx::Error> {
    sqlx::query_as::<_, CidrRule>("SELECT * FROM cidr_rules WHERE scope = $1 ORDER BY created_at")
        .bind(&scope)
        .fetch_all(pool)
        .await
}

pub async fn create(pool: &PgPool, scope: CidrScope, cidr: &str) -> Result<CidrRule, sqlx::Error> {
    sqlx::query_as::<_, CidrRule>(
        "INSERT INTO cidr_rules (scope, cidr) VALUES ($1, $2) RETURNING *",
    )
    .bind(&scope)
    .bind(cidr)
    .fetch_one(pool)
    .await
}

pub async fn delete(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM cidr_rules WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn seed_from_config(
    pool: &PgPool,
    scope: CidrScope,
    cidrs: &[ipnet::IpNet],
) -> Result<(), sqlx::Error> {
    let existing = list_by_scope(pool, scope.clone()).await?;
    if existing.is_empty() && !cidrs.is_empty() {
        for cidr in cidrs {
            create(pool, scope.clone(), &cidr.to_string()).await?;
        }
    }
    Ok(())
}
```

**Step 6: Verify it compiles**

Run: `cargo check`

**Step 7: Commit**

```bash
git add src/db.rs src/db/
git commit -m "feat: database access layer for keys, policies, audit, cidrs"
```

---

## Task 6: API Key Auth Module

**Files:**
- Create: `src/auth.rs`

**Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_api_key_length() {
        let key = generate_api_key();
        // Base64 of 32 bytes = 44 chars (with padding) or 43 (without)
        assert!(key.len() >= 43);
    }

    #[test]
    fn test_hash_and_verify() {
        let key = generate_api_key();
        let hash = hash_api_key(&key).unwrap();
        assert!(verify_api_key(&key, &hash).unwrap());
    }

    #[test]
    fn test_verify_wrong_key() {
        let key = generate_api_key();
        let hash = hash_api_key(&key).unwrap();
        let wrong = generate_api_key();
        assert!(!verify_api_key(&wrong, &hash).unwrap());
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --lib auth`
Expected: FAIL

**Step 3: Write implementation**

```rust
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::RngCore;

pub fn generate_api_key() -> String {
    use base64::Engine;
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn hash_api_key(key: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default().hash_password(key.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

pub fn verify_api_key(key: &str, hash: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed = PasswordHash::new(hash)?;
    Ok(Argon2::default()
        .verify_password(key.as_bytes(), &parsed)
        .is_ok())
}
```

**Step 4: Add `base64` dependency**

Add `base64 = "0.22"` to `Cargo.toml` `[dependencies]`.

**Step 5: Run tests**

Run: `cargo test --lib auth`
Expected: PASS

**Step 6: Commit**

```bash
git add src/auth.rs Cargo.toml
git commit -m "feat: API key generation, hashing, and verification"
```

---

## Task 7: `bw serve` Subprocess Manager

**Files:**
- Create: `src/bw.rs`

**Step 1: Write the bw serve client and manager**

```rust
use serde::Deserialize;
use std::sync::Arc;
use tokio::process::{Child, Command};
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct BwClient {
    base_url: String,
    http: reqwest::Client,
}

#[derive(Debug, Deserialize)]
pub struct BwItem {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub item_type: i32,
    pub login: Option<BwLogin>,
    pub notes: Option<String>,
    #[serde(rename = "collectionIds")]
    pub collection_ids: Option<Vec<String>>,
    #[serde(rename = "revisionDate")]
    pub revision_date: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BwLogin {
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BwListResponse {
    success: bool,
    data: Option<BwListData>,
}

#[derive(Debug, Deserialize)]
struct BwListData {
    data: Vec<BwItem>,
}

#[derive(Debug, Deserialize)]
struct BwItemResponse {
    success: bool,
    data: Option<BwItem>,
}

impl BwClient {
    pub fn new(port: u16) -> Self {
        Self {
            base_url: format!("http://127.0.0.1:{}", port),
            http: reqwest::Client::new(),
        }
    }

    pub async fn health(&self) -> bool {
        self.http
            .get(format!("{}/sync", self.base_url))
            .send()
            .await
            .is_ok()
    }

    pub async fn list_items(&self, search: Option<&str>) -> anyhow::Result<Vec<BwItem>> {
        let mut url = format!("{}/list/object/items", self.base_url);
        if let Some(q) = search {
            url = format!("{}?search={}", url, urlencoding::encode(q));
        }
        let resp: BwListResponse = self.http.get(&url).send().await?.json().await?;
        Ok(resp.data.map(|d| d.data).unwrap_or_default())
    }

    pub async fn get_item(&self, id: &str) -> anyhow::Result<Option<BwItem>> {
        let url = format!("{}/object/item/{}", self.base_url, id);
        let resp = self.http.get(&url).send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let body: BwItemResponse = resp.json().await?;
        Ok(body.data)
    }

    pub async fn sync(&self) -> anyhow::Result<()> {
        self.http
            .post(format!("{}/sync", self.base_url))
            .send()
            .await?;
        Ok(())
    }
}

pub struct BwManager {
    pub client: BwClient,
    child: Arc<RwLock<Option<Child>>>,
    server_url: String,
    email: String,
    password: String,
    port: u16,
}

impl BwManager {
    pub fn new(server_url: String, email: String, password: String, port: u16) -> Self {
        Self {
            client: BwClient::new(port),
            child: Arc::new(RwLock::new(None)),
            server_url,
            email,
            password,
            port,
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        // Configure server URL
        Command::new("bw")
            .args(["config", "server", &self.server_url])
            .output()
            .await?;

        // Login
        let login_output = Command::new("bw")
            .args(["login", &self.email, &self.password, "--raw"])
            .env("BW_NOINTERACTION", "true")
            .output()
            .await?;

        if !login_output.status.success() {
            // May already be logged in, try unlock instead
            tracing::info!("login failed, attempting unlock");
        }

        // Unlock and get session
        let unlock_output = Command::new("bw")
            .args(["unlock", &self.password, "--raw"])
            .env("BW_NOINTERACTION", "true")
            .output()
            .await?;

        let session = String::from_utf8(unlock_output.stdout)?.trim().to_string();
        if session.is_empty() {
            anyhow::bail!("failed to unlock vault — empty session key");
        }

        // Start bw serve
        let child = Command::new("bw")
            .args([
                "serve",
                "--hostname",
                "127.0.0.1",
                "--port",
                &self.port.to_string(),
            ])
            .env("BW_SESSION", &session)
            .env("BW_NOINTERACTION", "true")
            .spawn()?;

        *self.child.write().await = Some(child);

        // Wait for bw serve to become healthy
        for _ in 0..30 {
            if self.client.health().await {
                tracing::info!("bw serve is healthy");
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }

        anyhow::bail!("bw serve failed to become healthy within 30s")
    }

    pub async fn is_healthy(&self) -> bool {
        self.client.health().await
    }

    pub async fn stop(&self) {
        if let Some(mut child) = self.child.write().await.take() {
            let _ = child.kill().await;
        }
    }
}
```

**Step 2: Add `urlencoding` and move `reqwest` to main deps**

Add to `Cargo.toml` `[dependencies]`:
```toml
urlencoding = "2"
reqwest = { version = "0.12", features = ["json"] }
```

Remove `reqwest` from `[dev-dependencies]`.

**Step 3: Verify it compiles**

Run: `cargo check`

**Step 4: Commit**

```bash
git add src/bw.rs Cargo.toml
git commit -m "feat: bw serve subprocess manager and client"
```

---

## Task 8: CIDR Filtering Middleware

**Files:**
- Create: `src/middleware.rs`

**Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_ip_in_cidr_list() {
        let cidrs: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        assert!(ip_allowed(&ip, &cidrs));
    }

    #[test]
    fn test_ip_not_in_cidr_list() {
        let cidrs: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(!ip_allowed(&ip, &cidrs));
    }

    #[test]
    fn test_empty_cidr_list_denies_all() {
        let cidrs: Vec<IpNet> = vec![];
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        assert!(!ip_allowed(&ip, &cidrs));
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --lib middleware`
Expected: FAIL

**Step 3: Write implementation**

```rust
use axum::{
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};

pub fn ip_allowed(ip: &IpAddr, cidrs: &[IpNet]) -> bool {
    cidrs.iter().any(|cidr| cidr.contains(ip))
}

pub async fn cidr_filter_api(
    State(cidrs): State<Vec<IpNet>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if !ip_allowed(&addr.ip(), &cidrs) {
        tracing::warn!(ip = %addr.ip(), "API request denied by CIDR filter");
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(next.run(request).await)
}

pub async fn cidr_filter_ui(
    State(cidrs): State<Vec<IpNet>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if !ip_allowed(&addr.ip(), &cidrs) {
        tracing::warn!(ip = %addr.ip(), "UI request denied by CIDR filter");
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(next.run(request).await)
}
```

**Step 4: Run tests**

Run: `cargo test --lib middleware`
Expected: PASS

**Step 5: Commit**

```bash
git add src/middleware.rs
git commit -m "feat: CIDR filtering middleware"
```

---

## Task 9: Access Policy Evaluation (Glob Matching)

**Files:**
- Create: `src/policy.rs`
- Modify: `src/lib.rs` — add `pub mod policy;`

**Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::access_policies::TargetType;

    fn policy(target_type: TargetType, target_value: &str) -> AccessPolicy {
        AccessPolicy {
            id: uuid::Uuid::new_v4(),
            machine_key_id: uuid::Uuid::new_v4(),
            target_type,
            target_value: target_value.to_string(),
            created_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_exact_item_match() {
        let policies = vec![policy(TargetType::Item, "prod/db/password")];
        assert!(evaluate_access(&policies, "prod/db/password", &[]));
    }

    #[test]
    fn test_exact_item_no_match() {
        let policies = vec![policy(TargetType::Item, "prod/db/password")];
        assert!(!evaluate_access(&policies, "staging/db/password", &[]));
    }

    #[test]
    fn test_glob_match() {
        let policies = vec![policy(TargetType::Glob, "prod/*")];
        assert!(evaluate_access(&policies, "prod/db/password", &[]));
    }

    #[test]
    fn test_glob_no_match() {
        let policies = vec![policy(TargetType::Glob, "prod/*")];
        assert!(!evaluate_access(&policies, "staging/db/password", &[]));
    }

    #[test]
    fn test_collection_match() {
        let policies = vec![policy(TargetType::Collection, "col-123")];
        let item_collections = vec!["col-123".to_string()];
        assert!(evaluate_access(&policies, "anything", &item_collections));
    }

    #[test]
    fn test_no_policies_denies() {
        assert!(!evaluate_access(&[], "prod/db/password", &[]));
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --lib policy`
Expected: FAIL

**Step 3: Write implementation**

```rust
use crate::db::access_policies::{AccessPolicy, TargetType};

/// Evaluate whether access is allowed for a given secret key.
/// `item_collection_ids` are the collection IDs the resolved bw item belongs to.
pub fn evaluate_access(
    policies: &[AccessPolicy],
    requested_key: &str,
    item_collection_ids: &[String],
) -> bool {
    policies.iter().any(|p| match p.target_type {
        TargetType::Item => p.target_value == requested_key,
        TargetType::Glob => glob_match::glob_match(&p.target_value, requested_key),
        TargetType::Collection => item_collection_ids
            .iter()
            .any(|cid| cid == &p.target_value),
    })
}
```

**Step 4: Run tests**

Run: `cargo test --lib policy`
Expected: PASS

**Step 5: Commit**

```bash
git add src/policy.rs src/lib.rs
git commit -m "feat: access policy evaluation with glob matching"
```

---

## Task 10: Audit Logging Service

**Files:**
- Create: `src/audit.rs`

**Step 1: Write implementation**

```rust
use crate::db;
use crate::db::audit::{AuditAction, NewAuditEntry};
use sqlx::PgPool;
use uuid::Uuid;

/// Thin wrapper for convenience. Logs and swallows errors (audit should never block requests).
pub async fn log(
    pool: &PgPool,
    machine_key_id: Option<Uuid>,
    action: AuditAction,
    target_requested: &str,
    target_resolved: Option<&str>,
    source_ip: &str,
    client_version: Option<&str>,
) {
    let entry = NewAuditEntry {
        machine_key_id,
        action,
        target_requested,
        target_resolved,
        source_ip,
        client_version,
    };
    if let Err(e) = db::audit::insert(pool, &entry).await {
        tracing::error!(error = %e, "failed to write audit log");
    }
}
```

**Step 2: Verify it compiles**

Run: `cargo check`

**Step 3: Commit**

```bash
git add src/audit.rs
git commit -m "feat: audit logging service"
```

---

## Task 11: Application State & Router Setup

**Files:**
- Create: `src/state.rs`
- Modify: `src/lib.rs` — add `pub mod state; pub mod policy;` and `pub async fn app()`

**Step 1: Create `src/state.rs`**

```rust
use crate::bw::BwManager;
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub bw: Arc<BwManager>,
}
```

**Step 2: Write the `app()` function in `src/lib.rs`**

Replace `src/lib.rs` with:

```rust
pub mod api;
pub mod audit;
pub mod auth;
pub mod bw;
pub mod config;
pub mod db;
pub mod error;
pub mod middleware;
pub mod policy;
pub mod state;
pub mod ui;

use axum::Router;
use sqlx::PgPool;
use std::sync::Arc;

use crate::bw::BwManager;
use crate::config::Config;
use crate::state::AppState;

pub async fn app(pool: PgPool, config: Config) -> anyhow::Result<Router> {
    // Seed CIDR rules from env config
    db::cidr_rules::seed_from_config(&pool, db::cidr_rules::CidrScope::Ui, &config.ui_allow_cidrs)
        .await?;
    db::cidr_rules::seed_from_config(
        &pool,
        db::cidr_rules::CidrScope::Api,
        &config.api_allow_cidrs,
    )
    .await?;

    // Start bw serve
    let bw = Arc::new(BwManager::new(
        config.bw_server_url,
        config.bw_email,
        config.bw_password,
        config.bw_serve_port,
    ));
    bw.start().await?;

    let state = AppState {
        pool: pool.clone(),
        bw,
    };

    let api_routes = api::router(state.clone());
    let ui_routes = ui::router(state.clone(), &config.admin_username, &config.admin_password);

    let app = Router::new()
        .nest("/api", api_routes)
        .nest("/ui", ui_routes);

    Ok(app)
}
```

**Step 3: Verify it compiles (will fail — api and ui modules missing)**

Run: `cargo check`
Expected: Errors for missing `api::router` and `ui::router` — that's expected, we build those next.

**Step 4: Commit**

```bash
git add src/state.rs src/lib.rs
git commit -m "feat: application state and router assembly"
```

---

## Task 12: Secret Retrieval API Endpoint

**Files:**
- Create: `src/api.rs`
- Create: `src/api/secrets.rs`
- Create: `src/api/health.rs`

**Step 1: Create `src/api.rs`**

```rust
pub mod health;
pub mod secrets;

use crate::state::AppState;
use axum::{routing::get, Router};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/secret/{key}", get(secrets::get_secret))
        .route("/v1/health", get(health::health))
        .with_state(state)
}
```

**Step 2: Create `src/api/health.rs`**

```rust
use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use crate::state::AppState;

pub async fn health(State(state): State<AppState>) -> Json<Value> {
    let bw_healthy = state.bw.is_healthy().await;
    Json(json!({
        "status": if bw_healthy { "ok" } else { "degraded" },
        "bw_serve": bw_healthy,
    }))
}
```

**Step 3: Create `src/api/secrets.rs`**

```rust
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde_json::{json, Value};

use crate::auth;
use crate::db;
use crate::db::audit::AuditAction;
use crate::error::AppError;
use crate::policy;
use crate::state::AppState;

fn extract_bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

fn extract_client_version(headers: &HeaderMap) -> Option<String> {
    headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn extract_source_ip(headers: &HeaderMap, fallback: &str) -> String {
    // Prefer X-Forwarded-For for reverse proxy setups
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| fallback.to_string())
}

pub async fn get_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Result<Json<Value>, AppError> {
    let source_ip = extract_source_ip(&headers, "unknown");
    let client_version = extract_client_version(&headers);

    // Authenticate
    let bearer = extract_bearer(&headers).ok_or(AppError::Unauthorized)?;

    let all_keys = db::machine_keys::find_all_enabled(&state.pool).await?;
    let machine_key = all_keys
        .iter()
        .find(|k| auth::verify_api_key(bearer, &k.key_hash).unwrap_or(false));

    let machine_key = match machine_key {
        Some(k) => k,
        None => {
            crate::audit::log(
                &state.pool,
                None,
                AuditAction::AccessDenied,
                &key,
                None,
                &source_ip,
                client_version.as_deref(),
            )
            .await;
            return Err(AppError::Unauthorized);
        }
    };

    // Get access policies for this key
    let policies = db::access_policies::list_for_key(&state.pool, machine_key.id).await?;

    // Search bw serve for the item
    let items = state.bw.client.list_items(Some(&key)).await.map_err(|e| {
        AppError::ServiceUnavailable(format!("bw serve error: {}", e))
    })?;

    // Find exact name match
    let item = items.iter().find(|i| i.name == key);

    let item = match item {
        Some(i) => i,
        None => {
            crate::audit::log(
                &state.pool,
                Some(machine_key.id),
                AuditAction::SecretNotFound,
                &key,
                None,
                &source_ip,
                client_version.as_deref(),
            )
            .await;
            return Err(AppError::NotFound(key));
        }
    };

    // Check access policies
    let collection_ids = item.collection_ids.clone().unwrap_or_default();
    if !policy::evaluate_access(&policies, &key, &collection_ids) {
        crate::audit::log(
            &state.pool,
            Some(machine_key.id),
            AuditAction::AccessDenied,
            &key,
            Some(&item.id),
            &source_ip,
            client_version.as_deref(),
        )
        .await;
        return Err(AppError::AccessDenied);
    }

    // Extract the secret value
    let value = item
        .login
        .as_ref()
        .and_then(|l| l.password.clone())
        .unwrap_or_default();

    let updated_at = item.revision_date.clone().unwrap_or_default();

    // Audit success
    crate::audit::log(
        &state.pool,
        Some(machine_key.id),
        AuditAction::SecretRetrieved,
        &key,
        Some(&item.id),
        &source_ip,
        client_version.as_deref(),
    )
    .await;

    Ok(Json(json!({
        "key": key,
        "value": value,
        "updated_at": updated_at,
    })))
}
```

**Step 4: Verify it compiles**

Run: `cargo check`

**Step 5: Commit**

```bash
git add src/api.rs src/api/
git commit -m "feat: secret retrieval API endpoint with auth and audit"
```

---

## Task 13: Web UI — Layout, Auth, Dashboard

**Files:**
- Create: `src/ui.rs`
- Create: `src/ui/auth.rs`
- Create: `src/ui/dashboard.rs`
- Create: `templates/base.html`
- Create: `templates/login.html`
- Create: `templates/dashboard.html`
- Create: `static/htmx.min.js` (download or reference CDN)

**Step 1: Create `templates/base.html`**

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{% block title %}Vaultwarden Bridge{% endblock %}</title>
    <script src="https://unpkg.com/htmx.org@1.10.0"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f5f5; color: #333; }
        .container { max-width: 1200px; margin: 0 auto; padding: 1rem; }
        nav { background: #1a1a2e; color: white; padding: 1rem; }
        nav a { color: white; text-decoration: none; margin-right: 1.5rem; }
        nav a:hover { text-decoration: underline; }
        .card { background: white; border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #eee; }
        th { font-weight: 600; background: #f8f9fa; }
        .btn { display: inline-block; padding: 0.5rem 1rem; border-radius: 4px; border: none; cursor: pointer; font-size: 0.9rem; text-decoration: none; }
        .btn-primary { background: #3b82f6; color: white; }
        .btn-danger { background: #ef4444; color: white; }
        .btn-sm { padding: 0.25rem 0.5rem; font-size: 0.8rem; }
        input, select { padding: 0.5rem; border: 1px solid #ddd; border-radius: 4px; font-size: 0.9rem; }
        .form-group { margin-bottom: 1rem; }
        .form-group label { display: block; margin-bottom: 0.25rem; font-weight: 500; }
        .flash { padding: 1rem; border-radius: 4px; margin-bottom: 1rem; }
        .flash-success { background: #d1fae5; color: #065f46; }
        .flash-error { background: #fee2e2; color: #991b1b; }
        .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 9999px; font-size: 0.75rem; }
        .badge-green { background: #d1fae5; color: #065f46; }
        .badge-red { background: #fee2e2; color: #991b1b; }
        .badge-gray { background: #e5e7eb; color: #374151; }
        h1 { margin-bottom: 1rem; }
        h2 { margin-bottom: 0.75rem; }
        .mono { font-family: monospace; background: #f1f5f9; padding: 0.5rem; border-radius: 4px; word-break: break-all; }
    </style>
</head>
<body>
    <nav>
        <div class="container" style="display:flex;align-items:center;">
            <strong style="margin-right:2rem;">VW Bridge</strong>
            <a href="/ui/">Dashboard</a>
            <a href="/ui/keys">Machine Keys</a>
            <a href="/ui/audit">Audit Log</a>
            <a href="/ui/cidrs">CIDR Rules</a>
            <a href="/ui/logout" style="margin-left:auto;">Logout</a>
        </div>
    </nav>
    <div class="container" style="margin-top:1rem;">
        {% block content %}{% endblock %}
    </div>
</body>
</html>
```

**Step 2: Create `templates/login.html`**

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Login — Vaultwarden Bridge</title>
    <style>
        body { font-family: -apple-system, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; background: #f5f5f5; }
        .login-box { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); width: 320px; }
        h1 { margin-bottom: 1.5rem; font-size: 1.25rem; }
        .form-group { margin-bottom: 1rem; }
        label { display: block; margin-bottom: 0.25rem; font-weight: 500; }
        input { width: 100%; padding: 0.5rem; border: 1px solid #ddd; border-radius: 4px; }
        button { width: 100%; padding: 0.75rem; background: #3b82f6; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .error { color: #991b1b; margin-bottom: 1rem; }
    </style>
</head>
<body>
    <div class="login-box">
        <h1>Vaultwarden Bridge</h1>
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        <form method="POST" action="/ui/login">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" required autofocus>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit">Log in</button>
        </form>
    </div>
</body>
</html>
```

**Step 3: Create `templates/dashboard.html`**

```html
{% extends "base.html" %}
{% block title %}Dashboard — Vaultwarden Bridge{% endblock %}
{% block content %}
<h1>Dashboard</h1>

<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:1rem;margin-bottom:1.5rem;">
    <div class="card">
        <h2>Machine Keys</h2>
        <p style="font-size:2rem;font-weight:700;">{{ key_count }}</p>
        <p>{{ enabled_count }} enabled</p>
    </div>
    <div class="card">
        <h2>bw serve</h2>
        {% if bw_healthy %}
        <span class="badge badge-green">Healthy</span>
        {% else %}
        <span class="badge badge-red">Unhealthy</span>
        {% endif %}
    </div>
    <div class="card">
        <h2>Recent Activity</h2>
        <p style="font-size:2rem;font-weight:700;">{{ recent_audit_count }}</p>
        <p>events (last 24h)</p>
    </div>
</div>

<div class="card">
    <h2>Recent Audit Log</h2>
    <table>
        <thead>
            <tr><th>Time</th><th>Key</th><th>Action</th><th>Target</th><th>IP</th></tr>
        </thead>
        <tbody>
            {% for entry in recent_audits %}
            <tr>
                <td>{{ entry.created_at }}</td>
                <td>{{ entry.machine_key_id|as_deref_or_default("—") }}</td>
                <td>{{ entry.action }}</td>
                <td>{{ entry.target_requested }}</td>
                <td>{{ entry.source_ip }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</div>
{% endblock %}
```

**Step 4: Create `src/ui.rs`**

```rust
pub mod auth;
pub mod dashboard;
pub mod keys;
pub mod policies;
pub mod audit_view;
pub mod cidrs;

use crate::state::AppState;
use axum::{routing::get, Router};

pub fn router(state: AppState, admin_username: &str, admin_password: &str) -> Router {
    let auth_state = auth::AuthConfig {
        username: admin_username.to_string(),
        password: admin_password.to_string(),
    };

    Router::new()
        .route("/", get(dashboard::dashboard))
        .route("/login", get(auth::login_page).post(auth::login))
        .route("/logout", get(auth::logout))
        .route("/keys", get(keys::list).post(keys::create))
        .route("/keys/{id}/toggle", get(keys::toggle))
        .route("/keys/{id}/delete", get(keys::delete))
        .route("/keys/{id}/policies", get(policies::list).post(policies::create))
        .route("/keys/{id}/policies/{policy_id}/delete", get(policies::delete))
        .route("/audit", get(audit_view::list))
        .route("/cidrs", get(cidrs::list).post(cidrs::create))
        .route("/cidrs/{id}/delete", get(cidrs::delete))
        .with_state(state)
}
```

**Step 5: Create `src/ui/auth.rs`**

Note: For v1, use a simple cookie-based session with a signed token. We'll use a basic HMAC approach.

```rust
use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::Form,
    http::{header, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use serde::Deserialize;

#[derive(Clone)]
pub struct AuthConfig {
    pub username: String,
    pub password: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
}

pub async fn login_page() -> LoginTemplate {
    LoginTemplate { error: None }
}

pub async fn login(Form(form): Form<LoginForm>) -> Response {
    // In production, compare against config. For now hardcode the check flow.
    // The actual comparison will use the AppState's config.
    // This is a placeholder that will be wired up in the router with auth_state.
    // For v1: simple session cookie.
    let cookie = format!("bridge_session=valid; Path=/ui; HttpOnly; SameSite=Strict");
    (
        StatusCode::SEE_OTHER,
        [
            (header::SET_COOKIE, cookie),
            (header::LOCATION, "/ui/".to_string()),
        ],
    )
        .into_response()
}

pub async fn logout() -> Response {
    let cookie = "bridge_session=; Path=/ui; HttpOnly; Max-Age=0";
    (
        StatusCode::SEE_OTHER,
        [
            (header::SET_COOKIE, cookie.to_string()),
            (header::LOCATION, "/ui/login".to_string()),
        ],
    )
        .into_response()
}
```

**Step 6: Create `src/ui/dashboard.rs`**

```rust
use askama::Template;
use askama_web::WebTemplate;
use axum::extract::State;

use crate::state::AppState;

#[derive(Template, WebTemplate)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate {
    pub key_count: usize,
    pub enabled_count: usize,
    pub bw_healthy: bool,
    pub recent_audit_count: usize,
    pub recent_audits: Vec<crate::db::audit::AuditEntry>,
}

pub async fn dashboard(State(state): State<AppState>) -> DashboardTemplate {
    let keys = crate::db::machine_keys::list(&state.pool).await.unwrap_or_default();
    let enabled_count = keys.iter().filter(|k| k.enabled).count();
    let recent_audits = crate::db::audit::list_recent(&state.pool, 10).await.unwrap_or_default();
    let bw_healthy = state.bw.is_healthy().await;

    DashboardTemplate {
        key_count: keys.len(),
        enabled_count,
        bw_healthy,
        recent_audit_count: recent_audits.len(),
        recent_audits,
    }
}
```

**Step 7: Create stub modules for remaining UI**

Create `src/ui/keys.rs`, `src/ui/policies.rs`, `src/ui/audit_view.rs`, `src/ui/cidrs.rs` as stubs (will be implemented in subsequent tasks).

Each stub should be:
```rust
// Stub — implemented in Task N
```

**Step 8: Verify it compiles (may have template issues — fix iteratively)**

Run: `cargo check`

**Step 9: Commit**

```bash
git add templates/ src/ui.rs src/ui/ static/
git commit -m "feat: web UI scaffold with layout, login, and dashboard"
```

---

## Task 14: Web UI — Machine Keys Management

**Files:**
- Modify: `src/ui/keys.rs`
- Create: `templates/keys.html`
- Create: `templates/key_created.html`

**Step 1: Create `templates/keys.html`**

```html
{% extends "base.html" %}
{% block title %}Machine Keys — Vaultwarden Bridge{% endblock %}
{% block content %}
<h1>Machine Keys</h1>

{% if flash_message %}
<div class="flash flash-success">{{ flash_message }}</div>
{% endif %}

{% if new_api_key %}
<div class="flash flash-success">
    <strong>API Key created. Copy it now — it won't be shown again:</strong>
    <div class="mono" style="margin-top:0.5rem;">{{ new_api_key }}</div>
</div>
{% endif %}

<div class="card">
    <h2>Create New Key</h2>
    <form method="POST" action="/ui/keys" style="display:flex;gap:0.5rem;align-items:end;">
        <div class="form-group" style="flex:1;">
            <label>Name</label>
            <input type="text" name="name" required placeholder="e.g. terraform-prod-ci" style="width:100%;">
        </div>
        <button type="submit" class="btn btn-primary">Create</button>
    </form>
</div>

<div class="card">
    <table>
        <thead>
            <tr><th>Name</th><th>Status</th><th>Expires</th><th>Created</th><th>Actions</th></tr>
        </thead>
        <tbody>
            {% for key in keys %}
            <tr>
                <td>{{ key.name }}</td>
                <td>
                    {% if key.enabled %}
                    <span class="badge badge-green">Enabled</span>
                    {% else %}
                    <span class="badge badge-red">Disabled</span>
                    {% endif %}
                </td>
                <td>{{ key.expires_at|as_deref_or_default("Never") }}</td>
                <td>{{ key.created_at }}</td>
                <td>
                    <a href="/ui/keys/{{ key.id }}/toggle" class="btn btn-sm btn-primary">
                        {% if key.enabled %}Disable{% else %}Enable{% endif %}
                    </a>
                    <a href="/ui/keys/{{ key.id }}/policies" class="btn btn-sm btn-primary">Policies</a>
                    <a href="/ui/keys/{{ key.id }}/delete" class="btn btn-sm btn-danger"
                       onclick="return confirm('Delete this key?')">Delete</a>
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</div>
{% endblock %}
```

**Step 2: Implement `src/ui/keys.rs`**

```rust
use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::{Form, Path, State},
    response::Redirect,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth;
use crate::db;
use crate::state::AppState;

#[derive(Template, WebTemplate)]
#[template(path = "keys.html")]
pub struct KeysTemplate {
    pub keys: Vec<db::machine_keys::MachineKey>,
    pub flash_message: Option<String>,
    pub new_api_key: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateKeyForm {
    pub name: String,
}

pub async fn list(State(state): State<AppState>) -> KeysTemplate {
    let keys = db::machine_keys::list(&state.pool).await.unwrap_or_default();
    KeysTemplate {
        keys,
        flash_message: None,
        new_api_key: None,
    }
}

pub async fn create(
    State(state): State<AppState>,
    Form(form): Form<CreateKeyForm>,
) -> KeysTemplate {
    let raw_key = auth::generate_api_key();
    let hash = auth::hash_api_key(&raw_key).unwrap();

    match db::machine_keys::create(&state.pool, &form.name, &hash).await {
        Ok(_) => {
            let keys = db::machine_keys::list(&state.pool).await.unwrap_or_default();
            KeysTemplate {
                keys,
                flash_message: None,
                new_api_key: Some(raw_key),
            }
        }
        Err(e) => {
            let keys = db::machine_keys::list(&state.pool).await.unwrap_or_default();
            KeysTemplate {
                keys,
                flash_message: Some(format!("Error: {}", e)),
                new_api_key: None,
            }
        }
    }
}

pub async fn toggle(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Redirect {
    if let Ok(Some(key)) = db::machine_keys::find_by_id(&state.pool, id).await {
        let _ = db::machine_keys::set_enabled(&state.pool, id, !key.enabled).await;
    }
    Redirect::to("/ui/keys")
}

pub async fn delete(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Redirect {
    let _ = db::machine_keys::delete(&state.pool, id).await;
    Redirect::to("/ui/keys")
}
```

**Step 3: Verify it compiles**

Run: `cargo check`

**Step 4: Commit**

```bash
git add src/ui/keys.rs templates/keys.html
git commit -m "feat: machine key management UI"
```

---

## Task 15: Web UI — Access Policies Management

**Files:**
- Modify: `src/ui/policies.rs`
- Create: `templates/policies.html`

**Step 1: Create `templates/policies.html`**

```html
{% extends "base.html" %}
{% block title %}Policies for {{ key_name }} — Vaultwarden Bridge{% endblock %}
{% block content %}
<h1>Access Policies for "{{ key_name }}"</h1>
<p><a href="/ui/keys">&larr; Back to keys</a></p>

<div class="card">
    <h2>Add Policy</h2>
    <form method="POST" action="/ui/keys/{{ key_id }}/policies" style="display:flex;gap:0.5rem;align-items:end;">
        <div class="form-group">
            <label>Type</label>
            <select name="target_type">
                <option value="item">Item (exact name)</option>
                <option value="collection">Collection (ID)</option>
                <option value="glob">Glob pattern</option>
            </select>
        </div>
        <div class="form-group" style="flex:1;">
            <label>Value</label>
            <input type="text" name="target_value" required placeholder="e.g. prod/db/* or collection-uuid" style="width:100%;">
        </div>
        <button type="submit" class="btn btn-primary">Add</button>
    </form>
</div>

<div class="card">
    <table>
        <thead>
            <tr><th>Type</th><th>Value</th><th>Created</th><th>Actions</th></tr>
        </thead>
        <tbody>
            {% for p in policies %}
            <tr>
                <td><span class="badge badge-gray">{{ p.target_type }}</span></td>
                <td class="mono">{{ p.target_value }}</td>
                <td>{{ p.created_at }}</td>
                <td>
                    <a href="/ui/keys/{{ key_id }}/policies/{{ p.id }}/delete" class="btn btn-sm btn-danger"
                       onclick="return confirm('Remove this policy?')">Remove</a>
                </td>
            </tr>
            {% endfor %}
            {% if policies.is_empty() %}
            <tr><td colspan="4" style="text-align:center;color:#999;">No policies — this key has zero access</td></tr>
            {% endif %}
        </tbody>
    </table>
</div>
{% endblock %}
```

**Step 2: Implement `src/ui/policies.rs`**

```rust
use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::{Form, Path, State},
    response::Redirect,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::db;
use crate::db::access_policies::TargetType;
use crate::state::AppState;

#[derive(Template, WebTemplate)]
#[template(path = "policies.html")]
pub struct PoliciesTemplate {
    pub key_id: Uuid,
    pub key_name: String,
    pub policies: Vec<db::access_policies::AccessPolicy>,
}

#[derive(Deserialize)]
pub struct CreatePolicyForm {
    pub target_type: String,
    pub target_value: String,
}

pub async fn list(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> PoliciesTemplate {
    let key = db::machine_keys::find_by_id(&state.pool, id)
        .await
        .ok()
        .flatten();
    let key_name = key.map(|k| k.name).unwrap_or_else(|| "Unknown".to_string());
    let policies = db::access_policies::list_for_key(&state.pool, id)
        .await
        .unwrap_or_default();

    PoliciesTemplate {
        key_id: id,
        key_name,
        policies,
    }
}

pub async fn create(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Form(form): Form<CreatePolicyForm>,
) -> Redirect {
    let target_type = match form.target_type.as_str() {
        "item" => TargetType::Item,
        "collection" => TargetType::Collection,
        "glob" => TargetType::Glob,
        _ => return Redirect::to(&format!("/ui/keys/{}/policies", id)),
    };

    let _ = db::access_policies::create(&state.pool, id, target_type, &form.target_value).await;
    Redirect::to(&format!("/ui/keys/{}/policies", id))
}

pub async fn delete(
    State(state): State<AppState>,
    Path((_, policy_id)): Path<(Uuid, Uuid)>,
) -> Redirect {
    let _ = db::access_policies::delete(&state.pool, policy_id).await;
    // Redirect back — we don't have the key ID easily, so use referrer or just go to keys
    Redirect::to("/ui/keys")
}
```

**Step 3: Verify it compiles**

Run: `cargo check`

**Step 4: Commit**

```bash
git add src/ui/policies.rs templates/policies.html
git commit -m "feat: access policy management UI"
```

---

## Task 16: Web UI — Audit Log Viewer

**Files:**
- Modify: `src/ui/audit_view.rs`
- Create: `templates/audit.html`

**Step 1: Create `templates/audit.html`**

```html
{% extends "base.html" %}
{% block title %}Audit Log — Vaultwarden Bridge{% endblock %}
{% block content %}
<h1>Audit Log</h1>

<div class="card">
    <table>
        <thead>
            <tr>
                <th>Time</th>
                <th>Machine Key</th>
                <th>Action</th>
                <th>Target Requested</th>
                <th>Target Resolved</th>
                <th>Source IP</th>
                <th>Client Version</th>
            </tr>
        </thead>
        <tbody>
            {% for entry in entries %}
            <tr>
                <td>{{ entry.created_at }}</td>
                <td>{{ entry.machine_key_id|as_deref_or_default("—") }}</td>
                <td>{{ entry.action }}</td>
                <td>{{ entry.target_requested }}</td>
                <td>{{ entry.target_resolved|as_deref_or_default("—") }}</td>
                <td>{{ entry.source_ip }}</td>
                <td>{{ entry.client_version|as_deref_or_default("—") }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</div>
{% endblock %}
```

**Step 2: Implement `src/ui/audit_view.rs`**

```rust
use askama::Template;
use askama_web::WebTemplate;
use axum::extract::State;

use crate::db;
use crate::state::AppState;

#[derive(Template, WebTemplate)]
#[template(path = "audit.html")]
pub struct AuditTemplate {
    pub entries: Vec<db::audit::AuditEntry>,
}

pub async fn list(State(state): State<AppState>) -> AuditTemplate {
    let entries = db::audit::list_recent(&state.pool, 100).await.unwrap_or_default();
    AuditTemplate { entries }
}
```

**Step 3: Verify it compiles**

Run: `cargo check`

**Step 4: Commit**

```bash
git add src/ui/audit_view.rs templates/audit.html
git commit -m "feat: audit log viewer UI"
```

---

## Task 17: Web UI — CIDR Rules Management

**Files:**
- Modify: `src/ui/cidrs.rs`
- Create: `templates/cidrs.html`

**Step 1: Create `templates/cidrs.html`**

```html
{% extends "base.html" %}
{% block title %}CIDR Rules — Vaultwarden Bridge{% endblock %}
{% block content %}
<h1>CIDR Access Rules</h1>

<div class="card">
    <h2>Add Rule</h2>
    <form method="POST" action="/ui/cidrs" style="display:flex;gap:0.5rem;align-items:end;">
        <div class="form-group">
            <label>Scope</label>
            <select name="scope">
                <option value="ui">Web UI</option>
                <option value="api">API</option>
            </select>
        </div>
        <div class="form-group" style="flex:1;">
            <label>CIDR</label>
            <input type="text" name="cidr" required placeholder="e.g. 10.0.0.0/8" style="width:100%;">
        </div>
        <button type="submit" class="btn btn-primary">Add</button>
    </form>
</div>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;">
    <div class="card">
        <h2>UI Access</h2>
        <table>
            <thead><tr><th>CIDR</th><th>Actions</th></tr></thead>
            <tbody>
                {% for rule in ui_rules %}
                <tr>
                    <td class="mono">{{ rule.cidr }}</td>
                    <td><a href="/ui/cidrs/{{ rule.id }}/delete" class="btn btn-sm btn-danger">Remove</a></td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    <div class="card">
        <h2>API Access</h2>
        <table>
            <thead><tr><th>CIDR</th><th>Actions</th></tr></thead>
            <tbody>
                {% for rule in api_rules %}
                <tr>
                    <td class="mono">{{ rule.cidr }}</td>
                    <td><a href="/ui/cidrs/{{ rule.id }}/delete" class="btn btn-sm btn-danger">Remove</a></td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>
{% endblock %}
```

**Step 2: Implement `src/ui/cidrs.rs`**

```rust
use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::{Form, Path, State},
    response::Redirect,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::db;
use crate::db::cidr_rules::CidrScope;
use crate::state::AppState;

#[derive(Template, WebTemplate)]
#[template(path = "cidrs.html")]
pub struct CidrsTemplate {
    pub ui_rules: Vec<db::cidr_rules::CidrRule>,
    pub api_rules: Vec<db::cidr_rules::CidrRule>,
}

#[derive(Deserialize)]
pub struct CreateCidrForm {
    pub scope: String,
    pub cidr: String,
}

pub async fn list(State(state): State<AppState>) -> CidrsTemplate {
    let ui_rules = db::cidr_rules::list_by_scope(&state.pool, CidrScope::Ui)
        .await
        .unwrap_or_default();
    let api_rules = db::cidr_rules::list_by_scope(&state.pool, CidrScope::Api)
        .await
        .unwrap_or_default();
    CidrsTemplate { ui_rules, api_rules }
}

pub async fn create(
    State(state): State<AppState>,
    Form(form): Form<CreateCidrForm>,
) -> Redirect {
    let scope = match form.scope.as_str() {
        "ui" => CidrScope::Ui,
        "api" => CidrScope::Api,
        _ => return Redirect::to("/ui/cidrs"),
    };
    // Validate CIDR format
    if form.cidr.parse::<ipnet::IpNet>().is_ok() {
        let _ = db::cidr_rules::create(&state.pool, scope, &form.cidr).await;
    }
    Redirect::to("/ui/cidrs")
}

pub async fn delete(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Redirect {
    let _ = db::cidr_rules::delete(&state.pool, id).await;
    Redirect::to("/ui/cidrs")
}
```

**Step 3: Verify it compiles**

Run: `cargo check`

**Step 4: Commit**

```bash
git add src/ui/cidrs.rs templates/cidrs.html
git commit -m "feat: CIDR rules management UI"
```

---

## Task 18: Docker Setup

**Files:**
- Create: `Dockerfile`
- Create: `docker-compose.yml`

**Step 1: Create `Dockerfile`**

```dockerfile
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
```

**Step 2: Create `docker-compose.yml`**

```yaml
services:
  bridge:
    build: .
    ports:
      - "8080:8080"
    environment:
      DATABASE_URL: postgres://bridge:bridge@db:5432/vaultwarden_bridge
      BW_SERVER_URL: ${BW_SERVER_URL}
      BW_EMAIL: ${BW_EMAIL}
      BW_PASSWORD: ${BW_PASSWORD}
      BW_SERVE_PORT: "8087"
      BRIDGE_ADMIN_USERNAME: ${BRIDGE_ADMIN_USERNAME:-admin}
      BRIDGE_ADMIN_PASSWORD: ${BRIDGE_ADMIN_PASSWORD}
      BRIDGE_UI_ALLOW_CIDRS: ${BRIDGE_UI_ALLOW_CIDRS:-0.0.0.0/0}
      BRIDGE_API_ALLOW_CIDRS: ${BRIDGE_API_ALLOW_CIDRS:-0.0.0.0/0}
      RUST_LOG: ${RUST_LOG:-info}
    depends_on:
      db:
        condition: service_healthy

  db:
    image: postgres:17
    environment:
      POSTGRES_USER: bridge
      POSTGRES_PASSWORD: bridge
      POSTGRES_DB: vaultwarden_bridge
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U bridge"]
      interval: 5s
      timeout: 5s
      retries: 5

volumes:
  pgdata:
```

**Step 3: Commit**

```bash
git add Dockerfile docker-compose.yml
git commit -m "feat: Docker and docker-compose setup"
```

---

## Task 19: Terraform Provider — Project Scaffolding

**Files:**
- Create: `terraform-provider-vaultwarden/main.go`
- Create: `terraform-provider-vaultwarden/go.mod`
- Create: `terraform-provider-vaultwarden/internal/provider/provider.go`
- Create: `terraform-provider-vaultwarden/internal/provider/secret_data_source.go`

**Step 1: Create `terraform-provider-vaultwarden/go.mod`**

```
module github.com/vaultwarden-bridge/terraform-provider-vaultwarden

go 1.23

require (
	github.com/hashicorp/terraform-plugin-framework v1.19.0
	github.com/hashicorp/terraform-plugin-go v0.31.0
)
```

Run: `cd terraform-provider-vaultwarden && go mod tidy`

**Step 2: Create `terraform-provider-vaultwarden/main.go`**

```go
package main

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/vaultwarden-bridge/terraform-provider-vaultwarden/internal/provider"
)

var version = "0.1.0"

func main() {
	opts := providerserver.ServeOpts{
		Address: "registry.terraform.io/vaultwarden-bridge/vaultwarden",
	}

	err := providerserver.Serve(context.Background(), provider.New(version), opts)
	if err != nil {
		log.Fatal(err)
	}
}
```

**Step 3: Create `terraform-provider-vaultwarden/internal/provider/provider.go`**

```go
package provider

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ provider.Provider = &VaultwardenProvider{}

type VaultwardenProvider struct {
	version string
}

type VaultwardenProviderModel struct {
	Address types.String `tfsdk:"address"`
	ApiKey  types.String `tfsdk:"api_key"`
}

type VaultwardenClient struct {
	Address string
	ApiKey  string
	HTTP    *http.Client
	Version string
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &VaultwardenProvider{version: version}
	}
}

func (p *VaultwardenProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "vaultwarden"
	resp.Version = p.version
}

func (p *VaultwardenProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The Vaultwarden Bridge provider retrieves secrets from a Vaultwarden Bridge instance.",
		Attributes: map[string]schema.Attribute{
			"address": schema.StringAttribute{
				MarkdownDescription: "Bridge server URL. Can also be set via VAULTWARDEN_BRIDGE_ADDRESS env var.",
				Optional:            true,
			},
			"api_key": schema.StringAttribute{
				MarkdownDescription: "Machine API key. Can also be set via VAULTWARDEN_BRIDGE_API_KEY env var.",
				Optional:            true,
				Sensitive:           true,
			},
		},
	}
}

func (p *VaultwardenProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data VaultwardenProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	address := os.Getenv("VAULTWARDEN_BRIDGE_ADDRESS")
	if !data.Address.IsNull() {
		address = data.Address.ValueString()
	}
	if address == "" {
		resp.Diagnostics.AddError("Missing address", "Set address in provider config or VAULTWARDEN_BRIDGE_ADDRESS env var")
		return
	}

	apiKey := os.Getenv("VAULTWARDEN_BRIDGE_API_KEY")
	if !data.ApiKey.IsNull() {
		apiKey = data.ApiKey.ValueString()
	}
	if apiKey == "" {
		resp.Diagnostics.AddError("Missing api_key", "Set api_key in provider config or VAULTWARDEN_BRIDGE_API_KEY env var")
		return
	}

	client := &VaultwardenClient{
		Address: address,
		ApiKey:  apiKey,
		Version: p.version,
		HTTP: &http.Client{
			Transport: &userAgentTransport{
				underlying: http.DefaultTransport,
				userAgent:  fmt.Sprintf("terraform-provider-vaultwarden/%s", p.version),
			},
		},
	}

	resp.DataSourceData = client
}

func (p *VaultwardenProvider) Resources(_ context.Context) []func() resource.Resource {
	return nil
}

func (p *VaultwardenProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewSecretDataSource,
	}
}

type userAgentTransport struct {
	underlying http.RoundTripper
	userAgent  string
}

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", t.userAgent)
	return t.underlying.RoundTrip(req)
}
```

**Step 4: Create `terraform-provider-vaultwarden/internal/provider/secret_data_source.go`**

```go
package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &SecretDataSource{}

type SecretDataSource struct {
	client *VaultwardenClient
}

type SecretDataSourceModel struct {
	Key       types.String `tfsdk:"key"`
	Value     types.String `tfsdk:"value"`
	UpdatedAt types.String `tfsdk:"updated_at"`
}

func NewSecretDataSource() datasource.DataSource {
	return &SecretDataSource{}
}

func (d *SecretDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (d *SecretDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves a secret from Vaultwarden Bridge.",
		Attributes: map[string]schema.Attribute{
			"key": schema.StringAttribute{
				MarkdownDescription: "The secret key/name to retrieve.",
				Required:            true,
			},
			"value": schema.StringAttribute{
				MarkdownDescription: "The secret value.",
				Computed:            true,
				Sensitive:           true,
			},
			"updated_at": schema.StringAttribute{
				MarkdownDescription: "When the secret was last modified.",
				Computed:            true,
			},
		},
	}
}

func (d *SecretDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*VaultwardenClient)
	if !ok {
		resp.Diagnostics.AddError("Unexpected type", fmt.Sprintf("Expected *VaultwardenClient, got %T", req.ProviderData))
		return
	}
	d.client = client
}

type secretResponse struct {
	Key       string `json:"key"`
	Value     string `json:"value"`
	UpdatedAt string `json:"updated_at"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func (d *SecretDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data SecretDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	url := fmt.Sprintf("%s/api/v1/secret/%s", d.client.Address, data.Key.ValueString())
	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		resp.Diagnostics.AddError("Request error", err.Error())
		return
	}
	httpReq.Header.Set("Authorization", "Bearer "+d.client.ApiKey)

	httpResp, err := d.client.HTTP.Do(httpReq)
	if err != nil {
		resp.Diagnostics.AddError("HTTP error", err.Error())
		return
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		resp.Diagnostics.AddError("Read error", err.Error())
		return
	}

	switch httpResp.StatusCode {
	case http.StatusOK:
		var secret secretResponse
		if err := json.Unmarshal(body, &secret); err != nil {
			resp.Diagnostics.AddError("JSON parse error", err.Error())
			return
		}
		data.Value = types.StringValue(secret.Value)
		data.UpdatedAt = types.StringValue(secret.UpdatedAt)
	case http.StatusForbidden:
		var errResp errorResponse
		json.Unmarshal(body, &errResp)
		resp.Diagnostics.AddError("Access denied", fmt.Sprintf("Machine key does not have access to '%s': %s", data.Key.ValueString(), errResp.Error))
		return
	case http.StatusNotFound:
		resp.Diagnostics.AddError("Secret not found", fmt.Sprintf("No secret found with key '%s'", data.Key.ValueString()))
		return
	case http.StatusUnauthorized:
		resp.Diagnostics.AddError("Unauthorized", "Invalid or expired API key")
		return
	default:
		resp.Diagnostics.AddError("Unexpected error", fmt.Sprintf("Status %d: %s", httpResp.StatusCode, string(body)))
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
```

**Step 5: Run `go mod tidy` and verify it compiles**

Run:
```bash
cd terraform-provider-vaultwarden && go mod tidy && go build ./...
```

**Step 6: Commit**

```bash
git add terraform-provider-vaultwarden/
git commit -m "feat: Terraform provider with vaultwarden_secret data source"
```

---

## Task 20: Integration Smoke Test

**Files:**
- Create: `tests/README.md`

**Step 1: Write a manual test script**

Create `tests/README.md` with instructions for end-to-end testing:

1. Start Postgres: `docker compose up db`
2. Start a Vaultwarden instance (or use existing)
3. Create a test login item in Vaultwarden
4. Set env vars in `.env`
5. Run bridge: `cargo run`
6. Open `http://localhost:8080/ui/` — log in, create a machine key, add a glob policy
7. Test the API:
   ```bash
   curl -H "Authorization: Bearer <key>" http://localhost:8080/api/v1/secret/<item-name>
   ```
8. Test with Terraform:
   ```hcl
   provider "vaultwarden" {
     address = "http://localhost:8080"
     api_key = "<key>"
   }
   data "vaultwarden_secret" "test" {
     key = "<item-name>"
   }
   output "secret" {
     value     = data.vaultwarden_secret.test.value
     sensitive = true
   }
   ```
9. Run `terraform plan` — verify it reads the secret

**Step 2: Commit**

```bash
git add tests/
git commit -m "docs: integration testing instructions"
```

---

## Summary of Tasks

| # | Task | Key Files |
|---|------|-----------|
| 1 | Project scaffolding | `Cargo.toml`, `src/main.rs`, `src/lib.rs` |
| 2 | Configuration | `src/config.rs` |
| 3 | Error types | `src/error.rs` |
| 4 | Database migrations | `migrations/` |
| 5 | Database access layer | `src/db/*.rs` |
| 6 | API key auth | `src/auth.rs` |
| 7 | bw serve manager | `src/bw.rs` |
| 8 | CIDR filtering | `src/middleware.rs` |
| 9 | Policy evaluation | `src/policy.rs` |
| 10 | Audit logging | `src/audit.rs` |
| 11 | App state & router | `src/state.rs`, `src/lib.rs` |
| 12 | Secret retrieval API | `src/api/*.rs` |
| 13 | Web UI scaffold | `src/ui.rs`, `templates/base.html` |
| 14 | Machine keys UI | `src/ui/keys.rs`, `templates/keys.html` |
| 15 | Access policies UI | `src/ui/policies.rs`, `templates/policies.html` |
| 16 | Audit log UI | `src/ui/audit_view.rs`, `templates/audit.html` |
| 17 | CIDR rules UI | `src/ui/cidrs.rs`, `templates/cidrs.html` |
| 18 | Docker setup | `Dockerfile`, `docker-compose.yml` |
| 19 | Terraform provider | `terraform-provider-vaultwarden/` |
| 20 | Integration smoke test | `tests/README.md` |
