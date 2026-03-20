//! Integration tests for the vaultwarden-bridge API.
//!
//! These tests require:
//! - A running PostgreSQL instance
//! - A running Vaultwarden instance seeded with test data
//! - The `bw` CLI available in PATH
//!
//! Set these env vars before running:
//!   DATABASE_URL, BW_SERVER_URL, BW_EMAIL, BW_PASSWORD,
//!   BRIDGE_ADMIN_USERNAME, BRIDGE_ADMIN_PASSWORD,
//!   BRIDGE_UI_ALLOW_CIDRS, BRIDGE_API_ALLOW_CIDRS

use reqwest::StatusCode;
use serde_json::Value;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::sync::OnceCell;

struct TestContext {
    base_url: String,
    pool: sqlx::PgPool,
}

static TEST_CONTEXT: OnceCell<TestContext> = OnceCell::const_new();

async fn get_context() -> &'static TestContext {
    TEST_CONTEXT
        .get_or_init(|| async {
            dotenvy::dotenv().ok();

            let config = vaultwarden_bridge::config::Config::from_env().expect("config from env");
            let pool = sqlx::PgPool::connect(&config.database_url)
                .await
                .expect("connect to postgres");
            sqlx::migrate!("./migrations")
                .run(&pool)
                .await
                .expect("run migrations");

            let app = vaultwarden_bridge::app(pool.clone(), config)
                .await
                .expect("build app");

            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            tokio::spawn(async move {
                axum::serve(
                    listener,
                    app.into_make_service_with_connect_info::<SocketAddr>(),
                )
                .await
                .unwrap();
            });

            // Give the server a moment to start
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;

            TestContext {
                base_url: format!("http://{}", addr),
                pool,
            }
        })
        .await
}

/// Create a machine key and return the raw API key. Uses a counter to ensure unique names.
static KEY_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

async fn create_test_key(pool: &sqlx::PgPool, prefix: &str) -> String {
    let n = KEY_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let name = format!("{}-{}", prefix, n);
    let raw_key = vaultwarden_bridge::auth::generate_api_key();
    let hash = vaultwarden_bridge::auth::hash_api_key(&raw_key).unwrap();
    vaultwarden_bridge::db::machine_keys::create(pool, &name, &hash)
        .await
        .expect("create machine key");
    raw_key
}

async fn add_glob_policy(pool: &sqlx::PgPool, key_prefix: &str, counter: u32, pattern: &str) {
    let name = format!("{}-{}", key_prefix, counter);
    let keys = vaultwarden_bridge::db::machine_keys::list(pool)
        .await
        .unwrap();
    let key = keys
        .iter()
        .find(|k| k.name == name)
        .unwrap_or_else(|| panic!("key '{}' not found", name));
    vaultwarden_bridge::db::access_policies::create(
        pool,
        key.id,
        vaultwarden_bridge::db::access_policies::TargetType::Glob,
        pattern,
    )
    .await
    .unwrap();
}

async fn add_item_policy(pool: &sqlx::PgPool, key_prefix: &str, counter: u32, item_name: &str) {
    let name = format!("{}-{}", key_prefix, counter);
    let keys = vaultwarden_bridge::db::machine_keys::list(pool)
        .await
        .unwrap();
    let key = keys
        .iter()
        .find(|k| k.name == name)
        .unwrap_or_else(|| panic!("key '{}' not found", name));
    vaultwarden_bridge::db::access_policies::create(
        pool,
        key.id,
        vaultwarden_bridge::db::access_policies::TargetType::Item,
        item_name,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn test_health_endpoint() {
    let ctx = get_context().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/health", ctx.base_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert!(body["status"].is_string());
    assert!(body["bw_serve"].is_boolean());
}

#[tokio::test]
async fn test_secret_retrieval_with_glob_policy() {
    let ctx = get_context().await;
    let client = reqwest::Client::new();

    let n = KEY_COUNTER.load(std::sync::atomic::Ordering::SeqCst);
    let api_key = create_test_key(&ctx.pool, "glob").await;
    add_glob_policy(&ctx.pool, "glob", n, "prod/**").await;

    let resp = client
        .get(format!("{}/api/v1/secret/prod/db/password", ctx.base_url))
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["key"], "prod/db/password");
    assert_eq!(body["value"], "super-secret-db-password");
}

#[tokio::test]
async fn test_secret_retrieval_with_item_policy() {
    let ctx = get_context().await;
    let client = reqwest::Client::new();

    let n = KEY_COUNTER.load(std::sync::atomic::Ordering::SeqCst);
    let api_key = create_test_key(&ctx.pool, "item").await;
    add_item_policy(&ctx.pool, "item", n, "staging/db/password").await;

    let resp = client
        .get(format!(
            "{}/api/v1/secret/staging/db/password",
            ctx.base_url
        ))
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["key"], "staging/db/password");
    assert_eq!(body["value"], "staging-db-password");
}

#[tokio::test]
async fn test_access_denied_without_policy() {
    let ctx = get_context().await;
    let client = reqwest::Client::new();

    let api_key = create_test_key(&ctx.pool, "nopolicy").await;

    let resp = client
        .get(format!("{}/api/v1/secret/prod/db/password", ctx.base_url))
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_access_denied_wrong_pattern() {
    let ctx = get_context().await;
    let client = reqwest::Client::new();

    let n = KEY_COUNTER.load(std::sync::atomic::Ordering::SeqCst);
    let api_key = create_test_key(&ctx.pool, "wrongpat").await;
    add_glob_policy(&ctx.pool, "wrongpat", n, "staging/**").await;

    let resp = client
        .get(format!("{}/api/v1/secret/prod/db/password", ctx.base_url))
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_unauthorized_no_bearer() {
    let ctx = get_context().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/secret/prod/db/password", ctx.base_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_unauthorized_bad_key() {
    let ctx = get_context().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/secret/prod/db/password", ctx.base_url))
        .header("Authorization", "Bearer totally-invalid-key")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_not_found() {
    let ctx = get_context().await;
    let client = reqwest::Client::new();

    let n = KEY_COUNTER.load(std::sync::atomic::Ordering::SeqCst);
    let api_key = create_test_key(&ctx.pool, "notfound").await;
    add_glob_policy(&ctx.pool, "notfound", n, "**").await;

    let resp = client
        .get(format!(
            "{}/api/v1/secret/nonexistent/secret/name",
            ctx.base_url
        ))
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_audit_log_populated() {
    let ctx = get_context().await;
    let client = reqwest::Client::new();

    let n = KEY_COUNTER.load(std::sync::atomic::Ordering::SeqCst);
    let api_key = create_test_key(&ctx.pool, "audit").await;
    add_glob_policy(&ctx.pool, "audit", n, "prod/**").await;

    client
        .get(format!("{}/api/v1/secret/prod/db/password", ctx.base_url))
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
        .unwrap();

    // Small delay for async audit write
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let entries = vaultwarden_bridge::db::audit::list_recent(&ctx.pool, 100)
        .await
        .unwrap();
    assert!(!entries.is_empty(), "audit log should have entries");
}

#[tokio::test]
async fn test_user_agent_captured_in_audit() {
    let ctx = get_context().await;
    let client = reqwest::Client::new();

    let n = KEY_COUNTER.load(std::sync::atomic::Ordering::SeqCst);
    let api_key = create_test_key(&ctx.pool, "ua").await;
    add_glob_policy(&ctx.pool, "ua", n, "prod/**").await;

    client
        .get(format!("{}/api/v1/secret/prod/db/password", ctx.base_url))
        .header("Authorization", format!("Bearer {}", api_key))
        .header("User-Agent", "terraform-provider-vaultwarden-bridge/0.1.0")
        .send()
        .await
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let entries = vaultwarden_bridge::db::audit::list_recent(&ctx.pool, 1)
        .await
        .unwrap();
    assert!(!entries.is_empty());
    let last = &entries[0];
    assert_eq!(
        last.client_version.as_deref(),
        Some("terraform-provider-vaultwarden-bridge/0.1.0")
    );
}
