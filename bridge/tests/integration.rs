//! Integration tests for the vaultwarden-bridge API.
//!
//! Expects a running bridge at TEST_BRIDGE_URL (default http://127.0.0.1:9090).
//! The bridge, Vaultwarden, and Postgres must be running and seeded before tests.

use reqwest::StatusCode;
use serde_json::Value;
use std::sync::atomic::{AtomicU32, Ordering};

fn bridge_url() -> String {
    std::env::var("TEST_BRIDGE_URL").unwrap_or_else(|_| "http://127.0.0.1:9090".to_string())
}

fn db_url() -> String {
    std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://bridge:bridge@localhost:5432/vaultwarden_bridge".to_string()
    })
}

static KEY_COUNTER: AtomicU32 = AtomicU32::new(0);

async fn pool() -> sqlx::PgPool {
    sqlx::PgPool::connect(&db_url()).await.unwrap()
}

async fn create_test_key(prefix: &str) -> (String, u32) {
    let n = KEY_COUNTER.fetch_add(1, Ordering::SeqCst);
    let name = format!("{}-{}", prefix, n);
    let raw_key = vaultwarden_bridge::auth::generate_api_key();
    let hash = vaultwarden_bridge::auth::hash_api_key(&raw_key).unwrap();
    let pool = pool().await;
    vaultwarden_bridge::db::machine_keys::create(&pool, &name, &hash)
        .await
        .expect("create machine key");
    (raw_key, n)
}

async fn add_glob_policy(prefix: &str, n: u32, pattern: &str) {
    let name = format!("{}-{}", prefix, n);
    let pool = pool().await;
    let keys = vaultwarden_bridge::db::machine_keys::list(&pool)
        .await
        .unwrap();
    let key = keys.iter().find(|k| k.name == name).unwrap();
    vaultwarden_bridge::db::access_policies::create(
        &pool,
        key.id,
        vaultwarden_bridge::db::access_policies::TargetType::Glob,
        pattern,
    )
    .await
    .unwrap();
}

async fn add_item_policy(prefix: &str, n: u32, item_name: &str) {
    let name = format!("{}-{}", prefix, n);
    let pool = pool().await;
    let keys = vaultwarden_bridge::db::machine_keys::list(&pool)
        .await
        .unwrap();
    let key = keys.iter().find(|k| k.name == name).unwrap();
    vaultwarden_bridge::db::access_policies::create(
        &pool,
        key.id,
        vaultwarden_bridge::db::access_policies::TargetType::Item,
        item_name,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn test_health_endpoint() {
    let resp = reqwest::get(format!("{}/api/v1/health", bridge_url()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["bw_serve"], true);
}

#[tokio::test]
async fn test_secret_retrieval_with_glob_policy() {
    let (api_key, n) = create_test_key("glob").await;
    add_glob_policy("glob", n, "prod/**").await;

    let resp = reqwest::Client::new()
        .get(format!("{}/api/v1/secret/prod/db/password", bridge_url()))
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
    let (api_key, n) = create_test_key("item").await;
    add_item_policy("item", n, "staging/db/password").await;

    let resp = reqwest::Client::new()
        .get(format!(
            "{}/api/v1/secret/staging/db/password",
            bridge_url()
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
    let (api_key, _) = create_test_key("nopolicy").await;

    let resp = reqwest::Client::new()
        .get(format!("{}/api/v1/secret/prod/db/password", bridge_url()))
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_access_denied_wrong_pattern() {
    let (api_key, n) = create_test_key("wrongpat").await;
    add_glob_policy("wrongpat", n, "staging/**").await;

    let resp = reqwest::Client::new()
        .get(format!("{}/api/v1/secret/prod/db/password", bridge_url()))
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_unauthorized_no_bearer() {
    let resp = reqwest::Client::new()
        .get(format!("{}/api/v1/secret/prod/db/password", bridge_url()))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_unauthorized_bad_key() {
    let resp = reqwest::Client::new()
        .get(format!("{}/api/v1/secret/prod/db/password", bridge_url()))
        .header("Authorization", "Bearer totally-invalid-key")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_not_found() {
    let (api_key, n) = create_test_key("notfound").await;
    add_glob_policy("notfound", n, "**").await;

    let resp = reqwest::Client::new()
        .get(format!(
            "{}/api/v1/secret/nonexistent/secret/name",
            bridge_url()
        ))
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_audit_log_populated() {
    let (api_key, n) = create_test_key("audit").await;
    add_glob_policy("audit", n, "prod/**").await;

    reqwest::Client::new()
        .get(format!("{}/api/v1/secret/prod/db/password", bridge_url()))
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let pool = pool().await;
    let entries = vaultwarden_bridge::db::audit::list_recent(&pool, 100)
        .await
        .unwrap();
    assert!(!entries.is_empty(), "audit log should have entries");
}

#[tokio::test]
async fn test_user_agent_captured_in_audit() {
    let (api_key, n) = create_test_key("ua").await;
    add_glob_policy("ua", n, "prod/**").await;

    reqwest::Client::new()
        .get(format!("{}/api/v1/secret/prod/db/password", bridge_url()))
        .header("Authorization", format!("Bearer {}", api_key))
        .header("User-Agent", "terraform-provider-vaultwarden-bridge/0.1.0")
        .send()
        .await
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let pool = pool().await;
    let entries = vaultwarden_bridge::db::audit::list_recent(&pool, 1)
        .await
        .unwrap();
    assert!(!entries.is_empty());
    assert_eq!(
        entries[0].client_version.as_deref(),
        Some("terraform-provider-vaultwarden-bridge/0.1.0")
    );
}
