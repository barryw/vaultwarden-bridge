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

/// Start the bridge on a random port and return the base URL.
async fn start_bridge() -> String {
    dotenvy::dotenv().ok();

    let config = vaultwarden_bridge::config::Config::from_env().expect("config from env");
    let pool = sqlx::PgPool::connect(&config.database_url)
        .await
        .expect("connect to postgres");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("run migrations");

    let app = vaultwarden_bridge::app(pool, config)
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

    format!("http://{}", addr)
}

/// Create a machine key via the database directly and return the raw API key.
async fn create_test_key(pool: &sqlx::PgPool, name: &str) -> String {
    let raw_key = vaultwarden_bridge::auth::generate_api_key();
    let hash = vaultwarden_bridge::auth::hash_api_key(&raw_key).unwrap();
    vaultwarden_bridge::db::machine_keys::create(pool, name, &hash)
        .await
        .expect("create machine key");
    raw_key
}

/// Add a glob policy to a machine key.
async fn add_glob_policy(pool: &sqlx::PgPool, key_name: &str, pattern: &str) {
    let keys = vaultwarden_bridge::db::machine_keys::list(pool)
        .await
        .unwrap();
    let key = keys.iter().find(|k| k.name == key_name).unwrap();
    vaultwarden_bridge::db::access_policies::create(
        pool,
        key.id,
        vaultwarden_bridge::db::access_policies::TargetType::Glob,
        pattern,
    )
    .await
    .unwrap();
}

/// Add an item policy to a machine key.
async fn add_item_policy(pool: &sqlx::PgPool, key_name: &str, item_name: &str) {
    let keys = vaultwarden_bridge::db::machine_keys::list(pool)
        .await
        .unwrap();
    let key = keys.iter().find(|k| k.name == key_name).unwrap();
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
    let base_url = start_bridge().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/health", base_url))
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
    let base_url = start_bridge().await;
    let client = reqwest::Client::new();

    let config = vaultwarden_bridge::config::Config::from_env().unwrap();
    let pool = sqlx::PgPool::connect(&config.database_url).await.unwrap();

    // Create a key with glob policy for prod/*
    let api_key = create_test_key(&pool, "test-glob-key").await;
    add_glob_policy(&pool, "test-glob-key", "prod/**").await;

    let resp = client
        .get(format!("{}/api/v1/secret/prod/db/password", base_url))
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
    let base_url = start_bridge().await;
    let client = reqwest::Client::new();

    let config = vaultwarden_bridge::config::Config::from_env().unwrap();
    let pool = sqlx::PgPool::connect(&config.database_url).await.unwrap();

    let api_key = create_test_key(&pool, "test-item-key").await;
    add_item_policy(&pool, "test-item-key", "staging/db/password").await;

    let resp = client
        .get(format!("{}/api/v1/secret/staging/db/password", base_url))
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
    let base_url = start_bridge().await;
    let client = reqwest::Client::new();

    let config = vaultwarden_bridge::config::Config::from_env().unwrap();
    let pool = sqlx::PgPool::connect(&config.database_url).await.unwrap();

    // Key with no policies — should be denied
    let api_key = create_test_key(&pool, "test-no-policy-key").await;

    let resp = client
        .get(format!("{}/api/v1/secret/prod/db/password", base_url))
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_access_denied_wrong_pattern() {
    let base_url = start_bridge().await;
    let client = reqwest::Client::new();

    let config = vaultwarden_bridge::config::Config::from_env().unwrap();
    let pool = sqlx::PgPool::connect(&config.database_url).await.unwrap();

    // Key with policy for staging/* — should be denied for prod/*
    let api_key = create_test_key(&pool, "test-wrong-pattern-key").await;
    add_glob_policy(&pool, "test-wrong-pattern-key", "staging/**").await;

    let resp = client
        .get(format!("{}/api/v1/secret/prod/db/password", base_url))
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_unauthorized_no_bearer() {
    let base_url = start_bridge().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/secret/prod/db/password", base_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_unauthorized_bad_key() {
    let base_url = start_bridge().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/secret/prod/db/password", base_url))
        .header("Authorization", "Bearer totally-invalid-key")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_not_found() {
    let base_url = start_bridge().await;
    let client = reqwest::Client::new();

    let config = vaultwarden_bridge::config::Config::from_env().unwrap();
    let pool = sqlx::PgPool::connect(&config.database_url).await.unwrap();

    // Key with wide-open policy
    let api_key = create_test_key(&pool, "test-notfound-key").await;
    add_glob_policy(&pool, "test-notfound-key", "**").await;

    let resp = client
        .get(format!(
            "{}/api/v1/secret/nonexistent/secret/name",
            base_url
        ))
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_audit_log_populated() {
    let base_url = start_bridge().await;
    let client = reqwest::Client::new();

    let config = vaultwarden_bridge::config::Config::from_env().unwrap();
    let pool = sqlx::PgPool::connect(&config.database_url).await.unwrap();

    let api_key = create_test_key(&pool, "test-audit-key").await;
    add_glob_policy(&pool, "test-audit-key", "prod/**").await;

    // Make a request
    client
        .get(format!("{}/api/v1/secret/prod/db/password", base_url))
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
        .unwrap();

    // Check audit log has entries
    let entries = vaultwarden_bridge::db::audit::list_recent(&pool, 100)
        .await
        .unwrap();
    assert!(!entries.is_empty(), "audit log should have entries");

    let last = &entries[0];
    assert_eq!(last.target_requested, "prod/db/password");
}

#[tokio::test]
async fn test_user_agent_captured_in_audit() {
    let base_url = start_bridge().await;
    let client = reqwest::Client::new();

    let config = vaultwarden_bridge::config::Config::from_env().unwrap();
    let pool = sqlx::PgPool::connect(&config.database_url).await.unwrap();

    let api_key = create_test_key(&pool, "test-ua-key").await;
    add_glob_policy(&pool, "test-ua-key", "prod/**").await;

    client
        .get(format!("{}/api/v1/secret/prod/db/password", base_url))
        .header("Authorization", format!("Bearer {}", api_key))
        .header("User-Agent", "terraform-provider-vaultwarden/0.1.0")
        .send()
        .await
        .unwrap();

    let entries = vaultwarden_bridge::db::audit::list_recent(&pool, 100)
        .await
        .unwrap();
    let last = &entries[0];
    assert_eq!(
        last.client_version.as_deref(),
        Some("terraform-provider-vaultwarden/0.1.0")
    );
}
