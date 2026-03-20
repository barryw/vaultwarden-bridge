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
