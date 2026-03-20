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

impl std::fmt::Display for TargetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetType::Item => write!(f, "item"),
            TargetType::Collection => write!(f, "collection"),
            TargetType::Glob => write!(f, "glob"),
        }
    }
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
