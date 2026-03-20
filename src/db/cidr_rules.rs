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
