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

impl std::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditAction::SecretRetrieved => write!(f, "secret_retrieved"),
            AuditAction::SecretNotFound => write!(f, "secret_not_found"),
            AuditAction::AccessDenied => write!(f, "access_denied"),
            AuditAction::IpDenied => write!(f, "ip_denied"),
        }
    }
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
    sqlx::query_as::<_, AuditEntry>("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT $1")
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
