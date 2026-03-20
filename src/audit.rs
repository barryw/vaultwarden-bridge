use crate::db;
use crate::db::audit::{AuditAction, NewAuditEntry};
use sqlx::PgPool;
use uuid::Uuid;

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
