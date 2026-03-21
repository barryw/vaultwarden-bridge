use askama::Template;
use askama_web::WebTemplate;
use axum::extract::State;

use crate::db;
use crate::state::AppState;

#[derive(Template, WebTemplate)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate {
    pub active_nav: &'static str,
    pub version: &'static str,
    pub key_count: usize,
    pub enabled_count: usize,
    pub bw_healthy: bool,
    pub recent_audit_count: usize,
    pub recent_audits: Vec<db::audit::AuditEntry>,
}

pub async fn dashboard(State(state): State<AppState>) -> DashboardTemplate {
    let keys = db::machine_keys::list(&state.pool)
        .await
        .unwrap_or_default();
    let enabled_count = keys.iter().filter(|k| k.enabled).count();
    let recent_audits = db::audit::list_recent(&state.pool, 10)
        .await
        .unwrap_or_default();
    let bw_healthy = state.bw.is_healthy().await;

    DashboardTemplate {
        active_nav: "dashboard",
        version: env!("CARGO_PKG_VERSION"),
        key_count: keys.len(),
        enabled_count,
        bw_healthy,
        recent_audit_count: recent_audits.len(),
        recent_audits,
    }
}
