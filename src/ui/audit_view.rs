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
    let entries = db::audit::list_recent(&state.pool, 100)
        .await
        .unwrap_or_default();
    AuditTemplate { entries }
}
