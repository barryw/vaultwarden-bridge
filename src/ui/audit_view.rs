use axum::extract::State;

use crate::state::AppState;

pub async fn list(State(_state): State<AppState>) -> String {
    "audit log - TODO".to_string()
}
