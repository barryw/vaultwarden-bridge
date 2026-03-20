use axum::Json;
use axum::extract::State;
use serde_json::{Value, json};

use crate::state::AppState;

pub async fn health(State(state): State<AppState>) -> Json<Value> {
    let bw_healthy = state.bw.is_healthy().await;
    Json(json!({
        "status": if bw_healthy { "ok" } else { "degraded" },
        "bw_serve": bw_healthy,
    }))
}
