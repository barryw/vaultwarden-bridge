use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use crate::state::AppState;

pub async fn health(State(state): State<AppState>) -> Json<Value> {
    let bw_healthy = state.bw.is_healthy().await;
    Json(json!({
        "status": if bw_healthy { "ok" } else { "degraded" },
        "bw_serve": bw_healthy,
    }))
}
