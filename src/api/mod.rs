pub mod health;
pub mod secrets;

use crate::state::AppState;
use axum::{Router, routing::get};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/secret/{key}", get(secrets::get_secret))
        .route("/v1/health", get(health::health))
        .with_state(state)
}
