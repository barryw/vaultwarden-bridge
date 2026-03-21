pub mod health;
pub mod secrets;

use std::sync::Arc;

use axum::{Router, routing::get};
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;

use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    // Rate limit: 30 requests per second per IP on secret retrieval
    let governor_config = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(30)
            .burst_size(10)
            .finish()
            .expect("governor config"),
    );

    Router::new()
        .route("/v1/secret/{*key}", get(secrets::get_secret))
        .layer(GovernorLayer {
            config: governor_config,
        })
        .route("/v1/health", get(health::health))
        .with_state(state)
}
