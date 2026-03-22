pub mod browse;
pub mod health;
pub mod secrets;

use std::sync::Arc;

use axum::{Router, routing::get};
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;

use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    // Rate limit: 60 request burst, refilling at 30/s per IP
    let governor_config = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(30)
            .burst_size(60)
            .finish()
            .expect("governor config"),
    );

    Router::new()
        .route("/v1/secret/{*key}", get(secrets::get_secret))
        .route("/v1/organizations", get(browse::list_organizations))
        .route("/v1/collections", get(browse::list_collections))
        .route("/v1/folders", get(browse::list_folders))
        .route("/v1/items", get(browse::list_items))
        .layer(GovernorLayer {
            config: governor_config,
        })
        .route("/v1/health", get(health::health))
        .with_state(state)
}
