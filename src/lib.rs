pub mod api;
pub mod audit;
pub mod auth;
pub mod bw;
pub mod config;
pub mod db;
pub mod error;
pub mod middleware;
pub mod policy;
pub mod state;
pub mod ui;

use axum::Router;
use sqlx::PgPool;
use std::sync::Arc;

use crate::bw::BwManager;
use crate::config::Config;
use crate::state::AppState;

pub async fn app(pool: PgPool, config: Config) -> anyhow::Result<Router> {
    // Seed CIDR rules from env config
    db::cidr_rules::seed_from_config(&pool, db::cidr_rules::CidrScope::Ui, &config.ui_allow_cidrs)
        .await?;
    db::cidr_rules::seed_from_config(
        &pool,
        db::cidr_rules::CidrScope::Api,
        &config.api_allow_cidrs,
    )
    .await?;

    // Start bw serve
    let bw = Arc::new(BwManager::new(
        config.bw_server_url,
        config.bw_email,
        config.bw_password,
        config.bw_serve_port,
    ));
    bw.start().await?;

    let state = AppState {
        pool: pool.clone(),
        bw,
    };

    let api_routes = api::router(state.clone());
    let ui_routes = ui::router(state.clone(), &config.admin_username, &config.admin_password);

    let app = Router::new()
        .nest("/api", api_routes)
        .nest("/ui", ui_routes);

    Ok(app)
}
