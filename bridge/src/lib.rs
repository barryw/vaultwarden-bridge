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
use axum::response::Redirect;
use axum::routing::get;
use rand::RngCore;
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
        config.bw_serve_external,
    ));
    bw.start().await?;

    // Generate a random session secret for HMAC-signed session cookies
    let mut session_secret = vec![0u8; 32];
    rand::rng().fill_bytes(&mut session_secret);

    let state = AppState {
        pool: pool.clone(),
        bw,
        session_secret,
        admin_username: config.admin_username,
        admin_password: config.admin_password,
    };

    let api_routes = api::router(state.clone());
    let ui_routes = ui::router(state.clone());

    let app = Router::new()
        .route("/", get(|| async { Redirect::permanent("/ui") }))
        .nest("/api", api_routes)
        .nest("/ui", ui_routes);

    Ok(app)
}
