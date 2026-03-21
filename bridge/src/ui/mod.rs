pub mod audit_view;
pub mod auth;
pub mod cidrs;
pub mod dashboard;
pub mod keys;
pub mod policies;
pub mod vault_search;

use crate::state::AppState;
use axum::{Router, routing::get};

pub fn router(state: AppState, _admin_username: &str, _admin_password: &str) -> Router {
    Router::new()
        .route("/", get(dashboard::dashboard))
        .route("/login", get(auth::login_page).post(auth::login))
        .route("/logout", get(auth::logout))
        .route("/keys", get(keys::list).post(keys::create))
        .route("/keys/{id}/toggle", get(keys::toggle))
        .route("/keys/{id}/delete", get(keys::delete))
        .route(
            "/keys/{id}/policies",
            get(policies::list).post(policies::create),
        )
        .route(
            "/keys/{id}/policies/{policy_id}/delete",
            get(policies::delete),
        )
        .route("/api/vault-items", get(vault_search::search))
        .route("/audit", get(audit_view::list))
        .route("/cidrs", get(cidrs::list).post(cidrs::create))
        .route("/cidrs/{id}/delete", get(cidrs::delete))
        .with_state(state)
}
