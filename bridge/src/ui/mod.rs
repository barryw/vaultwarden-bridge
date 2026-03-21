pub mod audit_view;
pub mod auth;
pub mod cidrs;
pub mod dashboard;
pub mod keys;
pub mod policies;
pub mod vault_search;

use axum::{Router, middleware, routing::get};

use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(dashboard::dashboard))
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
        .route("/logout", get(auth::logout))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_session,
        ))
        .route("/login", get(auth::login_page).post(auth::login))
        .with_state(state)
}
