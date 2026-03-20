use crate::state::AppState;
use axum::Router;

pub fn router(state: AppState, _admin_username: &str, _admin_password: &str) -> Router {
    Router::new().with_state(state)
}
