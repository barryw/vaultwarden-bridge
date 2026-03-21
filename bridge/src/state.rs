use crate::bw::BwManager;
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub bw: Arc<BwManager>,
    pub session_secret: Vec<u8>,
    pub admin_username: String,
    pub admin_password: String,
}
