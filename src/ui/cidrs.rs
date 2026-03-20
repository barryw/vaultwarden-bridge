use axum::{
    extract::{Form, Path, State},
    response::Redirect,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::state::AppState;

#[derive(Deserialize)]
pub struct CreateCidrForm {
    pub scope: String,
    pub cidr: String,
}

pub async fn list(State(_state): State<AppState>) -> String {
    "cidrs list - TODO".to_string()
}

pub async fn create(
    State(_state): State<AppState>,
    Form(_form): Form<CreateCidrForm>,
) -> Redirect {
    Redirect::to("/ui/cidrs")
}

pub async fn delete(State(_state): State<AppState>, Path(_id): Path<Uuid>) -> Redirect {
    Redirect::to("/ui/cidrs")
}
