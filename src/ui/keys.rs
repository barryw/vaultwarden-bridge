use axum::{
    extract::{Form, Path, State},
    response::Redirect,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::state::AppState;

#[derive(Deserialize)]
pub struct CreateKeyForm {
    pub name: String,
}

pub async fn list(State(_state): State<AppState>) -> String {
    "keys list - TODO".to_string()
}

pub async fn create(
    State(_state): State<AppState>,
    Form(_form): Form<CreateKeyForm>,
) -> Redirect {
    Redirect::to("/ui/keys")
}

pub async fn toggle(State(_state): State<AppState>, Path(_id): Path<Uuid>) -> Redirect {
    Redirect::to("/ui/keys")
}

pub async fn delete(State(_state): State<AppState>, Path(_id): Path<Uuid>) -> Redirect {
    Redirect::to("/ui/keys")
}
