use axum::{
    extract::{Form, Path, State},
    response::Redirect,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::state::AppState;

#[derive(Deserialize)]
pub struct CreatePolicyForm {
    pub target_type: String,
    pub target_value: String,
}

pub async fn list(State(_state): State<AppState>, Path(_id): Path<Uuid>) -> String {
    "policies list - TODO".to_string()
}

pub async fn create(
    State(_state): State<AppState>,
    Path(_id): Path<Uuid>,
    Form(_form): Form<CreatePolicyForm>,
) -> Redirect {
    Redirect::to("/ui/keys")
}

pub async fn delete(
    State(_state): State<AppState>,
    Path((_key_id, _policy_id)): Path<(Uuid, Uuid)>,
) -> Redirect {
    Redirect::to("/ui/keys")
}
