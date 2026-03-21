use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::{Form, Path, State},
    response::Redirect,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::db;
use crate::db::access_policies::TargetType;
use crate::state::AppState;

#[derive(Template, WebTemplate)]
#[template(path = "policies.html")]
pub struct PoliciesTemplate {
    pub active_nav: &'static str,
    pub key_id: Uuid,
    pub key_name: String,
    pub policies: Vec<db::access_policies::AccessPolicy>,
}

#[derive(Deserialize)]
pub struct CreatePolicyForm {
    pub target_type: String,
    pub target_value: String,
}

pub async fn list(State(state): State<AppState>, Path(id): Path<Uuid>) -> PoliciesTemplate {
    let key = db::machine_keys::find_by_id(&state.pool, id)
        .await
        .ok()
        .flatten();
    let key_name = key.map(|k| k.name).unwrap_or_else(|| "Unknown".to_string());
    let policies = db::access_policies::list_for_key(&state.pool, id)
        .await
        .unwrap_or_default();
    PoliciesTemplate {
        active_nav: "keys",
        key_id: id,
        key_name,
        policies,
    }
}

pub async fn create(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Form(form): Form<CreatePolicyForm>,
) -> Redirect {
    let target_type = match form.target_type.as_str() {
        "item" => TargetType::Item,
        "collection" => TargetType::Collection,
        "glob" => TargetType::Glob,
        _ => return Redirect::to(&format!("/ui/keys/{}/policies", id)),
    };
    let _ = db::access_policies::create(&state.pool, id, target_type, &form.target_value).await;
    Redirect::to(&format!("/ui/keys/{}/policies", id))
}

pub async fn delete(
    State(state): State<AppState>,
    Path((key_id, policy_id)): Path<(Uuid, Uuid)>,
) -> Redirect {
    let _ = db::access_policies::delete(&state.pool, policy_id).await;
    Redirect::to(&format!("/ui/keys/{}/policies", key_id))
}
