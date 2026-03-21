use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::{Form, Path, State},
    response::Redirect,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth;
use crate::db;
use crate::state::AppState;

#[derive(Template, WebTemplate)]
#[template(path = "keys.html")]
pub struct KeysTemplate {
    pub active_nav: &'static str,
    pub keys: Vec<db::machine_keys::MachineKey>,
    pub flash_message: Option<String>,
    pub new_api_key: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateKeyForm {
    pub name: String,
}

pub async fn list(State(state): State<AppState>) -> KeysTemplate {
    let keys = db::machine_keys::list(&state.pool)
        .await
        .unwrap_or_default();
    KeysTemplate {
        active_nav: "keys",
        keys,
        flash_message: None,
        new_api_key: None,
    }
}

pub async fn create(
    State(state): State<AppState>,
    Form(form): Form<CreateKeyForm>,
) -> KeysTemplate {
    let raw_key = auth::generate_api_key();
    let hash = auth::hash_api_key(&raw_key).unwrap();

    match db::machine_keys::create(&state.pool, &form.name, &hash).await {
        Ok(_) => {
            let keys = db::machine_keys::list(&state.pool)
                .await
                .unwrap_or_default();
            KeysTemplate {
                active_nav: "keys",
                keys,
                flash_message: None,
                new_api_key: Some(raw_key),
            }
        }
        Err(e) => {
            let keys = db::machine_keys::list(&state.pool)
                .await
                .unwrap_or_default();
            KeysTemplate {
                active_nav: "keys",
                keys,
                flash_message: Some(format!("Error: {}", e)),
                new_api_key: None,
            }
        }
    }
}

pub async fn toggle(State(state): State<AppState>, Path(id): Path<Uuid>) -> Redirect {
    if let Ok(Some(key)) = db::machine_keys::find_by_id(&state.pool, id).await {
        let _ = db::machine_keys::set_enabled(&state.pool, id, !key.enabled).await;
    }
    Redirect::to("/ui/keys")
}

pub async fn delete(State(state): State<AppState>, Path(id): Path<Uuid>) -> Redirect {
    let _ = db::machine_keys::delete(&state.pool, id).await;
    Redirect::to("/ui/keys")
}
