use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::{Form, Path, State},
    response::Redirect,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::db;
use crate::db::cidr_rules::CidrScope;
use crate::state::AppState;

#[derive(Template, WebTemplate)]
#[template(path = "cidrs.html")]
pub struct CidrsTemplate {
    pub ui_rules: Vec<db::cidr_rules::CidrRule>,
    pub api_rules: Vec<db::cidr_rules::CidrRule>,
}

#[derive(Deserialize)]
pub struct CreateCidrForm {
    pub scope: String,
    pub cidr: String,
}

pub async fn list(State(state): State<AppState>) -> CidrsTemplate {
    let ui_rules = db::cidr_rules::list_by_scope(&state.pool, CidrScope::Ui)
        .await
        .unwrap_or_default();
    let api_rules = db::cidr_rules::list_by_scope(&state.pool, CidrScope::Api)
        .await
        .unwrap_or_default();
    CidrsTemplate { ui_rules, api_rules }
}

pub async fn create(State(state): State<AppState>, Form(form): Form<CreateCidrForm>) -> Redirect {
    let scope = match form.scope.as_str() {
        "ui" => CidrScope::Ui,
        "api" => CidrScope::Api,
        _ => return Redirect::to("/ui/cidrs"),
    };
    if form.cidr.parse::<ipnet::IpNet>().is_ok() {
        let _ = db::cidr_rules::create(&state.pool, scope, &form.cidr).await;
    }
    Redirect::to("/ui/cidrs")
}

pub async fn delete(State(state): State<AppState>, Path(id): Path<Uuid>) -> Redirect {
    let _ = db::cidr_rules::delete(&state.pool, id).await;
    Redirect::to("/ui/cidrs")
}
