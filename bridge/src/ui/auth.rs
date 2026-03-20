use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::Form,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;

#[derive(Template, WebTemplate)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
}

pub async fn login_page() -> LoginTemplate {
    LoginTemplate { error: None }
}

pub async fn login(Form(_form): Form<LoginForm>) -> Response {
    // For v1: simple static credential check will be wired up later
    // For now, just set a session cookie and redirect
    let cookie = "bridge_session=valid; Path=/ui; HttpOnly; SameSite=Strict".to_string();
    (
        StatusCode::SEE_OTHER,
        [
            (header::SET_COOKIE, cookie),
            (header::LOCATION, "/ui/".to_string()),
        ],
    )
        .into_response()
}

pub async fn logout() -> Response {
    let cookie = "bridge_session=; Path=/ui; HttpOnly; Max-Age=0";
    (
        StatusCode::SEE_OTHER,
        [
            (header::SET_COOKIE, cookie.to_string()),
            (header::LOCATION, "/ui/login".to_string()),
        ],
    )
        .into_response()
}
