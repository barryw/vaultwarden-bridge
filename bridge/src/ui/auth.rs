use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::state::AppState;

type HmacSha256 = Hmac<Sha256>;

#[derive(Template, WebTemplate)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub version: &'static str,
    pub error: Option<String>,
}

#[derive(serde::Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
}

/// Generate a signed session token: HMAC-SHA256(session_secret, "bridge_session")
fn make_session_token(session_secret: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(session_secret).expect("HMAC accepts any key length");
    mac.update(b"bridge_session");
    let result = mac.finalize().into_bytes();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(result)
}

/// Verify a session cookie value against the session secret.
fn verify_session_token(token: &str, session_secret: &[u8]) -> bool {
    let expected = make_session_token(session_secret);
    token.as_bytes().ct_eq(expected.as_bytes()).into()
}

fn set_session_cookie(token: &str) -> String {
    format!(
        "bridge_session={}; Path=/ui; HttpOnly; SameSite=Strict; Secure",
        token
    )
}

pub async fn login_page() -> LoginTemplate {
    LoginTemplate {
        version: env!("CARGO_PKG_VERSION"),
        error: None,
    }
}

pub async fn login(
    State(state): State<AppState>,
    axum::extract::Form(form): axum::extract::Form<LoginForm>,
) -> Response {
    let user_ok = form
        .username
        .as_bytes()
        .ct_eq(state.admin_username.as_bytes())
        .into();
    let pass_ok = form
        .password
        .as_bytes()
        .ct_eq(state.admin_password.as_bytes())
        .into();

    if user_ok && pass_ok {
        let token = make_session_token(&state.session_secret);
        (
            StatusCode::SEE_OTHER,
            [
                (header::SET_COOKIE, set_session_cookie(&token)),
                (header::LOCATION, "/ui".to_string()),
            ],
        )
            .into_response()
    } else {
        LoginTemplate {
            version: env!("CARGO_PKG_VERSION"),
            error: Some("Invalid credentials".to_string()),
        }
        .into_response()
    }
}

pub async fn logout() -> Response {
    let cookie = "bridge_session=; Path=/ui; HttpOnly; SameSite=Strict; Secure; Max-Age=0";
    (
        StatusCode::SEE_OTHER,
        [
            (header::SET_COOKIE, cookie.to_string()),
            (header::LOCATION, "/ui/login".to_string()),
        ],
    )
        .into_response()
}

/// Middleware that validates the session cookie on all UI routes except /login.
pub async fn require_session(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();

    // Allow login page and static assets without session
    if path == "/ui/login" || path == "/login" {
        return next.run(request).await;
    }

    let has_valid_session = request
        .headers()
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .map(|s| s.trim())
        .filter_map(|s| s.split_once('='))
        .any(|(name, value)| {
            name == "bridge_session" && verify_session_token(value, &state.session_secret)
        });

    if has_valid_session {
        next.run(request).await
    } else {
        Redirect::to("/ui/login").into_response()
    }
}
