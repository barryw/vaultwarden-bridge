use axum::extract::{Query, State};
use axum::response::Html;
use serde::Deserialize;

use crate::state::AppState;

#[derive(Deserialize)]
pub struct SearchParams {
    pub q: Option<String>,
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub async fn search(
    State(state): State<AppState>,
    Query(params): Query<SearchParams>,
) -> Html<String> {
    let query = params.q.unwrap_or_default();
    if query.is_empty() {
        return Html(String::new());
    }

    let items = state
        .bw
        .client
        .list_items(Some(&query))
        .await
        .unwrap_or_default();

    if items.is_empty() {
        return Html(String::new());
    }

    let mut html = String::new();
    for item in items.iter().take(10) {
        let name = escape_html(&item.name);
        html.push_str(&format!(
            "<div class=\"suggestion\" onclick=\"selectSuggestion(this)\" data-value=\"{name}\">{name}</div>",
        ));
    }

    Html(html)
}
