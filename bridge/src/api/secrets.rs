use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use serde_json::{Value, json};

use crate::auth;
use crate::db;
use crate::db::audit::AuditAction;
use crate::error::AppError;
use crate::policy;
use crate::state::AppState;

fn extract_bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

fn extract_client_version(headers: &HeaderMap) -> Option<String> {
    headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn extract_source_ip(headers: &HeaderMap, fallback: &str) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| fallback.to_string())
}

pub async fn get_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_key): Path<String>,
) -> Result<Json<Value>, AppError> {
    let key = raw_key.trim_start_matches('/').to_string();
    let source_ip = extract_source_ip(&headers, "unknown");
    let client_version = extract_client_version(&headers);

    // Authenticate
    let bearer = extract_bearer(&headers).ok_or(AppError::Unauthorized)?;

    let all_keys = db::machine_keys::find_all_enabled(&state.pool).await?;
    let machine_key = all_keys
        .iter()
        .find(|k| auth::verify_api_key(bearer, &k.key_hash).unwrap_or(false));

    let machine_key = match machine_key {
        Some(k) => k,
        None => {
            crate::audit::log(
                &state.pool,
                None,
                AuditAction::AccessDenied,
                &key,
                None,
                &source_ip,
                client_version.as_deref(),
            )
            .await;
            return Err(AppError::Unauthorized);
        }
    };

    // Get access policies for this key
    let policies = db::access_policies::list_for_key(&state.pool, machine_key.id).await?;

    // Search bw serve for the item
    let items = state
        .bw
        .client
        .list_items(Some(&key))
        .await
        .map_err(|e| AppError::ServiceUnavailable(format!("bw serve error: {}", e)))?;

    // Find exact name match
    let item = items.iter().find(|i| i.name == key);

    let item = match item {
        Some(i) => i,
        None => {
            crate::audit::log(
                &state.pool,
                Some(machine_key.id),
                AuditAction::SecretNotFound,
                &key,
                None,
                &source_ip,
                client_version.as_deref(),
            )
            .await;
            return Err(AppError::NotFound(key));
        }
    };

    // Check access policies
    let collection_ids = item.collection_ids.clone().unwrap_or_default();
    if !policy::evaluate_access(&policies, &key, &collection_ids) {
        crate::audit::log(
            &state.pool,
            Some(machine_key.id),
            AuditAction::AccessDenied,
            &key,
            Some(&item.id),
            &source_ip,
            client_version.as_deref(),
        )
        .await;
        return Err(AppError::AccessDenied);
    }

    // Extract the secret value
    let value = item
        .login
        .as_ref()
        .and_then(|l| l.password.clone())
        .unwrap_or_default();

    let updated_at = item.revision_date.clone().unwrap_or_default();

    // Audit success
    crate::audit::log(
        &state.pool,
        Some(machine_key.id),
        AuditAction::SecretRetrieved,
        &key,
        Some(&item.id),
        &source_ip,
        client_version.as_deref(),
    )
    .await;

    Ok(Json(json!({
        "key": key,
        "value": value,
        "updated_at": updated_at,
    })))
}
