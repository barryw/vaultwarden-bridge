use std::net::SocketAddr;

use axum::{
    Json,
    extract::{ConnectInfo, Path, State},
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

pub async fn get_secret(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(raw_key): Path<String>,
) -> Result<Json<Value>, AppError> {
    let key = raw_key.trim_start_matches('/').to_string();
    let source_ip = addr.ip().to_string();
    let client_version = extract_client_version(&headers);

    // Authenticate — use key prefix for O(1) DB lookup, then single Argon2 verify
    let bearer = extract_bearer(&headers).ok_or(AppError::Unauthorized)?;
    let prefix = auth::key_prefix(bearer);

    let candidates = db::machine_keys::find_enabled_by_prefix(&state.pool, &prefix).await?;
    let machine_key = candidates
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

    // Build type-specific response
    let updated_at = item.revision_date.clone().unwrap_or_default();
    let type_name = item.type_name();

    let mut resp = json!({
        "key": key,
        "type": type_name,
        "notes": item.notes,
        "updated_at": updated_at,
    });

    // Custom fields
    if let Some(fields) = &item.fields {
        let fields_json: Vec<Value> = fields
            .iter()
            .map(|f| {
                json!({
                    "name": f.name,
                    "value": f.value,
                    "type": f.type_name(),
                })
            })
            .collect();
        resp["fields"] = json!(fields_json);
    }

    // Type-specific block
    match item.item_type {
        1 => {
            if let Some(login) = &item.login {
                let uris: Vec<&str> = login
                    .uris
                    .as_ref()
                    .map(|u| u.iter().filter_map(|uri| uri.uri.as_deref()).collect())
                    .unwrap_or_default();

                resp["login"] = json!({
                    "username": login.username,
                    "password": login.password,
                    "totp": login.totp,
                    "uris": uris,
                });
            }
        }
        3 => {
            if let Some(card) = &item.card {
                resp["card"] = json!({
                    "cardholder_name": card.cardholder_name,
                    "brand": card.brand,
                    "number": card.number,
                    "exp_month": card.exp_month,
                    "exp_year": card.exp_year,
                    "cvv": card.code,
                });
            }
        }
        4 => {
            if let Some(identity) = &item.identity {
                resp["identity"] = json!({
                    "title": identity.title,
                    "first_name": identity.first_name,
                    "middle_name": identity.middle_name,
                    "last_name": identity.last_name,
                    "address1": identity.address1,
                    "address2": identity.address2,
                    "address3": identity.address3,
                    "city": identity.city,
                    "state": identity.state,
                    "postal_code": identity.postal_code,
                    "country": identity.country,
                    "company": identity.company,
                    "email": identity.email,
                    "phone": identity.phone,
                    "ssn": identity.ssn,
                    "username": identity.username,
                    "passport_number": identity.passport_number,
                    "license_number": identity.license_number,
                });
            }
        }
        2 => {
            // Secure note — content is in the common `notes` field, no type-specific block
        }
        _ => {}
    }

    Ok(Json(resp))
}
