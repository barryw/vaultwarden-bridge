use std::net::SocketAddr;

use axum::{
    Json,
    extract::{ConnectInfo, Path, Query, State},
    http::HeaderMap,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::auth;
use crate::db;
use crate::db::audit::AuditAction;
use crate::db::machine_keys::MachineKey;
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

/// Authenticate a Bearer token and return the machine key. Used by secrets and browse endpoints.
pub async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    addr: &SocketAddr,
) -> Result<MachineKey, AppError> {
    let bearer = extract_bearer(headers).ok_or(AppError::Unauthorized)?;
    let prefix = auth::key_prefix(bearer);

    let candidates = db::machine_keys::find_enabled_by_prefix(&state.pool, &prefix).await?;
    let machine_key = candidates
        .iter()
        .find(|k| auth::verify_api_key(bearer, &k.key_hash).unwrap_or(false));

    match machine_key {
        Some(k) => Ok(k.clone()),
        None => {
            crate::audit::log(
                &state.pool,
                None,
                AuditAction::AccessDenied,
                "",
                None,
                &addr.ip().to_string(),
                extract_client_version(headers).as_deref(),
            )
            .await;
            Err(AppError::Unauthorized)
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SecretQuery {
    pub collection: Option<String>,
    pub folder: Option<String>,
}

pub async fn get_secret(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(raw_key): Path<String>,
    Query(query): Query<SecretQuery>,
) -> Result<Json<Value>, AppError> {
    let key = raw_key.trim_start_matches('/').to_string();
    let source_ip = addr.ip().to_string();
    let client_version = extract_client_version(&headers);

    let machine_key = authenticate(&state, &headers, &addr).await?;

    // Get access policies for this key
    let policies = db::access_policies::list_for_key(&state.pool, machine_key.id).await?;

    // Search bw serve for the item
    let items = state
        .bw
        .client
        .list_items(Some(&key))
        .await
        .map_err(|e| AppError::ServiceUnavailable(format!("bw serve error: {}", e)))?;

    // Find all exact name matches
    let mut matches: Vec<_> = items.iter().filter(|i| i.name == key).collect();

    // Apply collection filter if provided
    if let Some(ref collection_name) = query.collection {
        let collections = state
            .bw
            .client
            .list_collections()
            .await
            .map_err(|e| AppError::ServiceUnavailable(format!("bw serve error: {}", e)))?;

        let collection = collections
            .iter()
            .find(|c| c.name == *collection_name)
            .ok_or_else(|| AppError::NotFound(format!("collection '{}'", collection_name)))?;

        matches.retain(|item| {
            item.collection_ids
                .as_deref()
                .unwrap_or_default()
                .contains(&collection.id)
        });
    }

    // Apply folder filter if provided
    if let Some(ref folder_name) = query.folder {
        let folders = state
            .bw
            .client
            .list_folders()
            .await
            .map_err(|e| AppError::ServiceUnavailable(format!("bw serve error: {}", e)))?;

        let folder = folders
            .iter()
            .find(|f| f.name == *folder_name)
            .ok_or_else(|| AppError::NotFound(format!("folder '{}'", folder_name)))?;

        matches.retain(|item| item.folder_id.as_deref() == Some(&folder.id));
    }

    // Handle ambiguity
    if matches.len() > 1 {
        let collections = state
            .bw
            .client
            .list_collections()
            .await
            .map_err(|e| AppError::ServiceUnavailable(format!("bw serve error: {}", e)))?;

        let folders = state
            .bw
            .client
            .list_folders()
            .await
            .map_err(|e| AppError::ServiceUnavailable(format!("bw serve error: {}", e)))?;

        let match_details: Vec<Value> = matches
            .iter()
            .map(|item| {
                let col_names: Vec<&str> = item
                    .collection_ids
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|cid| {
                        collections
                            .iter()
                            .find(|c| &c.id == cid)
                            .map(|c| c.name.as_str())
                    })
                    .collect();

                let folder_name = item
                    .folder_id
                    .as_ref()
                    .and_then(|fid| folders.iter().find(|f| f.id == *fid))
                    .map(|f| f.name.as_str());

                json!({
                    "collection_names": col_names,
                    "folder_name": folder_name,
                })
            })
            .collect();

        return Err(AppError::Ambiguous(json!({
            "error": "ambiguous",
            "message": format!("Found {} items named '{}'", matches.len(), key),
            "matches": match_details,
        })));
    }

    let item = match matches.first() {
        Some(i) => *i,
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
