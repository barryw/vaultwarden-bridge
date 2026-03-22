use std::net::SocketAddr;

use axum::{
    Json,
    extract::{ConnectInfo, Query, State},
    http::HeaderMap,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::AppError;
use crate::state::AppState;

use super::secrets::authenticate;

#[derive(Debug, Deserialize)]
pub struct ItemsQuery {
    pub collection: Option<String>,
    pub folder: Option<String>,
}

pub async fn list_organizations(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    authenticate(&state, &headers, &addr).await?;

    let orgs = state
        .bw
        .client
        .list_organizations()
        .await
        .map_err(|e| AppError::ServiceUnavailable(format!("bw serve error: {}", e)))?;

    let result: Vec<Value> = orgs
        .iter()
        .map(|o| {
            json!({
                "id": o.id,
                "name": o.name,
            })
        })
        .collect();

    Ok(Json(json!(result)))
}

pub async fn list_collections(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    authenticate(&state, &headers, &addr).await?;

    let collections = state
        .bw
        .client
        .list_collections()
        .await
        .map_err(|e| AppError::ServiceUnavailable(format!("bw serve error: {}", e)))?;

    let orgs = state
        .bw
        .client
        .list_organizations()
        .await
        .map_err(|e| AppError::ServiceUnavailable(format!("bw serve error: {}", e)))?;

    let result: Vec<Value> = collections
        .iter()
        .map(|c| {
            let org_name = orgs
                .iter()
                .find(|o| o.id == c.organization_id)
                .map(|o| o.name.as_str())
                .unwrap_or("unknown");
            json!({
                "id": c.id,
                "name": c.name,
                "organization_name": org_name,
            })
        })
        .collect();

    Ok(Json(json!(result)))
}

pub async fn list_folders(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    authenticate(&state, &headers, &addr).await?;

    let folders = state
        .bw
        .client
        .list_folders()
        .await
        .map_err(|e| AppError::ServiceUnavailable(format!("bw serve error: {}", e)))?;

    let result: Vec<Value> = folders
        .iter()
        .map(|f| {
            json!({
                "id": f.id,
                "name": f.name,
            })
        })
        .collect();

    Ok(Json(json!(result)))
}

pub async fn list_items(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<ItemsQuery>,
) -> Result<Json<Value>, AppError> {
    authenticate(&state, &headers, &addr).await?;

    let items = state
        .bw
        .client
        .list_items(None)
        .await
        .map_err(|e| AppError::ServiceUnavailable(format!("bw serve error: {}", e)))?;

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

    // Resolve collection filter name to ID
    let collection_id_filter = if let Some(ref name) = query.collection {
        let col = collections.iter().find(|c| c.name == *name);
        match col {
            Some(c) => Some(c.id.clone()),
            None => return Err(AppError::NotFound(format!("collection '{}'", name))),
        }
    } else {
        None
    };

    // Resolve folder filter name to ID
    let folder_id_filter = if let Some(ref name) = query.folder {
        let fld = folders.iter().find(|f| f.name == *name);
        match fld {
            Some(f) => Some(f.id.clone()),
            None => return Err(AppError::NotFound(format!("folder '{}'", name))),
        }
    } else {
        None
    };

    let result: Vec<Value> = items
        .iter()
        .filter(|item| {
            if let Some(ref cid) = collection_id_filter {
                let ids = item.collection_ids.as_deref().unwrap_or_default();
                if !ids.contains(cid) {
                    return false;
                }
            }
            if let Some(ref fid) = folder_id_filter
                && item.folder_id.as_deref() != Some(fid.as_str())
            {
                return false;
            }
            true
        })
        .map(|item| {
            let collection_names: Vec<&str> = item
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
                "name": item.name,
                "type": item.type_name(),
                "collection_names": collection_names,
                "folder_name": folder_name,
            })
        })
        .collect();

    Ok(Json(json!(result)))
}
