use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::process::{Child, Command};
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct BwClient {
    base_url: String,
    http: reqwest::Client,
}

#[derive(Debug, Deserialize)]
pub struct BwItem {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub item_type: i32,
    pub login: Option<BwLogin>,
    pub card: Option<BwCard>,
    pub identity: Option<BwIdentity>,
    pub fields: Option<Vec<BwField>>,
    pub notes: Option<String>,
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
    #[serde(rename = "folderId")]
    pub folder_id: Option<String>,
    #[serde(rename = "collectionIds")]
    pub collection_ids: Option<Vec<String>>,
    #[serde(rename = "revisionDate")]
    pub revision_date: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BwOrganization {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct BwCollection {
    pub id: String,
    pub name: String,
    #[serde(rename = "organizationId")]
    pub organization_id: String,
}

#[derive(Debug, Deserialize)]
pub struct BwFolder {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
struct BwOrgListResponse {
    #[allow(dead_code)]
    success: bool,
    data: Option<BwOrgListData>,
}

#[derive(Debug, Deserialize)]
struct BwOrgListData {
    data: Vec<BwOrganization>,
}

#[derive(Debug, Deserialize)]
struct BwCollectionListResponse {
    #[allow(dead_code)]
    success: bool,
    data: Option<BwCollectionListData>,
}

#[derive(Debug, Deserialize)]
struct BwCollectionListData {
    data: Vec<BwCollection>,
}

#[derive(Debug, Deserialize)]
struct BwFolderListResponse {
    #[allow(dead_code)]
    success: bool,
    data: Option<BwFolderListData>,
}

#[derive(Debug, Deserialize)]
struct BwFolderListData {
    data: Vec<BwFolder>,
}

/// Maps item_type integers to API type strings.
impl BwItem {
    pub fn type_name(&self) -> &'static str {
        match self.item_type {
            1 => "login",
            2 => "note",
            3 => "card",
            4 => "identity",
            _ => "unknown",
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct BwLogin {
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
    pub uris: Option<Vec<BwLoginUri>>,
}

#[derive(Debug, Deserialize)]
pub struct BwLoginUri {
    pub uri: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BwCard {
    #[serde(rename = "cardholderName")]
    pub cardholder_name: Option<String>,
    pub brand: Option<String>,
    pub number: Option<String>,
    #[serde(rename = "expMonth")]
    pub exp_month: Option<String>,
    #[serde(rename = "expYear")]
    pub exp_year: Option<String>,
    pub code: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BwIdentity {
    pub title: Option<String>,
    #[serde(rename = "firstName")]
    pub first_name: Option<String>,
    #[serde(rename = "middleName")]
    pub middle_name: Option<String>,
    #[serde(rename = "lastName")]
    pub last_name: Option<String>,
    pub address1: Option<String>,
    pub address2: Option<String>,
    pub address3: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    #[serde(rename = "postalCode")]
    pub postal_code: Option<String>,
    pub country: Option<String>,
    pub company: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub ssn: Option<String>,
    pub username: Option<String>,
    #[serde(rename = "passportNumber")]
    pub passport_number: Option<String>,
    #[serde(rename = "licenseNumber")]
    pub license_number: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BwField {
    pub name: Option<String>,
    pub value: Option<String>,
    #[serde(rename = "type")]
    pub field_type: i32,
}

impl BwField {
    pub fn type_name(&self) -> &'static str {
        match self.field_type {
            0 => "text",
            1 => "hidden",
            2 => "boolean",
            3 => "linked",
            _ => "unknown",
        }
    }
}

#[derive(Debug, Deserialize)]
struct BwListResponse {
    #[allow(dead_code)]
    success: bool,
    data: Option<BwListData>,
}

#[derive(Debug, Deserialize)]
struct BwListData {
    data: Vec<BwItem>,
}

#[derive(Debug, Deserialize)]
struct BwItemResponse {
    #[allow(dead_code)]
    success: bool,
    data: Option<BwItem>,
}

impl BwClient {
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            base_url: format!("http://{}:{}", host, port),
            http: reqwest::Client::new(),
        }
    }

    pub async fn health(&self) -> bool {
        self.http
            .get(format!("{}/sync", self.base_url))
            .send()
            .await
            .is_ok()
    }

    pub async fn list_items(&self, search: Option<&str>) -> anyhow::Result<Vec<BwItem>> {
        let mut url = format!("{}/list/object/items", self.base_url);
        if let Some(q) = search {
            url = format!("{}?search={}", url, urlencoding::encode(q));
        }
        let resp: BwListResponse = self.http.get(&url).send().await?.json().await?;
        Ok(resp.data.map(|d| d.data).unwrap_or_default())
    }

    pub async fn get_item(&self, id: &str) -> anyhow::Result<Option<BwItem>> {
        let url = format!("{}/object/item/{}", self.base_url, id);
        let resp = self.http.get(&url).send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let body: BwItemResponse = resp.json().await?;
        Ok(body.data)
    }

    pub async fn list_organizations(&self) -> anyhow::Result<Vec<BwOrganization>> {
        let url = format!("{}/list/object/organizations", self.base_url);
        let resp: BwOrgListResponse = self.http.get(&url).send().await?.json().await?;
        Ok(resp.data.map(|d| d.data).unwrap_or_default())
    }

    pub async fn list_collections(&self) -> anyhow::Result<Vec<BwCollection>> {
        let url = format!("{}/list/object/collections", self.base_url);
        let resp: BwCollectionListResponse = self.http.get(&url).send().await?.json().await?;
        Ok(resp.data.map(|d| d.data).unwrap_or_default())
    }

    pub async fn list_folders(&self) -> anyhow::Result<Vec<BwFolder>> {
        let url = format!("{}/list/object/folders", self.base_url);
        let resp: BwFolderListResponse = self.http.get(&url).send().await?.json().await?;
        Ok(resp.data.map(|d| d.data).unwrap_or_default())
    }

    pub async fn sync(&self) -> anyhow::Result<()> {
        self.http
            .post(format!("{}/sync", self.base_url))
            .send()
            .await?;
        Ok(())
    }
}

pub struct BwManager {
    pub client: BwClient,
    child: Arc<RwLock<Option<Child>>>,
    server_url: String,
    email: String,
    password: String,
    port: u16,
    external: bool,
}

impl BwManager {
    pub fn new(
        server_url: String,
        email: String,
        password: String,
        bw_serve_host: String,
        port: u16,
        external: bool,
    ) -> Self {
        Self {
            client: BwClient::new(&bw_serve_host, port),
            child: Arc::new(RwLock::new(None)),
            server_url,
            email,
            password,
            port,
            external,
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        if self.external {
            return self.wait_for_external().await;
        }
        self.start_managed().await
    }

    /// Wait for an externally managed bw serve (e.g. k8s sidecar).
    async fn wait_for_external(&self) -> anyhow::Result<()> {
        tracing::info!(port = self.port, "waiting for external bw serve");
        for _ in 0..60 {
            if self.client.health().await {
                tracing::info!("external bw serve is healthy");
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        anyhow::bail!("external bw serve not healthy within 60s")
    }

    /// Start and manage bw serve as a subprocess.
    async fn start_managed(&self) -> anyhow::Result<()> {
        Command::new("bw")
            .args(["config", "server", &self.server_url])
            .output()
            .await?;

        let login_output = Command::new("bw")
            .args([
                "login",
                &self.email,
                "--passwordenv",
                "BW_PASSWORD",
                "--raw",
            ])
            .env("BW_PASSWORD", &self.password)
            .env("BW_NOINTERACTION", "true")
            .output()
            .await?;

        if !login_output.status.success() {
            tracing::info!("login failed, attempting unlock");
        }

        let unlock_output = Command::new("bw")
            .args(["unlock", "--passwordenv", "BW_PASSWORD", "--raw"])
            .env("BW_PASSWORD", &self.password)
            .env("BW_NOINTERACTION", "true")
            .output()
            .await?;

        let session = String::from_utf8(unlock_output.stdout)?.trim().to_string();
        if session.is_empty() {
            anyhow::bail!("failed to unlock vault — empty session key");
        }

        let child = Command::new("bw")
            .args([
                "serve",
                "--hostname",
                "127.0.0.1",
                "--port",
                &self.port.to_string(),
            ])
            .env("BW_SESSION", &session)
            .env("BW_NOINTERACTION", "true")
            .spawn()?;

        *self.child.write().await = Some(child);

        for _ in 0..30 {
            if self.client.health().await {
                tracing::info!("bw serve is healthy");
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }

        anyhow::bail!("bw serve failed to become healthy within 30s")
    }

    pub async fn is_healthy(&self) -> bool {
        self.client.health().await
    }

    pub async fn stop(&self) {
        if let Some(mut child) = self.child.write().await.take() {
            let _ = child.kill().await;
        }
    }
}
