use serde::Deserialize;
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
    pub notes: Option<String>,
    #[serde(rename = "collectionIds")]
    pub collection_ids: Option<Vec<String>>,
    #[serde(rename = "revisionDate")]
    pub revision_date: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BwLogin {
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
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
    pub fn new(port: u16) -> Self {
        Self {
            base_url: format!("http://127.0.0.1:{}", port),
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
        port: u16,
        external: bool,
    ) -> Self {
        Self {
            client: BwClient::new(port),
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
            .args(["login", &self.email, &self.password, "--raw"])
            .env("BW_NOINTERACTION", "true")
            .output()
            .await?;

        if !login_output.status.success() {
            tracing::info!("login failed, attempting unlock");
        }

        let unlock_output = Command::new("bw")
            .args(["unlock", &self.password, "--raw"])
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
