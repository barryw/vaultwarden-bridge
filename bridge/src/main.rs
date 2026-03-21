use axum::ServiceExt;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::normalize_path::NormalizePathLayer;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    tracing::info!("starting vaultwarden-bridge");

    let config = vaultwarden_bridge::config::Config::from_env()?;
    let listen_port = config.listen_port;
    let pool = sqlx::PgPool::connect(&config.database_url).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;

    let router = vaultwarden_bridge::app(pool, config).await?;

    // NormalizePathLayer MUST wrap the router as a tower Service (not via .layer())
    // so it modifies the request URI BEFORE Axum routing occurs.
    let app = ServiceBuilder::new()
        .layer(NormalizePathLayer::trim_trailing_slash())
        .service(router);

    let addr = SocketAddr::from(([0, 0, 0, 0], listen_port));
    tracing::info!(%addr, "listening");
    let listener = TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        ServiceExt::<axum::extract::Request>::into_make_service_with_connect_info::<SocketAddr>(
            app,
        ),
    )
    .await?;

    Ok(())
}
