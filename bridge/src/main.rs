use std::net::SocketAddr;
use tokio::net::TcpListener;
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

    let app = vaultwarden_bridge::app(pool, config).await?;

    // Strip trailing slashes before routing (e.g. /ui/ -> /ui)
    let app = app.layer(vaultwarden_bridge::NormalizePathLayer::trim_trailing_slash());

    let addr = SocketAddr::from(([0, 0, 0, 0], listen_port));
    tracing::info!(%addr, "listening");
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service()).await?;

    Ok(())
}
