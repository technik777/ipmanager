mod config;
mod db;
mod dhcp_kea;
mod domain;
mod web;

use anyhow::Result;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cfg = config::Config::from_env()?;
    tracing::info!(
        bind_addr = %cfg.bind_addr,
        base_url = %cfg.base_url,
        db_max_connections = cfg.db_max_connections,
        db_min_connections = cfg.db_min_connections,
        "config loaded"
    );

    let pool = db::connect(&cfg).await?;
    tracing::info!("database connected");

    db::ensure_initial_admin(&cfg, &pool).await?;

    // Sessions store init (wie bisher)
    let store = tower_sessions_sqlx_store::PostgresStore::new(pool.clone());
    store.migrate().await?;

    let session_layer = tower_sessions::SessionManagerLayer::new(store)
        .with_secure(cfg.session_cookie_secure)
        .with_name(cfg.session_cookie_name.clone())
        .with_expiry(tower_sessions::Expiry::OnInactivity(
            time::Duration::seconds(cfg.session_ttl.as_secs() as i64),
        ));

    // Templates
    let tera = tera::Tera::new("templates/**/*")?;

    let state = web::AppState {
        pool,
        templates: std::sync::Arc::new(tera),
    };

    let app = web::router(state).layer(session_layer);

    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr).await?;
    tracing::info!(addr = %cfg.bind_addr, "listening");
    axum::serve(listener, app).await?;

    Ok(())
}
