mod config;
mod db;
pub mod dhcp;
mod domain;
mod importer;
mod integrations;
mod models;
mod notifications;
mod pxe;
mod web;

use anyhow::{Context, Result};
use std::{net::SocketAddr, sync::Arc};
use tera::Tera;
use tokio::sync::{oneshot, Mutex};
use tower_sessions::{cookie::Key, SessionManagerLayer};
use tower_sessions_sqlx_store::PostgresStore;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().init();

    let cfg = config::Config::from_env()?;

    let pool = db::connect(&cfg).await?;
    db::ensure_initial_admin(&cfg, &pool).await?;

    let dnsmasq_status = Arc::new(Mutex::new(dhcp::dnsmasq::DnsmasqStatus::default()));

    if let Err(e) =
        dhcp::dnsmasq::sync_dnsmasq_hosts(&pool, &cfg, dnsmasq_status.as_ref(), None).await
    {
        tracing::error!(error = ?e, "Initialer dnsmasq Sync fehlgeschlagen");
        dhcp::dnsmasq::record_sync_error(
            dnsmasq_status.as_ref(),
            format!("Initialer dnsmasq Sync fehlgeschlagen: {e:#}"),
        )
        .await;
    }

    let templates = Tera::new("templates/**/*").context("failed to load templates")?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let state = web::AppState {
        pool: pool.clone(),
        templates: Arc::new(templates),
        config: cfg.clone(),
        dnsmasq_status,
        shutdown_tx: Arc::new(Mutex::new(Some(shutdown_tx))),
    };

    let session_store = PostgresStore::new(pool.clone());
    session_store
        .migrate()
        .await
        .context("failed to migrate session store")?;
    let session_key = Key::from(cfg.session_secret.as_bytes());
    let session_layer = SessionManagerLayer::new(session_store)
        .with_name(cfg.session_cookie_name.clone())
        .with_secure(cfg.session_cookie_secure)
        .with_signed(session_key);

    let app = web::router(state).layer(session_layer);
    let bind_addr = if cfg.bind_addr.trim() == "127.0.0.1:3000" {
        "0.0.0.0:3000".to_string()
    } else {
        cfg.bind_addr.clone()
    };
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .context("failed to bind server address")?;
    tracing::info!(addr = %bind_addr, "listening");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        let _ = shutdown_rx.await;
        tracing::info!("shutdown signal received");
    })
    .await
    .context("server error")?;

    Ok(())
}
