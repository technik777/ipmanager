use anyhow::{Context, Result};
use reqwest::StatusCode;
use serde::Serialize;
use sqlx::PgPool;

use crate::config::Config;
use crate::domain::mac::MacAddr;
use crate::notifications::email;

#[derive(Serialize)]
struct MacmonEndpointRequest<'a> {
    mac: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<&'a str>,
}

pub async fn sync_new_hosts(pool: &PgPool, cfg: &Config) -> Result<usize> {
    let Some(base_url) = cfg.macmon_base_url.as_deref() else {
        tracing::info!("macmon config missing; skipping macmon sync");
        return Ok(0);
    };
    let Some(username) = cfg.macmon_username.as_deref() else {
        tracing::warn!("macmon username missing; skipping macmon sync");
        return Ok(0);
    };
    let Some(password) = cfg.macmon_password.as_deref() else {
        tracing::warn!("macmon password missing; skipping macmon sync");
        return Ok(0);
    };

    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "select mac_address, hostname
         from hosts h
         where not exists (
            select 1 from macmon_exports m where m.mac_address = h.mac_address
         )
         order by hostname asc",
    )
    .fetch_all(pool)
    .await
    .context("failed to load new hosts for macmon")?;

    if rows.is_empty() {
        return Ok(0);
    }

    let skip_ssl = reqwest::Url::parse(base_url)
        .ok()
        .and_then(|url| url.host_str().map(|host| host == "10.112.57.2"))
        .unwrap_or(false);
    let mut client_builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(10));
    if skip_ssl {
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }
    let client = client_builder
        .build()
        .context("failed to build macmon http client")?;

    let endpoint_url = format!("{}/api/v1.2/endpoints", base_url.trim_end_matches('/'));
    let mut sent = 0usize;

    for (mac_raw, hostname) in rows {
        let mac = match mac_raw.parse::<MacAddr>() {
            Ok(m) => m.to_string(),
            Err(_) => {
                tracing::warn!(mac = %mac_raw, "invalid mac format; skipping macmon sync");
                continue;
            }
        };
        let payload = MacmonEndpointRequest {
            mac: &mac,
            comment: hostname.as_deref(),
        };

        let resp = client
            .post(&endpoint_url)
            .basic_auth(username, Some(password))
            .json(&payload)
            .send()
            .await;

        match resp {
            Ok(r) if r.status().is_success() => {
                tracing::info!(url = %endpoint_url, status = %r.status(), "macmon request ok");
                if let Err(e) = mark_exported(pool, &mac_raw).await {
                    tracing::error!(error = ?e, mac = %mac_raw, "failed to mark macmon export");
                }
                sent += 1;
            }
            Ok(r) if r.status() == StatusCode::CONFLICT => {
                tracing::debug!(url = %endpoint_url, status = %r.status(), "macmon request conflict");
                tracing::debug!(mac = %mac_raw, "macmon endpoint already exists; marking exported");
                if let Err(e) = mark_exported(pool, &mac_raw).await {
                    tracing::error!(error = ?e, mac = %mac_raw, "failed to mark macmon export");
                }
            }
            Ok(r) => {
                let status = r.status();
                let body = r.text().await.unwrap_or_default();
                tracing::debug!(
                    mac = %mac_raw,
                    url = %endpoint_url,
                    status = %status,
                    body = %body,
                    "macmon create endpoint failed"
                );
                if status.is_client_error() || status.is_server_error() {
                    let cfg = cfg.clone();
                    let message = format!(
                        "macmon API returned {status} for {mac}.\nURL: {url}\nBody: {body}",
                        status = status,
                        mac = mac_raw,
                        url = endpoint_url,
                        body = body
                    );
                    tokio::spawn(async move {
                        if let Err(e) = email::send_admin_alert(
                            &cfg,
                            "ipmanager: macmon API Fehler",
                            &message,
                        )
                        .await
                        {
                            tracing::error!(error = ?e, "failed to send macmon email alert");
                        }
                    });
                }
            }
            Err(e) => {
                tracing::error!(error = ?e, mac = %mac_raw, "macmon request failed");
            }
        }
    }

    Ok(sent)
}

async fn mark_exported(pool: &PgPool, mac: &str) -> Result<()> {
    sqlx::query(
        "insert into macmon_exports (mac_address) values ($1)
         on conflict (mac_address) do nothing",
    )
    .bind(mac)
    .execute(pool)
    .await
    .context("failed to record macmon export")?;
    Ok(())
}
