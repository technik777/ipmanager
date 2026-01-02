use std::{
    fs,
    io::Write,
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
};

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use ipnet::IpNet;
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::config::Config;

#[derive(Debug, Clone)]
pub struct DeployOutcome {
    pub written_to: String,
    pub reload_attempted: bool,
    pub reload_ok: Option<bool>,
    pub reload_message: Option<String>,
}

#[derive(Debug, Serialize)]
struct KeaRoot {
    #[serde(rename = "Dhcp4")]
    dhcp4: Dhcp4,
}

#[derive(Debug, Serialize)]
struct Dhcp4 {
    #[serde(rename = "valid-lifetime")]
    valid_lifetime: u32,
    #[serde(rename = "renew-timer")]
    renew_timer: u32,
    #[serde(rename = "rebind-timer")]
    rebind_timer: u32,

    #[serde(rename = "interfaces-config")]
    interfaces_config: InterfacesConfig,

    #[serde(rename = "lease-database")]
    lease_database: LeaseDatabase,

    #[serde(rename = "subnet4")]
    subnet4: Vec<Subnet4>,

    #[serde(rename = "user-context")]
    user_context: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct InterfacesConfig {
    interfaces: Vec<String>,
}

#[derive(Debug, Serialize)]
struct LeaseDatabase {
    #[serde(rename = "type")]
    typ: String,
    persist: bool,
    name: String,
}

#[derive(Debug, Serialize)]
struct Subnet4 {
    id: u32,
    subnet: String,
    pools: Vec<Pool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    reservations: Vec<Reservation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "user-context")]
    user_context: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct Pool {
    pool: String,
}

#[derive(Debug, Serialize)]
struct Reservation {
    #[serde(rename = "hw-address")]
    hw_address: String,
    #[serde(rename = "ip-address")]
    ip_address: String,
    hostname: String,
}

pub async fn render_dhcp4_config(pool: &PgPool) -> Result<String> {
    // IMPORTANT:
    // Postgres inet::text renders with a /32 (e.g. 192.168.174.50/32).
    // We want plain host addresses for Kea pools, so use host(inet).
    let subnets: Vec<(Uuid, String, Option<String>, Option<String>)> = sqlx::query_as(
        "select id,
                cidr::text,
                host(dhcp_pool_start),
                host(dhcp_pool_end)
         from subnets
         where dhcp_enabled = true
         order by name asc",
    )
    .fetch_all(pool)
    .await
    .context("failed to load dhcp-enabled subnets")?;

    let mut subnet_blocks: Vec<Subnet4> = Vec::new();
    let mut subnet_id_counter: u32 = 1;

    for (subnet_uuid, cidr, dhcp_pool_start, dhcp_pool_end) in subnets {
        let net: IpNet = cidr
            .parse()
            .with_context(|| format!("invalid subnet CIDR in DB: {cidr}"))?;

        let ipv4 = match net {
            IpNet::V4(v4) => v4,
            IpNet::V6(_) => {
                tracing::warn!(cidr = %cidr, "skipping ipv6 subnet for dhcp4 config");
                continue;
            }
        };

        let pool_range = ipv4_pool_for_subnet(&ipv4, &cidr, dhcp_pool_start, dhcp_pool_end)
            .with_context(|| format!("unable to determine pool for subnet {cidr}"))?;

        let hosts: Vec<(String, String, String)> = sqlx::query_as(
            "select mac, ip::text, hostname
             from hosts
             where subnet_id = $1
             order by hostname asc",
        )
        .bind(subnet_uuid)
        .fetch_all(pool)
        .await
        .with_context(|| format!("failed to load hosts for subnet {cidr}"))?;

        let reservations = hosts
            .into_iter()
            .map(|(mac, ip, hostname)| Reservation {
                hw_address: mac,
                ip_address: ip,
                hostname,
            })
            .collect::<Vec<_>>();

        subnet_blocks.push(Subnet4 {
            id: subnet_id_counter,
            subnet: cidr,
            pools: vec![Pool { pool: pool_range }],
            reservations,
            user_context: Some(serde_json::json!({
                "ipmanager": {
                    "subnet_uuid": subnet_uuid.to_string()
                }
            })),
        });

        subnet_id_counter += 1;
    }

    let root = KeaRoot {
        dhcp4: Dhcp4 {
            valid_lifetime: 3600,
            renew_timer: 900,
            rebind_timer: 1800,
            interfaces_config: InterfacesConfig {
                interfaces: vec!["*".to_string()],
            },
            lease_database: LeaseDatabase {
                typ: "memfile".to_string(),
                persist: true,
                name: "/var/lib/kea/dhcp4.leases".to_string(),
            },
            subnet4: subnet_blocks,
            user_context: serde_json::json!({
                "generated-by": "ipmanager",
                "generated-at": Utc::now().to_rfc3339(),
            }),
        },
    };

    Ok(serde_json::to_string_pretty(&root).context("failed to serialize kea config")?)
}

/// Determine the Kea pool range for a subnet:
/// - If dhcp_pool_start/end are NULL: use default (first usable .. last usable).
/// - If set: validate IPv4, within usable subnet bounds, start <= end.
/// Any invalid range yields an error with context (no silent fallback).
fn ipv4_pool_for_subnet(
    net: &ipnet::Ipv4Net,
    cidr: &str,
    start: Option<String>,
    end: Option<String>,
) -> Result<String> {
    match (start, end) {
        (None, None) => default_ipv4_pool(net)
            .with_context(|| format!("default pool computation failed for {cidr}")),
        (Some(start), Some(end)) => {
            let (first_usable, last_usable) = ipv4_usable_bounds(net)
                .with_context(|| format!("subnet {cidr} is too small for a usable pool"))?;

            let start_ip = parse_ipv4_strict(&start).with_context(|| {
                format!("subnet {cidr}: invalid dhcp_pool_start '{start}' (must be IPv4)")
            })?;
            let end_ip = parse_ipv4_strict(&end).with_context(|| {
                format!("subnet {cidr}: invalid dhcp_pool_end '{end}' (must be IPv4)")
            })?;

            if !net.contains(&start_ip) {
                return Err(anyhow!(
                    "subnet {cidr}: dhcp_pool_start {start_ip} is not inside subnet"
                ));
            }
            if !net.contains(&end_ip) {
                return Err(anyhow!(
                    "subnet {cidr}: dhcp_pool_end {end_ip} is not inside subnet"
                ));
            }

            if u32::from(start_ip) < u32::from(first_usable) || u32::from(start_ip) > u32::from(last_usable) {
                return Err(anyhow!(
                    "subnet {cidr}: dhcp_pool_start {start_ip} is outside usable range {first_usable} - {last_usable}"
                ));
            }
            if u32::from(end_ip) < u32::from(first_usable) || u32::from(end_ip) > u32::from(last_usable) {
                return Err(anyhow!(
                    "subnet {cidr}: dhcp_pool_end {end_ip} is outside usable range {first_usable} - {last_usable}"
                ));
            }

            if u32::from(start_ip) > u32::from(end_ip) {
                return Err(anyhow!(
                    "subnet {cidr}: invalid dhcp pool range: start {start_ip} > end {end_ip}"
                ));
            }

            Ok(format!("{start_ip} - {end_ip}"))
        }
        (start, end) => Err(anyhow!(
            "subnet {cidr}: invalid dhcp pool configuration: start={start:?}, end={end:?} (must both be set or both NULL)"
        )),
    }
}

fn parse_ipv4_strict(s: &str) -> Result<Ipv4Addr> {
    // Be tolerant to accidentally masked strings like "192.0.2.10/32"
    let s = s.split('/').next().unwrap_or(s);

    let ip: IpAddr = s
        .parse()
        .with_context(|| format!("failed to parse IP address: {s}"))?;
    match ip {
        IpAddr::V4(v4) => Ok(v4),
        IpAddr::V6(_) => Err(anyhow!("IPv6 address is not allowed here: {s}")),
    }
}

fn ipv4_usable_bounds(net: &ipnet::Ipv4Net) -> Result<(Ipv4Addr, Ipv4Addr)> {
    let network = net.network();
    let broadcast = net.broadcast();

    let first = inc_ipv4(network).ok_or_else(|| anyhow!("cannot compute first usable address"))?;
    let last = dec_ipv4(broadcast).ok_or_else(|| anyhow!("cannot compute last usable address"))?;

    if u32::from(first) > u32::from(last) {
        return Err(anyhow!("subnet too small for usable pool"));
    }

    Ok((first, last))
}

pub async fn deploy(pool: &PgPool, cfg: &Config) -> Result<DeployOutcome> {
    let json = render_dhcp4_config(pool).await?;

    write_atomic(&cfg.kea_config_path, json.as_bytes()).context("failed to write kea config")?;

    let mode = cfg.kea_reload_mode.trim().to_lowercase();
    if mode == "api" {
        let Some(url) = cfg.kea_control_agent_url.clone() else {
            return Err(anyhow!(
                "KEA_RELOAD_MODE=api but KEA_CONTROL_AGENT_URL is not set"
            ));
        };

        let (ok, msg) = reload_via_api(url.as_str(), cfg.kea_api_timeout).await;
        return Ok(DeployOutcome {
            written_to: cfg.kea_config_path.clone(),
            reload_attempted: true,
            reload_ok: Some(ok),
            reload_message: Some(msg),
        });
    }

    Ok(DeployOutcome {
        written_to: cfg.kea_config_path.clone(),
        reload_attempted: false,
        reload_ok: None,
        reload_message: None,
    })
}

fn default_ipv4_pool(net: &ipnet::Ipv4Net) -> Result<String> {
    let (first, last) = ipv4_usable_bounds(net)?;
    Ok(format!("{first} - {last}"))
}

fn inc_ipv4(ip: Ipv4Addr) -> Option<Ipv4Addr> {
    let v = u32::from(ip);
    v.checked_add(1).map(Ipv4Addr::from)
}

fn dec_ipv4(ip: Ipv4Addr) -> Option<Ipv4Addr> {
    let v = u32::from(ip);
    v.checked_sub(1).map(Ipv4Addr::from)
}

fn write_atomic(path: &str, data: &[u8]) -> Result<()> {
    let target = PathBuf::from(path);
    let dir = target
        .parent()
        .ok_or_else(|| anyhow!("config path has no parent dir: {path}"))?;
    let base = target
        .file_name()
        .ok_or_else(|| anyhow!("config path has no filename: {path}"))?
        .to_string_lossy()
        .to_string();

    fs::create_dir_all(dir).with_context(|| format!("failed to create dir {}", dir.display()))?;

    let tmp = dir.join(format!(
        ".{}.tmp.{}",
        base,
        Utc::now().timestamp_nanos_opt().unwrap_or(0)
    ));

    let mut f =
        fs::File::create(&tmp).with_context(|| format!("failed to create {}", tmp.display()))?;
    f.write_all(data).context("failed to write tmp")?;
    f.sync_all().ok();
    drop(f);

    fs::rename(&tmp, &target).with_context(|| {
        format!(
            "failed to rename tmp {} -> {}",
            tmp.display(),
            target.display()
        )
    })?;

    Ok(())
}

async fn reload_via_api(url: &str, timeout: std::time::Duration) -> (bool, String) {
    let body = serde_json::json!({
        "command": "config-reload",
        "service": ["dhcp4"]
    });

    let client = match reqwest::Client::builder().timeout(timeout).build() {
        Ok(c) => c,
        Err(e) => return (false, format!("reqwest client build failed: {e}")),
    };

    let resp = match client.post(url).json(&body).send().await {
        Ok(r) => r,
        Err(e) => return (false, format!("request failed: {e}")),
    };

    let status = resp.status();
    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => format!("(failed to read response body: {e})"),
    };

    if !status.is_success() {
        return (false, format!("HTTP {status}: {text}"));
    }

    (true, text)
}
