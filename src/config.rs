use std::time::Duration;

use anyhow::{Context, Result};
use url::Url;

#[derive(Clone, Debug)]
pub struct Config {
    // DB
    pub database_url: String,
    pub db_max_connections: u32,
    pub db_min_connections: u32,

    // Web
    pub bind_addr: String,
    pub base_url: Url,

    // Initial admin
    pub initial_admin_user: String,
    pub initial_admin_password: String,

    // Sessions
    pub session_secret: String,
    pub session_cookie_name: String,
    pub session_cookie_secure: bool,
    pub session_ttl: Duration,

    // PXE/iPXE
    pub pxe_enabled: bool,
    pub pxe_root_dir: String,
    pub tftp_root_dir: String,
    pub pxe_assets_dir: String,
    pub pxe_configs_dir: String,
    pub pxe_http_base_url: Url,
    pub pxe_tftp_server: String,
    pub pxe_bios_bootfile: String,
    pub pxe_uefi_bootfile: String,

    // SMTP
    pub smtp_host: Option<String>,
    pub smtp_port: Option<u16>,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,
    pub smtp_from: Option<String>,
    pub smtp_to: Vec<String>,
    pub smtp_use_starttls: bool,
    pub admin_email: Option<String>,

    // Macmon
    pub macmon_enabled: bool,
    pub macmon_base_url: Option<String>,
    pub macmon_username: Option<String>,
    pub macmon_password: Option<String>,

    // dnsmasq
    pub dnsmasq_hosts_file: String,
    pub dnsmasq_conf_dir: String,
    pub dnsmasq_reload_cmd: String,
    pub dnsmasq_interface: Option<String>,
    pub dnsmasq_bind_addr: String,
    pub dnsmasq_port: u16,
    pub domain_name: String,
    pub ipmanager_ip: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();

        let database_url = env("DATABASE_URL")?;
        let db_max_connections = env_u32("DB_MAX_CONNECTIONS").unwrap_or(10);
        let db_min_connections = env_u32("DB_MIN_CONNECTIONS").unwrap_or(1);

        let bind_addr = env_default("BIND_ADDR", "127.0.0.1:3000");
        let base_url = Url::parse(&env_default("BASE_URL", "http://127.0.0.1:3000"))
            .context("BASE_URL must be a valid URL")?;

        let initial_admin_user = env_default("INITIAL_ADMIN_USER", "admin");
        let initial_admin_password = env_default("INITIAL_ADMIN_PASSWORD", "admin123");

        let session_secret = env("SESSION_SECRET")?;
        let session_cookie_name = env_default("SESSION_COOKIE_NAME", "ipmanager_session");
        let session_cookie_secure = env_bool("SESSION_COOKIE_SECURE").unwrap_or(false);
        let session_ttl =
            env_duration_secs("SESSION_TTL_SECS").unwrap_or(Duration::from_secs(60 * 60 * 24));

        let pxe_enabled = env_bool("PXE_ENABLED").unwrap_or(false);
        let pxe_root_dir = env_default("PXE_ROOT_DIR", "/var/lib/ipmanager/pxe");
        let tftp_root_dir = env_optional("TFTP_ROOT")
            .or_else(|| env_optional("TFTP_ROOT_DIR"))
            .unwrap_or_else(|| "/var/lib/tftpboot".to_string());
        let pxe_assets_dir = env_optional("PXE_ASSETS_DIR").unwrap_or_else(|| {
            format!("{}/pxe-assets", tftp_root_dir.trim_end_matches('/'))
        });
        let pxe_configs_dir = env_optional("PXE_CONFIGS_DIR").unwrap_or_else(|| {
            format!("{}/pxe-configs", tftp_root_dir.trim_end_matches('/'))
        });
        let pxe_http_base_url = Url::parse(&env_default(
            "PXE_HTTP_BASE_URL",
            "http://127.0.0.1:3000/pxe-assets",
        ))
        .context("PXE_HTTP_BASE_URL must be a valid URL")?;
        let pxe_tftp_server = env_default("PXE_TFTP_SERVER", "127.0.0.1");
        let pxe_bios_bootfile = env_default("PXE_BIOS_BOOTFILE", "undionly.kpxe");
        let pxe_uefi_bootfile = env_default("PXE_UEFI_BOOTFILE", "ipxe.efi");

        let smtp_host = env_optional("SMTP_HOST");
        let smtp_port = env_u16("SMTP_PORT");
        let smtp_username = env_optional("SMTP_USERNAME");
        let smtp_password = env_optional("SMTP_PASSWORD");
        let smtp_from = env_optional("SMTP_FROM");
        let smtp_to = env_optional("SMTP_TO")
            .map(|value| {
                value
                    .split(',')
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let smtp_use_starttls = env_bool("SMTP_USE_STARTTLS").unwrap_or(true);
        let admin_email = env_optional("ADMIN_EMAIL");

        let macmon_enabled = env_bool("MACMON_ENABLED").unwrap_or(false);
        let macmon_base_url = env_optional("MACMON_BASE_URL");
        let macmon_username = env_optional("MACMON_USERNAME");
        let macmon_password = env_optional("MACMON_PASSWORD");

        // dnsmasq
        let dnsmasq_hosts_file =
            env_default("DNSMASQ_HOSTS_FILE", "/etc/dnsmasq.d/01-rust-hosts.conf");
        let dnsmasq_conf_dir = env_optional("DNS_CONF_DIR")
            .or_else(|| env_optional("DNSMASQ_CONF_DIR"))
            .unwrap_or_else(|| "/etc/dnsmasq.d".to_string());
        let dnsmasq_reload_cmd =
            env_default("DNSMASQ_RELOAD_CMD", "sudo systemctl restart dnsmasq");
        let dnsmasq_interface = env_optional("DNSMASQ_INTERFACE");
        let dnsmasq_bind_addr = env_default("DNSMASQ_BIND_ADDR", "127.0.0.1");
        let dnsmasq_port = env_u16("DNSMASQ_PORT").unwrap_or(53);
        let domain_name = env_default("DOMAIN_NAME", "ipmanager.local");
        let ipmanager_ip = env_default("IPMANAGER_IP", "127.0.0.1");

        Ok(Self {
            database_url,
            db_max_connections,
            db_min_connections,

            bind_addr,
            base_url,

            initial_admin_user,
            initial_admin_password,

            session_secret,
            session_cookie_name,
            session_cookie_secure,
            session_ttl,

            pxe_enabled,
            pxe_root_dir,
            tftp_root_dir,
            pxe_assets_dir,
            pxe_configs_dir,
            pxe_http_base_url,
            pxe_tftp_server,
            pxe_bios_bootfile,
            pxe_uefi_bootfile,

            smtp_host,
            smtp_port,
            smtp_username,
            smtp_password,
            smtp_from,
            smtp_to,
            smtp_use_starttls,
            admin_email,

            macmon_enabled,
            macmon_base_url,
            macmon_username,
            macmon_password,

            // dnsmasq
            dnsmasq_hosts_file,
            dnsmasq_conf_dir,
            dnsmasq_reload_cmd,
            dnsmasq_interface,
            dnsmasq_bind_addr,
            dnsmasq_port,
            domain_name,
            ipmanager_ip,
        })
    }
}

fn env(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("missing env var: {key}"))
}

fn env_default(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_u32(key: &str) -> Option<u32> {
    std::env::var(key)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
}

fn env_bool(key: &str) -> Option<bool> {
    std::env::var(key)
        .ok()
        .and_then(|s| match s.trim().to_lowercase().as_str() {
            "1" | "true" | "yes" | "y" | "on" => Some(true),
            "0" | "false" | "no" | "n" | "off" => Some(false),
            _ => None,
        })
}

fn env_duration_secs(key: &str) -> Option<Duration> {
    env_u32(key).map(|v| Duration::from_secs(v as u64))
}

fn env_optional(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_u16(key: &str) -> Option<u16> {
    std::env::var(key)
        .ok()
        .and_then(|s| s.trim().parse::<u16>().ok())
}
