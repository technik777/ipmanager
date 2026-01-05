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
    pub pxe_http_base_url: Url,
    pub pxe_tftp_server: String,
    pub pxe_bios_bootfile: String,
    pub pxe_uefi_bootfile: String,

    // KEA (neu)
    pub kea_config_path: String,
    /// "none" | "api"
    pub kea_reload_mode: String,
    pub kea_control_agent_url: Option<Url>,
    pub kea_api_timeout: Duration,
    pub kea_control_agent_username: Option<String>,
    pub kea_control_agent_password: Option<String>,
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
        let pxe_http_base_url = Url::parse(&env_default("PXE_HTTP_BASE_URL", "http://127.0.0.1:3000/pxe-assets"))
            .context("PXE_HTTP_BASE_URL must be a valid URL")?;
        let pxe_tftp_server = env_default("PXE_TFTP_SERVER", "127.0.0.1");
        let pxe_bios_bootfile = env_default("PXE_BIOS_BOOTFILE", "undionly.kpxe");
        let pxe_uefi_bootfile = env_default("PXE_UEFI_BOOTFILE", "ipxe.efi");

        // KEA
        let kea_config_path = env_default("KEA_CONFIG_PATH", "/etc/kea/kea-dhcp4.conf");
        let kea_reload_mode = env_default("KEA_RELOAD_MODE", "none");
        let kea_control_agent_url = match env_opt("KEA_CONTROL_AGENT_URL") {
            Some(s) => Some(Url::parse(&s).context("KEA_CONTROL_AGENT_URL must be a valid URL")?),

            None => None,
        };
        let kea_api_timeout =
            env_duration_secs("KEA_API_TIMEOUT_SECS").unwrap_or(Duration::from_secs(5));

        let kea_control_agent_username = env_opt("KEA_CONTROL_AGENT_USERNAME");
        let kea_control_agent_password = env_opt("KEA_CONTROL_AGENT_PASSWORD");

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
            pxe_http_base_url,
            pxe_tftp_server,
            pxe_bios_bootfile,
            pxe_uefi_bootfile,

            // KEA
            kea_config_path,
            kea_reload_mode,
            kea_control_agent_url,
            kea_api_timeout,
            kea_control_agent_username,
            kea_control_agent_password,
        })
    }
}

fn env(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("missing env var: {key}"))
}

fn env_default(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_opt(key: &str) -> Option<String> {
    std::env::var(key).ok().and_then(|s| {
        let t = s.trim().to_string();
        if t.is_empty() {
            None
        } else {
            Some(t)
        }
    })
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
