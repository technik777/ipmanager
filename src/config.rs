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

    // SMTP (für später)
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    pub smtp_pass: String,
    pub smtp_from: String,
    pub smtp_starttls: bool,
    pub alert_email_to: Option<String>,

    // DNS (für später)
    pub dns_server: String,
    pub dns_port: u16,
    pub dns_tsig_key_name: String,
    pub dns_tsig_secret: String,
    pub dns_default_zone: Option<String>,
    pub dns_default_reverse_zone: Option<String>,
    pub dns_update_timeout: Duration,

    // macmon (für später)
    pub macmon_api_url: Url,
    pub macmon_api_token: String,
    pub macmon_timeout: Duration,

    // DHCP (legacy – lassen wir drin, nutzen wir aber nicht mehr für Kea)
    pub dhcp_config_path: String,
    pub dhcp_write_atomic: bool,

    // KEA (neu)
    pub kea_config_path: String,
    /// "none" | "api"
    pub kea_reload_mode: String,
    pub kea_control_agent_url: Option<Url>,
    pub kea_api_timeout: Duration,

    // Jobs (für später)
    pub job_poll_interval: Duration,
    pub job_max_retries: u32,
    pub job_backoff_base: Duration,
    pub job_backoff_max: Duration,
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

        let session_secret = env_default("SESSION_SECRET", "please_change_me");
        let session_cookie_name = env_default("SESSION_COOKIE_NAME", "ipmanager_session");
        let session_cookie_secure = env_bool("SESSION_COOKIE_SECURE").unwrap_or(false);
        let session_ttl =
            env_duration_secs("SESSION_TTL_SECS").unwrap_or(Duration::from_secs(60 * 60 * 24));

        let smtp_host = env_default("SMTP_HOST", "localhost");
        let smtp_port = env_u16("SMTP_PORT").unwrap_or(25);
        let smtp_user = env_default("SMTP_USER", "");
        let smtp_pass = env_default("SMTP_PASS", "");
        let smtp_from = env_default("SMTP_FROM", "ipmanager@localhost");
        let smtp_starttls = env_bool("SMTP_STARTTLS").unwrap_or(true);
        let alert_email_to = env_opt("ALERT_EMAIL_TO");

        let dns_server = env_default("DNS_SERVER", "127.0.0.1");
        let dns_port = env_u16("DNS_PORT").unwrap_or(53);
        let dns_tsig_key_name = env_default("DNS_TSIG_KEY_NAME", "ipmanager-key");
        let dns_tsig_secret = env_default("DNS_TSIG_SECRET", "");
        let dns_default_zone = env_opt("DNS_DEFAULT_ZONE");
        let dns_default_reverse_zone = env_opt("DNS_DEFAULT_REVERSE_ZONE");
        let dns_update_timeout =
            env_duration_secs("DNS_UPDATE_TIMEOUT_SECS").unwrap_or(Duration::from_secs(5));

        let macmon_api_url = Url::parse(&env_default("MACMON_API_URL", "http://127.0.0.1/"))
            .context("MACMON_API_URL must be a valid URL")?;
        let macmon_api_token = env_default("MACMON_API_TOKEN", "");
        let macmon_timeout =
            env_duration_secs("MACMON_TIMEOUT_SECS").unwrap_or(Duration::from_secs(5));

        let dhcp_config_path = env_default("DHCP_CONFIG_PATH", "/etc/dhcp/dhcpd.conf");
        let dhcp_write_atomic = env_bool("DHCP_WRITE_ATOMIC").unwrap_or(true);

        // KEA
        let kea_config_path = env_default("KEA_CONFIG_PATH", "/etc/kea/kea-dhcp4.conf");
        let kea_reload_mode = env_default("KEA_RELOAD_MODE", "none");
        let kea_control_agent_url = match env_opt("KEA_CONTROL_AGENT_URL") {
            Some(s) => Some(Url::parse(&s).context("KEA_CONTROL_AGENT_URL must be a valid URL")?),
            None => None,
        };
        let kea_api_timeout =
            env_duration_secs("KEA_API_TIMEOUT_SECS").unwrap_or(Duration::from_secs(5));

        let job_poll_interval =
            env_duration_secs("JOB_POLL_INTERVAL_SECS").unwrap_or(Duration::from_secs(5));
        let job_max_retries = env_u32("JOB_MAX_RETRIES").unwrap_or(10);
        let job_backoff_base =
            env_duration_secs("JOB_BACKOFF_BASE_SECS").unwrap_or(Duration::from_secs(2));
        let job_backoff_max =
            env_duration_secs("JOB_BACKOFF_MAX_SECS").unwrap_or(Duration::from_secs(30));

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

            smtp_host,
            smtp_port,
            smtp_user,
            smtp_pass,
            smtp_from,
            smtp_starttls,
            alert_email_to,

            dns_server,
            dns_port,
            dns_tsig_key_name,
            dns_tsig_secret,
            dns_default_zone,
            dns_default_reverse_zone,
            dns_update_timeout,

            macmon_api_url,
            macmon_api_token,
            macmon_timeout,

            dhcp_config_path,
            dhcp_write_atomic,

            kea_config_path,
            kea_reload_mode,
            kea_control_agent_url,
            kea_api_timeout,

            job_poll_interval,
            job_max_retries,
            job_backoff_base,
            job_backoff_max,
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

fn env_u16(key: &str) -> Option<u16> {
    std::env::var(key)
        .ok()
        .and_then(|s| s.trim().parse::<u16>().ok())
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
