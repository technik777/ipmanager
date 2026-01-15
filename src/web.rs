use axum::{
    extract::{ConnectInfo, Form, Path, Query, State},
    http::{header::ACCEPT, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use ipnet::IpNet;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::{
    collections::HashSet,
    net::{Ipv4Addr, SocketAddr},
    path::{Path as StdPath, PathBuf},
    str::FromStr,
    sync::Arc,
};
use tera::{Context, Tera};
use tokio::sync::Mutex;
use tokio::sync::oneshot;
use tower_sessions::Session;
use uuid::Uuid;

use crate::dhcp::dnsmasq;
use crate::domain::mac::MacAddr;
use crate::config::Config;
use tower_http::services::ServeDir;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub templates: Arc<Tera>,
    pub config: crate::config::Config,
    pub dnsmasq_status: Arc<Mutex<dnsmasq::DnsmasqStatus>>,
    pub shutdown_tx: Arc<Mutex<Option<oneshot::Sender<()>>>>,
}

/* ----------------------------- API (JSON) ----------------------------- */

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct MeResponse {
    pub username: String,
    pub role: String,
}

#[derive(Deserialize)]
pub struct LanOutletsQuery {
    pub location_id: String,
}

#[derive(Serialize)]
pub struct LanOutletApiItem {
    pub id: String,
    pub label: String,
}

#[derive(Deserialize)]
pub struct FindFreeIpQuery {
    pub subnet_id: String,
}

#[derive(Deserialize)]
pub struct HostsApiQuery {
    pub q: Option<String>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

#[derive(Serialize)]
pub struct HostApiItem {
    pub id: String,
    pub hostname: String,
    pub ip: String,
    pub mac: String,
    pub pxe_enabled: bool,
    pub pxe_image_name: Option<String>,
}

#[derive(Serialize)]
pub struct HostsApiResponse {
    pub items: Vec<HostApiItem>,
    pub page: u32,
    pub per_page: u32,
    pub total: i64,
    pub total_pages: u32,
}

#[derive(Serialize)]
pub struct DnsmasqSyncStatusResponse {
    pub last_restart_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_test_ok: Option<bool>,
    pub last_test_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_test_error: Option<String>,
    pub tftp_files: Vec<String>,
    pub orphaned_hosts: Vec<OrphanedHost>,
    pub warnings: Vec<String>,
    pub audit_logs: Vec<AuditLogEntry>,
}

#[derive(Serialize)]
pub struct OrphanedHost {
    pub hostname: String,
    pub mac_address: String,
    pub pxe_image: String,
}

#[derive(Serialize)]
pub struct AuditLogEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub user_id: Option<String>,
    pub action: String,
    pub details: serde_json::Value,
}

/* ----------------------------- SSR (HTML) ----------------------------- */

#[derive(Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct HostCreateForm {
    pub hostname: String,
    pub ip: String,
    pub mac: String,
    pub location_id: String,
    pub lan_outlet_id: String,
    pub subnet_id: String,
    pub pxe_enabled: Option<String>,
    pub pxe_image_id: Option<String>,
}

#[derive(Deserialize)]
pub struct HostUpdateForm {
    pub hostname: String,
    pub ip: String,
    pub mac: String,
    pub location_id: String,
    pub lan_outlet_id: String,
    pub subnet_id: String,
    pub pxe_enabled: Option<String>,
    pub pxe_image_id: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct HostsQuery {
    pub q: Option<String>,
    pub dnsmasq: Option<String>,
}

#[derive(Deserialize)]
pub struct LocationCreateForm {
    pub name: String,
}

#[derive(Deserialize)]
pub struct LanOutletCreateForm {
    pub location_id: String,
    pub label: String,
    pub description: Option<String>,
}

#[derive(Deserialize)]
pub struct SubnetCreateForm {
    pub name: String,
    pub cidr: String,
    pub dns_zone: Option<String>,
    pub reverse_zone: Option<String>,
    pub dhcp_enabled: Option<String>,
    pub pxe_enabled: Option<String>,
    pub dhcp_pool_start: Option<String>,
    pub dhcp_pool_end: Option<String>,
}

#[derive(Deserialize)]
pub struct SubnetUpdateForm {
    pub name: String,
    pub cidr: String,
    pub dns_zone: Option<String>,
    pub reverse_zone: Option<String>,
    pub dhcp_enabled: Option<String>,
    pub pxe_enabled: Option<String>,
    pub dhcp_pool_start: Option<String>,
    pub dhcp_pool_end: Option<String>,
}

#[derive(Serialize)]
struct SubnetEdit {
    id: String,
    name: String,
    cidr: String,
    dns_zone: Option<String>,
    reverse_zone: Option<String>,
    dhcp_enabled: bool,
    dhcp_pool_start: Option<String>,
    dhcp_pool_end: Option<String>,
    pxe_enabled: bool,
}

#[derive(Serialize)]
struct HostRow {
    id: String,
    hostname: String,
    ip: String,
    mac: String,
    location_name: Option<String>,
    lan_outlet_label: Option<String>,
    pxe_enabled: bool,
    pxe_image_name: Option<String>,
}

#[derive(Serialize)]
struct HostShow {
    id: String,
    hostname: String,
    ip: String,
    mac: String,
    location_id: String,
    lan_outlet_id: String,
    subnet_id: String,
    location_name: Option<String>,
    lan_outlet_label: Option<String>,
    subnet_display: Option<String>,
    pxe_enabled: bool,
    pxe_image_id: Option<String>,
    pxe_image_name: Option<String>,
}

#[derive(Serialize)]
struct LocationOption {
    id: String,
    name: String,
}

#[derive(Serialize)]
struct LocationRow {
    name: String,
}

#[derive(Serialize)]
struct LanOutletOption {
    id: String,
    location_id: String,
    location_name: String,
    label: String,
}

#[derive(Serialize)]
struct LanOutletRow {
    location_name: String,
    label: String,
    description: Option<String>,
}

#[derive(Serialize)]
struct SubnetOption {
    id: String,
    name: String,
    cidr: String,
}

#[derive(Serialize)]
struct PxeImageOption {
    id: String,
    name: String,
}

#[derive(Serialize)]
struct DnsmasqWarning {
    code: String,
    message: String,
}

#[derive(Serialize)]
struct SubnetRow {
    id: String,
    name: String,
    cidr: String,
    dns_zone: Option<String>,
    reverse_zone: Option<String>,
    dhcp_enabled: bool,
    dhcp_pool_start: Option<String>,
    dhcp_pool_end: Option<String>,
    pxe_enabled: bool,
}

#[derive(Debug, Serialize, Clone)]
struct PxeImage {
    id: i64,
    name: String,
    kind: String,
    arch: String,
    kernel_path: Option<String>,
    initrd_path: Option<String>,
    chain_url: Option<String>,
    cmdline: Option<String>,
    enabled: bool,
}

#[derive(Deserialize)]
struct PxeImageForm {
    name: String,
    kind: String,
    arch: String,
    kernel_path: Option<String>,
    initrd_path: Option<String>,
    chain_url: Option<String>,
    cmdline: Option<String>,
    enabled: Option<String>,
}

struct ValidatedPxe {
    name: String,
    kind: String,
    arch: String,
    kernel_path: Option<String>,
    initrd_path: Option<String>,
    chain_url: Option<String>,
    cmdline: Option<String>,
    enabled: bool,
}

pub fn router(state: AppState) -> Router {
    let mut router = Router::new()
        // SSR
        .route("/", get(index))
        .route("/login", get(login_page).post(login_submit))
        .route("/logout", post(logout))
        .route("/me", get(me_page))
        .route("/hosts", get(hosts_list).post(hosts_create))
        .route("/hosts/new", get(hosts_new))
        .route("/hosts/:id", get(host_show).post(host_update))
        .route("/hosts/:id/edit", get(host_edit))
        .route("/hosts/:id/delete", post(host_delete))
        .route("/locations", get(locations_list).post(locations_create))
        .route("/locations/new", get(locations_new))
        .route(
            "/lan-outlets",
            get(lan_outlets_list).post(lan_outlets_create),
        )
        .route("/lan-outlets/new", get(lan_outlets_new))
        .route("/subnets", get(subnets_list).post(subnets_create))
        .route("/subnets/", get(|| async { Redirect::to("/subnets") }))
        .route("/subnets/new", get(subnets_new))
        .route("/subnets/:id/edit", get(subnets_edit))
        .route("/subnets/:id", post(subnets_update))
        // dnsmasq DHCP
        .route("/dhcp/dnsmasq", get(dhcp_dnsmasq_page))
        .route("/dhcp/dnsmasq/deploy", post(dhcp_dnsmasq_deploy))
        // PXE / iPXE
        .route("/boot.ipxe", get(boot_ipxe))
        // API
        .route("/api/login", post(api_login))
        .route("/api/me", get(api_me))
        .route("/api/lan-outlets", get(api_lan_outlets_by_location))
        .route("/api/find-free-ip", get(api_find_free_ip))
        .route("/api/hosts", get(api_hosts))
        .route("/api/dnsmasq/status", get(api_dnsmasq_status))
        .route("/api/admin/shutdown", post(api_admin_shutdown));

    if state.config.pxe_enabled {
        let pxe_root =
            std::env::var("PXE_ROOT_DIR").unwrap_or_else(|_| "/var/lib/ipmanager/pxe".to_string());
        tracing::info!("Serving PXE assets from: {}", pxe_root);
        router = router
            .route("/pxe/images", get(pxe_images_list))
            .route(
                "/pxe/images/new",
                get(pxe_images_new).post(pxe_images_create),
            )
            .route(
                "/pxe/images/:id/edit",
                get(pxe_images_edit).post(pxe_images_update),
            )
            .route("/pxe/images/:id/delete", post(pxe_images_delete));
        router = router.nest_service("/pxe-assets", ServeDir::new(&pxe_root));
    }

    router.with_state(state)
}

/* ----------------------------- Auth helpers ----------------------------- */

fn validate_ipv4(ip: &str) -> Result<Ipv4Addr, String> {
    let candidate = if ip.contains('/') {
        ip.to_string()
    } else {
        format!("{ip}/32")
    };

    match candidate.parse::<IpNetwork>() {
        Ok(IpNetwork::V4(v4)) => Ok(v4.ip()),
        Ok(IpNetwork::V6(_)) => Err("IPv6 wird nicht unterstützt".to_string()),
        Err(_) => Err("Ungültige IP-Adresse".to_string()),
    }
}

fn validate_mac(mac: &str) -> Result<MacAddr, String> {
    MacAddr::from_str(mac.trim()).map_err(|_| "Ungültige MAC-Adresse".to_string())
}

#[allow(dead_code)]
fn list_pxe_files(root_dir: &StdPath) -> Vec<String> {
    let allowed_ext = [
        "ipxe", "efi", "kpxe", "pxe", "vmlinuz", "img", "gz", "xz", "iso", "wim",
    ];

    let mut files = Vec::new();
    let mut stack = vec![root_dir.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let Ok(read_dir) = std::fs::read_dir(&dir) else {
            continue;
        };

        for entry in read_dir.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if !allowed_ext.iter().any(|a| a.eq_ignore_ascii_case(ext)) {
                    continue;
                }
            }

            if let Ok(rel) = path.strip_prefix(root_dir) {
                if rel
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
                {
                    continue;
                }
                if let Some(s) = rel.to_str() {
                    files.push(s.replace('\\', "/"));
                }
            }
        }
    }

    files.sort();
    files
}

async fn list_tftp_files(root_dir: &StdPath) -> Vec<String> {
    let mut files = Vec::new();
    let mut stack = vec![PathBuf::from(root_dir)];

    while let Some(dir) = stack.pop() {
        let mut entries = match tokio::fs::read_dir(&dir).await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = ?e, path = %dir.display(), "failed to read tftp dir");
                continue;
            }
        };

        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            let file_type = match entry.file_type().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(error = ?e, path = %path.display(), "failed to read tftp entry");
                    continue;
                }
            };

            if file_type.is_dir() {
                stack.push(path);
                continue;
            }

            let ext = path.extension().and_then(|v| v.to_str()).unwrap_or("");
            if ext != "efi" && ext != "kpxe" {
                continue;
            }

            let relative = path
                .strip_prefix(root_dir)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();
            files.push(relative);
        }
    }

    files.sort();
    files
}

async fn load_orphaned_hosts(pool: &PgPool, tftp_set: &HashSet<String>) -> Vec<OrphanedHost> {
    let rows: Vec<(String, String, Option<String>)> = match sqlx::query_as(
        "select h.hostname,
                h.mac_address,
                coalesce(pi.chain_url, pi.kernel_path) as pxe_image
         from hosts h
         left join pxe_images pi on pi.id = h.pxe_image_id
         where h.pxe_image_id is not null",
    )
    .fetch_all(pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = ?e, "failed to load hosts for orphaned PXE validation");
            return Vec::new();
        }
    };

    rows.into_iter()
        .filter_map(|(hostname, mac_address, pxe_image)| {
            let image = pxe_image.as_deref().map(str::trim).filter(|v| !v.is_empty())?;
            if !valid_rel_path(image) {
                return None;
            }
            if tftp_set.contains(image) {
                return None;
            }
            Some(OrphanedHost {
                hostname,
                mac_address,
                pxe_image: image.to_string(),
            })
        })
        .collect()
}

async fn load_audit_logs(pool: &PgPool) -> Vec<AuditLogEntry> {
    let rows: Vec<(chrono::DateTime<chrono::Utc>, Option<Uuid>, String, serde_json::Value)> =
        match sqlx::query_as(
            "select timestamp, user_id, action, details
             from audit_logs
             order by timestamp desc
             limit 5",
        )
        .fetch_all(pool)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = ?e, "failed to load audit logs");
            return Vec::new();
        }
    };

    rows.into_iter()
        .map(|(timestamp, user_id, action, details)| AuditLogEntry {
            timestamp,
            user_id: user_id.map(|id| id.to_string()),
            action,
            details,
        })
        .collect()
}

fn sanitize_cmdline(s: &str) -> String {
    s.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

fn valid_rel_path(p: &str) -> bool {
    let path = StdPath::new(p);
    !p.is_empty()
        && !path.is_absolute()
        && !p.starts_with('/')
        && !path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
}

fn ensure_path_allowed(root: &StdPath, rel: &str) -> bool {
    if !valid_rel_path(rel) {
        return false;
    }
    let candidate = root.join(rel);
    match candidate.canonicalize() {
        Ok(real) => real.starts_with(root) && real.is_file(),
        Err(_) => false,
    }
}

fn ipv4_to_u32(ip: Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets())
}

async fn is_authenticated(session: &Session) -> bool {
    matches!(session.get::<String>("username").await, Ok(Some(_)))
}

async fn add_auth_context(ctx: &mut Context, session: &Session, state: &AppState) {
    let authed = is_authenticated(session).await;
    ctx.insert("is_authenticated", &authed);
    ctx.insert("pxe_enabled", &state.config.pxe_enabled);
}

async fn get_dhcp_leases(_subnet_id: Uuid, _state: &AppState) -> Result<Vec<Ipv4Addr>, String> {
    tracing::debug!("get_dhcp_leases stub invoked; returning empty list");
    Ok(Vec::new())
}

async fn find_free_ip(state: &AppState, subnet_id: Uuid) -> Result<Ipv4Addr, String> {
    let row: Option<(String, Option<String>, Option<String>)> = sqlx::query_as(
        "select cidr::text, host(dhcp_pool_start), host(dhcp_pool_end)
         from subnets
         where id = $1
         limit 1",
    )
    .bind(subnet_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!(error = ?e, %subnet_id, "failed loading subnet for find_free_ip");
        "Subnet konnte nicht geladen werden".to_string()
    })?;

    let Some((cidr, pool_start, pool_end)) = row else {
        return Err("Subnet nicht gefunden".to_string());
    };

    let net: ipnet::IpNet = cidr
        .parse()
        .map_err(|_| "Subnet CIDR ist ungültig".to_string())?;
    let net = match net {
        ipnet::IpNet::V4(v4) => v4,
        ipnet::IpNet::V6(_) => return Err("IPv6 wird nicht unterstützt".to_string()),
    };

    let pool_start = match pool_start {
        Some(s) => Some(
            s.parse::<Ipv4Addr>()
                .map_err(|_| "DHCP Pool Start ungültig")?,
        ),
        None => None,
    };
    let pool_end = match pool_end {
        Some(s) => Some(
            s.parse::<Ipv4Addr>()
                .map_err(|_| "DHCP Pool Ende ungültig")?,
        ),
        None => None,
    };

    let taken_hosts: HashSet<Ipv4Addr> =
        sqlx::query_scalar::<_, String>("select ip_address from hosts where subnet_id = $1")
            .bind(subnet_id)
            .fetch_all(&state.pool)
            .await
            .map(|rows| {
                rows.into_iter()
                    .filter_map(|s| s.parse::<Ipv4Addr>().ok())
                    .collect()
            })
            .unwrap_or_default();

    let dhcp_leases = get_dhcp_leases(subnet_id, state).await.unwrap_or_default();
    let mut taken_all: HashSet<Ipv4Addr> = taken_hosts;
    taken_all.extend(dhcp_leases.into_iter());

    let start_num = pool_start.map(ipv4_to_u32);
    let end_num = pool_end.map(ipv4_to_u32);

    for candidate in net.hosts() {
        let c_num = ipv4_to_u32(candidate);
        if let Some(s) = start_num {
            if c_num < s {
                continue;
            }
        }
        if let Some(e) = end_num {
            if c_num > e {
                continue;
            }
        }
        if !taken_all.contains(&candidate) {
            return Ok(candidate);
        }
    }

    Err("Keine freie IP im Subnet gefunden".to_string())
}

async fn require_auth(session: &Session) -> Result<(), Response> {
    if is_authenticated(session).await {
        Ok(())
    } else {
        Err(Redirect::to("/login").into_response())
    }
}

async fn require_auth_api(session: &Session) -> Result<(), StatusCode> {
    if is_authenticated(session).await {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

async fn load_user_id_from_session(session: &Session, pool: &PgPool) -> Option<Uuid> {
    let username: Option<String> = session.get("username").await.ok().flatten();
    let username = username?.trim().to_string();
    if username.is_empty() {
        return None;
    }
    let row: Option<(Uuid,)> = sqlx::query_as("select id from users where username = $1")
        .bind(username)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();
    row.map(|(id,)| id)
}

/* ----------------------------- Dropdown loaders ----------------------------- */

async fn load_locations(pool: &PgPool) -> Result<Vec<LocationOption>, ()> {
    let rows: Vec<(Uuid, String)> =
        sqlx::query_as("select id, name from locations order by name asc")
            .fetch_all(pool)
            .await
            .map_err(|_| ())?;
    Ok(rows
        .into_iter()
        .map(|(id, name)| LocationOption {
            id: id.to_string(),
            name,
        })
        .collect())
}

async fn load_lan_outlets(pool: &PgPool) -> Result<Vec<LanOutletOption>, ()> {
    let rows: Vec<(Uuid, Uuid, String, String)> = sqlx::query_as(
        "select o.id, o.location_id, l.name as location_name, o.label
         from lan_outlets o
         join locations l on l.id = o.location_id
         order by l.name asc, o.label asc",
    )
    .fetch_all(pool)
    .await
    .map_err(|_| ())?;

    Ok(rows
        .into_iter()
        .map(|(id, location_id, location_name, label)| LanOutletOption {
            id: id.to_string(),
            location_id: location_id.to_string(),
            location_name,
            label,
        })
        .collect())
}

async fn load_subnets(pool: &PgPool) -> Result<Vec<SubnetOption>, ()> {
    let rows: Vec<(Uuid, String, String)> =
        sqlx::query_as("select id, name, cidr::text from subnets order by name asc")
            .fetch_all(pool)
            .await
            .map_err(|_| ())?;
    Ok(rows
        .into_iter()
        .map(|(id, name, cidr)| SubnetOption {
            id: id.to_string(),
            name,
            cidr,
        })
        .collect())
}

async fn load_pxe_images(pool: &PgPool) -> Result<Vec<PxeImageOption>, ()> {
    let rows: Vec<(i64, String)> = sqlx::query_as(
        "select id, name
         from pxe_images
         where enabled = true
         order by name asc",
    )
    .fetch_all(pool)
    .await
    .map_err(|_| ())?;

    Ok(rows
        .into_iter()
        .map(|(id, name)| PxeImageOption {
            id: id.to_string(),
            name,
        })
        .collect())
}

/* ----------------------------- SSR Handlers ----------------------------- */

async fn index(State(state): State<AppState>, session: Session) -> Response {
    let mut ctx = Context::new();
    add_auth_context(&mut ctx, &session, &state).await;
    render(&state.templates, "index.html", ctx)
}

async fn login_page(State(state): State<AppState>, session: Session) -> Response {
    let mut ctx = Context::new();
    add_auth_context(&mut ctx, &session, &state).await;

    if is_authenticated(&session).await {
        return Redirect::to("/me").into_response();
    }

    ctx.insert("error", &Option::<String>::None);
    render(&state.templates, "login.html", ctx)
}

async fn login_submit(
    State(state): State<AppState>,
    session: Session,
    Form(form): Form<LoginForm>,
) -> Response {
    let row: Result<Option<(String, String)>, _> = sqlx::query_as(
        "select password_hash, role from users where username = $1 and is_active = true",
    )
    .bind(&form.username)
    .fetch_optional(&state.pool)
    .await;

    let (hash, role) = match row {
        Ok(Some(v)) => v,
        Ok(None) => return render_login_error(&state, &session, "Login fehlgeschlagen").await,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    match bcrypt::verify(&form.password, &hash) {
        Ok(true) => {
            if session.insert("username", &form.username).await.is_err() {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            if session.insert("role", &role).await.is_err() {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            Redirect::to("/me").into_response()
        }
        _ => render_login_error(&state, &session, "Login fehlgeschlagen").await,
    }
}

async fn logout(session: Session) -> Response {
    let _ = session.remove::<String>("username").await;
    let _ = session.remove::<String>("role").await;
    let _ = session.cycle_id().await;
    Redirect::to("/").into_response()
}

async fn me_page(State(state): State<AppState>, session: Session) -> Response {
    let username: Option<String> = match session.get("username").await {
        Ok(v) => v,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let role: Option<String> = match session.get("role").await {
        Ok(v) => v,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let (Some(username), Some(role)) = (username, role) else {
        return Redirect::to("/login").into_response();
    };

    let mut ctx = Context::new();
    add_auth_context(&mut ctx, &session, &state).await;
    ctx.insert("username", &username);
    ctx.insert("role", &role);

    render(&state.templates, "me.html", ctx)
}

/* ----------------------------- dnsmasq DHCP (SSR) ----------------------------- */

async fn try_sync_dnsmasq(state: &AppState, context: &str) {
    if let Err(e) =
        dnsmasq::sync_dnsmasq_hosts(
            &state.pool,
            &state.config,
            state.dnsmasq_status.as_ref(),
            None,
        )
            .await
    {
        tracing::error!(error = ?e, %context, "dnsmasq sync failed");
    } else {
        tracing::info!(%context, "dnsmasq sync completed");
    }
}

fn wants_json(headers: &HeaderMap) -> bool {
    headers
        .get(ACCEPT)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.contains("application/json"))
        .unwrap_or(false)
}

fn map_dnsmasq_sync_error(error: &anyhow::Error) -> DnsmasqWarning {
    for cause in error.chain() {
        if let Some(io_error) = cause.downcast_ref::<std::io::Error>() {
            match io_error.kind() {
                std::io::ErrorKind::PermissionDenied => {
                    return DnsmasqWarning {
                        code: "permission_denied".to_string(),
                        message: "Fehlende Berechtigung fuer dnsmasq Schreibzugriff oder Reload."
                            .to_string(),
                    };
                }
                std::io::ErrorKind::NotFound => {
                    return DnsmasqWarning {
                        code: "not_found".to_string(),
                        message: "dnsmasq Config-Pfad oder Reload-Kommando wurde nicht gefunden."
                            .to_string(),
                    };
                }
                _ => {}
            }
        }
    }

    let message = error.to_string();
    if message.contains("failed to fetch hosts for dnsmasq sync") {
        return DnsmasqWarning {
            code: "db_fetch_failed".to_string(),
            message: "DNSMASQ Sync scheiterte beim Laden der Hosts aus der DB.".to_string(),
        };
    }
    if message.contains("failed to write dnsmasq hosts file") {
        return DnsmasqWarning {
            code: "write_failed".to_string(),
            message: "DNSMASQ Hosts-Datei konnte nicht geschrieben werden.".to_string(),
        };
    }
    if message.contains("dnsmasq reload command failed")
        || message.contains("failed to execute dnsmasq reload command")
    {
        return DnsmasqWarning {
            code: "reload_failed".to_string(),
            message: "DNSMASQ Reload-Kommando ist fehlgeschlagen.".to_string(),
        };
    }

    DnsmasqWarning {
        code: "unknown".to_string(),
        message: "DNSMASQ Sync fehlgeschlagen. Details im Log.".to_string(),
    }
}

async fn dhcp_dnsmasq_page(State(state): State<AppState>, session: Session) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }

    let cfg = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            let mut ctx = Context::new();
            add_auth_context(&mut ctx, &session, &state).await;
            ctx.insert(
                "error",
                &Some(format!("Config konnte nicht geladen werden: {e:#}")),
            );
            ctx.insert("hosts_preview", &"".to_string());
            ctx.insert("dnsmasq_hosts_file", &"".to_string());
            ctx.insert("dnsmasq_reload_cmd", &"".to_string());
            return render(&state.templates, "dhcp_dnsmasq.html", ctx);
        }
    };

    let hosts_preview = match tokio::fs::read_to_string(&cfg.dnsmasq_hosts_file).await {
        Ok(contents) => contents,
        Err(e) => {
            let mut ctx = Context::new();
            add_auth_context(&mut ctx, &session, &state).await;
            ctx.insert(
                "error",
                &Some(format!(
                    "Hosts-Datei konnte nicht gelesen werden: {e:#}"
                )),
            );
            ctx.insert("hosts_preview", &"".to_string());
            ctx.insert("dnsmasq_hosts_file", &cfg.dnsmasq_hosts_file);
            ctx.insert("dnsmasq_reload_cmd", &cfg.dnsmasq_reload_cmd);
            return render(&state.templates, "dhcp_dnsmasq.html", ctx);
        }
    };

    let mut ctx = Context::new();
    add_auth_context(&mut ctx, &session, &state).await;
    ctx.insert("error", &Option::<String>::None);
    ctx.insert("hosts_preview", &hosts_preview);
    ctx.insert("dnsmasq_hosts_file", &cfg.dnsmasq_hosts_file);
    ctx.insert("dnsmasq_reload_cmd", &cfg.dnsmasq_reload_cmd);

    render(&state.templates, "dhcp_dnsmasq.html", ctx)
}

async fn dhcp_dnsmasq_deploy(State(state): State<AppState>, session: Session) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }

    let cfg = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = ?e, "failed to load config for dnsmasq deploy");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let user_id = load_user_id_from_session(&session, &state.pool).await;
    if let Err(e) = dnsmasq::sync_dnsmasq_hosts(
        &state.pool,
        &cfg,
        state.dnsmasq_status.as_ref(),
        user_id,
    )
    .await
    {
        tracing::error!(error = ?e, "dnsmasq deploy failed");

        let mut ctx = Context::new();
        add_auth_context(&mut ctx, &session, &state).await;
        ctx.insert("error", &Some(format!("Deploy fehlgeschlagen: {e:#}")));
        ctx.insert("hosts_preview", &"".to_string());
        ctx.insert("dnsmasq_hosts_file", &cfg.dnsmasq_hosts_file);
        ctx.insert("dnsmasq_reload_cmd", &cfg.dnsmasq_reload_cmd);
        return render(&state.templates, "dhcp_dnsmasq.html", ctx);
    }

    let hosts_preview = tokio::fs::read_to_string(&cfg.dnsmasq_hosts_file)
        .await
        .unwrap_or_default();

    let mut ctx = Context::new();
    add_auth_context(&mut ctx, &session, &state).await;
    ctx.insert("error", &Option::<String>::None);
    ctx.insert("hosts_preview", &hosts_preview);
    ctx.insert("dnsmasq_hosts_file", &cfg.dnsmasq_hosts_file);
    ctx.insert("dnsmasq_reload_cmd", &cfg.dnsmasq_reload_cmd);
    ctx.insert(
        "outcome",
        &serde_json::json!({
            "written_to": cfg.dnsmasq_hosts_file,
            "reload_status": "ok",
            "reload_message": ""
        }),
    );

    render(&state.templates, "dhcp_dnsmasq.html", ctx)
}

/* ----------------------------- Hosts (SSR) ----------------------------- */

type HostsListRowDb = (
    Uuid,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    bool,
    Option<String>,
);

async fn hosts_list(
    State(state): State<AppState>,
    session: Session,
    Query(query): Query<HostsQuery>,
) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }

    tracing::info!("render hosts_list");

    let q_raw = query.q.clone().unwrap_or_default();
    let q = q_raw.trim().to_string();
    let dnsmasq_status = query.dnsmasq.as_deref().map(str::to_string);
    let dnsmasq_message = match query.dnsmasq.as_deref() {
        Some("ok") => Some("Host erstellt, DHCP-Sync erfolgreich."),
        Some("warn") => Some("Host erstellt, aber DHCP-Sync fehlgeschlagen. Details im Log."),
        _ => None,
    };

    let rows: Vec<HostsListRowDb> = if q.is_empty() {
        match sqlx::query_as(
            "select h.id,
                        h.hostname,
                        h.ip_address,
                        h.mac_address,
                        l.name as location_name,
                        o.label as lan_outlet_label,
                        h.pxe_enabled,
                        pi.name as pxe_image_name
                 from hosts h
                 left join locations l on l.id = h.location_id
                 left join lan_outlets o on o.id = h.lan_outlet_id
                 left join pxe_images pi on pi.id = h.pxe_image_id
                 order by h.hostname asc",
        )
        .fetch_all(&state.pool)
        .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = ?e, "DB error in hosts_list");
                return render_error_page(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DB Fehler beim Laden der Hosts",
                );
            }
        }
    } else {
        let like = format!("%{}%", q);
        match sqlx::query_as(
            "select h.id,
                        h.hostname,
                        h.ip_address::text,
                        h.mac_address,
                        l.name as location_name,
                        o.label as lan_outlet_label,
                        h.pxe_enabled,
                        pi.name as pxe_image_name
                 from hosts h
                 left join locations l on l.id = h.location_id
                 left join lan_outlets o on o.id = h.lan_outlet_id
                 left join pxe_images pi on pi.id = h.pxe_image_id
                 where h.hostname ilike $1
                    or (h.ip_address::text) ilike $1
                    or h.mac_address ilike $1
                    or coalesce(l.name, '') ilike $1
                    or coalesce(o.label, '') ilike $1
                    or coalesce(pi.name, '') ilike $1
                order by h.hostname asc",
        )
        .bind(like)
        .fetch_all(&state.pool)
        .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = ?e, "DB error in hosts_list (search)");
                return render_error_page(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DB Fehler beim Laden der Hosts",
                );
            }
        }
    };

    let hosts: Vec<HostRow> = rows
        .into_iter()
        .map(
            |(
                id,
                hostname,
                ip,
                mac,
                location_name,
                lan_outlet_label,
                pxe_enabled,
                pxe_image_name,
            )| HostRow {
                id: id.to_string(),
                hostname,
                ip,
                mac,
                location_name,
                lan_outlet_label,
                pxe_enabled,
                pxe_image_name,
            },
        )
        .collect();

    let mut ctx = Context::new();
    add_auth_context(&mut ctx, &session, &state).await;
    ctx.insert("hosts", &hosts);
    ctx.insert("q", &q);
    ctx.insert("dnsmasq_message", &dnsmasq_message);
    ctx.insert("dnsmasq_status", &dnsmasq_status);

    render(&state.templates, "hosts_list.html", ctx)
}

async fn hosts_new(State(state): State<AppState>, session: Session) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }

    tracing::info!("render template hosts_new.html");

    let locations = match load_locations(&state.pool).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = ?e, "DB error in hosts_new loading locations");
            return render_error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB Fehler beim Laden der Standorte",
            );
        }
    };
    let lan_outlets = match load_lan_outlets(&state.pool).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = ?e, "DB error in hosts_new loading lan_outlets");
            return render_error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB Fehler beim Laden der LAN-Dosen",
            );
        }
    };
    let subnets = match load_subnets(&state.pool).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = ?e, "DB error in hosts_new loading subnets");
            return render_error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB Fehler beim Laden der Subnets",
            );
        }
    };
    let pxe_images = if state.config.pxe_enabled {
        match load_pxe_images(&state.pool).await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = ?e, "DB error in hosts_new loading pxe images");
                return render_error_page(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DB Fehler beim Laden der PXE Images",
                );
            }
        }
    } else {
        Vec::new()
    };

    let mut ctx = Context::new();
    add_auth_context(&mut ctx, &session, &state).await;
    ctx.insert("error", &Option::<String>::None);
    ctx.insert("locations", &locations);
    ctx.insert("lan_outlets", &lan_outlets);
    ctx.insert("subnets", &subnets);
    ctx.insert("pxe_images", &pxe_images);
    ctx.insert("suggested_ip", &Option::<String>::None);
    ctx.insert(
        "form",
        &serde_json::json!({
            "hostname": "",
            "ip": "",
            "mac": "",
            "location_id": "",
            "lan_outlet_id": "",
            "subnet_id": "",
            "pxe_enabled": false,
            "pxe_image_id": ""
        }),
    );

    render(&state.templates, "hosts_new.html", ctx)
}

async fn hosts_create(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Form(form): Form<HostCreateForm>,
) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }

    let hostname = form.hostname.trim().to_string();
    if hostname.is_empty() {
        return render_hosts_new_error(&state, &session, &form, "Hostname darf nicht leer sein")
            .await;
    }

    let ip: Ipv4Addr = match validate_ipv4(form.ip.trim()) {
        Ok(v) => v,
        Err(msg) => return render_hosts_new_error(&state, &session, &form, &msg).await,
    };

    let mac: MacAddr = match validate_mac(form.mac.trim()) {
        Ok(v) => v,
        Err(msg) => return render_hosts_new_error(&state, &session, &form, &msg).await,
    };
    let mac_norm = mac.to_string();

    let location_id: Uuid = match Uuid::parse_str(form.location_id.trim()) {
        Ok(v) => v,
        Err(_) => {
            return render_hosts_new_error(&state, &session, &form, "Ungültiger Standort").await
        }
    };

    let lan_outlet_id: Uuid = match Uuid::parse_str(form.lan_outlet_id.trim()) {
        Ok(v) => v,
        Err(_) => {
            return render_hosts_new_error(&state, &session, &form, "Ungültige LAN-Dose").await
        }
    };

    let subnet_id: Uuid = match Uuid::parse_str(form.subnet_id.trim()) {
        Ok(v) => v,
        Err(_) => {
            return render_hosts_new_error(&state, &session, &form, "Ungültiges Subnet").await
        }
    };

    let managed_subnets: Vec<String> = match sqlx::query_scalar("select cidr::text from subnets")
        .fetch_all(&state.pool)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = ?e, "DB error in hosts_create loading subnets");
            return render_error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB Fehler beim Laden der Subnets",
            );
        }
    };
    let ip_addr = std::net::IpAddr::V4(ip);
    let ip_in_managed_subnet = managed_subnets.iter().any(|cidr| {
        cidr.parse::<IpNetwork>()
            .map(|net| net.contains(ip_addr))
            .unwrap_or(false)
    });
    if !ip_in_managed_subnet {
        if wants_json(&headers) {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "IP-Adresse liegt außerhalb der verwalteten Subnetze"
                })),
            )
                .into_response();
        }
        let mut resp = render_hosts_new_error(
            &state,
            &session,
            &form,
            "IP-Adresse liegt außerhalb der verwalteten Subnetze",
        )
        .await;
        *resp.status_mut() = StatusCode::BAD_REQUEST;
        return resp;
    }

    // IP muss im gewählten Subnet liegen
    let cidr: Option<String> =
        match sqlx::query_scalar("select cidr::text from subnets where id = $1")
            .bind(subnet_id)
            .fetch_optional(&state.pool)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = ?e, "DB error in hosts_create loading subnet by id");
                return render_error_page(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DB Fehler beim Laden des Subnets",
                );
            }
        };
    let Some(cidr) = cidr else {
        return render_hosts_new_error(&state, &session, &form, "Ungültiges Subnet").await;
    };
    let net: ipnet::Ipv4Net = match cidr.parse() {
        Ok(n) => n,
        Err(_) => {
            return render_hosts_new_error(&state, &session, &form, "Subnet CIDR ist ungültig")
                .await
        }
    };
    if !net.contains(&ip) {
        return render_hosts_new_error(
            &state,
            &session,
            &form,
            "IP liegt nicht im gewählten Subnet",
        )
        .await;
    }

    // Vor dem Insert prüfen, ob Hostname/IP/MAC schon existieren
    if let Ok(Some((conflict_host, conflict_ip, conflict_mac))) =
        sqlx::query_as::<_, (String, String, String)>(
            "select hostname, ip_address, mac_address
         from hosts
         where hostname = $1
            or ip_address = $2
            or mac_address = $3
         limit 1",
        )
        .bind(&hostname)
        .bind(ip.to_string())
        .bind(&mac_norm)
        .fetch_optional(&state.pool)
        .await
    {
        let msg = if conflict_host == hostname {
            "Hostname ist bereits vergeben"
        } else if conflict_ip == ip.to_string() {
            "IP ist bereits vergeben"
        } else if conflict_mac == mac_norm {
            "MAC ist bereits vergeben"
        } else {
            "Hostname/IP/MAC ist bereits vergeben"
        };
        return render_hosts_new_error(&state, &session, &form, msg).await;
    }

    let pxe_enabled = form.pxe_enabled.is_some();

    let ok_pair: Option<i32> =
        match sqlx::query_scalar("select 1 from lan_outlets where id = $1 and location_id = $2")
            .bind(lan_outlet_id)
            .bind(location_id)
            .fetch_optional(&state.pool)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = ?e, "DB error checking lan_outlet/location pair");
                return render_error_page(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DB Fehler beim Prüfen der LAN-Dose",
                );
            }
        };

    if ok_pair.is_none() {
        return render_hosts_new_error(
            &state,
            &session,
            &form,
            "LAN-Dose gehört nicht zum gewählten Standort",
        )
        .await;
    }

    let pxe_image_id = match form
        .pxe_image_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(v) => match v.parse::<i64>() {
            Ok(id) => Some(id),
            Err(_) => {
                return render_hosts_new_error(&state, &session, &form, "Ungültiges PXE Image")
                    .await
            }
        },
        None => None,
    };

    if let Some(img_id) = pxe_image_id {
        let exists: Option<i32> =
            match sqlx::query_scalar("select 1 from pxe_images where id = $1 and enabled = true")
                .bind(img_id)
                .fetch_optional(&state.pool)
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(error = ?e, "DB error checking pxe_image_id on host create");
                    return render_error_page(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "DB Fehler beim Prüfen des PXE Images",
                    );
                }
            };

        if exists.is_none() {
            return render_hosts_new_error(&state, &session, &form, "Ungültiges PXE Image").await;
        }
    }

    tracing::debug!(
        hostname = %hostname,
        ip = %ip,
        mac = %mac_norm,
        location_id = %location_id,
        lan_outlet_id = %lan_outlet_id,
        subnet_id = %subnet_id,
        pxe_enabled,
        pxe_image_id,
        "Attempting to insert host"
    );

    let res = sqlx::query(
        "insert into hosts (hostname, ip_address, mac_address, location_id, lan_outlet_id, subnet_id, pxe_enabled, pxe_image_id)
         values ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(&hostname)
    .bind(ip.to_string())
    .bind(&mac_norm)
    .bind(location_id)
    .bind(lan_outlet_id)
    .bind(subnet_id)
    .bind(pxe_enabled)
    .bind(pxe_image_id)
    .execute(&state.pool)
    .await;

    match res {
        Ok(r) => {
            tracing::debug!(
                rows_affected = r.rows_affected(),
                "Inserted host into database"
            );
            let warning = match dnsmasq::sync_dnsmasq_hosts(
                &state.pool,
                &state.config,
                state.dnsmasq_status.as_ref(),
                None,
            )
            .await
            {
                Ok(_) => None,
                Err(e) => {
                    tracing::error!(error = ?e, "dnsmasq sync failed after host create");
                    Some(map_dnsmasq_sync_error(&e))
                }
            };
            if wants_json(&headers) {
                let payload = serde_json::json!({
                    "status": "created",
                    "dnsmasq_sync": if warning.is_some() { "failed" } else { "ok" },
                    "warning": warning,
                });
                return (StatusCode::CREATED, Json(payload)).into_response();
            }
            let redirect_url = if warning.is_some() {
                "/hosts?dnsmasq=warn"
            } else {
                "/hosts?dnsmasq=ok"
            };
            Redirect::to(redirect_url).into_response()
        }
        Err(e) => {
            let db_info = e.as_database_error();
            let code = db_info.and_then(|d| d.code()).map(|c| c.to_string());
            let constraint = db_info.and_then(|d| d.constraint()).map(str::to_string);
            tracing::error!(
                error = %e,
                code = code.as_deref().unwrap_or("unknown"),
                constraint = constraint.as_deref().unwrap_or("unknown"),
                hostname = %hostname,
                ip = %ip,
                mac = %mac_norm,
                location_id = %location_id,
                lan_outlet_id = %lan_outlet_id,
                subnet_id = %subnet_id,
                pxe_enabled,
                "Failed to insert host into database"
            );
            let msg = if let Some(db_err) = e.as_database_error() {
                let code = db_err.code().map(|c| c.to_string()).unwrap_or_default();
                if code == "23505" {
                    "Konflikt: Hostname/IP/MAC ist bereits vergeben"
                } else if code == "23503" {
                    "Ungültige Referenz (Subnet/Standort/Dose)"
                } else {
                    "Datenbankfehler beim Speichern"
                }
            } else {
                "Datenbankfehler beim Speichern"
            };
            render_hosts_new_error(&state, &session, &form, msg).await
        }
    }
}

type HostShowRowDb = (
    Uuid,
    String,
    String,
    String,
    Uuid,
    Uuid,
    Uuid,
    Option<String>,
    Option<String>,
    Option<String>,
    bool,
    Option<i64>,
    Option<String>,
);

async fn host_show(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }

    let row: HostShowRowDb = match sqlx::query_as(
        "select h.id,
                h.hostname,
                h.ip_address,
                h.mac_address,
                h.location_id,
                h.lan_outlet_id,
                h.subnet_id,
                l.name as location_name,
                o.label as lan_outlet_label,
                (s.name || ' (' || s.cidr::text || ')') as subnet_display,
                h.pxe_enabled,
                h.pxe_image_id,
                pi.name as pxe_image_name
         from hosts h
         left join locations l on l.id = h.location_id
         left join lan_outlets o on o.id = h.lan_outlet_id
         left join subnets s on s.id = h.subnet_id
         left join pxe_images pi on pi.id = h.pxe_image_id
         where h.id = $1
         limit 1",
    )
    .bind(id)
    .fetch_one(&state.pool)
    .await
    {
        Ok(v) => v,
        Err(sqlx::Error::RowNotFound) => {
            tracing::error!(host_id = %id, "host_show not found");
            return StatusCode::NOT_FOUND.into_response();
        }
        Err(e) => {
            tracing::error!(error = ?e, host_id = %id, "DB error in host_show");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let (
        hid,
        hostname,
        ip,
        mac,
        location_id,
        lan_outlet_id,
        subnet_id,
        location_name,
        lan_outlet_label,
        subnet_display,
        pxe_enabled,
        pxe_image_id,
        pxe_image_name,
    ) = row;

    let host = HostShow {
        id: hid.to_string(),
        hostname,
        ip,
        mac,
        location_id: location_id.to_string(),
        lan_outlet_id: lan_outlet_id.to_string(),
        subnet_id: subnet_id.to_string(),
        location_name,
        lan_outlet_label,
        subnet_display,
        pxe_enabled,
        pxe_image_id: pxe_image_id.map(|id| id.to_string()),
        pxe_image_name,
    };

    let mut ctx = Context::new();
    add_auth_context(&mut ctx, &session, &state).await;
    ctx.insert("host", &host);

    render(&state.templates, "host_show.html", ctx)
}

async fn host_edit(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }

    let host = match load_host_for_edit(&state.pool, id).await {
        Ok(Some(h)) => h,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let locations = match load_locations(&state.pool).await {
        Ok(v) => v,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let lan_outlets = match load_lan_outlets(&state.pool).await {
        Ok(v) => v,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let subnets = match load_subnets(&state.pool).await {
        Ok(v) => v,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let pxe_images = if state.config.pxe_enabled {
        match load_pxe_images(&state.pool).await {
            Ok(v) => v,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    } else {
        Vec::new()
    };

    let mut ctx = Context::new();
    add_auth_context(&mut ctx, &session, &state).await;
    ctx.insert("error", &Option::<String>::None);
    ctx.insert("host", &host);
    ctx.insert("locations", &locations);
    ctx.insert("lan_outlets", &lan_outlets);
    ctx.insert("subnets", &subnets);
    ctx.insert("pxe_images", &pxe_images);

    render(&state.templates, "host_edit.html", ctx)
}

async fn host_update(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<Uuid>,
    Form(form): Form<HostUpdateForm>,
) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }

    let hostname = form.hostname.trim().to_string();
    if hostname.is_empty() {
        return render_host_edit_error(
            &state,
            &session,
            id,
            &form,
            "Hostname darf nicht leer sein",
        )
        .await;
    }

    let ip: Ipv4Addr = match validate_ipv4(form.ip.trim()) {
        Ok(v) => v,
        Err(msg) => {
            return render_host_edit_error(&state, &session, id, &form, &msg).await;
        }
    };

    let mac: MacAddr = match validate_mac(form.mac.trim()) {
        Ok(v) => v,
        Err(msg) => {
            return render_host_edit_error(&state, &session, id, &form, &msg).await;
        }
    };
    let mac_norm = mac.to_string();

    let location_id: Uuid = match Uuid::parse_str(form.location_id.trim()) {
        Ok(v) => v,
        Err(_) => {
            return render_host_edit_error(&state, &session, id, &form, "Ungültiger Standort").await
        }
    };

    let lan_outlet_id: Uuid = match Uuid::parse_str(form.lan_outlet_id.trim()) {
        Ok(v) => v,
        Err(_) => {
            return render_host_edit_error(&state, &session, id, &form, "Ungültige LAN-Dose").await
        }
    };

    let subnet_id: Uuid = match Uuid::parse_str(form.subnet_id.trim()) {
        Ok(v) => v,
        Err(_) => {
            return render_host_edit_error(&state, &session, id, &form, "Ungültiges Subnet").await
        }
    };

    // IP muss im gewählten Subnet liegen
    let cidr: Option<String> =
        match sqlx::query_scalar("select cidr::text from subnets where id = $1")
            .bind(subnet_id)
            .fetch_optional(&state.pool)
            .await
        {
            Ok(v) => v,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
    let Some(cidr) = cidr else {
        return render_host_edit_error(&state, &session, id, &form, "Ungültiges Subnet").await;
    };
    let net: ipnet::Ipv4Net = match cidr.parse() {
        Ok(n) => n,
        Err(_) => {
            return render_host_edit_error(&state, &session, id, &form, "Subnet CIDR ist ungültig")
                .await
        }
    };
    if !net.contains(&ip) {
        return render_host_edit_error(
            &state,
            &session,
            id,
            &form,
            "IP liegt nicht im gewählten Subnet",
        )
        .await;
    }

    // Vor dem Update prüfen, ob Hostname/IP/MAC schon existieren (anderer Datensatz)
    if let Ok(Some((conflict_host, conflict_ip, conflict_mac))) =
        sqlx::query_as::<_, (String, String, String)>(
            "select hostname, ip_address, mac_address
             from hosts
             where id <> $1
               and (hostname = $2 or ip_address = $3 or mac_address = $4)
             limit 1",
        )
        .bind(id)
        .bind(&hostname)
        .bind(ip.to_string())
        .bind(&mac_norm)
        .fetch_optional(&state.pool)
        .await
    {
        let msg = if conflict_host == hostname {
            "Hostname ist bereits vergeben"
        } else if conflict_ip == ip.to_string() {
            "IP ist bereits vergeben"
        } else if conflict_mac == mac_norm {
            "MAC ist bereits vergeben"
        } else {
            "Hostname/IP/MAC ist bereits vergeben"
        };
        return render_host_edit_error(&state, &session, id, &form, msg).await;
    }

    let pxe_enabled = form.pxe_enabled.is_some();

    let pxe_image_id = match form
        .pxe_image_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(v) => match v.parse::<i64>() {
            Ok(id) => Some(id),
            Err(_) => {
                return render_host_edit_error(&state, &session, id, &form, "Ungültiges PXE Image")
                    .await
            }
        },
        None => None,
    };

    if let Some(img_id) = pxe_image_id {
        let exists: Option<i32> =
            match sqlx::query_scalar("select 1 from pxe_images where id = $1 and enabled = true")
                .bind(img_id)
                .fetch_optional(&state.pool)
                .await
            {
                Ok(v) => v,
                Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            };

        if exists.is_none() {
            return render_host_edit_error(&state, &session, id, &form, "Ungültiges PXE Image")
                .await;
        }
    }

    let ok_pair: Option<i32> =
        match sqlx::query_scalar("select 1 from lan_outlets where id = $1 and location_id = $2")
            .bind(lan_outlet_id)
            .bind(location_id)
            .fetch_optional(&state.pool)
            .await
        {
            Ok(v) => v,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };

    if ok_pair.is_none() {
        return render_host_edit_error(
            &state,
            &session,
            id,
            &form,
            "LAN-Dose gehört nicht zum gewählten Standort",
        )
        .await;
    }

    let res = sqlx::query(
        "update hosts
         set hostname = $1,
             ip_address = $2,
             mac_address = $3,
             location_id = $4,
             lan_outlet_id = $5,
             subnet_id = $6,
             pxe_enabled = $7,
             pxe_image_id = $8
         where id = $9",
    )
    .bind(&hostname)
    .bind(ip.to_string())
    .bind(&mac_norm)
    .bind(location_id)
    .bind(lan_outlet_id)
    .bind(subnet_id)
    .bind(pxe_enabled)
    .bind(pxe_image_id)
    .bind(id)
    .execute(&state.pool)
    .await;

    match res {
        Ok(r) => {
            if r.rows_affected() == 0 {
                StatusCode::NOT_FOUND.into_response()
            } else {
                try_sync_dnsmasq(&state, "hosts_update").await;
                Redirect::to(&format!("/hosts/{}", id)).into_response()
            }
        }
        Err(e) => {
            let msg = if let Some(db_err) = e.as_database_error() {
                let code = db_err.code().map(|c| c.to_string()).unwrap_or_default();
                if code == "23505" {
                    "Konflikt: Hostname/IP/MAC ist bereits vergeben"
                } else if code == "23503" {
                    "Ungültige Referenz (Subnet/Standort/Dose)"
                } else {
                    "Datenbankfehler beim Speichern"
                }
            } else {
                "Datenbankfehler beim Speichern"
            };
            render_host_edit_error(&state, &session, id, &form, msg).await
        }
    }
}

async fn host_delete(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }

    let res = sqlx::query("delete from hosts where id = $1")
        .bind(id)
        .execute(&state.pool)
        .await;

    match res {
        Ok(r) => {
            if r.rows_affected() == 0 {
                StatusCode::NOT_FOUND.into_response()
            } else {
                try_sync_dnsmasq(&state, "hosts_delete").await;
                Redirect::to("/hosts").into_response()
            }
        }
        Err(e) => {
            tracing::error!(error = %e, host_id = %id, "failed to delete host");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

type HostEditRowDb = (
    Uuid,
    String,
    String,
    String,
    Uuid,
    Uuid,
    Uuid,
    Option<String>,
    Option<String>,
    Option<String>,
    bool,
    Option<i64>,
    Option<String>,
);

async fn load_host_for_edit(pool: &PgPool, id: Uuid) -> Result<Option<HostShow>, ()> {
    let row: Option<HostEditRowDb> = sqlx::query_as(
        "select h.id,
                h.hostname,
                h.ip_address,
                h.mac_address,
                h.location_id,
                h.lan_outlet_id,
                h.subnet_id,
                l.name as location_name,
                o.label as lan_outlet_label,
                (s.name || ' (' || s.cidr::text || ')') as subnet_display,
                h.pxe_enabled,
                h.pxe_image_id,
                pi.name as pxe_image_name
         from hosts h
         left join locations l on l.id = h.location_id
         left join lan_outlets o on o.id = h.lan_outlet_id
         left join subnets s on s.id = h.subnet_id
         left join pxe_images pi on pi.id = h.pxe_image_id
         where h.id = $1
         limit 1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|_| ())?;

    Ok(row.map(
        |(
            hid,
            hostname,
            ip,
            mac,
            location_id,
            lan_outlet_id,
            subnet_id,
            location_name,
            lan_outlet_label,
            subnet_display,
            pxe_enabled,
            pxe_image_id,
            pxe_image_name,
        )| HostShow {
            id: hid.to_string(),
            hostname,
            ip,
            mac,
            location_id: location_id.to_string(),
            lan_outlet_id: lan_outlet_id.to_string(),
            subnet_id: subnet_id.to_string(),
            location_name,
            lan_outlet_label,
            subnet_display,
            pxe_enabled,
            pxe_image_id: pxe_image_id.map(|id| id.to_string()),
            pxe_image_name,
        },
    ))
}

/* ----------------------------- Locations (SSR) ----------------------------- */

async fn locations_list(State(state): State<AppState>, session: Session) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }

    let rows: Vec<(String,)> = match sqlx::query_as("select name from locations order by name asc")
        .fetch_all(&state.pool)
        .await
    {
        Ok(v) => v,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let locations: Vec<LocationRow> = rows
        .into_iter()
        .map(|(name,)| LocationRow { name })
        .collect();

    let mut ctx = Context::new();
    add_auth_context(&mut ctx, &session, &state).await;
    ctx.insert("locations", &locations);

    render(&state.templates, "locations_list.html", ctx)
}

async fn locations_new(State(state): State<AppState>, session: Session) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }

    let mut ctx = Context::new();
    add_auth_context(&mut ctx, &session, &state).await;
    ctx.insert("error", &Option::<String>::None);

    render(&state.templates, "locations_new.html", ctx)
}

async fn locations_create(
    State(state): State<AppState>,
    session: Session,
    Form(form): Form<LocationCreateForm>,
) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }

    let name = form.name.trim().to_string();
    if name.is_empty() {
        return render_locations_new_error(&state, &session, "Name darf nicht leer sein").await;
    }

    let res = sqlx::query("insert into locations (name) values ($1)")
        .bind(&name)
        .execute(&state.pool)
        .await;

    match res {
        Ok(_) => Redirect::to("/locations").into_response(),
        Err(e) => {
            let msg = if let Some(db_err) = e.as_database_error() {
                let code = db_err.code().map(|c| c.to_string()).unwrap_or_default();
                if code == "23505" {
                    "Standort existiert bereits"
                } else {
                    "Datenbankfehler beim Speichern"
                }
            } else {
                "Datenbankfehler beim Speichern"
            };
            render_locations_new_error(&state, &session, msg).await
        }
    }
}

async fn render_locations_new_error(state: &AppState, session: &Session, msg: &str) -> Response {
    let mut ctx = Context::new();
    add_auth_context(&mut ctx, session, state).await;
    ctx.insert("error", &Some(msg.to_string()));
    render(&state.templates, "locations_new.html", ctx)
}

/* ----------------------------- LAN Outlets (SSR) ----------------------------- */

async fn lan_outlets_list(State(state): State<AppState>, session: Session) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }

    let rows: Vec<(String, String, Option<String>)> = match sqlx::query_as(
        "select l.name as location_name, o.label, o.description
         from lan_outlets o
         join locations l on l.id = o.location_id
         order by l.name asc, o.label asc",
    )
    .fetch_all(&state.pool)
    .await
    {
        Ok(v) => v,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let lan_outlets: Vec<LanOutletRow> = rows
        .into_iter()
        .map(|(location_name, label, description)| LanOutletRow {
            location_name,
            label,
            description,
        })
        .collect();

    let mut ctx = Context::new();
    add_auth_context(&mut ctx, &session, &state).await;
    ctx.insert("lan_outlets", &lan_outlets);

    render(&state.templates, "lan_outlets_list.html", ctx)
}

async fn lan_outlets_new(State(state): State<AppState>, session: Session) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }

    let locations = match load_locations(&state.pool).await {
        Ok(v) => v,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let mut ctx = Context::new();
    add_auth_context(&mut ctx, &session, &state).await;
    ctx.insert("error", &Option::<String>::None);
    ctx.insert("locations", &locations);

    render(&state.templates, "lan_outlets_new.html", ctx)
}

async fn lan_outlets_create(
    State(state): State<AppState>,
    session: Session,
    Form(form): Form<LanOutletCreateForm>,
) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }

    let location_id: Uuid = match Uuid::parse_str(form.location_id.trim()) {
        Ok(v) => v,
        Err(_) => {
            return render_lan_outlets_new_error(&state, &session, "Ungültiger Standort").await
        }
    };

    let label = form.label.trim().to_string();
    if label.is_empty() {
        return render_lan_outlets_new_error(&state, &session, "Label darf nicht leer sein").await;
    }

    let description = form
        .description
        .as_deref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let res = sqlx::query(
        "insert into lan_outlets (location_id, label, description) values ($1, $2, $3)",
    )
    .bind(location_id)
    .bind(&label)
    .bind(&description)
    .execute(&state.pool)
    .await;

    match res {
        Ok(_) => Redirect::to("/lan-outlets").into_response(),
        Err(e) => {
            let msg = if let Some(db_err) = e.as_database_error() {
                let code = db_err.code().map(|c| c.to_string()).unwrap_or_default();
                if code == "23505" {
                    "LAN-Dose existiert an diesem Standort bereits"
                } else if code == "23503" {
                    "Standort existiert nicht"
                } else {
                    "Datenbankfehler beim Speichern"
                }
            } else {
                "Datenbankfehler beim Speichern"
            };
            render_lan_outlets_new_error(&state, &session, msg).await
        }
    }
}

async fn render_lan_outlets_new_error(state: &AppState, session: &Session, msg: &str) -> Response {
    let locations = match load_locations(&state.pool).await {
        Ok(v) => v,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let mut ctx = Context::new();
    add_auth_context(&mut ctx, session, state).await;
    ctx.insert("error", &Some(msg.to_string()));
    ctx.insert("locations", &locations);
    render(&state.templates, "lan_outlets_new.html", ctx)
}

/* ----------------------------- Subnets (SSR) ----------------------------- */

type SubnetsListRowDb = (
    Uuid,
    String,
    String,
    Option<String>,
    Option<String>,
    bool,
    Option<String>,
    Option<String>,
    bool,
);

async fn subnets_list(State(state): State<AppState>, session: Session) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }

    let rows: Vec<SubnetsListRowDb> = match sqlx::query_as(
        "select id,
                name,
                cidr::text,
                dns_zone,
                reverse_zone,
                dhcp_enabled,
                host(dhcp_pool_start),
                host(dhcp_pool_end),
                pxe_enabled
         from subnets
         order by name asc",
    )
    .fetch_all(&state.pool)
    .await
    {
        Ok(v) => v,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let subnets: Vec<SubnetRow> = rows
        .into_iter()
        .map(
            |(
                id,
                name,
                cidr,
                dns_zone,
                reverse_zone,
                dhcp_enabled,
                dhcp_pool_start,
                dhcp_pool_end,
                pxe_enabled,
            )| SubnetRow {
                id: id.to_string(),
                name,
                cidr,
                dns_zone,
                reverse_zone,
                dhcp_enabled,
                dhcp_pool_start,
                dhcp_pool_end,
                pxe_enabled,
            },
        )
        .collect();

    let mut ctx = Context::new();
    add_auth_context(&mut ctx, &session, &state).await;
    ctx.insert("subnets", &subnets);

    render(&state.templates, "subnets_list.html", ctx)
}

async fn subnets_new(State(state): State<AppState>, session: Session) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }

    let mut ctx = Context::new();
    add_auth_context(&mut ctx, &session, &state).await;
    ctx.insert("error", &Option::<String>::None);

    render(&state.templates, "subnets_new.html", ctx)
}

async fn subnets_create(
    State(state): State<AppState>,
    session: Session,
    Form(form): Form<SubnetCreateForm>,
) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }

    let name = form.name.trim().to_string();
    if name.is_empty() {
        return render_subnets_new_error(&state, &session, "Name darf nicht leer sein").await;
    }

    let cidr_raw = form.cidr.trim();
    let cidr: IpNet = match cidr_raw.parse() {
        Ok(v) => v,
        Err(_) => return render_subnets_new_error(&state, &session, "Ungültiges CIDR").await,
    };

    let dns_zone = form
        .dns_zone
        .as_deref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let reverse_zone = form
        .reverse_zone
        .as_deref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let dhcp_enabled = form.dhcp_enabled.is_some();
    let pxe_enabled = form.pxe_enabled.is_some();

    let dhcp_pool_start = form
        .dhcp_pool_start
        .as_deref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let dhcp_pool_end = form
        .dhcp_pool_end
        .as_deref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    if dhcp_pool_start.is_some() ^ dhcp_pool_end.is_some() {
        return render_subnets_new_error(
            &state,
            &session,
            "Ungültige DHCP-Pool Range: Start und Ende müssen beide gesetzt sein oder beide leer sein.",
        )
        .await;
    }

    let res = sqlx::query(
        "insert into subnets (name, cidr, dns_zone, reverse_zone, dhcp_enabled, pxe_enabled, dhcp_pool_start, dhcp_pool_end)
         values ($1, $2, $3, $4, $5, $6, $7::inet, $8::inet)",
    )
    .bind(&name)
    .bind(cidr.to_string())
    .bind(&dns_zone)
    .bind(&reverse_zone)
    .bind(dhcp_enabled)
    .bind(pxe_enabled)
    .bind(&dhcp_pool_start)
    .bind(&dhcp_pool_end)
    .execute(&state.pool)
    .await;

    match res {
        Ok(_) => Redirect::to("/subnets").into_response(),
        Err(e) => {
            tracing::warn!(error = ?e, "subnet insert failed");

            let msg = if let Some(db_err) = e.as_database_error() {
                let code = db_err.code().map(|c| c.to_string()).unwrap_or_default();

                match code.as_str() {
                    "23505" => "Subnet existiert bereits (Name/CIDR)",
                    "23514" => "Ungültige DHCP-Pool Range: Start und Ende müssen beide gesetzt sein oder beide leer sein.",
                    "22P02" => "Ungültige IP-Adresse in DHCP Pool Start/Ende.",
                    _ => "Datenbankfehler beim Speichern",
                }
            } else {
                "Datenbankfehler beim Speichern"
            };

            render_subnets_new_error(&state, &session, msg).await
        }
    }
}

async fn subnets_edit(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }

    let row: Option<SubnetsListRowDb> = match sqlx::query_as(
        "select id,
                name,
                cidr::text,
                dns_zone,
                reverse_zone,
                dhcp_enabled,
                host(dhcp_pool_start),
                host(dhcp_pool_end),
                pxe_enabled
         from subnets
         where id = $1
         limit 1",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(v) => v,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let Some((
        sid,
        name,
        cidr,
        dns_zone,
        reverse_zone,
        dhcp_enabled,
        dhcp_pool_start,
        dhcp_pool_end,
        pxe_enabled,
    )) = row
    else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let subnet = SubnetEdit {
        id: sid.to_string(),
        name,
        cidr,
        dns_zone,
        reverse_zone,
        dhcp_enabled,
        dhcp_pool_start,
        dhcp_pool_end,
        pxe_enabled,
    };

    let mut ctx = Context::new();
    add_auth_context(&mut ctx, &session, &state).await;
    ctx.insert("error", &Option::<String>::None);
    ctx.insert("subnet", &subnet);
    render(&state.templates, "subnets_edit.html", ctx)
}

async fn subnets_update(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<Uuid>,
    Form(form): Form<SubnetUpdateForm>,
) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }

    let name = form.name.trim().to_string();
    if name.is_empty() {
        return render_subnets_edit_error(&state, &session, id, &form, "Name darf nicht leer sein")
            .await;
    }

    let cidr_raw = form.cidr.trim();
    let cidr: IpNet = match cidr_raw.parse() {
        Ok(v) => v,
        Err(_) => {
            return render_subnets_edit_error(&state, &session, id, &form, "Ungültiges CIDR").await
        }
    };

    let dns_zone = form
        .dns_zone
        .as_deref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let reverse_zone = form
        .reverse_zone
        .as_deref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let dhcp_enabled = form.dhcp_enabled.is_some();
    let pxe_enabled = form.pxe_enabled.is_some();

    let dhcp_pool_start = form
        .dhcp_pool_start
        .as_deref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let dhcp_pool_end = form
        .dhcp_pool_end
        .as_deref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    if dhcp_pool_start.is_some() ^ dhcp_pool_end.is_some() {
        return render_subnets_edit_error(
            &state,
            &session,
            id,
            &form,
            "Ungültige DHCP-Pool Range: Start und Ende müssen beide gesetzt sein oder beide leer sein.",
        )
        .await;
    }

    let res = sqlx::query(
        "update subnets
         set name = $1,
             cidr = $2,
             dns_zone = $3,
             reverse_zone = $4,
             dhcp_enabled = $5,
             pxe_enabled = $6,
             dhcp_pool_start = $7::inet,
             dhcp_pool_end = $8::inet
         where id = $9",
    )
    .bind(&name)
    .bind(cidr.to_string())
    .bind(&dns_zone)
    .bind(&reverse_zone)
    .bind(dhcp_enabled)
    .bind(pxe_enabled)
    .bind(&dhcp_pool_start)
    .bind(&dhcp_pool_end)
    .bind(id)
    .execute(&state.pool)
    .await;

    match res {
        Ok(r) => {
            if r.rows_affected() == 0 {
                StatusCode::NOT_FOUND.into_response()
            } else {
                Redirect::to("/subnets").into_response()
            }
        }
        Err(e) => {
            tracing::warn!(error = ?e, "subnet update failed");

            let msg = if let Some(db_err) = e.as_database_error() {
                let code = db_err.code().map(|c| c.to_string()).unwrap_or_default();
                match code.as_str() {
                    "23505" => "Subnet existiert bereits (Name/CIDR)",
                    "23514" => "Ungültige DHCP-Pool Range: Start und Ende müssen beide gesetzt sein oder beide leer sein.",
                    "22P02" => "Ungültige IP-Adresse in DHCP Pool Start/Ende.",
                    _ => "Datenbankfehler beim Speichern",
                }
            } else {
                "Datenbankfehler beim Speichern"
            };

            render_subnets_edit_error(&state, &session, id, &form, msg).await
        }
    }
}

async fn render_subnets_edit_error(
    state: &AppState,
    session: &Session,
    id: Uuid,
    form: &SubnetUpdateForm,
    msg: &str,
) -> Response {
    let subnet = SubnetEdit {
        id: id.to_string(),
        name: form.name.trim().to_string(),
        cidr: form.cidr.trim().to_string(),
        dns_zone: form
            .dns_zone
            .as_deref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        reverse_zone: form
            .reverse_zone
            .as_deref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        dhcp_enabled: form.dhcp_enabled.is_some(),
        dhcp_pool_start: form
            .dhcp_pool_start
            .as_deref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        dhcp_pool_end: form
            .dhcp_pool_end
            .as_deref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        pxe_enabled: form.pxe_enabled.is_some(),
    };

    let mut ctx = Context::new();
    add_auth_context(&mut ctx, session, state).await;
    ctx.insert("error", &Some(msg.to_string()));
    ctx.insert("subnet", &subnet);
    render(&state.templates, "subnets_edit.html", ctx)
}

async fn render_subnets_new_error(state: &AppState, session: &Session, msg: &str) -> Response {
    let mut ctx = Context::new();
    add_auth_context(&mut ctx, session, state).await;
    ctx.insert("error", &Some(msg.to_string()));
    render(&state.templates, "subnets_new.html", ctx)
}

/* ----------------------------- API Handlers ----------------------------- */

async fn api_login(
    State(state): State<AppState>,
    session: Session,
    Json(req): Json<LoginRequest>,
) -> StatusCode {
    let row: Option<(String, String)> = match sqlx::query_as(
        "select password_hash, role from users where username = $1 and is_active = true",
    )
    .bind(&req.username)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(v) => v,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR,
    };

    let Some((hash, role)) = row else {
        return StatusCode::UNAUTHORIZED;
    };

    match bcrypt::verify(&req.password, &hash) {
        Ok(true) => {
            if session.insert("username", &req.username).await.is_err() {
                return StatusCode::INTERNAL_SERVER_ERROR;
            }
            if session.insert("role", &role).await.is_err() {
                return StatusCode::INTERNAL_SERVER_ERROR;
            }
            StatusCode::OK
        }
        _ => StatusCode::UNAUTHORIZED,
    }
}

async fn api_me(session: Session) -> Result<Json<MeResponse>, StatusCode> {
    let username: Option<String> = session
        .get("username")
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let role: Option<String> = session
        .get("role")
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match (username, role) {
        (Some(username), Some(role)) => Ok(Json(MeResponse { username, role })),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

async fn api_lan_outlets_by_location(
    State(state): State<AppState>,
    session: Session,
    Query(q): Query<LanOutletsQuery>,
) -> Result<Json<Vec<LanOutletApiItem>>, StatusCode> {
    require_auth_api(&session).await?;

    let location_id = Uuid::parse_str(q.location_id.trim()).map_err(|_| StatusCode::BAD_REQUEST)?;

    let rows: Vec<(Uuid, String)> = sqlx::query_as(
        "select id, label
         from lan_outlets
         where location_id = $1
         order by label asc",
    )
    .bind(location_id)
    .fetch_all(&state.pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let items = rows
        .into_iter()
        .map(|(id, label)| LanOutletApiItem {
            id: id.to_string(),
            label,
        })
        .collect();

    Ok(Json(items))
}

async fn api_find_free_ip(
    State(state): State<AppState>,
    session: Session,
    Query(q): Query<FindFreeIpQuery>,
) -> Response {
    if let Err(resp) = require_auth_api(&session).await {
        return resp.into_response();
    }

    let subnet_id = match Uuid::parse_str(q.subnet_id.trim()) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "Ungültiges Subnet").into_response(),
    };

    match find_free_ip(&state, subnet_id).await {
        Ok(ip) => Json(serde_json::json!({ "free_ip": ip.to_string() })).into_response(),
        Err(e) => {
            tracing::warn!(error = %e, subnet_id = %subnet_id, "find_free_ip failed");
            (StatusCode::NOT_FOUND, e).into_response()
        }
    }
}

async fn api_hosts(
    State(state): State<AppState>,
    session: Session,
    Query(q): Query<HostsApiQuery>,
) -> Result<Json<HostsApiResponse>, StatusCode> {
    require_auth_api(&session).await?;

    let search = q.q.unwrap_or_default();
    let search = search.trim().to_string();
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(50).clamp(1, 200);
    let offset = (page - 1) as i64 * per_page as i64;

    let (total, rows): (i64, Vec<HostsListRowDb>) = if search.is_empty() {
        let total: i64 = sqlx::query_scalar("select count(*) from hosts")
            .fetch_one(&state.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "DB error in api_hosts count");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        let rows: Vec<HostsListRowDb> = sqlx::query_as(
            "select h.id,
                    h.hostname,
                    h.ip_address,
                    h.mac_address,
                    l.name as location_name,
                    o.label as lan_outlet_label,
                    h.pxe_enabled,
                    pi.name as pxe_image_name
             from hosts h
             left join locations l on l.id = h.location_id
             left join lan_outlets o on o.id = h.lan_outlet_id
             left join pxe_images pi on pi.id = h.pxe_image_id
             order by h.hostname asc
             limit $1 offset $2",
        )
        .bind(per_page as i64)
        .bind(offset)
        .fetch_all(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "DB error in api_hosts list");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        (total, rows)
    } else {
        let like = format!("%{}%", search);
        let total: i64 = sqlx::query_scalar(
            "select count(*)
             from hosts h
             where h.hostname ilike $1
                or h.ip_address ilike $1
                or h.mac_address ilike $1",
        )
        .bind(&like)
        .fetch_one(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "DB error in api_hosts count search");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        let rows: Vec<HostsListRowDb> = sqlx::query_as(
            "select h.id,
                    h.hostname,
                    h.ip_address,
                    h.mac_address,
                    l.name as location_name,
                    o.label as lan_outlet_label,
                    h.pxe_enabled,
                    pi.name as pxe_image_name
             from hosts h
             left join locations l on l.id = h.location_id
             left join lan_outlets o on o.id = h.lan_outlet_id
             left join pxe_images pi on pi.id = h.pxe_image_id
             where h.hostname ilike $1
                or h.ip_address ilike $1
                or h.mac_address ilike $1
             order by h.hostname asc
             limit $2 offset $3",
        )
        .bind(&like)
        .bind(per_page as i64)
        .bind(offset)
        .fetch_all(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "DB error in api_hosts search");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        (total, rows)
    };

    let items = rows
        .into_iter()
        .map(
            |(id, hostname, ip, mac, _location_name, _lan_outlet_label, pxe_enabled, pxe_image_name)| {
                HostApiItem {
                    id: id.to_string(),
                    hostname,
                    ip,
                    mac,
                    pxe_enabled,
                    pxe_image_name,
                }
            },
        )
        .collect();

    let total_pages = if total == 0 {
        1
    } else {
        ((total as f64) / (per_page as f64)).ceil() as u32
    };

    Ok(Json(HostsApiResponse {
        items,
        page,
        per_page,
        total,
        total_pages,
    }))
}

async fn api_dnsmasq_status(
    State(state): State<AppState>,
    session: Session,
) -> Result<Json<DnsmasqSyncStatusResponse>, StatusCode> {
    require_auth_api(&session).await?;

    let status = state.dnsmasq_status.lock().await.clone();
    let (last_test_ok, last_test_at, last_test_error) = match status.last_test {
        Some(test) => (Some(test.ok), Some(test.at), test.stderr),
        None => (None, None, None),
    };

    let tftp_files = list_tftp_files(StdPath::new(&state.config.tftp_root_dir)).await;
    let tftp_set: HashSet<String> = tftp_files.iter().cloned().collect();
    let orphaned_hosts = load_orphaned_hosts(&state.pool, &tftp_set).await;
    let audit_logs = load_audit_logs(&state.pool).await;

    Ok(Json(DnsmasqSyncStatusResponse {
        last_restart_at: status.last_restart_at,
        last_test_ok,
        last_test_at,
        last_test_error,
        tftp_files,
        orphaned_hosts,
        warnings: status.warnings,
        audit_logs,
    }))
}

async fn api_admin_shutdown(
    State(state): State<AppState>,
    session: Session,
) -> Result<StatusCode, StatusCode> {
    require_auth_api(&session).await?;

    let mut guard = state.shutdown_tx.lock().await;
    if let Some(tx) = guard.take() {
        let _ = tx.send(());
        Ok(StatusCode::ACCEPTED)
    } else {
        Ok(StatusCode::GONE)
    }
}

/* ----------------------------- PXE / iPXE ----------------------------- */

fn validate_pxe_form(
    cfg: &Config,
    form: &PxeImageForm,
    files: &[String],
) -> Result<ValidatedPxe, String> {
    let name = form.name.trim();
    if !valid_name(name) {
        return Err("Name ist ungültig (erlaubt: A-Z, a-z, 0-9, ._- )".to_string());
    }

    let kind = form.kind.trim().to_lowercase();
    if kind != "linux" && kind != "chain" {
        return Err("Ungültiger Typ (kind)".to_string());
    }

    let arch = form.arch.trim().to_lowercase();
    if arch != "any" && arch != "bios" && arch != "uefi" {
        return Err("Ungültige Architektur".to_string());
    }

    let enabled = form.enabled.is_some();
    let cmdline = form
        .cmdline
        .as_deref()
        .map(|s| sanitize_cmdline(s.trim()))
        .filter(|s| !s.is_empty());

    let kernel_path = form
        .kernel_path
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let initrd_path = form
        .initrd_path
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let chain_url = form
        .chain_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let root = StdPath::new(&cfg.pxe_root_dir);

    if kind == "linux" {
        let kernel = kernel_path
            .clone()
            .ok_or_else(|| "Kernel-Pfad ist erforderlich".to_string())?;
        if !files.contains(&kernel) && !ensure_path_allowed(root, &kernel) {
            return Err("Kernel-Pfad ist ungültig oder existiert nicht".to_string());
        }
        if let Some(initrd) = initrd_path.as_ref() {
            if !files.contains(initrd) && !ensure_path_allowed(root, initrd) {
                return Err("Initrd-Pfad ist ungültig oder existiert nicht".to_string());
            }
        }
    } else if kind == "chain" {
        let url = chain_url
            .clone()
            .ok_or_else(|| "Chain-URL ist erforderlich".to_string())?;
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err("Chain-URL muss mit http:// oder https:// beginnen".to_string());
        }
    }

    Ok(ValidatedPxe {
        name: name.to_string(),
        kind,
        arch,
        kernel_path,
        initrd_path,
        chain_url,
        cmdline,
        enabled,
    })
}

type PxeImagesListRowDb = (
    i64,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    bool,
);

async fn list_pxe_images(pool: &PgPool) -> Result<Vec<PxeImage>, ()> {
    let rows: Result<Vec<PxeImagesListRowDb>, _> = sqlx::query_as(
        "select id,
                name,
                kind,
                arch,
                kernel_path,
                initrd_path,
                chain_url,
                cmdline,
                enabled
         from pxe_images
         order by name asc",
    )
    .fetch_all(pool)
    .await;

    rows.map_err(|_| ()).map(|v| {
        v.into_iter()
            .map(
                |(id, name, kind, arch, kernel_path, initrd_path, chain_url, cmdline, enabled)| {
                    PxeImage {
                        id,
                        name,
                        kind,
                        arch,
                        kernel_path,
                        initrd_path,
                        chain_url,
                        cmdline,
                        enabled,
                    }
                },
            )
            .collect()
    })
}

async fn get_pxe_image(pool: &PgPool, id: i64) -> Result<Option<PxeImage>, ()> {
    let row: Result<Option<PxeImagesListRowDb>, _> = sqlx::query_as(
        "select id,
                name,
                kind,
                arch,
                kernel_path,
                initrd_path,
                chain_url,
                cmdline,
                enabled
         from pxe_images
         where id = $1
         limit 1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await;

    row.map_err(|_| ()).map(|opt| {
        opt.map(
            |(id, name, kind, arch, kernel_path, initrd_path, chain_url, cmdline, enabled)| {
                PxeImage {
                    id,
                    name,
                    kind,
                    arch,
                    kernel_path,
                    initrd_path,
                    chain_url,
                    cmdline,
                    enabled,
                }
            },
        )
    })
}

async fn insert_pxe_image(pool: &PgPool, data: &ValidatedPxe) -> Result<i64, String> {
    let res = sqlx::query_scalar(
        "insert into pxe_images (name, kind, arch, kernel_path, initrd_path, chain_url, cmdline, enabled)
         values ($1, $2, $3, $4, $5, $6, $7, $8)
         returning id",
    )
    .bind(&data.name)
    .bind(&data.kind)
    .bind(&data.arch)
    .bind(&data.kernel_path)
    .bind(&data.initrd_path)
    .bind(&data.chain_url)
    .bind(&data.cmdline)
    .bind(data.enabled)
    .fetch_one(pool)
    .await;

    match res {
        Ok(id) => Ok(id),
        Err(e) => {
            if let Some(db_err) = e.as_database_error() {
                let code = db_err.code().map(|c| c.to_string()).unwrap_or_default();
                if code == "23505" {
                    return Err("Name ist bereits vorhanden".to_string());
                }
                if code == "23514" {
                    return Err("Daten sind ungültig (Constraint verletzt)".to_string());
                }
            }
            Err("Datenbankfehler beim Speichern".to_string())
        }
    }
}

async fn update_pxe_image(pool: &PgPool, id: i64, data: &ValidatedPxe) -> Result<(), String> {
    let res = sqlx::query(
        "update pxe_images
         set name = $1,
             kind = $2,
             arch = $3,
             kernel_path = $4,
             initrd_path = $5,
             chain_url = $6,
             cmdline = $7,
             enabled = $8
         where id = $9",
    )
    .bind(&data.name)
    .bind(&data.kind)
    .bind(&data.arch)
    .bind(&data.kernel_path)
    .bind(&data.initrd_path)
    .bind(&data.chain_url)
    .bind(&data.cmdline)
    .bind(data.enabled)
    .bind(id)
    .execute(pool)
    .await;

    match res {
        Ok(r) => {
            if r.rows_affected() == 0 {
                Err("Eintrag nicht gefunden".to_string())
            } else {
                Ok(())
            }
        }
        Err(e) => {
            if let Some(db_err) = e.as_database_error() {
                let code = db_err.code().map(|c| c.to_string()).unwrap_or_default();
                if code == "23505" {
                    return Err("Name ist bereits vorhanden".to_string());
                }
                if code == "23514" {
                    return Err("Daten sind ungültig (Constraint verletzt)".to_string());
                }
            }
            Err("Datenbankfehler beim Speichern".to_string())
        }
    }
}

async fn delete_pxe_image(pool: &PgPool, id: i64) -> Result<(), ()> {
    sqlx::query("delete from pxe_images where id = $1")
        .bind(id)
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(|_| ())
}

async fn boot_ipxe(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    let client_ip = addr.ip();
    if !state.config.pxe_enabled {
        tracing::info!(
            "PXE Boot request from {} - Status: Exit",
            client_ip
        );
        return StatusCode::NOT_FOUND.into_response();
    }

    let should_boot = match sqlx::query_scalar::<_, bool>(
        "select pxe_enabled from hosts where ip_address = $1 limit 1",
    )
    .bind(client_ip.to_string())
    .fetch_optional(&state.pool)
    .await
    {
        Ok(Some(enabled)) => enabled,
        Ok(None) => false,
        Err(e) => {
            tracing::error!(
                error = ?e,
                ip = %client_ip,
                "failed to load host pxe flag"
            );
            false
        }
    };

    let script = if should_boot {
        let assets_base = state.config.pxe_http_base_url.as_str().trim_end_matches('/');
        tracing::info!(
            "PXE Boot request from {} - Status: Authorized",
            client_ip
        );
        format!(
            "#!ipxe\nkernel {}/vmlinuz initrd=initrd.img root=/dev/ram0\ninitrd {}/initrd.img\nboot\n",
            assets_base, assets_base
        )
    } else {
        tracing::info!(
            "PXE Boot request from {} - Status: Exit",
            client_ip
        );
        "#!ipxe\nexit\n".to_string()
    };

    (
        axum::http::HeaderMap::from_iter(std::iter::once((
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("text/plain; charset=utf-8"),
        ))),
        script,
    )
        .into_response()
}

async fn pxe_images_list(
    State(state): State<AppState>,
    session: Session,
    Query(q): Query<HostsQuery>,
) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }
    if !state.config.pxe_enabled {
        return StatusCode::NOT_FOUND.into_response();
    }

    let search = q.q.unwrap_or_default();
    let images = match list_pxe_images(&state.pool).await {
        Ok(v) => v,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let filtered = if search.trim().is_empty() {
        images.clone()
    } else {
        let like = search.to_lowercase();
        images
            .into_iter()
            .filter(|img| {
                img.name.to_lowercase().contains(&like)
                    || img.arch.to_lowercase().contains(&like)
                    || img.kind.to_lowercase().contains(&like)
            })
            .collect::<Vec<_>>()
    };

    let mut ctx = Context::new();
    add_auth_context(&mut ctx, &session, &state).await;
    ctx.insert("images", &filtered);
    ctx.insert("search_query", &search);
    ctx.insert("pxe_enabled", &state.config.pxe_enabled);
    render(&state.templates, "pxe_images_list.html", ctx)
}

async fn pxe_images_new(State(state): State<AppState>, session: Session) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }
    if !state.config.pxe_enabled {
        return StatusCode::NOT_FOUND.into_response();
    }

    let files = list_pxe_files(StdPath::new(&state.config.pxe_root_dir));

    let mut ctx = Context::new();
    add_auth_context(&mut ctx, &session, &state).await;
    ctx.insert("error", &Option::<String>::None);
    ctx.insert("files", &files);
    ctx.insert(
        "form",
        &serde_json::json!({
            "name": "",
            "kind": "linux",
            "arch": "any",
            "kernel_path": "",
            "initrd_path": "",
            "chain_url": "",
            "cmdline": "",
            "enabled": true
        }),
    );
    ctx.insert("pxe_enabled", &state.config.pxe_enabled);
    render(&state.templates, "pxe_images_new.html", ctx)
}

async fn pxe_images_create(
    State(state): State<AppState>,
    session: Session,
    Form(form): Form<PxeImageForm>,
) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }
    if !state.config.pxe_enabled {
        return StatusCode::NOT_FOUND.into_response();
    }

    let files = list_pxe_files(StdPath::new(&state.config.pxe_root_dir));

    let validated = match validate_pxe_form(&state.config, &form, &files) {
        Ok(v) => v,
        Err(msg) => return render_pxe_new_error(&state, &session, &files, &form, &msg).await,
    };

    match insert_pxe_image(&state.pool, &validated).await {
        Ok(_) => Redirect::to("/pxe/images").into_response(),
        Err(msg) => render_pxe_new_error(&state, &session, &files, &form, &msg).await,
    }
}

async fn pxe_images_edit(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<i64>,
) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }
    if !state.config.pxe_enabled {
        return StatusCode::NOT_FOUND.into_response();
    }

    let image = match get_pxe_image(&state.pool, id).await {
        Ok(Some(v)) => v,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let files = list_pxe_files(StdPath::new(&state.config.pxe_root_dir));

    let mut ctx = Context::new();
    add_auth_context(&mut ctx, &session, &state).await;
    ctx.insert("error", &Option::<String>::None);
    ctx.insert("files", &files);
    ctx.insert("image", &image);
    ctx.insert("pxe_enabled", &state.config.pxe_enabled);

    render(&state.templates, "pxe_images_edit.html", ctx)
}

async fn pxe_images_update(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<i64>,
    Form(form): Form<PxeImageForm>,
) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }
    if !state.config.pxe_enabled {
        return StatusCode::NOT_FOUND.into_response();
    }

    let files = list_pxe_files(StdPath::new(&state.config.pxe_root_dir));
    let validated = match validate_pxe_form(&state.config, &form, &files) {
        Ok(v) => v,
        Err(msg) => return render_pxe_edit_error(&state, &session, id, &files, &form, &msg).await,
    };

    match update_pxe_image(&state.pool, id, &validated).await {
        Ok(_) => Redirect::to("/pxe/images").into_response(),
        Err(msg) => render_pxe_edit_error(&state, &session, id, &files, &form, &msg).await,
    }
}

async fn pxe_images_delete(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<i64>,
) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }
    if !state.config.pxe_enabled {
        return StatusCode::NOT_FOUND.into_response();
    }

    let _ = delete_pxe_image(&state.pool, id).await;
    Redirect::to("/pxe/images").into_response()
}

/* ----------------------------- Rendering helpers ----------------------------- */

fn render(tera: &Tera, template: &str, ctx: Context) -> Response {
    match tera.render(template, &ctx) {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!(
                template = %template,
                error = ?e,
                "template render failed"
            );
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn render_error_page(status: StatusCode, message: &str) -> Response {
    (
        status,
        Html(format!(
            "<h1>Fehler</h1><p>{}</p>",
            html_escape::encode_text(message)
        )),
    )
        .into_response()
}

async fn render_login_error(state: &AppState, session: &Session, msg: &str) -> Response {
    let mut ctx = Context::new();
    add_auth_context(&mut ctx, session, state).await;
    ctx.insert("error", &Some(msg.to_string()));
    render(&state.templates, "login.html", ctx)
}

async fn render_hosts_new_error(
    state: &AppState,
    session: &Session,
    form: &HostCreateForm,
    msg: &str,
) -> Response {
    let locations = match load_locations(&state.pool).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = ?e, "DB error in render_hosts_new_error locations");
            return render_error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB Fehler beim Laden der Standorte",
            );
        }
    };
    let lan_outlets = match load_lan_outlets(&state.pool).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = ?e, "DB error in render_hosts_new_error lan_outlets");
            return render_error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB Fehler beim Laden der LAN-Dosen",
            );
        }
    };
    let subnets = match load_subnets(&state.pool).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = ?e, "DB error in render_hosts_new_error subnets");
            return render_error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB Fehler beim Laden der Subnets",
            );
        }
    };
    let pxe_images = if state.config.pxe_enabled {
        match load_pxe_images(&state.pool).await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = ?e, "DB error in render_hosts_new_error pxe_images");
                return render_error_page(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DB Fehler beim Laden der PXE Images",
                );
            }
        }
    } else {
        Vec::new()
    };

    let mut ctx = Context::new();
    add_auth_context(&mut ctx, session, state).await;
    ctx.insert("error", &Some(msg.to_string()));
    ctx.insert("locations", &locations);
    ctx.insert("lan_outlets", &lan_outlets);
    ctx.insert("subnets", &subnets);
    ctx.insert("pxe_images", &pxe_images);
    let suggested_ip = if let Ok(subnet_uuid) = Uuid::parse_str(form.subnet_id.trim()) {
        find_free_ip(state, subnet_uuid)
            .await
            .ok()
            .map(|ip| ip.to_string())
    } else {
        None
    };
    ctx.insert("suggested_ip", &suggested_ip);
    ctx.insert(
        "form",
        &serde_json::json!({
            "hostname": form.hostname.trim(),
            "ip": form.ip.trim(),
            "mac": form.mac.trim(),
            "location_id": form.location_id.trim(),
            "lan_outlet_id": form.lan_outlet_id.trim(),
            "subnet_id": form.subnet_id.trim(),
            "pxe_enabled": form.pxe_enabled.is_some(),
            "pxe_image_id": form.pxe_image_id.as_deref().unwrap_or("").trim()
        }),
    );

    render(&state.templates, "hosts_new.html", ctx)
}

async fn render_host_edit_error(
    state: &AppState,
    session: &Session,
    id: Uuid,
    form: &HostUpdateForm,
    msg: &str,
) -> Response {
    let locations = match load_locations(&state.pool).await {
        Ok(v) => v,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let lan_outlets = match load_lan_outlets(&state.pool).await {
        Ok(v) => v,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let subnets = match load_subnets(&state.pool).await {
        Ok(v) => v,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let pxe_images = if state.config.pxe_enabled {
        match load_pxe_images(&state.pool).await {
            Ok(v) => v,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    } else {
        Vec::new()
    };

    let host = HostShow {
        id: id.to_string(),
        hostname: form.hostname.trim().to_string(),
        ip: form.ip.trim().to_string(),
        mac: form.mac.trim().to_string(),
        location_id: form.location_id.trim().to_string(),
        lan_outlet_id: form.lan_outlet_id.trim().to_string(),
        subnet_id: form.subnet_id.trim().to_string(),
        location_name: None,
        lan_outlet_label: None,
        subnet_display: None,
        pxe_enabled: form.pxe_enabled.is_some(),
        pxe_image_id: form
            .pxe_image_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string()),
        pxe_image_name: None,
    };

    let mut ctx = Context::new();
    add_auth_context(&mut ctx, session, state).await;
    ctx.insert("error", &Some(msg.to_string()));
    ctx.insert("host", &host);
    ctx.insert("locations", &locations);
    ctx.insert("lan_outlets", &lan_outlets);
    ctx.insert("subnets", &subnets);
    ctx.insert("pxe_images", &pxe_images);

    render(&state.templates, "host_edit.html", ctx)
}

async fn render_pxe_new_error(
    state: &AppState,
    session: &Session,
    files: &[String],
    form: &PxeImageForm,
    msg: &str,
) -> Response {
    let mut ctx = Context::new();
    add_auth_context(&mut ctx, session, state).await;
    ctx.insert("error", &Some(msg.to_string()));
    ctx.insert("files", files);
    ctx.insert(
        "form",
        &serde_json::json!({
            "name": form.name.trim(),
            "kind": form.kind.trim(),
            "arch": form.arch.trim(),
            "kernel_path": form.kernel_path.as_deref().unwrap_or(""),
            "initrd_path": form.initrd_path.as_deref().unwrap_or(""),
            "chain_url": form.chain_url.as_deref().unwrap_or(""),
            "cmdline": form.cmdline.as_deref().unwrap_or(""),
            "enabled": form.enabled.is_some()
        }),
    );
    ctx.insert("pxe_enabled", &state.config.pxe_enabled);
    render(&state.templates, "pxe_images_new.html", ctx)
}

async fn render_pxe_edit_error(
    state: &AppState,
    session: &Session,
    id: i64,
    files: &[String],
    form: &PxeImageForm,
    msg: &str,
) -> Response {
    let mut ctx = Context::new();
    add_auth_context(&mut ctx, session, state).await;
    ctx.insert("error", &Some(msg.to_string()));
    ctx.insert("files", files);
    ctx.insert(
        "image",
        &serde_json::json!({
            "id": id,
            "name": form.name.trim(),
            "kind": form.kind.trim(),
            "arch": form.arch.trim(),
            "kernel_path": form.kernel_path.as_deref().unwrap_or(""),
            "initrd_path": form.initrd_path.as_deref().unwrap_or(""),
            "chain_url": form.chain_url.as_deref().unwrap_or(""),
            "cmdline": form.cmdline.as_deref().unwrap_or(""),
            "enabled": form.enabled.is_some()
        }),
    );
    ctx.insert("pxe_enabled", &state.config.pxe_enabled);
    render(&state.templates, "pxe_images_edit.html", ctx)
}

#[cfg(test)]
mod tests {
    use super::{ensure_path_allowed, validate_ipv4, validate_mac, validate_pxe_form, PxeImageForm};
    use crate::config::Config;
    use std::fs;
    use std::net::Ipv4Addr;
    use std::time::Duration;
    use url::Url;

    #[test]
    fn validate_ipv4_accepts_plain_address() {
        let ip = validate_ipv4("192.168.1.10").unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 10));
    }

    #[test]
    fn validate_ipv4_rejects_invalid_and_ipv6() {
        assert!(validate_ipv4("256.256.0.1").is_err());
        assert!(validate_ipv4("2001:db8::1").is_err());
    }

    #[test]
    fn validate_mac_normalizes_and_rejects_bad() {
        let mac = validate_mac("AA:bb:CC:dd:EE:ff").unwrap();
        assert_eq!(mac.to_string(), "aa:bb:cc:dd:ee:ff");
        assert!(validate_mac("001A2B3C4D5E").is_ok()); // plain hex is allowed by parser
        assert!(validate_mac("ZZ:11:22:33:44:55").is_err());
    }

    fn dummy_config() -> Config {
        Config {
            database_url: "postgres://user:pass@localhost/db".to_string(),
            db_max_connections: 1,
            db_min_connections: 0,
            bind_addr: "127.0.0.1:3000".to_string(),
            base_url: Url::parse("http://localhost:3000/").unwrap(),
            initial_admin_user: "admin".to_string(),
            initial_admin_password: "pass".to_string(),
            session_secret: "secretsecretsecretsecretsecretsecret".to_string(),
            session_cookie_name: "sess".to_string(),
            session_cookie_secure: false,
            session_ttl: Duration::from_secs(3600),
            pxe_enabled: true,
            pxe_root_dir: "/var/lib/ipmanager/pxe".to_string(),
            tftp_root_dir: "/var/lib/tftpboot".to_string(),
            pxe_http_base_url: Url::parse("http://localhost:3000/pxe-assets").unwrap(),
            pxe_tftp_server: "192.0.2.1".to_string(),
            pxe_bios_bootfile: "undionly.kpxe".to_string(),
            pxe_uefi_bootfile: "ipxe.efi".to_string(),
            smtp_host: None,
            smtp_port: None,
            smtp_username: None,
            smtp_password: None,
            smtp_from: None,
            smtp_to: Vec::new(),
            smtp_use_starttls: true,
            admin_email: None,
            macmon_base_url: None,
            macmon_username: None,
            macmon_password: None,
            dnsmasq_hosts_file: "/etc/dnsmasq.d/01-rust-hosts.conf".to_string(),
            dnsmasq_reload_cmd: "sudo systemctl kill -s SIGHUP dnsmasq".to_string(),
            dnsmasq_interface: Some("eth0".to_string()),
            dnsmasq_bind_addr: "127.0.0.1".to_string(),
            dnsmasq_port: 53,
        }
    }

    #[test]
    fn validate_pxe_form_linux_ok() {
        let cfg = dummy_config();
        let files = vec!["vmlinuz".to_string(), "initrd.img".to_string()];
        let form = PxeImageForm {
            name: "test-linux".to_string(),
            kind: "linux".to_string(),
            arch: "any".to_string(),
            kernel_path: Some("vmlinuz".to_string()),
            initrd_path: Some("initrd.img".to_string()),
            chain_url: None,
            cmdline: Some("console=ttyS0\nroot=/dev/sda1".to_string()),
            enabled: Some("on".to_string()),
        };
        let validated = validate_pxe_form(&cfg, &form, &files).unwrap();
        assert_eq!(validated.name, "test-linux");
        assert_eq!(validated.kernel_path.as_deref(), Some("vmlinuz"));
        assert_eq!(validated.initrd_path.as_deref(), Some("initrd.img"));
        assert_eq!(
            validated.cmdline.as_deref(),
            Some("console=ttyS0 root=/dev/sda1")
        );
        assert!(validated.enabled);
    }

    #[test]
    fn validate_pxe_form_rejects_parent_dir() {
        let cfg = dummy_config();
        let files = vec!["ok".to_string()];
        let form = PxeImageForm {
            name: "bad".to_string(),
            kind: "linux".to_string(),
            arch: "any".to_string(),
            kernel_path: Some("../evil".to_string()),
            initrd_path: None,
            chain_url: None,
            cmdline: None,
            enabled: None,
        };
        assert!(validate_pxe_form(&cfg, &form, &files).is_err());
    }

    #[test]
    fn validate_pxe_form_chain_requires_url() {
        let cfg = dummy_config();
        let files = vec![];
        let form = PxeImageForm {
            name: "chain1".to_string(),
            kind: "chain".to_string(),
            arch: "any".to_string(),
            kernel_path: None,
            initrd_path: None,
            chain_url: None,
            cmdline: None,
            enabled: None,
        };
        assert!(validate_pxe_form(&cfg, &form, &files).is_err());
    }

    #[test]
    fn ensure_path_allowed_checks_root() {
        let tmpdir = tempfile::tempdir().unwrap();
        let file_path = tmpdir.path().join("file.bin");
        fs::write(&file_path, b"data").unwrap();
        assert!(ensure_path_allowed(tmpdir.path(), "file.bin"));
        assert!(!ensure_path_allowed(tmpdir.path(), "../file.bin"));
    }
}
