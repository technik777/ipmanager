use axum::{
    extract::{Form, Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, get_service, post},
    Json, Router,
};
use ipnetwork::IpNetwork;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::{net::Ipv4Addr, path::Path as StdPath, str::FromStr, sync::Arc};
use tera::{Context, Tera};
use tower_sessions::Session;
use uuid::Uuid;

use crate::domain::mac::MacAddr;
use crate::{config::Config, dhcp_kea};
use tower_http::services::ServeDir;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub templates: Arc<Tera>,
    pub config: crate::config::Config,
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
}

#[derive(Deserialize, Default)]
pub struct HostsQuery {
    pub q: Option<String>,
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

#[derive(Debug, Serialize)]
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
        .route("/hosts/{id}", get(host_show).post(host_update))
        .route("/hosts/{id}/edit", get(host_edit))
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
        .route("/subnets/{id}/edit", get(subnets_edit))
        .route("/subnets/{id}", post(subnets_update))
        // Kea DHCP
        .route("/dhcp/kea", get(dhcp_kea_page))
        .route("/dhcp/kea/deploy", post(dhcp_kea_deploy))
        // PXE / iPXE
        .route("/boot.ipxe", get(boot_ipxe))
        // API
        .route("/api/login", post(api_login))
        .route("/api/me", get(api_me))
        .route("/api/lan-outlets", get(api_lan_outlets_by_location));

    if state.config.pxe_enabled {
        router = router
            .route("/pxe/images", get(pxe_images_list))
            .route("/pxe/images/new", get(pxe_images_new).post(pxe_images_create))
            .route("/pxe/images/{id}/edit", get(pxe_images_edit).post(pxe_images_update))
            .route("/pxe/images/{id}/delete", post(pxe_images_delete));
        router = router.route_service(
            "/pxe-assets/*path",
            get_service(ServeDir::new(state.config.pxe_root_dir.clone())),
        );
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
        "ipxe", "efi", "kpxe", "pxe", "vmlinuz", "img", "gz", "xz", "iso",
    ];

    let Ok(read_dir) = std::fs::read_dir(root_dir) else {
        return Vec::new();
    };

    let mut files = Vec::new();
    for entry in read_dir.flatten() {
        let path = entry.path();
        if path.is_dir() {
            continue;
        }
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if !allowed_ext.iter().any(|a| a.eq_ignore_ascii_case(ext)) {
                continue;
            }
        } else {
            continue;
        }

        if let Ok(rel) = path.strip_prefix(root_dir) {
            if rel.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
                continue;
            }
            if let Some(s) = rel.to_str() {
                files.push(s.replace('\\', "/"));
            }
        }
    }

    files.sort();
    files
}

fn sanitize_label(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
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
        && !path.components().any(|c| matches!(c, std::path::Component::ParentDir))
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

async fn is_authenticated(session: &Session) -> bool {
    match session.get::<String>("username").await {
        Ok(Some(_)) => true,
        _ => false,
    }
}

async fn add_auth_context(ctx: &mut Context, session: &Session) {
    let authed = is_authenticated(session).await;
    ctx.insert("is_authenticated", &authed);
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

/* ----------------------------- SSR Handlers ----------------------------- */

async fn index(State(state): State<AppState>, session: Session) -> Response {
    let mut ctx = Context::new();
    add_auth_context(&mut ctx, &session).await;
    render(&state.templates, "index.html", ctx)
}

async fn login_page(State(state): State<AppState>, session: Session) -> Response {
    let mut ctx = Context::new();
    add_auth_context(&mut ctx, &session).await;

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
        Ok(None) => {
            return render_login_error(&state.templates, &session, "Login fehlgeschlagen").await
        }
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
        _ => render_login_error(&state.templates, &session, "Login fehlgeschlagen").await,
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
    add_auth_context(&mut ctx, &session).await;
    ctx.insert("username", &username);
    ctx.insert("role", &role);

    render(&state.templates, "me.html", ctx)
}

/* ----------------------------- Kea DHCP (SSR) ----------------------------- */

async fn dhcp_kea_page(State(state): State<AppState>, session: Session) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }

    let cfg = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            let mut ctx = Context::new();
            add_auth_context(&mut ctx, &session).await;
            ctx.insert(
                "error",
                &Some(format!("Config konnte nicht geladen werden: {e:#}")),
            );
            ctx.insert("kea_json", &"{}".to_string());
            ctx.insert("kea_reload_mode", &"none".to_string());
            return render(&state.templates, "dhcp_kea.html", ctx);
        }
    };

    let kea_json = match dhcp_kea::render_dhcp4_config(&state.pool, &cfg).await {
        Ok(j) => j,
        Err(e) => {
            let mut ctx = Context::new();
            add_auth_context(&mut ctx, &session).await;
            ctx.insert("error", &Some(format!("Render fehlgeschlagen: {e:#}")));
            ctx.insert("kea_json", &"{}".to_string());
            ctx.insert("kea_reload_mode", &cfg.kea_reload_mode);
            return render(&state.templates, "dhcp_kea.html", ctx);
        }
    };

    let mut ctx = Context::new();
    add_auth_context(&mut ctx, &session).await;
    ctx.insert("error", &Option::<String>::None);
    ctx.insert("kea_json", &kea_json);
    ctx.insert("kea_reload_mode", &cfg.kea_reload_mode);

    render(&state.templates, "dhcp_kea.html", ctx)
}

async fn dhcp_kea_deploy(State(state): State<AppState>, session: Session) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }

    let cfg = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = ?e, "failed to load config for kea deploy");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let outcome = match dhcp_kea::deploy(&state.pool, &cfg).await {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = ?e, "kea deploy failed");

            let mut ctx = Context::new();
            add_auth_context(&mut ctx, &session).await;
            ctx.insert("error", &Some(format!("Deploy fehlgeschlagen: {e:#}")));

            let kea_json = dhcp_kea::render_dhcp4_config(&state.pool, &cfg)
                .await
                .unwrap_or_else(|_| "{}".to_string());
            ctx.insert("kea_json", &kea_json);

            ctx.insert("kea_reload_mode", &cfg.kea_reload_mode);
            return render(&state.templates, "dhcp_kea.html", ctx);
        }
    };

    let kea_json = dhcp_kea::render_dhcp4_config(&state.pool, &cfg)
        .await
        .unwrap_or_else(|_| "{}".to_string());

    let mut ctx = Context::new();
    add_auth_context(&mut ctx, &session).await;
    ctx.insert("error", &Option::<String>::None);
    ctx.insert("kea_json", &kea_json);
    ctx.insert("kea_reload_mode", &cfg.kea_reload_mode);
    let reload_status = match outcome.reload_ok {
        Some(true) => "ok",
        Some(false) => "failed",
        None => "not-attempted",
    };

    ctx.insert(
        "outcome",
        &serde_json::json!({
            "written_to": outcome.written_to,
            "reload_attempted": outcome.reload_attempted,
            "reload_status": reload_status,
            "reload_message": outcome.reload_message
        }),
    );

    render(&state.templates, "dhcp_kea.html", ctx)
}

/* ----------------------------- Hosts (SSR) ----------------------------- */

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

    let rows: Vec<(
        Uuid,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        bool,
    )> = if q.is_empty() {
        match sqlx::query_as(
            "select h.id,
                        h.hostname,
                        host(h.ip),
                        h.mac,
                        l.name as location_name,
                        o.label as lan_outlet_label,
                        h.pxe_enabled
                 from hosts h
                 left join locations l on l.id = h.location_id
                 left join lan_outlets o on o.id = h.lan_outlet_id
                 order by h.hostname asc",
        )
        .fetch_all(&state.pool)
        .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = ?e, "DB error in hosts_list");
                return render_error_page(StatusCode::INTERNAL_SERVER_ERROR, "DB Fehler beim Laden der Hosts");
            }
        }
    } else {
        let like = format!("%{}%", q);
        match sqlx::query_as(
            "select h.id,
                        h.hostname,
                        h.ip::text,
                        h.mac,
                        l.name as location_name,
                        o.label as lan_outlet_label,
                        h.pxe_enabled
                 from hosts h
                 left join locations l on l.id = h.location_id
                 left join lan_outlets o on o.id = h.lan_outlet_id
                 where h.hostname ilike $1
                    or (h.ip::text) ilike $1
                    or h.mac ilike $1
                    or coalesce(l.name, '') ilike $1
                    or coalesce(o.label, '') ilike $1
                order by h.hostname asc",
        )
        .bind(like)
        .fetch_all(&state.pool)
        .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = ?e, "DB error in hosts_list (search)");
                return render_error_page(StatusCode::INTERNAL_SERVER_ERROR, "DB Fehler beim Laden der Hosts");
            }
        }
    };

    let hosts: Vec<HostRow> = rows
        .into_iter()
        .map(
            |(id, hostname, ip, mac, location_name, lan_outlet_label, pxe_enabled)| HostRow {
                id: id.to_string(),
                hostname,
                ip,
                mac,
                location_name,
                lan_outlet_label,
                pxe_enabled,
            },
        )
        .collect();

    let mut ctx = Context::new();
    add_auth_context(&mut ctx, &session).await;
    ctx.insert("hosts", &hosts);
    ctx.insert("q", &q);

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
            return render_error_page(StatusCode::INTERNAL_SERVER_ERROR, "DB Fehler beim Laden der Standorte");
        }
    };
    let lan_outlets = match load_lan_outlets(&state.pool).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = ?e, "DB error in hosts_new loading lan_outlets");
            return render_error_page(StatusCode::INTERNAL_SERVER_ERROR, "DB Fehler beim Laden der LAN-Dosen");
        }
    };
    let subnets = match load_subnets(&state.pool).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = ?e, "DB error in hosts_new loading subnets");
            return render_error_page(StatusCode::INTERNAL_SERVER_ERROR, "DB Fehler beim Laden der Subnets");
        }
    };

    let mut ctx = Context::new();
    add_auth_context(&mut ctx, &session).await;
    ctx.insert("error", &Option::<String>::None);
    ctx.insert("locations", &locations);
    ctx.insert("lan_outlets", &lan_outlets);
    ctx.insert("subnets", &subnets);
    ctx.insert(
        "form",
        &serde_json::json!({
            "hostname": "",
            "ip": "",
            "mac": "",
            "location_id": "",
            "lan_outlet_id": "",
            "subnet_id": "",
            "pxe_enabled": false
        }),
    );

    render(&state.templates, "hosts_new.html", ctx)
}

async fn hosts_create(
    State(state): State<AppState>,
    session: Session,
    Form(form): Form<HostCreateForm>,
) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }

    let hostname = form.hostname.trim().to_string();
    if hostname.is_empty() {
        return render_hosts_new_error(&state, &session, &form, "Hostname darf nicht leer sein").await;
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
        Err(_) => return render_hosts_new_error(&state, &session, &form, "Ungültiger Standort").await,
    };

    let lan_outlet_id: Uuid = match Uuid::parse_str(form.lan_outlet_id.trim()) {
        Ok(v) => v,
        Err(_) => return render_hosts_new_error(&state, &session, &form, "Ungültige LAN-Dose").await,
    };

    let subnet_id: Uuid = match Uuid::parse_str(form.subnet_id.trim()) {
        Ok(v) => v,
        Err(_) => return render_hosts_new_error(&state, &session, &form, "Ungültiges Subnet").await,
    };

    // IP muss im gewählten Subnet liegen
    let cidr: Option<String> = match sqlx::query_scalar("select cidr::text from subnets where id = $1")
        .bind(subnet_id)
        .fetch_optional(&state.pool)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = ?e, "DB error in hosts_create loading subnet by id");
            return render_error_page(StatusCode::INTERNAL_SERVER_ERROR, "DB Fehler beim Laden des Subnets");
        }
    };
    let Some(cidr) = cidr else {
        return render_hosts_new_error(&state, &session, &form, "Ungültiges Subnet").await;
    };
    let net: ipnet::Ipv4Net = match cidr.parse() {
        Ok(n) => n,
        Err(_) => return render_hosts_new_error(&state, &session, &form, "Subnet CIDR ist ungültig").await,
    };
    if !net.contains(&ip) {
        return render_hosts_new_error(&state, &session, &form, "IP liegt nicht im gewählten Subnet").await;
    }

    // Vor dem Insert prüfen, ob Hostname/IP/MAC schon existieren
    if let Ok(Some((conflict_host, conflict_ip, conflict_mac))) = sqlx::query_as::<_, (String, String, String)>(
        "select hostname, host(ip), mac
         from hosts
         where hostname = $1
            or ip = $2::inet
            or mac = $3
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
                return render_error_page(StatusCode::INTERNAL_SERVER_ERROR, "DB Fehler beim Prüfen der LAN-Dose");
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

    tracing::debug!(
        hostname = %hostname,
        ip = %ip,
        mac = %mac_norm,
        location_id = %location_id,
        lan_outlet_id = %lan_outlet_id,
        subnet_id = %subnet_id,
        pxe_enabled,
        "Attempting to insert host"
    );

    let res = sqlx::query(
        "insert into hosts (hostname, ip, mac, location_id, lan_outlet_id, subnet_id, pxe_enabled)
         values ($1, $2::inet, $3, $4, $5, $6, $7)",
    )
    .bind(&hostname)
    .bind(ip.to_string())
    .bind(&mac_norm)
    .bind(location_id)
    .bind(lan_outlet_id)
    .bind(subnet_id)
    .bind(pxe_enabled)
    .execute(&state.pool)
    .await;

    match res {
        Ok(r) => {
            tracing::debug!(rows_affected = r.rows_affected(), "Inserted host into database");
            Redirect::to("/hosts").into_response()
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

async fn host_show(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }

    let row: Option<(
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
    )> = match sqlx::query_as(
        "select h.id,
                h.hostname,
                host(h.ip),
                h.mac,
                h.location_id,
                h.lan_outlet_id,
                h.subnet_id,
                l.name as location_name,
                o.label as lan_outlet_label,
                (s.name || ' (' || s.cidr::text || ')') as subnet_display,
                h.pxe_enabled
         from hosts h
         left join locations l on l.id = h.location_id
         left join lan_outlets o on o.id = h.lan_outlet_id
         left join subnets s on s.id = h.subnet_id
         where h.id = $1
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
    )) = row
    else {
        return StatusCode::NOT_FOUND.into_response();
    };

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
    };

    let mut ctx = Context::new();
    add_auth_context(&mut ctx, &session).await;
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

    let mut ctx = Context::new();
    add_auth_context(&mut ctx, &session).await;
    ctx.insert("error", &Option::<String>::None);
    ctx.insert("host", &host);
    ctx.insert("locations", &locations);
    ctx.insert("lan_outlets", &lan_outlets);
    ctx.insert("subnets", &subnets);

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
    let cidr: Option<String> = match sqlx::query_scalar("select cidr::text from subnets where id = $1")
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
        Err(_) => return render_host_edit_error(&state, &session, id, &form, "Subnet CIDR ist ungültig").await,
    };
    if !net.contains(&ip) {
        return render_host_edit_error(&state, &session, id, &form, "IP liegt nicht im gewählten Subnet").await;
    }

    // Vor dem Update prüfen, ob Hostname/IP/MAC schon existieren (anderer Datensatz)
    if let Ok(Some((conflict_host, conflict_ip, conflict_mac))) =
        sqlx::query_as::<_, (String, String, String)>(
            "select hostname, host(ip), mac
             from hosts
             where id <> $1
               and (hostname = $2 or ip = $3::inet or mac = $4)
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
             ip = $2::inet,
             mac = $3,
             location_id = $4,
             lan_outlet_id = $5,
             subnet_id = $6,
             pxe_enabled = $7
         where id = $8",
    )
    .bind(&hostname)
    .bind(ip.to_string())
    .bind(&mac_norm)
    .bind(location_id)
    .bind(lan_outlet_id)
    .bind(subnet_id)
    .bind(pxe_enabled)
    .bind(id)
    .execute(&state.pool)
    .await;

    match res {
        Ok(r) => {
            if r.rows_affected() == 0 {
                StatusCode::NOT_FOUND.into_response()
            } else {
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

async fn load_host_for_edit(pool: &PgPool, id: Uuid) -> Result<Option<HostShow>, ()> {
    let row: Option<(
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
    )> = sqlx::query_as(
        "select h.id,
                h.hostname,
                host(h.ip),
                h.mac,
                h.location_id,
                h.lan_outlet_id,
                h.subnet_id,
                l.name as location_name,
                o.label as lan_outlet_label,
                (s.name || ' (' || s.cidr::text || ')') as subnet_display,
                h.pxe_enabled
         from hosts h
         left join locations l on l.id = h.location_id
         left join lan_outlets o on o.id = h.lan_outlet_id
         left join subnets s on s.id = h.subnet_id
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
    add_auth_context(&mut ctx, &session).await;
    ctx.insert("locations", &locations);

    render(&state.templates, "locations_list.html", ctx)
}

async fn locations_new(State(state): State<AppState>, session: Session) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }

    let mut ctx = Context::new();
    add_auth_context(&mut ctx, &session).await;
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
    add_auth_context(&mut ctx, session).await;
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
    add_auth_context(&mut ctx, &session).await;
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
    add_auth_context(&mut ctx, &session).await;
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
    add_auth_context(&mut ctx, session).await;
    ctx.insert("error", &Some(msg.to_string()));
    ctx.insert("locations", &locations);
    render(&state.templates, "lan_outlets_new.html", ctx)
}

/* ----------------------------- Subnets (SSR) ----------------------------- */

async fn subnets_list(State(state): State<AppState>, session: Session) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }

    let rows: Vec<(
        Uuid,
        String,
        String,
        Option<String>,
        Option<String>,
        bool,
        Option<String>,
        Option<String>,
        bool,
    )> = match sqlx::query_as(
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
    add_auth_context(&mut ctx, &session).await;
    ctx.insert("subnets", &subnets);

    render(&state.templates, "subnets_list.html", ctx)
}

async fn subnets_new(State(state): State<AppState>, session: Session) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }

    let mut ctx = Context::new();
    add_auth_context(&mut ctx, &session).await;
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

    let row: Option<(
        Uuid,
        String,
        String,
        Option<String>,
        Option<String>,
        bool,
        Option<String>,
        Option<String>,
        bool,
    )> = match sqlx::query_as(
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
    add_auth_context(&mut ctx, &session).await;
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
    add_auth_context(&mut ctx, session).await;
    ctx.insert("error", &Some(msg.to_string()));
    ctx.insert("subnet", &subnet);
    render(&state.templates, "subnets_edit.html", ctx)
}

async fn render_subnets_new_error(state: &AppState, session: &Session, msg: &str) -> Response {
    let mut ctx = Context::new();
    add_auth_context(&mut ctx, session).await;
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

/* ----------------------------- PXE / iPXE ----------------------------- */

fn validate_pxe_form(cfg: &Config, form: &PxeImageForm, files: &[String]) -> Result<ValidatedPxe, String> {
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
        let kernel = kernel_path.clone().ok_or_else(|| "Kernel-Pfad ist erforderlich".to_string())?;
        if !files.contains(&kernel) && !ensure_path_allowed(root, &kernel) {
            return Err("Kernel-Pfad ist ungültig oder existiert nicht".to_string());
        }
        if let Some(initrd) = initrd_path.as_ref() {
            if !files.contains(initrd) && !ensure_path_allowed(root, initrd) {
                return Err("Initrd-Pfad ist ungültig oder existiert nicht".to_string());
            }
        }
    } else if kind == "chain" {
        let url = chain_url.clone().ok_or_else(|| "Chain-URL ist erforderlich".to_string())?;
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

async fn list_pxe_images(pool: &PgPool) -> Result<Vec<PxeImage>, ()> {
    let rows: Result<
        Vec<(
            i64,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            bool,
        )>,
        _,
    > = sqlx::query_as(
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
                |(id, name, kind, arch, kernel_path, initrd_path, chain_url, cmdline, enabled)| PxeImage {
                    id,
                    name,
                    kind,
                    arch,
                    kernel_path,
                    initrd_path,
                    chain_url,
                    cmdline,
                    enabled,
                },
            )
            .collect()
    })
}

async fn get_pxe_image(pool: &PgPool, id: i64) -> Result<Option<PxeImage>, ()> {
    let row: Result<
        Option<(
            i64,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            bool,
        )>,
        _,
    > = sqlx::query_as(
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
            |(id, name, kind, arch, kernel_path, initrd_path, chain_url, cmdline, enabled)| PxeImage {
                id,
                name,
                kind,
                arch,
                kernel_path,
                initrd_path,
                chain_url,
                cmdline,
                enabled,
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

fn build_ipxe_script(cfg: &Config, images: &[PxeImage]) -> String {
    let mut out = String::new();
    let base_assets = cfg.pxe_http_base_url.as_str().trim_end_matches('/');
    let boot_url = cfg
        .base_url
        .join("boot.ipxe")
        .map(|u| u.to_string())
        .unwrap_or_else(|_| format!("{}/boot.ipxe", cfg.base_url));

    out.push_str("#!ipxe\n");
    out.push_str("set menu-timeout 5000\n");
    out.push_str(&format!("set base {}\n\n", base_assets));
    out.push_str(&format!("# tftp-server: {}\n", cfg.pxe_tftp_server));
    out.push_str(&format!("# bios-bootfile: {}\n", cfg.pxe_bios_bootfile));
    out.push_str(&format!("# uefi-bootfile: {}\n\n", cfg.pxe_uefi_bootfile));
    out.push_str(":start\n");
    out.push_str("menu IPManager PXE Boot Menu\n");
    out.push_str("item --gap -- ----------------------------\n");
    out.push_str("item local Local disk\n");
    out.push_str("item shell iPXE shell\n");

    for img in images {
        if !img.enabled {
            continue;
        }
        let name = sanitize_label(&img.name);
        out.push_str(&format!("item img{} {} [{}]\n", img.id, name, img.arch));
    }

    out.push_str("choose --timeout ${menu-timeout} --default local selected || goto start\n");
    out.push_str("goto ${selected}\n\n");

    out.push_str(":local\nexit\n\n");
    out.push_str(":shell\nshell\ngoto start\n\n");

    for img in images {
        if !img.enabled {
            continue;
        }
        let label = format!("img{}", img.id);
        out.push_str(&format!(":{}\n", label));
        match img.kind.as_str() {
            "linux" => {
                if let Some(kernel) = &img.kernel_path {
                    let cmd = sanitize_cmdline(img.cmdline.as_deref().unwrap_or(""));
                    out.push_str(&format!("kernel ${{base}}/{kernel} {cmd}\n"));
                    if let Some(initrd) = &img.initrd_path {
                        out.push_str(&format!("initrd ${{base}}/{initrd}\n"));
                    }
                    out.push_str("boot || goto start\n\n");
                }
            }
            "chain" => {
                if let Some(url) = &img.chain_url {
                    out.push_str(&format!("chain {url} || goto start\n\n"));
                }
            }
            _ => {
                out.push_str("goto start\n\n");
            }
        }
    }

    if cfg.pxe_enabled {
        // Hint for iPXE direct chain if desired
        out.push_str(&format!("# ipxe boot script served by {}\n", boot_url));
    }

    out
}

async fn boot_ipxe(State(state): State<AppState>) -> Response {
    if !state.config.pxe_enabled {
        return StatusCode::NOT_FOUND.into_response();
    }

    let rows: Result<
        Vec<(
            i64,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            bool,
        )>,
        _,
    > = sqlx::query_as(
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
         where enabled = true
         order by name asc",
    )
    .fetch_all(&state.pool)
    .await;

    let images = match rows {
        Ok(v) => v
            .into_iter()
            .map(
                |(id, name, kind, arch, kernel_path, initrd_path, chain_url, cmdline, enabled)| PxeImage {
                    id,
                    name,
                    kind,
                    arch,
                    kernel_path,
                    initrd_path,
                    chain_url,
                    cmdline,
                    enabled,
                },
            )
            .collect::<Vec<_>>(),
        Err(e) => {
            tracing::error!(error = ?e, "failed to load pxe images");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let script = build_ipxe_script(&state.config, &images);

    (
        axum::http::HeaderMap::from_iter(std::iter::once((
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("text/plain; charset=utf-8"),
        ))),
        script,
    )
        .into_response()
}

async fn pxe_images_list(State(state): State<AppState>, session: Session) -> Response {
    if let Err(resp) = require_auth(&session).await {
        return resp;
    }
    if !state.config.pxe_enabled {
        return StatusCode::NOT_FOUND.into_response();
    }

    let images = match list_pxe_images(&state.pool).await {
        Ok(v) => v,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let mut ctx = Context::new();
    add_auth_context(&mut ctx, &session).await;
    ctx.insert("images", &images);
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
    add_auth_context(&mut ctx, &session).await;
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
    add_auth_context(&mut ctx, &session).await;
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

async fn render_login_error(tera: &Tera, session: &Session, msg: &str) -> Response {
    let mut ctx = Context::new();
    add_auth_context(&mut ctx, session).await;
    ctx.insert("error", &Some(msg.to_string()));
    render(tera, "login.html", ctx)
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
            return render_error_page(StatusCode::INTERNAL_SERVER_ERROR, "DB Fehler beim Laden der Standorte");
        }
    };
    let lan_outlets = match load_lan_outlets(&state.pool).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = ?e, "DB error in render_hosts_new_error lan_outlets");
            return render_error_page(StatusCode::INTERNAL_SERVER_ERROR, "DB Fehler beim Laden der LAN-Dosen");
        }
    };
    let subnets = match load_subnets(&state.pool).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = ?e, "DB error in render_hosts_new_error subnets");
            return render_error_page(StatusCode::INTERNAL_SERVER_ERROR, "DB Fehler beim Laden der Subnets");
        }
    };

    let mut ctx = Context::new();
    add_auth_context(&mut ctx, session).await;
    ctx.insert("error", &Some(msg.to_string()));
    ctx.insert("locations", &locations);
    ctx.insert("lan_outlets", &lan_outlets);
    ctx.insert("subnets", &subnets);
    ctx.insert(
        "form",
        &serde_json::json!({
            "hostname": form.hostname.trim(),
            "ip": form.ip.trim(),
            "mac": form.mac.trim(),
            "location_id": form.location_id.trim(),
            "lan_outlet_id": form.lan_outlet_id.trim(),
            "subnet_id": form.subnet_id.trim(),
            "pxe_enabled": form.pxe_enabled.is_some()
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
    };

    let mut ctx = Context::new();
    add_auth_context(&mut ctx, session).await;
    ctx.insert("error", &Some(msg.to_string()));
    ctx.insert("host", &host);
    ctx.insert("locations", &locations);
    ctx.insert("lan_outlets", &lan_outlets);
    ctx.insert("subnets", &subnets);

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
    add_auth_context(&mut ctx, session).await;
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
    add_auth_context(&mut ctx, session).await;
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
    use super::{
        build_ipxe_script, ensure_path_allowed, validate_ipv4, validate_mac, validate_pxe_form,
        PxeImage, PxeImageForm,
    };
    use std::net::Ipv4Addr;
    use url::Url;
    use crate::config::Config;
    use std::time::Duration;
    use std::fs;
    use tempfile;

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
            pxe_http_base_url: Url::parse("http://localhost:3000/pxe-assets").unwrap(),
            pxe_tftp_server: "192.0.2.1".to_string(),
            pxe_bios_bootfile: "undionly.kpxe".to_string(),
            pxe_uefi_bootfile: "ipxe.efi".to_string(),
            kea_config_path: "/etc/kea/kea-dhcp4.conf".to_string(),
            kea_reload_mode: "none".to_string(),
            kea_control_agent_url: None,
            kea_api_timeout: Duration::from_secs(5),
            kea_control_agent_username: None,
            kea_control_agent_password: None,
        }
    }

    #[test]
    fn build_ipxe_includes_items_and_kernel() {
        let cfg = dummy_config();
        let images = vec![
            PxeImage {
                id: 1,
                name: "Linux".to_string(),
                kind: "linux".to_string(),
                arch: "any".to_string(),
                kernel_path: Some("vmlinuz".to_string()),
                initrd_path: Some("initrd.img".to_string()),
                chain_url: None,
                cmdline: Some("console=ttyS0".to_string()),
                enabled: true,
            },
            PxeImage {
                id: 2,
                name: "Chain".to_string(),
                kind: "chain".to_string(),
                arch: "any".to_string(),
                kernel_path: None,
                initrd_path: None,
                chain_url: Some("http://example.com/ipxe".to_string()),
                cmdline: None,
                enabled: true,
            },
        ];

        let script = build_ipxe_script(&cfg, &images);
        assert!(script.contains("#!ipxe"));
        assert!(script.contains("item img1 Linux"));
        assert!(script.contains("kernel ${base}/vmlinuz console=ttyS0"));
        assert!(script.contains("initrd ${base}/initrd.img"));
        assert!(script.contains("item img2 Chain"));
        assert!(script.contains("chain http://example.com/ipxe"));
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
        assert_eq!(validated.cmdline.as_deref(), Some("console=ttyS0 root=/dev/sda1"));
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
