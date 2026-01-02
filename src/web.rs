use axum::{
    extract::{Form, Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::{net::IpAddr, str::FromStr, sync::Arc};
use tera::{Context, Tera};
use tower_sessions::Session;
use uuid::Uuid;

use crate::domain::mac::MacAddr;
use crate::{config::Config, dhcp_kea};

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub templates: Arc<Tera>,
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
    name: String,
    cidr: String,
    dns_zone: Option<String>,
    reverse_zone: Option<String>,
    dhcp_enabled: bool,
    pxe_enabled: bool,
}

pub fn router(state: AppState) -> Router {
    Router::new()
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
        .route("/subnets/new", get(subnets_new))
        // Kea DHCP
        .route("/dhcp/kea", get(dhcp_kea_page))
        .route("/dhcp/kea/deploy", post(dhcp_kea_deploy))
        // API
        .route("/api/login", post(api_login))
        .route("/api/me", get(api_me))
        .route("/api/lan-outlets", get(api_lan_outlets_by_location))
        .with_state(state)
}

/* ----------------------------- Auth helpers ----------------------------- */

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

    let kea_json = match dhcp_kea::render_dhcp4_config(&state.pool).await {
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
            ctx.insert("kea_json", &"{}".to_string());
            ctx.insert("kea_reload_mode", &cfg.kea_reload_mode);
            return render(&state.templates, "dhcp_kea.html", ctx);
        }
    };

    let kea_json = dhcp_kea::render_dhcp4_config(&state.pool)
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
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
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
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
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
    ctx.insert("locations", &locations);
    ctx.insert("lan_outlets", &lan_outlets);
    ctx.insert("subnets", &subnets);

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
        return render_hosts_new_error(&state, &session, "Hostname darf nicht leer sein").await;
    }

    let ip: IpAddr = match form.ip.trim().parse() {
        Ok(v) => v,
        Err(_) => return render_hosts_new_error(&state, &session, "Ungültige IP-Adresse").await,
    };

    let mac: MacAddr = match MacAddr::from_str(form.mac.trim()) {
        Ok(v) => v,
        Err(_) => return render_hosts_new_error(&state, &session, "Ungültige MAC-Adresse").await,
    };
    let mac_norm = mac.to_string();

    let location_id: Uuid = match Uuid::parse_str(form.location_id.trim()) {
        Ok(v) => v,
        Err(_) => return render_hosts_new_error(&state, &session, "Ungültiger Standort").await,
    };

    let lan_outlet_id: Uuid = match Uuid::parse_str(form.lan_outlet_id.trim()) {
        Ok(v) => v,
        Err(_) => return render_hosts_new_error(&state, &session, "Ungültige LAN-Dose").await,
    };

    let subnet_id: Uuid = match Uuid::parse_str(form.subnet_id.trim()) {
        Ok(v) => v,
        Err(_) => return render_hosts_new_error(&state, &session, "Ungültiges Subnet").await,
    };

    let pxe_enabled = form.pxe_enabled.is_some();

    let ok_pair: Option<i64> =
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
        return render_hosts_new_error(
            &state,
            &session,
            "LAN-Dose gehört nicht zum gewählten Standort",
        )
        .await;
    }

    let res = sqlx::query(
        "insert into hosts (hostname, ip, mac, location_id, lan_outlet_id, subnet_id, pxe_enabled)
         values ($1, $2, $3, $4, $5, $6, $7)",
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
        Ok(_) => Redirect::to("/hosts").into_response(),
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
            render_hosts_new_error(&state, &session, msg).await
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

    let ip: IpAddr = match form.ip.trim().parse() {
        Ok(v) => v,
        Err(_) => {
            return render_host_edit_error(&state, &session, id, &form, "Ungültige IP-Adresse")
                .await
        }
    };

    let mac: MacAddr = match MacAddr::from_str(form.mac.trim()) {
        Ok(v) => v,
        Err(_) => {
            return render_host_edit_error(&state, &session, id, &form, "Ungültige MAC-Adresse")
                .await
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

    let pxe_enabled = form.pxe_enabled.is_some();

    let ok_pair: Option<i64> =
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
             ip = $2,
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

    let rows: Vec<(String, String, Option<String>, Option<String>, bool, bool)> =
        match sqlx::query_as(
            "select name,
                    cidr::text,
                    dns_zone,
                    reverse_zone,
                    dhcp_enabled,
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
            |(name, cidr, dns_zone, reverse_zone, dhcp_enabled, pxe_enabled)| SubnetRow {
                name,
                cidr,
                dns_zone,
                reverse_zone,
                dhcp_enabled,
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

async fn render_login_error(tera: &Tera, session: &Session, msg: &str) -> Response {
    let mut ctx = Context::new();
    add_auth_context(&mut ctx, session).await;
    ctx.insert("error", &Some(msg.to_string()));
    render(tera, "login.html", ctx)
}

async fn render_hosts_new_error(state: &AppState, session: &Session, msg: &str) -> Response {
    let locations = load_locations(&state.pool).await.ok();
    let lan_outlets = load_lan_outlets(&state.pool).await.ok();
    let subnets = load_subnets(&state.pool).await.ok();

    if locations.is_none() || lan_outlets.is_none() || subnets.is_none() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let mut ctx = Context::new();
    add_auth_context(&mut ctx, session).await;
    ctx.insert("error", &Some(msg.to_string()));
    ctx.insert("locations", &locations.unwrap());
    ctx.insert("lan_outlets", &lan_outlets.unwrap());
    ctx.insert("subnets", &subnets.unwrap());

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
