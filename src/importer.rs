#![allow(dead_code)]

use anyhow::{Context, Result};
use ipnet::IpNet;
use sqlx::PgPool;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use uuid::Uuid;

use crate::domain::mac::MacAddr;

#[derive(Debug, Clone)]
pub struct ImportError {
    pub line: usize,
    pub message: String,
}

#[derive(Debug, Clone, Default)]
pub struct ImportSummary {
    pub created: usize,
    pub updated: usize,
    pub locations_updated: usize,
    pub errors: Vec<ImportError>,
}

pub fn normalize_mac(raw: &str) -> String {
    let mut clean = String::new();
    for (i, c) in raw.chars().enumerate() {
        if i > 0 && i % 2 == 0 {
            clean.push(':');
        }
        clean.push(c);
    }
    clean.to_uppercase()
}

pub async fn import_colon_format(pool: &PgPool, input: &str) -> Result<ImportSummary> {
    let subnet_rows: Vec<(Uuid, String)> = sqlx::query_as("select id, cidr::text from subnets")
        .fetch_all(pool)
        .await
        .context("failed to load subnets for colon import")?;
    let subnets: Vec<(Uuid, IpNet)> = subnet_rows
        .into_iter()
        .filter_map(|(id, cidr)| match IpNet::from_str(cidr.trim()) {
            Ok(net) => Some((id, net)),
            Err(_) => None,
        })
        .collect();

    let mut locations: HashMap<String, Uuid> = sqlx::query_as("select id, name from locations")
        .fetch_all(pool)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|(id, name): (Uuid, String)| (name, id))
        .collect();

    let mut rooms: HashMap<(Uuid, String), Uuid> =
        sqlx::query_as("select id, location_id, name from rooms")
            .fetch_all(pool)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|(id, location_id, name): (Uuid, Uuid, String)| ((location_id, name), id))
            .collect();

    let mut outlets: HashMap<(Uuid, String), Uuid> =
        sqlx::query_as("select id, location_id, label from lan_outlets")
            .fetch_all(pool)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|(id, location_id, label): (Uuid, Uuid, String)| ((location_id, label), id))
            .collect();

    let mut summary = ImportSummary::default();

    for (idx, line) in input.lines().enumerate() {
        let line_no = idx + 1;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 7 {
            summary.errors.push(ImportError {
                line: line_no,
                message: "Zu wenige Felder in Zeile".to_string(),
            });
            continue;
        }

        let hostname = fields[0].trim();
        let ip_raw = fields[1].trim();
        let mac_raw = fields[2].trim();
        let location_name = fields[4].trim();
        let room_name = fields[5].trim();
        let lan_port = fields[6].trim();

        if hostname.is_empty() || ip_raw.is_empty() || mac_raw.is_empty() {
            summary.errors.push(ImportError {
                line: line_no,
                message: "Hostname, IP oder MAC fehlt".to_string(),
            });
            continue;
        }

        let ip: Ipv4Addr = match ip_raw.parse() {
            Ok(ip) => ip,
            Err(_) => {
                summary.errors.push(ImportError {
                    line: line_no,
                    message: "Ungueltige IP-Adresse".to_string(),
                });
                continue;
            }
        };

        let mac_compact: String = mac_raw.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        let mac_norm = normalize_mac(&mac_compact);
        let mac = match MacAddr::from_str(&mac_norm) {
            Ok(mac) => mac.to_string(),
            Err(_) => {
                summary.errors.push(ImportError {
                    line: line_no,
                    message: "Ungueltige MAC-Adresse".to_string(),
                });
                continue;
            }
        };

        let subnet_id = match subnets
            .iter()
            .find(|(_, net)| net.contains(&IpAddr::V4(ip)))
            .map(|(id, _)| *id)
        {
            Some(id) => id,
            None => {
                summary.errors.push(ImportError {
                    line: line_no,
                    message: "Kein passendes Subnet fuer IP gefunden".to_string(),
                });
                continue;
            }
        };

        let location_id = if location_name.is_empty() {
            None
        } else if let Some(id) = locations.get(location_name) {
            Some(*id)
        } else {
            let inserted_id: Option<Uuid> = sqlx::query_scalar(
                "insert into locations (name) values ($1)
                 on conflict (name) do nothing
                 returning id",
            )
            .bind(location_name)
            .fetch_optional(pool)
            .await
            .unwrap_or_default();
            if inserted_id.is_some() {
                summary.locations_updated += 1;
            }
            let id: Option<Uuid> = if inserted_id.is_some() {
                inserted_id
            } else {
                sqlx::query_scalar("select id from locations where name = $1")
                    .bind(location_name)
                    .fetch_optional(pool)
                    .await
                    .unwrap_or_default()
            };
            if let Some(id) = id {
                locations.insert(location_name.to_string(), id);
            }
            id
        };

        let _room_id = if room_name.is_empty() {
            None
        } else if let Some(location_id) = location_id {
            let key = (location_id, room_name.to_string());
            if let Some(id) = rooms.get(&key) {
                Some(*id)
            } else {
                sqlx::query(
                    "insert into rooms (location_id, name) values ($1, $2)
                     on conflict (location_id, name) do nothing",
                )
                .bind(location_id)
                .bind(room_name)
                .execute(pool)
                .await
                .ok();
                let id: Option<Uuid> =
                    sqlx::query_scalar("select id from rooms where location_id = $1 and name = $2")
                        .bind(location_id)
                        .bind(room_name)
                        .fetch_optional(pool)
                        .await
                        .unwrap_or_default();
                if let Some(id) = id {
                    rooms.insert(key, id);
                }
                id
            }
        } else {
            None
        };

        let outlet_label = if lan_port.is_empty() {
            None
        } else if room_name.is_empty() {
            Some(lan_port.to_string())
        } else {
            Some(format!("{}-{}", room_name, lan_port))
        };

        let lan_outlet_id =
            if let (Some(location_id), Some(label)) = (location_id, outlet_label.as_deref()) {
                let key = (location_id, label.to_string());
                if let Some(id) = outlets.get(&key) {
                    Some(*id)
                } else {
                    sqlx::query(
                        "insert into lan_outlets (location_id, label, description)
                     values ($1, $2, $3)
                     on conflict (location_id, label) do nothing",
                    )
                    .bind(location_id)
                    .bind(label)
                    .bind(if room_name.is_empty() {
                        None
                    } else {
                        Some(room_name)
                    })
                    .execute(pool)
                    .await
                    .ok();
                    let id: Option<Uuid> = sqlx::query_scalar(
                        "select id from lan_outlets where location_id = $1 and label = $2",
                    )
                    .bind(location_id)
                    .bind(label)
                    .fetch_optional(pool)
                    .await
                    .unwrap_or_default();
                    if let Some(id) = id {
                        outlets.insert(key, id);
                    }
                    id
                }
            } else {
                None
            };

        let lan_port_value = if lan_port.is_empty() && room_name.is_empty() {
            None
        } else if room_name.is_empty() {
            Some(lan_port.to_string())
        } else if lan_port.is_empty() {
            Some(room_name.to_string())
        } else {
            Some(format!("{}-{}", room_name, lan_port))
        };

        let res: Option<bool> = sqlx::query_scalar(
            "insert into hosts (hostname, ip_address, mac_address, subnet_id, location_id, lan_outlet_id, location, lan_port, lan_dose, is_authorized)
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, true)
             on conflict (mac_address) do update
             set hostname = excluded.hostname,
                 ip_address = excluded.ip_address,
                 subnet_id = excluded.subnet_id,
                 location_id = excluded.location_id,
                 lan_outlet_id = excluded.lan_outlet_id,
                 location = excluded.location,
                 lan_port = excluded.lan_port,
                 lan_dose = excluded.lan_dose,
                 is_authorized = excluded.is_authorized
             returning (xmax = 0) as inserted",
        )
        .bind(hostname)
        .bind(ip.to_string())
        .bind(mac)
        .bind(subnet_id)
        .bind(location_id)
        .bind(lan_outlet_id)
        .bind(if location_name.is_empty() {
            None
        } else {
            Some(location_name)
        })
        .bind(lan_port_value.as_deref())
        .bind(lan_port_value.as_deref())
        .fetch_optional(pool)
        .await
        .unwrap_or_default();

        match res {
            Some(true) => summary.created += 1,
            Some(false) => summary.updated += 1,
            None => summary.errors.push(ImportError {
                line: line_no,
                message: "DB-Fehler beim Speichern".to_string(),
            }),
        }
    }

    Ok(summary)
}
