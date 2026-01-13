# Datenbank-Schema: SyncLogic IP-Manager

Diese Dokumentation beschreibt das PostgreSQL-Schema für die Verwaltung von Netzwerken und DHCP-Hosts.

## 1. Überblick

Das Schema ist darauf ausgelegt, die Integrität der IP-Vergabe sicherzustellen. Wir nutzen PostgreSQL-interne Netzwerk-Datentypen, um fehlerhafte Eingaben (z. B. ungültige IPs oder MACs) bereits beim Schreibvorgang zu verhindern.

## 2. Tabellen-Definitionen

### 2.1 Tabelle: `subnets`

Speichert die IP-Bereiche, die vom System verwaltet werden.

| Spalte | Datentyp | Beschreibung |
| --- | --- | --- |
| `id` | `SERIAL` | Primärschlüssel. |
| `network` | `CIDR` | Netzwerkadresse (z. B. `10.112.57.0/24`). |
| `description` | `VARCHAR(255)` | Beschreibung des VLANs oder Standorts. |
| `vlan_id` | `INTEGER` | Optionale VLAN-ID. |

```sql
CREATE TABLE subnets (
    id SERIAL PRIMARY KEY,
    network CIDR NOT NULL UNIQUE,
    description VARCHAR(255),
    vlan_id INTEGER
);

```

### 2.2 Tabelle: `hosts`

Speichert die individuellen DHCP-Reservierungen.

| Spalte | Datentyp | Beschreibung |
| --- | --- | --- |
| `id` | `SERIAL` | Primärschlüssel. |
| `mac_address` | `MACADDR` | Eindeutige Hardware-Adresse (Format: `08:00:27:85:93:22`). |
| `ip_address` | `INET` | Die zugewiesene IP-Adresse. |
| `hostname` | `VARCHAR(255)` | Der DNS-Name des Geräts. |
| `subnet_id` | `INTEGER` | Fremdschlüssel auf die Tabelle `subnets`. |
| `created_at` | `TIMESTAMPTZ` | Zeitstempel der Erstellung (Default: `NOW()`). |

```sql
CREATE TABLE hosts (
    id SERIAL PRIMARY KEY,
    mac_address MACADDR NOT NULL UNIQUE,
    ip_address INET NOT NULL UNIQUE,
    hostname VARCHAR(255) NOT NULL,
    subnet_id INTEGER REFERENCES subnets(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

```

## 3. Constraints & Validierung

Um eine saubere DHCP-Konfiguration für `dnsmasq` zu garantieren, werden folgende Regeln angewendet:

1. **MAC-Eindeutigkeit:** Eine MAC-Adresse kann nicht zwei verschiedenen IPs zugewiesen werden.
2. **IP-Eindeutigkeit:** Jede IP im System darf nur einmal vergeben werden.
3. **Bereichsprüfung (Logic in Rust):** Das Rust-Backend prüft vor dem Insert, ob die `ip_address` mathematisch innerhalb des CIDR-Bereichs des zugehörigen `subnets` liegt.

## 4. Indizierung

Für schnelle Abfragen des Backends (besonders beim Export der Konfigurationsdatei) werden Indizes auf die Suchfelder gesetzt:

```sql
CREATE INDEX idx_hosts_ip ON hosts(ip_address);
CREATE INDEX idx_hosts_mac ON hosts(mac_address);

```

## 5. SQLx Integration (Rust)

Das Rust-Backend nutzt `sqlx` mit dem `postgres`-Feature. Dank der `MACADDR` und `INET` Typen kann Rust diese direkt in Typen wie `std::net::IpAddr` mappen.