````markdown
# IPManager – IP-Management & Kea DHCP Control (PostgreSQL, Rust/Axum) inkl. PXE/iPXE-Menü

IPManager ist eine Webanwendung zur Verwaltung von Hosts, Subnetzen und DHCP-relevanten Daten in PostgreSQL sowie zur Generierung/Deploy von Kea DHCPv4-Konfigurationen. Zusätzlich bietet IPManager ein PXE/iPXE-Boot-Menü, das dynamisch aus der Datenbank erzeugt wird und Boot-Images per Web-UI verwaltbar macht.

## Features

### Core
- Web-UI für:
  - Hosts (Create/Read/Update/Delete)
  - Subnetze & DHCP-Pools (je nach Projektstand)
- PostgreSQL als zentrale Datenbank (SQLx)
- Rust/Axum Backend, Tera Templates (Server Side Rendering)
- Sessions via `tower-sessions` (stabiler Key aus `SESSION_SECRET`)
- Strikte Eingabevalidierung:
  - IPv4-only (IPv6 wird abgewiesen)
  - MAC-Formatprüfung
  - Duplicate-Checks (Hostname/IP/MAC) vor DB-Schreiboperationen
- Unit-Tests + optionale Integrationstests gegen echte PostgreSQL-DB

### Kea DHCPv4 Integration
- Generierung einer Kea DHCPv4 JSON-Konfiguration aus DB/Config
- PXE/iPXE Bootfile-Logik über globale `client-classes`:
  - iPXE Clients → erhalten direkt `boot.ipxe` (HTTP)
  - UEFI x86_64 → erhalten UEFI-iPXE Bootfile via TFTP
  - BIOS (Catch-all) → erhalten BIOS-iPXE Bootfile via TFTP

### PXE/iPXE Boot Menü
- Web-UI CRUD für PXE-Images (Linux/Chain)
- Sichere Dateiauswahl (Dropdown) aus einem konfigurierten PXE-Root-Verzeichnis
- `/pxe-assets/*` liefert PXE-Dateien per HTTP (nur bei aktivem PXE)
- `/boot.ipxe` generiert dynamisch ein iPXE-Menü aus DB-Einträgen

---

## Anforderungen

- Rust Toolchain (stable) + Cargo
- PostgreSQL
- (Optional) Kea DHCP Server für produktiven Betrieb
- (Optional) TFTP Server / Bereitstellung von iPXE-Binaries (BIOS/UEFI), wenn PXE genutzt wird

---

## Projektstruktur (high level)

- `main.rs` – Router/Server-Setup, Session-Layer, Static Serving (PXE Assets)
- `config.rs` – Laden der Konfiguration aus Environment
- `web.rs` – Webhandler/Validierungen/CRUD
- `dhcp_kea.rs` – Kea DHCPv4 JSON Generator (inkl. PXE client-classes)
- `migrations/` – SQL Migrationen (inkl. PXE-Images Tabelle)
- `templates/` – Tera Templates (inkl. PXE UI)

---

## Konfiguration (Environment)

IPManager wird über Environment Variablen konfiguriert. Verwende eine `.env` Datei (z.B. über `dotenv`) oder setze Variablen im Service.

### Pflicht (typischer Betrieb)
- `DATABASE_URL`
  - Beispiel: `postgres://user:pass@localhost:5432/ipmanager`
- `SESSION_SECRET`
  - Muss gesetzt sein (kein Default). Verwende einen ausreichend langen zufälligen Wert.
- `SESSION_COOKIE_NAME` (optional, Default: `ipmanager_session`)
- `SESSION_COOKIE_SECURE` (optional; `true` für HTTPS-only Cookies)
- `SESSION_TTL` (optional; je nach Config-Implementierung)

### Optional: Integrationstests mit echter DB
- `TEST_DATABASE_URL`
  - Wenn gesetzt, laufen DB-Integrationstests gegen diese Datenbank.
  - Wenn nicht gesetzt, werden Integrationstests sauber übersprungen.

### PXE/iPXE (nur wenn PXE genutzt wird)
- `PXE_ENABLED` (true/false)
- `PXE_ROOT_DIR`
  - Verzeichnis mit Boot-Artefakten (Kernel/Initrd/iPXE Binaries etc.)
- `PXE_HTTP_BASE_URL`
  - Basis-URL, unter der `/pxe-assets` erreichbar ist (z.B. `http://ipmanager:8080/pxe-assets`)
- `PXE_TFTP_SERVER`
  - IP/Hostname des TFTP-Servers (für Kea next-server / Bootloader-Download)
- `PXE_BIOS_BOOTFILE`
  - Bootfile für BIOS (z.B. `undionly.kpxe` oder `ipxe.pxe`)
- `PXE_UEFI_BOOTFILE`
  - Bootfile für UEFI x86_64 (z.B. `ipxe.efi` oder `snponly.efi`)

> Hinweis: IPManager liefert PXE Assets per HTTP aus (`/pxe-assets/*`). Der iPXE-Bootloader selbst wird typischerweise per TFTP verteilt (BIOS/UEFI), danach lädt iPXE das Menü via HTTP.

---

## Setup: Datenbank & Migrationen

1. Datenbank anlegen (Beispiel):
   ```bash
   createdb ipmanager
````

2. `DATABASE_URL` setzen:

   ```bash
   export DATABASE_URL="postgres://user:pass@localhost:5432/ipmanager"
   ```

3. Migrationen ausführen (je nach eurem Setup):

   * Wenn ihr `sqlx-cli` nutzt:

     ```bash
     cargo install sqlx-cli --no-default-features --features postgres
     sqlx migrate run
     ```
   * Alternativ: über euer bestehendes Migrations-/Startskript.

---

## Build & Run

### Development

```bash
cargo run
```

### Tests

```bash
cargo test
```

### Integrationstests (optional)

Setze `TEST_DATABASE_URL` auf eine leere Test-DB; Migrationen werden automatisch ausgeführt, und jeder Test läuft in einer Transaktion mit Rollback.

```bash
export TEST_DATABASE_URL="postgres://user:pass@localhost:5432/ipmanager_test"
cargo test
```

---

## Web-UI: Hosts

* Hosts werden mit IPv4 und MAC-Adresse verwaltet.
* Validierungen:

  * IPv4 muss gültig sein (IPv6 wird abgewiesen)
  * MAC muss gültiges Format haben
  * Duplicate-Check: Hostname/IP/MAC dürfen nicht bereits existieren
* Zusätzlich wird geprüft, ob IP/Zuordnung zum Subnetz plausibel ist (je nach Implementierung im Projekt).

---

## PXE/iPXE: Nutzung

### 1) PXE aktivieren

Setze in `.env` (oder Environment):

```env
PXE_ENABLED=true
PXE_ROOT_DIR=/var/lib/ipmanager/pxe
PXE_HTTP_BASE_URL=http://ipmanager:8080/pxe-assets
PXE_TFTP_SERVER=192.168.1.10
PXE_BIOS_BOOTFILE=undionly.kpxe
PXE_UEFI_BOOTFILE=ipxe.efi
```

### 2) Dateien bereitstellen

Lege Boot-Artefakte in `PXE_ROOT_DIR` ab. IPManager bietet diese Dateien per HTTP an:

* URL: `http://<ipmanager>/pxe-assets/<relative-path>`

Die PXE-Image-UI nutzt eine Dropdown-Liste dieser Dateien (sicherer Whitelist/Existenz-Check).

### 3) PXE-Images im Web anlegen

* Öffne: `/pxe/images`
* Erstelle Einträge:

  * **Linux**: Kernel-Pfad (Pflicht), optional Initrd, Cmdline
  * **Chain**: URL (http/https)

Validierung (serverseitig):

* Name: `[A-Za-z0-9._-]`, nicht leer
* `kind`: linux/chain
* `arch`: any/bios/uefi
* Linux: Pfade müssen relativ sein, ohne `..`, innerhalb `PXE_ROOT_DIR`, und existieren
* Chain: `http://` oder `https://` Pflicht
* Cmdline wird getrimmt; Zeilenumbrüche werden entfernt

### 4) iPXE-Menü abrufen

* Endpoint: `/boot.ipxe`
* Liefert ein iPXE-Skript mit Menü:

  * Local disk
  * iPXE shell
  * alle `enabled` PXE-Images aus DB

### 5) Kea DHCP: PXE/iPXE Bootfile-Logik

Wenn `PXE_ENABLED=true`, erzeugt der Kea-Generator globale `client-classes`:

* `ipxe`:

  * Match: Vendor-Class iPXE
  * boot-file-name: `boot.ipxe` URL (HTTP)
* `uefi_x64`:

  * Match: `option[93].hex == 0x0009`
  * next-server: `PXE_TFTP_SERVER`
  * boot-file-name: `PXE_UEFI_BOOTFILE`
* `bios`:

  * Catch-all
  * next-server: `PXE_TFTP_SERVER`
  * boot-file-name: `PXE_BIOS_BOOTFILE`

Wichtig:

* Reihenfolge der Klassen ist so gesetzt, dass iPXE immer gewinnt, wenn iPXE bereits läuft.

---

## Beispiel: iPXE Menü-Ausschnitt

Ein Beispiel-Ausschnitt aus `/boot.ipxe` (vereinfacht):

```text
#!ipxe
menu IPManager PXE Boot Menu
item local Local disk
item shell iPXE shell
item img1 Ubuntu Installer [any]
item img2 Rescue Chain [any]
choose selected || goto start

:img1
kernel http://ipmanager:8080/pxe-assets/vmlinuz ip=dhcp ...
initrd http://ipmanager:8080/pxe-assets/initrd.img
boot

:img2
chain https://example.org/rescue.ipxe
```

---

## Security / Betriebshinweise

* `SESSION_SECRET` muss in Produktion zufällig und ausreichend lang sein.
* `PXE_ROOT_DIR` sollte restriktive Rechte haben (nur Leserechte für den Webprozess, soweit möglich).
* Stelle sicher, dass `/pxe-assets` nur das ausliefert, was du ausliefern willst.
* In produktiven Setups empfiehlt sich TLS (Reverse Proxy), insbesondere wenn du Chain-URLs oder Assets über HTTPS ausliefern willst.

---

## Troubleshooting

### PXE-Menü erscheint nicht

* Prüfe, ob `PXE_ENABLED=true` gesetzt ist
* Prüfe, ob `/boot.ipxe` erreichbar ist
* Prüfe Kea-Konfiguration: client-classes vorhanden?
* Prüfe iPXE Vendor-Class:

  * In iPXE sollte Vendor-Class „iPXE“ sein (damit die `ipxe` class greift)

### Files nicht im Dropdown

* Liegen die Dateien wirklich unter `PXE_ROOT_DIR`?
* Sind die Pfade relativ und ohne `..`?
* Sind die Dateiendungen/Filter in `list_pxe_files` passend?

### Integrationstests laufen nicht

* Setze `TEST_DATABASE_URL`
* Stelle sicher, dass die DB leer/als Test-DB gedacht ist

---

## Lizenz

Interne Nutzung / projektabhängig. (Falls gewünscht, hier eine Lizenz eintragen.)

```
::contentReference[oaicite:0]{index=0}
```
