# Architektur: SyncLogic IP-Manager

Diese Dokumentation beschreibt die Systemstruktur des IP-Managers zur automatisierten Verwaltung von DHCP-Reservierungen und IP-Adressbeständen.

## 1. Übersicht der Komponenten

Das System besteht aus drei Hauptschichten:

* **Persistenzschicht (PostgreSQL):** Speichert die "Source of Truth". Hier liegen Subnetz-Definitionen, vergebene IP-Adressen, MAC-Adressen und Hostnamen.
* **Logikschicht (Rust Backend):** Das Herzstück des Projekts. Es validiert IP-Adressbereiche, verwaltet die Datenbanktransaktionen und generiert die Konfigurationsdateien für den DHCP-Dienst.
* **Infrastrukturschicht (dnsmasq):** Ein leichtgewichtiger, stabiler DHCP- und DNS-Server, der die vom Backend generierten statischen Zuweisungen im Netzwerk umsetzt.

## 2. Datenfluss und Synchronisation

Der Prozess der Adressvergabe ist strikt unidirektional (Database-First), um Inkonsistenzen zu vermeiden:

1. **Manipulation:** Ein Administrator fügt über den `ipmanager` (CLI oder API) einen neuen Host hinzu.
2. **Validierung & Speicherung:** Rust prüft die Korrektheit (z. B. IP im richtigen Subnetz, MAC-Format) und schreibt die Daten in die **PostgreSQL**-Datenbank.
3. **Export:** Ein Trigger oder ein periodischer Job im Backend liest die aktiven Reservierungen aus Postgres und erzeugt eine flache Konfigurationsdatei: `/etc/dnsmasq.d/01-rust-managed.conf`.
4. **Aktivierung:** Das Backend sendet ein Signal an das Betriebssystem (`systemctl reload dnsmasq` oder `SIGHUP`), damit dnsmasq die Datei ohne Verbindungsabbruch neu einliest.

## 3. Dateibasierte Integration (dnsmasq)

Anstelle einer komplexen API nutzt das System das bewährte `conf-dir`-Prinzip von dnsmasq.

* **Hauptvorteil:** Hohe Robustheit. Selbst wenn das Rust-Backend offline ist, vergibt dnsmasq weiterhin die zuletzt bekannten IP-Adressen.
* **Sicherheit:** Das Backend benötigt lediglich Schreibrechte für ein spezifisches Verzeichnis in `/etc/dnsmasq.d/`, was die Angriffsfläche im Vergleich zu einem vollumfänglichen DHCP-Root-Dienst minimiert.

## 4. Technologie-Stack

| Komponente | Technologie | Grund der Wahl |
| --- | --- | --- |
| **Datenbank** | PostgreSQL | Robuste Datentypen für Netzwerke (`inet`, `macaddr`), hohe Integrität. |
| **Backend** | Rust (Tokio, SQLx) | Speichersicherheit, hohe Performance, exzellente SQL-Integration. |
| **DHCP-Dienst** | dnsmasq | Extrem stabil, einfacher Datei-Sync, geringer Overhead gegenüber Kea. |
| **Betriebssystem** | Ubuntu 24.04 | Aktuelle Kernel-Features und stabile Paketbasis. |

## 5. Deployment-Struktur

* **Konfigurationspfad:** `/etc/dnsmasq.d/`
* **Export-Format:** `dhcp-host=AA:BB:CC:DD:EE:FF,10.0.0.1,hostname`
* **Service-Management:** Systemd (`isc-kea` wurde vollständig durch `dnsmasq` ersetzt).