# API Spezifikation: dnsmasq Host-Integration

Diese Spezifikation definiert die Schnittstelle zwischen dem Rust-Backend (`ipmanager`) und dem DHCP-Dienst `dnsmasq`.

## 1. Schnittstellentyp

**Dateibasiertes Konfigurations-Injektion** via `conf-dir`.

## 2. Speicherort & Berechtigungen

* **Pfad:** `/etc/dnsmasq.d/01-rust-managed.conf`
* **Besitzer:** `root` (oder der User, unter dem das Rust-Backend läuft)
* **Leserechte:** `dnsmasq` muss Leserechte besitzen (Standard: `644`).

## 3. Datenformat (Eintrag pro Zeile)

Jede statische Reservierung wird als einzelne Zeile im `dhcp-host`-Format von dnsmasq exportiert.

### Struktur eines Eintrags:

`dhcp-host=[MAC-ADRESSE],[IP-ADRESSE],[HOSTNAME],[LEASE-TIME]`

| Parameter | Typ | Beispiel | Beschreibung |
| --- | --- | --- | --- |
| **MAC-ADRESSE** | String (Hex) | `00:1a:2b:3c:4d:5e` | Eindeutige Hardware-Adresse des Clients. |
| **IP-ADRESSE** | String (IPv4) | `10.112.57.50` | Die aus der PostgreSQL-DB zugewiesene IP. |
| **HOSTNAME** | String | `server-01` | Optionaler DNS-Name für den Client. |
| **LEASE-TIME** | String | `infinite` | Optional (Standard: `infinite` für statische IPs). |

## 4. Beispiel-Inhalt der generierten Datei

```text
# Automatisch generiert durch SyncLogic ipmanager - NICHT MANUELL EDITIEREN
dhcp-host=00:1a:2b:3c:4d:5e,10.112.57.50,pro-web-01,infinite
dhcp-host=08:00:27:85:93:22,10.112.57.51,pro-db-01,infinite
dhcp-host=a1:b2:c3:d4:e5:f6,10.112.57.60,backup-node,infinite

```

## 5. Synchronisations-Logik (Rust Backend)

Das Backend muss bei jeder Änderung in der PostgreSQL-Datenbank folgende Schritte ausführen:

1. **Query:** Abruf aller aktiven Reservierungen aus der Tabelle `hosts`.
2. **Atomic Write:** Die Datei wird erst in ein temporäres Verzeichnis geschrieben und dann per `mv` (Move) nach `/etc/dnsmasq.d/` verschoben, um unvollständige Konfigurationen bei Abstürzen zu vermeiden.
3. **Validation:** Optionaler Aufruf von `dnsmasq --test`, um die Syntax zu prüfen.
4. **Signal:** Senden eines `SIGHUP` an den dnsmasq-Prozess oder Ausführung von `systemctl restart dnsmasq`.

## 6. Fehlerbehandlung

* **Duplikate:** Das Rust-Backend muss sicherstellen, dass keine MAC oder IP doppelt in der Datei vorkommt (Datenbank-Constraints in Postgres nutzen).
* **Format-Validierung:** MAC-Adressen müssen dem Regex `^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$` entsprechen.
* **Service-Check:** Wenn der Signal-Befehl fehlschlägt, muss ein Rollback oder eine Alarmierung im Backend erfolgen.