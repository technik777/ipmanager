# Operation Manual: SyncLogic IP-Manager

Dieses Handbuch beschreibt den laufenden Betrieb, die Wartungsaufgaben und die Recovery-Prozesse für das IP-Management-System.

## 1. Täglicher Betrieb & Monitoring

Um sicherzustellen, dass der DHCP-Dienst und das Backend reibungslos funktionieren, sollten folgende Komponenten überwacht werden:

### 1.1 Dienst-Status prüfen

Der wichtigste Indikator ist der Status des dnsmasq-Daemons:

```bash
sudo systemctl status dnsmasq

```

### 1.2 Logfiles rotieren und einsehen

dnsmasq schreibt standardmäßig in das System-Log. Um die letzten 100 DHCP-Transaktionen (Vergabe von Leases) zu sehen:

```bash
grep "dnsmasq-dhcp" /var/log/syslog | tail -n 100

```

## 2. Datenbank-Wartung (PostgreSQL)

Da PostgreSQL die "Source of Truth" ist, ist ein Datenverlust hier kritisch.

### 2.1 Backup erstellen

Erstelle täglich einen Dump der Datenbank:

```bash
# Manueller Export
pg_dump -U ipadmin ipmanager_db > ipmanager_backup_$(date +%F).sql

```

### 2.2 Wiederherstellung (Restore)

Im Falle einer Datenbank-Korruption:

```bash
# Datenbank neu erstellen und Backup einspielen
dropdb ipmanager_db
createdb ipmanager_db
psql ipmanager_db < ipmanager_backup_DATEI.sql

```

## 3. Verwalten von Subnetzen und Hosts

Obwohl das Ziel die Automatisierung über Rust ist, können Notfall-Anpassungen direkt in der Datenbank vorgenommen werden.

### 3.1 Neuen IP-Bereich hinzufügen

```sql
INSERT INTO subnets (network, description) 
VALUES ('10.112.58.0/24', 'Neues Büro UG');

```

### 3.2 Host manuell sperren/löschen

Um eine Reservierung zu entfernen:

```sql
DELETE FROM hosts WHERE mac_address = '00:11:22:33:44:55';

```

*Hinweis: Nach manuellen DB-Eingriffen muss der Rust-Sync-Prozess manuell angestoßen werden, um die `dnsmasq`-Files zu aktualisieren.*

## 4. Notfall-Prozeduren (Disaster Recovery)

### 4.1 DHCP-Server Totalausfall

Falls dnsmasq nicht mehr startet und der Fehler nicht sofort findbar ist:

1. Sichere die aktuelle `/etc/dnsmasq.d/01-rust-managed.conf`.
2. Deinstalliere und installiere dnsmasq neu: `sudo apt reinstall dnsmasq`.
3. Kopiere die gesicherte Konfiguration zurück.

### 4.2 Manuelle DHCP-Übernahme

Sollte das Rust-Backend ausfallen, bleibt dnsmasq funktionsfähig (statisch). Du kannst die `/etc/dnsmasq.d/01-rust-managed.conf` händisch mit einem Texteditor bearbeiten, um dringende Änderungen vorzunehmen, bis das Backend wieder läuft.

## 5. Software-Updates

### 5.1 Rust-Backend aktualisieren

Wenn eine neue Version von `ipmanager` auf GitHub verfügbar ist:

```bash
cd ~/ipmanager
git pull
cargo build --release
sudo systemctl restart ipmanager-service # Falls als Service eingerichtet