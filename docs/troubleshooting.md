# Troubleshooting: SyncLogic IP-Manager

Dieses Dokument hilft bei der Diagnose und Behebung von Fehlern im Zusammenspiel zwischen dem Rust-Backend, der PostgreSQL-Datenbank und dem dnsmasq-Service.

## 1. DHCP-Dienst (dnsmasq) startet nicht

### Symptom: `systemctl status dnsmasq` zeigt "failed"

**Mögliche Ursachen:**

* **Port-Konflikt:** Ein anderer Dienst (z. B. Kea, ISC-DHCP oder systemd-resolved) belegt Port 67 (DHCP) oder Port 53 (DNS).
* **Syntaxfehler:** Die vom Rust-Backend generierte Datei in `/etc/dnsmasq.d/` hat ein falsches Format.

**Lösungen:**

1. **Syntax-Check:** Führe `dnsmasq --test` aus. Es zeigt dir genau die Zeile an, die den Fehler verursacht.
2. **Port-Prüfung:** `sudo ss -tulpn | grep -E ":67|:53"` zeigt, welche Prozesse die Ports belegen.
3. **Logs prüfen:** `sudo journalctl -u dnsmasq -n 50` liefert die detaillierte Fehlermeldung beim Start.

---

## 2. Änderungen werden im Netzwerk nicht aktiv

### Symptom: Host in DB geändert, aber Client bekommt alte IP

**Mögliche Ursachen:**

* **Signal fehlt:** Das Rust-Backend hat die Datei geschrieben, aber dnsmasq nicht neu geladen.
* **Lease-Zeit:** Der Client hat noch eine gültige Lease und fragt den Server nicht nach neuen Daten.

**Lösungen:**

1. **Dienst-Reload prüfen:** Stelle sicher, dass `sudo systemctl restart dnsmasq` vom Rust-Backend erfolgreich ausgeführt wurde.
2. **Datei-Check:** Prüfe mit `cat /etc/dnsmasq.d/01-rust-managed.conf`, ob der neue Host wirklich in der Datei steht.
3. **Client-Reset:** Erneuere die IP am Client manuell (z. B. `ipconfig /renew` unter Windows oder `sudo dhclient -v -r` unter Linux).

---

## 3. Datenbank-Verbindungsprobleme

### Symptom: Rust-Backend meldet `ConnectionRefused` oder `AuthFailed`

**Mögliche Ursachen:**

* **Postgres lauscht nicht:** Die Datenbank ist gestoppt.
* **Berechtigungen:** Der User `ipadmin` hat keine Rechte auf die Tabelle.

**Lösungen:**

1. **Status prüfen:** `sudo systemctl status postgresql`.
2. **Manuelle Anmeldung:** Versuche `psql -U ipadmin -d ipmanager_db -h localhost` – wenn das fehlschlägt, ist das Passwort oder die `pg_hba.conf` falsch.

---

## 4. Berechtigungsfehler (Permission Denied)

### Symptom: Rust-Backend kann die `.conf` Datei nicht schreiben

**Mögliche Ursachen:**

* **Dateirechte:** Der User, unter dem das Rust-Programm läuft, hat keine Schreibrechte in `/etc/dnsmasq.d/`.

**Lösung:**
Vergib die Rechte wie im `setup_guide.md` beschrieben:

```bash
sudo chown youruser:dnsmasq /etc/dnsmasq.d/01-rust-managed.conf
sudo chmod 664 /etc/dnsmasq.d/01-rust-managed.conf

```

---

## 5. Log-Analyse-Quickstart

Nutze diese Befehle für eine schnelle Diagnose:

| Befehl | Zweck |
| --- | --- |
| `tail -f /var/log/syslog | grep dnsmasq` | Live-Überwachung der DHCP-Vergaben. |
| `dnsmasq --test` | Validierung aller Konfigurationsdateien. |
| `cargo test` | Ausführen der internen Validierungs-Logik im Rust-Backend. |