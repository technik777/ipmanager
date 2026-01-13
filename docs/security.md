# Sicherheitskonzept: SyncLogic IP-Manager

Dieses Dokument beschreibt die Sicherheitsmaßnahmen und Best Practices zum Schutz des IP-Managers und der Netzwerk-Infrastruktur.

## 1. Prinzip der minimalen Berechtigung (Least Privilege)

Das System ist so konzipiert, dass keine Komponente mehr Rechte besitzt, als sie für ihre spezifische Aufgabe benötigt.

### 1.1 Dienst-Ebene (dnsmasq)

* **User-Isolation:** dnsmasq wird unter einem eigenen, unprivilegierten Systembenutzer (`dnsmasq`) ausgeführt.
* **Dateizugriff:** dnsmasq hat nur Leserechte auf `/etc/dnsmasq.d/` und keine Schreibrechte auf Systemverzeichnisse.

### 1.2 Backend-Ebene (Rust)

* **Kein Root-Zwang:** Das Rust-Backend läuft als Standard-Benutzer. Schreibrechte werden explizit nur für die Datei `/etc/dnsmasq.d/01-rust-managed.conf` vergeben.
* **Sudo-Restriktion:** In der `/etc/sudoers` wird dem Backend exklusiv erlaubt, `systemctl restart dnsmasq` ohne Passwort auszuführen. Ein Zugriff auf andere Systembefehle ist untersagt.

## 2. Datenbank-Sicherheit (PostgreSQL)

* **Authentifizierung:** Das Backend verbindet sich über einen dedizierten User (`ipadmin`) mit einem starken Passwort.
* **Netzwerk-Zugriff:** PostgreSQL wird so konfiguriert (`pg_hba.conf`), dass es standardmäßig nur Verbindungen von `localhost` (127.0.0.1) akzeptiert.
* **Input-Validierung:** Durch die Nutzung von `sqlx` und Prepared Statements in Rust sind **SQL-Injection-Angriffe** technisch ausgeschlossen.

## 3. Netzwerk-Sicherheit

* **DHCP-Validierung:** Das Backend validiert MAC- und IP-Adressen gegen reguläre Ausdrücke und prüft die Zugehörigkeit zum Subnetz, bevor sie in die Konfiguration geschrieben werden. Dies verhindert "IP-Hijacking" durch fehlerhafte Einträge.
* **Vermeidung von Port-Exposition:** Das Backend bietet keine öffentliche Webschnittstelle an, sofern diese nicht explizit durch einen Reverse-Proxy (wie Nginx mit TLS) und Authentifizierung geschützt ist.

## 4. Dateisystem-Schutz

Die Datei-Berechtigungen werden wie folgt gesetzt, um Manipulationen durch andere Benutzer des Systems zu verhindern:

| Pfad | Berechtigung | Besitzer | Zweck |
| --- | --- | --- | --- |
| `/etc/dnsmasq.conf` | `644` | `root:root` | Systemweite Basis-Config. |
| `/etc/dnsmasq.d/01-rust-managed.conf` | `664` | `youruser:dnsmasq` | Dynamische DHCP-Hosts. |
| `.env` | `600` | `youruser:youruser` | Enthält Datenbank-Passwort. |

## 5. Abwehr von DHCP-Angriffen

Obwohl der IP-Manager die Vergabe steuert, sollte das zugrunde liegende Netzwerk zusätzlich abgesichert werden:

* **DHCP Snooping:** Es wird empfohlen, auf den Switches DHCP-Snooping zu aktivieren, damit nur der Port, an dem dein dnsmasq-Server hängt, DHCP-Antworten senden darf.
* **Log-Monitoring:** Regelmäßige Überprüfung der dnsmasq-Logs auf ungewöhnliche Anfragen ("DHCP Starvation Attacks").