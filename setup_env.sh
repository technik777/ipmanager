#!/bin/bash

# ===================================================================
# IPManager - Komplett-Setup (System, DNS-Fix, NTP & iPXE)
# Stand: 22. Jan 2026
# ===================================================================

set -e

echo "--- Starte IPManager System-Setup für User: $USER ---"

# 1. System-Updates & Abhängigkeiten
echo "Installiere System-Pakete (inkl. chrony für NTP)..."
sudo apt update && sudo apt upgrade -y
sudo apt install -y build-essential libssl-dev pkg-config postgresql postgresql-contrib dnsmasq curl git tcpdump chrony

# 2. Rust Installation
if ! command -v cargo &> /dev/null; then
    echo "Installiere Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
fi

# 3. Datenbank Setup
echo "Konfiguriere PostgreSQL..."
sudo -u postgres psql -c "CREATE USER ipmanager WITH PASSWORD 'admin123';" || true
sudo -u postgres psql -c "CREATE DATABASE ipmanager OWNER ipmanager;" || true

# 4. Verzeichnisstruktur & Berechtigungen
echo "Konfiguriere Verzeichnisse..."
sudo mkdir -p /var/lib/tftpboot/pxe-assets
sudo mkdir -p /etc/dnsmasq.d/

# Rechte für den aktuellen User setzen
sudo chown -R $USER:$USER /etc/dnsmasq.d/
sudo chown -R $USER:$USER /var/lib/tftpboot/

# 5. iPXE Images Download
echo "Lade iPXE Binaries herunter..."
IPXE_DIR="/var/lib/tftpboot/pxe-assets"
URLS=(
    "https://boot.ipxe.org/ipxe.lkrn"
    "https://boot.ipxe.org/ipxe.pxe"
    "https://boot.ipxe.org/ipxe.efi"
)

for url in "${URLS[@]}"; do
    filename=$(basename $url)
    if [ ! -f "$IPXE_DIR/$filename" ]; then
        echo "Downloade $filename..."
        curl -L -o "$IPXE_DIR/$filename" "$url"
    else
        echo "$filename existiert bereits, überspringe..."
    fi
done

# 6. Sudoers-Regel für dnsmasq Reload
SUDOERS_LINE="$USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart dnsmasq"
if ! sudo grep -q "$USER.*dnsmasq" /etc/sudoers; then
    echo "Erstelle Sudoers-Eintrag für dnsmasq..."
    echo "$SUDOERS_LINE" | sudo tee -a /etc/sudoers > /dev/null
fi

# 7. SQLx CLI
if ! command -v sqlx &> /dev/null; then
    echo "Installiere SQLx CLI..."
    cargo install sqlx-cli --no-default-features --features postgres
fi

# 8. DNS-Konflikt lösen (systemd-resolved deaktivieren)
echo "Löse Port 53 Konflikt (systemd-resolved)..."
if systemctl is-active --quiet systemd-resolved; then
    sudo systemctl disable --now systemd-resolved
    [ -L /etc/resolv.conf ] && sudo rm /etc/resolv.conf
    # Statische resolv.conf für den Server selbst
    echo -e "nameserver 8.8.8.8\nnameserver 1.1.1.1" | sudo tee /etc/resolv.conf > /dev/null
    echo "systemd-resolved deaktiviert. Port 53 ist nun frei."
else
    echo "systemd-resolved ist bereits inaktiv."
fi

# 9. NTP-Server Konfiguration (Chrony)
echo "Konfiguriere Chrony NTP-Server..."
# Erlaube Zugriff für das gesamte Firmennetz
if ! grep -q "allow 10.0.0.0/8" /etc/chrony/chrony.conf; then
    echo "allow 10.0.0.0/8" | sudo tee -a /etc/chrony/chrony.conf
    echo "allow 172.16.0.0/12" | sudo tee -a /etc/chrony/chrony.conf
    echo "allow 192.168.0.0/16" | sudo tee -a /etc/chrony/chrony.conf
    sudo systemctl restart chrony
    echo "Chrony konfiguriert und neu gestartet."
fi

# 10. GitHub Remote & Push Setup
echo "Konfiguriere Git und führe Push aus..."
mkdir -p ~/.ssh
ssh-keyscan github.com >> ~/.ssh/known_hosts 2>/dev/null
git remote set-url origin git@github.com:SyncLogic-2026/ipmanager.git || git remote add origin git@github.com:SyncLogic-2026/ipmanager.git

git add .
if ! git diff-index --quiet HEAD --; then
    git commit -m "Update: System Setup inkl. Chrony NTP und iPXE Assets"
    git push -u origin main || git push -u origin master
else
    echo "Keine Änderungen zum Committen vorhanden."
fi

echo "--- Setup und Push erfolgreich abgeschlossen! ---"
echo "IPManager (DNS/DHCP/NTP) ist bereit für den Einsatz."