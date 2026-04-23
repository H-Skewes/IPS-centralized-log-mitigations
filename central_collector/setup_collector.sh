#!/bin/bash
# setup_collector.sh - Set up the central log collector VM
# Usage: sudo bash setup_collector.sh

set -e

echo "=================================================="
echo "  Cloud Security Lab - Central Collector Setup"
echo "=================================================="

if [ "$EUID" -ne 0 ]; then
    echo "[!] Run as root: sudo bash setup_collector.sh"
    exit 1
fi

echo "[*] Installing dependencies..."
apt update -q
apt install -y python3-pip openssh-client

pip3 install paramiko

echo "[*] Generating self-signed TLS certificate..."
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt \
    -days 365 -nodes \
    -subj "/CN=log-collector/O=LabSecurity/C=US" \
    -addext "subjectAltName=IP:10.10.0.20"

echo "[+] Certificate generated: server.crt / server.key"

echo "[*] Generating SSH key for mitigation (passwordless SSH to victim VMs)..."
if [ ! -f /root/.ssh/id_ed25519 ]; then
    ssh-keygen -t ed25519 -f /root/.ssh/id_ed25519 -N "" -C "lab-collector"
    echo "[+] SSH key generated at /root/.ssh/id_ed25519"
else
    echo "[!] SSH key already exists at /root/.ssh/id_ed25519"
fi

echo ""
echo "=================================================="
echo "[+] Collector setup complete!"
echo "=================================================="
echo ""
echo "IMPORTANT: Copy the SSH public key to each victim VM:"
echo ""
cat /root/.ssh/id_ed25519.pub
echo ""
echo "On each victim VM run:"
echo "  mkdir -p /root/.ssh"
echo "  echo '<above key>' >> /root/.ssh/authorized_keys"
echo "  chmod 600 /root/.ssh/authorized_keys"
echo ""
echo "Then start the collector:"
echo "  sudo python3 collector.py"
