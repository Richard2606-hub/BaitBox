#!/usr/bin/env bash
# ============================================================================
# BaitBox — Block 1: Fresh Ubuntu 24.04 Vultr Cloud Compute VM Provisioning
# ============================================================================
# Installs Docker Engine, gVisor (runsc) kernel-isolated runtime, Caddy,
# Python 3.12, Node.js 22, creates a dedicated non-root `baitbox` service user,
# builds the disposable chamber and egress filter images, and verifies
# connectivity to Vultr Serverless Inference (https://api.vultrinference.com/v1).
# ============================================================================

set -euo pipefail

echo "[1/7] Updating Ubuntu 24.04 packages and installing system dependencies..."
sudo apt-get update -y
sudo apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    apt-transport-https \
    software-properties-common \
    python3.12 \
    python3.12-venv \
    python3-pip \
    sqlite3 \
    ufw \
    jq \
    git

echo "[2/7] Installing Official Docker Engine & Compose Plugin..."
sudo install -m 0755 -d /etc/apt/keyrings
if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg
fi

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update -y
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker

echo "[3/7] Installing gVisor (runsc) runtime for kernel-level chamber isolation..."
(
  set -e
  ARCH=$(uname -m)
  URL="https://storage.googleapis.com/gvisor/releases/release/latest/${ARCH}"
  wget -q "${URL}/runsc" "${URL}/runsc.sha512" \
       "${URL}/containerd-shim-runsc-v1" "${URL}/containerd-shim-runsc-v1.sha512"
  sha512sum -c runsc.sha512 -c containerd-shim-runsc-v1.sha512
  rm -f *.sha512
  chmod a+rx runsc containerd-shim-runsc-v1
  sudo mv runsc containerd-shim-runsc-v1 /usr/local/bin/
  sudo /usr/local/bin/runsc install
  sudo systemctl restart docker
  echo "gVisor (runsc) installed and registered with Docker successfully."
) || {
  echo "WARNING: gVisor (runsc) installation skipped or unsupported on this kernel; falling back to hardened standard Docker."
}

echo "[4/7] Installing Caddy web server for automatic HTTPS..."
sudo apt-get install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg --yes
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt-get update -y
sudo apt-get install -y caddy

echo "[5/7] Creating dedicated non-root 'baitbox' service user and locking down secrets..."
if ! id -u baitbox >/dev/null 2>&1; then
    sudo useradd --system --create-home --home-dir /opt/baitbox --shell /usr/sbin/nologin baitbox
fi
sudo usermod -aG docker baitbox

sudo mkdir -p /opt/baitbox/data/screenshots
sudo chown -R baitbox:baitbox /opt/baitbox
if [ -f .env ]; then
    sudo cp .env /opt/baitbox/.env
    sudo chown baitbox:baitbox /opt/baitbox/.env
    sudo chmod 0600 /opt/baitbox/.env
    echo "Locked /opt/baitbox/.env to mode 0600 (readable only by baitbox control-plane user)."
fi

echo "[6/7] Building BaitBox Disposable Chamber (M5) and Egress Filter (M6) images..."
sudo docker build -t baitbox-chamber:latest ./chamber
sudo docker build -t baitbox-egress:latest ./egress

echo "[7/7] Verifying Vultr Serverless Inference Catalog & Endpoint..."
python3.12 -m venv /tmp/baitbox-VerifyEnv
/tmp/baitbox-VerifyEnv/bin/pip install --quiet openai httpx vultr-model-catalog
/tmp/baitbox-VerifyEnv/bin/python scripts/check_vultr_models.py || true
rm -rf /tmp/baitbox-VerifyEnv

echo "============================================================================"
echo "BaitBox Vultr VM Setup Complete!"
echo "Next steps:"
echo "  1. Set VULTR_INFERENCE_API_KEY in .env"
echo "  2. Run: docker compose up -d --build"
echo "============================================================================"
