#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/deepai-proxy"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT="${PORT:-1417}"
PROXY_API_KEY="${PROXY_API_KEY:-deepai-local}"
DEEPAI_KEYS="${DEEPAI_KEYS:-}"

if ! command -v python3 >/dev/null 2>&1; then
  apt-get update -y && apt-get install -y python3
fi

mkdir -p "$APP_DIR"
if [ "$SRC_DIR" != "$APP_DIR" ]; then
  cp -f "$SRC_DIR/server.py" "$SRC_DIR/run.sh" "$SRC_DIR/config.example.json" "$SRC_DIR/deepai-proxy.service" "$APP_DIR/"
fi
chmod +x "$APP_DIR/server.py" "$APP_DIR/run.sh"

if [ ! -f "$APP_DIR/.env" ]; then
  cat > "$APP_DIR/.env" <<EOF
HOST=0.0.0.0
PORT=${PORT}
PROXY_API_KEY=${PROXY_API_KEY}
DEEPAI_KEYS=${DEEPAI_KEYS}
CONFIG_DIR=/opt/deepai-proxy/data
EOF
  chmod 600 "$APP_DIR/.env"
fi

cp -f "$APP_DIR/deepai-proxy.service" /etc/systemd/system/deepai-proxy.service
systemctl daemon-reload
systemctl enable --now deepai-proxy.service

PUB_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo "======================================================"
echo "deepai-proxy installed & running!"
echo "Base URL (for 9Router) : http://${PUB_IP:-127.0.0.1}:${PORT}/v1"
echo "Web Dashboard          : http://${PUB_IP:-127.0.0.1}:${PORT}/"
echo "Gateway / Admin Token  : ${PROXY_API_KEY}"
echo "Service status         : systemctl status deepai-proxy"
echo "Logs                   : journalctl -u deepai-proxy -f"
echo "======================================================"
