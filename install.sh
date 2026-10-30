
#!/usr/bin/env bash

set -euo pipefail

REPO="sahand363/sahand-tunnel"
VERSION_URL="https://github.com/${REPO}/releases/latest/download"
BIN="/usr/local/bin/sahand-tunnel"
CONFIG_DIR="/etc/sahand-tunnel"
DATA_DIR="/var/lib/sahand-tunnel"
SERVICE="/etc/systemd/system/sahand-tunnel.service"

if [ "$EUID" -ne 0 ]; then
    echo "Please run this installer as root."
    exit 1
fi

if [ "$(uname -s)" != "Linux" ]; then
    echo "Only Linux is supported."
    exit 1
fi

if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [ "${ID:-}" != "ubuntu" ]; then
        echo "This installer currently supports Ubuntu."
        exit 1
    fi
fi

case "$(uname -m)" in
    x86_64)
        ARCH="amd64"
        ;;
    aarch64|arm64)
        ARCH="arm64"
        ;;
    *)
        echo "Unsupported CPU architecture."
        exit 1
        ;;
esac

BIN_NAME="sahand-tunnel-linux-${ARCH}"

if ! command -v curl >/dev/null 2>&1; then
    echo "Installing curl..."
    apt-get update
    apt-get install -y curl ca-certificates
fi

if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemd is required."
    exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo
echo "Downloading Sahand Tunnel..."
echo "Architecture: ${ARCH}"

curl -fL \
    "${VERSION_URL}/${BIN_NAME}" \
    -o "${TMP}/${BIN_NAME}"

curl -fL \
    "${VERSION_URL}/SHA256SUMS" \
    -o "${TMP}/SHA256SUMS"

grep -E "  ${BIN_NAME}$" \
    "${TMP}/SHA256SUMS" > "${TMP}/checksum"

cd "$TMP"
sha256sum -c checksum

echo
echo "Installing application..."

install -d -m 0755 "$CONFIG_DIR"
install -d -m 0755 "$DATA_DIR"

install -m 0755 \
    "${TMP}/${BIN_NAME}" \
    "$BIN"

cat > "$SERVICE" <<EOF
[Unit]
Description=Sahand Tunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=SAHAND_CONFIG=${CONFIG_DIR}/config.json
WorkingDirectory=${DATA_DIR}
ExecStart=${BIN} serve
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

cat > /usr/local/bin/sahand-tunnel-update <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

curl -fsSL \
  https://raw.githubusercontent.com/sahand363/sahand-tunnel/main/install.sh \
  | SAHAND_NO_MENU=1 bash
EOF

chmod 0755 /usr/local/bin/sahand-tunnel-update

systemctl daemon-reload

if [ -f "${CONFIG_DIR}/config.json" ]; then
    systemctl enable sahand-tunnel
    systemctl restart sahand-tunnel
fi

echo
echo "================================"
echo "  SAHAND TUNNEL INSTALLED"
echo "================================"
echo

if [ "${SAHAND_NO_MENU:-0}" != "1" ]; then
    export SAHAND_CONFIG="${CONFIG_DIR}/config.json"
    exec "$BIN" menu
fi
