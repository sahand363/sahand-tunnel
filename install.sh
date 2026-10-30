
#!/usr/bin/env bash
set -Eeuo pipefail

REPO="sahand363/sahand-tunnel"
VERSION_URL="https://github.com/${REPO}/releases/download/dev"

BIN="/usr/local/bin/sahand-tunnel"
CONFIG_DIR="/etc/sahand-tunnel"
DATA_DIR="/var/lib/sahand-tunnel"
CONFIG="${CONFIG_DIR}/config.json"

SERVICE="/etc/systemd/system/sahand-tunnel.service"
CADDYFILE="/etc/caddy/Caddyfile"
CADDY_SERVICE="/etc/systemd/system/caddy.service"

APP_PORT=""
DOMAIN=""
ADMIN_USER=""
NO_MENU="${SAHAND_NO_MENU:-0}"

log() {
    echo
    echo "==> $*"
}

fail() {
    echo
    echo "ERROR: $*" >&2
    exit 1
}

if [ "$EUID" -ne 0 ]; then
    fail "Please run this installer as root."
fi

if [ "$(uname -s)" != "Linux" ]; then
    fail "Only Linux is supported."
fi

if [ -f /etc/os-release ]; then
    . /etc/os-release
    [ "${ID:-}" = "ubuntu" ] || fail "Only Ubuntu is supported."
else
    fail "Cannot identify operating system."
fi

case "$(uname -m)" in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) fail "Unsupported CPU architecture." ;;
esac

command -v systemctl >/dev/null 2>&1 || fail "systemd is required."

if ! command -v curl >/dev/null 2>&1; then
    log "Installing curl and certificates"
    apt-get update
    apt-get install -y curl ca-certificates
fi

TMP="$(mktemp -d)"
BACKUP=""

cleanup() {
    rm -rf "$TMP"
}
trap cleanup EXIT

mkdir -p "$CONFIG_DIR" "$DATA_DIR"
chmod 700 "$CONFIG_DIR" "$DATA_DIR"

log "Checking existing installation"

EXISTING=0

if [ -f "$CONFIG" ]; then
    EXISTING=1
    cp "$CONFIG" "$TMP/config.backup.json"

    ROLE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("role",""))' "$CONFIG")"
    NODE_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("node_id",""))' "$CONFIG")"
    OLD_DOMAIN="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("panel_url",""))' "$CONFIG")"
    OLD_USER="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("admin_username",""))' "$CONFIG")"

    if [ -z "$ROLE" ] || [ -z "$NODE_ID" ]; then
        fail "Existing configuration is incomplete. Backup it before continuing."
    fi
else
    ROLE=""
    NODE_ID=""
    OLD_DOMAIN=""
    OLD_USER=""
fi

log "Panel access configuration"

if [ "$NO_MENU" = "1" ] && [ "$EXISTING" -eq 1 ]; then
    DOMAIN="${OLD_DOMAIN#https://}"
    ADMIN_USER="$OLD_USER"

    [ -n "$DOMAIN" ] || fail "Existing panel domain is missing."
    [ -n "$ADMIN_USER" ] || fail "Existing administrator username is missing."
else
    echo "Choose panel access method:"
    echo "1. Domain + valid HTTPS"
    echo "2. Server IP + HTTPS (not available yet)"
    echo

    read -r -p "Select [1]: " ACCESS_METHOD
    ACCESS_METHOD="${ACCESS_METHOD:-1}"

    [ "$ACCESS_METHOD" = "1" ] || fail "Only Domain + HTTPS is supported in this release."

    if [ "$EXISTING" -eq 1 ]; then
        read -r -p "Domain [${OLD_DOMAIN#https://}]: " DOMAIN
        DOMAIN="${DOMAIN:-${OLD_DOMAIN#https://}}"
    else
        read -r -p "Enter your panel domain (example: panel.example.com): " DOMAIN
    fi

    DOMAIN="${DOMAIN#https://}"
    DOMAIN="${DOMAIN#http://}"
    DOMAIN="${DOMAIN%%/*}"
    DOMAIN="${DOMAIN%%:*}"

    [[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]] || fail "Invalid domain name."
    [[ "$DOMAIN" == *.* ]] || fail "Enter a fully qualified domain name."

    if [ "$EXISTING" -eq 1 ]; then
        read -r -p "Administrator username [${OLD_USER}]: " ADMIN_USER
        ADMIN_USER="${ADMIN_USER:-$OLD_USER}"
    else
        read -r -p "Administrator username: " ADMIN_USER
    fi

    [ -n "$ADMIN_USER" ] || fail "Administrator username is required."
fi

PANEL_URL="https://${DOMAIN}"

log "Checking DNS"

python3 - "$DOMAIN" <<'PY'
import socket
import sys

domain = sys.argv[1]

try:
    addresses = sorted({
        item[4][0]
        for item in socket.getaddrinfo(domain, None)
    })
except Exception as exc:
    print("DNS lookup failed:", exc)
    sys.exit(1)

if not addresses:
    print("No DNS records found.")
    sys.exit(1)

print("Resolved addresses:")
for address in addresses:
    print(" -", address)
PY

DNS_RESULT=$?

if [ "$DNS_RESULT" -ne 0 ]; then
    fail "Domain DNS is not resolving. Configure its A record and try again."
fi

SERVER_IP="$(curl -4 -fsS --max-time 10 https://api.ipify.org || true)"

if [ -n "$SERVER_IP" ]; then
    if ! python3 - "$DOMAIN" "$SERVER_IP" <<'PY'
import socket
import sys

domain, server_ip = sys.argv[1], sys.argv[2]

try:
    ips = {
        item[4][0]
        for item in socket.getaddrinfo(domain, None)
    }
except Exception:
    sys.exit(1)

if server_ip not in ips:
    print("Warning: domain does not resolve to this server's IPv4 address.")
    print("Expected:", server_ip)
    print("Found:", ", ".join(sorted(ips)))
    sys.exit(1)
PY
    then
        fail "Domain A record does not point to this server."
    fi
fi

log "Selecting persistent random panel port"

if [ "$EXISTING" -eq 1 ]; then
    APP_PORT="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("panel_port",""))' "$CONFIG")"
fi

if ! [[ "$APP_PORT" =~ ^[0-9]+$ ]] || [ "$APP_PORT" -lt 20000 ] || [ "$APP_PORT" -gt 60000 ]; then
    APP_PORT="$(shuf -i 20000-60000 -n 1)"
fi

echo "Local application port: ${APP_PORT}"

log "Installing required packages"

apt-get update
apt-get install -y curl ca-certificates gnupg debian-keyring debian-archive-keyring apt-transport-https python3

if ! command -v caddy >/dev/null 2>&1; then
    log "Installing Caddy"

    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
        | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg

    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
        -o /etc/apt/sources.list.d/caddy-stable.list

    chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    chmod o+r /etc/apt/sources.list.d/caddy-stable.list

    apt-get update
    apt-get install -y caddy
fi

log "Downloading Sahand Tunnel"

BIN_NAME="sahand-tunnel-linux-${ARCH}"

curl -fL "${VERSION_URL}/${BIN_NAME}" -o "${TMP}/${BIN_NAME}" \
    || fail "Could not download application binary."

curl -fL "${VERSION_URL}/SHA256SUMS" -o "${TMP}/SHA256SUMS" \
    || fail "Could not download checksum file."

grep -E "  ${BIN_NAME}$" "${TMP}/SHA256SUMS" > "${TMP}/checksum" \
    || fail "Binary checksum not found."

(
    cd "$TMP"
    sha256sum -c checksum
) || fail "Binary checksum verification failed."

install -m 0755 "${TMP}/${BIN_NAME}" "$BIN"

log "Configuring application"

if [ "$EXISTING" -eq 1 ]; then
    # Keep existing identity and password hash.
    python3 - "$CONFIG" "$TMP/config.new.json" "$PANEL_URL" "$APP_PORT" "$DOMAIN" <<'PY'
import json
import sys

src, dst, panel_url, port, domain = sys.argv[1:]

with open(src) as f:
    cfg = json.load(f)

cfg["panel_url"] = panel_url
cfg["panel_port"] = int(port)
cfg["listen_addr"] = "127.0.0.1:" + port

with open(dst, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
PY
    install -m 0600 "$TMP/config.new.json" "$CONFIG"
else
    if [ "$NO_MENU" = "1" ]; then
        fail "Cannot perform unattended first installation."
    fi

    echo
    echo "Create administrator password (minimum 12 characters)."
    read -r -s -p "Password: " ADMIN_PASSWORD
    echo
    read -r -s -p "Confirm password: " ADMIN_PASSWORD_CONFIRM
    echo

    [ "$ADMIN_PASSWORD" = "$ADMIN_PASSWORD_CONFIRM" ] || fail "Passwords do not match."
    [ "${#ADMIN_PASSWORD}" -ge 12 ] || fail "Password must contain at least 12 characters."

    printf '%s\n' "$ADMIN_PASSWORD" | "$BIN" init \
        --role "${ROLE:-master}" \
        --listen "127.0.0.1:${APP_PORT}" \
        --panel-url "$PANEL_URL" \
        --admin-user "$ADMIN_USER" \
        --admin-password-stdin \
        || fail "Application configuration failed."

    unset ADMIN_PASSWORD ADMIN_PASSWORD_CONFIRM
fi

chmod 0600 "$CONFIG"

log "Creating application service"

cat > "$SERVICE" <<EOF
[Unit]
Description=Sahand Tunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=SAHAND_CONFIG=${CONFIG}
WorkingDirectory=${DATA_DIR}
ExecStart=${BIN} serve
Restart=on-failure
RestartSec=5
User=root
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=${DATA_DIR} ${CONFIG_DIR}

[Install]
WantedBy=multi-user.target
EOF

log "Configuring Caddy HTTPS reverse proxy"

mkdir -p /etc/caddy

cat > "$CADDYFILE" <<EOF
${DOMAIN} {
    encode zstd gzip
    reverse_proxy 127.0.0.1:${APP_PORT}
}
EOF

chmod 0644 "$CADDYFILE"

log "Validating Caddy configuration"

caddy validate --config "$CADDYFILE" --adapter caddyfile \
    || fail "Caddy configuration validation failed."

log "Starting application and Caddy"

systemctl daemon-reload
systemctl enable sahand-tunnel
systemctl restart sahand-tunnel

systemctl enable caddy
systemctl restart caddy

log "Waiting for HTTPS certificate"

CERT_OK=0

for i in $(seq 1 60); do
    if curl -fsS --max-time 5 "https://${DOMAIN}/api/v1/health" \
        -o "$TMP/health.json"; then
        if grep -q '"status":"ok"' "$TMP/health.json"; then
            CERT_OK=1
            break
        fi
    fi
    sleep 5
done

if [ "$CERT_OK" -ne 1 ]; then
    echo
    echo "Caddy logs:"
    journalctl -u caddy -n 50 --no-pager || true
    fail "HTTPS certificate or panel health check failed. Panel is not ready."
fi

log "Installing update helper"

cat > /usr/local/bin/sahand-tunnel-update <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

curl -fsSL \
  https://raw.githubusercontent.com/sahand363/sahand-tunnel/main/install.sh \
  | SAHAND_NO_MENU=1 bash
EOF

chmod 0755 /usr/local/bin/sahand-tunnel-update

echo
echo "======================================"
echo "       SAHAND TUNNEL INSTALLED"
echo "======================================"
echo
echo "Panel: ${PANEL_URL}"
echo "Application port: ${APP_PORT}"
echo "Role: ${ROLE:-master}"
echo
echo "Service status:"
systemctl is-active sahand-tunnel
systemctl is-active caddy
echo

if [ "$NO_MENU" != "1" ]; then
    export SAHAND_CONFIG="$CONFIG"
    if [ -r /dev/tty ]; then
        exec "$BIN" menu </dev/tty
    else
        echo "Run: sahand-tunnel menu"
    fi
fi
