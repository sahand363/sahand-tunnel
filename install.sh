
#!/usr/bin/env bash
set -Eeuo pipefail

REPO="sahand363/sahand-tunnel"
VERSION_URL="https://github.com/${REPO}/releases/download/dev"
RAW_INSTALLER="https://raw.githubusercontent.com/${REPO}/main/install.sh"

BIN="/usr/local/bin/sahand-tunnel"
CONFIG_DIR="/etc/sahand-tunnel"
DATA_DIR="/var/lib/sahand-tunnel"
CONFIG="${CONFIG_DIR}/config.json"

SERVICE="/etc/systemd/system/sahand-tunnel.service"
CADDYFILE="/etc/caddy/Caddyfile"

NO_MENU="${SAHAND_NO_MENU:-0}"
EXISTING=0

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

[ "$(uname -s)" = "Linux" ] || fail "Only Linux is supported."

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
    apt-get update
    apt-get install -y curl ca-certificates
fi

if ! command -v python3 >/dev/null 2>&1; then
    apt-get update
    apt-get install -y python3
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$CONFIG_DIR" "$DATA_DIR"
chmod 0700 "$CONFIG_DIR" "$DATA_DIR"

log "Checking existing installation"

if [ -f "$CONFIG" ]; then
    EXISTING=1

    cp -p "$CONFIG" "$TMP/config.backup.json"

    ROLE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("role",""))' "$CONFIG")"
    NODE_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("node_id",""))' "$CONFIG")"
    OLD_DOMAIN="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("panel_url",""))' "$CONFIG")"
    OLD_USER="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("admin_username",""))' "$CONFIG")"
    OLD_PORT="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("panel_port",0))' "$CONFIG")"

    [ "$ROLE" = "master" ] || [ "$ROLE" = "agent" ] || fail "Existing role is invalid."
    [ -n "$NODE_ID" ] || fail "Existing Node ID is missing."
else
    ROLE=""
    NODE_ID=""
    OLD_DOMAIN=""
    OLD_USER=""
    OLD_PORT="0"
fi

log "Configuring server role"

if [ "$EXISTING" -eq 0 ]; then
    [ "$NO_MENU" != "1" ] || fail "First installation requires an interactive terminal."

    echo "Select server role:"
    echo "1. Master"
    echo "2. Agent"
    echo

    read -r -p "Select [1]: " ROLE_CHOICE
    ROLE_CHOICE="${ROLE_CHOICE:-1}"

    case "$ROLE_CHOICE" in
        1) ROLE="master" ;;
        2) ROLE="agent" ;;
        *) fail "Invalid role selection." ;;
    esac

    read -r -p "Administrator username: " ADMIN_USER
    [ -n "$ADMIN_USER" ] || fail "Administrator username is required."

else
    log "Existing role: ${ROLE}"

    if [ "$NO_MENU" = "1" ]; then
        DOMAIN="${OLD_DOMAIN#https://}"
        ADMIN_USER="$OLD_USER"
    else
        read -r -p "Domain [${OLD_DOMAIN#https://}]: " DOMAIN
        DOMAIN="${DOMAIN:-${OLD_DOMAIN#https://}}"

        read -r -p "Administrator username [${OLD_USER}]: " ADMIN_USER
        ADMIN_USER="${ADMIN_USER:-$OLD_USER}"
    fi

    [ -n "$ADMIN_USER" ] || fail "Administrator username is missing."
fi

if [ "$EXISTING" -eq 0 ]; then
    read -r -p "Enter panel domain (example: panel.example.com): " DOMAIN
fi

DOMAIN="${DOMAIN#https://}"
DOMAIN="${DOMAIN#http://}"
DOMAIN="${DOMAIN%%/*}"
DOMAIN="${DOMAIN%%:*}"
DOMAIN="${DOMAIN,,}"

[[ "$DOMAIN" =~ ^[a-z0-9.-]+$ ]] || fail "Invalid domain."
[[ "$DOMAIN" == *.* ]] || fail "Enter a fully qualified domain name."

PANEL_URL="https://${DOMAIN}"

if [ "$NO_MENU" = "1" ] && [ "$EXISTING" -eq 1 ]; then
    [ -n "$OLD_DOMAIN" ] || fail "Existing panel domain is missing."
fi

log "Checking domain DNS"

if ! getent ahostsv4 "$DOMAIN" >/dev/null 2>&1; then
    fail "Domain does not resolve. Configure its DNS A record first."
fi

SERVER_IP="$(curl -4 -fsS --max-time 10 https://api.ipify.org || true)"

if [ -n "$SERVER_IP" ]; then
    if ! getent ahostsv4 "$DOMAIN" | awk '{print $1}' | grep -Fxq "$SERVER_IP"; then
        fail "Domain A record does not point to this server's public IPv4 address."
    fi
fi

log "Selecting persistent application port"

if [[ "$OLD_PORT" =~ ^[0-9]+$ ]] && [ "$OLD_PORT" -ge 20000 ] && [ "$OLD_PORT" -le 60000 ]; then
    APP_PORT="$OLD_PORT"
else
    APP_PORT="$(python3 - <<'PY'
import random
import socket

for _ in range(100):
    port = random.randint(20000, 60000)
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", port))
        print(port)
        break
    except OSError:
        pass
    finally:
        s.close()
else:
    raise SystemExit("Could not find an available port")
PY
)" || fail "Could not select an application port."
fi

echo "Application port: ${APP_PORT}"

log "Installing required packages"

apt-get update
apt-get install -y curl ca-certificates python3 gnupg debian-keyring debian-archive-keyring apt-transport-https

if ! command -v caddy >/dev/null 2>&1; then
    log "Installing Caddy"

    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
        | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg

    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
        -o /etc/apt/sources.list.d/caddy-stable.list

    chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    chmod o+r /etc/apt/sources.list.d/caddy-stable.list

    apt-get update
    apt-get install -y caddy
fi

log "Downloading application"

BIN_NAME="sahand-tunnel-linux-${ARCH}"

curl -fL "${VERSION_URL}/${BIN_NAME}" -o "${TMP}/${BIN_NAME}" \
    || fail "Application download failed."

curl -fL "${VERSION_URL}/SHA256SUMS" -o "${TMP}/SHA256SUMS" \
    || fail "Checksum download failed."

grep -E "  ${BIN_NAME}$" "${TMP}/SHA256SUMS" > "${TMP}/checksum" \
    || fail "Checksum entry not found."

(
    cd "$TMP"
    sha256sum -c checksum
) || fail "Checksum verification failed."

install -m 0755 "${TMP}/${BIN_NAME}" "$BIN"

log "Configuring application"

if [ "$EXISTING" -eq 1 ]; then
    HAS_PASSWORD="$(python3 -c 'import json,sys; c=json.load(open(sys.argv[1])); print("yes" if c.get("admin_salt") and c.get("admin_hash") else "no")' "$CONFIG")"

    if [ "$HAS_PASSWORD" = "no" ]; then
        [ "$NO_MENU" != "1" ] || fail "Administrator password must be configured interactively before unattended updates."

        echo
        echo "Create administrator credentials for this existing installation."

        read -r -s -p "New administrator password (minimum 12 characters): " ADMIN_PASSWORD
        echo
        read -r -s -p "Confirm password: " ADMIN_PASSWORD_CONFIRM
        echo

        [ "$ADMIN_PASSWORD" = "$ADMIN_PASSWORD_CONFIRM" ] || fail "Passwords do not match."
        [ "${#ADMIN_PASSWORD}" -ge 12 ] || fail "Password must contain at least 12 characters."

        printf '%s\n' "$ADMIN_PASSWORD" | "$BIN" init \
            --role "$ROLE" \
            --listen "127.0.0.1:${APP_PORT}" \
            --panel-port "$APP_PORT" \
            --panel-url "$PANEL_URL" \
            --admin-user "$ADMIN_USER" \
            --admin-password-stdin \
            || fail "Administrator configuration failed."

        unset ADMIN_PASSWORD ADMIN_PASSWORD_CONFIRM

    else
        python3 - "$CONFIG" "$TMP/config.new.json" "$PANEL_URL" "$APP_PORT" <<'PY'
import json
import sys

src, dst, panel_url, port = sys.argv[1:]

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
    fi

else
    echo
    echo "Create administrator password (minimum 12 characters)."

    read -r -s -p "Password: " ADMIN_PASSWORD
    echo
    read -r -s -p "Confirm password: " ADMIN_PASSWORD_CONFIRM
    echo

    [ "$ADMIN_PASSWORD" = "$ADMIN_PASSWORD_CONFIRM" ] || fail "Passwords do not match."
    [ "${#ADMIN_PASSWORD}" -ge 12 ] || fail "Password must contain at least 12 characters."

    printf '%s\n' "$ADMIN_PASSWORD" | "$BIN" init \
        --role "$ROLE" \
        --listen "127.0.0.1:${APP_PORT}" \
        --panel-port "$APP_PORT" \
        --panel-url "$PANEL_URL" \
        --admin-user "$ADMIN_USER" \
        --admin-password-stdin \
        || fail "Application configuration failed."

    unset ADMIN_PASSWORD ADMIN_PASSWORD_CONFIRM

    python3 - "$CONFIG" "$TMP/config.new.json" "$APP_PORT" <<'PY'
import json
import sys

src, dst, port = sys.argv[1:]

with open(src) as f:
    cfg = json.load(f)

cfg["panel_port"] = int(port)

with open(dst, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
PY

    install -m 0600 "$TMP/config.new.json" "$CONFIG"
fi

chmod 0600 "$CONFIG"

log "Creating systemd service"

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

log "Configuring Caddy"

mkdir -p /etc/caddy

cat > "$CADDYFILE" <<EOF
${DOMAIN} {
    encode zstd gzip
    reverse_proxy 127.0.0.1:${APP_PORT}
}
EOF

chmod 0644 "$CADDYFILE"

caddy validate --config "$CADDYFILE" --adapter caddyfile \
    || fail "Caddy configuration validation failed."

log "Starting services"

systemctl daemon-reload
systemctl enable sahand-tunnel
systemctl restart sahand-tunnel

systemctl enable caddy
systemctl restart caddy

log "Waiting for HTTPS and application health"

CERT_OK=0

for i in $(seq 1 60); do
    if curl -fsS --max-time 5 "https://${DOMAIN}/api/v1/health" -o "$TMP/health.json"; then
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
    fail "HTTPS certificate or application health check failed."
fi

log "Installing update command"

cat > /usr/local/bin/sahand-tunnel-update <<EOF
#!/usr/bin/env bash
set -euo pipefail

curl -fsSL "${RAW_INSTALLER}" | SAHAND_NO_MENU=1 bash
EOF

chmod 0755 /usr/local/bin/sahand-tunnel-update

echo
echo "======================================"
echo "       SAHAND TUNNEL INSTALLED"
echo "======================================"
echo
echo "Panel: ${PANEL_URL}"
echo "Role: ${ROLE}"
echo "Application port: ${APP_PORT}"
echo

systemctl is-active sahand-tunnel
systemctl is-active caddy

echo
echo "Installation completed successfully."
echo

if [ "$NO_MENU" != "1" ]; then
    export SAHAND_CONFIG="$CONFIG"

    if [ -r /dev/tty ]; then
        exec "$BIN" menu </dev/tty
    else
        echo "Run: sahand-tunnel menu"
    fi
fi
