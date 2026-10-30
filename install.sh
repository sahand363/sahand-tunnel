
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

read_tty() {
    read -r "$@" </dev/tty
}

read_secret_tty() {
    read -r -s "$@" </dev/tty
    echo
}

[ "$EUID" -eq 0 ] || fail "Please run this installer as root."
[ "$(uname -s)" = "Linux" ] || fail "Only Linux is supported."

if [ -f /etc/os-release ]; then
    . /etc/os-release
    [ "${ID:-}" = "ubuntu" ] || fail "Only Ubuntu is supported."
else
    fail "Cannot identify operating system."
fi

command -v systemctl >/dev/null 2>&1 || fail "systemd is required."

case "$(uname -m)" in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) fail "Unsupported CPU architecture." ;;
esac

if [ "$NO_MENU" != "1" ] && [ ! -r /dev/tty ]; then
    fail "Interactive terminal is required for installation."
fi

if ! command -v curl >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
    apt-get update
    apt-get install -y curl ca-certificates python3
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
    OLD_USER="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("admin_username",""))' "$CONFIG")"
    OLD_PORT="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("panel_port",0))' "$CONFIG")"
    OLD_DOMAIN="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("panel_url",""))' "$CONFIG")"

    [ "$ROLE" = "master" ] || [ "$ROLE" = "agent" ] || fail "Existing role is invalid."
    [ -n "$NODE_ID" ] || fail "Existing Node ID is missing."
else
    ROLE=""
    NODE_ID=""
    OLD_USER=""
    OLD_PORT="0"
    OLD_DOMAIN=""
fi

log "Configuring server"

if [ "$EXISTING" -eq 0 ]; then
    [ "$NO_MENU" != "1" ] || fail "First installation requires an interactive terminal."

    echo
    echo "Select server role:"
    echo "1. Master"
    echo "2. Agent"
    read_tty -p "Select [1]: " ROLE_CHOICE
    ROLE_CHOICE="${ROLE_CHOICE:-1}"

    case "$ROLE_CHOICE" in
        1) ROLE="master" ;;
        2) ROLE="agent" ;;
        *) fail "Invalid role." ;;
    esac

    read_tty -p "Administrator username: " ADMIN_USER
    [ -n "$ADMIN_USER" ] || fail "Administrator username is required."
else
    ADMIN_USER="$OLD_USER"
fi

if [ "$EXISTING" -eq 1 ]; then
    HAS_PASSWORD="$(python3 -c '
import json,sys
c=json.load(open(sys.argv[1]))
print("yes" if c.get("admin_salt") and c.get("admin_hash") else "no")
' "$CONFIG")"
else
    HAS_PASSWORD="no"
fi

if [ "$HAS_PASSWORD" = "yes" ] && [ "$NO_MENU" = "1" ]; then
    log "Preserving existing administrator credentials"
elif [ "$HAS_PASSWORD" = "yes" ]; then
    read_tty -p "Keep existing administrator password? [Y/n]: " KEEP_PASSWORD
    KEEP_PASSWORD="${KEEP_PASSWORD:-Y}"
    if [[ "$KEEP_PASSWORD" =~ ^[Yy]$ ]]; then
        KEEP_PASSWORD_FLAG="yes"
    else
        KEEP_PASSWORD_FLAG="no"
    fi
else
    KEEP_PASSWORD_FLAG="no"
fi

if [ "$EXISTING" -eq 0 ] || [ "${KEEP_PASSWORD_FLAG:-yes}" = "no" ]; then
    echo
    echo "Create administrator password (minimum 12 characters)."
    read_secret_tty -p "Password: " ADMIN_PASSWORD
    read_secret_tty -p "Confirm password: " ADMIN_PASSWORD_CONFIRM

    [ "$ADMIN_PASSWORD" = "$ADMIN_PASSWORD_CONFIRM" ] || fail "Passwords do not match."
    [ "${#ADMIN_PASSWORD}" -ge 12 ] || fail "Password must contain at least 12 characters."
fi

log "Selecting application port"

if [[ "$OLD_PORT" =~ ^[0-9]+$ ]] && [ "$OLD_PORT" -ge 1024 ] && [ "$OLD_PORT" -le 65535 ]; then
    APP_PORT="$OLD_PORT"
else
    APP_PORT="$(python3 - <<'PY'
import random
import socket

for _ in range(100):
    p = random.randint(20000, 60000)
    s = socket.socket()
    try:
        s.bind(("0.0.0.0", p))
        print(p)
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

log "Generating application configuration"

if [ "$HAS_PASSWORD" = "yes" ] && [ "${KEEP_PASSWORD_FLAG:-yes}" = "yes" ]; then
    python3 - "$CONFIG" "$TMP/config.new.json" "$APP_PORT" <<'PY'
import json
import sys

src, dst, port = sys.argv[1:]
with open(src) as f:
    cfg = json.load(f)

cfg["panel_port"] = int(port)
cfg["listen_addr"] = "0.0.0.0:" + port

with open(dst, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
PY
    install -m 0600 "$TMP/config.new.json" "$CONFIG"
else
    NEW_CONFIG="${TMP}/config.generated.json"

    printf '%s\n' "$ADMIN_PASSWORD" \
        | SAHAND_CONFIG="$NEW_CONFIG" "$BIN" init \
            --role "$ROLE" \
            --listen "0.0.0.0:${APP_PORT}" \
            --panel-port "$APP_PORT" \
            --admin-user "$ADMIN_USER" \
            --admin-password-stdin \
        || fail "Application configuration failed."

    if [ "$EXISTING" -eq 1 ]; then
        python3 - "$TMP/config.backup.json" "$NEW_CONFIG" "$TMP/config.merged.json" <<'PY'
import json
import sys

old_path, new_path, output_path = sys.argv
with open(old_path) as f:
    old = json.load(f)
with open(new_path) as f:
    new = json.load(f)

new["role"] = old["role"]
new["node_id"] = old["node_id"]
new["created_at"] = old.get("created_at", new.get("created_at"))

with open(output_path, "w") as f:
    json.dump(new, f, indent=2)
    f.write("\n")
PY
        install -m 0600 "$TMP/config.merged.json" "$CONFIG"
    else
        install -m 0600 "$NEW_CONFIG" "$CONFIG"
    fi
fi

unset ADMIN_PASSWORD ADMIN_PASSWORD_CONFIRM 2>/dev/null || true
chmod 0600 "$CONFIG"

log "Validating configuration"

python3 - "$CONFIG" "$ROLE" "$APP_PORT" <<'PY'
import json
import sys

path, role, port = sys.argv[1:]
with open(path) as f:
    cfg = json.load(f)

assert cfg.get("role") == role
assert cfg.get("node_id")
assert cfg.get("panel_port") == int(port)
assert cfg.get("listen_addr") == "0.0.0.0:" + port
assert cfg.get("admin_username")
assert cfg.get("admin_salt")
assert cfg.get("admin_hash")
print("Configuration validation successful.")
PY

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

log "Installing domain and SSL configuration command"

cat > /usr/local/bin/sahand-tunnel-domain <<'DOMAIN_SCRIPT'
#!/usr/bin/env bash
set -Eeuo pipefail

CONFIG="/etc/sahand-tunnel/config.json"
CADDYFILE="/etc/caddy/Caddyfile"

[ "$EUID" -eq 0 ] || {
    echo "Run this command as root."
    exit 1
}

command -v python3 >/dev/null 2>&1 || {
    echo "python3 is required."
    exit 1
}

command -v curl >/dev/null 2>&1 || {
    echo "curl is required."
    exit 1
}

if [ ! -f "$CONFIG" ]; then
    echo "Configuration file not found."
    exit 1
fi

echo
echo "Configure domain and automatic HTTPS"
echo "A DNS A record must point to this server."
echo

read -r -p "Domain (example: panel.example.com): " DOMAIN
DOMAIN="${DOMAIN#https://}"
DOMAIN="${DOMAIN#http://}"
DOMAIN="${DOMAIN%%/*}"
DOMAIN="${DOMAIN%%:*}"
DOMAIN="${DOMAIN,,}"

if [[ ! "$DOMAIN" =~ ^[a-z0-9.-]+$ ]] || [[ "$DOMAIN" != *.* ]]; then
    echo "Invalid domain."
    exit 1
fi

SERVER_IP="$(curl -4 -fsS --max-time 10 https://api.ipify.org)" || {
    echo "Could not determine server public IPv4 address."
    exit 1
}

if ! getent ahostsv4 "$DOMAIN" | awk '{print $1}' | grep -Fxq "$SERVER_IP"; then
    echo "The domain A record does not point to this server."
    echo "Expected IPv4: $SERVER_IP"
    exit 1
fi

PORT="$(python3 -c 'import json; print(json.load(open("/etc/sahand-tunnel/config.json"))["panel_port"])')"

apt-get update
apt-get install -y curl ca-certificates gnupg debian-keyring debian-archive-keyring apt-transport-https

if ! command -v caddy >/dev/null 2>&1; then
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
        | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg

    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
        -o /etc/apt/sources.list.d/caddy-stable.list

    chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    chmod o+r /etc/apt/sources.list.d/caddy-stable.list

    apt-get update
    apt-get install -y caddy
fi

mkdir -p /etc/caddy
touch "$CADDYFILE"

python3 - "$CADDYFILE" "$DOMAIN" "$PORT" <<'PY'
import sys

path, domain, port = sys.argv[1:]
start = "# BEGIN SAHAND-TUNNEL"
end = "# END SAHAND-TUNNEL"

with open(path) as f:
    content = f.read()

if (start in content) != (end in content):
    raise SystemExit("Incomplete Sahand Tunnel block in Caddyfile")

block = f"""{start}
{domain} {{
    encode zstd gzip
    reverse_proxy 127.0.0.1:{port}
}}
{end}"""

if start in content:
    before = content.split(start, 1)[0]
    after = content.split(end, 1)[1]
    content = before.rstrip() + "\n\n" + block + "\n" + after.lstrip()
else:
    content = content.rstrip() + "\n\n" + block + "\n"

with open(path, "w") as f:
    f.write(content)
PY

caddy validate --config "$CADDYFILE" --adapter caddyfile

python3 - "$CONFIG" "$DOMAIN" <<'PY'
import json
import os
import sys

path, domain = sys.argv[1:]
with open(path) as f:
    cfg = json.load(f)

cfg["panel_url"] = "https://" + domain

tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")

os.chmod(tmp, 0o600)
os.replace(tmp, path)
PY

systemctl enable caddy
systemctl restart caddy

echo
echo "Waiting for HTTPS certificate and panel health..."

OK=0
for i in $(seq 1 60); do
    if curl -fsS --max-time 5 "https://${DOMAIN}/api/v1/health" | grep -q '"status":"ok"'; then
        OK=1
        break
    fi
    sleep 5
done

if [ "$OK" -ne 1 ]; then
    echo "HTTPS health check failed."
    journalctl -u caddy -n 40 --no-pager || true
    exit 1
fi

echo
echo "Domain and HTTPS configured successfully."
echo "Panel: https://${DOMAIN}"
DOMAIN_SCRIPT

chmod 0755 /usr/local/bin/sahand-tunnel-domain

log "Installing update command"

cat > /usr/local/bin/sahand-tunnel-update <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
curl -fsSL "${RAW_INSTALLER}" | SAHAND_NO_MENU=1 bash
EOF

chmod 0755 /usr/local/bin/sahand-tunnel-update

log "Starting application"

systemctl daemon-reload
systemctl enable sahand-tunnel
systemctl restart sahand-tunnel

echo
echo "======================================"
echo "       SAHAND TUNNEL INSTALLED"
echo "======================================"
echo
echo "Role: ${ROLE}"
echo "Application port: ${APP_PORT}"
echo
echo "Panel address:"
echo "  http://SERVER-IP:${APP_PORT}"
echo
echo "Domain and HTTPS are optional."
echo "To configure them later, run:"
echo "  sahand-tunnel menu"
echo
echo "Make sure TCP port ${APP_PORT} is allowed in your firewall."
echo "For HTTPS, also allow TCP ports 80 and 443."
echo
echo "Installation completed successfully."

if [ "$NO_MENU" != "1" ]; then
    export SAHAND_CONFIG="$CONFIG"
    exec "$BIN" menu </dev/tty
fi
