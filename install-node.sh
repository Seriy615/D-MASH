#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# One-command installer:
#   curl -fsSLO https://raw.githubusercontent.com/Seriy615/D-MASH/<release>/install-node.sh
#   sudo DMASH_NODE_REVISION=<reviewed-commit> bash install-node.sh
# Download first so the operator can inspect the script and pin its source.

PREFIX="${DMASH_NODE_PREFIX:-/opt/dmash-node}"
REPO_URL="${DMASH_REPO_URL:-https://github.com/Seriy615/D-MASH.git}"
REVISION="${DMASH_NODE_REVISION:-20a5eb27cee2323faa424d83a8d95753728d84f9}"
HTTP_PORT="${DMASH_HTTP_PORT:-18080}"
P2P_PORT="${DMASH_P2P_PORT:-19090}"
DOMAIN="${DMASH_NODE_DOMAIN:-}"
NODE_NAME="${DMASH_NODE_NAME:-}"
VISIBILITY="${DMASH_NODE_VISIBILITY:-}"
SETUP_NGINX="${DMASH_SETUP_NGINX:-}"
SETUP_FIREWALL="${DMASH_SETUP_FIREWALL:-}"

prompt_default() {
  local label="$1" default="$2" value
  if [[ ! -t 0 || "${DMASH_NONINTERACTIVE:-0}" == "1" ]]; then printf -v "$3" '%s' "$default"; return; fi
  read -r -p "$label [$default]: " value
  printf -v "$3" '%s' "${value:-$default}"
}

if [[ -z "$DOMAIN" ]]; then prompt_default "1. Domain (empty = do not configure nginx)" "" DOMAIN; fi
if [[ -z "$VISIBILITY" ]]; then
  prompt_default "2. Private (Y) / Public (N)" "N" visibility_answer
  [[ "$visibility_answer" =~ ^[Yy]$ ]] && VISIBILITY=private || VISIBILITY=public
fi
if [[ -z "$NODE_NAME" ]]; then prompt_default "3. Node name" "D-MASH Node" NODE_NAME; fi
if [[ -z "$SETUP_NGINX" && -n "$DOMAIN" ]]; then prompt_default "Configure nginx and Let's Encrypt? (Y/N)" "Y" nginx_answer; [[ "$nginx_answer" =~ ^[Yy]$ ]] && SETUP_NGINX=1 || SETUP_NGINX=0; fi
SETUP_NGINX="${SETUP_NGINX:-0}"
if [[ -z "$SETUP_FIREWALL" ]]; then prompt_default "Configure firewall ports automatically? (Y/N)" "N" firewall_answer; [[ "$firewall_answer" =~ ^[Yy]$ ]] && SETUP_FIREWALL=1 || SETUP_FIREWALL=0; fi
SETUP_FIREWALL="${SETUP_FIREWALL:-0}"

if [[ "$VISIBILITY" == "private" ]]; then
  echo "Private node mode is recorded in policy, but password authentication is not implemented in DMP-C yet." >&2
  echo "A password was deliberately not requested or stored because it would not protect the current protocol." >&2
fi

[[ "$(id -u)" == 0 ]] || { echo "Run as root: sudo bash install-node.sh" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
command -v git >/dev/null || { echo "git is required" >&2; exit 1; }

id dmash-node >/dev/null 2>&1 || useradd --system --home-dir "$PREFIX" --create-home --shell /usr/sbin/nologin dmash-node
mkdir -p "$PREFIX"
if [[ ! "$REVISION" =~ ^[0-9a-fA-F]{40}$ ]]; then echo "DMASH_NODE_REVISION must be a full immutable git commit" >&2; exit 1; fi
if [[ ! -d "$PREFIX/src/.git" ]]; then git clone "$REPO_URL" "$PREFIX/src"; fi
git -C "$PREFIX/src" fetch --depth 1 origin "$REVISION"
git -C "$PREFIX/src" checkout --detach --force "$REVISION"

SRC="$PREFIX/src/D-MASH/client"
[[ -d "$SRC/backend" ]] || { echo "repository does not contain D-MASH/client/backend" >&2; exit 1; }
python3 -m venv "$PREFIX/.venv"
"$PREFIX/.venv/bin/pip" install --requirement "$SRC/requirements.txt"
install -d -o dmash-node -g dmash-node -m 0700 "$PREFIX/backend"
cp -a "$SRC/backend/." "$PREFIX/backend/"
chown -R dmash-node:dmash-node "$PREFIX"

cat > /etc/dmash-node.env <<EOF
DMASH_HTTP_HOST=127.0.0.1
DMASH_HTTP_PORT=$HTTP_PORT
P2P_HOST=0.0.0.0
P2P_PORT=$P2P_PORT
DMASH_NODE_VISIBILITY=${DMASH_NODE_VISIBILITY:-public}
DMASH_CAN_ROUTE=${DMASH_CAN_ROUTE:-true}
DMASH_CAN_ACCEPT_DEVICES=${DMASH_CAN_ACCEPT_DEVICES:-true}
DMASH_NODE_NAME=$NODE_NAME
EOF
chmod 600 /etc/dmash-node.env
cat > /etc/systemd/system/dmash-node.service <<EOF
[Unit]
Description=D-MASH Node
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=dmash-node
Group=dmash-node
WorkingDirectory=$PREFIX/backend
EnvironmentFile=/etc/dmash-node.env
ExecStart=$PREFIX/.venv/bin/python $PREFIX/backend/main.py
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=$PREFIX/backend
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now dmash-node

if [[ "$SETUP_NGINX" == "1" ]]; then
  command -v nginx >/dev/null || { echo "nginx is required for automatic HTTPS setup" >&2; exit 1; }
  command -v certbot >/dev/null || { echo "certbot is required for automatic HTTPS setup" >&2; exit 1; }
  install -d -m 0755 /etc/nginx/sites-available /etc/nginx/sites-enabled
  cat > "/etc/nginx/sites-available/dmash-node-$DOMAIN" <<NGINX
server {
    listen 80;
    server_name $DOMAIN;
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / {
        proxy_pass http://127.0.0.1:$HTTP_PORT;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
NGINX
  ln -sfn "/etc/nginx/sites-available/dmash-node-$DOMAIN" "/etc/nginx/sites-enabled/dmash-node-$DOMAIN"
  nginx -t && systemctl reload nginx
  certbot --nginx --non-interactive --agree-tos --register-unsafely-without-email -d "$DOMAIN" --redirect
fi

if [[ "$SETUP_FIREWALL" == "1" ]]; then
  if command -v ufw >/dev/null; then ufw allow 80/tcp; ufw allow 443/tcp; ufw allow "$P2P_PORT/tcp"; ufw --force enable;
  elif command -v firewall-cmd >/dev/null; then firewall-cmd --permanent --add-service=http --add-service=https --add-port="$P2P_PORT/tcp"; firewall-cmd --reload;
  else echo "No supported firewall manager found; configure TCP 443 and $P2P_PORT manually." >&2; fi
fi
echo "D-MASH node installed. Identity: $PREFIX/backend/node_identity.key"
echo "Node '$NODE_NAME' installed as $VISIBILITY. Keep HTTP port $HTTP_PORT loopback-only; expose HTTPS/WSS and P2P TCP port $P2P_PORT."
