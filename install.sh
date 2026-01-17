#!/usr/bin/env bash
set -euo pipefail

############################################
# CONFIG
############################################
INSTALL_DIR="/opt/authentik"
COMPOSE_URL="https://goauthentik.io/docker-compose.yml"
LOCALHOST="127.0.0.1"

############################################
# HELPERS
############################################
log() { echo -e "\n== $* =="; }
die() { echo "ERROR: $*" >&2; exit 1; }

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    bash -lc "$*"
  else
    sudo bash -lc "$*"
  fi
}

rand_alnum() {
  local len="${1:-32}"
  tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$len"
}

prompt_default() {
  local prompt="$1" def="$2" val=""
  read -r -p "$prompt [$def]: " val || true
  [[ -z "$val" ]] && echo "$def" || echo "$val"
}

strip_url() {
  local x="$1"
  x="${x#http://}"; x="${x#https://}"
  x="${x%%/*}"
  echo "$x"
}

############################################
# QUESTIONS
############################################
echo "== authentik + TAK automation =="

HTTP_PORT="$(prompt_default 'authentik http port number?' '9000')"
HTTPS_PORT="$(prompt_default 'authentik https port number?' '9001')"

read -r -p "Authentik Domain? (optional): " AUTH_DOMAIN || true
read -r -p "TAK Portal Domain? (required): " TAK_DOMAIN || true
[[ -z "${TAK_DOMAIN:-}" ]] && die "TAK Portal Domain is required"

AUTH_DOMAIN="$(strip_url "${AUTH_DOMAIN:-}")"
TAK_DOMAIN="$(strip_url "$TAK_DOMAIN")"

BASE_URL="http://${LOCALHOST}:${HTTP_PORT}"

############################################
# PREREQS
############################################
log "Installing prerequisites"
as_root "apt-get update -y"
as_root "apt-get install -y ca-certificates curl jq openssl gnupg lsb-release python3"

############################################
# DOCKER + COMPOSE
############################################
if ! command -v docker >/dev/null 2>&1; then
  log "Installing Docker"
  as_root "install -m 0755 -d /etc/apt/keyrings"
  as_root "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg"
  as_root "chmod a+r /etc/apt/keyrings/docker.gpg"
  as_root "echo \"deb [arch=\$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \$(. /etc/os-release && echo \\\"\$VERSION_CODENAME\\\") stable\" > /etc/apt/sources.list.d/docker.list"
  as_root "apt-get update -y"
  as_root "apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin"
fi

docker compose version >/dev/null 2>&1 || as_root "apt-get install -y docker-compose-plugin"

log "Docker OK"
docker --version
docker compose version

############################################
# INSTALL DIR
############################################
log "Preparing ${INSTALL_DIR}"
as_root "mkdir -p ${INSTALL_DIR}"
cd "${INSTALL_DIR}"

############################################
# DOWNLOAD COMPOSE
############################################
log "Downloading docker-compose.yml"
curl -fsSLo docker-compose.yml "${COMPOSE_URL}"

############################################
# PATCH PORTS (SAFE METHOD)
############################################
log "Patching compose ports"

python3 <<'PY'
from pathlib import Path
p = Path("docker-compose.yml")
txt = p.read_text()
txt = txt.replace("9000:9000", "${COMPOSE_PORT_HTTP:-9000}:9000")
txt = txt.replace("9443:9443", "${COMPOSE_PORT_HTTPS:-9443}:9443")
p.write_text(txt)
PY

############################################
# SECRETS
############################################
AUTHENTIK_SECRET_KEY="$(openssl rand -base64 36 | tr -d '\n')"
PG_PASS="$(rand_alnum 28)"

BOOTSTRAP_EMAIL="admin@${AUTH_DOMAIN:-local}"
BOOTSTRAP_PASSWORD="$(rand_alnum 24)"
BOOTSTRAP_TOKEN="$(rand_alnum 40)"

LDAP_SERVICE_PW="$(rand_alnum 14)"
TAKPORTAL_PW="$(rand_alnum 20)"
TAKPORTAL_API_TOKEN="$(rand_alnum 64)"

############################################
# ENV FILE
############################################
log "Writing .env"
cat > .env <<EOF
AUTHENTIK_SECRET_KEY=${AUTHENTIK_SECRET_KEY}
PG_PASS=${PG_PASS}

COMPOSE_PORT_HTTP=${HTTP_PORT}
COMPOSE_PORT_HTTPS=${HTTPS_PORT}

AUTHENTIK_BOOTSTRAP_EMAIL=${BOOTSTRAP_EMAIL}
AUTHENTIK_BOOTSTRAP_PASSWORD=${BOOTSTRAP_PASSWORD}
AUTHENTIK_BOOTSTRAP_TOKEN=${BOOTSTRAP_TOKEN}
EOF

############################################
# START CONTAINERS
############################################
log "Starting authentik"
docker compose pull
docker compose up -d

############################################
# WAIT FOR API
############################################
log "Waiting for API"
for i in {1..150}; do
  curl -fsS "${BASE_URL}/api/v3/root/config/" >/dev/null && break
  sleep 2
done || die "authentik API not responding"

############################################
# BLUEPRINT
############################################
log "Applying blueprint"

cat > tak-blueprint.yaml <<EOF
version: 1
metadata:
  name: TAK Bootstrap
entries:
  - model: authentik_core.group
    state: present
    identifiers: { name: authentik-GlobalAdmin }

  - model: authentik_policies_password.passwordpolicy
    state: present
    identifiers: { name: default-password-change-password-policy }
    attrs:
      min_length: 12
      min_uppercase: 1
      min_lowercase: 1
      min_digits: 1
      min_symbols: 1

  - model: authentik_providers_ldap.ldapprovider
    state: present
    identifiers: { name: TAK LDAP }
    attrs:
      base_dn: DC=takldap
      bind_mode: cached
      search_mode: cached

  - model: authentik_core.user
    state: present
    identifiers: { username: adm_ldapservice }
    attrs:
      password: ${LDAP_SERVICE_PW}
      path: service_accounts

  - model: authentik_core.user
    state: present
    identifiers: { username: adm_takportal }
    attrs:
      password: ${TAKPORTAL_PW}
      groups:
        - authentik Admins

  - model: authentik_core.token
    state: present
    identifiers: { identifier: takportal-api }
    attrs:
      key: ${TAKPORTAL_API_TOKEN}
      intent: api
      user: !Find [authentik_core.user, [username, adm_takportal]]
EOF

curl -fsS \
  -H "Authorization: Bearer ${BOOTSTRAP_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg c "$(cat tak-blueprint.yaml)" '{name:"TAK Blueprint",enabled:true,content:$c}')" \
  "${BASE_URL}/api/v3/managed/blueprints/" >/dev/null || true

############################################
# DONE
############################################
log "INSTALL COMPLETE"

echo
echo "URL:                 ${BASE_URL}/if/admin/"
echo "Bootstrap Email:     ${BOOTSTRAP_EMAIL}"
echo "Bootstrap Password:  ${BOOTSTRAP_PASSWORD}"
echo "Bootstrap API Token: ${BOOTSTRAP_TOKEN}"
echo
echo "LDAP Service PW:     ${LDAP_SERVICE_PW}"
echo "TAK Portal User PW:  ${TAKPORTAL_PW}"
echo "TAK Portal API Key:  ${TAKPORTAL_API_TOKEN}"
echo
echo "Logs: cd ${INSTALL_DIR} && docker compose logs -f"
