#!/usr/bin/env bash
set -Eeuo pipefail

############################################
# Verbose logging setup
############################################
TS="$(date +%Y%m%d-%H%M%S)"
LOGFILE="/var/log/authentik-install-${TS}.log"
if ! ( touch "$LOGFILE" >/dev/null 2>&1 ); then
  LOGFILE="./authentik-install-${TS}.log"
  touch "$LOGFILE"
fi

# Timestamped xtrace lines
export PS4='+ [$(date "+%F %T")] ${BASH_SOURCE##*/}:${LINENO}:${FUNCNAME[0]:-main}() '

# Send stdout+stderr to screen + logfile
exec > >(tee -a "$LOGFILE") 2>&1
set -x

on_err() {
  local ec=$?
  echo
  echo "===== ERROR ====="
  echo "Exit code: $ec"
  echo "At line: ${BASH_LINENO[0]} in ${BASH_SOURCE[1]}"
  echo "Command: ${BASH_COMMAND}"
  echo "Log file: $LOGFILE"
  echo "============="
  echo
  exit "$ec"
}
trap on_err ERR

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
  [[ -z "${val:-}" ]] && echo "$def" || echo "$val"
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
echo "== authentik + TAK automation (VERBOSE) =="
echo "Log file: $LOGFILE"

HTTP_PORT="$(prompt_default 'authentik http port number?' '9000')"
HTTPS_PORT="$(prompt_default 'authentik https port number?' '9001')"

read -r -p "Authentik Domain? (optional): " AUTH_DOMAIN || true
read -r -p "TAK Portal Domain? (required): " TAK_DOMAIN || true
[[ -z "${TAK_DOMAIN:-}" ]] && { echo "TAK Portal Domain is required"; exit 1; }

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
# DOCKER + COMPOSE v2
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
head -n 30 docker-compose.yml

############################################
# PATCH PORTS
############################################
log "Patching compose ports to use env vars"
python3 <<'PY'
from pathlib import Path
p = Path("docker-compose.yml")
txt = p.read_text()
txt = txt.replace("9000:9000", "${COMPOSE_PORT_HTTP:-9000}:9000")
txt = txt.replace("9443:9443", "${COMPOSE_PORT_HTTPS:-9443}:9443")
p.write_text(txt)
PY

# show patched lines
grep -nE '9000:9000|9443:9443|COMPOSE_PORT_HTTP|COMPOSE_PORT_HTTPS' docker-compose.yml || true

############################################
# SECRETS
############################################
log "Generating secrets (dotenv-safe)"
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

sed -n '1,200p' .env

############################################
# PORT CHECK
############################################
log "Checking for port conflicts"
as_root "ss -ltnp | grep -E '(:${HTTP_PORT}\b|:${HTTPS_PORT}\b)' || true"

############################################
# START CONTAINERS
############################################
log "docker compose pull"
docker compose pull

log "docker compose up -d"
docker compose up -d

log "docker compose ps"
docker compose ps || true

############################################
# WAIT FOR API
############################################
log "Waiting for authentik API at ${BASE_URL}"
for i in $(seq 1 150); do
  if curl -fsS "${BASE_URL}/api/v3/root/config/" >/dev/null 2>&1; then
    echo "authentik is responding."
    break
  fi
  sleep 2
  if [[ "$i" -eq 150 ]]; then
    echo "Timed out waiting for API"
    docker compose logs --tail=200 || true
    exit 1
  fi
done

############################################
# BLUEPRINT (best-effort)
############################################
log "Writing blueprint"
cat > tak-blueprint.yaml <<EOF
version: 1
metadata:
  name: TAK Bootstrap
entries:
  - model: authentik_core.user
    state: present
    identifiers: { username: adm_ldapservice }
    attrs:
      password: ${LDAP_SERVICE_PW}
      path: service_accounts
EOF

log "Creating blueprint via API (best-effort)"
curl -fsS \
  -H "Authorization: Bearer ${BOOTSTRAP_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg c "$(cat tak-blueprint.yaml)" '{name:"TAK Blueprint",enabled:true,content:$c}')" \
  "${BASE_URL}/api/v3/managed/blueprints/" || true

############################################
# DONE
############################################
log "INSTALL COMPLETE"
echo "Log file:            $LOGFILE"
echo "authentik URL:       ${BASE_URL}/if/admin/"
echo "Bootstrap Email:     ${BOOTSTRAP_EMAIL}"
echo "Bootstrap Password:  ${BOOTSTRAP_PASSWORD}"
echo "Bootstrap API Token: ${BOOTSTRAP_TOKEN}"
echo "LDAP Service PW:     ${LDAP_SERVICE_PW}"
echo "TAK Portal User PW:  ${TAKPORTAL_PW}"
echo "TAK Portal API Key:  ${TAKPORTAL_API_TOKEN}"
echo "Logs: cd ${INSTALL_DIR} && docker compose logs -f"
