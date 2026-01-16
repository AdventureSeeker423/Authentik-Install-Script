#!/usr/bin/env bash
set -euo pipefail

# tak-authentik-bootstrap.sh
# Ubuntu script to install & configure authentik using Docker Compose v2 + Blueprints.

require() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1"; exit 1; }; }

rand_b64() { openssl rand -base64 36 | tr -d '\n'; }
rand_pw() {
  local len="${1:-14}"
  # URL-safe-ish, still includes symbols
  tr -dc 'A-Za-z0-9!@#$%^&*()-_=+[]{}:,.?' </dev/urandom | head -c "$len"
}

prompt_default() {
  local prompt="$1"; local def="$2"; local var
  read -r -p "$prompt [$def]: " var || true
  if [[ -z "${var:-}" ]]; then
    echo "$def"
  else
    echo "$var"
  fi
}

echo "== authentik + TAK automation =="
HTTP_PORT="$(prompt_default 'authentik http port number?' '9000')"
HTTPS_PORT="$(prompt_default 'authentik https port number?' '9001')"
read -r -p "Authentik Domain? (optional) []: " AUTH_DOMAIN || true
read -r -p "TAK Portal Domain? (required): " TAK_DOMAIN
if [[ -z "${TAK_DOMAIN:-}" ]]; then
  echo "TAK Portal Domain is required."
  exit 1
fi

# Normalize domains (strip scheme/path if user pasted a URL)
strip_url() {
  local x="$1"
  x="${x#http://}"; x="${x#https://}"
  x="${x%%/*}"
  echo "$x"
}
AUTH_DOMAIN="$(strip_url "${AUTH_DOMAIN:-}")"
TAK_DOMAIN="$(strip_url "${TAK_DOMAIN}")"

# If no AUTH_DOMAIN provided, we’ll use localhost:PORT for API calls and leave brand domain alone.
LOCAL_BASE="http://127.0.0.1:${HTTP_PORT}"
if [[ -n "${AUTH_DOMAIN}" ]]; then
  # you can still reach API via localhost if you’re on the host; this is just for blueprint branding.
  :
fi

echo
echo "== Installing prerequisites (docker, compose v2, curl, jq, openssl) =="

sudo apt-get update -y
sudo apt-get install -y ca-certificates curl jq openssl gnupg lsb-release

if ! command -v docker >/dev/null 2>&1; then
  # Install Docker Engine (Ubuntu)
  sudo install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  sudo chmod a+r /etc/apt/keyrings/docker.gpg
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
  sudo apt-get update -y
  sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi

require docker
require jq
require curl
require openssl

echo
echo "== Deploying authentik with Docker Compose v2 =="

INSTALL_DIR="/opt/authentik"
sudo mkdir -p "$INSTALL_DIR"
sudo chown "$USER":"$USER" "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Official docs: download latest docker-compose.yml :contentReference[oaicite:8]{index=8}
curl -fsSLo docker-compose.yml https://goauthentik.io/docker-compose.yml

AK_SECRET_KEY="$(rand_b64)"
PG_PASS="$(rand_pw 28)"

# Bootstrap admin + token via env vars (authentik supports env var configuration) :contentReference[oaicite:9]{index=9}
BOOTSTRAP_PASSWORD="$(rand_pw 24)"
BOOTSTRAP_TOKEN="$(rand_pw 40)"   # used as API token (Authorization: Bearer)
BOOTSTRAP_EMAIL="admin@${AUTH_DOMAIN:-local}"

cat > .env <<EOF
AUTHENTIK_SECRET_KEY=${AK_SECRET_KEY}
PG_PASS=${PG_PASS}

# Map container ports 9000/9443 to host ports (you asked for defaults 9000/9001)
COMPOSE_PORT_HTTP=${HTTP_PORT}
COMPOSE_PORT_HTTPS=${HTTPS_PORT}

# Bootstrap a default admin user and API token
AUTHENTIK_BOOTSTRAP_EMAIL=${BOOTSTRAP_EMAIL}
AUTHENTIK_BOOTSTRAP_PASSWORD=${BOOTSTRAP_PASSWORD}
AUTHENTIK_BOOTSTRAP_TOKEN=${BOOTSTRAP_TOKEN}
EOF

docker compose pull
docker compose up -d

echo
echo "== Waiting for authentik API to become ready =="
# root config endpoint exists in API v3 :contentReference[oaicite:10]{index=10}
for i in $(seq 1 120); do
  if curl -fsS "${LOCAL_BASE}/api/v3/root/config/" >/dev/null 2>&1; then
    echo "authentik is responding."
    break
  fi
  sleep 2
  if [[ "$i" -eq 120 ]]; then
    echo "Timed out waiting for authentik API on ${LOCAL_BASE}"
    exit 1
  fi
done

# Build blueprint variables
LDAP_SERVICE_PW="$(rand_pw 14)"
TAKPORTAL_PW="$(rand_pw 20)"
TAKPORTAL_API_TOKEN_KEY="$(rand_pw 64)"  # non-expiring API token key value

# Blueprint content:
# - Creates LDAP auth flow w/ identification(username-only), password stage, login stage (pattern from docs) :contentReference[oaicite:11]{index=11}
# - Creates LDAP provider/app "TAK LDAP" base DN DC=takldap :contentReference[oaicite:12]{index=12}
# - Creates group authentik-GlobalAdmin
# - Creates password policy object with required complexity (field names are per common policy schema)
# - Sets/creates brand domain if AUTH_DOMAIN is set (otherwise leaves default brand untouched)
# - Creates Proxy provider/app for TAK portal forward auth (mode forward_single) :contentReference[oaicite:13]{index=13}
# - Sets proxy token validity to 14 hours :contentReference[oaicite:14]{index=14}
# - Creates adm_ldapservice service account under path service_accounts, with random 14-char password
# - Creates adm_takportal user, adds to "authentik Admins" group, and creates a non-expiring API token (intent: api) :contentReference[oaicite:15]{index=15}

BRAND_ENTRY=""
if [[ -n "${AUTH_DOMAIN}" ]]; then
  # This tries to ensure a brand exists for the auth domain.
  BRAND_ENTRY=$(cat <<'EOF'
    - model: authentik_brands.brand
      state: present
      identifiers:
        domain: "__AUTH_DOMAIN__"
      attrs:
        domain: "__AUTH_DOMAIN__"
EOF
)
fi

cat > tak-blueprint.yaml <<EOF
version: 1
metadata:
  name: TAK - Authentik bootstrap (LDAP + Proxy + Users)
entries:
${BRAND_ENTRY}
  - model: authentik_core.group
    state: present
    identifiers:
      name: authentik-GlobalAdmin
    attrs:
      name: authentik-GlobalAdmin

  - model: authentik_policies_password.passwordpolicy
    state: present
    identifiers:
      name: default-password-change-password-policy
    attrs:
      name: default-password-change-password-policy
      min_length: 12
      min_uppercase: 1
      min_lowercase: 1
      min_symbols: 1
      min_digits: 1

  - model: authentik_flows.flow
    state: present
    identifiers:
      slug: ldap-authentication-flow
    attrs:
      name: ldap-authentication-flow
      title: LDAP Authentication
      designation: authentication

  - model: authentik_stages_identification.identificationstage
    state: present
    identifiers:
      name: ldap-identification-stage
    attrs:
      name: ldap-identification-stage
      user_fields:
        - username

  - model: authentik_stages_password.passwordstage
    state: present
    identifiers:
      name: ldap-authentication-password
    attrs:
      name: ldap-authentication-password

  - model: authentik_stages_user_login.userloginstage
    state: present
    identifiers:
      name: ldap-authentication-login
    attrs:
      name: ldap-authentication-login
      session_duration: seconds=0

  - model: authentik_flows.flowstagebinding
    state: present
    identifiers:
      target: !Find [authentik_flows.flow, [slug, "ldap-authentication-flow"]]
      order: 10
    attrs:
      stage: !Find [authentik_stages_identification.identificationstage, [name, "ldap-identification-stage"]]

  - model: authentik_flows.flowstagebinding
    state: present
    identifiers:
      target: !Find [authentik_flows.flow, [slug, "ldap-authentication-flow"]]
      order: 20
    attrs:
      stage: !Find [authentik_stages_password.passwordstage, [name, "ldap-authentication-password"]]

  - model: authentik_flows.flowstagebinding
    state: present
    identifiers:
      target: !Find [authentik_flows.flow, [slug, "ldap-authentication-flow"]]
      order: 100
    attrs:
      stage: !Find [authentik_stages_user_login.userloginstage, [name, "ldap-authentication-login"]]

  - model: authentik_providers_ldap.ldapprovider
    state: present
    identifiers:
      name: TAK LDAP
    attrs:
      name: TAK LDAP
      base_dn: DC=takldap
      bind_flow: !Find [authentik_flows.flow, [slug, "ldap-authentication-flow"]]
      bind_mode: cached
      search_mode: cached

  - model: authentik_core.application
    state: present
    identifiers:
      slug: tak-ldap
    attrs:
      name: TAK LDAP
      slug: tak-ldap
      provider: !Find [authentik_providers_ldap.ldapprovider, [name, "TAK LDAP"]]

  - model: authentik_providers_proxy.proxyprovider
    state: present
    identifiers:
      name: TAK Portal Proxy
    attrs:
      name: TAK Portal Proxy
      mode: forward_single
      external_host: https://${TAK_DOMAIN}
      authorization_flow: !Find [authentik_flows.flow, [slug, "default-provider-authorization-implicit-consent"]]
      token_validity: hours=14

  - model: authentik_core.application
    state: present
    identifiers:
      slug: tak-portal
    attrs:
      name: TAK Portal
      slug: tak-portal
      provider: !Find [authentik_providers_proxy.proxyprovider, [name, "TAK Portal Proxy"]]

  - model: authentik_core.user
    state: present
    identifiers:
      username: adm_ldapservice
    attrs:
      name: adm_ldapservice
      username: adm_ldapservice
      path: service_accounts
      password: ${LDAP_SERVICE_PW}
      # grant broad-ish visibility perms; adjust to your exact RBAC model as needed
      permissions:
        - authentik_providers_ldap.search_full_directory
        - authentik_providers_ldap.view_ldapprovider

  - model: authentik_core.user
    state: present
    identifiers:
      username: adm_takportal
    attrs:
      name: adm_takportal
      username: adm_takportal
      password: ${TAKPORTAL_PW}
      groups:
        - !Find [authentik_core.group, [name, "authentik Admins"]]

  - model: authentik_core.token
    state: present
    identifiers:
      identifier: adm_takportal-api
    attrs:
      key: ${TAKPORTAL_API_TOKEN_KEY}
      user: !Find [authentik_core.user, [username, "adm_takportal"]]
      intent: api
EOF

# Patch auth domain placeholder if present
if [[ -n "${AUTH_DOMAIN}" ]]; then
  sed -i "s/__AUTH_DOMAIN__/${AUTH_DOMAIN}/g" tak-blueprint.yaml
fi

echo
echo "== Creating + applying blueprint via API =="
# managed_blueprints_create + managed_blueprints_apply_create :contentReference[oaicite:16]{index=16}
BP_CREATE_RESP="$(curl -fsS \
  -H "Authorization: Bearer ${BOOTSTRAP_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg name "TAK Bootstrap" --arg content "$(cat tak-blueprint.yaml)" \
        '{name:$name, enabled:true, content:$content}')" \
  "${LOCAL_BASE}/api/v3/managed/blueprints/")"

BP_UUID="$(echo "$BP_CREATE_RESP" | jq -r '.pk // .uuid // .id // empty')"
if [[ -z "${BP_UUID}" ]]; then
  echo "Failed to determine blueprint instance UUID from response:"
  echo "$BP_CREATE_RESP" | jq .
  exit 1
fi

curl -fsS \
  -H "Authorization: Bearer ${BOOTSTRAP_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{}' \
  "${LOCAL_BASE}/api/v3/managed/blueprints/${BP_UUID}/apply/" >/dev/null

echo
echo "== Done =="
echo
echo "authentik URL (HTTP):  ${LOCAL_BASE}"
echo "authentik Admin path:  ${LOCAL_BASE}/if/admin/"
echo
echo "Bootstrap admin email:     ${BOOTSTRAP_EMAIL}"
echo "Bootstrap admin password:  ${BOOTSTRAP_PASSWORD}"
echo "Bootstrap API token:       ${BOOTSTRAP_TOKEN}"
echo
echo "adm_ldapservice password (14 chars): ${LDAP_SERVICE_PW}"
echo "adm_takportal password:              ${TAKPORTAL_PW}"
echo "adm_takportal non-expiring API key:  ${TAKPORTAL_API_TOKEN_KEY}"
echo
echo "TIP: If you want forward-auth to work, configure your reverse proxy using authentik's forward-auth docs."
echo "TIP: If you want LDAP/Proxy outposts auto-deployed, ensure the docker socket integration is enabled in your compose (authentik worker must have docker socket)."
