#!/usr/bin/env bash
set -euo pipefail

############################################
# Authentik + TAK bootstrap installer
# Ubuntu-focused
#
# Logging:
#   - Console + /var/log/authentik_tak_installer.log
############################################

LOG_FILE="/var/log/authentik_tak_installer.log"
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE" || true

log() {
  local ts
  ts="$(date -Is)"
  echo "[$ts] $*" | tee -a "$LOG_FILE" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "Run as root (or with sudo)."
  fi
}

rand_b64() {
  # URL-safe-ish base64 (no / + =), good for secrets/tokens
  local n="${1:-48}"
  python3 - <<PY
import secrets, string
alphabet = string.ascii_letters + string.digits + "-_"
print("".join(secrets.choice(alphabet) for _ in range($n)))
PY
}

rand_pw() {
  # strong-ish password, printable, avoids quotes
  local n="${1:-14}"
  python3 - <<PY
import secrets, string
alphabet = string.ascii_letters + string.digits + "!@#%^*-_=+?"
print("".join(secrets.choice(alphabet) for _ in range($n)))
PY
}

install_deps() {
  log "Installing system dependencies..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y \
    ca-certificates curl jq openssl \
    python3 python3-venv python3-pip \
    gnupg lsb-release

  # Docker install (Ubuntu repo version). If you prefer Docker's official repo, swap this section.
  if ! command -v docker >/dev/null 2>&1; then
    log "Installing docker..."
    apt-get install -y docker.io
    systemctl enable --now docker
  else
    log "Docker already installed."
  fi

  # Docker compose plugin
  if ! docker compose version >/dev/null 2>&1; then
    log "Installing docker compose plugin..."
    apt-get install -y docker-compose-plugin || apt-get install -y docker-compose
  else
    log "Docker Compose already available."
  fi
}

############################################
# Inputs (defaults for now)
############################################
get_inputs() {
  # For now: bypass prompts with defaults (as requested)
  # Toggle to "false" later to enable prompts.
  local BYPASS="${BYPASS_PROMPTS:-true}"

  AUTH_HTTP_PORT_DEFAULT="9000"
  AUTH_HTTPS_PORT_DEFAULT="9001"
  AUTH_DOMAIN_DEFAULT="https://auth.google.com"
  TAK_DOMAIN_DEFAULT="https://takportal.google.com"

  if [[ "$BYPASS" == "true" ]]; then
    AUTH_HTTP_PORT="${AUTH_HTTP_PORT_DEFAULT}"
    AUTH_HTTPS_PORT="${AUTH_HTTPS_PORT_DEFAULT}"
    AUTH_DOMAIN="${AUTH_DOMAIN_DEFAULT}"
    TAK_DOMAIN="${TAK_DOMAIN_DEFAULT}"
    log "Bypassing prompts with defaults:"
    log "  AUTH_HTTP_PORT=$AUTH_HTTP_PORT"
    log "  AUTH_HTTPS_PORT=$AUTH_HTTPS_PORT"
    log "  AUTH_DOMAIN=$AUTH_DOMAIN"
    log "  TAK_DOMAIN=$TAK_DOMAIN"
    return
  fi

  read -r -p "authentik http port number? [${AUTH_HTTP_PORT_DEFAULT}] " AUTH_HTTP_PORT
  AUTH_HTTP_PORT="${AUTH_HTTP_PORT:-$AUTH_HTTP_PORT_DEFAULT}"

  read -r -p "authentik https port number? [${AUTH_HTTPS_PORT_DEFAULT}] " AUTH_HTTPS_PORT
  AUTH_HTTPS_PORT="${AUTH_HTTPS_PORT:-$AUTH_HTTPS_PORT_DEFAULT}"

  read -r -p "Authentik Domain? (optional) [${AUTH_DOMAIN_DEFAULT}] " AUTH_DOMAIN
  AUTH_DOMAIN="${AUTH_DOMAIN:-$AUTH_DOMAIN_DEFAULT}"

  read -r -p "TAK Portal Domain? (optional) [${TAK_DOMAIN_DEFAULT}] " TAK_DOMAIN
  TAK_DOMAIN="${TAK_DOMAIN:-$TAK_DOMAIN_DEFAULT}"
}

############################################
# Compose deployment
############################################
setup_compose() {
  INSTALL_DIR="${INSTALL_DIR:-/opt/authentik}"
  mkdir -p "$INSTALL_DIR"
  cd "$INSTALL_DIR"

  log "Preparing secrets and environment..."

  # Core secrets
  POSTGRES_PASSWORD="$(rand_pw 32)"
  AUTHENTIK_SECRET_KEY="$(rand_b64 64)"

  # Bootstrap admin (akadmin) password & API token (documented bootstrap env vars). :contentReference[oaicite:2]{index=2}
  BOOTSTRAP_PASSWORD="$(rand_pw 20)"
  BOOTSTRAP_TOKEN="$(rand_b64 48)"
  BOOTSTRAP_EMAIL="${BOOTSTRAP_EMAIL:-root@example.com}"

  # Service passwords requested
  ADM_LDAPSERVICE_PASSWORD="$(rand_pw 14)"
  ADM_TAKPORTAL_PASSWORD="$(rand_pw 14)"

  # Write .env
  cat > .env <<EOF
# Ports
AUTHENTIK_HTTP_PORT=${AUTH_HTTP_PORT}
AUTHENTIK_HTTPS_PORT=${AUTH_HTTPS_PORT}

# PostgreSQL
PG_PASS=${POSTGRES_PASSWORD}

# authentik
AUTHENTIK_SECRET_KEY=${AUTHENTIK_SECRET_KEY}

# bootstrap admin (akadmin)
AUTHENTIK_BOOTSTRAP_EMAIL=${BOOTSTRAP_EMAIL}
AUTHENTIK_BOOTSTRAP_PASSWORD=${BOOTSTRAP_PASSWORD}
AUTHENTIK_BOOTSTRAP_TOKEN=${BOOTSTRAP_TOKEN}
EOF

  log "Writing docker-compose.yml..."
  cat > docker-compose.yml <<'EOF'
services:
  postgresql:
    image: docker.io/library/postgres:16
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -d authentik -U authentik"]
      interval: 10s
      timeout: 5s
      retries: 5
    environment:
      POSTGRES_PASSWORD: ${PG_PASS}
      POSTGRES_USER: authentik
      POSTGRES_DB: authentik
    volumes:
      - ./database:/var/lib/postgresql/data

  redis:
    image: docker.io/library/redis:7
    restart: unless-stopped
    command: ["redis-server", "--save", "60", "1", "--loglevel", "warning"]
    volumes:
      - ./redis:/data

  server:
    image: ghcr.io/goauthentik/server:latest
    restart: unless-stopped
    command: server
    environment:
      AUTHENTIK_REDIS__HOST: redis
      AUTHENTIK_POSTGRESQL__HOST: postgresql
      AUTHENTIK_POSTGRESQL__USER: authentik
      AUTHENTIK_POSTGRESQL__NAME: authentik
      AUTHENTIK_POSTGRESQL__PASSWORD: ${PG_PASS}
      AUTHENTIK_SECRET_KEY: ${AUTHENTIK_SECRET_KEY}
      AUTHENTIK_LOG_LEVEL: info
      AUTHENTIK_BOOTSTRAP_EMAIL: ${AUTHENTIK_BOOTSTRAP_EMAIL}
      AUTHENTIK_BOOTSTRAP_PASSWORD: ${AUTHENTIK_BOOTSTRAP_PASSWORD}
      AUTHENTIK_BOOTSTRAP_TOKEN: ${AUTHENTIK_BOOTSTRAP_TOKEN}
    ports:
      - "${AUTHENTIK_HTTP_PORT}:9000"
      - "${AUTHENTIK_HTTPS_PORT}:9443"
    volumes:
      - ./media:/media
      - ./custom-templates:/templates
    depends_on:
      postgresql:
        condition: service_healthy
      redis:
        condition: service_started

  worker:
    image: ghcr.io/goauthentik/server:latest
    restart: unless-stopped
    command: worker
    environment:
      AUTHENTIK_REDIS__HOST: redis
      AUTHENTIK_POSTGRESQL__HOST: postgresql
      AUTHENTIK_POSTGRESQL__USER: authentik
      AUTHENTIK_POSTGRESQL__NAME: authentik
      AUTHENTIK_POSTGRESQL__PASSWORD: ${PG_PASS}
      AUTHENTIK_SECRET_KEY: ${AUTHENTIK_SECRET_KEY}
      AUTHENTIK_LOG_LEVEL: info
      AUTHENTIK_BOOTSTRAP_EMAIL: ${AUTHENTIK_BOOTSTRAP_EMAIL}
      AUTHENTIK_BOOTSTRAP_PASSWORD: ${AUTHENTIK_BOOTSTRAP_PASSWORD}
      AUTHENTIK_BOOTSTRAP_TOKEN: ${AUTHENTIK_BOOTSTRAP_TOKEN}
    volumes:
      - ./media:/media
      - ./custom-templates:/templates
    depends_on:
      postgresql:
        condition: service_healthy
      redis:
        condition: service_started
EOF

  preflight_environment() {
  local virt
  virt="$(systemd-detect-virt || true)"

  if [[ "$virt" == "lxc" ]]; then
    log "Detected LXC environment."
    cat >&2 <<'MSG'
This installer uses Docker containers. Docker inside an *unprivileged* LXC often cannot start containers
because the host blocks access to kernel sysctls (/proc/sys/*) and other required features.

To run this installer reliably, use:
  - a VM, bare metal, or
  - a *privileged* LXC with nesting enabled (host-side setting).

There is no safe way for an install script to bypass these host restrictions automatically.
MSG
    exit 2
  fi
}
  log "Starting authentik stack with docker compose..."
  docker compose up -d

  log "Waiting for authentik API to come up on http://127.0.0.1:${AUTH_HTTP_PORT}/api/v3/ ..."
  for i in {1..120}; do
    if curl -fsS "http://127.0.0.1:${AUTH_HTTP_PORT}/api/v3/root/config/" >/dev/null 2>&1; then
      log "authentik API is reachable."
      return
    fi
    sleep 2
  done

  die "authentik did not become reachable in time. Check: docker compose logs -f"
}

############################################
# Python configurator
############################################
run_configurator() {
  cd "$INSTALL_DIR"

  log "Creating Python venv and installing Python dependencies..."
  if [[ ! -d .venv ]]; then
    python3 -m venv .venv
  fi
  # shellcheck disable=SC1091
  source .venv/bin/activate
  pip install --upgrade pip >/dev/null
  pip install requests >/dev/null

  log "Writing configurator script..."
  cat > configure_authentik.py <<'PY'
import os
import sys
import json
import time
from urllib.parse import urlparse

import requests

def log(msg: str) -> None:
    ts = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    print(f"[{ts}] {msg}", file=sys.stderr)

class AK:
    def __init__(self, base: str, token: str):
        self.base = base.rstrip("/")
        self.s = requests.Session()
        self.s.headers.update({
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    def _url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return f"{self.base}{path}"

    def get(self, path: str, **kw):
        r = self.s.get(self._url(path), timeout=30, **kw)
        return r

    def post(self, path: str, payload: dict, **kw):
        r = self.s.post(self._url(path), data=json.dumps(payload), timeout=30, **kw)
        return r

    def patch(self, path: str, payload: dict, **kw):
        r = self.s.patch(self._url(path), data=json.dumps(payload), timeout=30, **kw)
        return r

    def put(self, path: str, payload: dict, **kw):
        r = self.s.put(self._url(path), data=json.dumps(payload), timeout=30, **kw)
        return r

def must_ok(r: requests.Response, what: str):
    if r.status_code >= 200 and r.status_code < 300:
        return
    # Log rich error for debugging
    try:
        body = r.json()
    except Exception:
        body = r.text
    raise RuntimeError(f"{what} failed: HTTP {r.status_code} {body}")

def find_by_name(ak: AK, list_path: str, name: str):
    r = ak.get(list_path, params={"name": name})
    must_ok(r, f"list {list_path}")
    data = r.json()
    results = data.get("results", data)
    for obj in results:
        if obj.get("name") == name:
            return obj
    return None

def find_by_slug(ak: AK, list_path: str, slug: str):
    r = ak.get(list_path, params={"slug": slug})
    must_ok(r, f"list {list_path}")
    data = r.json()
    results = data.get("results", data)
    for obj in results:
        if obj.get("slug") == slug:
            return obj
    return None

def create_or_get(ak: AK, list_path: str, payload: dict, key="name", finder=find_by_name):
    name = payload.get(key)
    if not name:
        raise ValueError(f"payload missing {key}: {payload}")
    existing = finder(ak, list_path, name)
    if existing:
        log(f"Exists: {list_path} {name}")
        return existing
    r = ak.post(list_path, payload)
    must_ok(r, f"create {list_path} {name}")
    obj = r.json()
    log(f"Created: {list_path} {name}")
    return obj

def main():
    http_port = os.environ["AUTH_HTTP_PORT"]
    token = os.environ["AUTH_BOOTSTRAP_TOKEN"]
    auth_domain = os.environ.get("AUTH_DOMAIN", "").strip()
    tak_domain = os.environ.get("TAK_DOMAIN", "").strip()

    ldap_pw = os.environ["ADM_LDAPSERVICE_PASSWORD"]
    tak_pw = os.environ["ADM_TAKPORTAL_PASSWORD"]

    base = f"http://127.0.0.1:{http_port}/api/v3"
    ak = AK(base=base, token=token)

    # Sanity check
    r = ak.get("/root/config/")
    must_ok(r, "root/config")
    log("Authenticated to authentik API using bootstrap token.")

    # --- Groups ---
    global_admin = create_or_get(
        ak, "/core/groups/",
        {"name": "authentik-GlobalAdmin"},
    )

    # Fetch authentik Admins group (created by bootstrap blueprint)
    admins = find_by_name(ak, "/core/groups/", "authentik Admins")
    if not admins:
        log("authentik Admins group not found, creating it (should normally exist).")
        admins = create_or_get(ak, "/core/groups/", {"name": "authentik Admins", "is_superuser": True})

    # --- Users ---
    # adm_ldapservice (service account style path)
    # Prefer the service_account endpoint if available
    r = ak.get("/core/users/paths/")
    if r.status_code == 200:
        # optional: paths exist on some versions, but not required
        pass

    # Check if user exists
    r = ak.get("/core/users/", params={"username": "adm_ldapservice"})
    must_ok(r, "list users")
    results = r.json().get("results", [])
    if results:
        ldap_user = results[0]
        log("User exists: adm_ldapservice")
    else:
        # Use normal create; path is often a string like "service_accounts"
        ldap_user = create_or_get(
            ak, "/core/users/",
            {
                "username": "adm_ldapservice",
                "name": "adm_ldapservice",
                "is_active": True,
                "path": "service_accounts",
            },
            key="username",
            finder=lambda ak2, p, u: (results[0] if results else None),
        )

    # Set password
    uid = ldap_user.get("pk") or ldap_user.get("id")
    if uid is None:
        raise RuntimeError(f"Cannot find user id for adm_ldapservice: {ldap_user}")
    r = ak.post(f"/core/users/{uid}/set_password/", {"password": ldap_pw})
    must_ok(r, "set_password adm_ldapservice")
    log("Set password for adm_ldapservice")

    # NOTE: Fine-grained provider/directory permissions are RBAC-heavy.
    # As a practical bootstrap, put it in authentik Admins so it can search/view LDAP directory/provider.
    r = ak.post(f"/core/groups/{admins['pk']}/add_user/", {"pk": uid})
    if r.status_code not in (204, 200):
        log(f"WARNING: add_user adm_ldapservice to authentik Admins failed: {r.status_code} {r.text}")
    else:
        log("Added adm_ldapservice to authentik Admins (bootstrap permission set).")

    # --- Password policy (12 chars, upper/lower/number/symbol) ---
    # Endpoint: /policies/password/
    policy_name = "default-password-change-password-policy"
    existing_policy = find_by_name(ak, "/policies/password/", policy_name)
    policy_payload = {
        "name": policy_name,
        "execution_logging": True,
        "amount_uppercase": 1,
        "amount_lowercase": 1,
        "amount_digits": 1,
        "amount_symbols": 1,
        "length_min": 12,
        "symbol_charset": "!@#$%^&*()-_=+[]{};:,.<>/?",
        "error_message": "Password does not meet complexity requirements.",
    }
    if existing_policy:
        pid = existing_policy.get("pk") or existing_policy.get("id")
        r = ak.put(f"/policies/password/{pid}/", policy_payload)
        if r.status_code >= 400:
            log(f"WARNING: update password policy failed: {r.status_code} {r.text}")
        else:
            log("Updated password policy.")
    else:
        r = ak.post("/policies/password/", policy_payload)
        if r.status_code >= 400:
            log(f"WARNING: create password policy failed: {r.status_code} {r.text}")
        else:
            log("Created password policy.")

    # --- Brand domain ---
    # /core/brands/
    # Use host part if a full URL is provided
    brand_domain = ""
    if auth_domain:
        u = urlparse(auth_domain if "://" in auth_domain else f"https://{auth_domain}")
        brand_domain = u.netloc or auth_domain
    else:
        brand_domain = "authentik.local"

    brand_name = f"Brand for {brand_domain}"
    existing_brand = find_by_name(ak, "/core/brands/", brand_name)
    brand_payload = {"name": brand_name, "domain": brand_domain, "default": True}
    if existing_brand:
        bid = existing_brand.get("pk") or existing_brand.get("id")
        r = ak.patch(f"/core/brands/{bid}/", brand_payload)
        if r.status_code >= 400:
            log(f"WARNING: update brand failed: {r.status_code} {r.text}")
        else:
            log("Updated brand.")
    else:
        r = ak.post("/core/brands/", brand_payload)
        if r.status_code >= 400:
            log(f"WARNING: create brand failed: {r.status_code} {r.text}")
        else:
            log("Created brand.")

    # --- LDAP authentication flow + stages ---
    # flows: /flows/instances/
    flow = find_by_slug(ak, "/flows/instances/", "ldap-authentication-flow")
    if not flow:
        r = ak.post("/flows/instances/", {
            "name": "ldap-authentication-flow",
            "title": "LDAP Authentication Flow",
            "slug": "ldap-authentication-flow",
            "designation": "authentication",
            "compatibility_mode": True,
        })
        if r.status_code >= 400:
            log(f"WARNING: create flow failed: {r.status_code} {r.text}")
            flow = None
        else:
            flow = r.json()
            log("Created flow ldap-authentication-flow")
    else:
        log("Flow exists: ldap-authentication-flow")

    # Stages: identification, password, user_login
    ident_stage = find_by_name(ak, "/stages/identification/", "ldap-identification-stage")
    if not ident_stage:
        r = ak.post("/stages/identification/", {
            "name": "ldap-identification-stage",
            "user_fields": ["username"],
            "password_fields": False,
            "show_matched_user": False,
        })
        if r.status_code >= 400:
            log(f"WARNING: create identification stage failed: {r.status_code} {r.text}")
        else:
            ident_stage = r.json()
            log("Created identification stage.")
    else:
        log("Identification stage exists.")

    pwd_stage = find_by_name(ak, "/stages/password/", "ldap-authentication-password")
    if not pwd_stage:
        r = ak.post("/stages/password/", {
            "name": "ldap-authentication-password",
            "backends": ["authentik.core.auth.InbuiltBackend"],
        })
        if r.status_code >= 400:
            log(f"WARNING: create password stage failed: {r.status_code} {r.text}")
        else:
            pwd_stage = r.json()
            log("Created password stage.")
    else:
        log("Password stage exists.")

    login_stage = find_by_name(ak, "/stages/user_login/", "ldap-authentication-login")
    if not login_stage:
        r = ak.post("/stages/user_login/", {"name": "ldap-authentication-login"})
        if r.status_code >= 400:
            log(f"WARNING: create user_login stage failed: {r.status_code} {r.text}")
        else:
            login_stage = r.json()
            log("Created user_login stage.")
    else:
        log("User_login stage exists.")

    # Bind stages to flow (order: ident -> password -> login)
    if flow and ident_stage and pwd_stage and login_stage:
        fid = flow.get("pk") or flow.get("id")
        def bind(stage_obj, order):
            sid = stage_obj.get("pk") or stage_obj.get("id")
            # check existing bindings
            r = ak.get("/flows/bindings/", params={"target": fid})
            if r.status_code == 200:
                existing = r.json().get("results", [])
                for b in existing:
                    if (b.get("stage") == sid) and (b.get("target") == fid):
                        return
            payload = {
                "target": fid,
                "stage": sid,
                "order": order,
                "evaluate_on_plan": True,
                "re_evaluate_policies": True,
            }
            r = ak.post("/flows/bindings/", payload)
            if r.status_code >= 400:
                log(f"WARNING: bind stage order={order} failed: {r.status_code} {r.text}")
            else:
                log(f"Bound stage order={order}.")
        bind(ident_stage, 10)
        bind(pwd_stage, 20)
        bind(login_stage, 30)

    # --- LDAP Provider + Application + Outpost ---
    # Provider: /providers/ldap/
    ldap_provider = find_by_name(ak, "/providers/ldap/", "TAK LDAP")
    if not ldap_provider:
        payload = {
            "name": "TAK LDAP",
            "base_dn": "DC=takldap",
            "bind_flow": flow.get("pk") if flow else None,
            # cached binding/query flags vary by version; try common names
            "cached_bind": True,
            "cached_query": True,
        }
        r = ak.post("/providers/ldap/", payload)
        if r.status_code >= 400:
            log(f"WARNING: create LDAP provider failed: {r.status_code} {r.text}")
            ldap_provider = None
        else:
            ldap_provider = r.json()
            log("Created LDAP provider TAK LDAP.")
    else:
        log("LDAP provider exists: TAK LDAP")

    # Application: /core/applications/
    ldap_app = find_by_name(ak, "/core/applications/", "TAK LDAP")
    if not ldap_app and ldap_provider:
        r = ak.post("/core/applications/", {
            "name": "TAK LDAP",
            "slug": "tak-ldap",
            "provider": ldap_provider.get("pk") or ldap_provider.get("id"),
        })
        if r.status_code >= 400:
            log(f"WARNING: create LDAP application failed: {r.status_code} {r.text}")
        else:
            ldap_app = r.json()
            log("Created LDAP application.")
    else:
        if ldap_app:
            log("LDAP application exists.")

    # Outpost instance: /outposts/instances/
    outpost = find_by_name(ak, "/outposts/instances/", "TAK LDAP")
    if not outpost and ldap_app:
        # Embedded outpost by default often exists; we can attach provider/app to it,
        # but here we create a named one as requested.
        payload = {
            "name": "TAK LDAP",
            "type": "ldap",
            "providers": [ldap_provider.get("pk") or ldap_provider.get("id")] if ldap_provider else [],
        }
        r = ak.post("/outposts/instances/", payload)
        if r.status_code >= 400:
            log(f"WARNING: create outpost instance failed: {r.status_code} {r.text}")
        else:
            outpost = r.json()
            log("Created outpost instance TAK LDAP.")
    else:
        if outpost:
            log("Outpost instance exists: TAK LDAP")

    # --- TAK Portal proxy provider + app ---
    # This depends on your desired forward-auth behavior.
    # Provider: /providers/proxy/
    proxy_provider = find_by_name(ak, "/providers/proxy/", "TAK Portal Proxy")
    if not proxy_provider:
        payload = {
            "name": "TAK Portal Proxy",
            "mode": "forward_single",  # common forward-auth mode name (may vary)
            "external_host": tak_domain,
            "authorization_flow": None,  # will use default if omitted on some versions
            "access_token_validity": "14:00:00",
            "refresh_token_validity": "14:00:00",
            "intercept_header_auth": True,
        }
        r = ak.post("/providers/proxy/", payload)
        if r.status_code >= 400:
            log(f"WARNING: create proxy provider failed: {r.status_code} {r.text}")
            proxy_provider = None
        else:
            proxy_provider = r.json()
            log("Created proxy provider TAK Portal Proxy.")
    else:
        log("Proxy provider exists: TAK Portal Proxy")

    tak_app = find_by_name(ak, "/core/applications/", "TAK Portal")
    if not tak_app and proxy_provider:
        payload = {
            "name": "TAK Portal",
            "slug": "tak-portal",
            "provider": proxy_provider.get("pk") or proxy_provider.get("id"),
            # Attempt to point at implicit-consent flow if it exists; otherwise leave null.
        }
        # Try to find the default implicit consent flow by slug (common default)
        implicit = find_by_slug(ak, "/flows/instances/", "default-provider-authorization-implicit-consent")
        if implicit:
            payload["authorization_flow"] = implicit.get("pk") or implicit.get("id")
        r = ak.post("/core/applications/", payload)
        if r.status_code >= 400:
            log(f"WARNING: create TAK Portal application failed: {r.status_code} {r.text}")
        else:
            tak_app = r.json()
            log("Created TAK Portal application.")
    else:
        if tak_app:
            log("TAK Portal application exists.")

    # --- adm_takportal user + superuser group + API token ---
    # Create user
    r = ak.get("/core/users/", params={"username": "adm_takportal"})
    must_ok(r, "list users")
    results = r.json().get("results", [])
    if results:
        tak_user = results[0]
        log("User exists: adm_takportal")
    else:
        r = ak.post("/core/users/", {"username": "adm_takportal", "name": "adm_takportal", "is_active": True})
        if r.status_code >= 400:
            log(f"WARNING: create user adm_takportal failed: {r.status_code} {r.text}")
            tak_user = None
        else:
            tak_user = r.json()
            log("Created user adm_takportal")

    if tak_user:
        uid2 = tak_user.get("pk") or tak_user.get("id")
        r = ak.post(f"/core/users/{uid2}/set_password/", {"password": tak_pw})
        if r.status_code >= 400:
            log(f"WARNING: set_password adm_takportal failed: {r.status_code} {r.text}")
        else:
            log("Set password for adm_takportal")

        # Add to authentik Admins (superuser) group
        r = ak.post(f"/core/groups/{admins['pk']}/add_user/", {"pk": uid2})
        if r.status_code not in (204, 200):
            log(f"WARNING: add_user adm_takportal to authentik Admins failed: {r.status_code} {r.text}")
        else:
            log("Added adm_takportal to authentik Admins (superuser).")

        # Create non-expiring API token
        # /core/tokens/
        token_name = "adm_takportal-api"
        # See if token exists
        r = ak.get("/core/tokens/", params={"identifier": token_name})
        if r.status_code == 200:
            found = r.json().get("results", [])
        else:
            found = []
        if found:
            log("API token already exists for adm_takportal (identifier adm_takportal-api).")
            tak_api_key = None
        else:
            r = ak.post("/core/tokens/", {
                "identifier": token_name,
                "intent": "api",
                "user": uid2,
                "expiring": False,
            })
            if r.status_code >= 400:
                log(f"WARNING: create API token failed: {r.status_code} {r.text}")
                tak_api_key = None
            else:
                tok = r.json()
                tak_api_key = tok.get("key")  # Usually only shown once.
                log("Created non-expiring API token for adm_takportal.")

    # Final summary to stdout (not stderr)
    print("")
    print("========== OUTPUTS ==========")
    print(f"adm_ldapservice password: {ldap_pw}")
    print(f"adm_takportal  password: {tak_pw}")
    # tak_api_key may be None if token existed or API doesn't return it
    if 'tak_api_key' in locals() and tak_api_key:
        print(f"adm_takportal API key:   {tak_api_key}")
    else:
        print("adm_takportal API key:   (not displayed; token may already exist or API didn't return key)")
    print("=============================")

if __name__ == "__main__":
    main()
PY

  log "Running configurator against authentik API..."
  export AUTH_HTTP_PORT="${AUTH_HTTP_PORT}"
  export AUTH_BOOTSTRAP_TOKEN="${BOOTSTRAP_TOKEN}"
  export AUTH_DOMAIN="${AUTH_DOMAIN}"
  export TAK_DOMAIN="${TAK_DOMAIN}"
  export ADM_LDAPSERVICE_PASSWORD="${ADM_LDAPSERVICE_PASSWORD}"
  export ADM_TAKPORTAL_PASSWORD="${ADM_TAKPORTAL_PASSWORD}"

  set +e
  python configure_authentik.py 2> >(tee -a "$LOG_FILE" >&2) | tee -a "$LOG_FILE"
  rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    log "Configurator exited with code $rc"
    log "Check log file: $LOG_FILE"
    exit $rc
  fi

  log "Done."
  log "Auth UI should be reachable at: http://<host>:${AUTH_HTTP_PORT}/"
  log "Bootstrap admin user: akadmin"
  log "Bootstrap admin password stored in ${INSTALL_DIR}/.env"
}

main() {
  need_root
  install_deps
  get_inputs
  setup_compose
  run_configurator

  log "Installer complete."
  log "TIP: View logs with: tail -f $LOG_FILE"
  log "TIP: View container logs with: cd $INSTALL_DIR && docker compose logs -f"
}

main "$@"
