#!/usr/bin/env bash
# Insight Shield — idempotent installer. Run on the Ubuntu target as root.
#
# Usage:
#   sudo cp -r insightshield /opt/insightshield/insightshield
#   sudo /opt/insightshield/insightshield/scripts/install.sh
#
# This script does NOT copy application code. You place the tree first, then
# run this from inside it. That is what makes re-running safe: there is no step
# that can overwrite your live code, your database, or your secrets.
#
# It is safe to run before Wazuh is installed — the Wazuh sections skip
# themselves with a warning and you re-run after `wazuh-install.sh -a`.
#
# Exit codes: 0 = everything applied or already correct, 1 = something failed.
#
# See docs/deployment-ubuntu.md for what each step is doing and why.

set -u

APP_ROOT=/opt/insightshield
APP="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$APP/.env"
VENV="$APP_ROOT/venv"
PW_PATH="$APP_ROOT/ms-playwright"
LOG_DIR=/var/log/insightshield
SVC_USER=insightshield
DASH_YML=/etc/wazuh-dashboard/opensearch_dashboards.yml
OSSEC_CONF=/var/ossec/etc/ossec.conf

FAIL=0
pass() { printf "\e[32m[PASS]\e[0m %s\n" "$1"; }
fail() { printf "\e[31m[FAIL]\e[0m %s\n" "$1"; FAIL=1; }
warn() { printf "\e[33m[WARN]\e[0m %s\n" "$1"; }
die()  { printf "\e[31m[FAIL]\e[0m %s\n" "$1"; exit 1; }

# Restarts are conditional on an actual change, so a no-op re-run does not
# bounce services that are happily serving traffic.
NGINX_CHANGED=0
WAZUH_CHANGED=0
DASH_CHANGED=0

echo "=== Insight Shield installer ==="
echo "    app tree: $APP"

# ── 1. Preflight ─────────────────────────────────────────────────────────────

[ "$(id -u)" = 0 ] || die "must run as root (sudo $0)"
[ -f "$APP/app.py" ] || die "$APP does not look like the app tree (no app.py)"
[ -f "$APP/.env.example" ] || die "$APP/.env.example missing"

command -v python3 >/dev/null || die "python3 not installed (see runbook §1.4)"
# ufw is not used by this script — scripts/firewall.sh needs it, and a missing
# ufw should surface here rather than three sections into the runbook.
for binary in nginx openssl sqlite3 jq curl ufw; do
  command -v "$binary" >/dev/null || warn "$binary not installed — see runbook §1.4"
done

HAVE_WAZUH=0
if [ -d /var/ossec ]; then
  HAVE_WAZUH=1
else
  warn "/var/ossec not found — skipping Wazuh wiring. Install Wazuh, then re-run."
fi

# ── 2. Service user, directories, ownership ──────────────────────────────────

if id "$SVC_USER" >/dev/null 2>&1; then
  pass "user: $SVC_USER exists"
else
  useradd --system --home "$APP_ROOT" --shell /usr/sbin/nologin "$SVC_USER" \
    && pass "user: created $SVC_USER" || fail "user: could not create $SVC_USER"
fi

install -d -o "$SVC_USER" -g "$SVC_USER" "$LOG_DIR" \
  && pass "dirs: $LOG_DIR ready" || fail "dirs: could not create $LOG_DIR"
# gunicorn writes access.log/error.log here and refuses to boot if it cannot.

chown -R "$SVC_USER":"$SVC_USER" "$APP_ROOT"
# nginx (www-data) serves /static/ straight off disk, so it needs traverse on
# the parents and read on the tree. Everything else stays owner-only.
chmod o+x "$APP_ROOT" "$APP"
chmod -R o+rX "$APP/static"
pass "dirs: ownership and nginx traverse bits set"

# ── 3. Virtualenv ────────────────────────────────────────────────────────────

if [ -x "$VENV/bin/python" ]; then
  pass "venv: $VENV exists"
else
  runuser -u "$SVC_USER" -- python3 -m venv "$VENV" \
    && pass "venv: created" || die "venv: creation failed"
fi

if runuser -u "$SVC_USER" -- "$VENV/bin/pip" install -q -r "$APP/requirements.txt"; then
  pass "venv: requirements installed"
else
  fail "venv: pip install failed"
fi

# ── 4. .env and secrets ──────────────────────────────────────────────────────

if [ -f "$ENV_FILE" ]; then
  pass "env: $ENV_FILE exists"
else
  cp "$APP/.env.example" "$ENV_FILE" && pass "env: created from .env.example"
fi
chown "$SVC_USER":"$SVC_USER" "$ENV_FILE"
chmod 600 "$ENV_FILE"

# Generate a secret ONLY when it is absent, empty, or still a .env.example
# placeholder. There is deliberately no --force and no branch that overwrites a
# real value: regenerating ENCRYPTION_KEY makes every encrypted credential and
# every existing backup permanently unrecoverable.
#
# The generators emit hex or url-safe base64, so no sed metacharacter can ever
# appear in the replacement text.
ensure_secret() {   # $1 = key name, $2 = shell command that prints the value
  local key="$1" gen="$2" current
  grep -q "^$key=" "$ENV_FILE" || printf '%s=\n' "$key" >> "$ENV_FILE"
  current="$(sed -n "s/^$key=//p" "$ENV_FILE" | head -1)"
  case "$current" in
    ""|your-*|generate-a-random-secret-key-here|change-me*)
      sed -i "s|^$key=.*|$key=$(eval "$gen")|" "$ENV_FILE"
      pass "env: $key generated"
      ;;
    *)
      pass "env: $key already set — left untouched"
      ;;
  esac
}

ensure_secret FLASK_SECRET_KEY \
  "python3 -c 'import secrets; print(secrets.token_hex(32))'"
ensure_secret ENCRYPTION_KEY \
  "$VENV/bin/python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
ensure_secret WAZUH_WEBHOOK_TOKEN \
  "python3 -c 'import secrets; print(secrets.token_hex(32))'"

WEBHOOK_TOKEN="$(sed -n 's/^WAZUH_WEBHOOK_TOKEN=//p' "$ENV_FILE" | head -1)"
[ -n "$WEBHOOK_TOKEN" ] || fail "env: WAZUH_WEBHOOK_TOKEN still empty after generation"

# ── 5. Playwright browser (B4) ───────────────────────────────────────────────
# Installed under $APP_ROOT rather than ~/.cache because the systemd unit sets
# ProtectHome=true, which makes the home directory invisible to the service.

if runuser -u "$SVC_USER" -- env PLAYWRIGHT_BROWSERS_PATH="$PW_PATH" \
     "$VENV/bin/python" -m playwright install chromium >/dev/null 2>&1; then
  pass "playwright: chromium present at $PW_PATH"
else
  fail "playwright: chromium install failed — /report.pdf will not work"
fi

# apt-level shared libraries. Idempotent, but noisy and slow, so quiet it.
if "$VENV/bin/python" -m playwright install-deps chromium >/dev/null 2>&1; then
  pass "playwright: system libraries present"
else
  warn "playwright: install-deps failed — run it manually if PDF export errors"
fi

# ── 6. nginx and TLS ─────────────────────────────────────────────────────────

install -d -m 755 /etc/nginx/ssl
if [ -f /etc/nginx/ssl/insightshield.crt ] && [ -f /etc/nginx/ssl/insightshield.key ]; then
  pass "nginx: TLS certificate exists — left untouched"
else
  # Only ever generated once. Re-issuing would invalidate the fingerprint every
  # browser and every curl --cacert on the network has already accepted.
  openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/insightshield.key \
    -out    /etc/nginx/ssl/insightshield.crt \
    -subj "/CN=insightshield.local" \
    -addext "subjectAltName=DNS:insightshield.local,IP:192.168.100.30" \
    >/dev/null 2>&1 \
    && { chmod 600 /etc/nginx/ssl/insightshield.key; pass "nginx: self-signed certificate generated"; } \
    || fail "nginx: certificate generation failed"
fi

if cmp -s "$APP/nginx/insightshield.conf" /etc/nginx/sites-available/insightshield; then
  pass "nginx: site config already current"
else
  cp "$APP/nginx/insightshield.conf" /etc/nginx/sites-available/insightshield
  NGINX_CHANGED=1
  pass "nginx: site config installed"
fi
ln -sfn /etc/nginx/sites-available/insightshield /etc/nginx/sites-enabled/insightshield
# The stock default vhost is a catch-all on :80 and shadows the redirect.
[ -e /etc/nginx/sites-enabled/default ] && { rm -f /etc/nginx/sites-enabled/default; NGINX_CHANGED=1; }

nginx -t >/dev/null 2>&1 || die "nginx: config test failed — run 'nginx -t' for the reason"
if [ "$NGINX_CHANGED" = 1 ]; then
  systemctl reload nginx && pass "nginx: reloaded" || fail "nginx: reload failed"
else
  pass "nginx: unchanged, no reload needed"
fi

# gunicorn's access.log and error.log are the only logs on this host that
# nothing rotates — app.py rotates its own and the distro handles nginx's.
install -m 644 "$APP/logrotate/insightshield" /etc/logrotate.d/insightshield \
  && pass "logrotate: /etc/logrotate.d/insightshield installed" \
  || fail "logrotate: could not install /etc/logrotate.d/insightshield"

# ── 7. Wazuh rules and integrator (B2, B3) ───────────────────────────────────

if [ "$HAVE_WAZUH" = 1 ]; then
  # install(1) sets mode and ownership in the same call and is idempotent.
  install -o root -g wazuh -m 660 "$APP/wazuh_rules/custom_retail_rules.xml" \
    /var/ossec/etc/rules/ && pass "wazuh: custom_retail_rules.xml installed" \
    || fail "wazuh: could not install rules"

  install -o root -g wazuh -m 750 "$APP/wazuh_rules/custom-insightshield" \
    /var/ossec/integrations/ \
    && install -o root -g wazuh -m 750 "$APP/wazuh_rules/custom-insightshield.py" \
       /var/ossec/integrations/ \
    && pass "wazuh: integrator installed" \
    || fail "wazuh: could not install integrator"

  # ossec.conf is NOT well-formed XML — it holds several sibling <ossec_config>
  # blocks with no single root — so no XML parser can rewrite it safely, and
  # any that could would strip the comments from a production config. Wazuh
  # concatenates every top-level block, so appending one is the safe edit.
  if grep -q 'custom-insightshield' "$OSSEC_CONF"; then
    CURRENT_KEY="$(sed -n 's|.*<api_key>\(.*\)</api_key>.*|\1|p' "$OSSEC_CONF" | head -1)"
    KEY_COUNT="$(grep -c '<api_key>' "$OSSEC_CONF")"
    if [ "$CURRENT_KEY" = "$WEBHOOK_TOKEN" ]; then
      pass "wazuh: ossec.conf api_key matches .env"
    elif [ "$KEY_COUNT" -eq 1 ]; then
      sed -i "s|<api_key>.*</api_key>|<api_key>$WEBHOOK_TOKEN</api_key>|" "$OSSEC_CONF"
      WAZUH_CHANGED=1
      pass "wazuh: ossec.conf api_key re-synced with .env"
    else
      # Repairing by pattern would clobber a Slack/VirusTotal integration's key.
      fail "wazuh: api_key drifted from .env and $KEY_COUNT <api_key> blocks exist — fix ossec.conf by hand"
    fi
  else
    cp "$OSSEC_CONF" "$OSSEC_CONF.pre-insightshield.$(date +%s)"
    cat >> "$OSSEC_CONF" <<EOF

<!-- Insight Shield — added by scripts/install.sh. Delete this whole
     <ossec_config> block to remove the integration. -->
<ossec_config>
  <integration>
    <name>custom-insightshield</name>
    <hook_url>http://127.0.0.1:5000/wazuh-webhook</hook_url>
    <api_key>$WEBHOOK_TOKEN</api_key>
    <level>2</level>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
EOF
    WAZUH_CHANGED=1
    pass "wazuh: <integration> block appended to ossec.conf (backup taken)"
  fi

  # Validate before restarting, and let the result gate the restart — a rules
  # file that does not compile must never be allowed to take the manager down.
  #
  # wazuh-analysisd -t, not wazuh-logtest: logtest is a thread inside analysisd
  # reached over a socket, so it cannot answer this question at this point in
  # the sequence (the manager may be freshly installed and not yet started, and
  # it certainly is not restarted yet). analysisd -t validates standalone.
  RULESET_OK=0
  if [ ! -x /var/ossec/bin/wazuh-analysisd ]; then
    warn "wazuh: wazuh-analysisd not found — ruleset not validated, skipping restart"
  elif /var/ossec/bin/wazuh-analysisd -t >/dev/null 2>&1; then
    RULESET_OK=1
    pass "wazuh: ruleset compiles (wazuh-analysisd -t)"
  else
    fail "wazuh: ruleset failed to compile — manager NOT restarted, it keeps serving the previous ruleset"
    fail "      run '/var/ossec/bin/wazuh-analysisd -t' for the error"
  fi

  if [ "$WAZUH_CHANGED" = 0 ]; then
    pass "wazuh: no config change, manager left running"
  elif [ "$RULESET_OK" = 1 ]; then
    systemctl restart wazuh-manager && pass "wazuh: manager restarted" \
      || fail "wazuh: manager restart failed"
  fi
fi

# ── 8. Wazuh dashboard port (B1) ─────────────────────────────────────────────
# The dashboard and nginx both default to 443 on this host. Whichever starts
# second dies with "Port 443 is already in use". nginx keeps 443 because the
# app's CSP, HSTS and REPORT_ASSET_BASE_URL all assume the standard port.

if [ -f "$DASH_YML" ]; then
  if grep -q '^server.port: 8443' "$DASH_YML"; then
    pass "dashboard: already on 8443"
  elif grep -q '^server.port: 443' "$DASH_YML"; then
    sed -i 's/^server\.port: 443/server.port: 8443/' "$DASH_YML"
    DASH_CHANGED=1
    pass "dashboard: moved 443 -> 8443"
  else
    # Somebody (or a package upgrade) already set a third value. Reporting beats
    # forcing — it may be deliberate, and it is not colliding with us.
    warn "dashboard: server.port is neither 443 nor 8443 — left alone: $(grep '^server.port' "$DASH_YML")"
  fi
  if [ "$DASH_CHANGED" = 1 ]; then
    systemctl restart wazuh-dashboard && pass "dashboard: restarted on 8443" \
      || fail "dashboard: restart failed"
  fi
else
  [ "$HAVE_WAZUH" = 1 ] && warn "dashboard: $DASH_YML not found — is wazuh-dashboard installed?"
fi

# ── 9. systemd units ─────────────────────────────────────────────────────────
# Two units. insightshield.service serves HTTP on 3 gunicorn workers;
# insightshield-worker.service owns APScheduler and must be the only process
# running it, or the 02:00 backup takes N concurrent copies of the same live
# SQLite file. They are independent — neither After= nor PartOf= — so one
# crashing does not take the other with it.

cp "$APP/insightshield.service"        /etc/systemd/system/insightshield.service
cp "$APP/insightshield-worker.service" /etc/systemd/system/insightshield-worker.service
systemctl daemon-reload
systemctl enable insightshield insightshield-worker >/dev/null 2>&1
if systemctl restart insightshield; then
  pass "systemd: insightshield.service started"
else
  fail "systemd: start failed — run 'journalctl -u insightshield -n 50'"
fi
if systemctl restart insightshield-worker; then
  pass "systemd: insightshield-worker.service started"
else
  fail "systemd: worker start failed — run 'journalctl -u insightshield-worker -n 50'"
fi

# ── 10. Result ───────────────────────────────────────────────────────────────

echo "==============================="
if [ "$FAIL" -eq 0 ]; then
  echo -e "\e[32mInstall complete.\e[0m"
  echo "Next:  sudo $APP/scripts/healthcheck.sh"
  echo "Then:  sudo $APP/scripts/firewall.sh   # runbook §7 — separate on purpose,"
  echo "       so re-running this installer can never cut your session"
  [ "$HAVE_WAZUH" = 0 ] && echo "       (install Wazuh first, then re-run this script to wire it up)"
  exit 0
else
  echo -e "\e[31mOne or more steps failed — see the [FAIL] lines above.\e[0m"
  exit 1
fi
