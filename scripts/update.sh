#!/usr/bin/env bash
# Insight Shield quick update — pull the latest code onto VM-03 and restart,
# without the full install.sh (no cert generation, no playwright, no seeding).
#
#   sudo /opt/insightshield/insightshield/scripts/update.sh
#
# ROOT IS REQUIRED: it redeploys the nginx site, touches ufw, and restarts
# systemd services. Safe to re-run — every step is conditional on an actual
# change, so a no-op run bounces nothing.
#
# This is the script to run for the 443 -> 8444 port move: it redeploys
# nginx/insightshield.conf (now listening on 8444), reloads nginx, reopens the
# firewall for 8444, and restarts the app. It never touches the Wazuh dashboard.

set -u

APP_ROOT=/opt/insightshield
APP="$(cd "$(dirname "$0")/.." && pwd)"
VENV="$APP_ROOT/venv"
SVC_USER=insightshield
NGINX_SITE=/etc/nginx/sites-available/insightshield

FAIL=0
pass() { printf "\e[32m[PASS]\e[0m %s\n" "$1"; }
fail() { printf "\e[31m[FAIL]\e[0m %s\n" "$1"; FAIL=1; }
warn() { printf "\e[33m[WARN]\e[0m %s\n" "$1"; }
die()  { printf "\e[31m[FAIL]\e[0m %s\n" "$1"; exit 1; }

echo "=== Insight Shield update ==="
[ "$(id -u)" = 0 ] || die "must run as root (sudo $0)"

# ── 1. Pull the new code ─────────────────────────────────────────────────────
# Only git-managed installs update in place here. A cp -r install (see
# install.sh header) has no upstream to pull from — re-copy the tree yourself,
# then run this script for the nginx/ufw/service half.
if [ -d "$APP/.git" ]; then
  BEFORE="$(git -C "$APP" rev-parse HEAD 2>/dev/null)"
  if runuser -u "$SVC_USER" -- git -C "$APP" pull --ff-only >/dev/null 2>&1 \
     || git -C "$APP" pull --ff-only >/dev/null 2>&1; then
    AFTER="$(git -C "$APP" rev-parse HEAD 2>/dev/null)"
    [ "$BEFORE" = "$AFTER" ] && pass "git: already up to date ($AFTER)" \
                             || pass "git: $BEFORE -> $AFTER"
  else
    die "git: pull --ff-only failed — resolve manually (local changes? diverged branch?)"
  fi
else
  warn "git: $APP is not a git checkout — re-copy the tree, then re-run for the deploy steps"
fi

# ── 2. Python deps (only if the lock moved) ──────────────────────────────────
if [ -x "$VENV/bin/pip" ]; then
  if runuser -u "$SVC_USER" -- "$VENV/bin/pip" install -q --require-hashes \
       -r "$APP/requirements.lock"; then
    pass "venv: requirements.lock satisfied"
  else
    fail "venv: pip install failed — do NOT bypass with requirements.txt (hash mismatch = lock vs index disagree)"
  fi
else
  warn "venv: $VENV/bin/pip not found — skipping dependency sync"
fi

# ── 3. Redeploy the nginx site (this is where 8444 lands) ────────────────────
if cmp -s "$APP/nginx/insightshield.conf" "$NGINX_SITE"; then
  pass "nginx: site already current"
else
  cp "$APP/nginx/insightshield.conf" "$NGINX_SITE"
  ln -sfn "$NGINX_SITE" /etc/nginx/sites-enabled/insightshield
  if nginx -t >/dev/null 2>&1; then
    systemctl reload nginx && pass "nginx: updated + reloaded (now on 8444)" \
      || fail "nginx: reload failed"
  else
    fail "nginx: config test failed — run 'nginx -t'; NOT reloading a broken config"
  fi
fi

# ── 4. Firewall — make sure 8444 is open ─────────────────────────────────────
# The port move is dead on arrival if ufw still only allows 443. firewall.sh is
# idempotent, so re-running it just adds the 8444 rule (and leaves the Wazuh
# dashboard's 443 rule in place).
if [ -x "$APP/scripts/firewall.sh" ]; then
  if "$APP/scripts/firewall.sh" >/dev/null 2>&1; then
    pass "firewall: rules re-applied (8444 open, dashboard 443 kept)"
  else
    warn "firewall: firewall.sh returned non-zero — run it directly to see why"
  fi
else
  warn "firewall: scripts/firewall.sh not executable — open 8444/tcp from the LAN manually"
fi

# ── 4b. One-shot data migrations ─────────────────────────────────────────────
# All are idempotent, so they run on every update and no-op once applied:
#   repair_providers  — fix any known-bad AI model slug, ensure Groq is primary
#                       (needs GROQ_API_KEY in .env to add Groq).
#   backfill_autoclose — close pre-existing MEDIUM/LOW/INFO alerts that predate
#                        the auto-close policy so they stop showing as "Open".
#   normalize_timestamps — rewrite alerts.timestamp to one timezone. The column
#                        held Wazuh's UTC and our PHT side by side, which sorted
#                        the table wrong and dropped rows out of every
#                        recent-window query.
#   relabel_alerts     — recompute attack_type with the label ingest uses now,
#                        replacing range-guessed labels ("[T/D] Ransomware" on
#                        every FIM change) and titles cut at 64 characters.
# Run as the service user with cwd=$APP so .env loads and the DB path resolves
# the same way the app does.
if [ -x "$VENV/bin/python" ]; then
  for m in repair_providers backfill_autoclose normalize_timestamps relabel_alerts; do
    if runuser -u "$SVC_USER" -- sh -c "cd '$APP' && '$VENV/bin/python' scripts/$m.py" >/dev/null 2>&1; then
      pass "migrate: $m applied"
    else
      warn "migrate: $m returned non-zero — run it directly to see why: sudo -u $SVC_USER $VENV/bin/python scripts/$m.py"
    fi
  done
else
  warn "migrate: $VENV/bin/python not found — skipping data migrations"
fi

# ── 5. Restart the app ───────────────────────────────────────────────────────
systemctl daemon-reload
for unit in insightshield insightshield-worker; do
  if systemctl restart "$unit"; then
    pass "systemd: $unit restarted"
  else
    fail "systemd: $unit restart failed — 'journalctl -u $unit -n 50'"
  fi
done

# ── 5b. Webhook token drift check ────────────────────────────────────────────
# update.sh does not touch ossec.conf (install.sh owns the <integration> block),
# but the token there and WAZUH_WEBHOOK_TOKEN in .env must match or every real
# Wazuh alert is rejected while a manual curl (which reads .env) still passes —
# the exact drift that silently stopped ingest in the field. Warn, don't fix:
# the fix is 'sudo scripts/install.sh', which re-syncs the key.
OSSEC_CONF=/var/ossec/etc/ossec.conf
if [ -r "$OSSEC_CONF" ] && [ -r "$APP/.env" ]; then
  CONF_TOK="$(grep -oP '(?<=<api_key>)[^<]+' "$OSSEC_CONF" 2>/dev/null | head -1)"
  ENV_TOK="$(grep -oP '(?<=^WAZUH_WEBHOOK_TOKEN=).*' "$APP/.env" 2>/dev/null | tr -d '\r')"
  if [ -n "$CONF_TOK" ] && [ "$CONF_TOK" = "$ENV_TOK" ]; then
    pass "webhook token in ossec.conf matches .env"
  else
    warn "webhook token MISMATCH (ossec.conf vs .env) — run 'sudo scripts/install.sh' to re-sync, or Wazuh alerts will be rejected"
  fi
fi

# ── 6. Verify ────────────────────────────────────────────────────────────────
if [ -x "$APP/scripts/healthcheck.sh" ]; then
  echo
  "$APP/scripts/healthcheck.sh" || FAIL=1
fi

echo
[ "$FAIL" = 0 ] && { pass "update complete"; exit 0; } \
                || { fail "update finished with failures — see above"; exit 1; }
