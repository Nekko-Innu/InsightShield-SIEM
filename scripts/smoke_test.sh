#!/usr/bin/env bash
# Insight Shield — End-to-end smoke test (master spec §9 sign-off gate).
#
# Walks the data-flow steps of the Round 9 verification checklist:
#   webhook  -> alert ingested into the DB
#   chain    -> manager translation populated
#   API      -> /api/severity-breakdown reflects the new alert
#   report   -> /report renders 200 for IT_ADMIN
#   RBAC     -> manager 302s away from /admin/settings, 403s on /api/agents
#
# Visual demo steps (SSE prepend, severity bar live update, status dot
# stays green, Telegram resolution notice) cannot be validated in pure
# shell — those are the manual sign-offs in the checklist.
#
# Usage: scripts/smoke_test.sh [BASE_URL]
#   BASE_URL defaults to https://127.0.0.1 (matches nginx self-signed setup).
# Exits 0 on full pass, 1 on first failure with a [FAIL] annotation.
#
# Environment:
#   SMOKE_WEBHOOK_TOKEN    must match WAZUH_WEBHOOK_TOKEN in the app's .env —
#                          /wazuh-webhook 403s every payload without it.
#   SMOKE_ADMIN_PASSWORD   post-rotation passwords. The seeded bootstrap values
#   SMOKE_MANAGER_PASSWORD are forced through /account/password on first login,
#                          so the defaults below only work on a virgin DB.

set -u

BASE="${1:-https://127.0.0.1:8444}"
WEBHOOK_TOKEN="${SMOKE_WEBHOOK_TOKEN:-}"
# No defaults: the bootstrap literals were removed from config.py, so there is
# nothing left to guess. Export the real values before running this.
ADMIN_PASSWORD="${SMOKE_ADMIN_PASSWORD:?set SMOKE_ADMIN_PASSWORD}"
MANAGER_PASSWORD="${SMOKE_MANAGER_PASSWORD:?set SMOKE_MANAGER_PASSWORD}"
COOKIES="$(mktemp)"
trap 'rm -f "$COOKIES"' EXIT

FAIL=0
pass() { printf "\e[32m[PASS]\e[0m %s\n" "$1"; }
fail() { printf "\e[31m[FAIL]\e[0m %s\n" "$1"; FAIL=1; }
warn() { printf "\e[33m[WARN]\e[0m %s\n" "$1"; }

# curl with -k (self-signed accepted), -s (silent), -S (errors), --cookie-jar
# for session persistence. We lock to a single jar across all requests so
# /login -> /report -> /api/* all share the same session cookie.
CURL="curl -kSs --cookie $COOKIES --cookie-jar $COOKIES"

echo "=== Insight Shield smoke test against $BASE ==="

# ── 1. Pre-flight: /health reachable ────────────────────────────────────────
if $CURL "$BASE/health" | grep -q '"status": *"ok"'; then
  pass "health endpoint reachable"
else
  fail "health endpoint unreachable — is gunicorn running and nginx forwarding?"
  exit 1
fi

# ── 2. Submit a synthetic Wazuh webhook ─────────────────────────────────────
# rule_level=12 maps to HIGH per wazuh_receiver.LEVEL_MAP. A unique device
# name + timestamp keeps re-runs idempotent (same alert, but new row).
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
DEVICE="POS-SMOKE-$(date +%s)"
PAYLOAD=$(cat <<EOF
{
  "rule_id": "100013",
  "rule_level": 13,
  "device_name": "$DEVICE",
  "description": "Smoke-test synthetic alert: privileged tool spawn",
  "timestamp": "$TS"
}
EOF
)

WEBHOOK_RESP=$($CURL -H "Content-Type: application/json" -H "X-Webhook-Token: $WEBHOOK_TOKEN" \
        -d "$PAYLOAD" "$BASE/wazuh-webhook")
ALERT_ID=$(echo "$WEBHOOK_RESP" | jq -r '.alert_id // empty' 2>/dev/null)
if [ -n "$ALERT_ID" ]; then
  pass "webhook accepted, alert_id=$ALERT_ID"
else
  fail "webhook rejected — set SMOKE_WEBHOOK_TOKEN to match WAZUH_WEBHOOK_TOKEN, or see /var/log/insightshield/app.log"
fi

# ── 3. Sign in as IT admin (session cookie persists in $COOKIES) ────────────
if $CURL -L -d "username=admin&password=$ADMIN_PASSWORD" \
        "$BASE/login" | grep -q "Insight Shield"; then
  pass "IT admin login succeeded"
else
  fail "IT admin login failed — set SMOKE_ADMIN_PASSWORD to the post-rotation password"
fi

# ── 3b. Did the HIGH alert get a LIVE AI translation, or silently fall to static?
# WARN-level: static is correct when no AI provider is configured, but a static
# HIGH/CRITICAL despite a configured provider is the "AI looks fine but isn't"
# failure a prior status doc graded as production-ready. provider_used comes
# from /api/alert/<id> (IT_ADMIN only — we're logged in as admin above).
if [ -n "${ALERT_ID:-}" ]; then
  PROV=$($CURL "$BASE/api/alert/$ALERT_ID" | jq -r '.provider_used // "?"' 2>/dev/null)
  if [ "$PROV" = "static" ]; then
    warn "chain: HIGH alert $ALERT_ID used the static template (provider_used=static) — fine if no AI provider is configured; if one is, AI is failing (run scripts/repair_providers.py; check logs for 'FAILED [4')"
  elif [ -n "$PROV" ] && [ "$PROV" != "?" ]; then
    pass "chain: HIGH alert $ALERT_ID got a live AI translation (provider_used=$PROV)"
  else
    fail "chain: could not read provider_used for alert $ALERT_ID"
  fi
fi

# ── 4. /api/severity-breakdown reflects the new alert (HIGH bucket >= 1) ───
SEV_JSON=$($CURL "$BASE/api/severity-breakdown?range=24h")
HIGH_COUNT=$(echo "$SEV_JSON" | jq -r '.[] | select(.key == "high") | .count' 2>/dev/null)
if [ -n "$HIGH_COUNT" ] && [ "$HIGH_COUNT" -ge 1 ]; then
  pass "/api/severity-breakdown high count = $HIGH_COUNT (>= 1)"
else
  fail "/api/severity-breakdown high count missing or zero (got: $HIGH_COUNT)"
fi

# ── 5. /report renders for IT admin ─────────────────────────────────────────
if $CURL "$BASE/report?from=$(date -d '7 days ago' +%Y-%m-%d)&to=$(date +%Y-%m-%d)" \
        | grep -q "Insight Shield &mdash; Security Audit Report"; then
  pass "/report renders H1 for IT admin"
else
  fail "/report did not render — check exec_summary chain availability"
fi

# ── 6. /admin/settings opens for IT admin ───────────────────────────────────
if $CURL "$BASE/admin/settings" | grep -q "Service Configuration"; then
  pass "/admin/settings renders for IT admin"
else
  fail "/admin/settings missing — Round 3 Settings page broken"
fi

# ── 7. Switch to manager session and re-test RBAC ───────────────────────────
# Drop the IT cookie and start fresh.
> "$COOKIES"

if $CURL -L -d "username=manager&password=$MANAGER_PASSWORD" \
        "$BASE/login" | grep -q "Insight Shield"; then
  pass "manager login succeeded"
else
  fail "manager login failed — set SMOKE_MANAGER_PASSWORD to the post-rotation password"
fi

# Manager hits /admin/settings -> 302 to /dashboard/manager
HTTP_CODE=$($CURL -o /dev/null -w "%{http_code}" "$BASE/admin/settings")
if [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "303" ]; then
  pass "manager /admin/settings -> $HTTP_CODE (redirect, RBAC intact)"
else
  fail "manager /admin/settings -> $HTTP_CODE (expected 302; Round 8 RBAC regression)"
fi

# Manager hits /api/agents -> 403 JSON
API_RESPONSE=$($CURL -w "%{http_code}" "$BASE/api/agents")
if echo "$API_RESPONSE" | grep -q '"error": *"forbidden"' \
        && echo "$API_RESPONSE" | grep -q '403$'; then
  pass "manager /api/agents -> 403 JSON forbidden"
else
  fail "manager /api/agents -> unexpected response (Round 8 RBAC regression)"
fi

# Manager CAN view /report
if $CURL "$BASE/report" | grep -q "Security Audit Report"; then
  pass "manager /report renders"
else
  fail "manager /report blocked — Round 7 manager-allowed regression"
fi

# ── 9. PDF export actually renders ──────────────────────────────────────────
# The only assertion that proves Playwright's Chromium is reachable from inside
# the systemd sandbox. ProtectHome=true hides the default ~/.cache install, so
# without PLAYWRIGHT_BROWSERS_PATH this is the step that fails — and it fails
# nowhere else, because every other page renders fine.
PDF_HEAD=$($CURL "$BASE/report.pdf?generated=1&from=$(date -d '7 days ago' +%Y-%m-%d)&to=$(date +%Y-%m-%d)" | head -c 4)
if [ "$PDF_HEAD" = "%PDF" ]; then
  pass "/report.pdf returns a real PDF (Playwright reachable under systemd)"
else
  fail "/report.pdf did not return a PDF — check PLAYWRIGHT_BROWSERS_PATH in the unit and Settings -> Errors"
fi

echo "=================================================="
if [ "$FAIL" -eq 0 ]; then
  echo -e "\e[32mAll smoke tests passed.\e[0m"
  exit 0
else
  echo -e "\e[31mOne or more checks failed — DO NOT hand off to operator.\e[0m"
  exit 1
fi
