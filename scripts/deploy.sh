#!/usr/bin/env bash
# scripts/deploy.sh — one-command Ubuntu deploy for the Wazuh host (VM-03).
#
# Replaces the hand-typed pull → deps → rules → restart → check sequence with a
# single categorised run. It is a thin orchestrator: the real work still lives in
# update.sh (app tier) and install.sh (rules + Wazuh integration), so this stays
# the one place that also VERIFIES the two things that silently broke in the
# field — the webhook token drifting between .env and ossec.conf, and the
# deployed ruleset not matching what the tests pin.
#
# Safe to re-run: every step underneath is idempotent.
#
#   sudo scripts/deploy.sh            # full deploy: app + rules + verify
#   sudo scripts/deploy.sh --verify   # verification only, changes nothing
#   sudo scripts/deploy.sh --app      # app tier only (update.sh), skip rules
#
set -u

APP="$(cd "$(dirname "$0")/.." && pwd)"
VENV=/opt/insightshield/venv
SVC_USER=insightshield
OSSEC_CONF=/var/ossec/etc/ossec.conf
DEPLOYED_RULES=/var/ossec/etc/rules/custom_retail_rules.xml
ENV_FILE="$APP/.env"
FAIL=0

c_pass=$'\e[32m'; c_fail=$'\e[31m'; c_warn=$'\e[33m'; c_head=$'\e[36m'; c_off=$'\e[0m'
pass() { printf "  ${c_pass}[PASS]${c_off} %s\n" "$1"; }
fail() { printf "  ${c_fail}[FAIL]${c_off} %s\n" "$1"; FAIL=1; }
warn() { printf "  ${c_warn}[WARN]${c_off} %s\n" "$1"; }
section() { printf "\n${c_head}== %s ==${c_off}\n" "$1"; }
die()  { printf "${c_fail}[FAIL]${c_off} %s\n" "$1"; exit 1; }

[ "$(id -u)" = 0 ] || die "must run as root (sudo $0)"

MODE=full
case "${1:-}" in
  --verify) MODE=verify ;;
  --app)    MODE=app ;;
  "")       MODE=full ;;
  *)        die "unknown option '$1' (use --verify or --app)" ;;
esac

# ── CATEGORY 1: preflight ────────────────────────────────────────────────────
section "1. Preflight"
if [ -d "$APP/.git" ]; then
  pass "git checkout present at $APP"
else
  warn "no .git at $APP — update.sh will skip the pull (re-copy the tree to deploy new code)"
fi
[ -x "$VENV/bin/python" ] && pass "venv interpreter found" \
                          || warn "venv missing at $VENV — app steps will warn"

# ── CATEGORY 2: application tier ─────────────────────────────────────────────
if [ "$MODE" != verify ]; then
  section "2. Application tier (scripts/update.sh)"
  if [ -x "$APP/scripts/update.sh" ]; then
    "$APP/scripts/update.sh" || FAIL=1
  else
    fail "scripts/update.sh not executable"
  fi
fi

# ── CATEGORY 3: rules + Wazuh integration ────────────────────────────────────
if [ "$MODE" = full ]; then
  section "3. Rules + Wazuh integration (scripts/install.sh)"
  # install.sh is the only script that installs the ruleset and restarts
  # wazuh-manager; run it after update.sh so the app is already current.
  if [ -x "$APP/scripts/install.sh" ]; then
    "$APP/scripts/install.sh" || FAIL=1
  else
    fail "scripts/install.sh not executable"
  fi
fi

# ── CATEGORY 4: verification (always) ────────────────────────────────────────
section "4. Verification"

# 4a. Ruleset compiles.
if [ -x /var/ossec/bin/wazuh-analysisd ]; then
  if /var/ossec/bin/wazuh-analysisd -t >/dev/null 2>&1; then
    pass "ruleset compiles (wazuh-analysisd -t)"
  else
    fail "ruleset does NOT compile — run '/var/ossec/bin/wazuh-analysisd -t'"
  fi
else
  warn "wazuh-analysisd not found — cannot validate ruleset"
fi

# 4b. Deployed rules == repo rules (install.sh should have made them identical).
if [ -r "$DEPLOYED_RULES" ] && [ -r "$APP/wazuh_rules/custom_retail_rules.xml" ]; then
  if cmp -s "$APP/wazuh_rules/custom_retail_rules.xml" "$DEPLOYED_RULES"; then
    pass "deployed ruleset matches repo"
  else
    fail "deployed ruleset differs from repo — run 'sudo scripts/install.sh'"
  fi
fi

# 4c. Rule count matches what the tests pin (guards a half-applied deploy).
if [ -r "$DEPLOYED_RULES" ]; then
  # grep -c prints 0 AND exits 1 on no match; "|| echo 0" made that "0\n0".
  n="$(grep -c '<rule ' "$DEPLOYED_RULES" 2>/dev/null || true)"
  want="$(grep -oE 'len\(_rules\(\)\) == [0-9]+' "$APP/tests/test_mitm_rules.py" 2>/dev/null | grep -oE '[0-9]+$')"
  if [ -n "$want" ] && [ "$n" = "$want" ]; then
    pass "rule count = $n (matches test_rule_count)"
  elif [ -n "$want" ]; then
    fail "rule count = $n but test pins $want — deploy is out of step with the repo"
  else
    warn "rule count = $n (could not read the test's expected value)"
  fi
fi

# 4d. Webhook token in ossec.conf matches .env. This is the drift that silently
#     404s/401s every real alert while a manual curl (which reads .env) passes.
if [ -r "$OSSEC_CONF" ] && [ -r "$ENV_FILE" ]; then
  conf_tok="$(grep -oP '(?<=<api_key>)[^<]+' "$OSSEC_CONF" 2>/dev/null | head -1)"
  env_tok="$(grep -oP '(?<=^WAZUH_WEBHOOK_TOKEN=).*' "$ENV_FILE" 2>/dev/null | tr -d '\r')"
  if [ -n "$conf_tok" ] && [ "$conf_tok" = "$env_tok" ]; then
    pass "webhook token in ossec.conf matches .env"
  else
    fail "webhook token MISMATCH: ossec.conf vs .env — run 'sudo scripts/install.sh' to re-sync"
  fi
else
  warn "cannot read ossec.conf or .env to compare the webhook token"
fi

# 4e. Services active.
for unit in insightshield insightshield-worker wazuh-manager nginx; do
  if systemctl is-active --quiet "$unit"; then
    pass "service active: $unit"
  else
    fail "service NOT active: $unit — 'journalctl -u $unit -n 50'"
  fi
done

# 4f. Live webhook round-trip through gunicorn with the .env token. Level 1 is
#     below the storage floor: the request passes the allowlist, the token gate
#     and validation, then process_alert discards it — nothing stored, nothing
#     paged. The probe used to send a level-12 100001, which stored a HIGH
#     "brute force" row (and a notification) on every deploy.
if [ -r "$ENV_FILE" ]; then
  tok="$(grep -oP '(?<=^WAZUH_WEBHOOK_TOKEN=).*' "$ENV_FILE" 2>/dev/null | tr -d '\r')"
  body="$(curl -sS -m 5 -w '\n%{http_code}' -X POST \
            http://127.0.0.1:5000/wazuh-webhook \
            -H 'Content-Type: application/json' \
            -H "X-Webhook-Token: $tok" \
            -d '{"rule_id":"0","rule_level":1,"device_name":"DEPLOY-SELFTEST","description":"deploy.sh verification"}' 2>/dev/null)"
  code="${body##*$'\n'}"
  if [ "$code" = 200 ] && printf '%s' "$body" | grep -q '"discarded"'; then
    pass "live webhook accepted the .env token (level-1 probe discarded, nothing stored)"
  elif [ "$code" = 403 ]; then
    fail "live webhook returned 403 — .env token rejected; restart insightshield after editing .env"
  else
    fail "live webhook returned HTTP ${code:-none} (expected 200 discarded) — 'journalctl -u insightshield -n 50'"
  fi
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo
if [ "$FAIL" = 0 ]; then
  pass "deploy verification clean"; exit 0
else
  fail "deploy finished with failures — see above"; exit 1
fi
