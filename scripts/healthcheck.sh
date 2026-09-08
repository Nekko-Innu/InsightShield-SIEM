#!/usr/bin/env bash
# Insight Shield deployment smoke tests — run on VM-03 after install/upgrade.
#
#   sudo scripts/healthcheck.sh
#
# ROOT IS REQUIRED. Six checks read root-owned files (.env is chmod 600,
# /var/ossec/{etc,integrations,logs} are 750). Run unprivileged, they used to
# report the things they could not read as missing or broken.
#
# Three severities, matching install.sh:
#   [PASS]  verified working
#   [WARN]  could not be checked here — not applicable, or a tool is absent
#   [FAIL]  verified broken
#
# A [WARN] never means "broken". Only [FAIL] sets the exit code, because a
# healthcheck that cries wolf teaches the operator to skim past red lines.
#
# Exit codes: 0 = nothing failed, 1 = any failure.

set -u
FAIL=0
pass() { printf "\e[32m[PASS]\e[0m %s\n" "$1"; }
fail() { printf "\e[31m[FAIL]\e[0m %s\n" "$1"; FAIL=1; }
warn() { printf "\e[33m[WARN]\e[0m %s\n" "$1"; }
die()  { printf "\e[31m[FAIL]\e[0m %s\n" "$1"; exit 1; }

# $1 = binary, $2 = what is skipped without it. Returns non-zero to skip.
need_cmd() {
  command -v "$1" >/dev/null 2>&1 && return 0
  warn "$1 not installed — skipping $2"
  return 1
}

echo "=== Insight Shield health check ==="

[ "$(id -u)" = 0 ] || die "must run as root (sudo $0) — six checks read root-owned files"

# install.sh supports being run before Wazuh exists, so this script has to
# agree with it: no Wazuh is a legitimate mid-deploy state, not a failure.
HAVE_WAZUH=0
if [ -d /var/ossec ]; then
  HAVE_WAZUH=1
else
  warn "/var/ossec not found — Wazuh checks skipped. Install Wazuh, then re-run."
fi

# 1. systemd services up
if systemctl is-active --quiet insightshield; then
  pass "systemd: insightshield.service active"
else
  fail "systemd: insightshield.service NOT active (systemctl status insightshield)"
fi

if systemctl is-active --quiet insightshield-worker; then
  pass "systemd: insightshield-worker.service active"
else
  fail "systemd: insightshield-worker.service NOT active — no agent polling, no nightly backup, no escalation (systemctl status insightshield-worker)"
fi

# The freshness check that proves the worker is doing work, not merely running,
# is check 7a below — it needs $DB, which is defined there.

# 2. gunicorn bound to loopback:5000
# Wait for the bind first. insightshield.service is Type=simple, so systemd
# calls the unit active the moment gunicorn's master forks — one to two seconds
# before three workers (no preload_app, each one running create_app() and
# db.init_db()) actually listen on 5000. update.sh restarts the service and
# calls this script immediately, so without this loop every single update
# reported "not bound" + two 502s for an app that was merely still booting,
# and the operator went looking for a crash that never happened.
# A genuinely dead app still fails: this gives up after 10s and falls through
# to the same checks.
# command -v rather than need_cmd(): a missing curl already warns once below,
# and twice for the same fact reads like two problems.
if command -v curl >/dev/null 2>&1; then
  for _ in $(seq 1 20); do
    curl -fsS http://127.0.0.1:5000/health >/dev/null 2>&1 && break
    sleep 0.5
  done
fi

if need_cmd ss "the listening-socket checks"; then
  if ss -tlnp 2>/dev/null | grep -q '127.0.0.1:5000'; then
    pass "gunicorn: bound to 127.0.0.1:5000"
  else
    fail "gunicorn: not bound to 127.0.0.1:5000"
  fi
fi

if need_cmd curl "the HTTP endpoint checks"; then
  # 3. Direct gunicorn /health
  if curl -fsS http://127.0.0.1:5000/health | grep -q '"status": *"ok"'; then
    pass "gunicorn: /health returns ok"
  else
    fail "gunicorn: /health failed"
  fi

  # 4. nginx /health via HTTPS (self-signed, so -k)
  if curl -fkSs https://127.0.0.1:8444/health | grep -q '"status": *"ok"'; then
    pass "nginx: HTTPS /health returns ok"
  else
    fail "nginx: HTTPS /health failed"
  fi

  # 5. Login page renders
  if curl -fkSs https://127.0.0.1:8444/login | grep -q 'Insight Shield'; then
    pass "nginx: /login renders"
  else
    fail "nginx: /login does not render"
  fi
fi

# 6. Wazuh manager active
if [ "$HAVE_WAZUH" = 1 ]; then
  if systemctl is-active --quiet wazuh-manager; then
    pass "wazuh-manager: active"
  else
    fail "wazuh-manager: not active"
  fi
fi

# 7. SQLite database exists and is readable
# db.py resolves the filename against the process CWD, which the systemd unit
# sets to /opt/insightshield/insightshield — this used to check one directory
# too high and reported a missing database on a perfectly healthy install.
DB=/opt/insightshield/insightshield/insightshield.db
if need_cmd sqlite3 "the database checks"; then
  if [ -f "$DB" ] && sqlite3 "$DB" 'SELECT count(*) FROM alerts;' >/dev/null 2>&1; then
    COLS=$(sqlite3 "$DB" 'PRAGMA table_info(alerts);' | wc -l)
    # Insight Shield schema is 21 columns: 15 operational + 1 ai_reasoning + 3 IT-ACK
    # + 1 attack_trail + 4 resolved/_by/_at/resolve_note + 1 it_recommendation.
    if [ "$COLS" -eq 21 ]; then
      pass "sqlite: alerts table has 21 columns"
    else
      fail "sqlite: alerts table has $COLS columns (expected 21 — run db.init_db())"
    fi

    # 7a. The scheduler worker is alive AND ticking.
    # `systemctl is-active` says nothing about a scheduler that has wedged: the
    # process stays up, the jobs stop, and the login page keeps showing whatever
    # the last poll said. The agent-status snapshot is rewritten every 30s, so
    # its age is the honest signal. 90s is the same threshold
    # agent_status.STALE_AFTER_S uses to turn the login dot red.
    SNAP_TS=$(sqlite3 "$DB" "SELECT updated_at FROM settings WHERE key='agent_status.snapshot';" 2>/dev/null)
    if [ -z "$SNAP_TS" ]; then
      warn "worker: no agent-status snapshot yet — normal for ~30s after a restart"
    else
      SNAP_AGE=$(( $(date +%s) - $(date -d "$SNAP_TS" +%s 2>/dev/null || echo 0) ))
      if [ "$SNAP_AGE" -ge 0 ] && [ "$SNAP_AGE" -lt 90 ]; then
        pass "worker: agent-status snapshot is ${SNAP_AGE}s old"
      else
        fail "worker: agent-status snapshot is ${SNAP_AGE}s old (>90s) — scheduler wedged? 'journalctl -u insightshield-worker -n 50'"
      fi
    fi

    # Round 3: ai_providers table must exist (data-driven AI chain consumer)
    TABLE_PRESENT=$(sqlite3 "$DB" "SELECT name FROM sqlite_master WHERE type='table' AND name='ai_providers'")
    if [ "$TABLE_PRESENT" = "ai_providers" ]; then
      pass "sqlite: ai_providers table present"
    else
      fail "sqlite: ai_providers table missing — run db.init_db()"
    fi

    # Round 3: bootstrap_settings_from_env should have run on first boot
    BOOTSTRAP_DONE=$(sqlite3 "$DB" "SELECT value FROM settings WHERE key='bootstrap_complete'" 2>/dev/null)
    if [ "$BOOTSTRAP_DONE" = "1" ]; then
      pass "sqlite: bootstrap_complete=1 (settings + api_keys + ai_providers seeded)"
    else
      fail "sqlite: bootstrap_complete missing — first-boot import did not run"
    fi

    # AI-provider health tripwire. WARN-level on purpose: a real provider outage
    # should not hard-fail a deploy, but a pipeline that is silently 100% static
    # must be visible — that is exactly the state a prior status doc graded as
    # "production-ready / rate-limit mitigated" while AI was actually dead.
    ACTIVE=$(sqlite3 "$DB" "SELECT COUNT(*) FROM ai_providers WHERE is_active=1;" 2>/dev/null)
    if [ "${ACTIVE:-0}" -eq 0 ]; then
      warn "ai: no active AI providers — every alert uses the static template (configure one, then scripts/repair_providers.py)"
    else
      pass "ai: $ACTIVE active provider(s)"
      # Known-dead slugs — mirror config.KNOWN_BAD_AI_MODELS. These 400 and read
      # as an outage, so an active provider carrying one is the root-cause flag.
      BAD=$(sqlite3 "$DB" "SELECT label||' -> '||model FROM ai_providers WHERE is_active=1 AND model IN ('google/gemma-4-26b-a4b-it:free','openrouter/free');" 2>/dev/null)
      if [ -n "$BAD" ]; then
        warn "ai: active provider has a known-invalid model ($BAD) — run scripts/repair_providers.py"
      fi
      # Live-vs-static reality check: if every recent HIGH/CRITICAL alert used the
      # static template despite an active provider, the provider is failing.
      HC_TOTAL=$(sqlite3 "$DB" "SELECT COUNT(*) FROM (SELECT id FROM alerts WHERE severity IN ('HIGH','CRITICAL') ORDER BY id DESC LIMIT 50);" 2>/dev/null)
      HC_STATIC=$(sqlite3 "$DB" "SELECT COUNT(*) FROM (SELECT provider_used FROM alerts WHERE severity IN ('HIGH','CRITICAL') ORDER BY id DESC LIMIT 50) t WHERE t.provider_used='static';" 2>/dev/null)
      if [ "${HC_TOTAL:-0}" -gt 0 ] && [ "${HC_STATIC:-0}" -eq "${HC_TOTAL:-0}" ]; then
        warn "ai: all ${HC_TOTAL} recent HIGH/CRITICAL alerts fell to the static template despite an active provider — AI is failing (bad model or quota); check logs for 'FAILED [4'"
      else
        pass "ai: recent HIGH/CRITICAL alerts include live AI translations (${HC_STATIC:-0}/${HC_TOTAL:-0} static)"
      fi
    fi
  else
    fail "sqlite: $DB missing or corrupt"
  fi
fi

# 8. Log file writable
# Nothing has ever written app.log — gunicorn.conf.py writes access.log and
# error.log here, and the app's own rotating log is logs/insightshield.log
# relative to the working directory.
LOG=/var/log/insightshield/access.log
if [ -w "$LOG" ]; then
  pass "logs: $LOG writable"
else
  fail "logs: $LOG not writable (check ownership)"
fi

# 9. custom_retail_rules.xml installed in /var/ossec/etc/rules, and the ruleset
# compiles. -t exits 0 on a clean ruleset and non-zero on any syntax error or
# missing decoder.
#
# wazuh-analysisd -t, not wazuh-logtest. logtest is a thread INSIDE analysisd
# and reaches it over a socket, so it fails whenever the manager is stopped —
# reporting a parse error that does not exist. analysisd -t validates
# standalone. (Before that it was ossec-logtest, removed in Wazuh 4.1, which
# made this check fail on every 4.x install regardless of the ruleset.)
if [ "$HAVE_WAZUH" = 1 ]; then
  RULES=/var/ossec/etc/rules/custom_retail_rules.xml
  if [ ! -f "$RULES" ]; then
    fail "wazuh: $RULES missing — run scripts/install.sh"
  elif [ ! -x /var/ossec/bin/wazuh-analysisd ]; then
    warn "wazuh: wazuh-analysisd not found — ruleset not validated"
  elif /var/ossec/bin/wazuh-analysisd -t >/dev/null 2>&1; then
    pass "wazuh: ruleset compiles (wazuh-analysisd -t)"
  else
    fail "wazuh: ruleset failed to compile — run '/var/ossec/bin/wazuh-analysisd -t' for the error"
  fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# Checks 10-15 cover the four failures documented in docs/deployment-ubuntu.md
# §0. Each one is silent in normal operation — no alert arrives, or PDF export
# breaks — so without these a bad install looks healthy.
# ─────────────────────────────────────────────────────────────────────────────

# 10. nginx owns 8444 (Insight Shield). The Wazuh dashboard keeps its default
# 443 — the two no longer contend for a port. The process column of `ss -p` is
# only populated for sockets the caller owns, one of the reasons this script
# insists on root.
DASH_YML=/etc/wazuh-dashboard/opensearch_dashboards.yml
if need_cmd ss "the port 8444 ownership check"; then
  if ! ss -tlnp 2>/dev/null | grep ':8444 ' | grep -q nginx; then
    fail "port 8444: nginx is not listening — check 'systemctl status nginx'"
  else
    pass "port 8444: nginx owns it (Insight Shield); Wazuh dashboard is on 443"
  fi
fi

# 11. Integrator installed with the mode and owner wazuh-integratord requires.
# Wrong permissions mean the daemon silently skips the script.
if [ "$HAVE_WAZUH" = 1 ] && need_cmd stat "the integrator permission check"; then
  INTEG=/var/ossec/integrations/custom-insightshield
  if [ -f "$INTEG" ] && [ -f "$INTEG.py" ]; then
    MODES="$(stat -c '%a %U:%G' "$INTEG" "$INTEG.py" 2>/dev/null | sort -u)"
    if [ "$MODES" = "750 root:wazuh" ]; then
      pass "wazuh: integrator installed 750 root:wazuh"
    else
      fail "wazuh: integrator has wrong mode/owner ($MODES, expected 750 root:wazuh) — run scripts/install.sh"
    fi
  else
    fail "wazuh: integrator missing from /var/ossec/integrations — no alert can ever reach the app"
  fi
fi

# 12. The <integration> block exists, and integratord has actually run.
# The rules can be perfect and the app healthy while this is missing; the
# symptom is simply an empty dashboard forever.
if [ "$HAVE_WAZUH" = 1 ]; then
  if ! grep -q 'custom-insightshield' /var/ossec/etc/ossec.conf 2>/dev/null; then
    fail "wazuh: no <integration> block in ossec.conf — Wazuh will never push an alert"
  elif [ -f /var/ossec/logs/integrations.log ]; then
    pass "wazuh: <integration> configured and integrations.log exists"
  else
    fail "wazuh: <integration> configured but integrations.log absent — integratord has not run"
  fi
fi

# 13. Token parity. The app fails closed, so a drift between these two values
# turns every alert into a 403 with nothing on screen to say why.
# Neither value is printed.
ENV_FILE=/opt/insightshield/insightshield/.env
# tr -d '\r': a .env saved with Windows CRLF endings leaves a trailing carriage
# return on the value. The app's dotenv loader strips it, but a raw sed does
# not — so without this the token compare and the probe header carry a stray
# \r, the compare mismatches a clean ossec.conf value, and the probe 403s,
# reporting a drift that does not exist.
ENV_TOKEN="$(sed -n 's/^WAZUH_WEBHOOK_TOKEN=//p' "$ENV_FILE" 2>/dev/null | head -1 | tr -d '\r')"
if [ -z "$ENV_TOKEN" ]; then
  fail "token: WAZUH_WEBHOOK_TOKEN unset in $ENV_FILE — the webhook rejects everything"
elif [ "$HAVE_WAZUH" = 1 ]; then
  CONF_TOKEN="$(sed -n 's|.*<api_key>\(.*\)</api_key>.*|\1|p' /var/ossec/etc/ossec.conf 2>/dev/null | head -1 | tr -d '\r')"
  if [ "$ENV_TOKEN" = "$CONF_TOKEN" ]; then
    pass "token: ossec.conf <api_key> matches .env"
  else
    fail "token: ossec.conf <api_key> != .env WAZUH_WEBHOOK_TOKEN — every alert will 403"
  fi
fi

# 14. The gates actually accept that token, end to end.
# rule_level 1 clears validate_payload and is then dropped by process_alert, so
# this exercises the IP allowlist AND the token check without writing a row.
if [ -z "$ENV_TOKEN" ]; then
  warn "webhook: probe skipped — no token to present"
elif need_cmd curl "the live webhook probe"; then
  PROBE=$(curl -fsS -X POST http://127.0.0.1:5000/wazuh-webhook \
    -H 'Content-Type: application/json' \
    -H "X-Webhook-Token: $ENV_TOKEN" \
    -d '{"rule_id":"100001","rule_level":1,"device_name":"healthcheck"}' 2>/dev/null)
  if echo "$PROBE" | grep -q '"status": *"discarded"'; then
    pass "webhook: accepts the .env token (probe alert discarded as expected)"
  else
    fail "webhook: rejected the .env token — check the X-Webhook-Token gate and the IP allowlist"
  fi
fi

# 15. Playwright is reachable by the service, not just installed somewhere.
# ProtectHome=true hides ~/.cache from the unit, so a browser in the default
# location is invisible and /report.pdf fails at render time only.
if ! systemctl show insightshield -p Environment 2>/dev/null | grep -q PLAYWRIGHT_BROWSERS_PATH; then
  fail "playwright: PLAYWRIGHT_BROWSERS_PATH not in the unit — /report.pdf will fail under ProtectHome=true"
elif ! need_cmd find "the browser binary check"; then
  : # need_cmd already warned
elif find /opt/insightshield/ms-playwright \( -name 'headless_shell' -o -name 'chrome' \) 2>/dev/null | grep -q .; then
  pass "playwright: browser present where the unit can see it"
else
  fail "playwright: no browser under /opt/insightshield/ms-playwright — run scripts/install.sh"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Checks 16-20 cover the host-level configuration the app depends on but does
# not own: the firewall, the clock, and the address. Each is silent when wrong —
# agents simply stop reporting, or timestamps quietly disagree — and none of it
# is applied by install.sh. See docs/deployment-ubuntu.md §1.2 and §7.
# ─────────────────────────────────────────────────────────────────────────────

# Same derivation scripts/firewall.sh uses, so the two agree about what "the
# LAN" and "the dashboard port" mean without a shared config file.
IFACE="$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')"
LAN_CIDR="${LAN_CIDR:-$(ip -4 route show dev "${IFACE:-lo}" scope link 2>/dev/null | awk '{print $1; exit}')}"
DASH_PORT="$(sed -n 's/^server\.port: *//p' "$DASH_YML" 2>/dev/null | head -1)"
DASH_PORT="${DASH_PORT:-443}"

if need_cmd ufw "the firewall checks"; then
  UFW_STATUS="$(ufw status 2>/dev/null)"

  # 16. The firewall is actually on. Without it the Wazuh API and indexer are
  # reachable from every POS terminal on the LAN.
  if echo "$UFW_STATUS" | grep -q '^Status: active'; then
    pass "ufw: active"
  else
    fail "ufw: inactive — Wazuh API (55000) and indexer (9200) are exposed to the LAN (run scripts/firewall.sh, runbook §7)"
  fi

  # 17. Every port the deployment needs is actually open. A missing 1514/1515
  # rule does not break anything until an agent next reconnects, which can be
  # hours after the firewall change — conntrack keeps existing sessions alive.
  for entry in "80:nginx HTTP redirect" "8444:Insight Shield"; do
    port="${entry%%:*}"
    if echo "$UFW_STATUS" | grep -qE "^${port}/tcp .*ALLOW"; then
      pass "ufw: ${port}/tcp allowed (${entry#*:})"
    else
      fail "ufw: ${port}/tcp NOT allowed — ${entry#*:} is unreachable from the LAN (run scripts/firewall.sh)"
    fi
  done
  if [ "$HAVE_WAZUH" = 1 ]; then
    for entry in "1514:Wazuh agent events" "1515:Wazuh agent enrollment" "$DASH_PORT:Wazuh dashboard"; do
      port="${entry%%:*}"
      if echo "$UFW_STATUS" | grep -qE "^${port}/tcp .*ALLOW"; then
        pass "ufw: ${port}/tcp allowed (${entry#*:})"
      else
        fail "ufw: ${port}/tcp NOT allowed — ${entry#*:} is blocked (run scripts/firewall.sh)"
      fi
    done
  fi

  # 18. The two ports that must never face the LAN.
  #
  # Rule-based, not probe-based, and that is deliberate: a curl from this host
  # to https://192.168.1.159:55000 is routed over lo, and ufw's before.rules
  # accept everything on lo unconditionally. The probe would succeed even when
  # the firewall is correctly blocking every POS terminal — a check that always
  # passes. What actually decides the outcome is the default policy plus the
  # absence of an ALLOW, so that is what gets asserted.
  #
  # For a real external probe, run this from a POS PC:
  #     curl -m 3 -k https://192.168.1.159:55000     # must time out
  if ufw status verbose 2>/dev/null | grep -q 'deny (incoming)' \
     && ! echo "$UFW_STATUS" | grep -E '^(55000|9200)/tcp' | grep -q ALLOW; then
    pass "ufw: 55000/9200 not reachable from the LAN"
  else
    fail "ufw: Wazuh API/indexer exposed — default incoming policy is not deny, or an ALLOW rule exists"
  fi
fi

# 19. Clock. Alert correlation compares timestamps written by Windows agents,
# the manager and this host; scheduler.py's 02:00 backup and the midnight
# health-score reset fire against the system clock; and Wazuh's own TLS fails on
# a skewed clock with a "certificate not yet valid" error that reads nothing
# like "your clock is wrong".
if need_cmd timedatectl "the clock checks"; then
  # The kernel's synchronized bit, NOT a service name: chrony displaces
  # systemd-timesyncd on newer Ubuntu and either is a correct answer.
  if [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" = yes ]; then
    pass "time: system clock synchronized"
  else
    fail "time: clock NOT synchronized — agent correlation will drift (sudo timedatectl set-ntp true)"
  fi

  TZ_NOW="$(timedatectl show -p Timezone --value 2>/dev/null)"
  if [ "$TZ_NOW" = Asia/Manila ]; then
    pass "time: timezone Asia/Manila"
  else
    # A warning, not a failure: config.py pins ZoneInfo("Asia/Manila") for every
    # app timestamp regardless. The cost is legibility — the journal, ossec.log
    # and the Wazuh dashboard will not line up with the Insight Shield UI.
    warn "time: system timezone is $TZ_NOW — app timestamps stay Asia/Manila, but the journal and ossec.log will not match the dashboard"
  fi
fi

# 20. The address itself. web/blueprints/webhook.py's allowlist, nginx's server_name and
# the TLS certificate's SAN all hardcode 192.168.1.159 — so this check
# hardcodes it too, on purpose. Changing the address means changing all four
# (runbook §1.1).
if ip -4 addr show scope global 2>/dev/null | grep -q 'inet 192\.168\.1\.159/'; then
  pass "network: 192.168.1.159 configured"
else
  fail "network: 192.168.1.159 not on any interface — the webhook allowlist, nginx server_name and TLS SAN all assume it (runbook §1.1, §1.2)"
fi

if [ "$(getent hosts insightshield.local 2>/dev/null | awk '{print $1; exit}')" = 192.168.1.159 ]; then
  pass "network: insightshield.local resolves to 192.168.1.159"
else
  fail "network: insightshield.local does not resolve to 192.168.1.159 — add it to /etc/hosts (runbook §1.2.4)"
fi

echo "==============================="
if [ "$FAIL" -eq 0 ]; then
  echo -e "\e[32mAll checks passed.\e[0m"
  exit 0
else
  echo -e "\e[31mOne or more checks failed.\e[0m"
  exit 1
fi
