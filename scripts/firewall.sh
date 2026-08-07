#!/usr/bin/env bash
# Insight Shield — host firewall. Run on the Ubuntu target as root.
#
#   sudo scripts/firewall.sh
#   LAN_CIDR=10.0.0.0/24 sudo -E scripts/firewall.sh    # multi-homed override
#
# Deliberately NOT part of install.sh. That script's contract is "idempotent,
# safe to re-run after every code update, never surprises you" — enabling a
# packet filter is a different class of action, and install.sh legitimately runs
# before Wazuh exists, when the ports that matter are not yet knowable.
#
# Lockout: port 22 is opened only when sshd is actually listening. Ubuntu
# Desktop ships without openssh-server, so on a stock box this adds nothing;
# where someone installed it, the failure mode is gone.
#
# Exit codes: 0 = firewall applied, 1 = something failed.
#
# See docs/deployment-ubuntu.md §7 for the policy and its rationale.

set -u

FAIL=0
pass() { printf "\e[32m[PASS]\e[0m %s\n" "$1"; }
fail() { printf "\e[31m[FAIL]\e[0m %s\n" "$1"; FAIL=1; }
warn() { printf "\e[33m[WARN]\e[0m %s\n" "$1"; }
die()  { printf "\e[31m[FAIL]\e[0m %s\n" "$1"; exit 1; }

echo "=== Insight Shield firewall ==="

# ── 1. Preflight ─────────────────────────────────────────────────────────────

[ "$(id -u)" = 0 ] || die "must run as root (sudo $0)"
command -v ufw >/dev/null || die "ufw not installed — apt install ufw (runbook §1.4)"

# Scope by subnet, not by interface: interface names are unstable across
# hypervisors, and the POS terminals are identified by network. Derived rather
# than hardcoded so this does not become a fourth copy of 192.168.100.30.
IFACE="$(ip -4 route show default | awk '{print $5; exit}')"
[ -n "$IFACE" ] || die "no default route — configure the network first (runbook §1.2)"
LAN_CIDR="${LAN_CIDR:-$(ip -4 route show dev "$IFACE" scope link | awk '{print $1; exit}')}"
[ -n "$LAN_CIDR" ] || die "could not derive the LAN subnet from $IFACE — set LAN_CIDR=x.x.x.x/nn"

HAVE_WAZUH=0
if [ -d /var/ossec ]; then
  HAVE_WAZUH=1
else
  warn "/var/ossec not found — skipping the Wazuh port rules. Install Wazuh, then re-run."
fi

# Read the dashboard's port back out of its own config rather than assuming
# 8443. install.sh §8 moves it off 443; reading it here means this script stays
# correct if the operator picked a third value, and dissolves the ordering
# hazard between the two scripts.
DASH_YML=/etc/wazuh-dashboard/opensearch_dashboards.yml
DASH_PORT="$(sed -n 's/^server\.port: *//p' "$DASH_YML" 2>/dev/null | head -1)"
DASH_PORT="${DASH_PORT:-8443}"
[ "$DASH_PORT" = 443 ] && die "wazuh-dashboard is still on 443 — it collides with nginx (runbook §0.1). Run scripts/install.sh first."

echo "    interface:      $IFACE"
echo "    LAN subnet:     $LAN_CIDR"
echo "    dashboard port: $DASH_PORT"
echo

# ── 2. Default policies ──────────────────────────────────────────────────────
# Egress stays open on purpose. The app needs 443 (Groq/Gemini/OpenRouter,
# Telegram, apt, PyPI, the Wazuh repos), 587 (Gmail SMTP), 53 and 123. An egress
# allowlist on a single lab host breaks apt and pip for no realistic gain, and
# would need re-editing every time a provider changes CDN.

ufw default deny incoming  >/dev/null 2>&1 && pass "policy: deny incoming"  || fail "policy: could not set deny incoming"
ufw default allow outgoing >/dev/null 2>&1 && pass "policy: allow outgoing" || fail "policy: could not set allow outgoing"

# ── 3. Denies ────────────────────────────────────────────────────────────────
# Added BEFORE the allows: ufw matches in order and the first match wins.
#
# Redundant against `default deny incoming` as things stand. They earn their
# lines as a tripwire — the day somebody adds a blanket `allow from <subnet>` to
# debug something, these still win — and they make `ufw status numbered`
# self-documenting about the two ports that must never be opened.
#
# The app reaches the Wazuh API over loopback (https://127.0.0.1:55000), and the
# dashboard reaches the indexer over loopback. Nothing on the LAN needs either.
ufw deny 55000/tcp >/dev/null 2>&1 && pass "deny: 55000/tcp (Wazuh API)"      || fail "deny: could not deny 55000/tcp"
ufw deny 9200/tcp  >/dev/null 2>&1 && pass "deny: 9200/tcp (Wazuh indexer)"   || fail "deny: could not deny 9200/tcp"

# ── 4. Allows ────────────────────────────────────────────────────────────────
# There is deliberately no rule for 5000. gunicorn binds 127.0.0.1:5000 and ufw
# does not filter loopback (before.rules accepts -i lo unconditionally), so a
# rule there would be theatre that reads as though it protects the webhook. The
# X-Webhook-Token gate in web/blueprints/webhook.py is what protects that
# endpoint.

allow_port() {  # $1 = port, $2 = what it is for
  if ufw allow from "$LAN_CIDR" to any port "$1" proto tcp >/dev/null 2>&1; then
    pass "allow: $1/tcp from $LAN_CIDR ($2)"
  else
    fail "allow: could not open $1/tcp ($2)"
  fi
}

allow_port 80  "nginx HTTP -> HTTPS redirect"
allow_port 443 "Insight Shield"

if [ "$HAVE_WAZUH" = 1 ]; then
  allow_port 1514 "Wazuh agent events"
  allow_port 1515 "Wazuh agent enrollment"
  allow_port "$DASH_PORT" "Wazuh dashboard"

  # Agents die silently on enrollment if the manager speaks UDP and only the TCP
  # rule exists. 4.x defaults to TCP, so this warns rather than guessing.
  if grep -A5 '<remote>' /var/ossec/etc/ossec.conf 2>/dev/null | grep -q '<protocol>udp</protocol>'; then
    warn "wazuh: manager <remote> is configured for UDP — add 'ufw allow from $LAN_CIDR to any port 1514 proto udp' or agents cannot connect"
  fi
fi

if ss -tln 2>/dev/null | grep -q ':22 '; then
  allow_port 22 "sshd is listening"
else
  pass "allow: no sshd listening — 22/tcp left closed"
fi

# ── 5. Enable ────────────────────────────────────────────────────────────────
# Rules added while ufw is inactive are stored and applied atomically on enable,
# so there is no window where the box is default-deny with nothing allowed.
# --force skips the "may disrupt existing ssh connections" prompt, which would
# otherwise hang a non-interactive run.

if ufw --force enable >/dev/null 2>&1; then
  pass "ufw: enabled"
else
  fail "ufw: could not enable"
fi

echo
ufw status verbose

# ── 6. Result ────────────────────────────────────────────────────────────────

echo "==============================="
if [ "$FAIL" -eq 0 ]; then
  echo -e "\e[32mFirewall applied.\e[0m"
  echo "Next:  sudo $(dirname "$0")/healthcheck.sh    # checks 16-20 verify this"
  echo "       From a POS PC, confirm https://<host>:55000 now times out."
  exit 0
else
  echo -e "\e[31mOne or more steps failed — see the [FAIL] lines above.\e[0m"
  exit 1
fi
