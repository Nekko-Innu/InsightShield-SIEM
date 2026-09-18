#!/usr/bin/env bash
# Insight Shield — demo filter toggle.
# When ON, HIGH/CRITICAL alerts that aren't one of the five capstone-demo
# attacks are dropped at ingest (not stored, translated, or notified) so the
# dashboard shows only the demo attacks. Wazuh detection is untouched.
#
#   sudo scripts/demo_filter.sh on      # show only the 5 demo attacks
#   sudo scripts/demo_filter.sh off     # show everything again (default)
#   sudo scripts/demo_filter.sh status  # print current setting
#
# The five attacks live in config.DEMO_ATTACK_RULES. Run on the Ubuntu host.
set -euo pipefail

APP="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$APP/.env"

set_flag() {
  # Replace an existing DEMO_FILTER line, else append one.
  if grep -q '^DEMO_FILTER=' "$ENV_FILE" 2>/dev/null; then
    sed -i "s/^DEMO_FILTER=.*/DEMO_FILTER=$1/" "$ENV_FILE"
  else
    printf 'DEMO_FILTER=%s\n' "$1" >> "$ENV_FILE"
  fi
  systemctl restart insightshield insightshield-worker
  echo "DEMO_FILTER=$1 — services restarted."
}

case "${1:-status}" in
  on)     set_flag 1 ;;
  off)    set_flag 0 ;;
  status) grep '^DEMO_FILTER=' "$ENV_FILE" 2>/dev/null || echo "DEMO_FILTER= (unset — filter off)" ;;
  *)      echo "usage: $0 {on|off|status}" >&2; exit 2 ;;
esac
