#!/usr/bin/env bash
# Insight Shield — STRIDE label toggle.
# Attack labels read "<name> · <STRIDE category>" ("Port scan · Information
# disclosure"). OFF drops the " · <category>" suffix from new alerts and
# rewrites stored ones; ON puts it back. Reversible either way — the label is
# recomputed from each alert's stored payload by scripts/relabel_alerts.py.
#
#   sudo scripts/stride.sh off     # hide STRIDE categories
#   sudo scripts/stride.sh on      # show them again (default)
#   sudo scripts/stride.sh status  # print current setting
#
# Run on the Ubuntu host.
set -euo pipefail

APP="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$APP/.env"
VENV=/opt/insightshield/venv

set_flag() {
  # Replace an existing SHOW_STRIDE line, else append one.
  if grep -q '^SHOW_STRIDE=' "$ENV_FILE" 2>/dev/null; then
    sed -i "s/^SHOW_STRIDE=.*/SHOW_STRIDE=$1/" "$ENV_FILE"
  else
    printf 'SHOW_STRIDE=%s\n' "$1" >> "$ENV_FILE"
  fi
  systemctl restart insightshield insightshield-worker
  # cwd=$APP so .env loads the same way the app does (see update.sh).
  runuser -u insightshield -- sh -c "cd '$APP' && '$VENV/bin/python' scripts/relabel_alerts.py"
  echo "SHOW_STRIDE=$1 — services restarted, stored alerts relabelled."
}

case "${1:-status}" in
  on)     set_flag 1 ;;
  off)    set_flag 0 ;;
  status) grep '^SHOW_STRIDE=' "$ENV_FILE" 2>/dev/null || echo "SHOW_STRIDE= (unset — STRIDE shown)" ;;
  *)      echo "usage: $0 {on|off|status}" >&2; exit 2 ;;
esac
