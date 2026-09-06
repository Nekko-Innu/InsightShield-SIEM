#!/usr/bin/env python3
# scripts/backfill_autoclose.py
# One-shot: auto-close existing sub-HIGH alerts that predate the auto-close
# policy. New alerts are auto-closed at ingest (wazuh_receiver.process_alert),
# but rows already in the table stay "Open / Pending" until this runs.
#
#   cd /opt/insightshield/insightshield
#   sudo -u insightshield venv/bin/python scripts/backfill_autoclose.py
#
# Idempotent: only touches unresolved MEDIUM/LOW/INFORMATIONAL rows, closes them
# as config.SYSTEM_ACTOR with the standard note. Safe to re-run. Never touches
# HIGH/CRITICAL or anything already resolved.

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
import db


def main() -> int:
    # Severities below HIGH — the complement of config.ACTIONABLE_SEVERITIES.
    non_actionable = sorted(set(config.SEVERITY_LEVELS) - config.ACTIONABLE_SEVERITIES)
    placeholders = ",".join("?" for _ in non_actionable)

    conn = db._get_conn()
    before = conn.execute(
        f"SELECT COUNT(*) FROM alerts WHERE (resolved = 0 OR resolved IS NULL) "
        f"AND severity IN ({placeholders})",
        tuple(non_actionable),
    ).fetchone()[0]

    print(f"=== Auto-close backfill ===")
    print(f"Non-actionable severities: {', '.join(non_actionable)}")
    print(f"Unresolved rows to close: {before}")
    if not before:
        print("Nothing to do.")
        return 0

    rows = conn.execute(
        f"SELECT id FROM alerts WHERE (resolved = 0 OR resolved IS NULL) "
        f"AND severity IN ({placeholders})",
        tuple(non_actionable),
    ).fetchall()
    closed = 0
    for r in rows:
        if db.auto_close_alert(r["id"]):
            closed += 1
    print(f"Closed {closed} alert(s) as '{config.SYSTEM_ACTOR}'.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
