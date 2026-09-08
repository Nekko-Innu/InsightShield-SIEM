#!/usr/bin/env python3
# scripts/normalize_timestamps.py
# One-shot: rewrite alerts.timestamp so every row carries the same (PHT) offset.
#
#   cd /opt/insightshield/insightshield
#   sudo -u insightshield venv/bin/python scripts/normalize_timestamps.py
#
# Why: the column held two timezones. Wazuh's integrator passes its own UTC
# stamp through untouched, while wazuh_receiver stamped PHT whenever the payload
# had none:
#
#   12542  2026-09-08T06:45:42.483000+00:00   (Wazuh, UTC)
#   12538  2026-09-08T14:15:37.000287+08:00   (ours, PHT)
#
# timestamp is TEXT and every query compares it as text, so the PHT rows sorted
# above everything newer, and — worse — a UTC row read as "06:45" against a
# "14:30" PHT cutoff and fell out of every recent-window query: the severity
# chart's today, the report's date range, the IT-recommendation reuse window,
# the backfill sweep.
#
# db.store_alert normalises new rows at ingest. This fixes the ones already
# written. Idempotent: a row already at +08:00 is left alone, so re-running (as
# scripts/update.sh does on every deploy) is a no-op.

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
import db

BATCH = 500


def main() -> int:
    conn = db._get_conn()
    total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    # The offset PHT rows already end with. Anything else needs converting —
    # matched on the stored text rather than parsed, so the scan stays cheap.
    stale = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE timestamp NOT LIKE '%+08:00'"
    ).fetchone()[0]

    print("=== Alert timestamp normalisation ===")
    print(f"Rows: {total}   needing conversion: {stale}")
    if not stale:
        print("Nothing to do — every row is already PHT.")
        return 0

    rows = conn.execute(
        "SELECT id, timestamp FROM alerts WHERE timestamp NOT LIKE '%+08:00'"
    ).fetchall()

    changed = 0
    for i, row in enumerate(rows, 1):
        fixed = db.normalize_ts(row["timestamp"])
        if fixed != row["timestamp"]:
            conn.execute(
                "UPDATE alerts SET timestamp = ? WHERE id = ?", (fixed, row["id"])
            )
            changed += 1
        # Commit in batches: one transaction over 12k rows holds a write lock
        # long enough to collide with a live webhook insert.
        if i % BATCH == 0:
            conn.commit()
            print(f"  ... {i}/{len(rows)}")
    conn.commit()

    print(f"Converted {changed} row(s) to {config.PHT}.")
    sample = conn.execute(
        "SELECT id, timestamp FROM alerts ORDER BY id DESC LIMIT 3"
    ).fetchall()
    for s in sample:
        print(f"  #{s['id']}  {s['timestamp']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
