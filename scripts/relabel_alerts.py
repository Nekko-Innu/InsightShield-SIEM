#!/usr/bin/env python3
# scripts/relabel_alerts.py
# One-shot: recompute alerts.attack_type from each row's stored Wazuh payload.
#
#   cd /opt/insightshield/insightshield
#   sudo -u insightshield venv/bin/python scripts/relabel_alerts.py
#
# Why: old rows carry labels ingest no longer produces — range-guessed ones
# like "[T/D] Ransomware" on every FIM change, and stock Wazuh titles cut at
# 64 characters mid-word.
#
# The new label comes from wazuh_receiver.attack_label, the exact function
# ingest uses, run over the raw_alert payload ingest stored. Idempotent: a row
# already carrying that label is left alone, so re-running (as
# scripts/update.sh does on every deploy) is a no-op.

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import db
import wazuh_receiver

BATCH = 500


def main() -> int:
    conn = db._get_conn()
    rows = conn.execute(
        "SELECT id, rule_id, attack_type, raw_alert FROM alerts"
    ).fetchall()

    print("=== Alert attack_type relabel ===")
    print(f"Rows: {len(rows)}")

    changed = skipped = 0
    for i, row in enumerate(rows, 1):
        try:
            payload = json.loads(row["raw_alert"])
        except (TypeError, ValueError):
            payload = None
        # Wazuh rule ids only. Internal alerts (ISH-CBF-001, ISH-AZP-001 from
        # alert_router.dispatch_internal_alert) store a nested raw_alert with no
        # top-level description, so attack_label would turn
        # "credential_brute_force" into "Unknown".
        if not isinstance(payload, dict) or not str(row["rule_id"]).isdigit():
            skipped += 1
            continue
        new = wazuh_receiver.attack_label(str(row["rule_id"]), payload)
        if new != row["attack_type"]:
            conn.execute(
                "UPDATE alerts SET attack_type = ? WHERE id = ?", (new, row["id"])
            )
            changed += 1
        # Commit in batches: one transaction over 12k rows holds a write lock
        # long enough to collide with a live webhook insert.
        if i % BATCH == 0:
            conn.commit()
            print(f"  ... {i}/{len(rows)}")
    conn.commit()

    print(f"Relabelled {changed} row(s); {skipped} skipped (internal alert, or raw_alert not a JSON object).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
