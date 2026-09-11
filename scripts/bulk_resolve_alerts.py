#!/usr/bin/env python3
# scripts/bulk_resolve_alerts.py
# One-shot: close open HIGH/CRITICAL alerts left over from test activity, as a
# named IT admin with a note and one audit-log row. Dry run unless --yes.
#
#   cd /opt/insightshield/insightshield
#   sudo -u insightshield /opt/insightshield/venv/bin/python scripts/bulk_resolve_alerts.py \
#       --by admin --note "Test activity: ..." [--since ISO] [--until ISO] \
#       [--rules 92900,100014] [--yes]
#
# What it deliberately leaves alone:
#   it_recommendation — resolving is what takes a row out of the IT-rec backfill
#       (db.get_alerts_missing_it_recommendation keys on resolved_at IS NULL). A
#       marker string here would overwrite real steps, render as the recommendation
#       on the alert page, and be copied onto new alerts by sibling reuse.
#   response_time_s — stays NULL so these closures never enter MTTA.
#   An existing human ack — COALESCE keeps its real name and time.
#
# Not modelled on backfill_autoclose: that closes as config.SYSTEM_ACTOR, which
# the UI and report read as "Auto-closed" sub-HIGH alerts. These are HIGH alerts
# a person decided to close, so they carry that person's name.

import argparse
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
import db


def _pht(s: str) -> str:
    # alerts.timestamp is +08:00 text compared as text, so a UTC bound passed
    # through unchanged would cut 8 hours early. Naive input is read as PHT.
    d = datetime.fromisoformat(s)
    if d.tzinfo is None:
        d = d.replace(tzinfo=config.PHT)
    return d.astimezone(config.PHT).isoformat()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--by", required=True, help="IT_ADMIN username to attribute the closure to")
    ap.add_argument("--note", required=True, help="resolve_note stored on each alert")
    ap.add_argument("--since", type=_pht, help="only alerts with timestamp >= this ISO time")
    ap.add_argument("--until", type=_pht, help="only alerts with timestamp <= this ISO time")
    ap.add_argument("--rules", help="comma-separated rule_ids (default: all)")
    ap.add_argument("--yes", action="store_true", help="write changes (default: dry run)")
    a = ap.parse_args(argv)

    conn = db._get_conn()
    user = conn.execute("SELECT role FROM users WHERE username = ?", (a.by,)).fetchone()
    if not user or (user["role"] or "").upper() != "IT_ADMIN":
        print(f"'{a.by}' is not an IT_ADMIN user.")
        return 1

    where = ["resolved_at IS NULL", "severity IN ('HIGH', 'CRITICAL')"]
    params = []
    if a.since:
        where.append("timestamp >= ?")
        params.append(a.since)
    if a.until:
        where.append("timestamp <= ?")
        params.append(a.until)
    if a.rules:
        ids = [r.strip() for r in a.rules.split(",") if r.strip()]
        where.append(f"rule_id IN ({','.join('?' * len(ids))})")
        params += ids
    w = " AND ".join(where)

    rows = conn.execute(
        f"SELECT rule_id, COUNT(*) FROM alerts WHERE {w} GROUP BY rule_id ORDER BY 2 DESC",
        params,
    ).fetchall()
    total = sum(r[1] for r in rows)
    print("=== Bulk resolve ===")
    for r in rows:
        print(f"  {r[0]:>8}  {r[1]:>4}")
    print(f"Matching: {total}  (since={a.since} until={a.until} rules={a.rules})")
    if not total:
        print("Nothing to do.")
        return 0
    if not a.yes:
        print("Dry run. Add --yes to apply.")
        return 0

    now = datetime.now(tz=config.PHT).isoformat()
    cur = db._execute_with_retry(
        f"""UPDATE alerts SET
                acknowledged    = 1,
                acknowledged_by = COALESCE(acknowledged_by, ?),
                acknowledged_at = COALESCE(acknowledged_at, ?),
                resolved        = 1,
                resolved_by     = ?,
                resolved_at     = ?,
                resolve_note    = ?
            WHERE {w}""",
        (a.by, now, a.by, now, a.note, *params),
    )
    conn.commit()
    db.log_audit(
        action="ALERT_BULK_RESOLVED", actor=a.by, actor_role="IT_ADMIN",
        target="alerts", ip="127.0.0.1",
        details={"count": cur.rowcount, "note": a.note[:200],
                 "since": a.since, "until": a.until, "rules": a.rules},
    )
    left = db.get_alerts_missing_it_recommendation(max_age_hours=24, limit=1000)
    print(f"Resolved {cur.rowcount} alert(s) as '{a.by}'.")
    print(f"Still in IT-rec backfill queue: {len(left)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
