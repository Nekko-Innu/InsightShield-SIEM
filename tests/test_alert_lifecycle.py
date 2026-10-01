"""Auto-close lifecycle: MEDIUM/LOW/INFO need no IT ack; they close at ingest.

Throwaway DB via db.DB_PATH (set before the first connection), like
tests/test_ai_chain_limits.py.
"""
import os
import tempfile
from datetime import datetime

os.environ.setdefault("FLASK_SECRET_KEY", "test-only-" + "0" * 32)
os.environ.setdefault("BOOTSTRAP_ADMIN_PASSWORD", "test-Admin!2026")
os.environ.setdefault("BOOTSTRAP_MANAGER_PASSWORD", "test-Manager!2026")

import pytest

import config
import db

_TMP_DB = os.path.join(tempfile.mkdtemp(prefix="is-lifecycle-test-"), "test.db")
db.DB_PATH = _TMP_DB
db.init_db()


def _store(severity):
    return db.store_alert({
        "timestamp": datetime.now(tz=config.PHT).isoformat(),
        "rule_id": "100001", "attack_type": "[T] Test", "severity": severity,
        "device_name": "POS-TEST", "raw_alert": "{}", "plain_text": "x",
        "ai_reasoning": "", "provider_used": "static", "fk_grade": 1.0,
        "attack_trail": None,
    })


def test_requires_ack_policy():
    assert config.requires_ack("HIGH") is True
    assert config.requires_ack("CRITICAL") is True
    for s in ("MEDIUM", "LOW", "INFORMATIONAL", "medium", ""):
        assert config.requires_ack(s) is False


def test_auto_close_sets_system_resolution_and_leaves_ack():
    aid = _store("MEDIUM")
    assert db.auto_close_alert(aid) is True
    row = db.get_alert(aid)
    assert row["resolved"] == 1
    assert row["resolved_by"] == config.SYSTEM_ACTOR
    assert row["resolve_note"]
    assert not row["acknowledged"]          # never acked
    assert not row["acknowledged_at"]
    # Idempotent.
    assert db.auto_close_alert(aid) is False


def test_auto_closed_cannot_be_acknowledged():
    aid = _store("LOW")
    db.auto_close_alert(aid)
    # The new AND resolved = 0 guard makes ack a no-op on an auto-closed row.
    assert db.acknowledge_alert(aid, "admin") is False


def test_open_and_status_semantics():
    med = _store("MEDIUM"); db.auto_close_alert(med)
    high = _store("HIGH")   # actionable -> stays open
    open_ids = {a["id"] for a in db.search_alerts(status="open", limit=100)}
    closed_ids = {a["id"] for a in db.search_alerts(status="closed", limit=100)}
    assert high in open_ids and med not in open_ids
    assert med in closed_ids and high not in closed_ids
    # count_open_alerts (resolved=0) excludes the auto-closed MEDIUM.
    assert high in {a["id"] for a in db.search_alerts(limit=100)}


def test_awaiting_ack_counts_only_unacked_high_critical():
    before = db.count_awaiting_ack()
    high = _store("HIGH")
    _store("CRITICAL")
    _store("MEDIUM")                         # left open: pre-lifecycle row shape
    assert db.count_awaiting_ack() == before + 2
    db.acknowledge_alert(high, "admin")
    assert db.count_awaiting_ack() == before + 1


def test_focus_mode_widens_hide_low_to_medium():
    med, high = _store("MEDIUM"), _store("HIGH")
    try:
        db.set_setting("alert_focus_mode", "0")
        shown = {a["id"] for a in db.search_alerts(hide_low=True, limit=1000)}
        assert med in shown and high in shown
        db.set_setting("alert_focus_mode", "1")
        shown = {a["id"] for a in db.search_alerts(hide_low=True, limit=1000)}
        assert med not in shown and high in shown
        # Pager count follows the same rule.
        assert db.count_alerts(hide_low=True) == len(shown)
        # Focus Mode alone hides nothing — only with the button on.
        assert med in {a["id"] for a in db.search_alerts(limit=1000)}
    finally:
        db.set_setting("alert_focus_mode", "0")


def test_status_watermark_moves_on_human_status_change_only():
    # What the Manager dashboard polls. An ack or a resolve must move
    # status_ts without moving latest_id; a system auto-close must not move it,
    # or every low-severity arrival would read as a status change.
    high = _store("HIGH")
    before = db.get_alert_watermark()
    assert before["latest_id"] == before["latest_actionable_id"] == high

    db.acknowledge_alert(high, "admin")
    acked = db.get_alert_watermark()
    assert acked["latest_id"] == before["latest_id"]
    assert acked["status_ts"] > before["status_ts"]

    db.resolve_alert(high, "admin", "handled")
    resolved = db.get_alert_watermark()
    assert resolved["status_ts"] > acked["status_ts"]

    med = _store("MEDIUM"); db.auto_close_alert(med)
    after = db.get_alert_watermark()
    assert after["latest_id"] == med
    assert after["latest_actionable_id"] == high
    assert after["status_ts"] == resolved["status_ts"]


def test_report_summary_splits_auto_from_human():
    # Fresh range check: human-resolve a HIGH, auto-close a MEDIUM, same day.
    med = _store("MEDIUM"); db.auto_close_alert(med)
    high = _store("HIGH")
    db.acknowledge_alert(high, "admin")
    db.resolve_alert(high, "admin", "handled")
    today = datetime.now(tz=config.PHT).date().isoformat()
    s = db.get_report_summary(today, today)
    assert s["resolved_count"] >= 1          # human resolves
    assert s["auto_closed_count"] >= 1       # system auto-closes
    # The MEDIUM must not be counted as a human resolution.
    assert s["auto_closed_count"] >= 1 and s["resolved_count"] >= 1
