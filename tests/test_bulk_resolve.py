"""scripts/bulk_resolve_alerts.py: the three ways the first draft corrupted data.

A UTC --until cut 8 hours early, a human's ack was overwritten, and a marker
string replaced the IT recommendation. Same throwaway-DB setup as
test_it_rec_burst.py.
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

os.environ.setdefault("FLASK_SECRET_KEY", "test-only-" + "0" * 32)
os.environ.setdefault("ENCRYPTION_KEY", "")
os.environ.setdefault("BOOTSTRAP_ADMIN_PASSWORD", "test-Admin!2026")
os.environ.setdefault("BOOTSTRAP_MANAGER_PASSWORD", "test-Manager!2026")

import config
import db

db.DB_PATH = os.path.join(tempfile.mkdtemp(prefix="is-bulk-test-"), "test.db")
db.init_db()
db.seed_users_from_config()

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "scripts"))
import bulk_resolve_alerts

STEPS = "INVESTIGATE: a. CHECK: b. MITIGATE: c."


def _alert(ts: datetime, recommendation=None) -> int:
    alert_id = db.store_alert({
        "timestamp": ts.isoformat(), "rule_id": "100014", "attack_type": "x",
        "severity": "HIGH", "device_name": "pos2", "raw_alert": "{}",
        "plain_text": "x", "ai_reasoning": "", "provider_used": "cache",
        "fk_grade": 6.0, "attack_trail": None,
    })
    if recommendation:
        db.update_it_recommendation(alert_id, recommendation)
    return alert_id


def test_bulk_resolve_keeps_real_data():
    base = datetime.now(tz=config.PHT).replace(hour=12, minute=0, second=0, microsecond=0)
    early = _alert(base, recommendation=STEPS)   # 12:00 PHT == 04:00 UTC
    acked = _alert(base)
    late = _alert(base + timedelta(hours=6))     # 18:00 PHT == 10:00 UTC
    db.acknowledge_alert(acked, "it2")
    human_ack = db.get_alert(acked)["acknowledged_at"]

    # 09:00 UTC is 17:00 PHT: must include the 12:00 rows and exclude 18:00.
    until = (base + timedelta(hours=5)).astimezone(timezone.utc)
    args = ["--by", "admin", "--note", "Test activity", "--until", until.isoformat()]

    assert bulk_resolve_alerts.main(args) == 0          # dry run
    assert db.get_alert(early)["resolved_at"] is None

    assert bulk_resolve_alerts.main(args + ["--yes"]) == 0
    e, a, l = db.get_alert(early), db.get_alert(acked), db.get_alert(late)
    assert e["resolved_by"] == "admin" and e["resolved_at"].endswith("+08:00")
    assert e["it_recommendation"] == STEPS
    assert e["response_time_s"] is None
    assert a["acknowledged_by"] == "it2" and a["acknowledged_at"] == human_ack
    assert l["resolved_at"] is None

    assert bulk_resolve_alerts.main(["--by", "manager", "--note", "x", "--yes"]) == 1
