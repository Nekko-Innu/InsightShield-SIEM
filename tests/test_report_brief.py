"""The management form of the Security Audit Report.

Two things are asserted: it reports the same event counts as the technical
form for the same period, and nothing on the exclusion list reaches the page.

Throwaway DB via db.DB_PATH, like tests/test_alert_lifecycle.py. Every row is
stamped on one day in 2019 so the counts hold whichever test DB is live.
"""
import json
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("FLASK_SECRET_KEY", "test-only-" + "0" * 32)
os.environ.setdefault("BOOTSTRAP_ADMIN_PASSWORD", "test-Admin!2026")
os.environ.setdefault("BOOTSTRAP_MANAGER_PASSWORD", "test-Manager!2026")

import pytest
from flask import Flask, render_template

import config
import db

_TMP_DB = os.path.join(tempfile.mkdtemp(prefix="is-brief-test-"), "test.db")
db.DB_PATH = _TMP_DB
db.init_db()

import web.filters
from web.blueprints import reports

DAY = "2019-03-10"
PLAIN = ("WHAT HAPPENED: Someone tried to read saved passwords on this till.\n"
         "HOW SERIOUS: Staff sign-in details may have been stolen.\n"
         "WHAT TO DO: Tell IT now. Do not use this till until IT says so.")
# The things the management form must never show.
ADDRESS, TECHNIQUE, RULE_ID = "10.9.8.7", "T1003", "100099"


def _store(severity, plain_text=PLAIN, minute=0):
    return db.store_alert({
        "timestamp": f"{DAY}T09:{minute:02d}:00+08:00",
        "rule_id": RULE_ID, "attack_type": "LSASS memory access", "severity": severity,
        "device_name": "POS-TEST",
        "raw_alert": json.dumps({"data": {"srcip": ADDRESS}, "rule": {"id": RULE_ID}}),
        "plain_text": plain_text, "ai_reasoning": "", "provider_used": "static",
        "fk_grade": 1.0,
        "attack_trail": json.dumps({"agent": {"ip": ADDRESS},
                                    "mitre": {"id": TECHNIQUE},
                                    "data": {"win.eventdata.sourceImage": "C:\\procdump.exe"}}),
    })


def _seed():
    _store("CRITICAL", minute=1)                                  # open, unanswered
    handled = _store("HIGH", minute=2)
    db.acknowledge_alert(handled, "admin")
    db.resolve_alert(handled, "admin", f"Blocked {ADDRESS} per rule {RULE_ID} ({TECHNIQUE})")
    db.auto_close_alert(_store("MEDIUM", minute=3))
    # A stored explanation that never passed the validator.
    _store("HIGH", plain_text="WHAT HAPPENED: SSH login from " + ADDRESS, minute=4)


@pytest.fixture(scope="module", autouse=True)
def _seeded():
    # At run time, not import time: every DB-backed module sets db.DB_PATH on
    # import, so in a full run the live DB is whichever module was collected
    # last, not the one this file created.
    if not db.get_alerts_by_date_range(DAY, DAY):
        _seed()


AGENTS = [{"name": "POS-1", "status": "Active"}, {"name": "POS-2", "status": "disconnected"}]


def _render(brief):
    app = Flask(__name__, template_folder=str(Path(reports.__file__).parents[2] / "templates"))
    web.filters.init_app(app)
    with app.app_context():
        return render_template(
            "_report_brief.html", brief=brief, date_from=DAY, date_to=DAY,
            generated_at=f"{DAY}T12:00:00+08:00", user=SimpleNamespace(username="manager", role="MANAGER"),
            report_form="management",
        )


def test_both_forms_report_the_same_event_counts():
    brief = reports._brief_context(DAY, DAY, AGENTS)
    technical = db.get_report_summary(DAY, DAY)
    assert brief["total"] == technical["total"] == 4
    assert brief["needed_action"] == technical["severity"]["HIGH"] + technical["severity"]["CRITICAL"]
    assert brief["closed"] == technical["resolved_count"] + technical["auto_closed_count"]


def test_status_and_coverage():
    brief = reports._brief_context(DAY, DAY, AGENTS)
    # An unanswered serious alert outranks whatever the score says.
    assert brief["status"] == "Action required"
    assert brief["attention"][0]["state"] == "waiting for IT"
    # "Active" counts as online — the case-sensitive compare is the old bug.
    assert (brief["agents_online"], brief["agents_offline"]) == (1, ["POS-2"])


def test_management_form_carries_nothing_from_the_exclusion_list():
    html = _render(reports._brief_context(DAY, DAY, AGENTS))
    assert "Someone tried to read saved passwords" in html     # the validated text is used
    for banned in (ADDRESS, TECHNIQUE, RULE_ID, "procdump", "LSASS", "CRITICAL", "HIGH", "MEDIUM"):
        assert banned not in html, banned
    for word in config.FORBIDDEN_WORDS:
        assert word.lower() not in html.lower(), word
