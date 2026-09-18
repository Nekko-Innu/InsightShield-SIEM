"""Demo filter: when config.DEMO_FILTER is on, HIGH/CRITICAL alerts that aren't
one of the five demo attacks are dropped at ingest (return -1, never stored).
Lower severities and demo-attack rules pass through. Detection is upstream and
unaffected — this only decides what Insight Shield shows.

Pure-logic test — downstream store/translate/route are stubbed so nothing
touches a provider or the DB.
"""
import os

os.environ.setdefault("FLASK_SECRET_KEY", "test-only-" + "0" * 32)
os.environ.setdefault("BOOTSTRAP_ADMIN_PASSWORD", "test-Admin!2026")
os.environ.setdefault("BOOTSTRAP_MANAGER_PASSWORD", "test-Manager!2026")

import config
import db
import groq_translator
import alert_router
import wazuh_receiver


def _stub_pipeline(monkeypatch):
    """Make store/translate/route no-ops that record whether store ran."""
    called = {"stored": False}
    monkeypatch.setattr(groq_translator, "translate",
                        lambda *a, **k: ("text", "static", "reason"))
    def _store(_row):
        called["stored"] = True
        return 123
    monkeypatch.setattr(db, "store_alert", _store)
    monkeypatch.setattr(db, "auto_close_alert", lambda *_a: None)
    monkeypatch.setattr(db, "get_alert", lambda *_a: {})
    monkeypatch.setattr(alert_router, "route_alert", lambda *_a: None)
    return called


def _alert(rule_id, severity):
    return {"rule_id": rule_id, "severity": severity,
            "device_name": "POS2", "description": "x"}


def test_non_demo_high_dropped_when_on(monkeypatch):
    called = _stub_pipeline(monkeypatch)
    monkeypatch.setattr(config, "DEMO_FILTER", True)
    # 100002 (admin after hours) is HIGH-ish but not one of the five attacks.
    assert wazuh_receiver.process_alert(_alert("100002", "HIGH")) == -1
    assert called["stored"] is False  # never reached the store step


def test_demo_attack_passes_when_on(monkeypatch):
    called = _stub_pipeline(monkeypatch)
    monkeypatch.setattr(config, "DEMO_FILTER", True)
    # 100001 (brute force) is a demo attack — must not be filtered out.
    assert wazuh_receiver.process_alert(_alert("100001", "HIGH")) == 123
    assert called["stored"] is True


def test_sub_high_passes_when_on(monkeypatch):
    called = _stub_pipeline(monkeypatch)
    monkeypatch.setattr(config, "DEMO_FILTER", True)
    # Filter only gates HIGH/CRITICAL; a MEDIUM non-demo rule still flows.
    assert wazuh_receiver.process_alert(_alert("100002", "MEDIUM")) == 123
    assert called["stored"] is True


def test_nothing_filtered_when_off(monkeypatch):
    called = _stub_pipeline(monkeypatch)
    monkeypatch.setattr(config, "DEMO_FILTER", False)
    assert wazuh_receiver.process_alert(_alert("100002", "HIGH")) == 123
    assert called["stored"] is True


def test_all_five_attack_families_allowlisted():
    for rid in ("100001", "100047", "92900", "100099", "100010", "100020", "100040"):
        assert rid in config.DEMO_ATTACK_RULES
