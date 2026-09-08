"""Burst handling for IT investigation steps: sibling reuse + backfill.

Ten identical criticals used to run ten provider chains through a semaphore of
one, and everything past the third was left permanently blank. These tests pin
the two mechanisms that replaced that: reuse a recent sibling's steps instead of
buying them again, and sweep up whatever still ended up blank.

Pure-logic, no network — the same throwaway-DB setup as test_ai_chain_limits.py.
"""
import os
import tempfile
from datetime import datetime, timedelta

os.environ.setdefault("FLASK_SECRET_KEY", "test-only-" + "0" * 32)
os.environ.setdefault("ENCRYPTION_KEY", "")
os.environ.setdefault("BOOTSTRAP_ADMIN_PASSWORD", "test-Admin!2026")
os.environ.setdefault("BOOTSTRAP_MANAGER_PASSWORD", "test-Manager!2026")

import pytest

import config
import db

_TMP_DB = os.path.join(tempfile.mkdtemp(prefix="is-itrec-test-"), "test.db")
db.DB_PATH = _TMP_DB
db.init_db()

import wazuh_receiver

STEPS = "INVESTIGATE: check the FIM log. CHECK: run wazuh-logtest. MITIGATE: isolate the host."


def _alert(rule_id="100020", device="wazuh-system", severity="CRITICAL",
           minutes_ago=0, recommendation=None) -> int:
    ts = (datetime.now(tz=config.PHT) - timedelta(minutes=minutes_ago)).isoformat()
    alert_id = db.store_alert({
        "timestamp": ts, "rule_id": rule_id, "attack_type": "[T/D] Ransomware",
        "severity": severity, "device_name": device,
        "raw_alert": '{"rule": {"id": "%s"}, "agent": {"name": "%s"}}' % (rule_id, device),
        "plain_text": "Ransomware detected.", "ai_reasoning": "", "provider_used": "cache",
        "fk_grade": 6.0, "attack_trail": None,
    })
    if recommendation is not None:
        db.update_it_recommendation(alert_id, recommendation)
    return alert_id


@pytest.fixture(autouse=True)
def _clean_alerts():
    db._get_conn().execute("DELETE FROM alerts")
    db._get_conn().commit()
    yield


def test_reuse_copies_a_recent_sibling_and_spends_no_call(monkeypatch):
    """The burst case: same rule, same device, minutes apart."""
    import it_recommender

    def _boom(*a, **kw):
        raise AssertionError("recommend() called — reuse should have short-circuited")

    monkeypatch.setattr(it_recommender, "recommend", _boom)

    source = _alert(minutes_ago=2, recommendation=STEPS)
    target = _alert(minutes_ago=0)

    assert wazuh_receiver._reuse_sibling_recommendation(target, "100020", "wazuh-system")
    stored = db.get_alert(target)["it_recommendation"]
    assert STEPS in stored
    assert f"#{source}" in stored, "provenance line must name the source alert"


def test_reuse_does_not_cross_devices_or_rules():
    _alert(device="POSsys1", minutes_ago=2, recommendation=STEPS)
    target = _alert(device="POSsys2")
    assert not wazuh_receiver._reuse_sibling_recommendation(target, "100020", "POSsys2")

    _alert(rule_id="100030", minutes_ago=2, recommendation=STEPS)
    target2 = _alert(rule_id="100031")
    assert not wazuh_receiver._reuse_sibling_recommendation(target2, "100031", "wazuh-system")


def test_reuse_ignores_stale_siblings_and_failure_sentinels(monkeypatch):
    monkeypatch.setattr(config, "IT_REC_REUSE_WINDOW_MIN", 15)
    _alert(minutes_ago=120, recommendation=STEPS)          # outside the window
    _alert(minutes_ago=1, recommendation=config.AI_CHAIN_EXHAUSTED)  # a failure, not an answer
    target = _alert()
    assert not wazuh_receiver._reuse_sibling_recommendation(target, "100020", "wazuh-system")


def test_window_zero_is_a_kill_switch(monkeypatch):
    monkeypatch.setattr(config, "IT_REC_REUSE_WINDOW_MIN", 0)
    _alert(minutes_ago=1, recommendation=STEPS)
    target = _alert()
    assert not wazuh_receiver._reuse_sibling_recommendation(target, "100020", "wazuh-system")


def test_provenance_header_does_not_stack():
    """Reuse of a reuse replaces the header instead of nesting one inside another."""
    first = _alert(minutes_ago=3, recommendation=STEPS)
    second = _alert(minutes_ago=2)
    wazuh_receiver._reuse_sibling_recommendation(second, "100020", "wazuh-system")
    third = _alert()
    wazuh_receiver._reuse_sibling_recommendation(third, "100020", "wazuh-system")

    stored = db.get_alert(third)["it_recommendation"]
    assert stored.count("Reused from alert") == 1
    assert f"#{second}" in stored and f"#{first}" not in stored
    assert stored.endswith(STEPS)


def test_backfill_query_finds_only_open_blank_high_criticals():
    blank = _alert(severity="CRITICAL")
    _alert(severity="CRITICAL", recommendation=STEPS)      # already has steps
    _alert(severity="MEDIUM")                              # below the AI gate
    sentinel = _alert(severity="HIGH", recommendation=config.AI_CHAIN_EXHAUSTED)

    found = {a["id"] for a in db.get_alerts_missing_it_recommendation(24, 10)}
    assert blank in found
    assert sentinel in found, "a stored failure should be retried, not treated as done"
    assert len(found) == 2


def test_manager_word_cap_is_untouched_by_the_it_rec_bump():
    """The IT cap moved to 120; the manager translation stays at 100."""
    import validator

    assert config.IT_REC_MAX_WORDS == 120
    assert config.MAX_WORDS == 100
    long_manager = " ".join(["word"] * 101)
    assert validator.validate_manager_translation(long_manager) is False
