"""Notifications: HIGH/CRITICAL dispatch with its per-device cooldown, the
escalation digest, the manager's once-per-alert nudge, and the email switch.

Pure-logic with a throwaway DB (rate_limit is SQLite-backed). notifier sends are
monkeypatched — no network.
"""
import os
import tempfile

os.environ.setdefault("FLASK_SECRET_KEY", "test-only-" + "0" * 32)
os.environ.setdefault("BOOTSTRAP_ADMIN_PASSWORD", "test-Admin!2026")
os.environ.setdefault("BOOTSTRAP_MANAGER_PASSWORD", "test-Manager!2026")

import pytest

import config
import db

_TMP_DB = os.path.join(tempfile.mkdtemp(prefix="is-mgr-test-"), "test.db")
db.DB_PATH = _TMP_DB
db.init_db()

import alert_router
import notifier
import rate_limit


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    rate_limit.reset()
    # Freeze routing to business hours so after-hours tier-bump can't turn a
    # MEDIUM into a HIGH and change what channels fire.
    monkeypatch.setattr(alert_router, "is_outside_hours", lambda: False)
    yield
    rate_limit.reset()


def _spy(monkeypatch):
    calls = {"it": 0, "email": 0, "manager": 0}
    monkeypatch.setattr(notifier, "send_telegram", lambda a, **k: calls.__setitem__("it", calls["it"] + 1))
    monkeypatch.setattr(notifier, "send_email", lambda a, **k: calls.__setitem__("email", calls["email"] + 1))
    monkeypatch.setattr(notifier, "send_manager_telegram", lambda a, **k: calls.__setitem__("manager", calls["manager"] + 1))
    return calls


@pytest.mark.parametrize("sev", ["HIGH", "CRITICAL"])
def test_high_critical_notify_manager(monkeypatch, sev):
    calls = _spy(monkeypatch)
    alert_router.route_alert(sev, {"id": 1, "rule_id": "100013", "severity": sev,
                                   "attack_type": "t", "device_name": "d"})
    assert calls["manager"] == 1
    assert calls["it"] == 1 and calls["email"] == 1


@pytest.mark.parametrize("sev", ["MEDIUM", "LOW", "INFORMATIONAL"])
def test_sub_high_never_notifies_manager(monkeypatch, sev):
    calls = _spy(monkeypatch)
    alert_router.route_alert(sev, {"id": 2, "rule_id": "100013", "severity": sev,
                                   "attack_type": "t", "device_name": "d"})
    assert calls["manager"] == 0


def test_escalation_dedup_one_nudge_per_alert():
    win = config.ESCALATION_MAX_AGE_H * 3600
    # Same alert: first sweep nudges, later sweeps denied.
    assert rate_limit.can_call("mgr-escal:1", 1, window_seconds=win)[0] is True
    assert rate_limit.can_call("mgr-escal:1", 1, window_seconds=win)[0] is False
    # A different alert gets its own single nudge.
    assert rate_limit.can_call("mgr-escal:2", 1, window_seconds=win)[0] is True


def test_manager_escalation_skips_when_deactivated(monkeypatch):
    monkeypatch.setattr(notifier, "_service_is_active", lambda svc: False)
    # No raise, returns False, and never reaches _post_telegram.
    assert notifier.send_manager_escalation([{"id": 9, "attack_type": "t", "device_name": "d"}]) is False


def test_repeat_alert_on_same_device_notifies_once(monkeypatch):
    # An ARP spoof stored ~60 CRITICAL rows in 30 s; each sent three messages.
    calls = _spy(monkeypatch)
    alert = {"rule_id": "100020", "severity": "CRITICAL", "attack_type": "t"}
    for i in range(5):
        alert_router.route_alert("CRITICAL", {**alert, "id": i, "device_name": "pos2"})
    assert calls == {"it": 1, "email": 1, "manager": 1}
    # Same attack on another machine is a new incident.
    alert_router.route_alert("CRITICAL", {**alert, "id": 9, "device_name": "pos1"})
    assert calls["it"] == 2


def test_escalation_sweep_sends_one_digest_not_one_per_alert(monkeypatch):
    import scheduler
    sent = []
    monkeypatch.setattr(db, "get_unacked_critical_alerts", lambda **k: [
        {"id": i, "attack_type": "ARP spoofing", "device_name": "pos2"} for i in range(1, 61)
    ] + [{"id": 70, "attack_type": "Port scan", "device_name": "pos1"}])
    monkeypatch.setattr(notifier, "_post_telegram", lambda tok, chat, text, **k: sent.append(text) or True)
    monkeypatch.setattr(notifier, "_service_is_active", lambda svc: True)

    scheduler._escalation_sweep()
    it, manager = sent
    assert it.startswith("[Insight Shield] 61 CRITICAL")
    assert "60 × ARP spoofing on pos2 (#1–#60)" in it and "Port scan on pos1 (#70)" in it
    assert "61 CRITICAL" in manager

    # Next sweep: IT is reminded again, the manager is not (once per alert).
    sent.clear()
    scheduler._escalation_sweep()
    assert len(sent) == 1 and sent[0].startswith("[Insight Shield] 61 CRITICAL")


def test_email_off_never_opens_smtp(monkeypatch):
    import smtplib
    monkeypatch.setattr(config, "EMAIL_ENABLED", False)
    monkeypatch.setattr(smtplib, "SMTP", lambda *a, **k: (_ for _ in ()).throw(AssertionError("SMTP opened")))
    assert notifier.send_email({"id": 1}) is False
