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


def test_retry_upgrades_a_static_row_when_the_fallback_succeeds(monkeypatch):
    """The inline 5s attempt fell back to static; the 25s retry gets a real answer."""
    import groq_translator

    alert_id = _alert()
    db._get_conn().execute(
        "UPDATE alerts SET plain_text = ?, provider_used = 'static' WHERE id = ?",
        ("STATIC TEMPLATE", alert_id),
    )
    db._get_conn().commit()

    seen = {}

    def _fake_translate(rule_id, description, device_name, use_ai=True,
                        budget_s=None, ignore_negative_cache=False):
        seen["budget_s"] = budget_s
        seen["ignore_negative_cache"] = ignore_negative_cache
        return ("WHAT HAPPENED: real answer. WHAT TO DO: act.", "Gemini", "reasoning")

    monkeypatch.setattr(groq_translator, "translate", _fake_translate)
    wazuh_receiver._upgrade_translation(alert_id, "100020", "desc", "wazuh-system")

    row = db.get_alert(alert_id)
    assert row["provider_used"] == "Gemini"
    assert "real answer" in row["plain_text"]
    # The whole point: full budget, and walk past the poison the inline attempt
    # just wrote for this key.
    assert seen["budget_s"] == config.AI_CHAIN_BUDGET_S
    assert seen["ignore_negative_cache"] is True


def test_retry_leaves_the_row_alone_when_it_also_fails(monkeypatch):
    import groq_translator

    alert_id = _alert()
    db._get_conn().execute(
        "UPDATE alerts SET plain_text = ?, provider_used = 'static' WHERE id = ?",
        ("STATIC TEMPLATE", alert_id),
    )
    db._get_conn().commit()

    monkeypatch.setattr(
        groq_translator, "translate",
        lambda *a, **kw: ("STATIC TEMPLATE", "static", "still down"),
    )
    wazuh_receiver._upgrade_translation(alert_id, "100020", "desc", "wazuh-system")

    row = db.get_alert(alert_id)
    assert row["provider_used"] == "static"
    assert row["plain_text"] == "STATIC TEMPLATE"


def test_ignore_negative_cache_walks_past_the_poison():
    """A negative entry stops the inline path and must not stop the retry."""
    import _ai_chain

    key = "test-negative-key"
    store = {key: config.AI_CHAIN_EXHAUSTED}

    def _get(k):
        return store.get(k)

    text, provider, _ = _ai_chain.run_chain(
        prompt="p", providers=[], validator_fn=lambda t: True,
        cache_get=_get, cache_key=key,
    )
    assert provider == config.AI_CHAIN_EXHAUSTED, "inline path must honour the poison"

    # Same entry, retry path: it gets past the cache and fails for the honest
    # reason instead (no providers configured), which is what lets a real chain
    # run in production.
    _, _, reasoning = _ai_chain.run_chain(
        prompt="p", providers=[], validator_fn=lambda t: True,
        cache_get=_get, cache_key=key, ignore_negative_cache=True,
    )
    assert "ignored (retry path)" in reasoning
    assert "No active providers" in reasoning


def test_failed_chain_copies_a_sibling_that_finished_meanwhile(monkeypatch):
    """Live 2026-09-18: six alerts in 8s all missed reuse at the start; one
    chain then failed (Groq 429 + Gemini 503) and stored AI_CHAIN_EXHAUSTED
    while three siblings already had steps. Reuse must be tried again."""
    import it_recommender

    target = _alert()
    source = _alert(minutes_ago=1)

    def _recommend(*a, **kw):
        db.update_it_recommendation(source, STEPS)   # sibling finishes mid-chain
        return config.AI_CHAIN_EXHAUSTED, config.AI_CHAIN_EXHAUSTED

    monkeypatch.setattr(it_recommender, "recommend", _recommend)
    wazuh_receiver._kick_it_recommendation(target, "{}", "wazuh-system", "100020")

    stored = db.get_alert(target)["it_recommendation"]
    assert STEPS in stored and f"#{source}" in stored


def test_capped_translation_reads_the_cache_instead_of_static():
    """Live 2026-09-18: alerts 2-5 were cache HITs, the 6th hit AI_REPEAT_CAP
    and went static although the identical cached text was right there."""
    import cache
    import groq_translator

    desc = "Multiple failed logins"
    key = "v3:" + __import__("hashlib").sha256(
        groq_translator._build_prompt(desc).encode("utf-8")).hexdigest()
    cache.set_cached(key, "WHAT HAPPENED: brute force on {device}.")
    try:
        text, provider, _ = groq_translator.translate(
            "100001", desc, "POSsys1", use_ai=False)
        assert provider == "cache"
        assert text == "WHAT HAPPENED: brute force on POSsys1."
    finally:
        cache.clear_all()


def test_manager_word_cap_is_untouched_by_the_it_rec_bump():
    """The IT cap moved to 120; the manager translation stays at 100."""
    import validator

    assert config.IT_REC_MAX_WORDS == 120
    assert config.MAX_WORDS == 100
    long_manager = " ".join(["word"] * 101)
    assert validator.validate_manager_translation(long_manager) is False


# ── Timestamp normalisation ──────────────────────────────────────────────────
# alerts.timestamp is TEXT and every window compares it as TEXT, so the column
# cannot hold two timezones. It did: Wazuh's integrator passes its own UTC stamp
# through untouched while the receiver stamped PHT when the payload had none.

def test_normalize_ts_puts_every_producer_in_one_timezone():
    wazuh_utc = "2026-09-08T06:45:42.483000+00:00"   # 14:45:42 PHT — the NEWER one
    ours_pht = "2026-09-08T14:15:37.000287+08:00"    # 14:15:37 PHT — the OLDER one

    a = db.normalize_ts(wazuh_utc)
    b = db.normalize_ts(ours_pht)
    assert a.endswith("+08:00") and b.endswith("+08:00")
    # The whole point: text comparison now agrees with chronology. Before this,
    # "14:15" > "06:45" as text put the older row on top of the newer one.
    assert a > b
    assert wazuh_utc < ours_pht, "the raw strings really did sort backwards"


def test_normalize_ts_handles_z_naive_and_garbage():
    assert db.normalize_ts("2026-09-08T06:45:42.483Z").startswith("2026-09-08T14:45:42")
    # Naive input is read as local (PHT) — what a hand-rolled curl means.
    assert db.normalize_ts("2026-09-08T14:15:37") == "2026-09-08T14:15:37+08:00"
    # An alert source does not get to decide where its row sorts.
    assert db.normalize_ts("garbage").endswith("+08:00")
    assert db.normalize_ts(None).endswith("+08:00")


def test_store_alert_normalizes_on_the_way_in():
    alert_id = db.store_alert({
        "timestamp": "2026-09-08T06:45:42.483000+00:00", "rule_id": "100020",
        "attack_type": "[T/D] Ransomware", "severity": "CRITICAL",
        "device_name": "wazuh-system", "raw_alert": "{}", "plain_text": "x",
        "ai_reasoning": "", "provider_used": "cache", "fk_grade": 6.0,
        "attack_trail": None,
    })
    stored = db.get_alert(alert_id)["timestamp"]
    assert stored == "2026-09-08T14:45:42.483000+08:00"


def test_recent_window_no_longer_skips_wazuh_stamped_rows():
    """The invisible half of the bug: UTC rows fell out of every PHT window."""
    now_utc = (datetime.now(tz=config.PHT) - timedelta(minutes=2)).astimezone(
        __import__("datetime").timezone.utc
    ).isoformat()
    source = db.store_alert({
        "timestamp": now_utc, "rule_id": "100020", "attack_type": "[T/D] Ransomware",
        "severity": "CRITICAL", "device_name": "wazuh-system", "raw_alert": "{}",
        "plain_text": "x", "ai_reasoning": "", "provider_used": "cache",
        "fk_grade": 6.0, "attack_trail": None,
    })
    db.update_it_recommendation(source, STEPS)

    found = db.get_recent_it_recommendation("100020", "wazuh-system", 15)
    assert found is not None, "a UTC-stamped alert must be visible to a PHT window"
    assert found[0] == source


def test_alert_list_orders_by_id_not_by_payload_timestamp():
    """A payload cannot push its row to the top by claiming a future time."""
    old = db.store_alert({
        "timestamp": "2030-01-01T00:00:00+08:00",  # a lie from the alert source
        "rule_id": "100020", "attack_type": "[T/D] Ransomware", "severity": "CRITICAL",
        "device_name": "wazuh-system", "raw_alert": "{}", "plain_text": "x",
        "ai_reasoning": "", "provider_used": "cache", "fk_grade": 6.0,
        "attack_trail": None,
    })
    newer = _alert()
    ids = [a["id"] for a in db.search_alerts(limit=10)]
    assert ids.index(newer) < ids.index(old)
