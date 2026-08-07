"""
The rate limiter and the AI cache used to be process-local dicts. They now live
in SQLite so that gunicorn can run more than one worker, and the property that
matters is exactly the one a single-process test cannot see: a second process
must observe the first one's writes.

So every test here runs against a throwaway DB in a temp CWD (db.py resolves
DB_PATH against the process CWD), and the two cross-process tests really do
spawn a second interpreter.
"""
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

APP_DIR = Path(__file__).resolve().parent.parent


@pytest.fixture()
def fresh_db(tmp_path, monkeypatch):
    """Point db.py at a brand-new database and hand back its directory."""
    import db

    monkeypatch.chdir(tmp_path)
    # _get_conn caches one connection per thread for the process lifetime, and
    # it was opened against whatever CWD was current at the time. Drop it so the
    # next call reopens against tmp_path.
    if hasattr(db._local, "conn"):
        db._local.conn.close()
        del db._local.conn
    db.init_db()
    yield tmp_path
    if hasattr(db._local, "conn"):
        db._local.conn.close()
        del db._local.conn


def _in_subprocess(tmp_path: Path, code: str) -> str:
    """Run `code` in a second interpreter against the same DB. Returns stdout."""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(APP_DIR) + os.pathsep + env.get("PYTHONPATH", "")
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(tmp_path), env=env, capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


# ── rate_limit ───────────────────────────────────────────────────────────────

def test_rate_limit_allows_up_to_the_budget_then_denies(fresh_db):
    import rate_limit

    assert rate_limit.can_call("k", 2) == (True, 0.0)
    assert rate_limit.can_call("k", 2) == (True, 0.0)

    allowed, retry_after = rate_limit.can_call("k", 2)
    assert allowed is False
    # Retry-After must be usable as an HTTP header value, not just falsy.
    assert 0 < retry_after <= 60.0


def test_rate_limit_window_expiry_releases_the_budget(fresh_db):
    import rate_limit

    assert rate_limit.can_call("k", 1, window_seconds=0.5)[0] is True
    assert rate_limit.can_call("k", 1, window_seconds=0.5)[0] is False
    time.sleep(0.6)
    assert rate_limit.can_call("k", 1, window_seconds=0.5)[0] is True


def test_rate_limit_keys_are_independent(fresh_db):
    import rate_limit

    assert rate_limit.can_call("a", 1)[0] is True
    assert rate_limit.can_call("a", 1)[0] is False
    assert rate_limit.can_call("b", 1)[0] is True


def test_rate_limit_reset_clears_one_key_or_all(fresh_db):
    import rate_limit

    rate_limit.can_call("a", 1)
    rate_limit.can_call("b", 1)

    rate_limit.reset("a")
    assert rate_limit.window_count("a") == 0
    assert rate_limit.window_count("b") == 1

    # reset(None) must wipe every key — the in-memory version did _buckets.clear(),
    # and a DB version that quietly no-ops here would silently disable the
    # IT Admin "clear rate limit" button.
    rate_limit.reset()
    assert rate_limit.window_count("b") == 0


def test_rate_limit_budget_is_shared_across_processes(fresh_db):
    """The whole reason this moved into SQLite."""
    import rate_limit

    assert rate_limit.can_call("shared", 2)[0] is True

    out = _in_subprocess(fresh_db, (
        "import rate_limit;"
        "print(rate_limit.can_call('shared', 2)[0], rate_limit.can_call('shared', 2)[0])"
    ))
    # Second process sees the first process's call: it gets one more, then denied.
    assert out == "True False"


# ── cache ────────────────────────────────────────────────────────────────────

def test_cache_round_trips_and_misses_are_none(fresh_db):
    import cache

    assert cache.get_cached("1001") is None
    cache.set_cached("1001", "plain english")
    assert cache.get_cached("1001") == "plain english"


def test_cache_namespaces_do_not_collide(fresh_db):
    import cache

    cache.set_cached("1001", "manager text")
    cache.set_itrec_cached("1001", "it steps")
    cache.set_exec_summary_cached("1001", "summary")

    assert cache.get_cached("1001") == "manager text"
    assert cache.get_itrec_cached("1001") == "it steps"
    assert cache.get_exec_summary_cached("1001") == "summary"


def test_cache_entry_expires(fresh_db):
    import cache

    cache.set_cached("1001", "text", ttl=0)
    assert cache.get_cached("1001") is None


def test_cache_stats_keeps_the_shape_the_ui_destructures(fresh_db):
    """/api/cache-stats and the IT dashboard Groq KPI tile both index into this."""
    import cache

    cache.set_cached("1001", "a")
    cache.get_cached("1001")
    cache.get_cached("1001")
    cache.set_exec_summary_cached("digest", "b")

    stats = cache.get_stats()
    assert stats["ttl_seconds"] == cache.TTL
    assert stats["manager"]["entries"] == 1
    assert stats["manager"]["total_hits"] == 2
    assert stats["manager"]["rule_ids"] == ["1001"]
    assert stats["it_rec"] == {"entries": 0, "total_hits": 0, "rule_ids": []}
    assert stats["exec_summary"]["keys"] == ["digest"]


def test_cache_invalidate_hits_every_namespace(fresh_db):
    import cache

    cache.set_cached("1001", "a")
    cache.set_itrec_cached("1001", "b")

    assert cache.invalidate("1001") is True
    assert cache.get_cached("1001") is None
    assert cache.get_itrec_cached("1001") is None
    assert cache.invalidate("1001") is False


def test_cache_clear_all_returns_a_count(fresh_db):
    import cache

    cache.set_cached("1001", "a")
    cache.set_itrec_cached("1002", "b")
    assert cache.clear_all() == 2
    assert cache.get_stats()["manager"]["entries"] == 0


def test_cache_is_shared_across_processes(fresh_db):
    """A background worker's AI result has to be visible to the web process."""
    import cache

    cache.set_cached("1001", "written by the parent")
    out = _in_subprocess(fresh_db, "import cache; print(cache.get_cached('1001'))")
    assert out == "written by the parent"


# ── purge ────────────────────────────────────────────────────────────────────

def test_purge_sweeps_stale_rate_events_and_expired_cache(fresh_db):
    """Lazy eviction only touches the key being read; quiet keys need the sweep."""
    import cache
    import db
    import rate_limit

    rate_limit.can_call("quiet", 5)
    cache.set_cached("1001", "expired", ttl=-1)
    # Backdate the rate event past the 24h sweep cutoff.
    conn = db._get_conn()
    conn.execute("UPDATE rate_events SET ts = ?", (time.time() - 90000,))
    conn.commit()

    result = db.purge_old_rows()
    assert result["rate_events"] == 1
    assert result["ai_cache"] == 1
    assert rate_limit.window_count("quiet") == 0


# ── escalation queue ─────────────────────────────────────────────────────────

def _insert_critical(minutes_ago: int, acknowledged: int = 0) -> int:
    """One CRITICAL alert at a chosen age. Returns its id."""
    from datetime import datetime, timedelta

    import config
    import db

    ts = (datetime.now(tz=config.PHT) - timedelta(minutes=minutes_ago)).isoformat()
    conn = db._get_conn()
    cursor = conn.execute(
        "INSERT INTO alerts (timestamp, rule_id, attack_type, severity, "
        "device_name, raw_alert, plain_text, acknowledged) "
        "VALUES (?, '5715', 'test', 'CRITICAL', 'DEV', '{}', 'test', ?)",
        (ts, acknowledged),
    )
    conn.commit()
    return cursor.lastrowid


def test_escalation_queue_picks_up_an_aged_unacked_critical(fresh_db):
    import config
    import db

    _insert_critical(minutes_ago=config.ESCALATION_INTERVAL_MIN + 1)
    queued = db.get_unacked_critical_alerts(
        min_age_minutes=config.ESCALATION_INTERVAL_MIN,
        max_age_hours=config.ESCALATION_MAX_AGE_H,
    )
    assert len(queued) == 1


def test_escalation_queue_skips_a_just_ingested_alert(fresh_db):
    """alert_router already notified on ingest; the sweep must not double up."""
    import config
    import db

    _insert_critical(minutes_ago=0)
    assert db.get_unacked_critical_alerts(
        min_age_minutes=config.ESCALATION_INTERVAL_MIN,
        max_age_hours=config.ESCALATION_MAX_AGE_H,
    ) == []


def test_acknowledging_removes_an_alert_from_the_escalation_queue(fresh_db):
    """The whole reason cancel_escalation could be deleted: the sweep re-reads
    `acknowledged` from the row, so any worker's acknowledgement stops it."""
    import config
    import db

    alert_id = _insert_critical(minutes_ago=config.ESCALATION_INTERVAL_MIN + 1)
    assert db.get_unacked_critical_alerts(config.ESCALATION_INTERVAL_MIN,
                                          config.ESCALATION_MAX_AGE_H) != []

    db.acknowledge_alert(alert_id, "admin")

    assert db.get_unacked_critical_alerts(config.ESCALATION_INTERVAL_MIN,
                                          config.ESCALATION_MAX_AGE_H) == []


def test_escalation_queue_gives_up_on_a_stale_alert(fresh_db):
    """Without an upper bound a DB-driven sweep would page IT forever, which is
    how people learn to ignore alerts."""
    import config
    import db

    _insert_critical(minutes_ago=config.ESCALATION_MAX_AGE_H * 60 + 60)
    assert db.get_unacked_critical_alerts(
        min_age_minutes=config.ESCALATION_INTERVAL_MIN,
        max_age_hours=config.ESCALATION_MAX_AGE_H,
    ) == []


def test_escalation_queue_ignores_non_critical_severities(fresh_db):
    import config
    import db

    conn = db._get_conn()
    from datetime import datetime, timedelta
    ts = (datetime.now(tz=config.PHT) - timedelta(minutes=30)).isoformat()
    conn.execute(
        "INSERT INTO alerts (timestamp, rule_id, attack_type, severity, "
        "device_name, raw_alert, plain_text, acknowledged) "
        "VALUES (?, '5715', 'test', 'HIGH', 'DEV', '{}', 'test', 0)", (ts,))
    conn.commit()

    assert db.get_unacked_critical_alerts(
        min_age_minutes=config.ESCALATION_INTERVAL_MIN,
        max_age_hours=config.ESCALATION_MAX_AGE_H,
    ) == []


# ── agent_status ─────────────────────────────────────────────────────────────

def test_agent_status_snapshot_crosses_processes(fresh_db):
    import agent_status

    agent_status_json = (
        "import json, db, agent_status;"
        "db.set_setting(agent_status.SNAPSHOT_KEY,"
        " json.dumps({'dot_color': 'green', 'summary': 'All systems operational'}));"
        "print('written')"
    )
    assert _in_subprocess(fresh_db, agent_status_json) == "written"

    snap = agent_status.get_snapshot()
    assert snap["dot_color"] == "green"


def test_agent_status_stale_snapshot_reads_as_red(fresh_db):
    """A dead scheduler must not leave the login page showing 'all operational'."""
    import json
    from datetime import timedelta

    import agent_status
    import config
    import db
    from datetime import datetime

    db.set_setting(agent_status.SNAPSHOT_KEY,
                   json.dumps({"dot_color": "green", "summary": "All systems operational"}))
    stale = (datetime.now(tz=config.PHT)
             - timedelta(seconds=agent_status.STALE_AFTER_S + 10)).isoformat()
    conn = db._get_conn()
    conn.execute("UPDATE settings SET updated_at = ? WHERE key = ?",
                 (stale, agent_status.SNAPSHOT_KEY))
    conn.commit()

    assert agent_status.get_snapshot()["dot_color"] == "red"


def test_agent_status_missing_snapshot_reads_as_red(fresh_db):
    import agent_status

    assert agent_status.get_snapshot()["dot_color"] == "red"
