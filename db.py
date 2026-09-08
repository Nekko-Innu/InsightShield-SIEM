# db.py
# Insight Shield — SQLite Schema + CRUD + Acknowledgment Queries
# Purpose : Single data access layer for all alert storage and retrieval.
#           Build this BEFORE any Flask route — nothing works without the schema.
# Safety  : WAL mode + check_same_thread=False for Flask concurrency.
#           All queries use ? parameterized statements — NEVER f-strings for SQL.
#
# Schema  : Fresh insightshield.db with 5 tables and NO migration framework.
#           The alerts table is 21 columns: 15 operational + ai_reasoning +
#           3 IT-ACK + attack_trail + 4 resolved/_by/_at/resolve_note + 1
#           it_recommendation. api_keys + settings are created here in Round 1;
#           their consumers (the Settings page, Fernet encryption helpers, .env
#           bootstrap) ship in Round 3.

import sqlite3
import json
import logging
import sys
import threading
import time
from datetime import datetime, timedelta

import config
import _request_cache
from alerts_util import derive_attacker_ip

# _request_cache imports flask only at module top and does `import db` lazily
# inside each helper, so this direction does not close a cycle.

logger = logging.getLogger("insightshield.db")

# Resolved against the process CWD on purpose: the E2E suite (tests/conftest.py)
# runs the app from a throwaway temp directory so every run gets a fresh
# database and the dev DB is never touched. Do not make this absolute.
DB_PATH = "insightshield.db"

# ── Per-thread connections (WAL mode) ────────────────────────────────────────
# This used to be ONE module-global connection shared by every thread with
# check_same_thread=False and no lock. A sqlite3.Connection owns transaction
# state, so a commit() on thread A committed thread B's half-finished work —
# intermittent, load-dependent, and effectively impossible to reproduce. With
# threads=16 in gunicorn.conf.py that is not a theoretical race.
#
# threading.local() gives each thread its own connection. WAL mode lets them
# read concurrently while one writes; _execute_with_retry below absorbs the
# brief "database is locked" windows when two threads write at once.
_local = threading.local()


def _get_conn() -> sqlite3.Connection:
    """Return this thread's DB connection, creating it on first use."""
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        # Wait rather than fail immediately when another thread holds the
        # write lock; pairs with the retry helper for the rest.
        conn.execute("PRAGMA busy_timeout=10000")
        _local.conn = conn
        logger.info(
            "Database connection opened for thread %s: %s (WAL mode)",
            threading.current_thread().name, DB_PATH,
        )
    return conn


def _execute_with_retry(sql: str, params: tuple = (), retries: int = 3,
                        backoff_s: float = 0.05) -> sqlite3.Cursor:
    """
    Run conn.execute(), retrying on 'database is locked' under WAL write
    contention. Any other OperationalError, or exhausted retries, re-raises.
    """
    conn = _get_conn()
    for attempt in range(retries):
        try:
            return conn.execute(sql, params)
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e).lower() and attempt < retries - 1:
                logger.warning("DB locked, retrying (%d/%d): %s", attempt + 1, retries, sql[:60])
                time.sleep(backoff_s * (attempt + 1))
                continue
            raise


# ── Schema (5 tables, fresh — no migration framework) ───────────────────────

CREATE_ALERTS_SQL = """
CREATE TABLE IF NOT EXISTS alerts (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp           TEXT    NOT NULL,
    rule_id             TEXT    NOT NULL,
    attack_type         TEXT    NOT NULL,
    severity            TEXT    NOT NULL,
    device_name         TEXT    NOT NULL,
    raw_alert           TEXT    NOT NULL,
    plain_text          TEXT,
    ai_reasoning        TEXT,
    provider_used       TEXT,
    fk_grade            REAL,
    acknowledged        INTEGER DEFAULT 0,
    acknowledged_by     TEXT,
    acknowledged_at     TEXT,
    response_time_s     INTEGER,
    attack_trail        TEXT,
    resolved            INTEGER DEFAULT 0,
    resolved_by         TEXT,
    resolved_at         TEXT,
    resolve_note        TEXT,
    it_recommendation   TEXT
);
"""  # 21 columns

CREATE_USERS_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    username              TEXT UNIQUE NOT NULL,
    password_hash         TEXT NOT NULL,
    role                  TEXT NOT NULL,
    created_at            TEXT NOT NULL,
    must_change_password  INTEGER DEFAULT 0,
    -- Bumped by logout. Folded into the session digest in web/auth_user.py, so
    -- incrementing it invalidates every cookie already issued for the account.
    session_epoch         INTEGER NOT NULL DEFAULT 0
);
"""

CREATE_AUDIT_LOG_SQL = """
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    actor       TEXT,
    actor_role  TEXT,
    action      TEXT NOT NULL,
    target      TEXT,
    ip          TEXT,
    user_agent  TEXT,
    details     TEXT
);
"""

# Bootstrap logic: see Round 3 (Fernet encryption helpers + Settings page).
# This table is inert in Round 1 — created here so the schema is final and
# downstream rounds don't need migrations. Stored values will be Fernet-encrypted.
CREATE_API_KEYS_SQL = """
CREATE TABLE IF NOT EXISTS api_keys (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    service         TEXT NOT NULL,
    key_name        TEXT NOT NULL,
    encrypted_value TEXT NOT NULL,
    is_active       INTEGER DEFAULT 1,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
"""

# Bootstrap logic: see bootstrap_settings_from_env. Round 3 makes this table
# the runtime source of truth for plain-text non-secret config (sender names,
# phone numbers, chat IDs, recipient emails, Wazuh URL/user).
CREATE_SETTINGS_SQL = """
CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

# Round 3: dynamic AI-provider list. Replaces the api_keys-as-AI-providers
# scheme. The api_keys table keeps non-AI service credentials (SMS, Telegram,
# Gmail, Wazuh). AI providers move here because they need richer per-row
# metadata: model name, base_url, auth_header, auth_prefix, request_format,
# active flag, position. The chain runner (_ai_chain.run_chain) consumes
# rows from this table via db.get_active_providers_ordered().
CREATE_AI_PROVIDERS_SQL = """
CREATE TABLE IF NOT EXISTS ai_providers (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    label               TEXT    NOT NULL,
    model               TEXT    NOT NULL,
    api_key_encrypted   TEXT    NOT NULL,
    base_url            TEXT    NOT NULL,
    auth_header         TEXT    NOT NULL,
    auth_prefix         TEXT    NOT NULL DEFAULT '',
    request_format      TEXT    NOT NULL,
    is_active           INTEGER NOT NULL DEFAULT 1,
    position            INTEGER NOT NULL,
    created_at          TEXT    NOT NULL,
    updated_at          TEXT    NOT NULL
);
"""

# Runtime error audit trail — separate from audit_log (which records user
# *actions*). Populated by the global Flask error handler and by best-effort
# log_error() calls sprinkled into the highest-risk unguarded code paths.
CREATE_ERROR_LOG_SQL = """
CREATE TABLE IF NOT EXISTS error_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    source      TEXT NOT NULL,
    module      TEXT,
    exc_type    TEXT,
    message     TEXT,
    path        TEXT,
    actor       TEXT,
    traceback   TEXT
);
"""

# Sliding-window rate limiter, shared across gunicorn workers. One row per
# permitted call; rate_limit.can_call counts the rows still inside the window.
# This used to be a dict of deques in rate_limit.py, which made every configured
# budget effectively N x its value once workers > 1 — including the Groq
# free-tier quota, which is a real external limit.
CREATE_RATE_EVENTS_SQL = """
CREATE TABLE IF NOT EXISTS rate_events (
    key TEXT NOT NULL,
    ts  REAL NOT NULL
);
"""

# AI response cache, shared across workers. Was three dicts in cache.py, so each
# worker kept its own copy and the "50 identical alerts = 1 API call" guarantee
# became "1 call per worker". `expires_at` is stored rather than derived from
# ts + TTL because _ai_chain negative-caches an exhausted provider chain with a
# much shorter lifetime than a real answer.
CREATE_AI_CACHE_SQL = """
CREATE TABLE IF NOT EXISTS ai_cache (
    ns          TEXT    NOT NULL,
    k           TEXT    NOT NULL,
    text        TEXT    NOT NULL,
    ts          REAL    NOT NULL,
    expires_at  REAL    NOT NULL,
    hits        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (ns, k)
);
"""


def _ensure_session_epoch_column(conn) -> None:
    """Add users.session_epoch to a database created before it existed.

    CREATE TABLE IF NOT EXISTS does nothing to a table that is already there, so
    the column in CREATE_USERS_SQL only reaches brand-new databases. There is no
    migration framework here by design; this is the idempotent equivalent —
    PRAGMA first, ALTER only when the column is genuinely absent. No f-string
    SQL: the table and column are literals, never user input.
    """
    cols = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
    if "session_epoch" not in cols:
        conn.execute(
            "ALTER TABLE users ADD COLUMN session_epoch INTEGER NOT NULL DEFAULT 0"
        )
        logger.info("Schema: added users.session_epoch (logout revocation)")


def init_db() -> None:
    """
    Initialise the DB: open connection, create the five tables, build indexes.
    Call once on Flask app startup. Idempotent — safe to call multiple times.
    """
    conn = _get_conn()
    conn.execute(CREATE_ALERTS_SQL)
    conn.execute(CREATE_USERS_SQL)
    _ensure_session_epoch_column(conn)
    conn.execute(CREATE_AUDIT_LOG_SQL)
    conn.execute(CREATE_API_KEYS_SQL)
    conn.execute(CREATE_SETTINGS_SQL)
    conn.execute(CREATE_AI_PROVIDERS_SQL)
    conn.execute(CREATE_ERROR_LOG_SQL)
    conn.execute(CREATE_RATE_EVENTS_SQL)
    conn.execute(CREATE_AI_CACHE_SQL)
    # alerts had no indexes at all, so every dashboard query, every 24h window
    # and every severity breakdown was a full table scan plus an in-memory
    # sort. That is why the 50-row caps existed; they have to come first.
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_resolved ON alerts(resolved)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ack_at ON alerts(acknowledged, acknowledged_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity_ts ON alerts(severity, timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor)")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_apikeys_lookup ON api_keys(service, key_name)")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_ai_providers_label ON ai_providers(label)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ai_providers_active_position ON ai_providers(is_active, position)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_error_ts ON error_log(ts)")
    # can_call runs on every webhook POST and every /api/status poll, and each
    # call both evicts and counts by key — this index is what keeps it cheap.
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rate_events_key_ts ON rate_events(key, ts)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ai_cache_expires ON ai_cache(expires_at)")
    conn.commit()
    logger.info("Database initialised: 9 tables (alerts=21 cols, users, audit_log, api_keys, settings, ai_providers, error_log, rate_events, ai_cache)")


# ── Alerts CRUD ──────────────────────────────────────────────────────────────

def store_alert(alert_dict: dict) -> int:
    """
    Insert a new alert row. Returns the auto-incremented ID.

    Parameters
    ----------
    alert_dict : dict
        Must contain: timestamp, rule_id, attack_type, severity, device_name,
        raw_alert (JSON string), plain_text, ai_reasoning, provider_used,
        fk_grade.
        raw_alert must already be json.dumps()'d — never pass a raw dict.
    """
    assert isinstance(alert_dict.get("raw_alert"), str), \
        "raw_alert must be a JSON string (use json.dumps()), not a dict"

    conn = _get_conn()
    cursor = _execute_with_retry(
        """
        INSERT INTO alerts (
            timestamp, rule_id, attack_type, severity, device_name,
            raw_alert, plain_text, ai_reasoning, provider_used,
            fk_grade, attack_trail
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            alert_dict["timestamp"],
            alert_dict["rule_id"],
            alert_dict["attack_type"],
            alert_dict["severity"],
            alert_dict["device_name"],
            alert_dict["raw_alert"],
            alert_dict.get("plain_text"),
            alert_dict.get("ai_reasoning"),
            alert_dict.get("provider_used"),
            alert_dict.get("fk_grade"),
            alert_dict.get("attack_trail"),
        ),
    )
    conn.commit()
    alert_id = cursor.lastrowid
    logger.info(
        "Alert stored: id=%s rule_id=%s severity=%s provider=%s",
        alert_id,
        alert_dict["rule_id"],
        alert_dict["severity"],
        alert_dict.get("provider_used"),
    )
    return alert_id


def get_latest_alert_id() -> int | None:
    """Return the highest alert id, or None if the table is empty."""
    conn = _get_conn()
    row = conn.execute("SELECT MAX(id) FROM alerts").fetchone()
    return row[0] if row and row[0] is not None else None


def get_alert(alert_id: int) -> dict | None:
    """
    Fetch a single alert by ID for the detail view.
    Returns dict with all 21 columns, or None if not found.
    """
    conn = _get_conn()
    row = conn.execute(
        "SELECT * FROM alerts WHERE id = ?", (alert_id,)
    ).fetchone()
    if row is None:
        return None
    return dict(row)


def get_recent_alerts(limit: int = 50) -> list[dict]:
    """Fetch the most recent alerts, ordered by timestamp DESC."""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def _alert_filter_clauses(status: str | None = None,
                          severity: str | None = None,
                          q: str | None = None,
                          hide_low: bool = False) -> tuple[list[str], list]:
    """Shared WHERE builder for search_alerts and count_alerts.

    One builder, not two, because search_audit and search_errors are already a
    hand-copied pair and have drifted. A count that disagrees with the page it
    labels is worse than no count.

    Values are always parameterised — nothing here is f-string interpolated.
    """
    clauses: list[str] = []
    params: list = []

    # Mirrors _alert_row.html's row_status exactly: resolved_at wins, then
    # acknowledged_at ('it-ack'), else open. An acknowledged-but-unresolved
    # alert therefore matches NEITHER 'open' nor 'closed' — that is the
    # behaviour the old client-side filter had, and changing it is a product
    # decision, not part of moving the filter to the server.
    if status == "open":
        clauses.append("acknowledged_at IS NULL AND resolved_at IS NULL")
    elif status == "closed":
        clauses.append("resolved_at IS NOT NULL")

    if severity:
        clauses.append("severity = ?")          # hits idx_alerts_severity_ts
        params.append(severity)

    if hide_low:
        clauses.append("severity NOT IN ('LOW', 'INFORMATIONAL')")

    if q:
        # raw_alert is in here because it is the only place the attacker IP
        # lives: alerts_util.derive_attacker_ip digs it out of the stored JSON
        # at render time, so there is no column to index.
        # ponytail: full scan on raw_alert; FTS5 past ~100k alerts.
        needle = f"%{q}%"
        clauses.append(
            "(device_name LIKE ? OR rule_id LIKE ? OR attack_type LIKE ? "
            " OR plain_text LIKE ? OR severity LIKE ? OR timestamp LIKE ? "
            " OR raw_alert LIKE ?)"
        )
        params.extend([needle] * 7)

    return clauses, params


def search_alerts(status: str | None = None,
                  severity: str | None = None,
                  q: str | None = None,
                  hide_low: bool = False,
                  limit: int = 50,
                  offset: int = 0) -> list[dict]:
    """One page of filtered alerts, newest first.

    The IT dashboard used to render get_recent_alerts(50) and filter it in the
    browser, so a CRITICAL that had fallen past row 50 could not be reached by
    any control in the app. Filtering and paging both happen here now.
    """
    clauses, params = _alert_filter_clauses(status, severity, q, hide_low)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    conn = _get_conn()
    rows = conn.execute(
        f"SELECT * FROM alerts{where} ORDER BY timestamp DESC, id DESC "
        f"LIMIT ? OFFSET ?",
        tuple(params) + (limit, offset),
    ).fetchall()
    return [dict(r) for r in rows]


def count_alerts(status: str | None = None,
                 severity: str | None = None,
                 q: str | None = None,
                 hide_low: bool = False) -> int:
    """How many alerts match the same filters — the denominator in the pager."""
    clauses, params = _alert_filter_clauses(status, severity, q, hide_low)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    conn = _get_conn()
    row = conn.execute(
        f"SELECT COUNT(*) AS n FROM alerts{where}", tuple(params)
    ).fetchone()
    return row["n"] if row else 0


def get_stream_watermark(status_key: str) -> tuple[int, str | None]:
    """One round trip: (highest alert id, when `status_key` was last written).

    This is what /api/events/stream ticks on. It replaced an in-process queue
    registry, which could only ever notify subscribers attached to the same
    worker that ingested the alert — with workers > 1 that silently dropped
    most live updates. Two primary-key probes, so it stays cheap even with
    every thread in the pool holding a stream.

    `status_key` is passed in rather than imported so db.py stays a leaf; the
    caller owns the settings key (agent_status.SNAPSHOT_KEY).
    """
    conn = _get_conn()
    max_id, status_ts = conn.execute(
        "SELECT (SELECT MAX(id) FROM alerts), "
        "       (SELECT updated_at FROM settings WHERE key = ?)",
        (status_key,),
    ).fetchone()
    return (max_id or 0), status_ts


def get_alerts_since(alert_id: int, limit: int = 20) -> list[dict]:
    """Alerts newer than `alert_id`, oldest first so the caller can advance its
    watermark row by row. `id` is the rowid, so this is an index scan.

    The limit caps one tick's work during an ingest burst; the caller's
    watermark advances inside the loop, so the next tick picks up the rest.
    """
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM alerts WHERE id > ? ORDER BY id ASC LIMIT ?",
        (alert_id, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def get_unacked_critical_alerts(min_age_minutes: int, max_age_hours: int) -> list[dict]:
    """CRITICAL alerts still unacknowledged, aged into the escalation window.

    This is the escalation queue. It used to be one APScheduler job per alert
    plus a dict mapping alert_id to job id — state that only existed in the
    process that happened to receive the webhook, and vanished on restart.
    Asking the database instead means any process can run the sweep, which is
    what lets the scheduler move out of the web workers.

    `min_age_minutes` keeps the sweep from re-notifying an alert that
    alert_router just sent on ingest; `max_age_hours` stops it paging forever
    for something nobody is going to acknowledge. Uses idx_alerts_severity_ts.
    """
    now = datetime.now(tz=config.PHT)
    newest = (now - timedelta(minutes=min_age_minutes)).isoformat()
    oldest = (now - timedelta(hours=max_age_hours)).isoformat()
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM alerts "
        " WHERE severity = 'CRITICAL' AND acknowledged = 0 "
        "   AND timestamp <= ? AND timestamp >= ? "
        " ORDER BY timestamp DESC",
        (newest, oldest),
    ).fetchall()
    return [dict(r) for r in rows]


def get_alerts_last_24h() -> list[dict]:
    """
    Fetch all alerts from the last 24 hours.
    Uses PHT timezone for the 24-hour window.
    """
    cutoff = datetime.now(tz=config.PHT) - timedelta(hours=24)
    cutoff_str = cutoff.isoformat()

    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM alerts WHERE timestamp >= ? ORDER BY timestamp DESC",
        (cutoff_str,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_all_alerts() -> list[dict]:
    """
    Every alert, newest first. Used only by /export.csv, which must not
    truncate — it is an evidence-export path. Every other caller should page
    through get_recent_alerts().
    """
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM alerts ORDER BY timestamp DESC"
    ).fetchall()
    return [dict(r) for r in rows]


def count_open_alerts() -> int:
    """
    Number of alerts that are not yet resolved, across the WHOLE table.

    The IT dashboard used to derive this by counting unacknowledged rows inside
    the 50-row `get_recent_alerts()` page, so the "Open Alerts" tile could never
    read higher than 50 — it saturated during exactly the burst it exists to
    warn about. It also treated "acknowledged" as closed, hiding every alert
    someone was actively working on. Open means not resolved.
    """
    conn = _get_conn()
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM alerts WHERE resolved = 0 OR resolved IS NULL"
    ).fetchone()
    return int(row["n"] or 0)


def mtta_seconds(hours: int = 24) -> float | None:
    """
    Mean time to acknowledge over the last `hours`, in seconds. None if nothing
    was acknowledged in the window.

    Replaces an unweighted mean of per-severity means over all time: one stale
    INFORMATIONAL alert carried the same weight as thousands of CRITICALs, and
    because the window was unbounded the figure could only ever drift downward
    as the table grew. This is a straight row-level average over a real window,
    matching how the manager dashboard already reports its numbers.
    """
    cutoff = (datetime.now(tz=config.PHT) - timedelta(hours=hours)).isoformat()
    conn = _get_conn()
    row = conn.execute(
        "SELECT AVG(response_time_s) AS avg_time FROM alerts "
        "WHERE acknowledged = 1 AND response_time_s IS NOT NULL "
        "AND acknowledged_at >= ?",
        (cutoff,),
    ).fetchone()
    return row["avg_time"] if row and row["avg_time"] is not None else None


def get_severity_breakdown(hours: int = 24) -> dict:
    """
    Count alerts by severity for the given time window.
    Returns dict with fixed key order: INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL.
    Uses a single SQL GROUP BY instead of fetching full rows.
    """
    cutoff = datetime.now(tz=config.PHT) - timedelta(hours=hours)
    cutoff_str = cutoff.isoformat()

    conn = _get_conn()
    rows = conn.execute(
        "SELECT severity, COUNT(*) as cnt FROM alerts "
        "WHERE timestamp >= ? GROUP BY severity",
        (cutoff_str,),
    ).fetchall()

    breakdown = {"INFORMATIONAL": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for row in rows:
        if row["severity"] in breakdown:
            breakdown[row["severity"]] = row["cnt"]
    return breakdown


def get_alerts_by_date_range(date_from: str, date_to: str) -> list[dict]:
    """
    Fetch all alerts between two ISO date strings (inclusive).
    date_from/date_to are date strings like '2026-04-01'.
    Appends T00:00:00 and T23:59:59 for full-day coverage.
    """
    start = f"{date_from}T00:00:00"
    end = f"{date_to}T23:59:59"

    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM alerts WHERE timestamp >= ? AND timestamp <= ? "
        "ORDER BY timestamp DESC",
        (start, end),
    ).fetchall()
    return [dict(r) for r in rows]


def get_report_summary(date_from: str, date_to: str) -> dict:
    """
    Compute summary stats for the report: total alerts, severity counts,
    avg FK grade, avg response time, provider distribution, resolution stats.
    """
    alerts = _request_cache.cached_alerts_by_range(date_from, date_to)
    total = len(alerts)
    if total == 0:
        return {"total": 0, "severity": {}, "avg_fk": 0.0, "avg_response": "—",
                "providers": {}, "resolved_count": 0, "auto_closed_count": 0,
                "ack_count": 0}

    severity = {"INFORMATIONAL": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    fk_grades = []
    resp_times = []
    providers = {}
    resolved_count = 0
    auto_closed_count = 0
    ack_count = 0

    for a in alerts:
        sev = a.get("severity", "INFORMATIONAL")
        if sev in severity:
            severity[sev] += 1
        if a.get("fk_grade"):
            fk_grades.append(a["fk_grade"])
        if a.get("response_time_s") is not None:
            resp_times.append(a["response_time_s"])
        prov = a.get("provider_used", "unknown")
        providers[prov] = providers.get(prov, 0) + 1
        # Split system auto-closes from human resolutions so the report doesn't
        # read ~100% "resolved" just because sub-HIGH alerts auto-close.
        if a.get("resolved"):
            if a.get("resolved_by") == config.SYSTEM_ACTOR:
                auto_closed_count += 1
            else:
                resolved_count += 1
        if a.get("acknowledged"):
            ack_count += 1

    return {
        "total": total,
        "severity": severity,
        "avg_fk": round(sum(fk_grades) / len(fk_grades), 2) if fk_grades else 0.0,
        "avg_response": f"{sum(resp_times) / len(resp_times):.0f}s" if resp_times else "—",
        "providers": providers,
        "resolved_count": resolved_count,
        "auto_closed_count": auto_closed_count,
        "ack_count": ack_count,
    }


# ── Round 7 audit-report helpers ─────────────────────────────────────────────
# These extend get_report_summary's surface for the Security Audit Report
# template. Each returns a small dict/list — Jinja consumes them directly
# without further shape massaging.

def get_top_threats(date_from: str, date_to: str, n: int = 3) -> list[dict]:
    """Top-N attack types in the date window, ordered by count desc.

    Returns [{attack_type, count}, ...]. Empty list when no alerts in range.
    """
    start = f"{date_from}T00:00:00"
    end = f"{date_to}T23:59:59"
    conn = _get_conn()
    rows = conn.execute(
        "SELECT attack_type, COUNT(*) AS cnt FROM alerts "
        "WHERE timestamp >= ? AND timestamp <= ? "
        "  AND attack_type IS NOT NULL AND attack_type != '' "
        "GROUP BY attack_type ORDER BY cnt DESC LIMIT ?",
        (start, end, n),
    ).fetchall()
    return [{"attack_type": r["attack_type"], "count": r["cnt"]} for r in rows]


def get_latest_alert_id_in_range(date_from: str, date_to: str) -> int:
    """Highest alert_id in the date window, or 0 if none.

    Round 7: feeds the executive_summary cache key. Any new alert in range
    bumps this value, the cache key changes, and the next call re-generates
    instead of returning a stale summary.
    """
    start = f"{date_from}T00:00:00"
    end = f"{date_to}T23:59:59"
    conn = _get_conn()
    row = conn.execute(
        "SELECT MAX(id) AS max_id FROM alerts "
        "WHERE timestamp >= ? AND timestamp <= ?",
        (start, end),
    ).fetchone()
    return int(row["max_id"]) if row and row["max_id"] else 0


def get_top_attacker_ips(date_from: str, date_to: str, n: int = 5) -> list[dict]:
    """Top-N attacker IPs in the date window, ordered by count desc.

    Uses alerts_util.derive_attacker_ip so the four-fallback derivation chain
    (attack_trail -> raw_alert.data.srcip -> arp.sender_ip -> regex on
    full_log) stays a single source of truth.
    Alerts where no IP can be derived are skipped, not bucketed under
    "unknown" — those don't belong in a "top attackers" view.
    """
    alerts = _request_cache.cached_alerts_by_range(date_from, date_to)
    counts: dict[str, int] = {}
    for a in alerts:
        ip = derive_attacker_ip(a)
        if not ip:
            continue
        counts[ip] = counts.get(ip, 0) + 1
    ordered = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:n]
    return [{"ip": ip, "count": cnt} for ip, cnt in ordered]


def get_auth_metrics(date_from: str, date_to: str) -> dict:
    """Authentication success/failure counts in the date window.

    Sources from the alerts table's `groups` field (already captured in
    attack_trail.rule.groups by wazuh_receiver). Anything in the
    'authentication_success' group counts as success; 'authentication_failed'
    or 'authentication_failures' counts as failure. Older alerts that never
    populated attack_trail return 0/0 — we don't try to infer from raw_alert.
    """
    alerts = _request_cache.cached_alerts_by_range(date_from, date_to)
    success = 0
    failure = 0
    for a in alerts:
        trail = a.get("attack_trail") or ""
        if not trail:
            continue
        try:
            doc = json.loads(trail) if isinstance(trail, str) else trail
        except (ValueError, TypeError):
            continue
        rule = doc.get("rule") if isinstance(doc, dict) else None
        if not isinstance(rule, dict):
            continue
        groups = rule.get("groups") or []
        if not isinstance(groups, list):
            groups = [groups]
        joined = ",".join(str(g) for g in groups).lower()
        if "authentication_success" in joined:
            success += 1
        if ("authentication_failed" in joined
                or "authentication_failures" in joined):
            failure += 1
    return {"success": success, "failure": failure}


def get_posture_score(date_from: str, date_to: str) -> int:
    """Security posture score 0-100 for the date window.

    Mirrors health_score.calculate's deduction model but operates over an
    arbitrary date range instead of the rolling 24h window so the report
    can show "posture for this week" / "posture for this month" alongside
    the dashboard's 24h health score. Same DEDUCT table from config.
    """
    alerts = _request_cache.cached_alerts_by_range(date_from, date_to)
    score = 100
    for a in alerts:
        sev = a.get("severity", "INFORMATIONAL")
        score -= config.DEDUCT.get(sev, 0)
    return max(0, score)


def acknowledge_alert(alert_id: int, username: str) -> bool:
    """
    Mark an alert as acknowledged by the given user. IT-ACK only — managers
    no longer acknowledge alerts in Insight Shield.

    Computes response_time_s via SQLite julianday formula.
    Only updates if acknowledged = 0 (prevents double-ACK).

    Returns True if the alert was updated, False if not found or already ACK'd.
    """
    ack_time = datetime.now(tz=config.PHT).isoformat()

    conn = _get_conn()
    cursor = _execute_with_retry(
        """
        UPDATE alerts SET
            acknowledged = 1,
            acknowledged_by = ?,
            acknowledged_at = ?,
            response_time_s = CAST(
                (julianday(?) - julianday(timestamp)) * 86400 AS INTEGER
            )
        WHERE id = ? AND acknowledged = 0 AND resolved = 0
        """,
        (username, ack_time, ack_time, alert_id),
    )
    conn.commit()

    if cursor.rowcount > 0:
        logger.info(
            "Alert acknowledged: id=%s by=%s at=%s",
            alert_id, username, ack_time,
        )
        return True
    logger.warning(
        "Acknowledge failed: id=%s (not found or already acknowledged)", alert_id
    )
    return False


def update_it_recommendation(
    alert_id: int,
    text: str,
    provider_used: str | None = None,
) -> bool:
    """
    Update only the it_recommendation column. Called by the fire-and-forget
    worker thread in wazuh_receiver after the second AI call completes.

    Never raises — returns False on lookup miss so the worker doesn't escalate.
    The provider_used argument is for log-line context only (it_recommendation
    is a single TEXT column, not a structured row).
    """
    conn = _get_conn()
    try:
        cursor = conn.execute(
            "UPDATE alerts SET it_recommendation = ? WHERE id = ?",
            (text, alert_id),
        )
        conn.commit()
        ok = cursor.rowcount > 0
        if ok:
            logger.info(
                "IT recommendation stored: alert_id=%s provider=%s",
                alert_id, provider_used,
            )
        else:
            logger.warning(
                "update_it_recommendation: alert_id=%s not found", alert_id,
            )
        return ok
    except Exception as e:
        logger.warning(
            "update_it_recommendation failed (alert_id=%s): %s", alert_id, e,
        )
        return False


def get_recent_it_recommendation(
    rule_id: str,
    device_name: str,
    within_min: int,
) -> tuple[int, str] | None:
    """
    Newest usable IT recommendation for the same rule on the same device inside
    `within_min` minutes, as (source_alert_id, text). None when there is none.

    Exists because the recommendation cache can never help a burst: its key is a
    sha256 of a prompt that embeds the whole raw alert (timestamps, full_log,
    paths), so ten repeats of one rule produce ten distinct keys and ten full
    provider chains. This query is the burst's actual cache — same rule, same
    machine, minutes apart is the same investigation.

    Ordered by id, not timestamp: ids are monotonic and ours, while timestamp
    comes from the alert payload and is attacker-influenced. The cutoff still
    filters on timestamp because that is what "recent" means to an operator;
    an alert with a bogus future timestamp can only make this MISS, never
    return something older than the window.

    AI_CHAIN_EXHAUSTED rows are excluded — that sentinel is a failure record,
    not an answer, and copying it forward would spread one outage across every
    later alert in the window.
    """
    if within_min <= 0:  # kill switch: config.IT_REC_REUSE_WINDOW_MIN = 0
        return None
    cutoff = (
        datetime.now(tz=config.PHT) - timedelta(minutes=within_min)
    ).isoformat()
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT id, it_recommendation FROM alerts "
            "WHERE rule_id = ? AND device_name = ? AND timestamp >= ? "
            "  AND it_recommendation IS NOT NULL "
            "  AND it_recommendation != '' AND it_recommendation != ? "
            "ORDER BY id DESC LIMIT 1",
            (str(rule_id), device_name, cutoff, config.AI_CHAIN_EXHAUSTED),
        ).fetchone()
    except Exception as e:
        # A read that fails must not stop the caller from doing the real AI
        # call — reuse is an optimisation, never a dependency.
        logger.warning(
            "get_recent_it_recommendation failed (rule_id=%s device=%s): %s",
            rule_id, device_name, e,
        )
        return None
    if row is None:
        return None
    return row["id"], row["it_recommendation"]


def get_alerts_missing_it_recommendation(
    max_age_hours: int,
    limit: int,
) -> list[dict]:
    """
    Open HIGH/CRITICAL alerts from the last `max_age_hours` with no IT
    recommendation, oldest first. Feeds scheduler._it_rec_backfill.

    Oldest-first because a backlog drains from the front; the operator looking
    at a blank card is looking at the alert that has been blank longest.
    Resolved alerts are skipped — nobody is investigating those any more.
    """
    cutoff = (
        datetime.now(tz=config.PHT) - timedelta(hours=max_age_hours)
    ).isoformat()
    conn = _get_conn()
    rows = conn.execute(
        "SELECT id, rule_id, device_name, raw_alert FROM alerts "
        "WHERE timestamp >= ? AND resolved_at IS NULL "
        "  AND severity IN ('HIGH', 'CRITICAL') "
        "  AND (it_recommendation IS NULL OR it_recommendation = '' "
        "       OR it_recommendation = ?) "
        "ORDER BY id ASC LIMIT ?",
        (cutoff, config.AI_CHAIN_EXHAUSTED, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def resolve_alert(alert_id: int, username: str, note: str = "") -> bool:
    """
    Mark an acknowledged alert as resolved. Only valid after IT ACK (acknowledged=1).
    Accepts an optional free-text note for the resolution reason.
    Returns True if updated, False if not found, not yet acknowledged, or already resolved.
    """
    resolve_time = datetime.now(tz=config.PHT).isoformat()

    conn = _get_conn()
    cursor = _execute_with_retry(
        """
        UPDATE alerts SET
            resolved = 1,
            resolved_by = ?,
            resolved_at = ?,
            resolve_note = ?
        WHERE id = ? AND acknowledged = 1 AND resolved = 0
        """,
        (username, resolve_time, note or None, alert_id),
    )
    conn.commit()

    if cursor.rowcount > 0:
        logger.info(
            "Alert resolved: id=%s by=%s at=%s",
            alert_id, username, resolve_time,
        )
        return True
    logger.warning(
        "Resolve failed: id=%s (not found, not IT-acked, or already resolved)",
        alert_id,
    )
    return False


def auto_close_alert(alert_id: int, note: str = None) -> bool:
    """
    Auto-close a sub-HIGH alert as a system action — no IT acknowledgment.

    MEDIUM/LOW/INFORMATIONAL alerts don't need a human to ack or resolve them
    (see config.requires_ack), so they are closed at ingest: resolved by
    config.SYSTEM_ACTOR with a fixed note. `acknowledged` is deliberately left
    untouched so the row never enters the ack lifecycle and stays out of MTTA
    (which keys on acknowledged = 1). Idempotent — the `resolved = 0` guard
    makes a re-run (or a race with a human resolve) a no-op.
    """
    close_time = datetime.now(tz=config.PHT).isoformat()
    conn = _get_conn()
    cursor = _execute_with_retry(
        """
        UPDATE alerts SET
            resolved = 1,
            resolved_by = ?,
            resolved_at = ?,
            resolve_note = ?
        WHERE id = ? AND resolved = 0
        """,
        (config.SYSTEM_ACTOR, close_time, note or config.AUTO_CLOSE_NOTE, alert_id),
    )
    conn.commit()
    if cursor.rowcount > 0:
        logger.info("Alert auto-closed (system): id=%s at=%s", alert_id, close_time)
        return True
    return False


def get_evaluation_metrics() -> dict:
    """
    Aggregate evaluation metrics for the IT dashboard and thesis reporting.

    Returns dict with:
        fk_avg                - average FK grade across all alerts
        response_times        - dict of avg response times by severity
        provider_distribution - dict of provider usage percentages
        total                 - total number of alerts
    """
    conn = _get_conn()

    total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    if total == 0:
        return {
            "fk_avg": 0.0,
            "response_times": {},
            "provider_distribution": {},
            "total": 0,
        }

    fk_row = conn.execute(
        "SELECT AVG(fk_grade) FROM alerts WHERE fk_grade IS NOT NULL"
    ).fetchone()
    fk_avg = round(fk_row[0], 2) if fk_row[0] is not None else 0.0

    resp_rows = conn.execute(
        "SELECT severity, AVG(response_time_s) as avg_time "
        "FROM alerts "
        "WHERE acknowledged = 1 AND response_time_s IS NOT NULL "
        "GROUP BY severity"
    ).fetchall()
    response_times = {row["severity"]: round(row["avg_time"], 1) for row in resp_rows}

    prov_rows = conn.execute(
        "SELECT provider_used, COUNT(*) as cnt "
        "FROM alerts "
        "WHERE provider_used IS NOT NULL "
        "GROUP BY provider_used"
    ).fetchall()
    prov_total = sum(row["cnt"] for row in prov_rows)
    provider_distribution = {}
    if prov_total > 0:
        provider_distribution = {
            row["provider_used"]: round(row["cnt"] / prov_total * 100, 1)
            for row in prov_rows
        }

    return {
        "fk_avg": fk_avg,
        "response_times": response_times,
        "provider_distribution": provider_distribution,
        "total": total,
    }


# ── Users (werkzeug.security auth) ───────────────────────────────────────────
# Runtime reads the `users` table seeded from config.USERS on first startup.
# config.USERS is bootstrap-only — editing it after the seeder has run is a no-op.

from werkzeug.security import generate_password_hash, check_password_hash


def create_user(username: str, password: str, role: str,
                must_change_password: int = 0) -> int:
    """
    Create a new user. Raises sqlite3.IntegrityError if the username exists.
    Password is hashed via werkzeug.security.generate_password_hash before storage.
    """
    pw_hash = generate_password_hash(password)
    conn = _get_conn()
    cursor = conn.execute(
        "INSERT INTO users (username, password_hash, role, created_at, must_change_password) "
        "VALUES (?, ?, ?, ?, ?)",
        (username, pw_hash, role, datetime.now(tz=config.PHT).isoformat(), must_change_password),
    )
    conn.commit()
    logger.info("User created: username=%s role=%s", username, role)
    return cursor.lastrowid


def get_user(username: str) -> dict | None:
    """Return the user row as a dict, or None if no such user."""
    conn = _get_conn()
    row = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    return dict(row) if row else None


# Hashed once at import, against a value nobody can ever type. verify_password
# checks the submitted password against this when the username does not exist,
# so both paths pay the same scrypt cost — without it, a missing username
# returned in microseconds while a real one paid full hashing, and the response
# time told an attacker which usernames exist.
_DUMMY_PASSWORD_HASH = generate_password_hash("no-such-user-placeholder")


def verify_password(username: str, password: str) -> dict | None:
    """
    Check a plaintext password against the stored hash.
    Returns the user dict on success, None on failure.
    """
    user = get_user(username)
    if user is None:
        check_password_hash(_DUMMY_PASSWORD_HASH, password)  # constant-time-ish
        return None
    try:
        ok = check_password_hash(user["password_hash"], password)
    except (ValueError, TypeError):
        return None
    return user if ok else None


def bump_session_epoch(username: str) -> None:
    """Invalidate every session cookie already issued for this account.

    Logout previously cleared only the caller's own jar, which is not
    revocation: the cookie is a self-contained signed credential, so a copy
    taken off the wire beforehand kept working until the 30-minute signature
    lifetime ran out. Incrementing the epoch changes the digest that
    web/auth_user.session_token embeds in the user id, and load_user rejects
    every cookie carrying the old one.

    ponytail: per-user, not per-session — logging out of one browser signs the
    account out everywhere. Correct-and-blunt for a two-account deployment; if
    per-device sessions are ever wanted, this becomes a session-id table and the
    digest keys off that instead.
    """
    conn = _get_conn()
    conn.execute(
        "UPDATE users SET session_epoch = session_epoch + 1 WHERE username = ?",
        (username,),
    )
    conn.commit()
    logger.info("Session epoch bumped for %s — prior cookies revoked", username)


def set_password(username: str, new_password: str) -> bool:
    """
    Update a user's password hash and clear must_change_password.
    Returns True if updated, False if user does not exist.
    """
    pw_hash = generate_password_hash(new_password)
    conn = _get_conn()
    cursor = conn.execute(
        "UPDATE users SET password_hash = ?, must_change_password = 0 WHERE username = ?",
        (pw_hash, username),
    )
    conn.commit()
    if cursor.rowcount > 0:
        logger.info("Password changed for user: %s", username)
        return True
    return False


def seed_users_from_config() -> None:
    """
    One-time seeder: if the users table is empty, hash and insert every entry
    from config.USERS. Safe to call on every startup — after the first run, the
    table is non-empty and this becomes a no-op.
    """
    conn = _get_conn()
    existing = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if existing > 0:
        return
    # Checked only on the empty-table path, so an existing install never fails
    # to boot over a variable it no longer needs. Mirrors
    # crypto_utils.get_master_key(): a missing secret is a refusal to start, not
    # a substituted default, because the substituted default here was public.
    missing = [f"BOOTSTRAP_{u.upper()}_PASSWORD"
               for u, d in config.USERS.items() if not d["password"]]
    if missing:
        logger.error(
            "Refusing to seed default accounts: %s not set. Set them in .env - "
            "shipping a known bootstrap password is how an install gets owned "
            "between first boot and first login.", ", ".join(missing))
        sys.exit(1)
    for username, data in config.USERS.items():
        try:
            create_user(
                username=username,
                password=data["password"],
                role=data["role"],
                # The seeded passwords are committed in config.py:USERS, so
                # they are public. This was 0, which meant the enforcement at
                # app.py's change_password gate had never once fired and both
                # accounts kept their published password forever.
                must_change_password=1,
            )
        except sqlite3.IntegrityError:
            pass  # Race: another worker seeded concurrently.
    logger.info("Seeded %d user(s) from config.USERS (first-run bootstrap)",
                len(config.USERS))


# ── Audit Log ────────────────────────────────────────────────────────────────

def log_audit(
    action: str,
    actor: str | None = None,
    actor_role: str | None = None,
    target: str | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
    details: str | None = None,
) -> int:
    """
    Append a row to audit_log. Never raises — audit writes are best-effort so a
    failure here must not block the originating request.
    """
    import json as _json
    if isinstance(details, (dict, list)):
        try:
            details = _json.dumps(details)[:1000]
        except (TypeError, ValueError):
            details = str(details)[:1000]
    elif isinstance(details, str):
        details = details[:1000]

    ts = datetime.now(tz=config.PHT).isoformat()
    try:
        conn = _get_conn()
        cursor = conn.execute(
            "INSERT INTO audit_log (ts, actor, actor_role, action, target, ip, user_agent, details) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (ts, actor, actor_role, action, target, ip,
             (user_agent or "")[:200], details),
        )
        conn.commit()
        return cursor.lastrowid or 0
    except Exception as e:
        logger.warning("log_audit failed (%s): %s", action, e)
        return 0


def get_recent_audit(limit: int = 50) -> list[dict]:
    """Return the most recent audit rows, newest first."""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM audit_log ORDER BY ts DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


def search_audit(actor: str | None = None,
                 action: str | None = None,
                 date_from: str | None = None,
                 date_to: str | None = None,
                 limit: int = 500) -> list[dict]:
    """Filtered audit search for /admin/audit. All filters are optional."""
    clauses = []
    params: list = []
    if actor:
        clauses.append("actor = ?")
        params.append(actor)
    if action:
        clauses.append("action LIKE ?")
        params.append(f"%{action}%")
    if date_from:
        clauses.append("ts >= ?")
        params.append(f"{date_from}T00:00:00")
    if date_to:
        clauses.append("ts <= ?")
        params.append(f"{date_to}T23:59:59")
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)
    conn = _get_conn()
    rows = conn.execute(
        f"SELECT * FROM audit_log{where} ORDER BY ts DESC LIMIT ?", tuple(params)
    ).fetchall()
    return [dict(r) for r in rows]


# ── Error Log (runtime exception audit) ─────────────────────────────────────

def log_error(
    source: str,
    module: str | None = None,
    exc_type: str | None = None,
    message: str | None = None,
    path: str | None = None,
    actor: str | None = None,
    traceback: str | None = None,
) -> int:
    """
    Append a row to error_log. Never raises — same best-effort contract as
    log_audit, since an error-reporting failure must not mask or replace the
    original error.
    """
    ts = datetime.now(tz=config.PHT).isoformat()
    try:
        conn = _get_conn()
        cursor = conn.execute(
            "INSERT INTO error_log (ts, source, module, exc_type, message, path, actor, traceback) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (ts, source, module, exc_type, (message or "")[:2000], path, actor,
             (traceback or "")[:8000]),
        )
        conn.commit()
        return cursor.lastrowid or 0
    except Exception as e:
        logger.warning("log_error failed (%s): %s", exc_type, e)
        return 0


def purge_old_rows(audit_days: int = 90, error_days: int = 30) -> dict[str, int]:
    """
    Delete audit_log and error_log rows older than the given retention windows,
    sweep the two shared-state tables, then checkpoint the WAL.
    Returns {"audit": n, "error": n, "rate_events": n, "ai_cache": n}.

    Nothing in this app deleted a row before now. audit_log grows on every
    mutating request and error_log on every exception, and the 02:00 backup
    copies the whole file daily — unbounded growth with a scheduled amplifier.
    The observed WAL was 4.1 MB against a 421 KB database because nothing ever
    checkpointed it either.

    Alerts are deliberately NOT purged: they are the evidence this product
    exists to keep.
    """
    conn = _get_conn()
    audit_cutoff = (datetime.now(tz=config.PHT) - timedelta(days=audit_days)).isoformat()
    error_cutoff = (datetime.now(tz=config.PHT) - timedelta(days=error_days)).isoformat()

    audit_n = _execute_with_retry(
        "DELETE FROM audit_log WHERE ts < ?", (audit_cutoff,)
    ).rowcount
    error_n = _execute_with_retry(
        "DELETE FROM error_log WHERE ts < ?", (error_cutoff,)
    ).rowcount

    # rate_limit evicts lazily, and only for the key it was asked about. Keys
    # that go quiet — csv:alice after logout, status:<ip> for a one-time
    # visitor — are never queried again and would leak their rows forever.
    # Anything older than a day is outside every configured window (the longest
    # is the 600s Medium-Telegram dedup).
    rate_n = _execute_with_retry(
        "DELETE FROM rate_events WHERE ts < ?", (time.time() - 86400,)
    ).rowcount
    # Same story for cache entries nobody reads again: _get only expires the
    # key it was handed.
    cache_n = _execute_with_retry(
        "DELETE FROM ai_cache WHERE expires_at < ?", (time.time(),)
    ).rowcount
    conn.commit()

    # TRUNCATE resets the WAL file to zero rather than just marking it reusable.
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    logger.info(
        "Retention purge: %d audit row(s) older than %dd, %d error row(s) older than %dd, "
        "%d stale rate_events, %d expired ai_cache",
        audit_n, audit_days, error_n, error_days, rate_n, cache_n,
    )
    return {"audit": audit_n, "error": error_n,
            "rate_events": rate_n, "ai_cache": cache_n}


def search_errors(source: str | None = None,
                  module: str | None = None,
                  date_from: str | None = None,
                  date_to: str | None = None,
                  limit: int = 500) -> list[dict]:
    """Filtered error-log search for the admin Errors tab. All filters optional."""
    clauses = []
    params: list = []
    if source:
        clauses.append("source = ?")
        params.append(source)
    if module:
        clauses.append("module LIKE ?")
        params.append(f"%{module}%")
    if date_from:
        clauses.append("ts >= ?")
        params.append(f"{date_from}T00:00:00")
    if date_to:
        clauses.append("ts <= ?")
        params.append(f"{date_to}T23:59:59")
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)
    conn = _get_conn()
    rows = conn.execute(
        f"SELECT * FROM error_log{where} ORDER BY ts DESC LIMIT ?", tuple(params)
    ).fetchall()
    return [dict(r) for r in rows]


# The audit actions that together describe someone testing what they are
# allowed to reach. Kept next to the query that counts them so a new action
# cannot be added to one without the other being obvious.
PROBE_ACTIONS = ("AUTHZ_DENIED", "CSRF_REJECTED", "WEBHOOK_AUTH_FAILED")


def probe_sources_in_window(
    actions: tuple[str, ...] = PROBE_ACTIONS,
    since_minutes: int = 60,
    min_count: int = 25,
) -> list[tuple[str, int]]:
    """
    Source IPs with at least `min_count` matching audit rows in the window.

    Deliberately a GROUP BY rather than a per-IP count like
    failed_logins_in_window: the login throttle already knows which IP it is
    asking about, whereas a sweep has to discover them. Returns
    [(ip, count), ...] worst first.

    The action list is bound as placeholders, not interpolated — only the
    placeholder COUNT is derived from Python, in keeping with this module's
    no-f-string-SQL rule.
    """
    if not actions:
        return []
    since_iso = (
        datetime.now(tz=config.PHT) - timedelta(minutes=since_minutes)
    ).isoformat()
    placeholders = ",".join("?" * len(actions))
    sql = (
        "SELECT ip, COUNT(*) AS n FROM audit_log "
        "WHERE action IN (" + placeholders + ") AND ts > ? AND ip IS NOT NULL "
        "GROUP BY ip HAVING n >= ? ORDER BY n DESC"
    )
    try:
        conn = _get_conn()
        rows = conn.execute(sql, (*actions, since_iso, min_count)).fetchall()
        return [(r["ip"], int(r["n"])) for r in rows]
    except Exception as e:
        logger.warning("probe_sources_in_window query failed: %s", e)
        return []


def failed_logins_in_window(
    ip: str | None = None,
    username: str | None = None,
    since_minutes: int = 15,
) -> int:
    """
    Count LOGIN_FAILURE rows in audit_log within the last `since_minutes`.

    Round E (§11.1a) — backend for the login throttle. Reads the same audit_log
    rows the existing `/admin/audit` page already exposes, so IT Admins can
    inspect blocked-IP evidence without a new UI surface.

    At least one of (ip, username) must be provided. If both are given, an OR
    is applied — useful for the credential-brute-force escalation check where
    we want "any failure tied to this IP OR this username".

    Uses idx_audit_ts (defined at db.py:157) for the ts predicate; ip/actor
    filtering is a small filter on top.
    """
    if not ip and not username:
        return 0
    since_iso = (
        datetime.now(tz=config.PHT) - timedelta(minutes=since_minutes)
    ).isoformat()
    clauses = ["action = 'LOGIN_FAILURE'", "ts > ?"]
    params: list = [since_iso]
    or_clauses: list[str] = []
    if ip:
        or_clauses.append("ip = ?")
        params.append(ip)
    if username:
        or_clauses.append("actor = ?")
        params.append(username)
    clauses.append("(" + " OR ".join(or_clauses) + ")")
    sql = "SELECT COUNT(*) AS n FROM audit_log WHERE " + " AND ".join(clauses)
    try:
        conn = _get_conn()
        row = conn.execute(sql, tuple(params)).fetchone()
        return int(row["n"]) if row else 0
    except Exception as e:
        logger.warning("failed_logins_in_window query failed: %s", e)
        return 0


# ── Settings & API Keys (Round 3 stubs) ──────────────────────────────────────
# These wrappers exist so module-level callers don't fail to import. Encryption,
# bootstrap-from-env, and Settings UI all land in Round 3.

def get_setting(key: str) -> str | None:
    """Return the plain-text value for a settings key, or None if not set."""
    conn = _get_conn()
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def get_setting_row(key: str) -> dict | None:
    """Return {"value", "updated_at"} for a settings key, or None if not set.

    The timestamp is what lets a reader tell "this was written 5 seconds ago"
    from "whatever wrote this died an hour ago" — used by agent_status to avoid
    serving a permanently stale snapshot when the scheduler process is down,
    and by the SSE stream to notice a snapshot changed without diffing JSON.
    """
    conn = _get_conn()
    row = conn.execute(
        "SELECT value, updated_at FROM settings WHERE key = ?", (key,)
    ).fetchone()
    return dict(row) if row else None


def set_setting(key: str, value: str) -> None:
    """Upsert a plain-text setting."""
    ts = datetime.now(tz=config.PHT).isoformat()
    conn = _get_conn()
    conn.execute(
        "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        (key, value, ts),
    )
    conn.commit()


def get_api_key(service: str, key_name: str = "API_KEY") -> str | None:
    """
    Return the DECRYPTED plaintext value for (service, key_name), or None
    if no row exists or is_active = 0.

    Encryption is an internal storage detail — callers think in plaintext.
    On corrupted ciphertext (rotated key, garbled row) decrypt_value logs a
    warning and returns None.
    """
    import crypto_utils
    conn = _get_conn()
    row = conn.execute(
        "SELECT encrypted_value FROM api_keys "
        "WHERE service = ? AND key_name = ? AND is_active = 1",
        (service, key_name),
    ).fetchone()
    if not row:
        return None
    return crypto_utils.decrypt_value(row["encrypted_value"])


def get_service_completeness() -> dict[str, str]:
    """Return per-service status map for the Round F (§17.1) settings cards.

    For each of the 4 cards in the Service Configuration redesign:
      - "online"  = required fields present and (for encrypted keys) decryptable
      - "offline" = at least one required field missing
      - "unknown" = the check itself failed (caught at the call site)

    Live Test results (§17.9 q3) override these for 10 minutes via session
    storage in the route — this helper is the *baseline* for the dot color
    on first page load.
    """
    def _has(value) -> bool:
        return bool(value and str(value).strip())

    out: dict[str, str] = {}

    # Telegram IT — bot token + chat id
    out["telegram_it"] = (
        "online" if _has(get_api_key("telegram_it", "BOT_TOKEN"))
                    and _has(get_setting("telegram_it_chat_id"))
        else "offline"
    )
    # Telegram Manager — same shape as IT
    out["telegram_manager"] = (
        "online" if _has(get_api_key("telegram_manager", "BOT_TOKEN"))
                    and _has(get_setting("telegram_manager_chat_id"))
        else "offline"
    )
    # Gmail SMTP — app password + from-address
    out["gmail"] = (
        "online" if _has(get_api_key("gmail", "APP_PASSWORD"))
                    and _has(get_setting("gmail_address"))
        else "offline"
    )
    # Wazuh API — password + url + user (3-tuple)
    out["wazuh"] = (
        "online" if _has(get_api_key("wazuh", "PASSWORD"))
                    and _has(get_setting("wazuh_api_url"))
                    and _has(get_setting("wazuh_api_user"))
        else "offline"
    )
    # Notification Recipients — pointers, not a service. No live probe makes
    # sense (you can't "test" a phone number). Status reflects whether all 3
    # required pointers are populated; the recipients card uses test_allowed=False
    # so the macro suppresses the Test button.
    out["recipients"] = (
        "online" if _has(get_setting("manager_phone"))
                    and _has(get_setting("it_admin_phone"))
                    and _has(get_setting("it_admin_email"))
        else "offline"
    )
    return out


def set_api_key(service: str, key_name: str, plaintext: str,
                is_active: int = 1) -> None:
    """
    Upsert a credential. Argument is PLAINTEXT — Fernet encryption is applied
    internally via crypto_utils.encrypt_value before the row is written.
    Empty plaintext stores empty ciphertext (effectively a soft-delete).
    """
    import crypto_utils
    encrypted = crypto_utils.encrypt_value(plaintext) if plaintext else ""
    ts = datetime.now(tz=config.PHT).isoformat()
    conn = _get_conn()
    conn.execute(
        "INSERT INTO api_keys (service, key_name, encrypted_value, is_active, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(service, key_name) DO UPDATE SET "
        "  encrypted_value = excluded.encrypted_value, "
        "  is_active       = excluded.is_active, "
        "  updated_at      = excluded.updated_at",
        (service, key_name, encrypted, is_active, ts, ts),
    )
    conn.commit()


def delete_api_key(service: str, key_name: str = "API_KEY") -> bool:
    """Hard-delete an api_keys row. Returns True if a row was removed."""
    conn = _get_conn()
    cursor = conn.execute(
        "DELETE FROM api_keys WHERE service = ? AND key_name = ?",
        (service, key_name),
    )
    conn.commit()
    return cursor.rowcount > 0


# ── AI providers (Round 3) ───────────────────────────────────────────────────
# The ai_providers table is the runtime source for _ai_chain.run_chain.
# Round 1 created the schema; Round 3 adds CRUD + the chain-consumer query.

def _row_to_provider_dict(row: sqlite3.Row) -> dict:
    """Map an ai_providers row to the dict shape _ai_chain.run_chain expects."""
    import crypto_utils
    return {
        "id":             row["id"],
        "label":          row["label"],
        "model":          row["model"],
        "api_key":        crypto_utils.decrypt_value(row["api_key_encrypted"]) or "",
        "base_url":       row["base_url"],
        "auth_header":    row["auth_header"],
        "auth_prefix":    row["auth_prefix"],
        "request_format": row["request_format"],
        "is_active":      bool(row["is_active"]),
        "position":       row["position"],
    }


def get_active_providers_ordered() -> list[dict]:
    """
    Return active providers sorted by position. Decrypts api_key per row.
    Output shape matches _ai_chain.run_chain's `providers` parameter.
    """
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM ai_providers WHERE is_active = 1 ORDER BY position ASC"
    ).fetchall()
    return [_row_to_provider_dict(r) for r in rows]


def list_all_providers() -> list[dict]:
    """All providers (active + inactive) in display order. Used by Settings UI."""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM ai_providers ORDER BY position ASC"
    ).fetchall()
    return [_row_to_provider_dict(r) for r in rows]


def get_provider(provider_id: int) -> dict | None:
    """Single provider by id, or None if not found."""
    conn = _get_conn()
    row = conn.execute(
        "SELECT * FROM ai_providers WHERE id = ?", (provider_id,)
    ).fetchone()
    return _row_to_provider_dict(row) if row else None


def add_provider(label: str, model: str, api_key: str, base_url: str,
                 auth_header: str, auth_prefix: str, request_format: str,
                 is_active: int = 1) -> int:
    """
    Insert a new provider. api_key is plaintext — encrypted internally.
    Position is computed as MAX(position)+1 so new providers go last.

    The label column carries no UNIQUE constraint (this used to claim it raised
    IntegrityError on a duplicate, which it never did), so duplicates are
    rejected by the route before it gets here — see provider_label_exists.
    """
    import crypto_utils
    encrypted = crypto_utils.encrypt_value(api_key) if api_key else ""
    ts = datetime.now(tz=config.PHT).isoformat()
    conn = _get_conn()
    next_pos = (conn.execute("SELECT COALESCE(MAX(position), -1) + 1 FROM ai_providers").fetchone()[0])
    cursor = conn.execute(
        "INSERT INTO ai_providers (label, model, api_key_encrypted, base_url, "
        "  auth_header, auth_prefix, request_format, is_active, position, "
        "  created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (label, model, encrypted, base_url, auth_header, auth_prefix,
         request_format, is_active, next_pos, ts, ts),
    )
    conn.commit()
    logger.info("Provider added: id=%s label=%s position=%s", cursor.lastrowid, label, next_pos)
    return cursor.lastrowid


def provider_label_exists(label: str) -> bool:
    """Case-insensitive label check. Two providers with the same label in the
    fallback chain are indistinguishable in the Settings list and in the KPI
    tile, which reads the first active provider's label."""
    conn = _get_conn()
    row = conn.execute(
        "SELECT 1 FROM ai_providers WHERE label = ? COLLATE NOCASE LIMIT 1", (label,)
    ).fetchone()
    return row is not None


def update_provider(provider_id: int, **fields) -> bool:
    """
    Partial update. Acceptable keys: label, model, api_key, base_url,
    auth_header, auth_prefix, request_format, is_active.

    If 'api_key' in fields, encrypt before write (column name maps to
    api_key_encrypted).
    """
    import crypto_utils
    if not fields:
        return False
    sets, params = [], []
    for k, v in fields.items():
        if k == "api_key":
            sets.append("api_key_encrypted = ?")
            params.append(crypto_utils.encrypt_value(v) if v else "")
        elif k in {"label", "model", "base_url", "auth_header",
                   "auth_prefix", "request_format", "is_active"}:
            sets.append(f"{k} = ?")
            params.append(v)
        # silently ignore other keys (defensive against form-injection)
    if not sets:
        return False
    sets.append("updated_at = ?")
    params.append(datetime.now(tz=config.PHT).isoformat())
    params.append(provider_id)
    conn = _get_conn()
    cursor = conn.execute(
        f"UPDATE ai_providers SET {', '.join(sets)} WHERE id = ?", params,
    )
    conn.commit()
    if cursor.rowcount > 0:
        logger.info("Provider updated: id=%s fields=%s", provider_id, list(fields.keys()))
        return True
    return False


def delete_provider(provider_id: int) -> bool:
    """
    Hard-delete a provider. Renumbers remaining rows so positions stay
    contiguous (0, 1, 2, ... no holes). Returns True on rowcount > 0.
    """
    conn = _get_conn()
    cursor = conn.execute("DELETE FROM ai_providers WHERE id = ?", (provider_id,))
    if cursor.rowcount == 0:
        return False
    # Re-number positions
    rows = conn.execute(
        "SELECT id FROM ai_providers ORDER BY position ASC"
    ).fetchall()
    ts = datetime.now(tz=config.PHT).isoformat()
    for new_pos, row in enumerate(rows):
        conn.execute(
            "UPDATE ai_providers SET position = ?, updated_at = ? WHERE id = ?",
            (new_pos, ts, row["id"]),
        )
    conn.commit()
    logger.info("Provider deleted: id=%s (positions re-numbered)", provider_id)
    return True


def move_provider(provider_id: int, direction: str) -> bool:
    """
    Swap a provider's position with the adjacent row.
    direction in {"up", "down"}. Returns False at the edge (top/bottom).
    """
    if direction not in ("up", "down"):
        raise ValueError(f"direction must be 'up' or 'down', got {direction!r}")
    conn = _get_conn()
    row = conn.execute(
        "SELECT id, position FROM ai_providers WHERE id = ?", (provider_id,)
    ).fetchone()
    if row is None:
        return False
    pos = row["position"]
    target_pos = pos - 1 if direction == "up" else pos + 1
    other = conn.execute(
        "SELECT id FROM ai_providers WHERE position = ?", (target_pos,)
    ).fetchone()
    if other is None:
        return False  # already at top/bottom
    ts = datetime.now(tz=config.PHT).isoformat()
    conn.execute(
        "UPDATE ai_providers SET position = ?, updated_at = ? WHERE id = ?",
        (target_pos, ts, provider_id),
    )
    conn.execute(
        "UPDATE ai_providers SET position = ?, updated_at = ? WHERE id = ?",
        (pos, ts, other["id"]),
    )
    conn.commit()
    logger.info("Provider moved: id=%s direction=%s new_pos=%s", provider_id, direction, target_pos)
    return True


def toggle_provider_active(provider_id: int) -> bool | None:
    """Flip is_active 0↔1. Returns the NEW state, or None if not found."""
    conn = _get_conn()
    row = conn.execute(
        "SELECT is_active FROM ai_providers WHERE id = ?", (provider_id,)
    ).fetchone()
    if row is None:
        return None
    new_state = 0 if row["is_active"] else 1
    ts = datetime.now(tz=config.PHT).isoformat()
    conn.execute(
        "UPDATE ai_providers SET is_active = ?, updated_at = ? WHERE id = ?",
        (new_state, ts, provider_id),
    )
    conn.commit()
    logger.info("Provider toggled: id=%s is_active=%s", provider_id, new_state)
    return bool(new_state)


def bootstrap_settings_from_env() -> None:
    """
    First-boot import: populate api_keys, settings, and ai_providers tables
    from os.environ via the existing config.X bootstrap defaults.

    Idempotent. Detects "already bootstrapped" via a settings row
    'bootstrap_complete' = '1'. After the first run, .env is only used for
    FLASK_SECRET_KEY and ENCRYPTION_KEY; runtime config flows through the DB.

    Empty config values are skipped (operators can configure them later via
    the Settings UI; the consumer modules degrade gracefully on missing rows).

    Wraps the entire import in BEGIN IMMEDIATE so concurrent gunicorn
    workers don't double-import.
    """
    conn = _get_conn()
    if conn.execute(
        "SELECT value FROM settings WHERE key = 'bootstrap_complete'"
    ).fetchone():
        return

    logger.info("bootstrap_settings_from_env: starting first-boot import")
    conn.execute("BEGIN IMMEDIATE")
    try:
        # 1. AI providers from config.DEFAULT_AI_PROVIDERS
        for p in config.DEFAULT_AI_PROVIDERS:
            if not p.get("api_key"):
                logger.info("bootstrap: skipping %s (no api_key in env)", p["label"])
                continue
            try:
                add_provider(
                    label=p["label"], model=p["model"],
                    api_key=p["api_key"],
                    base_url=p["base_url"], auth_header=p["auth_header"],
                    auth_prefix=p["auth_prefix"], request_format=p["request_format"],
                    is_active=1 if p.get("is_active", True) else 0,
                )
            except sqlite3.IntegrityError:
                # Concurrent worker beat us to this label — fine.
                logger.debug("bootstrap: %s already exists, skipping", p["label"])

        # 2. api_keys (non-AI services)
        _bootstrap_api_key("telegram_it",      "BOT_TOKEN",   config.TELEGRAM_BOT_TOKEN)
        _bootstrap_api_key("telegram_manager", "BOT_TOKEN",   config.TELEGRAM_MANAGER_BOT_TOKEN)
        _bootstrap_api_key("gmail",            "APP_PASSWORD", config.GMAIL_APP_PASSWORD)
        _bootstrap_api_key("wazuh",            "PASSWORD",    config.WAZUH_API_PASSWORD)

        # 3. plain-text settings
        _bootstrap_setting("telegram_it_chat_id",       config.TELEGRAM_CHAT_ID)
        _bootstrap_setting("telegram_manager_chat_id",  config.TELEGRAM_MANAGER_CHAT_ID)
        _bootstrap_setting("gmail_address",             config.GMAIL_ADDRESS)
        _bootstrap_setting("manager_phone",             config.MANAGER_PHONE)
        _bootstrap_setting("it_admin_phone",            config.IT_ADMIN_PHONE)
        _bootstrap_setting("it_admin_email",            config.IT_ADMIN_EMAIL)
        _bootstrap_setting("wazuh_api_url",             config.WAZUH_API_URL)
        _bootstrap_setting("wazuh_api_user",            config.WAZUH_API_USER)

        # 4. Mark complete so subsequent boots no-op
        set_setting("bootstrap_complete", "1")
        conn.commit()
        logger.info("bootstrap_settings_from_env: complete")
    except Exception as e:
        conn.rollback()
        logger.error("bootstrap_settings_from_env: failed, rolled back: %s", e)
        raise


def _bootstrap_api_key(service: str, key_name: str, plaintext: str) -> None:
    """Internal bootstrap helper — skips empty values (operator hasn't set yet)."""
    if plaintext:
        set_api_key(service, key_name, plaintext)


def _bootstrap_setting(key: str, value: str) -> None:
    """Internal bootstrap helper — skips empty values."""
    if value:
        set_setting(key, value)
