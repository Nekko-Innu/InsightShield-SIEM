# rate_limit.py
# Insight Shield — Sliding-window rate limiter, shared across gunicorn workers.
# Purpose : Enforce a per-window budget on anything that needs one — outbound AI
#           provider calls, CSV/PDF exports, the webhook, credential reveals.
# Used by : _ai_chain (Groq free-tier budget), alert_router (Medium Telegram
#           dedup), app.py (csv, report_pdf, client_error, webhook, status,
#           reveal, settings service tests)
#
# Design notes
#   * One row per permitted call in the `rate_events` table: (key, ts).
#   * Before every decision we delete rows older than the window FOR THAT KEY,
#     then count what remains and compare against `limit_per_min`.
#   * State is in SQLite, not process memory. That is the whole point: with
#     workers > 1 a dict-of-deques gave every budget N x its configured value,
#     including the Groq free-tier quota, which is a real external limit.
#   * Rows for keys that go quiet are swept by db.purge_old_rows (03:00 job).

import logging
import time
from typing import Tuple

import db

logger = logging.getLogger("insightshield.rate_limit")

WINDOW_SECONDS = 60.0


def can_call(provider: str, limit_per_min: int,
             window_seconds: float = WINDOW_SECONDS) -> Tuple[bool, float]:
    """
    Decide whether a call to <provider> is within its budget for the window.

    Returns (allowed, retry_after_seconds).
    * allowed=True  — the call is recorded immediately; caller must proceed.
    * allowed=False — retry_after_seconds tells the caller (or its audit log)
                      how long until the oldest in-window call expires.

    Sliding window, not fixed. The count is "how many calls in the last
    <window_seconds> right now". Default window is 60 s — matching the
    original per-minute behaviour used by the Groq provider limiter.
    Pass a larger window_seconds for coarser budgets (e.g. 600 for a
    10-minute dedup window on Medium Telegram alerts).

    # ponytail: check-then-insert is not atomic across processes, so two
    # workers can both see count=24 against a limit of 25 and both insert.
    # Overshoot is bounded by the worker count, and GROQ_BUDGET_PER_MIN=25
    # against Groq's real 30/min is exactly that slack. If a budget ever needs
    # to be exact, give this module its own isolation_level=None connection and
    # wrap the sequence in BEGIN IMMEDIATE — it cannot be done on db._get_conn()
    # because that connection's implicit transactions would collide.
    """
    # ponytail: wall clock, not time.monotonic(), because monotonic is
    # meaningless once the value outlives the process that produced it and
    # these rows are read by every worker. Ceiling: an NTP step skews a window
    # by the size of the step — milliseconds on an NTP-synced host, but a
    # manual clock change could briefly widen or void one window. Upgrade: none
    # worth building; if it ever matters, the fix is monitoring clock sync
    # (scripts/healthcheck.sh already checks it), not a different clock here.
    now = time.time()
    conn = db._get_conn()
    conn.execute(
        "DELETE FROM rate_events WHERE key = ? AND ts < ?",
        (provider, now - window_seconds),
    )
    count, oldest = conn.execute(
        "SELECT COUNT(*), MIN(ts) FROM rate_events WHERE key = ?", (provider,)
    ).fetchone()

    if count < limit_per_min:
        conn.execute(
            "INSERT INTO rate_events (key, ts) VALUES (?, ?)", (provider, now)
        )
        conn.commit()
        return True, 0.0

    # Commit anyway — the eviction above is real work and the deny path must not
    # leave it sitting in an open transaction holding a write lock.
    conn.commit()
    return False, max(0.0, (oldest + window_seconds) - now)


def saturate(provider: str, limit_per_min: int,
             window_seconds: float = WINDOW_SECONDS) -> None:
    """
    Fill <provider>'s window so can_call() denies until it drains naturally.

    Called when a provider returns HTTP 429 mid-chain: it has told us to slow
    down, so stop re-hitting it for the rest of the window instead of letting
    the next queued alert re-learn the 429. Inserts just enough events to reach
    limit_per_min; a no-op if the window is already full.
    """
    now = time.time()
    conn = db._get_conn()
    conn.execute(
        "DELETE FROM rate_events WHERE key = ? AND ts < ?",
        (provider, now - window_seconds),
    )
    count = conn.execute(
        "SELECT COUNT(*) FROM rate_events WHERE key = ?", (provider,)
    ).fetchone()[0]
    to_add = max(0, limit_per_min - count)
    if to_add:
        conn.executemany(
            "INSERT INTO rate_events (key, ts) VALUES (?, ?)",
            [(provider, now)] * to_add,
        )
    conn.commit()
    logger.info("rate_limit saturated: provider=%s (+%d to reach %d)",
                provider, to_add, limit_per_min)


def window_count(provider: str) -> int:
    """Current in-window call count — exposed for diagnostics/KPIs."""
    now = time.time()
    conn = db._get_conn()
    conn.execute(
        "DELETE FROM rate_events WHERE key = ? AND ts < ?",
        (provider, now - WINDOW_SECONDS),
    )
    conn.commit()
    return conn.execute(
        "SELECT COUNT(*) FROM rate_events WHERE key = ?", (provider,)
    ).fetchone()[0]


def reset(provider: str | None = None) -> None:
    """
    Clear the window for <provider>, or for every key if None.
    Intended for tests and for the IT Admin "clear rate limit" button.
    """
    conn = db._get_conn()
    if provider is None:
        conn.execute("DELETE FROM rate_events")
    else:
        conn.execute("DELETE FROM rate_events WHERE key = ?", (provider,))
    conn.commit()
    logger.info("rate_limit reset: provider=%s", provider or "<ALL>")
