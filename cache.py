# cache.py
# Insight Shield — AI response cache, shared across gunicorn workers.
# Purpose : Cache AI translations by rule_id so that 50 identical DoS alerts
#           = 1 API call, not 50. Prevents rate-limit exhaustion during
#           repeated attacks (Groq free tier: 30 req/min).
# TTL     : 1 hour (3600 seconds) by default. Stale entries are evicted on next
#           read, and swept wholesale by db.purge_old_rows at 03:00.
# Storage : the `ai_cache` table, not process memory. Three dicts meant each
#           worker kept its own copy, so "50 alerts = 1 call" degraded to
#           "1 call per worker" — and a restart threw the whole cache away.
#
# Behaviour change from the in-memory version: entries now survive a restart.
# That is what a cache is for, and it removes the "redeploy = 50 fresh Groq
# calls" cliff. The Settings "clear cache" button is still the escape hatch.

import logging
import time

import config
import db

logger = logging.getLogger("insightshield.cache")

# Namespace keys for the ai_cache.ns column. Manager translations and IT
# recommendations are keyed by rule_id; exec summaries by a digest of
# (date_from, date_to, latest_alert_id_in_range) from
# executive_summary._make_cache_key, so any new alert in range invalidates
# implicitly.
NS_MANAGER = "manager"
NS_ITREC   = "it_rec"
NS_EXEC    = "exec_summary"

TTL = 3600  # 1-hour lifetime per entry per namespace


# ── Manager-translation namespace ────────────────────────────────────────────

def get_cached(rule_id: str) -> str | None:
    """Return cached MANAGER translation for rule_id, or None on miss/expiry."""
    return _get(NS_MANAGER, rule_id)


def set_cached(rule_id: str, text: str, ttl: int = TTL) -> None:
    """Store a MANAGER translation."""
    _set(NS_MANAGER, rule_id, text, ttl)


# ── IT-recommendation namespace ──────────────────────────────────────────────

def get_itrec_cached(rule_id: str) -> str | None:
    """Return cached IT investigation steps for rule_id, or None on miss/expiry."""
    return _get(NS_ITREC, rule_id)


def set_itrec_cached(rule_id: str, text: str, ttl: int = TTL) -> None:
    """Store an IT recommendation."""
    _set(NS_ITREC, rule_id, text, ttl)


# ── Executive-summary namespace ──────────────────────────────────────────────

def get_exec_summary_cached(key: str) -> str | None:
    """Return cached audit-report executive summary, or None on miss/expiry.

    The key is a hex digest from executive_summary._make_cache_key, so the
    namespace API stays string-keyed like the others.
    """
    return _get(NS_EXEC, key)


def set_exec_summary_cached(key: str, text: str, ttl: int = TTL) -> None:
    """Store an executive summary under its date-range/latest-id digest."""
    _set(NS_EXEC, key, text, ttl)


# ── Internals ────────────────────────────────────────────────────────────────

def _get(ns: str, k: str) -> str | None:
    conn = db._get_conn()
    row = conn.execute(
        "SELECT text, ts, expires_at FROM ai_cache WHERE ns = ? AND k = ?", (ns, k)
    ).fetchone()
    if row is None:
        return None
    now = time.time()
    if now >= row["expires_at"]:
        conn.execute("DELETE FROM ai_cache WHERE ns = ? AND k = ?", (ns, k))
        conn.commit()
        logger.debug("Cache EXPIRED (%s): key=%s age=%.0fs", ns, k, now - row["ts"])
        return None
    conn.execute(
        "UPDATE ai_cache SET hits = hits + 1 WHERE ns = ? AND k = ?", (ns, k)
    )
    conn.commit()
    logger.debug("Cache HIT (%s): key=%s age=%.0fs", ns, k, now - row["ts"])
    return row["text"]


def _set(ns: str, k: str, text: str, ttl: int = TTL) -> None:
    # _ai_chain negative-caches a fully exhausted provider chain through this
    # same setter, so a failure is not remembered for an hour the way a real
    # answer is. Special-cased here rather than at the call site because all
    # three namespaces write through the same three public setters.
    if text == config.AI_CHAIN_EXHAUSTED:
        ttl = config.AI_NEGATIVE_CACHE_S
    now = time.time()
    conn = db._get_conn()
    # INSERT OR REPLACE rather than an upsert that preserves hits: a replaced
    # entry is a different answer, so its hit count starts over.
    conn.execute(
        "INSERT OR REPLACE INTO ai_cache (ns, k, text, ts, expires_at, hits) "
        "VALUES (?, ?, ?, ?, ?, 0)",
        (ns, k, text, now, now + ttl),
    )
    conn.commit()
    logger.debug("Cache SET (%s): key=%s ttl=%ds", ns, k, ttl)


# ── Maintenance ──────────────────────────────────────────────────────────────

def invalidate(rule_id: str) -> bool:
    """Manually remove a single entry from ALL namespaces. Returns True if any existed.

    Also clears the exec-summary namespace so an admin who resets a cache entry
    by rule_id doesn't leave a stale audit-report summary behind.
    """
    conn = db._get_conn()
    n = conn.execute("DELETE FROM ai_cache WHERE k = ?", (rule_id,)).rowcount
    conn.commit()
    return n > 0


def clear_all() -> int:
    """Remove all entries from ALL namespaces. Returns total count removed."""
    conn = db._get_conn()
    count = conn.execute("DELETE FROM ai_cache").rowcount
    conn.commit()
    logger.info("Cache cleared: %d entries removed (manager + it_rec + exec_summary)", count)
    return count


def get_stats() -> dict:
    """
    Return per-namespace cache statistics. Shape is unchanged from the
    in-memory version — /api/cache-stats, the Settings cache panel and the IT
    dashboard's Groq KPI tile all destructure it:

        {
            "manager":      {"entries": N, "total_hits": M, "rule_ids": [...]},
            "it_rec":       {"entries": N, "total_hits": M, "rule_ids": [...]},
            "exec_summary": {"entries": N, "total_hits": M, "keys": [...]},
            "ttl_seconds":  3600,
        }
    """
    conn = db._get_conn()
    rows = conn.execute(
        "SELECT ns, k, hits FROM ai_cache WHERE expires_at > ?", (time.time(),)
    ).fetchall()

    def _ns(ns: str, key_field: str) -> dict:
        mine = [r for r in rows if r["ns"] == ns]
        return {
            "entries":    len(mine),
            "total_hits": sum(r["hits"] for r in mine),
            key_field:    [r["k"] for r in mine],
        }

    return {
        "manager":      _ns(NS_MANAGER, "rule_ids"),
        "it_rec":       _ns(NS_ITREC, "rule_ids"),
        "exec_summary": _ns(NS_EXEC, "keys"),
        "ttl_seconds":  TTL,
    }
