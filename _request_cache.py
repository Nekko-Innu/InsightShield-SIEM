# _request_cache.py
# Insight Shield — Per-request memoisation for hot DB reads.
# Avoids hammering SQLite when notifier.send_X reads three settings during
# a single notification fire-out, or when /dashboard/it reads ai_providers
# four times for KPI tile + chain init + display.
#
# The cache lives on flask.g, which Flask resets per request. Background
# threads (e.g. wazuh_receiver._kick_it_recommendation) run OUTSIDE a
# request context — flask.has_request_context() returns False, and the
# helpers fall through to a direct DB read (uncached). Acceptable: those
# threads run once per alert, not in a hot path.

import flask


def cached_setting(key: str) -> str | None:
    """Return db.get_setting(key) memoised per Flask request."""
    if not flask.has_request_context():
        import db
        return db.get_setting(key)
    cache = flask.g.setdefault("_settings_cache", {})
    if key not in cache:
        import db
        cache[key] = db.get_setting(key)
    return cache[key]


def cached_api_key(service: str, key_name: str = "API_KEY") -> str | None:
    """Return db.get_api_key(service, key_name) memoised per Flask request."""
    if not flask.has_request_context():
        import db
        return db.get_api_key(service, key_name)
    cache = flask.g.setdefault("_api_keys_cache", {})
    composite = (service, key_name)
    if composite not in cache:
        import db
        cache[composite] = db.get_api_key(service, key_name)
    return cache[composite]


def cached_active_providers() -> list[dict]:
    """Return db.get_active_providers_ordered() memoised per Flask request."""
    if not flask.has_request_context():
        import db
        return db.get_active_providers_ordered()
    if "_active_providers" not in flask.g:
        import db
        flask.g._active_providers = db.get_active_providers_ordered()
    return flask.g._active_providers


def cached_alerts_by_range(date_from: str, date_to: str) -> list[dict]:
    """Return db.get_alerts_by_date_range(...) memoised per Flask request.

    /report ran that query FIVE times per render: once directly, then again
    inside each of get_report_summary, get_top_attacker_ips, get_auth_metrics
    and get_posture_score. Each is a full scan of the date window including the
    raw_alert JSON blobs. Same range, same request, same answer.
    """
    if not flask.has_request_context():
        import db
        return db.get_alerts_by_date_range(date_from, date_to)
    cache = flask.g.setdefault("_alerts_by_range", {})
    composite = (date_from, date_to)
    if composite not in cache:
        import db
        cache[composite] = db.get_alerts_by_date_range(date_from, date_to)
    return cache[composite]


def invalidate_request_cache() -> None:
    """
    Clear all per-request caches. Called by Settings POST handlers after a
    write so the same request's later reads see fresh values. Subsequent
    requests get fresh `flask.g` automatically.
    """
    if not flask.has_request_context():
        return
    flask.g.pop("_settings_cache", None)
    flask.g.pop("_api_keys_cache", None)
    flask.g.pop("_active_providers", None)
    # Nothing that calls this writes alerts today, so dropping this one is
    # currently a no-op — but a cache this function knows nothing about is how
    # "invalidate everything" quietly stops meaning that.
    flask.g.pop("_alerts_by_range", None)
