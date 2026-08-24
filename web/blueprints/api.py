# web/blueprints/api.py
# The JSON endpoints the dashboards poll, plus /health.

import logging

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

import agent_status as agent_status_mod
import cache
import db
import health_score
import rate_limit
from alerts_util import build_severity_array
from decorators import ROLE_IT_ADMIN, role_required
from wazuh_api import get_agent_status
from web.responses import rate_limited_response

logger = logging.getLogger("insightshield.web.api")

bp = Blueprint("api", __name__)


@bp.route("/api/alerts/latest")
@login_required
def alerts_latest():
    """Latest-alert-id probe for manager dashboard polling (ui.js 15s tick)."""
    return jsonify({"latest_id": db.get_latest_alert_id() or 0})

@bp.route("/health")
def health():
    """
    Unauthenticated liveness probe for gunicorn / nginx / systemd health checks.

    Deliberately lightweight: no DB hit, no session, no logging on the hot path.
    Useful for `curl http://127.0.0.1:5000/health` during deployment verification
    and for nginx upstream availability monitoring.
    """
    return jsonify({"status": "ok", "version": "1.0"}), 200

@bp.route("/api/client-error", methods=["POST"])
@login_required
def api_client_error():
    """
    Browser-side error beacon (static/ui.js window.onerror / unhandledrejection
    listeners). Lands in the same error_log table as backend exceptions so
    the Settings -> Errors tab covers both sides of the app. Rate-limited per
    user so a broken page stuck in a JS error loop can't flood the table.
    """
    allowed, _ = rate_limit.can_call(f"client_error:{current_user.username}", limit_per_min=10)
    if not allowed:
        return jsonify({"status": "rate_limited"}), 429

    payload = request.get_json(silent=True) or {}
    db.log_error(
        source="client",
        module=(payload.get("url") or "")[:200],
        exc_type="ClientError",
        message=payload.get("message"),
        path=payload.get("url"),
        actor=current_user.username,
        traceback=payload.get("stack"),
    )
    return jsonify({"status": "logged"}), 200

@bp.route("/api/alert/<int(min=1, max=2147483647):alert_id>")
@login_required
@role_required(ROLE_IT_ADMIN)
def api_alert(alert_id):
    """
    Return alert data as JSON. IT_ADMIN only.

    This is `jsonify(db.get_alert(id))` — the entire 21-column row, including
    raw_alert, ai_reasoning, it_recommendation and attack_trail. It was
    login_required-only, so a Manager could walk ids 1..N (upper bound handed
    out free by /api/alerts/latest) and pull every alert's full forensic record
    as clean JSON, bypassing the IT_ADMIN gating alert_detail.html applies to
    exactly those fields. The docstring claimed a "manager popup modal"; no such
    consumer exists anywhere in static/ or templates/.
    """
    alert = db.get_alert(alert_id)
    if alert is None:
        return jsonify({"error": "Not found"}), 404
    return jsonify(alert)

@bp.route("/api/severity-breakdown")
@login_required
@role_required("IT_ADMIN")
def api_severity_breakdown():
    """Return severity counts as a JSON array (crit -> info) for a given
    time range. IT_ADMIN only.

    Round 6: shape changed from dict to array per master spec Part 6 so
    clients render in fixed order without sorting. Each entry carries the
    rule-level range it covers, sourced from wazuh_receiver.LEVEL_MAP.
    """
    range_map = {
        "24h": 24,
        "3d":  72,
        "7d":  168, "1w": 168,   # "7d" is the dashboard UI label; "1w" kept for back-compat
        "30d": 720, "1m": 720,   # "30d" likewise; "1m" kept for back-compat
        "6m":  4320,
        "1y":  8760,
    }
    requested = request.args.get("range", "24h").lower()
    hours = range_map.get(requested, 24)

    breakdown = db.get_severity_breakdown(hours=hours)
    return jsonify(build_severity_array(breakdown))

@bp.route("/api/health-score")
@login_required
@role_required(ROLE_IT_ADMIN)
def api_health_score():
    # No consumer in static/ or templates/ — the manager dashboard renders the
    # score server-side. Gated rather than deleted in case an operator scripts
    # against it.
    return jsonify({"health_score": health_score.calculate()})

@bp.route("/api/cache-stats")
@login_required
@role_required("IT_ADMIN")
def api_cache_stats():
    return jsonify(cache.get_stats())

# Round 8: spec lists /api/agents under "Manager-blocked (403)". Pre-Round-8
# this route had no role check at all (manager could see the per-agent list);
# the decorator closes that gap. /api/status remains public for the login
# page indicator.
@bp.route("/api/agents")
@login_required
@role_required("IT_ADMIN")
def api_agents():
    return jsonify(get_agent_status())

# Round 5: Public agent-status snapshot. NO @login_required — the login
# page itself polls this every 30s, so authentication would defeat the
# purpose. The snapshot lives in the settings table, written by the 30s
# scheduler job; this handler does one indexed read and never touches Wazuh.
# A snapshot older than agent_status.STALE_AFTER_S reads as red rather than
# as whatever the dead writer last said.
@bp.route("/api/status")
def api_status():
    # Anonymous and cheap, but anonymous and unbounded is a free amplifier.
    # The login page polls every 30s; 30/min is ~15x that.
    allowed, retry_after = rate_limit.can_call(
        f"status:{request.remote_addr}", limit_per_min=30
    )
    if not allowed:
        return rate_limited_response(retry_after)

    snap = agent_status_mod.get_snapshot()
    # Hide the per-agent list from the public payload — keep it to
    # coarse counts + summary text. Names already leak via the login
    # page's known_devices list, so the trade-off is conscious; if a
    # future round needs the per-agent list, add an authed /api/agents
    # consumer instead of widening the public payload.
    return jsonify({
        "manager_status": snap.get("manager_status"),
        "summary":        snap.get("summary"),
        "dot_color":      snap.get("dot_color"),
        "agents_online":  snap.get("agents_online"),
        "agents_total":   snap.get("agents_total"),
        "updated_at":     snap.get("updated_at"),
    })
