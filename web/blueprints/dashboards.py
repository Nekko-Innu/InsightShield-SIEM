# web/blueprints/dashboards.py
# The two role dashboards plus the /dashboard router that sends a user to
# whichever one is theirs.

import logging
from datetime import datetime, timedelta

from flask import Blueprint, redirect, render_template, request, url_for
from flask_login import current_user, login_required

import _request_cache
import cache
import config
import db
import health_score
from decorators import ROLE_MANAGER, role_required
from wazuh_api import get_agent_status
from web.filters import humanize_seconds
from web.responses import dashboard_for_role

logger = logging.getLogger("insightshield.web.dashboards")

bp = Blueprint("dashboards", __name__)


@bp.route("/dashboard/manager")
@login_required
@role_required(ROLE_MANAGER)
def dashboard_manager():
    alerts = db.get_recent_alerts(limit=50)
    score = health_score.calculate()
    agents = get_agent_status()

    # 24h summary — template reads summary.total/.critical/.high/.open.
    recent_24h = db.get_alerts_last_24h()
    summary = {
        "total": len(recent_24h),
        "critical": sum(1 for a in recent_24h if a.get("severity") == "CRITICAL"),
        "high": sum(1 for a in recent_24h if a.get("severity") == "HIGH"),
        "open": sum(
            1 for a in recent_24h
            if not a.get("acknowledged_at")
        ),
    }

    # Devices — template reads devices[].name / .online.
    devices = [
        {"name": ag.get("name", "unknown"),
         "online": (ag.get("status") or "").lower() == "active"}
        for ag in agents
    ]

    return render_template(
        "dashboard_manager.html",
        alerts=alerts,
        health_score=score,
        user=current_user,
        agents=agents,
        summary=summary,
        devices=devices,
    )

ALERTS_PER_PAGE = 50

@bp.route("/dashboard/it")
@login_required
@role_required("IT_ADMIN")
def dashboard_it():
    # 50 keeps page 1 visually identical to the old uncapped-but-truncated
    # table, so nothing about the dashboard's density changes — only that
    # page 2 now exists.
    # Filters and paging run in SQL, not in the browser. The toolbar used to
    # set row.hidden on the 50 rows already rendered, so a CRITICAL that had
    # fallen past row 50 was unreachable by every control on the page.
    # Same request.args -> filters dict -> template convention admin_settings()
    # uses, so the toolbar can round-trip its own state through the URL.
    filters = {
        "status":   request.args.get("status", "").strip(),
        "severity": request.args.get("severity", "").strip(),
        "q":        request.args.get("q", "").strip(),
        "hide_low": request.args.get("hide_low") == "1",
    }
    total = db.count_alerts(
        status=filters["status"] or None,
        severity=filters["severity"] or None,
        q=filters["q"] or None,
        hide_low=filters["hide_low"],
    )
    last_page = max(1, -(-total // ALERTS_PER_PAGE))  # ceil
    try:
        page = int(request.args.get("page", 1))
    except (TypeError, ValueError):
        page = 1
    page = min(max(page, 1), last_page)
    alerts = db.search_alerts(
        status=filters["status"] or None,
        severity=filters["severity"] or None,
        q=filters["q"] or None,
        hide_low=filters["hide_low"],
        limit=ALERTS_PER_PAGE,
        offset=(page - 1) * ALERTS_PER_PAGE,
    )
    # The template hands this to dashboard-it-realtime.js as data-filtered, so
    # a live alert that may not belong on the current page becomes a "N new
    # alerts · Reload" chip instead of a row that ignores the active filter.
    pager = {
        "page": page, "last_page": last_page, "total": total,
        "per_page": ALERTS_PER_PAGE,
        "first_row": (page - 1) * ALERTS_PER_PAGE + 1 if total else 0,
        "last_row": min(page * ALERTS_PER_PAGE, total),
        "filtered": bool(filters["status"] or filters["severity"]
                         or filters["q"] or filters["hide_low"] or page > 1),
    }
    cache_stats = cache.get_stats()
    agents = get_agent_status()

    # health_score.calculate(), db.get_evaluation_metrics() and
    # db.get_severity_breakdown() used to run here too and be passed to the
    # template, which reads none of them — the bar chart fetches
    # /api/severity-breakdown client-side so it can honour the range buttons.
    # Three DB round-trips per dashboard load for nothing.

    # KPI strip — small summary dict the template destructures as kpi.* in dashboard_it.html:39.
    # Whole-table count, not a scan of the 50 rows rendered below it.
    open_count = db.count_open_alerts()
    active_agents = sum(1 for ag in agents if (ag.get("status") or "").lower() == "active")
    # Round D follow-up: render agents as X/Y with the same threshold palette
    # the manager dashboard already uses (100% online → green; exactly 1
    # offline → amber; 2+ offline → red). Empty fleet renders neutral grey.
    agents_total   = len(agents)
    agents_offline = agents_total - active_agents
    if agents_total == 0:
        agents_color = "var(--surface-300)"
    elif agents_offline == 0:
        agents_color = "var(--status-online)"
    elif agents_offline == 1:
        agents_color = "var(--status-degraded)"
    else:
        agents_color = "var(--status-offline)"
    # Row-level average over a 24h window. metrics["response_times"] is still
    # rendered per-severity further down the page; it just no longer feeds a
    # mean-of-means into this tile.
    mtta_secs = db.mtta_seconds(hours=24)
    mtta = humanize_seconds(mtta_secs) if mtta_secs is not None else "—"
    # Count BURST_ABSORBER skips in the last 24h for the Groq KPI tile (F9).
    try:
        today = datetime.now(tz=config.PHT).strftime("%Y-%m-%d")
        yday = (datetime.now(tz=config.PHT) - timedelta(days=1)).strftime("%Y-%m-%d")
        burst_rows = db.search_audit(
            action="BURST_ABSORBER",
            date_from=yday,
            date_to=today,
            limit=5000,
        )
        burst_skipped = len(burst_rows)
    except Exception:
        burst_skipped = 0

    # Dual-namespace cache stats shape (Round 2): cache_stats has 'manager'
    # and 'it_rec' sub-dicts. KPI tile shows the manager-translation hit
    # count — that's the user-facing AI cost saver. IT recommendations are
    # read at most once per alert detail page view; their hit count is less
    # informative for the operations dashboard.
    groq_hits = (cache_stats or {}).get('manager', {}).get('total_hits', 0)
    groq_kpi = f"{groq_hits} hits"
    if burst_skipped:
        groq_kpi += f" · {burst_skipped} skipped (burst)"

    kpi = {
        "open": open_count,
        "mtta": mtta,
        "agents": f"{active_agents}/{agents_total}",
        "agents_color": agents_color,
        "groq": groq_kpi,
    }

    audit_log = db.get_recent_audit(limit=10)

    return render_template(
        "dashboard_it.html",
        alerts=alerts,
        agents=agents,
        kpi=kpi,
        audit_log=audit_log,
        user=current_user,
        filters=filters,
        pager=pager,
        primary_provider_label=_resolve_primary_provider_label(),
    )

def _resolve_primary_provider_label() -> str:
    """
    Round 3: KPI tile label is the first active provider's label, sourced from
    the DB. Falls back to config.PRIMARY_AI_LABEL (env-driven, default "Groq")
    if no providers are active — covers the just-bootstrapped state where
    ai_providers might be empty if the operator hasn't configured anything yet.
    """
    providers = _request_cache.cached_active_providers()
    if providers:
        return providers[0]["label"]
    return config.PRIMARY_AI_LABEL

@bp.route("/dashboard")
@login_required
def dashboard():
    """Role-aware dashboard alias. Templates link to url_for('dashboards.dashboard')."""
    return redirect(url_for(dashboard_for_role()))
