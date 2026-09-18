# web/blueprints/dashboards.py
# The two role dashboards plus the /dashboard router that sends a user to
# whichever one is theirs.

import logging
from datetime import datetime, timedelta

from flask import Blueprint, redirect, render_template, request, session, url_for
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

ALERTS_PER_PAGE = 50

# The filter keys a toolbar submit carries. `applied` is the marker the shared
# _alert_filters.html form adds so we can tell a real submit from a bare nav.
_FILTER_KEYS = ("status", "severity", "q", "hide_low")


def _alert_filters_from_request() -> dict:
    """Read the alert-list filters, persisted per session so they survive
    navigation — the fix for "Hide low severity" reverting when you open an
    alert or hit another page.

    - applied=1 (a real toolbar submit) -> authoritative from args, saved to
      the session (records hide_low=False when unchecked, which sends no field).
    - no filter params at all (a bare nav / Dashboard link) -> load the
      remembered filters from the session.
    - some params but no marker (a shared/deep link) -> honour the params
      present, but don't overwrite the saved preference.
    """
    args = request.args

    def _from_args() -> dict:
        return {
            "status":   args.get("status", "").strip(),
            "severity": args.get("severity", "").strip(),
            "q":        args.get("q", "").strip(),
            "hide_low": args.get("hide_low") == "1",
        }

    if args.get("applied") == "1":
        filters = _from_args()
        session["alert_filters"] = filters
        return filters
    if not any(k in args for k in _FILTER_KEYS):
        saved = session.get("alert_filters") or {}
        return {
            "status":   saved.get("status", ""),
            "severity": saved.get("severity", ""),
            "q":        saved.get("q", ""),
            "hide_low": bool(saved.get("hide_low", False)),
        }
    return _from_args()


def _alerts_pager_filtered(filters: dict, page: int = 1) -> bool:
    """Whether any filter (or a non-first page) is active — drives the Clear link."""
    return bool(filters["status"] or filters["severity"]
                or filters["q"] or filters["hide_low"] or page > 1)


def _focus_mode() -> bool:
    """Admin's Focus Mode switch — only relabels the Hide-low button here; the
    filtering itself happens in db._alert_filter_clauses."""
    return _request_cache.cached_setting("alert_focus_mode") == "1"


def _build_pager(filters: dict, last_page: int, total: int) -> dict:
    """The `pager` dict templates/_pager.html reads, plus the clamped page.

    Both dashboards page the same table with the same filters and the same
    per-page count, so the ?page= parsing and the six derived numbers live
    here rather than being written twice — the manager copy of this arithmetic
    is what was missing while its feed was stuck on offset=0.
    """
    try:
        page = int(request.args.get("page", 1))
    except (TypeError, ValueError):
        page = 1
    page = min(max(page, 1), last_page)
    return {
        "page": page, "last_page": last_page, "total": total,
        "per_page": ALERTS_PER_PAGE,
        "first_row": (page - 1) * ALERTS_PER_PAGE + 1 if total else 0,
        "last_row": min(page * ALERTS_PER_PAGE, total),
        "filtered": _alerts_pager_filtered(filters, page),
    }


@bp.route("/dashboard/manager")
@login_required
@role_required(ROLE_MANAGER)
def dashboard_manager():
    # Server-side filtering and paging, same db.search_alerts path as the IT
    # dashboard, filters persisted per session.
    #
    # The feed used to be a single 50-row window: limit=50, offset=0, no page
    # parameter and a `pager` dict holding one flag. So an alert that fell past
    # row 50 was counted in every tile on the page and could not be opened from
    # it — the manager's only route to it was a filter narrow enough to pull it
    # back inside the window. It now pages like the IT table.
    filters = _alert_filters_from_request()
    total = db.count_alerts(
        status=filters["status"] or None,
        severity=filters["severity"] or None,
        q=filters["q"] or None,
        hide_low=filters["hide_low"],
    )
    last_page = max(1, -(-total // ALERTS_PER_PAGE))  # ceil
    pager = _build_pager(filters, last_page, total)
    alerts = db.search_alerts(
        status=filters["status"] or None,
        severity=filters["severity"] or None,
        q=filters["q"] or None,
        hide_low=filters["hide_low"],
        limit=ALERTS_PER_PAGE,
        offset=(pager["page"] - 1) * ALERTS_PER_PAGE,
    )
    score = health_score.calculate()
    agents = get_agent_status()

    # 24h summary — template reads summary.total/.critical/.high/.open.
    recent_24h = db.get_alerts_last_24h()
    summary = {
        "total": len(recent_24h),
        "critical": sum(1 for a in recent_24h if a.get("severity") == "CRITICAL"),
        "high": sum(1 for a in recent_24h if a.get("severity") == "HIGH"),
        # "Open" means not resolved — matching db.count_open_alerts and the IT
        # dashboard. Keyed on resolved_at (not acknowledged_at) so auto-closed
        # sub-HIGH alerts drop out of the count and an acked-but-unresolved
        # HIGH/CRITICAL still shows as open work.
        "open": sum(
            1 for a in recent_24h
            if not a.get("resolved_at")
        ),
    }

    # Agents — the template used to count these itself with
    # selectattr('status', 'equalto', 'active'), a case-SENSITIVE compare,
    # while this route lowercased the same field to build a `devices` list the
    # template never rendered. One Wazuh agent reporting "Active" and the tile
    # under-reported the fleet in red on a healthy branch. Counted once, here,
    # the same way dashboard_it does it.
    agents_total = len(agents)
    agents_online = sum(1 for ag in agents if (ag.get("status") or "").lower() == "active")

    # The feed's poll baseline. It used to be `alerts[0].id` in the template —
    # fine while the page was always the newest 50 rows, wrong the moment the
    # feed can page: on page 2 the first row is not the newest alert, so the
    # 15s poll compared the table's MAX(id) against a mid-table id, found them
    # different every single time, and would have toasted "new alert" forever.
    # Same value /api/alerts/latest returns, so an unchanged table compares
    # equal.
    latest_alert_id = db.get_latest_alert_id() or ""

    # `devices` and `user` are gone from this context: nothing in the template
    # read either (it uses current_user from the base layout).
    return render_template(
        "dashboard_manager.html",
        alerts=alerts,
        health_score=score,
        agents_online=agents_online,
        agents_total=agents_total,
        summary=summary,
        filters=filters,
        pager=pager,
        focus_mode=_focus_mode(),
        latest_alert_id=latest_alert_id,
    )


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
    # Filters now come from the shared helper, which persists them in the
    # session — so "Hide low severity" (and the rest) survive opening an alert
    # or clicking a bare Dashboard link, instead of reverting on every nav.
    filters = _alert_filters_from_request()
    total = db.count_alerts(
        status=filters["status"] or None,
        severity=filters["severity"] or None,
        q=filters["q"] or None,
        hide_low=filters["hide_low"],
    )
    last_page = max(1, -(-total // ALERTS_PER_PAGE))  # ceil
    # The template hands pager.filtered to dashboard-it-realtime.js as
    # data-filtered, so a live alert that may not belong on the current page
    # becomes a "N new alerts · Reload" chip instead of a row that ignores the
    # active filter.
    pager = _build_pager(filters, last_page, total)
    alerts = db.search_alerts(
        status=filters["status"] or None,
        severity=filters["severity"] or None,
        q=filters["q"] or None,
        hide_low=filters["hide_low"],
        limit=ALERTS_PER_PAGE,
        offset=(pager["page"] - 1) * ALERTS_PER_PAGE,
    )
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
    # 24h MTTA. The count-of-awaiting tile that briefly replaced it just
    # mirrored the Open-alerts backlog, so it's back to the mean time. On a
    # window where nothing serious was acked yet, show "Awaiting acknowledge"
    # rather than a bare "—" so a quiet tile reads as pending, not broken.
    mtta = db.mtta_seconds(24)
    mtta_display = humanize_seconds(mtta) if mtta is not None else "Awaiting acknowledge"
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
        "mtta": mtta_display,
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
        focus_mode=_focus_mode(),
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
