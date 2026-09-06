# web/blueprints/reports.py
# The security report (HTML + PDF) and the alerts CSV export.

import logging
from datetime import datetime, timedelta

from flask import (
    Blueprint, Response, flash, redirect, render_template, request, url_for,
)
from flask_login import current_user, login_required
from markupsafe import escape

import _request_cache
import config
import db
import rate_limit
from decorators import role_required
from wazuh_api import get_agent_status
from web.responses import csv_safe, rate_limited_response, reject_csv_flood


def _report_detail_alerts(alerts: list[dict]) -> tuple[list[dict], int]:
    """Actionable (HIGH/CRITICAL) alerts for the report's itemized sections.

    An audit report summarises everything but itemises only what needed action,
    so the per-alert Alert Details + raw-JSON appendix are scoped to HIGH/CRITICAL
    and capped at config.REPORT_DETAIL_CAP — otherwise a busy period (or the
    login-noise flood) renders hundreds of pages. `alerts` arrives newest-first
    (db.get_alerts_by_date_range orders timestamp DESC). Returns
    (capped_list, total_actionable) so the template can show "N of M".
    """
    actionable = [a for a in alerts
                  if (a.get("severity") or "").upper() in config.ACTIONABLE_SEVERITIES]
    return actionable[:config.REPORT_DETAIL_CAP], len(actionable)

logger = logging.getLogger("insightshield.web.reports")

bp = Blueprint("reports", __name__)


def _clamp_report_range(date_from: str, date_to: str) -> tuple[str, str, bool]:
    """
    Bound a report date range to config.REPORT_MAX_RANGE_DAYS.

    Returns (from, to, was_clamped). Unparseable input is left alone — the DB
    layer already treats it as a plain string comparison — so this only ever
    narrows a range it fully understands.
    """
    fmt = "%Y-%m-%d"
    max_days = config.REPORT_MAX_RANGE_DAYS
    try:
        start = datetime.strptime(date_from, fmt)
        end = datetime.strptime(date_to, fmt)
    except (TypeError, ValueError):
        # Unparseable input is clamped to the default window, NOT passed
        # through. It used to be returned untouched on the reasoning that the
        # DB layer treats it as a plain string — but that is exactly why it was
        # dangerous: get_alerts_by_date_range builds "{date_from}T00:00:00" and
        # compares lexicographically, so `?from=0&to=9` selects every row ever
        # stored ('2026-…' sorts between '0' and '9'). That turned the one
        # control meant to bound this query into a no-op for any input the
        # parser rejects, and /report is reachable by a manager with no rate
        # limit, reading every raw_alert blob into memory.
        end = datetime.now()
        start = end - timedelta(days=max_days)
        return start.strftime(fmt), end.strftime(fmt), True

    if end < start:
        start, end = end, start
    if (end - start).days <= max_days:
        return start.strftime(fmt), end.strftime(fmt), False
    return (end - timedelta(days=max_days)).strftime(fmt), end.strftime(fmt), True

@bp.route("/export.csv")
@login_required
@role_required("IT_ADMIN")
def export_csv():
    """IT-only CSV export of recent alerts. Column set mirrors dashboard table."""
    import csv
    import io
    rejected = reject_csv_flood()
    if rejected:
        return rejected
    # No row cap. This used to pass limit=1000 and then log `row_count` as if
    # the file were complete, so an export covering more than 1000 alerts was
    # silently truncated with nothing in the file or the audit trail saying so.
    # This is an evidence-export path; a slow complete answer beats a fast
    # partial one that looks complete.
    rows = db.get_all_alerts()
    cols = ["id", "timestamp", "severity", "device_name", "attack_type",
            "plain_text", "ai_reasoning", "provider_used", "acknowledged"]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for a in rows:
        row = dict(a) if not isinstance(a, dict) else a
        w.writerow([csv_safe(row.get(k, "")) for k in cols])
    db.log_audit(
        action="EXPORT_CSV",
        actor=current_user.username,
        actor_role=current_user.role,
        target="alerts",
        ip=request.remote_addr,
        details={"row_count": len(rows), "truncated": False},
    )
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=insightshield-alerts.csv"},
    )

@bp.route("/report")
@login_required
def report():
    """
    Security Audit Report. Round 7: open to BOTH IT_ADMIN and Manager.
    Query params: ?from=2026-04-01&to=2026-04-17 (default last 7 days).

    Round G (§18): the executive-summary AI chain only fires when
    ?generated=1 is also present — i.e., when the user explicitly
    clicked the Generate button (its hidden input bakes the flag into
    the GET query). A bare /report visit (no params, or only
    from/to) renders an empty document with a 'Pick a range and click
    Generate' CTA, skipping the 6 SELECT round-trips and the AI chain
    entirely. Stops the AI chain from auto-running on every page load.

    Sections (rendered by templates/report.html, only when generated=1):
      - Executive Summary (H2) — AI-generated, cached 1h by date+latest-id
      - Summary Metrics (H2) — total, top-3 threats, posture score
      - Agent Compliance & Health (H2)
      - Incident Breakdown (H2) — severity, top attacker IPs, auth metrics
      - Vulnerability Detection (H2) — conditional on Wazuh VA data
    """
    today = datetime.now(tz=config.PHT).strftime("%Y-%m-%d")
    week_ago = (datetime.now(tz=config.PHT) - timedelta(days=7)).strftime("%Y-%m-%d")

    date_from = request.args.get("from", week_ago)
    date_to = request.args.get("to", today)
    # Clamped here, before anything reads the range. /report.pdf always did this
    # and /report did not, so an over-long range produced a different
    # latest_alert_id_in_range on each route — a different exec-summary cache
    # key, and therefore a second full AI call for the PDF that could never
    # reuse the one the HTML page had just paid for.
    date_from, date_to, clamped = _clamp_report_range(date_from, date_to)
    if clamped:
        logger.info(
            "report range clamped to %d days for %s: %s..%s",
            config.REPORT_MAX_RANGE_DAYS, current_user.username, date_from, date_to,
        )
        flash(
            f"Date range narrowed to the most recent "
            f"{config.REPORT_MAX_RANGE_DAYS} days.", "info",
        )
    # Round G gate flag — set by the hidden <input name="generated"
    # value="1"> in the Generate form (templates/report.html). Without
    # it, no DB queries fire and no AI chain runs.
    generated = request.args.get("generated") == "1"

    # Every /report hit is audit-logged for chain-of-custody, including
    # bare visits to the empty-state CTA. The `generated` flag is
    # captured in details so reviewers can distinguish CTA views from
    # full-report renders.
    db.log_audit(
        action="REPORT_VIEW",
        actor=current_user.username,
        actor_role=current_user.role,
        target="report",
        ip=request.remote_addr,
        details={"from": date_from, "to": date_to, "generated": generated},
    )

    if not generated:
        return render_template(
            "report.html",
            generated=False,
            date_from=date_from,
            date_to=date_to,
            generated_at=datetime.now(tz=config.PHT).isoformat(),
            user=current_user,
        )

    # Through the request cache, not db directly: get_report_summary,
    # get_top_attacker_ips, get_auth_metrics and get_posture_score below each
    # read the same date window internally, so this one render used to run the
    # same full scan — raw_alert JSON blobs included — five times. All six now
    # share one result for the life of the request.
    alerts = _request_cache.cached_alerts_by_range(date_from, date_to)
    summary = db.get_report_summary(date_from, date_to)
    top_threats = db.get_top_threats(date_from, date_to, n=3)
    top_attacker_ips = db.get_top_attacker_ips(date_from, date_to, n=5)
    auth_metrics = db.get_auth_metrics(date_from, date_to)
    posture_score = db.get_posture_score(date_from, date_to)
    latest_alert_id = db.get_latest_alert_id_in_range(date_from, date_to)
    agents = get_agent_status()

    # Executive summary — third caller of _ai_chain.run_chain. Cache hit
    # when (date_from, date_to, latest_alert_id) matches a prior call;
    # any new in-range alert bumps latest_alert_id and forces a refresh.
    import executive_summary as exec_summary
    summary_text, summary_provider = exec_summary.generate(
        date_from=date_from,
        date_to=date_to,
        summary=summary,
        top_threats=top_threats,
        posture_score=posture_score,
        latest_alert_id=latest_alert_id,
    )

    detail_alerts, detail_total = _report_detail_alerts(alerts)

    return render_template(
        "report.html",
        generated=True,
        alerts=alerts,
        detail_alerts=detail_alerts,
        detail_total=detail_total,
        detail_cap=config.REPORT_DETAIL_CAP,
        summary=summary,
        top_threats=top_threats,
        top_attacker_ips=top_attacker_ips,
        auth_metrics=auth_metrics,
        posture_score=posture_score,
        agents=agents,
        exec_summary_text=summary_text,
        exec_summary_provider=summary_provider,
        date_from=date_from,
        date_to=date_to,
        generated_at=datetime.now(tz=config.PHT).isoformat(),
        user=current_user,
    )

@bp.route("/report.pdf")
@login_required
def report_pdf():
    """
    Render /report HTML in-process, drive headless Chromium to PDF.
    Round G §18 stage G3.

    Reuses /report's data-prep and ?generated=1 gating verbatim — a
    bare /report.pdf without the flag returns a PDF showing only the
    cover and empty-state CTA (no DB queries, no AI chain). With the
    flag, the full document renders: cover (page 1), TOC (page 2),
    Executive Summary, Summary Metrics, NIST CSF 2.0 — Detect,
    Alert Details, Appendix A — Raw Wazuh JSON.

    Implementation notes:
      - Synchronous Playwright API. Blocks the request worker for the
        duration of Chromium launch + render + PDF generation. Cold
        start ~2s, warm cache ~500ms. Acceptable for the single-user
        thesis app under gunicorn workers >= 2.
      - In-process render_template + page.set_content avoids the auth
        dance — Playwright never holds a session cookie, never has
        to round-trip through @login_required for the report route.
      - <base href="..."> injection: relative /static/* URLs in the
        rendered HTML resolve against the running Flask server when
        Chromium fetches them. Without this, set_content's resource
        loader treats relative URLs as relative to about:blank and
        drops them.
      - emulate_media(media="print") is critical: cover/TOC page
        breaks live in @media print only. Without this call screen
        styles win and the PDF renders as one continuous page.
      - print_background=True carries through the navy --brand-500
        accent bar on the cover, the badge fills, and the Appendix A
        dark-bg JSON pre. Without it, all backgrounds default white.

    Per-host one-time setup:
        pip install playwright>=1.45
        python -m playwright install chromium
    """
    today = datetime.now(tz=config.PHT).strftime("%Y-%m-%d")
    week_ago = (datetime.now(tz=config.PHT) - timedelta(days=7)).strftime("%Y-%m-%d")

    date_from = request.args.get("from", week_ago)
    date_to = request.args.get("to", today)
    generated = request.args.get("generated") == "1"

    # Each request launches a Chromium process synchronously and holds a worker
    # thread for the whole render. The route is login_required-only, so a
    # Manager can drive it, and an unclamped range (?from=1970-01-01) renders
    # every alert ever plus the full raw-JSON appendix into one process. Two
    # limits: N per minute per user, and a bounded span.
    allowed, retry_after = rate_limit.can_call(
        f"report_pdf:{current_user.username}",
        limit_per_min=config.REPORT_PDF_PER_MIN,
    )
    if not allowed:
        return rate_limited_response(retry_after)

    date_from, date_to, clamped = _clamp_report_range(date_from, date_to)
    if clamped:
        logger.info(
            "report.pdf range clamped to %d days for %s: %s..%s",
            config.REPORT_MAX_RANGE_DAYS, current_user.username, date_from, date_to,
        )

    # Build the same template context /report builds. The duplication
    # is deliberate — extracting a helper would couple the two routes
    # and risk drift in the gating logic. Two ~30-line setups is
    # cheaper to maintain than one 50-line abstraction.
    context = {
        "generated": generated,
        "date_from": date_from,
        "date_to": date_to,
        "generated_at": datetime.now(tz=config.PHT).isoformat(),
        "user": current_user,
    }
    if generated:
        context["alerts"] = _request_cache.cached_alerts_by_range(date_from, date_to)
        context["detail_alerts"], context["detail_total"] = _report_detail_alerts(context["alerts"])
        context["detail_cap"] = config.REPORT_DETAIL_CAP
        context["summary"] = db.get_report_summary(date_from, date_to)
        context["top_threats"] = db.get_top_threats(date_from, date_to, n=3)
        context["top_attacker_ips"] = db.get_top_attacker_ips(date_from, date_to, n=5)
        context["auth_metrics"] = db.get_auth_metrics(date_from, date_to)
        context["posture_score"] = db.get_posture_score(date_from, date_to)
        context["agents"] = get_agent_status()
        latest_alert_id = db.get_latest_alert_id_in_range(date_from, date_to)
        import executive_summary as exec_summary
        text, provider = exec_summary.generate(
            date_from=date_from,
            date_to=date_to,
            summary=context["summary"],
            top_threats=context["top_threats"],
            posture_score=context["posture_score"],
            latest_alert_id=latest_alert_id,
        )
        context["exec_summary_text"] = text
        context["exec_summary_provider"] = provider

    html = render_template("report.html", **context)
    # See implementation notes in docstring re: <base> injection.
    #
    # This used to interpolate request.host_url, which derives from the Host
    # header — and ProxyFix(x_host=1) makes a client-supplied X-Forwarded-Host
    # authoritative, with no SERVER_NAME allowlist to check it against. A forged
    # header would point headless Chromium at an attacker origin for every
    # relative /static/* URL in the report: attacker CSS/JS executing inside the
    # renderer with the report content in the DOM. Pin to configured value.
    html = html.replace(
        "<head>",
        f'<head>\n  <base href="{escape(config.REPORT_ASSET_BASE_URL)}">',
        1,
    )

    from playwright.sync_api import sync_playwright

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            try:
                page = browser.new_page()
                page.set_content(html, wait_until="networkidle")
                # Force-open every <details> on the page so collapsed
                # sections — most importantly Appendix A's per-alert raw
                # JSON entries — render their content in the PDF. Without
                # this, the appendix shows only the summary lines and the
                # forensic payloads are missing.
                page.evaluate(
                    "document.querySelectorAll('details').forEach(d => d.setAttribute('open', ''))"
                )
                page.emulate_media(media="print")
                pdf_bytes = page.pdf(
                    format="A4",
                    print_background=True,
                    # Round G follow-up: honour @page size:A4 + margins
                    # declared in static/report-bureau.css's Marker block
                    # (18mm/16mm/22mm). Without this Chromium would default
                    # to Letter-ish dimensions and ignore the @page rule.
                    prefer_css_page_size=True,
                    margin={
                        "top": "1.5cm",
                        "bottom": "1.5cm",
                        "left": "1.5cm",
                        "right": "1.5cm",
                    },
                    display_header_footer=False,
                )
            finally:
                browser.close()
    except Exception as e:
        import traceback as _tb
        logger.error("report.pdf generation failed: %s", e)
        db.log_error(
            # request.endpoint, not a hand-written label: this was pinned to
            # "app.report_pdf" and kept saying it after the route left app.py,
            # so this one row never matched the Errors tab's Module filter.
            # web/errors.py's global handler already logs the same way.
            source="server", module=request.endpoint,
            exc_type=type(e).__name__, message=str(e),
            path=request.path, actor=current_user.username,
            traceback=_tb.format_exc(),
        )
        flash("PDF generation failed — the browser engine may not be installed. Contact IT.", "error")
        return redirect(url_for("reports.report", **{"from": date_from, "to": date_to}))

    db.log_audit(
        action="REPORT_PDF_EXPORT",
        actor=current_user.username,
        actor_role=current_user.role,
        target="report.pdf",
        ip=request.remote_addr,
        details={"from": date_from, "to": date_to, "generated": generated},
    )

    filename = f"insightshield-audit-{date_from}_{date_to}.pdf"
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
