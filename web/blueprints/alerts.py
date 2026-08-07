# web/blueprints/alerts.py
# Alert detail, acknowledge and resolve.

import logging

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

import db
import notifier
from decorators import role_required
from web.responses import dashboard_for_role

logger = logging.getLogger("insightshield.web.alerts")

bp = Blueprint("alerts", __name__)


@bp.route("/alert/<int:alert_id>")
@login_required
def alert_detail(alert_id):
    alert = db.get_alert(alert_id)
    if alert is None:
        flash("Alert not found.", "error")
        return redirect(url_for(dashboard_for_role()))
    return render_template(
        "alert_detail.html",
        alert=alert,
        user=current_user,
    )

@bp.route("/alert/<int:alert_id>/it-acknowledge", methods=["POST"], endpoint="it_acknowledge")
@login_required
@role_required("IT_ADMIN")
def it_acknowledge_alias(alert_id):
    """Alias for the canonical IT-ACK route. Template calls url_for('alerts.it_acknowledge').
    Decorated explicitly even though it delegates to `acknowledge` (also
    decorated) so the role gate is visible at the route definition itself."""
    return acknowledge(alert_id)

# Not a route any more. /alert/<id>/acknowledge was the pre-Round-8 URL and
# nothing links to it — it_acknowledge_alias calls this function directly. A
# second URL onto the same state change is a second thing to keep gated.
@login_required
@role_required("IT_ADMIN")
def acknowledge(alert_id):
    wants_json = request.accept_mimetypes.best == "application/json"

    def _respond(ok: bool, message: str, category: str, status: int = 200):
        if wants_json:
            return jsonify({"success": ok, "message": message}), status
        flash(message, category)
        return redirect(url_for("alerts.alert_detail", alert_id=alert_id))

    result = db.acknowledge_alert(alert_id, current_user.username)
    if result:
        # Nothing to cancel: the escalation sweep re-reads acknowledged from the
        # alerts table, so setting it here is what stops the escalation. The old
        # cancel call only worked in whichever worker had registered the job.
        db.log_audit(
            action="ALERT_ACKNOWLEDGED",
            actor=current_user.username,
            actor_role=current_user.role,
            target=f"alert:{alert_id}",
            ip=request.remote_addr,
        )
        return _respond(True, "Alert acknowledged successfully.", "success")
    return _respond(False, "Alert already acknowledged or not found.", "warning", 404)

@bp.route("/alert/<int:alert_id>/resolve", methods=["POST"])
@login_required
@role_required("IT_ADMIN")
def resolve_alert(alert_id):
    """
    Mark an IT-acknowledged alert as resolved (case closed). IT_ADMIN only.
    Requires the alert to already be IT-acknowledged (acknowledged=1).
    """
    wants_json = request.accept_mimetypes.best == "application/json"

    def _respond(ok: bool, message: str, status: int = 200):
        if wants_json:
            return jsonify({"success": ok, "message": message}), status
        flash(message, "success" if ok else "warning")
        return redirect(url_for("alerts.alert_detail", alert_id=alert_id))

    note = request.form.get("resolve_note", "").strip()
    result = db.resolve_alert(alert_id, current_user.username, note=note)
    if result:
        resolved = db.get_alert(alert_id)
        if resolved:
            # Best-effort notify manager; failure returns False and does not
            # affect the resolve path (audit log still fires below).
            notifier.send_manager_resolution_notification(resolved)
        logger.info("Alert resolved %s by %s", alert_id, current_user.username)
        db.log_audit(
            action="ALERT_RESOLVED",
            actor=current_user.username,
            actor_role=current_user.role,
            target=f"alert:{alert_id}",
            ip=request.remote_addr,
            details={"note": note[:200]} if note else None,
        )
        return _respond(True, "Alert marked as resolved.")
    return _respond(
        False,
        "Alert must be IT-acknowledged before resolving, or is already resolved.",
        400,
    )
