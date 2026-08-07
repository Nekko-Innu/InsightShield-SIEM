# web/hooks.py
# before_request hooks: the must_change_password gate and the audit middleware.
#
# ORDER: web.csrf.init_app must run BEFORE this module's init_app. Flask calls
# before_request functions in registration order, so if the audit hook were
# registered first, a request rejected for a bad CSRF token would still be
# written to audit_log as though it had succeeded.

from flask import flash, jsonify, redirect, request, url_for
from flask_login import current_user

import db
from decorators import _is_machine_path

# Log every mutating request made by an authenticated user. High-frequency
# polling endpoints are excluded so the audit_log table doesn't flood with one
# row every 15 seconds per connected browser tab.
#
# Path-based, not endpoint-based — unaffected by the blueprint split.
AUDIT_SKIP_PREFIXES = (
    "/api/alerts/latest",
    "/api/health-score",
    "/api/cache-stats",
    "/api/severity-breakdown",
    "/api/agents",
    "/api/events/stream",  # Round 4: long-lived SSE — would flood audit_log
    "/api/status",         # Round 5: public 30s poll from login page
    "/api/client-error",   # error beacon — already lands in error_log, not audit_log
    "/health",
    "/static/",
)

# Endpoints a user with must_change_password=1 may still reach. Everything else
# is bounced to the password form. ENDPOINT names, so these carry blueprint
# prefixes; "static" has none because Flask registers it on the app itself.
PASSWORD_GATE_EXEMPT = frozenset({
    "auth.change_password", "auth.logout", "auth.login", "static",
    "api.health", "api.api_client_error",
})

AUDIT_SKIP_METHODS = {"OPTIONS", "HEAD"}

# Only mutating requests are audited here. This middleware used to log every
# authenticated GET as `GET /dashboard/it`, which (a) flooded the 500-row
# window with page-navigation noise so real actions fell off the end, (b) grew
# audit_log without bound, and (c) contradicted the app's own copy at
# audit.html:125-128 ("the audit table [is] focused on user-initiated actions").
# Meaningful reads already log themselves with a semantic action name —
# REPORT_VIEW, EXPORT_CSV, ALERT_VIEW — which is what the Audit tab should show.
AUDIT_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _enforce_password_rotation():
    """
    Make must_change_password an actual gate, not a suggestion.

    It was enforced in exactly one place — a redirect immediately after a
    successful login. Typing /report, /admin/settings, /export.csv or
    /api/alert/5 straight afterwards (or just clicking any nav link on the
    password page) gave the user their full role privileges while still holding
    the credential that was supposed to be forced-rotated. For accounts seeded
    from config.USERS that credential is published in this repo.
    """
    if not current_user.is_authenticated:
        return None
    if not getattr(current_user, "must_change_password", False):
        return None
    if request.endpoint in PASSWORD_GATE_EXEMPT:
        return None
    if _is_machine_path(request.path):
        return jsonify({"error": "password_change_required"}), 403
    flash("You must change your password before continuing.", "warning")
    return redirect(url_for("auth.change_password"))


def _audit_request() -> None:
    if request.method in AUDIT_SKIP_METHODS:
        return
    if request.method not in AUDIT_METHODS:
        return
    path = request.path or ""
    if path.startswith(AUDIT_SKIP_PREFIXES):
        return
    if not current_user.is_authenticated:
        return
    db.log_audit(
        action=f"{request.method} {path}",
        actor=current_user.username,
        actor_role=current_user.role,
        target=path,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent", ""),
    )


def init_app(app) -> None:
    """Register AFTER web.csrf.init_app — see the module docstring."""
    app.before_request(_enforce_password_rotation)
    app.before_request(_audit_request)
