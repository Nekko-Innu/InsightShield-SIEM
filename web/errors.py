# web/errors.py
# Safety net for whatever the point-fixes elsewhere in the codebase don't
# catch. Every uncaught exception gets logged to logs/insightshield.log AND to
# the error_log table (visible in Settings → Errors), then a response shaped
# for the caller: JSON for /api/*|/export* (the same path-based dispatch
# decorators.role_required already uses), an error page otherwise.

import logging
import traceback

from flask import jsonify, render_template, request
from flask_login import current_user

import db
from decorators import _is_machine_path

logger = logging.getLogger("insightshield.web.errors")


def render_error(code: int, title: str, message: str):
    """
    Render the shared error page with the real HTTP status.

    All three handlers used to `flash(...)` and then return
    `redirect(url_for("dashboard_manager")), <code>` — a Location header on a
    non-redirect status. Browsers ignore Location on a 404/403/500, so the
    navigation never happened, the user got Werkzeug's bare "You should be
    redirected" stub, and the flash sat queued in the session until it popped up
    on some unrelated later page. That is the phantom "That page doesn't exist."
    toast. It also sent every wrong-role and every 404 to the MANAGER dashboard
    regardless of who you were.
    """
    return render_template(
        "error.html", code=code, title=title, message=message
    ), code


def _handle_uncaught_exception(e):
    # Let Werkzeug's own HTTP errors keep their status. Only 404 and 403 had
    # dedicated handlers, so everything else — 405 Method Not Allowed, and the
    # abort(400) that rejects path traversal in admin_backup_download — was
    # rewritten to a 500 "Something went wrong on our end" and written to
    # error_log as if it were a crash. A blocked attack looked identical to a
    # bug, and the Errors tab filled with rejections that were working as
    # intended.
    from werkzeug.exceptions import HTTPException

    if isinstance(e, HTTPException):
        logger.info("HTTP %s on %s %s", e.code, request.method, request.path)
        if _is_machine_path(request.path):
            return jsonify({"error": e.name}), e.code
        return e

    logger.exception("Uncaught exception on %s", request.path)
    db.log_error(
        source="server",
        module=request.endpoint or request.path,
        exc_type=type(e).__name__,
        message=str(e),
        path=request.path,
        actor=getattr(current_user, "username", None),
        traceback=traceback.format_exc(),
    )
    if _is_machine_path(request.path):
        return jsonify({"error": "Internal server error"}), 500
    return render_error(
        500,
        "Something went wrong",
        "The error has been logged. Try again, or contact IT if it keeps happening.",
    )


def _handle_not_found(e):
    if _is_machine_path(request.path):
        return jsonify({"error": "not found"}), 404
    return render_error(
        404, "Page not found", "That page doesn't exist, or the link was mistyped."
    )


def _handle_forbidden(e):
    # Every denied role check lands here, so this is the single place an
    # authorization sweep is countable from.
    # ponytail: one audit row per 403, unthrottled, so a flood of denied
    # requests is also a flood of small writes. Bounded by the 90-day
    # AUDIT_RETENTION_DAYS purge, and the flood is exactly what the probe sweep
    # now alerts on. Add a per-IP write cap only if audit_log growth is measured
    # to be a problem — capping it blindly would blind the detector. Recorded with the actor when there
    # is one — an authenticated user probing above their role is a different
    # story from an anonymous scanner, and the audit view can tell them apart.
    db.log_audit(
        action="AUTHZ_DENIED",
        actor=getattr(current_user, "username", None),
        actor_role=getattr(current_user, "role", None),
        target=request.endpoint or request.path,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent", ""),
    )
    if _is_machine_path(request.path):
        return jsonify({"error": "forbidden"}), 403
    return render_error(
        403,
        "Access denied",
        "Your role does not have access to that page.",
    )


def init_app(app) -> None:
    app.register_error_handler(Exception, _handle_uncaught_exception)
    app.register_error_handler(404, _handle_not_found)
    app.register_error_handler(403, _handle_forbidden)
