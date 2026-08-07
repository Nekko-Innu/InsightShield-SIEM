# web/csrf.py
# Hand-rolled per-session CSRF token plus the blanket before_request check.
#
# The token is generated on first read and persists in flask.session for the
# session lifetime (30 minutes per PERMANENT_SESSION_LIFETIME).

import hmac
import logging
import secrets

from flask import flash, jsonify, redirect, request, session

from decorators import _is_machine_path

from web.responses import safe_referrer

logger = logging.getLogger("insightshield.web.csrf")

# Routes exempt from the blanket CSRF check. Only one, and it has its own
# authentication:
#   /wazuh-webhook  — machine-to-machine POST from Wazuh's integrator script,
#                     which carries no browser session. Gated by an IP allowlist
#                     plus the X-Webhook-Token shared secret instead.
#
# These are ENDPOINT names, not paths. When the route moved into the `webhook`
# blueprint its endpoint became "webhook.wazuh_webhook" — get this wrong and
# every Wazuh alert is rejected with a 403, silently, at ingest.
CSRF_EXEMPT_ENDPOINTS = frozenset({"webhook.wazuh_webhook"})
CSRF_PROTECTED_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


def verify_csrf() -> bool:
    """True if the request's _csrf form field matches the session value."""
    submitted = request.form.get("_csrf") or request.headers.get("X-CSRF-Token")
    expected = session.get("csrf_token")
    if not submitted or not expected:
        return False
    # compare_digest, not ==, so a wrong token cannot be recovered byte-by-byte
    # from response timing.
    return hmac.compare_digest(str(submitted), str(expected))


def _enforce_csrf():
    """
    Blanket CSRF check on every mutating request.

    Previously `verify_csrf()` was called by hand, and only the ten
    /admin/settings/* routes remembered to do it. Everything else — login,
    logout, password change, acknowledge, resolve, backup prune — accepted a
    forged cross-site POST. An IT_ADMIN visiting a hostile page could have live
    incidents force-closed and backups deleted.

    Enforcing it here rather than per-route means a new POST route is protected
    by default; forgetting is no longer possible. The ten existing inline
    `verify_csrf()` calls are now redundant but harmless — they are left in
    place because settings.js expects their JSON error shape.
    """
    if request.method not in CSRF_PROTECTED_METHODS:
        return None
    if request.endpoint in CSRF_EXEMPT_ENDPOINTS:
        return None
    if verify_csrf():
        return None

    logger.warning(
        "CSRF reject: endpoint=%s path=%s ip=%s",
        request.endpoint, request.path, request.remote_addr,
    )
    if _is_machine_path(request.path):
        return jsonify({"error": "csrf"}), 403
    flash("Your session expired or the form was stale. Please try again.", "error")
    return redirect(safe_referrer()), 303


def init_app(app) -> None:
    """MUST be registered before web.hooks — see the note in that module."""
    app.context_processor(lambda: {"csrf_token": csrf_token})
    app.before_request(_enforce_csrf)
