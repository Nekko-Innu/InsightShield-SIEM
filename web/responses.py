# web/responses.py
# Response helpers shared across routes, plus the after_request that puts the
# security headers on every response.

import logging

from flask import (
    jsonify, make_response, redirect, request, url_for,
)
from flask_login import current_user

import config
import rate_limit
from decorators import dashboard_endpoint_for

logger = logging.getLogger("insightshield.web.responses")


# Copied verbatim from nginx/insightshield.conf. Keep the two in sync: whichever
# layer is in front wins silently if they drift.
CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
       "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "connect-src 'self'; font-src 'self' data:; frame-ancestors 'none'")

PERMISSIONS_POLICY = "geolocation=(), camera=(), microphone=(), payment=(), usb=()"


def init_app(app) -> None:
    """Set the security headers in the app, not only in the reverse proxy.

    nginx/insightshield.conf sets five of these correctly, so the posture held
    only behind that exact proxy — `flask run`, direct-to-gunicorn, containers,
    any other proxy and the E2E suite all got none of them. Same reasoning the
    webhook handler already applies to body caps, which nginx also enforces and
    the app enforces again.
    """
    @app.after_request
    def _security_headers(resp):
        # setdefault, not assignment: where nginx already set a header its value
        # wins, so this is a floor rather than an override.
        resp.headers.setdefault("Content-Security-Policy", CSP)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Permissions-Policy", PERMISSIONS_POLICY)
        # Gated: a local HTTP dev session must not pin the browser to HTTPS for
        # a year over a hostname it will keep using without TLS.
        if config.COOKIES_REQUIRE_HTTPS:
            resp.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return resp


def rate_limited_response(retry_after):
    """The 429 four separate routes were each building by hand.

    /export.csv, /admin/audit.csv, /report.pdf, /wazuh-webhook and /api/status
    all emitted the identical body plus Retry-After header, copied five times.
    The login route is deliberately NOT one of them — it re-renders login.html
    with a 429 so the user sees the throttle message on the form.
    """
    resp = make_response(
        jsonify({"error": "rate_limited", "retry_after_s": retry_after}), 429
    )
    resp.headers["Retry-After"] = str(retry_after)
    return resp


def reject_csv_flood():
    """
    None if the caller may export, else a 429 response.

    Both CSV routes read the whole table into memory and serialise it. One
    shared budget on purpose: they are the same evidence-export capability, and
    a script alternating between them should not get double the allowance.
    """
    allowed, retry_after = rate_limit.can_call(
        f"csv:{current_user.username}", limit_per_min=6
    )
    if allowed:
        return None
    return rate_limited_response(retry_after)


def csv_safe(value):
    """Neutralise spreadsheet formula injection (CWE-1236).

    csv.writer quotes, it does not neutralise. Excel, LibreOffice and Sheets
    evaluate any cell whose first character is one of = + - @ TAB CR, so a
    device_name posted to /wazuh-webhook executes when an analyst opens the
    export. Prefixing with an apostrophe forces the cell to text.
    """
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def safe_referrer(fallback_endpoint: str = "auth.login") -> str:
    """request.referrer, but only if it points at this host.

    The default is a blueprint-qualified endpoint name, and
    test_endpoints.test_safe_referrer_default_fallback_resolves reads it off
    this signature to prove it still routes. It shipped as the bare "login"
    through the blueprint split, which made url_for raise BuildError and turned
    every CSRF rejection lacking an on-host referrer into a 500 — on the one
    path least likely to be walked by hand.

    Referer is set by the client, so `redirect(request.referrer or ...)` is an
    unvalidated redirect: an attacker page cross-posts to a mutating endpoint,
    the CSRF guard rejects it, and the app bounces the victim back to the
    attacker's origin carrying a same-origin-looking "session expired" flash —
    a clean handoff to a login clone.
    """
    from urllib.parse import urlparse

    ref = request.referrer
    if ref:
        parsed = urlparse(ref)
        if not parsed.netloc or parsed.netloc == urlparse(request.host_url).netloc:
            return ref
        logger.warning("Discarded off-host referrer: %s", ref)
    return url_for(fallback_endpoint)


# ── Dashboard routing ────────────────────────────────────────────────────────

def dashboard_for_role() -> str:
    # One role->dashboard map, shared with decorators.py. Two copies drifted
    # apart before: this one was case-sensitive on "IT_ADMIN" while the DB
    # holds "manager" lower-case.
    return dashboard_endpoint_for(getattr(current_user, "role", None))


def redirect_to_dashboard():
    # Was a third copy of the same map, and the case-sensitive one: it compared
    # current_user.role == "IT_ADMIN" against a column that also holds
    # lower-case values. Routed through dashboard_for_role now, so there is one
    # map to be wrong.
    return redirect(url_for(dashboard_for_role()))
