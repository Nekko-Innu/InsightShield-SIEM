# web/responses.py
# Response helpers shared across routes. Nothing here touches the app object;
# it is imported, not init_app'd.

import logging

from flask import (
    jsonify, make_response, redirect, request, url_for,
)
from flask_login import current_user

import rate_limit
from decorators import dashboard_endpoint_for

logger = logging.getLogger("insightshield.web.responses")


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
