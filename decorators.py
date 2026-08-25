# decorators.py
# Insight Shield — Round 8 (Part 8: RBAC hardening)
#
# Single source of truth for role-based access control. Replaces the
# scattered `if current_user.role != "IT_ADMIN": flash(...); return redirect(...)`
# bodies that grew across Rounds 1-7. Stacks under @login_required so the
# auth check always runs first; this decorator only sees authenticated
# users by construction.
#
# Path-based dispatch:
#   /api/*   -> 403 JSON { "error": "forbidden", "required_role": "..." }
#   else     -> flash + 302 redirect to /dashboard/manager (HTML)
#
# Why path and not Accept header: every /api/* route in this app returns
# JSON unconditionally, and every other authenticated route returns HTML.
# Branching on path keeps the contract testable from curl/test_client
# without setting Accept, and matches what the existing routes already do.

import logging
from functools import wraps

from flask import abort, jsonify, redirect, url_for, request
from flask_login import current_user

logger = logging.getLogger("insightshield.decorators")

# Canonical role strings. The DB is the authority (config.USERS is bootstrap-only
# and no-ops once the users table is non-empty), and it was seeded with
# "IT_ADMIN" upper-case but "manager" lower-case. Every comparison in the app is
# an IT_ADMIN test with an implicit else, so the inconsistency was invisible —
# right up until someone wrote role_required("MANAGER"), which would have denied
# the manager on their own dashboard. Compare case-insensitively and the whole
# class of bug goes away.
ROLE_IT_ADMIN = "IT_ADMIN"
ROLE_MANAGER = "MANAGER"


def normalize_role(role: str | None) -> str:
    """Upper-case, whitespace-stripped role string. '' for a missing role."""
    return (role or "").strip().upper()


def dashboard_endpoint_for(role: str | None) -> str:
    """The Flask endpoint name of the dashboard belonging to `role`.

    Blueprint-qualified: both dashboards live in web.blueprints.dashboards, so
    the bare names these used to be no longer build.
    """
    return ("dashboards.dashboard_it" if normalize_role(role) == ROLE_IT_ADMIN
            else "dashboards.dashboard_manager")


def _is_machine_path(path: str) -> bool:
    """True for paths that expect a machine-readable response on auth failure.

    Covers /api/* (JSON endpoints) AND /export* (CSV / binary downloads).
    A flash redirect on a wget/curl-style download would silently swallow
    the failure mode the caller is checking for; 403 is the contract.
    """
    return path.startswith("/api/") or path.startswith("/export")


def role_required(role: str):
    """Decorator factory: enforce that current_user.role == `role`.

    Use AFTER @login_required (outer-to-inner: login first, role second):

        @app.route("/admin/foo")
        @login_required
        @role_required("IT_ADMIN")
        def admin_foo():
            ...

    Comparison is case-insensitive (see normalize_role above).

    Behavior on mismatch:
        - For /api/* and /export* paths: ({"error": "forbidden", ...}, 403).
        - Otherwise: abort(403), which renders templates/error.html with a
          real 403 status.

    This used to flash and 302 to /dashboard/manager, and the docstring called
    that "a safe landing page ... since the manager dashboard itself is in the
    allowed set". That was true, and it was the whole problem: the deny path
    only terminated because /dashboard/manager had no role gate, so the one
    route that needed gating could not be gated without deadlocking every
    wrong-role request into an infinite redirect. abort(403) has no redirect
    target at all, so the loop cannot exist and /dashboard/manager is now free
    to enforce its own role.

    Defensive: if reached without an authenticated user (i.e. someone
    forgot @login_required) we still 401 instead of crashing on
    current_user.role. login_required should normally have already
    redirected to /login by the time we run.
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            if not getattr(current_user, "is_authenticated", False):
                # Defensive — login_required should have caught this. We
                # don't redirect to login here because that would mask
                # the missing decorator; explicit 401 keeps the bug visible.
                logger.warning(
                    "role_required(%s) reached without authentication on %s — "
                    "missing @login_required upstream?",
                    role, request.path,
                )
                if _is_machine_path(request.path):
                    return jsonify({"error": "unauthorized"}), 401
                return redirect(url_for("auth.login"))

            actual = getattr(current_user, "role", None)
            if normalize_role(actual) == normalize_role(role):
                return view_func(*args, **kwargs)

            # Mismatch — refuse with the path-appropriate response.
            logger.info(
                "role_required denied: user=%s role=%s required=%s path=%s",
                getattr(current_user, "username", "?"), actual, role, request.path,
            )
            if _is_machine_path(request.path):
                # Audited HERE, not in web/errors.py. This branch RETURNS a 403
                # response rather than raising one, so it never reaches the
                # error handler that records the HTML deny path — and the result
                # was that an attacker probing only /api/* and /export* produced
                # no AUTHZ_DENIED rows and never tripped the probe sweep in
                # scheduler._authz_probe_sweep. That is the surface a scripted
                # attacker picks first, so it was the wrong half to leave blind.
                # The HTML path below stays audited by errors._handle_forbidden,
                # which also catches 403s raised from outside this decorator —
                # do not "tidy" the two into one without keeping that coverage.
                # Imported locally: decorators sits below db in the import graph,
                # and the cost only lands on a request that is already refused.
                import db

                db.log_audit(
                    action="AUTHZ_DENIED",
                    actor=getattr(current_user, "username", None),
                    actor_role=getattr(current_user, "role", None),
                    target=request.endpoint or request.path,
                    ip=request.remote_addr,
                    user_agent=request.headers.get("User-Agent", ""),
                )
                return jsonify({
                    "error":         "forbidden",
                    "required_role": normalize_role(role),
                }), 403
            abort(403)
        return wrapped
    return decorator
