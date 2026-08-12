# app.py
# Insight Shield — Flask application factory.
# Purpose : Build and wire the app. Nothing else lives here.
#           Routes are in web/blueprints/, infrastructure in web/.
# Used by : gunicorn (app:app), worker.py (create_app), tests/conftest.py

import logging
import logging.handlers
import os
from datetime import timedelta
from pathlib import Path

from flask import Flask, request, session
from flask.sessions import SecureCookieSessionInterface
from werkzeug.middleware.proxy_fix import ProxyFix

import config
import crypto_utils

# Round 3: validate ENCRYPTION_KEY at module import. crypto_utils.get_master_key()
# calls sys.exit(1) on missing/invalid — systemd reports the unit as failed and
# the operator sees the cause immediately. Running with a broken key would
# silently emit empty/corrupt API keys to providers, which is worse.
crypto_utils.get_master_key()

import db
import scheduler

from web import auth_user, csrf, errors, filters, hooks
from web.blueprints import (
    admin_ops, admin_settings, alerts, api, auth, dashboards, reports, stream,
    webhook,
)

# ── Logging Setup ────────────────────────────────────────────────────────────
# Rotating file handler + the original stderr stream (gunicorn redirects
# stderr into its own error.log, which has no rotation — this gives us a
# queryable, size-capped log independent of that). 5MB x 5 backups.
_log_dir = Path("logs")
_log_dir.mkdir(parents=True, exist_ok=True)
_log_formatter = logging.Formatter(
    "%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
_file_handler = logging.handlers.RotatingFileHandler(
    _log_dir / "insightshield.log", maxBytes=5 * 1024 * 1024, backupCount=5,
)
_file_handler.setFormatter(_log_formatter)
_stream_handler = logging.StreamHandler()
_stream_handler.setFormatter(_log_formatter)
logging.basicConfig(level=logging.INFO, handlers=[_file_handler, _stream_handler])
logger = logging.getLogger("insightshield.app")


# Requests a browser makes on a timer, with no user behind them. Deliberately
# NOT web.hooks.AUDIT_SKIP_PREFIXES, which is a longer list serving a different
# question ("is this worth an audit row?"): it also holds
# /api/severity-breakdown, which ui.js fetches from the dashboard's range-button
# click handler as well as from the fallback poll. Borrowing that list would
# have logged out an IT admin who spent half an hour doing nothing but clicking
# range toggles. Anything not listed here counts as the user being present.
_MACHINE_POLL_PREFIXES = (
    "/api/alerts/latest",   # 15s watermark tick, both dashboards
    "/api/events/stream",   # SSE, IT dashboard
    "/api/status",          # 30s login-page status chip (unauthenticated)
    "/health",              # gunicorn / nginx / systemd probe
    "/static/",             # asset loads, including prefetch and cache revalidation
)


class _IdleTimeoutSessionInterface(SecureCookieSessionInterface):
    """Machine polling must not count as user activity.

    SESSION_REFRESH_EACH_REQUEST is on by default, so every authenticated
    response re-issues the session cookie with a fresh 30 minutes. Both
    dashboards poll themselves — /api/alerts/latest every 15s on the manager
    side, /api/events/stream on the IT side — and both are @login_required, so
    a browser left open on a dashboard renewed its own session forever and the
    configured idle timeout fired for nobody who kept a tab open.

    Skipping the refresh on those paths (and only when the session was not
    modified, so a login or logout during one still writes its cookie) makes
    the timeout measure what it claims to: time since the user last did
    something.
    """

    def should_set_cookie(self, app, session):
        if not session.modified and (request.path or "").startswith(
            _MACHINE_POLL_PREFIXES
        ):
            return False
        return super().should_set_cookie(app, session)


def _configure(app: Flask) -> None:
    app.secret_key = config.FLASK_SECRET_KEY
    app.session_interface = _IdleTimeoutSessionInterface()

    # nginx terminates TLS and proxies to 127.0.0.1:5000, so without this every
    # request looks like it came from loopback. That silently voided three controls:
    # the /wazuh-webhook IP allowlist (127.0.0.1 is the first entry, so it passed for
    # everyone), the login throttle (one shared bucket = a global 15-minute lockout
    # from five failed attempts by anybody), and every audit_log.ip row.
    # x_for=1 means "trust exactly one proxy hop" — nginx. Do not raise it; each
    # extra hop trusted is one an attacker can forge.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(
        minutes=config.PERMANENT_SESSION_LIFETIME_MIN
    )
    app.config.update(
        # Secure/HttpOnly/SameSite were all unset, so the session and remember
        # cookies rode plain HTTP and were sendable cross-site.
        SESSION_COOKIE_SECURE=config.COOKIES_REQUIRE_HTTPS,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        # No REMEMBER_COOKIE_* settings: login_user() is called without
        # remember=True, so no remember cookie is ever issued. It used to be,
        # for 7 days, which outlived the 30-minute session and quietly logged
        # the user back in the moment that session expired — the idle timeout
        # could never end a login. Authentication now lives in the session
        # cookie alone, which is the only thing PERMANENT_SESSION_LIFETIME
        # governs.
    )


def create_app() -> Flask:
    """
    Build the app. Called at import for `app:app` (gunicorn, conftest) and
    explicitly by worker.py.

    The web tier and the scheduler worker run the same application object; the
    ONLY difference is whether init_scheduler() is called. Escalation is a DB
    sweep now rather than per-alert in-memory jobs, so nothing in a web worker
    depends on a scheduler being present in that process.

    Every bootstrap step is idempotent, because with 3 gunicorn workers plus
    the worker unit this runs in four processes at once on a cold start:
    init_db uses CREATE TABLE IF NOT EXISTS, bootstrap_settings_from_env has
    its bootstrap_complete sentinel, and seed_users_from_config swallows the
    IntegrityError the losers of the race get from users.username UNIQUE.
    """
    app = Flask(__name__)
    _configure(app)

    # Registered FIRST, before anything that can touch current_user. Dropping
    # remember=True stops new remember cookies but retires none of the ones
    # already in browsers: Flask-Login still reads `remember_token` on every
    # request, so a cookie minted by the previous build keeps authenticating —
    # and re-minting 30-minute sessions — for its full 7 days after deploy,
    # which is exactly the idle-timeout bypass this round removed. Verified
    # against this build: a crafted legacy cookie reached /dashboard/it with
    # HTTP 200. Setting session["_remember"] = "clear" both blocks the load
    # (Flask-Login's remember branch checks that key) and makes its own
    # after-request hook expire the cookie on the way out, so each affected
    # browser is cleaned up on its next request.
    @app.before_request
    def _retire_legacy_remember_cookie():
        if "remember_token" in request.cookies:
            session["_remember"] = "clear"

    # ORDER IS LOAD-BEARING. Flask runs before_request functions in
    # registration order, and CSRF must precede the password-rotation gate and
    # the audit hook: register hooks first and a request rejected for a bad
    # CSRF token still gets written to audit_log as though it succeeded.
    csrf.init_app(app)
    hooks.init_app(app)
    errors.init_app(app)
    filters.init_app(app)
    auth_user.init_app(app)

    # URL rules are unchanged by the split — only endpoint names gained a
    # blueprint prefix — so nginx, smoke_test.sh and existing bookmarks are
    # unaffected.
    for module in (auth, dashboards, alerts, reports, api, stream, webhook,
                   admin_ops, admin_settings):
        app.register_blueprint(module.bp)

    with app.app_context():
        db.init_db()
        # Round 3: first-boot import of api_keys + settings + ai_providers from .env.
        # Idempotent — subsequent boots see the bootstrap_complete sentinel and no-op.
        db.bootstrap_settings_from_env()
        db.seed_users_from_config()

        # Production runs the scheduler in insightshield-worker.service, so the
        # web workers must NOT start one — see scheduler.py's module docstring
        # for what two schedulers do to a nightly SQLite backup. This flag is a
        # single-process dev convenience (and how the E2E suite gets an
        # agent-status snapshot without a second process).
        if os.environ.get("INSIGHTSHIELD_RUN_SCHEDULER") == "1":
            scheduler.init_scheduler()

        if not config.WAZUH_WEBHOOK_TOKEN:
            # /wazuh-webhook fails closed without this, so say it at boot rather
            # than let the operator discover it as a wall of 403s in Wazuh's log.
            logger.error(
                "WAZUH_WEBHOOK_TOKEN is unset — /wazuh-webhook will reject every "
                "payload with 403. Set it in .env and send the same value as the "
                "X-Webhook-Token header from the Wazuh integrator script."
            )
        logger.info("Insight Shield started: DB initialized")

    return app


app = create_app()
