# web/blueprints/auth.py
# Login, logout, password rotation, and the login throttle that backs them.
#
# The throttle counts LOGIN_FAILURE rows via db.failed_logins_in_window, so it
# has always been correct across multiple workers — the in-memory bucket the
# gunicorn config used to warn about is rate_limit's AI-provider limiter, a
# different thing entirely.

import json
import logging
from datetime import datetime, timedelta

from flask import (
    Blueprint, flash, make_response, redirect, render_template, request, url_for,
)
from flask_login import current_user, login_required, login_user, logout_user

import alert_router
import config
import db
from web.auth_user import User
from web.filters import humanize_seconds
from web.responses import redirect_to_dashboard

logger = logging.getLogger("insightshield.web.auth")

bp = Blueprint("auth", __name__)


# ── Login throttle (Round E §11.1a) ─────────────────────────────────────────
# Reads audit_log via db.failed_logins_in_window(); no new dependencies, no
# new schema. Two thresholds — per-IP and per-username — block independently
# so an attacker can't bypass either by rotating the other. The 20-in-60-min
# escalation threshold (separate code path) emits a credential_brute_force
# HIGH alert via alert_router; see §11.1c.
_THROTTLE_IP_LIMIT      = 5    # LOGIN_FAILURE per IP within window before 429
_THROTTLE_IP_WINDOW_MIN = 15
_THROTTLE_USER_LIMIT      = 10  # LOGIN_FAILURE per username within window
_THROTTLE_USER_WINDOW_MIN = 60
# §11.1c — escalation threshold. At >=N failures per IP per window, emit a
# `credential_brute_force` HIGH alert via alert_router. Idempotent: at most
# one alert per IP per window via the audit_log target check.
_THROTTLE_ESCALATE_LIMIT      = 20
_THROTTLE_ESCALATE_WINDOW_MIN = 60

def _check_login_throttle(ip: str | None, username: str | None) -> int | None:
    """Return retry-after seconds if the login should be blocked; else None.

    Per-IP fires first (catches the common case of a single attacker host),
    falling through to per-username (catches IP-rotated attacks against one
    account). Returning the WINDOW length as retry-after is conservative —
    the actual quiet time is shorter (oldest failure rolls out of the
    window earlier), but precision isn't worth the SQL overhead here.
    """
    if ip:
        ip_failures = db.failed_logins_in_window(
            ip=ip, since_minutes=_THROTTLE_IP_WINDOW_MIN
        )
        if ip_failures >= _THROTTLE_IP_LIMIT:
            return _THROTTLE_IP_WINDOW_MIN * 60
    if username:
        user_failures = db.failed_logins_in_window(
            username=username, since_minutes=_THROTTLE_USER_WINDOW_MIN
        )
        if user_failures >= _THROTTLE_USER_LIMIT:
            return _THROTTLE_USER_WINDOW_MIN * 60
    return None

def _maybe_dispatch_brute_force_alert(ip: str | None, count: int) -> None:
    """Emit a credential_brute_force HIGH alert if not already emitted for
    this IP within the escalation window. Idempotent — repeated failures
    past the threshold won't re-dispatch (would otherwise spam Telegram/SMS).

    Round E (§11.1c). The body of this moved to
    alert_router.dispatch_internal_alert when the authorization-probe sweep
    needed the same dedupe/store/route/audit sequence; the alert it produces is
    byte-for-byte what it was — same rule_id, same target string, same HIGH
    routing to IT SMS + Telegram + Email + Manager Telegram.
    """
    alert_router.dispatch_internal_alert(
        attack_type="credential_brute_force",
        rule_id="ISH-CBF-001",
        source_ip=ip,
        plain_text=(
            f"Repeated failed logins from {ip}: {count} attempts in "
            f"{_THROTTLE_ESCALATE_WINDOW_MIN} min. Possible credential brute force."
        ),
        evidence={"count": count, "window_min": _THROTTLE_ESCALATE_WINDOW_MIN},
        dedupe_minutes=_THROTTLE_ESCALATE_WINDOW_MIN,
    )

# ── Routes ───────────────────────────────────────────────────────────────────

@bp.route("/")
def index():
    return redirect(url_for("auth.login"))

@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect_to_dashboard()

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Round E (§11.1a) — throttle pre-check. Runs before verify_password so
        # bcrypt cost isn't paid for blocked actors; flash uses the new
        # 'throttle' category so login.html can render it with a clock icon.
        retry_after = _check_login_throttle(request.remote_addr, username)
        if retry_after is not None:
            flash(
                f"Too many attempts. Try again in {humanize_seconds(retry_after)}.",
                "throttle",
            )
            logger.warning(
                "Login throttle trip: ip=%s username=%s retry_after=%ds",
                request.remote_addr, username, retry_after,
            )
            db.log_audit(
                action="LOGIN_THROTTLED",
                actor=username or "anonymous",
                ip=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                details=f"retry_after_s={retry_after}",
            )
            resp = make_response(
                render_template("login.html", known_devices=config.KNOWN_DEVICES),
                429,
            )
            resp.headers["Retry-After"] = str(retry_after)
            return resp

        user_data = db.verify_password(username, password)
        if user_data:
            user = User(
                username,
                user_data["role"],
                must_change_password=user_data.get("must_change_password", 0),
                password_hash=user_data.get("password_hash"),
                session_epoch=user_data.get("session_epoch", 0),
            )
            # Drop any pre-auth CSRF token so one minted for an anonymous
            # visitor cannot survive into the authenticated session, and mark
            # the session permanent so PERMANENT_SESSION_LIFETIME (30 min)
            # actually applies — without this Flask issues a browser-session
            # cookie and the configured idle timeout is dead config.
            from flask import session

            session.pop("csrf_token", None)
            session.permanent = True
            # No remember=True: a remember cookie outlives the session and
            # re-authenticates the moment PERMANENT_SESSION_LIFETIME expires,
            # which made the 30-minute idle timeout unenforceable.
            login_user(user)
            logger.info("User logged in: %s (role=%s)", username, user_data["role"])
            db.log_audit(
                action="LOGIN_SUCCESS",
                actor=username,
                actor_role=user_data["role"],
                ip=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
            )
            if user.must_change_password:
                flash("You must change your password before continuing.", "warning")
                return redirect(url_for("auth.change_password"))
            return redirect_to_dashboard()
        else:
            flash("Invalid credentials. Please try again.", "error")
            logger.warning("Failed login attempt: username=%s", username)
            db.log_audit(
                action="LOGIN_FAILURE",
                actor=username or "anonymous",
                actor_role=None,
                ip=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
            )
            # Round E (§11.1c) — escalation. Re-count INCLUDING the failure
            # we just logged; if it crosses the threshold, dispatch a HIGH
            # credential_brute_force alert (idempotent within the window).
            escalation_count = db.failed_logins_in_window(
                ip=request.remote_addr,
                since_minutes=_THROTTLE_ESCALATE_WINDOW_MIN,
            )
            if escalation_count >= _THROTTLE_ESCALATE_LIMIT:
                _maybe_dispatch_brute_force_alert(
                    request.remote_addr, escalation_count
                )

    return render_template("login.html", known_devices=config.KNOWN_DEVICES)

# POST only. Accepting GET made this a one-click forced logout — any <img src>
# or link on a hostile page could end an IT admin's session mid-incident.
# _base.html:138 already submits this as a POST form.
@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    logger.info("User logged out: %s", current_user.username)
    db.log_audit(
        action="LOGOUT",
        actor=current_user.username,
        actor_role=current_user.role,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent", ""),
    )
    # Order is load-bearing. logout_user() drops the Flask-Login keys but leaves
    # the rest of the session (including the CSRF token) intact, so the session
    # still has to be cleared — nothing should survive the boundary between two
    # users on a shared machine. It has to happen FIRST: logout_user() marks the
    # remember cookie for deletion by writing session["_remember"] = "clear",
    # which Flask-Login's after_request hook reads to expire the cookie. Clearing
    # the session afterwards wiped that marker, the remember_token cookie was
    # never expired, and the next request silently logged the user back in for
    # the cookie's full 7-day life. logout_user() decides to set the marker from
    # request.cookies, not from the session, so it is unaffected by the wipe.
    # login_user() no longer passes remember=True, so there is no such cookie to
    # clear today — the ordering stays because it is the correct one, and it is
    # what keeps this safe if remember-me is ever switched back on.
    # Before session.clear(), because current_user has to still be populated —
    # and this is the half that makes logout a revocation rather than a tidy-up.
    # session.clear() and logout_user() only empty the jar in front of us; the
    # cookie itself is a self-contained signed credential, so a copy captured
    # off the wire beforehand replayed straight back in until its 30-minute
    # signature expired. Bumping the epoch changes the digest in the user id and
    # kills every cookie already issued for this account.
    db.bump_session_epoch(current_user.username)

    from flask import session

    session.clear()
    logout_user()
    return redirect(url_for("auth.login"))

@bp.route("/account/password", methods=["GET", "POST"], endpoint="change_password")
@login_required
def change_password():
    """
    Let the logged-in user rotate their own password. Requires the current
    password, a new password entered twice (min 10 chars), and clears the
    must_change_password flag on success.
    """
    if request.method == "POST":
        current_pw = request.form.get("current_password", "")
        new_pw     = request.form.get("new_password", "")
        confirm_pw = request.form.get("confirm_password", "")

        if db.verify_password(current_user.username, current_pw) is None:
            flash("Current password is incorrect.", "error")
            return render_template("password_change.html")

        if len(new_pw) < 10:
            flash("New password must be at least 10 characters.", "error")
            return render_template("password_change.html")

        if new_pw != confirm_pw:
            flash("New password and confirmation do not match.", "error")
            return render_template("password_change.html")

        if new_pw == current_pw:
            flash("New password must be different from the current password.", "error")
            return render_template("password_change.html")

        if db.set_password(current_user.username, new_pw):
            flash("Password changed successfully.", "success")
            logger.info("Password changed for user: %s", current_user.username)
            db.log_audit(
                action="PASSWORD_CHANGED",
                actor=current_user.username,
                actor_role=current_user.role,
                target=f"user:{current_user.username}",
                ip=request.remote_addr,
            )
            # Changing the password changes the derived session token, which by
            # design invalidates every session for this account — including the
            # one making this request. Re-issue it so the user who just rotated
            # their own password stays logged in while every OTHER session is
            # killed. session_epoch has to be carried through here, or the
            # re-issued cookie is minted against epoch 0 and dies on the next
            # request.
            changed = db.get_user(current_user.username)
            refreshed = User(
                changed["username"],
                changed["role"],
                must_change_password=changed.get("must_change_password", 0),
                password_hash=changed.get("password_hash"),
                session_epoch=changed.get("session_epoch", 0),
            )
            login_user(refreshed)
            return redirect_to_dashboard()

        flash("Could not change password — contact IT.", "error")

    return render_template("password_change.html")
