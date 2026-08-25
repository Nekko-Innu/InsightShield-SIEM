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

def _check_ip_throttle(ip: str | None) -> int | None:
    """Retry-after seconds if this SOURCE has failed too often; else None.

    Applied before verify_password, so a hammering host does not get to spend
    our password-hash budget. Keyed on the address the attacker actually
    occupies, so blocking it costs them something and costs nobody else
    anything. Returning the WINDOW length is conservative — the real quiet time
    is shorter as the oldest failure rolls out — but precision is not worth the
    SQL here.
    """
    if not ip:
        return None
    if db.failed_logins_in_window(
        ip=ip, since_minutes=_THROTTLE_IP_WINDOW_MIN
    ) >= _THROTTLE_IP_LIMIT:
        return _THROTTLE_IP_WINDOW_MIN * 60
    return None


def _username_throttle_tripped(username: str | None) -> int | None:
    """Retry-after seconds if this ACCOUNT has failed too often; else None.

    Consulted ONLY after a password check has already failed. It used to run
    before verify_password, alongside the per-IP check, and that was an
    unauthenticated account-lockout: the counter keys on the SUBMITTED
    username, so ten failed POSTs of `username=admin` from a couple of rotating
    addresses refused the real holder of the password from every location for
    an hour. Nothing reset it on a successful login and there is no unlock in
    the UI, so ten requests an hour held the only IT_ADMIN account shut
    indefinitely — while this same app paged that admin about the attack they
    could no longer log in to triage.

    Checking it after the password means a correct credential is never
    refused, which costs nothing defensively: someone who supplies the right
    password is not the brute-force attempt this counter exists to slow. Wrong
    guesses against a hot account still get the 429, so IP-rotated guessing is
    still answered, and the per-IP block above still bounds the hash cost.
    """
    if not username:
        return None
    if db.failed_logins_in_window(
        username=username, since_minutes=_THROTTLE_USER_WINDOW_MIN
    ) >= _THROTTLE_USER_LIMIT:
        return _THROTTLE_USER_WINDOW_MIN * 60
    return None


def _throttled_login_response(username: str | None, retry_after: int, scope: str):
    """The 429 both throttle paths return. Flash category 'throttle' is what
    login.html renders with a clock icon."""
    flash(
        f"Too many attempts. Try again in {humanize_seconds(retry_after)}.",
        "throttle",
    )
    logger.warning(
        "Login throttle trip (%s): ip=%s username=%s retry_after=%ds",
        scope, request.remote_addr, username, retry_after,
    )
    db.log_audit(
        action="LOGIN_THROTTLED",
        actor=username or "anonymous",
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent", ""),
        details=f"scope={scope} retry_after_s={retry_after}",
    )
    resp = make_response(
        render_template("login.html", known_devices=config.KNOWN_DEVICES),
        429,
    )
    resp.headers["Retry-After"] = str(retry_after)
    return resp

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

        # Round E (§11.1a) — per-SOURCE throttle, before verify_password so the
        # password-hash cost is not paid for a host that is already blocked.
        # The per-ACCOUNT counter deliberately does NOT run here; see
        # _username_throttle_tripped for why checking it before the password
        # was an unauthenticated lockout of the only admin account.
        retry_after = _check_ip_throttle(request.remote_addr)
        if retry_after is not None:
            return _throttled_login_response(username, retry_after, "ip")

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

            # Per-ACCOUNT throttle, consulted only now that this attempt has
            # already been rejected on its own merits. Answers IP-rotated
            # guessing against one account without ever refusing someone who
            # supplied the right password.
            user_retry = _username_throttle_tripped(username)
            if user_retry is not None:
                return _throttled_login_response(username, user_retry, "username")

            flash("Invalid credentials. Please try again.", "error")

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

        # Same source throttle as /login. This route calls verify_password too,
        # and used to do it with no throttle, no failure row and no escalation
        # check — so an attacker holding a hijacked session could guess the real
        # password here, one request at a time, against the one authenticated
        # endpoint nothing was watching, and convert a 30-minute window into
        # permanent access. The generic "POST /account/password" audit row is
        # byte-identical for a wrong guess and a real rotation, so the Audit tab
        # could not tell 25 guesses from 25 changes either.
        retry_after = _check_ip_throttle(request.remote_addr)
        if retry_after is not None:
            flash(
                f"Too many attempts. Try again in {humanize_seconds(retry_after)}.",
                "throttle",
            )
            resp = make_response(render_template("password_change.html"), 429)
            resp.headers["Retry-After"] = str(retry_after)
            return resp

        if db.verify_password(current_user.username, current_pw) is None:
            flash("Current password is incorrect.", "error")
            logger.warning("Failed password-change attempt: username=%s",
                           current_user.username)
            # LOGIN_FAILURE, not a bespoke action: this is a password guess, and
            # recording it as one puts it in front of the throttle, the
            # brute-force escalation and the audit view that already exist.
            db.log_audit(
                action="LOGIN_FAILURE",
                actor=current_user.username,
                actor_role=current_user.role,
                ip=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                details="source=account_password_change",
            )
            escalation_count = db.failed_logins_in_window(
                ip=request.remote_addr,
                since_minutes=_THROTTLE_ESCALATE_WINDOW_MIN,
            )
            if escalation_count >= _THROTTLE_ESCALATE_LIMIT:
                _maybe_dispatch_brute_force_alert(
                    request.remote_addr, escalation_count
                )
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
