# web/auth_user.py
# Flask-Login wiring: the User model, the session-revocation token, and the
# user loader.

import hashlib
import hmac
import logging

from flask_login import LoginManager, UserMixin

import db
from decorators import ROLE_IT_ADMIN, ROLE_MANAGER, normalize_role

logger = logging.getLogger("insightshield.web.auth_user")

login_manager = LoginManager()


def session_token(password_hash: str | None) -> str:
    """
    Short opaque token derived from the stored password hash.

    Embedded in the Flask-Login user id (see User.get_id) so that changing a
    password invalidates every existing session for that account. Deriving it from the hash means no schema change and no new column
    to keep in sync — the revocation event and the password change are the same
    event by construction.

    The password hash never leaves the server; only this digest of it does, and
    it is not reversible to the hash (let alone the password).
    """
    return hashlib.sha256((password_hash or "").encode("utf-8")).hexdigest()[:16]


class User(UserMixin):
    """Flask-Login user — backed by the users table (v5 schema)."""
    def __init__(self, username, role, must_change_password=0, password_hash=None):
        self.id = username
        self.username = username
        self.role = role
        self.must_change_password = bool(must_change_password)
        self.session_token = session_token(password_hash)

    def get_id(self):
        """
        Flask-Login stores this in the session cookie.

        It used to be the bare username, so a copied session stayed valid no
        matter what: logging out ends the session on the browser that called
        it, and changing the password invalidated nothing anywhere else.
        Appending the password-derived token makes load_user reject any cookie
        minted before the last password change.
        """
        return f"{self.username}:{self.session_token}"

    @property
    def is_it_admin(self) -> bool:
        """
        Case-insensitive IT_ADMIN test for templates.

        The templates used to compare `current_user.role == 'IT_ADMIN'` at 11
        sites. Jinja's == is case-sensitive, so every one of those was a silent
        fail-open/fail-closed waiting on a differently-cased role string — and
        the DB already stored "manager" lower-case next to "IT_ADMIN" upper.
        """
        return normalize_role(self.role) == ROLE_IT_ADMIN

    @property
    def role_display(self) -> str:
        """Human-readable role label. Case-insensitive on the stored value."""
        return {
            ROLE_MANAGER: "Manager",
            ROLE_IT_ADMIN: "IT Admin",
        }.get(normalize_role(self.role), self.role)


@login_manager.user_loader
def load_user(user_id):
    # user_id is "<username>:<session_token>" (see User.get_id). Cookies minted
    # before this change carry a bare username and no token — they are rejected,
    # which logs everyone out once on deploy. That is the intended behaviour for
    # a session-revocation fix.
    username, _, token = (user_id or "").partition(":")
    if not username or not token:
        return None

    user_data = db.get_user(username)
    if not user_data:
        return None

    expected = session_token(user_data.get("password_hash"))
    if not hmac.compare_digest(token, expected):
        logger.info("Rejecting stale session for %s (password changed)", username)
        return None

    return User(
        username,
        user_data["role"],
        must_change_password=user_data.get("must_change_password", 0),
        password_hash=user_data.get("password_hash"),
    )


def init_app(app) -> None:
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to access the dashboard."
    # "strong" is meant to delete the session when the client identifier (IP +
    # user agent) changes, rather than merely marking it non-fresh. Note what it
    # actually does here: Flask-Login 0.6.3's _session_protection_failed reads
    # `if mode == "basic" or sess.permanent:` FIRST, and login sets
    # session.permanent = True so PERMANENT_SESSION_LIFETIME applies — so a
    # permanent session takes the basic branch (mark _fresh False, session
    # survives) and never reaches the strong branch. Session revocation on this
    # app rests on the password-derived token in User.get_id, not on this line.
    login_manager.session_protection = "strong"
