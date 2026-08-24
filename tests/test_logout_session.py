"""Logout has to end the session on the server AND on the client.

Regression cover for the audit's ST-008. Two defects live here:

1. logout() called logout_user() and then session.clear(), which wiped the
   session["_remember"] = "clear" marker Flask-Login's after_request hook reads
   to expire the remember cookie. The cookie survived and the next request
   logged the user straight back in.
2. login_user(..., remember=True) issued that 7-day cookie in the first place,
   which also made the 30-minute idle timeout unenforceable (see
   test_session_timeout.py). Remember-me is gone; this file asserts it stays
   gone, because re-adding it silently un-fixes both cases.

Driven with `requests` rather than Playwright: the assertions are about
Set-Cookie headers, which are easier to read from a plain HTTP client than
through a browser context.
"""
import hashlib
import re
import sqlite3
from datetime import datetime, timedelta, timezone

import requests
from werkzeug.security import generate_password_hash

# Its own account, created straight in the DB with must_change_password=0: the
# seeded admin/manager logins are behind the forced-rotation gate and are shared
# with the session-scoped live_server that the rest of the suite logs into.
USERNAME = "logout_probe"
PASSWORD = "Logout-Probe-Pass!2026"


def _create_user(db_path):
    conn = sqlite3.connect(db_path, timeout=10)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO users "
            "(username, password_hash, role, created_at, must_change_password) "
            "VALUES (?, ?, ?, ?, 0)",
            (USERNAME, generate_password_hash(PASSWORD), "IT_ADMIN",
             datetime.now(tz=timezone(timedelta(hours=8))).isoformat()),
        )
        conn.commit()
    finally:
        conn.close()


def _csrf(session, url):
    body = session.get(f"{url}/login").text
    return re.search(r'name="_csrf" value="([^"]+)"', body).group(1)


def test_logout_ends_access_and_issues_no_remember_cookie(live_server, live_server_db):
    _create_user(live_server_db)
    s = requests.Session()

    token = _csrf(s, live_server)
    login = s.post(f"{live_server}/login",
                   data={"username": USERNAME, "password": PASSWORD, "_csrf": token},
                   allow_redirects=False)
    assert login.status_code == 302
    # Flask-Login's strong session protection emits an empty, already-expired
    # remember_token on the login response (it clears a cookie that isn't
    # there). What must never appear is one carrying a value.
    assert not re.search(r"remember_token=[^;\s]", login.headers.get("Set-Cookie", "")), (
        "login must not issue a persistent auth cookie — it outlives the session "
        "and defeats the idle timeout"
    )
    assert "remember_token" not in s.cookies
    assert s.get(f"{live_server}/dashboard/it").status_code == 200

    page = s.get(f"{live_server}/dashboard/it")
    token = re.search(r'name="csrf-token" content="([^"]+)"', page.text).group(1)

    logout = s.post(f"{live_server}/logout", data={"_csrf": token},
                    allow_redirects=False)
    assert logout.status_code == 302
    assert "session=;" in logout.headers.get("Set-Cookie", "")

    # Same client, same jar: nothing left in it may re-authenticate.
    after = s.get(f"{live_server}/dashboard/it", allow_redirects=False)
    assert after.status_code == 302 and "/login" in after.headers["Location"]


def test_captured_cookie_is_dead_after_logout(live_server, live_server_db):
    """Logout must revoke the cookie itself, not merely the browser's copy.

    The test above proves the *same* client cannot continue, which is a weaker
    claim than it looks: session.clear() and logout_user() only empty the jar in
    front of them. A value copied off the wire beforehand is a complete,
    still-signed credential, and against the build before this change it
    replayed from a fresh client straight into the dashboard with HTTP 200.
    """
    _create_user(live_server_db)
    s = requests.Session()

    token = _csrf(s, live_server)
    login = s.post(f"{live_server}/login",
                   data={"username": USERNAME, "password": PASSWORD, "_csrf": token},
                   allow_redirects=False)
    assert login.status_code == 302
    # Captured while the session is live — this is the attacker's copy.
    stolen = s.cookies["session"]
    assert s.get(f"{live_server}/dashboard/it").status_code == 200

    page = s.get(f"{live_server}/dashboard/it")
    token = re.search(r'name="csrf-token" content="([^"]+)"', page.text).group(1)
    logout = s.post(f"{live_server}/logout", data={"_csrf": token},
                    allow_redirects=False)
    assert logout.status_code == 302

    replay = requests.Session()
    replay.cookies.set("session", stolen, domain="127.0.0.1", path="/")
    resp = replay.get(f"{live_server}/dashboard/it", allow_redirects=False)
    assert resp.status_code == 302 and "/login" in resp.headers["Location"], (
        "a session cookie captured before logout still authenticates"
    )


def test_legacy_remember_cookie_does_not_authenticate(live_server, live_server_db):
    """A remember_token minted by the previous build must be dead on arrival.

    Dropping remember=True stops new cookies but retires none of the ones
    already in browsers: Flask-Login reads remember_token regardless of how the
    app logs people in, so without app.py's _retire_legacy_remember_cookie hook
    a pre-upgrade cookie kept minting fresh sessions for its full 7 days. This
    was confirmed against the build before that hook: HTTP 200 on /dashboard/it.
    """
    from flask import Flask
    from flask_login.utils import encode_cookie

    _create_user(live_server_db)
    conn = sqlite3.connect(live_server_db, timeout=10)
    try:
        pw_hash = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?", (USERNAME,)
        ).fetchone()[0]
    finally:
        conn.close()

    # Exactly what the old build stored: "<username>:<password-derived token>",
    # signed with the running server's secret (tests/conftest.py sets it).
    shim = Flask(__name__)
    shim.secret_key = "e2e-test-secret-key"
    token = hashlib.sha256(pw_hash.encode()).hexdigest()[:16]
    with shim.test_request_context():
        legacy = encode_cookie(f"{USERNAME}:{token}")

    s = requests.Session()
    s.cookies.set("remember_token", legacy, domain="127.0.0.1", path="/")
    resp = s.get(f"{live_server}/dashboard/it", allow_redirects=False)
    assert resp.status_code == 302 and "/login" in resp.headers["Location"], (
        "a remember cookie from the previous build still authenticates"
    )
    assert "remember_token" not in s.cookies, "the stale cookie was not expired"
