"""ST-009: the configured idle timeout actually ends a login.

Needs its own server because it needs its own environment: the session lifetime
is read from config at import, so the only way to test a timeout without a
30-minute wall-clock wait is to boot an instance with
INSIGHTSHIELD_SESSION_LIFETIME_MIN=1 and wait just over a minute. That wait is
real and unavoidable — the expiry is enforced by the signed cookie's own
timestamp, so there is nothing to fake client-side.

The polling half is the point of the second assertion. Both dashboards call
@login_required endpoints on a timer (/api/alerts/latest every 15s on the
manager side, /api/events/stream on the IT side). With Flask's default
SESSION_REFRESH_EACH_REQUEST those responses re-issued the cookie, so a browser
left open on a dashboard renewed its own session forever and the timeout fired
for nobody. app._IdleTimeoutSessionInterface excludes those paths; this test
fails if that exclusion is removed.
"""
import os
import re
import sqlite3
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import requests
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash

APP_DIR = Path(__file__).resolve().parent.parent
HOST = "127.0.0.1"
PORT = 5101  # not 5099 — the session-scoped live_server owns that one
BASE_URL = f"http://{HOST}:{PORT}"

LIFETIME_MIN = 1
IDLE_SECONDS = 70  # one minute plus slack for the signer's own rounding
POLL_EVERY = 15    # matches ui.js's manager-dashboard tick

USERNAME = "timeout_probe"
PASSWORD = "Timeout-Probe-Pass!2026"


@pytest.fixture(scope="module")
def short_session_server(tmp_path_factory):
    tmp_dir = tmp_path_factory.mktemp("insightshield-timeout")

    env = os.environ.copy()
    env["ENCRYPTION_KEY"] = Fernet.generate_key().decode()
    env["FLASK_SECRET_KEY"] = "timeout-test-secret-key"
    env["INSIGHTSHIELD_ALLOW_HTTP_COOKIES"] = "1"
    env["WAZUH_WEBHOOK_TOKEN"] = "timeout-test-token"
    # Seeding refuses to run without these, and this fixture boots its own
    # server against its own empty DB. The probe account below is created by
    # hand; these only get the bootstrap seed past its guard.
    env["BOOTSTRAP_ADMIN_PASSWORD"] = "timeout-Admin-Bootstrap!2026"
    env["BOOTSTRAP_MANAGER_PASSWORD"] = "timeout-Manager-Bootstrap!2026"
    env["INSIGHTSHIELD_SESSION_LIFETIME_MIN"] = str(LIFETIME_MIN)
    env["PYTHONPATH"] = str(APP_DIR) + os.pathsep + env.get("PYTHONPATH", "")

    proc = subprocess.Popen(
        [sys.executable, "-c",
         "from app import app; app.run(host=%r, port=%d, debug=False, use_reloader=False)"
         % (HOST, PORT)],
        cwd=str(tmp_dir), env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.time() + 20
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(f"{BASE_URL}/health", timeout=1) as r:
                    if r.status == 200:
                        break
            except OSError:
                time.sleep(0.3)
        else:
            raise RuntimeError("timeout-test app did not start")

        conn = sqlite3.connect(tmp_dir / "insightshield.db", timeout=10)
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
        yield BASE_URL
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def _login(url):
    s = requests.Session()
    token = re.search(r'name="_csrf" value="([^"]+)"',
                      s.get(f"{url}/login").text).group(1)
    s.post(f"{url}/login",
           data={"username": USERNAME, "password": PASSWORD, "_csrf": token})
    assert s.get(f"{url}/dashboard/it").status_code == 200
    return s


@pytest.mark.slow
def test_idle_session_expires(short_session_server):
    """Three clients, one wait. Machine polling must not hold a session open;
    a user clicking things must."""
    url = short_session_server
    idle = _login(url)
    polling = _login(url)
    clicking = _login(url)

    deadline = time.time() + IDLE_SECONDS
    while time.time() < deadline:
        time.sleep(min(POLL_EVERY, max(0.0, deadline - time.time())))
        # An open dashboard tab, nobody at the keyboard.
        polling.get(f"{url}/api/alerts/latest")
        # A user working: ui.js fetches this from the range-button click
        # handler, so it is real activity even though a fallback poll hits the
        # same URL. It must keep the session alive.
        clicking.get(f"{url}/api/severity-breakdown?range=24h")

    for label, session in (("idle", idle), ("polling", polling)):
        resp = session.get(f"{url}/dashboard/it", allow_redirects=False)
        assert resp.status_code == 302, f"{label} session outlived the timeout"
        assert "/login" in resp.headers["Location"], f"{label} session not sent to login"

    active = clicking.get(f"{url}/dashboard/it", allow_redirects=False)
    assert active.status_code == 200, (
        "a user clicking dashboard controls was logged out mid-session"
    )
