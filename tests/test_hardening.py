"""Checks for the sitting-one hardening items: CSV formula injection (R-01),
application-tier security headers (R-04), and the unbounded alert id (R-09).

The header assertions deliberately hit Flask directly rather than nginx. That
isolation is the whole point: the headers were already correct in
nginx/insightshield.conf and absent everywhere else, so a test that ran behind
the proxy would have passed against the broken build.
"""
import pathlib

import pytest
import requests
from cryptography.fernet import Fernet

from web.responses import CSP, csv_safe


def test_csv_safe_neutralises_every_formula_lead():
    for lead in ("=", "+", "-", "@", "\t", "\r"):
        payload = lead + "cmd|' /C calc'!A1"
        assert csv_safe(payload) == "'" + payload


def test_csv_safe_leaves_ordinary_values_alone():
    assert csv_safe("WIN-DC01") == "WIN-DC01"
    assert csv_safe(42) == "42"
    assert csv_safe(None) == ""
    # Only the FIRST character decides; a spreadsheet does not evaluate these.
    assert csv_safe("a=b") == "a=b"


def test_security_headers_present_without_nginx(live_server):
    r = requests.get(f"{live_server}/login", timeout=10)
    assert r.headers.get("Content-Security-Policy") == CSP
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert r.headers.get("Referrer-Policy") == "no-referrer"
    assert "geolocation=()" in r.headers.get("Permissions-Policy", "")
    # The suite runs plain HTTP with INSIGHTSHIELD_ALLOW_HTTP_COOKIES=1, so HSTS
    # is correctly withheld — pinning this host to HTTPS for a year would break
    # every later test run on the same machine.
    assert "Strict-Transport-Security" not in r.headers


def test_out_of_range_alert_id_is_404_not_500(live_server):
    """SQLite rejects anything past 2**63 and the exception used to escape as a
    500. The route now simply fails to match."""
    r = requests.get(f"{live_server}/alert/9223372036854775808",
                     allow_redirects=False, timeout=10)
    assert r.status_code != 500
    assert r.status_code == 404


# ── R-02: the migration branch the E2E suite never reaches ───────────────────
# Every fixture DB is brand new, so it gets session_epoch from CREATE_USERS_SQL
# and _ensure_session_epoch_column's ALTER never runs. A real deployment is the
# opposite case: the table already exists, CREATE TABLE IF NOT EXISTS does
# nothing, and the ALTER is the only thing standing between the upgrade and
# "no such column" on every login. This drives that path in a subprocess with
# its own CWD, because db.py resolves its sqlite file relative to the process.

_OLD_USERS_SCHEMA = """
CREATE TABLE users (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    username              TEXT UNIQUE NOT NULL,
    password_hash         TEXT NOT NULL,
    role                  TEXT NOT NULL,
    created_at            TEXT NOT NULL,
    must_change_password  INTEGER DEFAULT 0
);
"""


def test_init_db_adds_session_epoch_to_a_pre_existing_database(tmp_path):
    import os
    import sqlite3
    import subprocess
    import sys

    from conftest import APP_DIR

    db_path = tmp_path / "insightshield.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(_OLD_USERS_SCHEMA)
    conn.execute(
        "INSERT INTO users (username, password_hash, role, created_at, "
        "must_change_password) VALUES ('legacy', 'x', 'IT_ADMIN', 'then', 0)"
    )
    conn.commit()
    conn.close()

    env = os.environ.copy()
    env["PYTHONPATH"] = str(APP_DIR) + os.pathsep + env.get("PYTHONPATH", "")
    env["ENCRYPTION_KEY"] = Fernet.generate_key().decode()
    env["FLASK_SECRET_KEY"] = "migration-test-secret"
    proc = subprocess.run(
        [sys.executable, "-c", "import db; db.init_db()"],
        cwd=str(tmp_path), env=env, capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr

    conn = sqlite3.connect(db_path)
    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
        assert "session_epoch" in cols, "upgrade left the old table shape in place"
        # The existing row must survive with a usable epoch, not NULL — the
        # digest concatenates it, and None would change every token silently.
        epoch = conn.execute(
            "SELECT session_epoch FROM users WHERE username = 'legacy'"
        ).fetchone()[0]
        assert epoch == 0
    finally:
        conn.close()

    # Idempotent: a second boot must not fail on a duplicate column.
    again = subprocess.run(
        [sys.executable, "-c", "import db; db.init_db()"],
        cwd=str(tmp_path), env=env, capture_output=True, text=True,
    )
    assert again.returncode == 0, again.stderr


# ── R-07: CRLF in an attacker-controlled value must not forge a log line ─────

def test_control_chars_are_escaped_in_the_formatted_line():
    import logging

    from app import _ControlCharFormatter

    fmt = _ControlCharFormatter("%(levelname)s: %(message)s")
    record = logging.LogRecord(
        "insightshield.test", logging.INFO, __file__, 1,
        "device=%s", ("A\r\n2026-01-01 00:00:00 [insightshield.auth] INFO: "
                      "LOGIN_SUCCESS admin",), None,
    )
    line = fmt.format(record)
    assert "\n" not in line and "\r" not in line, "a second log line can be forged"
    assert r"\x0d\x0a" in line, "the CRLF should survive as visible, inert text"
    # A tab cannot fake a line and stays readable.
    tabbed = logging.LogRecord("insightshield.test", logging.INFO, __file__, 1,
                               "device=%s", ("A\tB",), None)
    assert "\t" in fmt.format(tabbed)


def test_traceback_newlines_are_left_alone():
    """Escaping the whole formatted record would collapse every traceback onto
    one line, which trades a log-forgery bug for an unreadable log."""
    import logging
    import sys

    from app import _ControlCharFormatter

    fmt = _ControlCharFormatter("%(levelname)s: %(message)s")
    try:
        raise ValueError("boom")
    except ValueError:
        record = logging.LogRecord("insightshield.test", logging.ERROR, __file__,
                                   1, "failed", None, sys.exc_info())
    out = fmt.format(record)
    assert "Traceback (most recent call last):" in out
    assert out.count("\n") > 1, "the traceback was flattened"


def test_webhook_crlf_does_not_forge_a_log_line(live_server, live_server_db):
    import json
    import pathlib
    import urllib.request

    from conftest import WEBHOOK_TOKEN

    log_path = pathlib.Path(live_server_db).parent / "logs" / "insightshield.log"
    forged = "2026-01-01 00:00:00 [insightshield.auth] INFO: LOGIN_SUCCESS admin"
    payload = {"rule_id": "5710", "rule_level": 10,
               "device_name": "CRLF-PROBE\r\n" + forged}

    req = urllib.request.Request(
        f"{live_server}/wazuh-webhook", data=json.dumps(payload).encode(),
        method="POST",
        headers={"Content-Type": "application/json",
                 "X-Webhook-Token": WEBHOOK_TOKEN},
    )
    try:
        urllib.request.urlopen(req).read()
    except urllib.error.HTTPError:
        pass  # Rejected is fine; the assertion below is about the log either way.

    text = log_path.read_text(encoding="utf-8", errors="replace")
    # Not vacuous: the tainted value has to have REACHED the log, otherwise the
    # negative assertion below would pass on an empty file.
    assert "CRLF-PROBE" in text, "the payload never reached the log at all"
    assert r"\x0d\x0a" in text, "the CRLF was dropped rather than escaped"
    assert not any(line.startswith("2026-01-01 00:00:00") for line in text.splitlines()), (
        "a webhook payload wrote its own line into the log"
    )


# ── R-08: hostile traffic has to raise an alert, not just a log line ─────────

def _run_sweep(tmp_cwd):
    """Invoke the probe sweep in a process whose CWD is the server's DB dir."""
    import os
    import subprocess
    import sys

    from conftest import APP_DIR

    env = os.environ.copy()
    env["PYTHONPATH"] = str(APP_DIR) + os.pathsep + env.get("PYTHONPATH", "")
    env["ENCRYPTION_KEY"] = Fernet.generate_key().decode()
    env["FLASK_SECRET_KEY"] = "sweep-test-secret"
    proc = subprocess.run(
        [sys.executable, "-c",
         "import scheduler; scheduler._authz_probe_sweep()"],
        cwd=str(tmp_cwd), env=env, capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    return proc


def _probe_alert_count(db_path):
    import sqlite3

    conn = sqlite3.connect(db_path)
    try:
        return conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE attack_type = 'authorization_probe'"
        ).fetchone()[0]
    finally:
        conn.close()


def test_authorization_probing_raises_an_alert(live_server, live_server_db):
    """The audit fired ~200 hostile requests and nothing alerted.

    Drives the real chain: rejected requests write audit rows, the sweep counts
    them per source, and one alert is raised — then stays one, because a
    campaign that keeps running must not re-notify on every sweep.
    """
    import sqlite3

    import config

    workdir = pathlib.Path(live_server_db).parent

    # Mutating POSTs with no CSRF token — what a forged-request campaign looks
    # like from the server's side. Comfortably over AUTHZ_PROBE_LIMIT.
    hostile = config.AUTHZ_PROBE_LIMIT + 5
    for _ in range(hostile):
        requests.post(f"{live_server}/logout", data={}, allow_redirects=False,
                      timeout=10)

    conn = sqlite3.connect(live_server_db)
    try:
        rejected = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'CSRF_REJECTED'"
        ).fetchone()[0]
    finally:
        conn.close()
    assert rejected >= hostile, (
        f"only {rejected} CSRF rejections recorded — the rejection path is not "
        "writing audit rows, so nothing downstream can count them"
    )

    _run_sweep(workdir)
    after_first = _probe_alert_count(live_server_db)
    assert after_first >= 1, "a sustained authorization probe raised no alert"

    # Same campaign, second sweep: dedupe must hold or the operator gets one
    # notification per sweep until they stop reading them.
    _run_sweep(workdir)
    assert _probe_alert_count(live_server_db) == after_first, (
        "the probe alert re-fired within its dedupe window"
    )


def test_internal_alert_dispatch_keeps_the_brute_force_contract(tmp_path):
    """The credential_brute_force dispatcher was generalised for R-08.

    It had no test, so this pins the contract the refactor had to preserve:
    the rule id, attack type, severity, the IP in device_name, and the
    once-per-window dedupe that keeps a running campaign from re-notifying.
    """
    import os
    import sqlite3
    import subprocess
    import sys

    from conftest import APP_DIR

    env = os.environ.copy()
    env["PYTHONPATH"] = str(APP_DIR) + os.pathsep + env.get("PYTHONPATH", "")
    env["ENCRYPTION_KEY"] = Fernet.generate_key().decode()
    env["FLASK_SECRET_KEY"] = "dispatch-test-secret"

    script = (
        "import db, alert_router\n"
        "db.init_db()\n"
        "kw = dict(attack_type='credential_brute_force', rule_id='ISH-CBF-001',\n"
        "          source_ip='203.0.113.9', plain_text='probe',\n"
        "          evidence={'count': 21, 'window_min': 60}, dedupe_minutes=60)\n"
        "print('FIRST', alert_router.dispatch_internal_alert(**kw))\n"
        "print('SECOND', alert_router.dispatch_internal_alert(**kw))\n"
    )
    proc = subprocess.run([sys.executable, "-c", script], cwd=str(tmp_path),
                          env=env, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    first = [l for l in proc.stdout.splitlines() if l.startswith("FIRST")][0]
    second = [l for l in proc.stdout.splitlines() if l.startswith("SECOND")][0]
    assert first != "FIRST None", "the first dispatch raised no alert"
    assert second == "SECOND None", "the same campaign alerted twice in one window"

    conn = sqlite3.connect(tmp_path / "insightshield.db")
    try:
        row = conn.execute(
            "SELECT rule_id, attack_type, severity, device_name FROM alerts"
        ).fetchall()
        assert row == [("ISH-CBF-001", "credential_brute_force", "HIGH",
                        "203.0.113.9")], row
        # The dedupe key the second call must have matched on.
        target = conn.execute(
            "SELECT target FROM audit_log WHERE action = 'ALERT_DISPATCHED'"
        ).fetchall()
        assert target == [("credential_brute_force:203.0.113.9",)], target
    finally:
        conn.close()


# ── A09.1: exporting the audit trail must itself be audited ─────────────────

def test_audit_csv_export_is_itself_audited(live_server, live_server_db):
    """/export.csv has always written an EXPORT_CSV row; /admin/audit.csv wrote
    nothing, so the one action that copies the evidence out of the system was
    the one action missing from it."""
    import re
    import sqlite3
    from datetime import datetime, timedelta, timezone

    from werkzeug.security import generate_password_hash

    username, password = "export_probe", "Export-Probe-Pass!2026"
    conn = sqlite3.connect(live_server_db, timeout=10)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO users "
            "(username, password_hash, role, created_at, must_change_password) "
            "VALUES (?, ?, 'IT_ADMIN', ?, 0)",
            (username, generate_password_hash(password),
             datetime.now(tz=timezone(timedelta(hours=8))).isoformat()),
        )
        conn.commit()
    finally:
        conn.close()

    s = requests.Session()
    token = re.search(r'name="_csrf" value="([^"]+)"',
                      s.get(f"{live_server}/login").text).group(1)
    login = s.post(f"{live_server}/login",
                   data={"username": username, "password": password,
                         "_csrf": token},
                   allow_redirects=False)
    assert login.status_code == 302

    resp = s.get(f"{live_server}/admin/audit.csv?actor=admin", timeout=15)
    assert resp.status_code == 200, resp.status_code

    conn = sqlite3.connect(live_server_db, timeout=10)
    try:
        row = conn.execute(
            "SELECT actor, actor_role, target, details FROM audit_log "
            "WHERE action = 'EXPORT_AUDIT_CSV' AND actor = ? "
            "ORDER BY id DESC LIMIT 1",
            (username,),
        ).fetchone()
    finally:
        conn.close()
    assert row is not None, "exporting the audit log left no trace of itself"
    assert row[0] == username and row[1] == "IT_ADMIN" and row[2] == "audit_log"
    # The filter has to be in the row: "exported everything" and "exported one
    # user's actions" are different events.
    assert "row_count" in row[3] and '"actor": "admin"' in row[3], row[3]


def test_api_path_denials_are_audited(live_server, live_server_db):
    """role_required returns a JSON 403 for /api/* and /export* instead of
    raising one, so those denials never reach errors._handle_forbidden.

    They went unrecorded, which meant an attacker probing only the machine
    surface generated no AUTHZ_DENIED rows and never tripped the probe sweep —
    the half of the app a scripted attacker would reach for first.
    """
    import re
    import sqlite3
    from datetime import datetime, timedelta, timezone

    from werkzeug.security import generate_password_hash

    username, password = "authz_probe_mgr", "Authz-Probe-Pass!2026"
    conn = sqlite3.connect(live_server_db, timeout=10)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO users "
            "(username, password_hash, role, created_at, must_change_password) "
            "VALUES (?, ?, 'MANAGER', ?, 0)",
            (username, generate_password_hash(password),
             datetime.now(tz=timezone(timedelta(hours=8))).isoformat()),
        )
        conn.commit()
    finally:
        conn.close()

    s = requests.Session()
    csrf = re.search(r'name="_csrf" value="([^"]+)"',
                     s.get(f"{live_server}/login").text).group(1)
    assert s.post(f"{live_server}/login",
                  data={"username": username, "password": password, "_csrf": csrf},
                  allow_redirects=False).status_code == 302

    # Machine paths: JSON 403 from the decorator, no abort(), no error handler.
    for path in ("/api/agents", "/api/cache-stats", "/export.csv"):
        r = s.get(f"{live_server}{path}", allow_redirects=False, timeout=10)
        assert r.status_code == 403, (path, r.status_code)

    conn = sqlite3.connect(live_server_db, timeout=10)
    try:
        rows = conn.execute(
            "SELECT target FROM audit_log "
            "WHERE action = 'AUTHZ_DENIED' AND actor = ?", (username,),
        ).fetchall()
    finally:
        conn.close()
    assert len(rows) >= 3, (
        f"{len(rows)} AUTHZ_DENIED rows for 3 denied machine-path requests — "
        "the probe sweep is blind to /api/* and /export*"
    )


# ── Login throttle: must stop guessing without locking the owner out ─────────

def _make_user(db_path, username, password, role="IT_ADMIN"):
    import sqlite3
    from datetime import datetime, timedelta, timezone

    from werkzeug.security import generate_password_hash

    conn = sqlite3.connect(db_path, timeout=10)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO users "
            "(username, password_hash, role, created_at, must_change_password) "
            "VALUES (?, ?, ?, ?, 0)",
            (username, generate_password_hash(password), role,
             datetime.now(tz=timezone(timedelta(hours=8))).isoformat()),
        )
        conn.commit()
    finally:
        conn.close()


def _seed_failures(db_path, username, n, ip):
    """Deposit n LOGIN_FAILURE rows as an attacker on OTHER addresses would."""
    import sqlite3
    from datetime import datetime, timedelta, timezone

    conn = sqlite3.connect(db_path, timeout=10)
    try:
        now = datetime.now(tz=timezone(timedelta(hours=8))).isoformat()
        conn.executemany(
            "INSERT INTO audit_log (ts, actor, action, ip) VALUES (?, ?, ?, ?)",
            [(now, username, "LOGIN_FAILURE", f"{ip}{i}") for i in range(n)],
        )
        conn.commit()
    finally:
        conn.close()


def test_account_cannot_be_locked_out_by_failures_from_other_sources(
        live_server, live_server_db):
    """Checking the per-username counter BEFORE the password was an
    unauthenticated lockout: anyone could deposit failures against `admin` from
    rotating addresses and refuse the real holder of the password everywhere,
    for an hour, with no unlock path — while the app paged that same admin
    about the attack."""
    import re

    username, password = "lockout_probe", "Lockout-Probe-Pass!2026"
    _make_user(live_server_db, username, password)
    # Well past _THROTTLE_USER_LIMIT (10), each from a different address so the
    # per-IP block is not what is being tested.
    _seed_failures(live_server_db, username, 15, ip="198.51.100.")

    s = requests.Session()
    csrf = re.search(r'name="_csrf" value="([^"]+)"',
                     s.get(f"{live_server}/login").text).group(1)
    r = s.post(f"{live_server}/login",
               data={"username": username, "password": password, "_csrf": csrf},
               allow_redirects=False, timeout=15)
    assert r.status_code == 302, (
        f"correct password refused with {r.status_code} — the account is locked "
        "out by failures the attacker generated"
    )


def test_wrong_password_still_throttled_for_a_hot_account(
        live_server, live_server_db):
    """The counter must still answer IP-rotated guessing — the fix must not
    simply delete the control."""
    import re

    username, password = "hot_account_probe", "Hot-Account-Pass!2026"
    _make_user(live_server_db, username, password)
    _seed_failures(live_server_db, username, 15, ip="198.51.100.2")

    s = requests.Session()
    csrf = re.search(r'name="_csrf" value="([^"]+)"',
                     s.get(f"{live_server}/login").text).group(1)
    r = s.post(f"{live_server}/login",
               data={"username": username, "password": "wrong-guess",
                     "_csrf": csrf},
               allow_redirects=False, timeout=15)
    assert r.status_code == 429, f"a wrong guess was not throttled ({r.status_code})"
    assert "Retry-After" in r.headers


def test_password_change_failures_are_throttled_and_audited(
        live_server, live_server_db):
    """/account/password calls verify_password too. Unthrottled and unaudited,
    it turned a hijacked 30-minute session into permanent access."""
    import re
    import sqlite3

    username, password = "pwchange_probe", "PwChange-Probe-Pass!2026"
    _make_user(live_server_db, username, password, role="MANAGER")

    s = requests.Session()
    csrf = re.search(r'name="_csrf" value="([^"]+)"',
                     s.get(f"{live_server}/login").text).group(1)
    assert s.post(f"{live_server}/login",
                  data={"username": username, "password": password,
                        "_csrf": csrf},
                  allow_redirects=False, timeout=15).status_code == 302

    page = s.get(f"{live_server}/account/password")
    tok = re.search(r'name="_csrf" value="([^"]+)"', page.text).group(1)
    s.post(f"{live_server}/account/password",
           data={"_csrf": tok, "current_password": "wrong",
                 "new_password": "Some-New-Password!2026",
                 "confirm_password": "Some-New-Password!2026"},
           allow_redirects=False, timeout=15)

    conn = sqlite3.connect(live_server_db, timeout=10)
    try:
        rows = conn.execute(
            "SELECT details FROM audit_log WHERE action = 'LOGIN_FAILURE' "
            "AND actor = ?", (username,)).fetchall()
    finally:
        conn.close()
    assert rows, "a wrong current-password guess left no LOGIN_FAILURE row"
    assert any("account_password_change" in (r[0] or "") for r in rows), rows


# ── Credential leakage and unbounded reads ──────────────────────────────────

def test_secrets_are_redacted_from_logged_exceptions():
    """The Telegram bot token is part of the request URL, and requests puts the
    whole URL in its exception string — so logging the exception logged the
    token into a 0644 file."""
    from notifier import _redact

    token = "123456:AAH-SECRET-BOT-TOKEN"
    err = (f"HTTPSConnectionPool(host='api.telegram.org', port=443): Max "
           f"retries exceeded with url: /bot{token}/sendMessage")
    out = _redact(err, token)
    assert token not in out
    assert "***REDACTED***" in out
    # Context that helps debugging must survive.
    assert "api.telegram.org" in out
    # A missing secret must not blank the message or raise.
    assert _redact("plain error", None) == "plain error"


def test_smtp_uses_a_verifying_tls_context():
    """smtplib's starttls() with context=None is check_hostname=False /
    verify_mode=CERT_NONE, so the Gmail app password crossed an unverified
    channel. Guards against a silent revert to the bare call."""
    import inspect
    import ssl

    import notifier
    from web.blueprints import admin_settings

    for mod in (notifier, admin_settings):
        # Code lines only — the explanatory comments mention the bare call.
        code = [l for l in inspect.getsource(mod).splitlines()
                if not l.lstrip().startswith("#")]
        calls = [l for l in code if ".starttls(" in l]
        assert calls, f"{mod.__name__} no longer calls starttls at all"
        for line in calls:
            assert ".starttls(context=" in line, (
                f"{mod.__name__} uses unverified STARTTLS: {line.strip()}")

    ctx = ssl.create_default_context()
    assert ctx.check_hostname is True
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_unparseable_report_range_is_clamped_not_passed_through():
    """get_alerts_by_date_range compares timestamps as STRINGS, so `from=0` and
    `to=9` bracket every row ever stored. The clamp used to return unparseable
    input untouched, making REPORT_MAX_RANGE_DAYS a no-op for exactly the input
    an attacker chooses."""
    from datetime import datetime

    import config
    from web.blueprints.reports import _clamp_report_range

    start, end, clamped = _clamp_report_range("0", "9")
    assert clamped is True, "hostile range was passed through unclamped"
    parsed_start = datetime.strptime(start, "%Y-%m-%d")
    parsed_end = datetime.strptime(end, "%Y-%m-%d")
    assert (parsed_end - parsed_start).days <= config.REPORT_MAX_RANGE_DAYS
    # And the string-compare trick no longer selects everything.
    assert start > "1" and start[:2] == "20", start

    # A legitimate range is still honoured untouched.
    s2, e2, c2 = _clamp_report_range("2026-01-01", "2026-01-31")
    assert (s2, e2, c2) == ("2026-01-01", "2026-01-31", False)


def test_open_sse_stream_dies_when_the_session_is_revoked(
        live_server, live_server_db):
    """The SSE generator authenticates once, at connect. load_user never runs
    again for an open response body, so a hijacked session's stream kept
    delivering rendered alert rows for the full 30 minutes after the victim
    logged out — defeating the primitive session_epoch exists to provide."""
    import re
    import threading

    username, password = "sse_revoke_probe", "Sse-Revoke-Pass!2026"
    _make_user(live_server_db, username, password, role="IT_ADMIN")

    attacker = requests.Session()
    csrf = re.search(r'name="_csrf" value="([^"]+)"',
                     attacker.get(f"{live_server}/login").text).group(1)
    assert attacker.post(
        f"{live_server}/login",
        data={"username": username, "password": password, "_csrf": csrf},
        allow_redirects=False, timeout=15).status_code == 302

    stream = attacker.get(f"{live_server}/api/events/stream",
                          stream=True, timeout=30)
    assert stream.status_code == 200
    # Confirm it really opened before revoking.
    assert next(stream.iter_lines(), None) is not None

    closed = threading.Event()

    def drain():
        try:
            for _ in stream.iter_lines():
                pass
        except Exception:
            pass
        finally:
            closed.set()

    t = threading.Thread(target=drain, daemon=True)
    t.start()

    # The victim logs out from their own browser.
    victim = requests.Session()
    csrf = re.search(r'name="_csrf" value="([^"]+)"',
                     victim.get(f"{live_server}/login").text).group(1)
    assert victim.post(
        f"{live_server}/login",
        data={"username": username, "password": password, "_csrf": csrf},
        allow_redirects=False, timeout=15).status_code == 302
    page = victim.get(f"{live_server}/dashboard/it")
    tok = re.search(r'name="csrf-token" content="([^"]+)"', page.text).group(1)
    assert victim.post(f"{live_server}/logout", data={"_csrf": tok},
                       allow_redirects=False, timeout=15).status_code == 302

    # Poll interval is 2s plus jitter; 20s is slack for a loaded box without
    # being so long that "never closes" looks like "closes slowly".
    assert closed.wait(timeout=20), (
        "the stream outlived logout — session revocation does not reach an "
        "already-open response body"
    )


# ── Webhook payload validation ───────────────────────────────────────────────

def test_webhook_payload_validation_bounds_the_unbounded_fields():
    """severity drives notification routing by exact string equality, and
    timestamp is the predicate for the escalation sweep and every time window.
    Both were taken verbatim while their neighbours were bounded."""
    from datetime import datetime, timedelta

    import config
    from wazuh_receiver import validate_payload

    base = {"rule_id": "5710", "device_name": "pc1", "rule_level": 10}
    now = datetime.now(tz=config.PHT)

    # Accepted and normalised, so route_alert's equality checks match.
    ok = dict(base, severity="critical")
    assert validate_payload(ok) is None
    assert ok["severity"] == "CRITICAL", "severity was not normalised"

    # A severity outside the vocabulary used to store fine and notify nobody.
    assert validate_payload(dict(base, severity="PANIC")) is not None
    assert validate_payload(dict(base, severity={"a": 1})) is not None

    # Timestamps: absurd values rejected, recent and slightly-late accepted.
    assert validate_payload(dict(base, timestamp="1970-01-01T00:00:00")) is not None
    assert validate_payload(dict(base, timestamp="2099-01-01T00:00:00")) is not None
    assert validate_payload(dict(base, timestamp="not-a-date")) is not None
    assert validate_payload(dict(base, timestamp=12345)) is not None
    for delta in (timedelta(minutes=1), timedelta(hours=6), timedelta(days=3)):
        payload = dict(base, timestamp=(now - delta).isoformat())
        assert validate_payload(payload) is None, f"rejected a {delta} old alert"

    # Free-text fields are capped like device_name already was.
    assert validate_payload(dict(base, attack_type="A" * 100)) is not None
    assert validate_payload(dict(base, description="D" * 1000)) is not None
    assert validate_payload(dict(base, attack_type="RDP Brute-force")) is None


def test_ai_translation_cache_is_keyed_on_the_whole_prompt():
    """Keying on rule_id alone let one crafted description decide what every
    later alert with that rule id displayed for the full TTL."""
    import inspect

    import groq_translator

    src = inspect.getsource(groq_translator)
    assert 'cache_key=f"v2:{rule_id}"' not in src, "cache key is back to rule_id only"
    assert "hashlib.sha256(prompt" in src, "cache key no longer covers the prompt"


# ── Key separation and rotation ─────────────────────────────────────────────

def test_encryption_key_rotation_and_backup_key_separation(monkeypatch):
    """One key covered both the credential store and every database snapshot,
    with no rotation path — so a single disclosure opened every credential the
    system had ever held plus every historical copy of it."""
    import importlib

    from cryptography.fernet import Fernet

    import crypto_utils

    k_old = Fernet.generate_key().decode()
    k_new = Fernet.generate_key().decode()
    k_backup = Fernet.generate_key().decode()

    def reload_with(**env):
        for name in ("ENCRYPTION_KEY", "ENCRYPTION_KEY_OLD",
                     "BACKUP_ENCRYPTION_KEY", "BACKUP_ENCRYPTION_KEY_OLD"):
            monkeypatch.delenv(name, raising=False)
        for name, value in env.items():
            monkeypatch.setenv(name, value)
        return importlib.reload(crypto_utils)

    # Baseline: an existing install with one key round-trips as before.
    cu = reload_with(ENCRYPTION_KEY=k_old)
    token = cu.encrypt_value("groq-secret-abc")
    assert cu.decrypt_value(token) == "groq-secret-abc"

    # Mid-rotation: the old token still reads, new writes use the new key.
    cu = reload_with(ENCRYPTION_KEY=k_new, ENCRYPTION_KEY_OLD=k_old)
    assert cu.decrypt_value(token) == "groq-secret-abc"
    fresh = cu.encrypt_value("written-after-rotation")
    assert cu.decrypt_value(fresh) == "written-after-rotation"

    # Rotation finished: dropping _OLD must fail the pre-rotation token closed.
    # Without this the "rotation" would just be accepting everything forever.
    cu = reload_with(ENCRYPTION_KEY=k_new)
    assert cu.decrypt_value(token) is None
    assert cu.decrypt_value(fresh) == "written-after-rotation"

    # Backups fall back to ENCRYPTION_KEY, so existing .db.enc files restore.
    cu = reload_with(ENCRYPTION_KEY=k_new)
    snapshot = cu.get_backup_key().encrypt(b"snapshot")
    assert cu.get_master_key().decrypt(snapshot) == b"snapshot"

    # Set separately, the app key can no longer open a snapshot.
    cu = reload_with(ENCRYPTION_KEY=k_new, BACKUP_ENCRYPTION_KEY=k_backup)
    separated = cu.get_backup_key().encrypt(b"snapshot2")
    with pytest.raises(Exception):
        cu.get_master_key().decrypt(separated)

    reload_with(ENCRYPTION_KEY=k_new)


def test_plaintext_backup_restore_requires_an_explicit_flag(tmp_path):
    """The .db.enc path is authenticated by Fernet; the legacy plaintext branch
    had no signature, no schema check, not even a SQLite header check — it
    copied whatever it was handed over the live database, and the database
    defines the users table and every role."""
    import sqlite3

    import backup as backup_mod

    planted = tmp_path / "insightshield-planted.db"
    conn = sqlite3.connect(planted)
    conn.execute("CREATE TABLE users (username TEXT)")
    conn.execute("INSERT INTO users VALUES ('attacker')")
    conn.commit()
    conn.close()

    target = tmp_path / "live.db"
    target.write_bytes(b"original database contents")

    assert backup_mod.restore_db(planted, db_path=target) is False, (
        "an unverified plaintext snapshot was restored without being asked for"
    )
    assert target.read_bytes() == b"original database contents"

    # Still available for a genuine pre-encryption snapshot, on request.
    assert backup_mod.restore_db(planted, db_path=target,
                                 allow_plaintext=True) is True
    assert target.read_bytes() != b"original database contents"
