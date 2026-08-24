"""Checks for the sitting-one hardening items: CSV formula injection (R-01),
application-tier security headers (R-04), and the unbounded alert id (R-09).

The header assertions deliberately hit Flask directly rather than nginx. That
isolation is the whole point: the headers were already correct in
nginx/insightshield.conf and absent everywhere else, so a test that ran behind
the proxy would have passed against the broken build.
"""
import pathlib

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
