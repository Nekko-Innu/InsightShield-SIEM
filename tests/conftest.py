"""Playwright E2E fixtures: boot a real Flask instance against a throwaway DB/env."""
import json
import os
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

APP_DIR = Path(__file__).resolve().parent.parent
HOST = "127.0.0.1"
PORT = 5099
BASE_URL = f"http://{HOST}:{PORT}"
# The suite asserts both webhook gates, so the token has to be a known value.
WEBHOOK_TOKEN = "e2e-webhook-token"


def _wait_for_health(url: str, timeout: float = 15.0) -> None:
    import urllib.request
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{url}/health", timeout=1) as resp:
                if resp.status == 200:
                    return
        except OSError:
            time.sleep(0.3)
    raise RuntimeError(f"App did not become healthy at {url} within {timeout}s")


# (severity, minutes_ago, acknowledged, resolved) — one row per tuple. Covers
# every severity the dashboard filters on and all three lifecycle states, and
# every offset stays inside the 24h window the KPI tiles and the severity
# breakdown query.
SEED_ALERTS = [
    ("CRITICAL",      3,   0, 0),
    ("HIGH",          25,  1, 0),
    ("MEDIUM",        70,  1, 1),
    ("LOW",           140, 1, 1),
    ("INFORMATIONAL", 240, 0, 0),
]
SEED_DEVICES = ["POS-TERMINAL-01", "BRANCH-SERVER", "HR-WORKSTATION", "POS-TERMINAL-02"]


def _seed_alerts(db_path: Path) -> None:
    """
    Put rows in the throwaway DB so the data-dependent screens have something
    to render. Without this every dashboard, filter and chart test would be
    asserting against an empty state and would pass with the feature broken.

    Written straight to sqlite rather than through /wazuh-webhook: that path
    runs the AI chain, the validator, the router and the notifier, none of
    which have credentials here. The app opens WAL with busy_timeout=10000, so
    a second-process writer is safe.
    """
    pht = timezone(timedelta(hours=8))
    now = datetime.now(tz=pht)
    rows = []
    for i, (severity, minutes_ago, acked, resolved) in enumerate(SEED_ALERTS):
        ts = (now - timedelta(minutes=minutes_ago)).isoformat()
        device = SEED_DEVICES[i % len(SEED_DEVICES)]
        rows.append((
            ts,
            f"1000{i}",
            f"Seeded {severity.lower()} event",
            severity,
            device,
            # raw_alert and attack_trail are JSON strings, never dicts — the
            # alert detail page's Tree and Raw JSON tabs parse them.
            json.dumps({"rule": {"id": f"1000{i}", "level": 12 - i},
                        "agent": {"name": device}, "full_log": f"seeded {i}"}),
            f"Seeded {severity.lower()} alert on {device} for the E2E suite.",
            f"Seeded reasoning for alert {i}.",
            "seed",
            8.5,
            acked,
            "admin" if acked else None,
            ts if acked else None,
            # Same shape wazuh_receiver._extract_attack_trail writes: a dict of
            # curated blocks, which is what alert_detail.html's Tree/Table tabs
            # walk.
            json.dumps({
                "agent": {"id": f"00{i}", "name": device, "ip": f"192.168.100.{10 + i}"},
                "rule": {"id": f"1000{i}", "level": 12 - i,
                         "description": f"Seeded {severity.lower()} event"},
                "decoder": {"name": "seed"},
                "location": "/var/log/seed.log",
                "full_log": f"seeded raw log line {i}",
            }),
            resolved,
            "admin" if resolved else None,
            ts if resolved else None,
        ))

    conn = sqlite3.connect(db_path, timeout=10)
    try:
        conn.executemany(
            """
            INSERT INTO alerts (
                timestamp, rule_id, attack_type, severity, device_name,
                raw_alert, plain_text, ai_reasoning, provider_used, fk_grade,
                acknowledged, acknowledged_by, acknowledged_at,
                attack_trail, resolved, resolved_by, resolved_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        conn.commit()
    finally:
        conn.close()


def insert_alert(db_path: Path, device: str, severity: str = "HIGH") -> int:
    """Write one renderable alert straight to SQLite and return its id.

    Same column list as _seed_alerts, for tests that need to act as a second
    process writing to the running server's database.
    """
    ts = datetime.now(tz=timezone(timedelta(hours=8))).isoformat()
    raw = json.dumps({"rule": {"id": "5715", "level": 10},
                      "agent": {"name": device}, "full_log": "direct insert"})
    conn = sqlite3.connect(db_path, timeout=10)
    try:
        cursor = conn.execute(
            """
            INSERT INTO alerts (
                timestamp, rule_id, attack_type, severity, device_name,
                raw_alert, plain_text, ai_reasoning, provider_used, fk_grade,
                acknowledged, acknowledged_by, acknowledged_at,
                attack_trail, resolved, resolved_by, resolved_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (ts, "5715", f"Direct insert on {device}", severity, device, raw,
             f"Direct insert on {device}.", "n/a", "seed", 8.5,
             0, None, None, raw, 0, None, None),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


# live_server yields a URL string and ~30 tests destructure it as one, so the
# database path is handed over on the side rather than by widening that return.
_SERVER_DB: dict = {}


@pytest.fixture()
def live_server_db(live_server):
    """Path to the running server's SQLite file, for tests that need to act as a
    second process against the same database."""
    return _SERVER_DB["path"]


@pytest.fixture(scope="session")
def live_server(tmp_path_factory):
    # db.py resolves its sqlite file relative to the process CWD, not to
    # app.py's location. Running with CWD set to a throwaway temp dir (and
    # APP_DIR only on PYTHONPATH) gives every test run a brand-new
    # insightshield.db — the dev DB at the repo root is never touched.
    tmp_dir = tmp_path_factory.mktemp("insightshield-e2e")

    env = os.environ.copy()
    env["ENCRYPTION_KEY"] = Fernet.generate_key().decode()
    env["FLASK_SECRET_KEY"] = "e2e-test-secret-key"
    # The suite serves plain HTTP; a Secure cookie would never come back and
    # every login test would fail on a missing session.
    env["INSIGHTSHIELD_ALLOW_HTTP_COOKIES"] = "1"
    # /wazuh-webhook fails closed without this, so an unset token would turn
    # every ingest assertion into a 403.
    env["WAZUH_WEBHOOK_TOKEN"] = WEBHOOK_TOKEN
    # Production runs the scheduler in insightshield-worker.service, so the web
    # app no longer starts one by itself. The suite is a single process and
    # still wants the 30s agent-status poll (the login page's status strip reads
    # its snapshot), so it opts in explicitly.
    env["INSIGHTSHIELD_RUN_SCHEDULER"] = "1"
    env["PYTHONPATH"] = str(APP_DIR) + os.pathsep + env.get("PYTHONPATH", "")

    proc = subprocess.Popen(
        [sys.executable, "-c",
         "from app import app; app.run(host=%r, port=%d, debug=False, use_reloader=False)"
         % (HOST, PORT)],
        cwd=str(tmp_dir),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_for_health(BASE_URL)
        # Health means app import finished, so init_db() has created the table.
        _seed_alerts(tmp_dir / "insightshield.db")
        _SERVER_DB["path"] = tmp_dir / "insightshield.db"
        yield BASE_URL
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

