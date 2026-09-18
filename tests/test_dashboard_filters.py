"""Alert-filter persistence: the "Hide low severity" toggle must survive
navigation (open an alert, click Dashboard) instead of reverting.

Tests dashboards._alert_filters_from_request() through a minimal Flask app so
the session cookie carries across requests, the way a browser does — no DB, no
real dashboard render needed.
"""
import os

os.environ.setdefault("FLASK_SECRET_KEY", "test-only-" + "0" * 32)
os.environ.setdefault("BOOTSTRAP_ADMIN_PASSWORD", "test-Admin!2026")
os.environ.setdefault("BOOTSTRAP_MANAGER_PASSWORD", "test-Manager!2026")

import pytest
from flask import Flask, jsonify

import web.blueprints.dashboards as d


@pytest.fixture()
def client():
    app = Flask(__name__)
    app.secret_key = "test"

    @app.route("/f")
    def f():
        return jsonify(d._alert_filters_from_request())

    return app.test_client()


def test_applied_submit_is_authoritative_and_saved(client):
    r = client.get("/f?applied=1&hide_low=1&severity=HIGH")
    j = r.get_json()
    assert j["hide_low"] is True
    assert j["severity"] == "HIGH"


def test_bare_nav_reloads_saved_filters(client):
    # Submit once (persist), then a bare nav with no params must reload it —
    # this is the revert bug: previously the toggle came back off here.
    client.get("/f?applied=1&hide_low=1&severity=CRITICAL")
    j = client.get("/f").get_json()
    assert j["hide_low"] is True
    assert j["severity"] == "CRITICAL"


def test_unchecked_hide_low_on_submit_clears_it(client):
    client.get("/f?applied=1&hide_low=1")           # on
    client.get("/f?applied=1&severity=HIGH")        # resubmit, checkbox unchecked
    j = client.get("/f").get_json()
    assert j["hide_low"] is False                    # cleared, not sticky-on
    assert j["severity"] == "HIGH"


def test_clear_link_empties_saved_filters(client):
    # The Clear link is href="{path}?applied=1" (empty submit). It must WIPE the
    # saved filters, not just show page 1 — otherwise a following bare nav reloads
    # the old search/severity and the search bar repopulates (the Clear bug).
    client.get("/f?applied=1&hide_low=1&severity=HIGH&q=lsass")
    cleared = client.get("/f?applied=1").get_json()   # what the Clear link hits
    assert cleared == {"status": "", "severity": "", "q": "", "hide_low": False}
    # And it stuck: a later bare nav stays empty instead of resurrecting them.
    assert client.get("/f").get_json()["q"] == ""


def test_shared_link_uses_args_without_touching_session(client):
    client.get("/f?applied=1&hide_low=1")            # session: hide_low on
    # A shared/deep link (no `applied` marker) honours its own params...
    shared = client.get("/f?severity=LOW").get_json()
    assert shared["severity"] == "LOW"
    assert shared["hide_low"] is False               # link didn't ask to hide
    # ...and must NOT have overwritten the saved preference.
    assert client.get("/f").get_json()["hide_low"] is True
