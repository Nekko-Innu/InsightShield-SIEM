"""E2E UI walk: every rendered page in both roles, plus the interactive bits.

test_smoke.py is the security tripwire — auth, RBAC, CSRF, traversal. This file
answers a different question: does the UI actually work? Every page is visited
with a console listener attached, so a template that renders 200 while its JS
throws still fails.

The live_server fixture seeds five alerts (conftest.SEED_ALERTS), so the
dashboards, filters, charts and alert detail render against real rows rather
than empty states.
"""
import json
import urllib.error
import urllib.request

import pytest

import sqlite3

from conftest import SEED_ALERTS, WEBHOOK_TOKEN, insert_alert
from test_smoke import IT_ADMIN, MANAGER, _csrf_token, _login


def _watch(page):
    """Collect console errors and uncaught exceptions for the rest of the test.

    "Failed to load resource" is filtered out. It is a network condition, not a
    JS defect, and the document's own status is asserted separately in _visit.
    Keeping it made the suite flaky in a way that said nothing about the app:
    every test calls _login, each login page load polls /api/status once, and
    30-odd logins a minute from one IP trips that endpoint's 30/min per-IP cap.
    The reply lands after the next navigation has started, so the 429 surfaces
    as a console error on whatever page happened to load next.
    """
    errors = []
    page.on(
        "console",
        lambda m: errors.append(m.text)
        if m.type == "error" and "Failed to load resource" not in m.text
        else None,
    )
    page.on("pageerror", lambda e: errors.append(str(e)))
    return errors


def _visit(page, url, path):
    """Navigate and assert the page rendered without a server or client error."""
    errors = _watch(page)
    response = page.goto(f"{url}{path}")
    assert response is not None, f"no response for {path}"
    assert response.status < 400, f"{path} returned {response.status}"
    assert not errors, f"{path} logged JS errors: {errors}"


def _post(url, path, data=None, headers=None):
    """Plain HTTP POST — for the endpoints where a browser session is beside the point."""
    body = json.dumps(data).encode() if data is not None else b""
    req = urllib.request.Request(
        f"{url}{path}", data=body, method="POST",
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


# ── Page walk ────────────────────────────────────────────────────────────────

IT_PAGES = [
    "/dashboard/it",
    "/alert/1",
    "/report",
    "/report?generated=1",
    "/report?generated=1&form=management",
    "/admin/settings?tab=service",
    "/admin/settings?tab=audit",
    "/admin/settings?tab=backups",
    "/admin/settings?tab=errors",
]


@pytest.mark.parametrize("path", IT_PAGES)
def test_it_admin_pages_load_clean(page, live_server, path):
    _login(page, live_server, IT_ADMIN)
    _visit(page, live_server, path)


@pytest.mark.parametrize("path", ["/dashboard/manager", "/alert/1", "/report",
                                  "/report?generated=1"])
def test_manager_pages_load_clean(page, live_server, path):
    _login(page, live_server, MANAGER)
    _visit(page, live_server, path)


def test_login_page_loads_clean_anonymous(page, live_server):
    _visit(page, live_server, "/login")
    # The status chip is populated by login-status.js polling /api/status. It
    # is the only pre-auth network call on the page, so a failure here is
    # invisible except as a stuck placeholder.
    page.wait_for_function(
        "document.querySelector('[data-status-summary]')?.textContent.trim().length > 0"
    )


def test_not_found_page_renders_for_authenticated_user(page, live_server):
    _login(page, live_server, IT_ADMIN)
    # Not _visit: that asserts status < 400, which is the whole point here.
    errors = _watch(page)
    response = page.goto(f"{live_server}/no-such-page")
    assert response.status == 404
    assert page.get_by_text("Page not found").first.is_visible()
    assert not errors, f"404 page logged JS errors: {errors}"


# ── Interaction ──────────────────────────────────────────────────────────────

def test_manager_feed_polls_the_real_endpoint(page, live_server):
    """The poll URL used to come from a url_for-globals introspection hack that
    yielded '' on any surprise, which ui.js reads as "don't poll"."""
    _login(page, live_server, MANAGER)
    page.goto(f"{live_server}/dashboard/manager")
    assert page.get_attribute("#alerts-feed", "data-poll-url") == "/api/alerts/latest"


def test_manager_feed_lists_seeded_alerts(page, live_server):
    _login(page, live_server, MANAGER)
    page.goto(f"{live_server}/dashboard/manager")
    assert page.locator("#alerts-feed li").count() >= len(SEED_ALERTS)


def test_manager_filtered_feed_reloads_for_a_serious_alert(page, live_server, live_server_db):
    """A HIGH/CRITICAL arrival reloads the feed with no click, filter or not.
    Routine arrivals raise no notice at all — they come every minute."""
    _login(page, live_server, MANAGER)
    page.goto(f"{live_server}/dashboard/manager?severity=HIGH")
    page.wait_for_selector("#alerts-feed")
    insert_alert(live_server_db, "MGR-LIVE-LOW", "LOW")

    # One 15s poll tick, plus slack.
    with page.expect_event("load", timeout=25_000):
        insert_alert(live_server_db, "MGR-LIVE-HIGH", "HIGH")
    assert page.locator("#alerts-feed li", has_text="MGR-LIVE-HIGH").count() == 1
    assert page.locator("#new-alerts-chip").count() == 0


def test_manager_view_follows_a_status_change_by_it(page, live_server, live_server_db):
    """An acknowledgment does not move MAX(id); the status watermark does."""
    alert_id = insert_alert(live_server_db, "MGR-STATUS-DEVICE", "HIGH")
    _login(page, live_server, MANAGER)
    page.goto(f"{live_server}/dashboard/manager")
    row = page.locator("#alerts-feed li", has_text="MGR-STATUS-DEVICE")
    assert "IT acknowledged" not in row.inner_text()

    with page.expect_event("load", timeout=25_000):
        # What db.acknowledge_alert writes, from a second process.
        conn = sqlite3.connect(live_server_db, timeout=10)
        conn.execute(
            "UPDATE alerts SET acknowledged = 1, acknowledged_by = 'admin', "
            "acknowledged_at = '2099-01-01T00:00:00+08:00' WHERE id = ?", (alert_id,))
        conn.commit()
        conn.close()
    assert "IT acknowledged" in page.locator(
        "#alerts-feed li", has_text="MGR-STATUS-DEVICE").inner_text()


def test_alert_filters_narrow_the_table(page, live_server):
    """Filters run in SQL and travel in the URL.

    The old version of this test drove the controls and asserted on :visible,
    which only ever exercised the row.hidden mechanism over the 50 rows already
    rendered — the exact reason an alert past row 50 was unreachable. Asserting
    on the served rows for a given query string exercises db.search_alerts
    instead, and the URL is now the filter's whole state.
    """
    _login(page, live_server, IT_ADMIN)
    page.goto(f"{live_server}/dashboard/it")
    rows = page.locator("#alerts-tbody tr[data-alert-id]")
    baseline = rows.count()
    assert baseline >= len(SEED_ALERTS), "seeded alerts did not reach the table"

    page.goto(f"{live_server}/dashboard/it?severity=CRITICAL")
    assert 0 < rows.count() < baseline
    for i in range(rows.count()):
        assert rows.nth(i).get_attribute("data-severity") == "critical"
    # The toolbar reflects the URL, so a shared link arrives with its controls set.
    assert page.input_value("#sev-filter") == "CRITICAL"

    page.goto(f"{live_server}/dashboard/it?q=HR-WORKSTATION")
    assert 0 < rows.count() < baseline

    page.goto(f"{live_server}/dashboard/it?hide_low=1")
    assert 0 < rows.count() < baseline
    for i in range(rows.count()):
        assert rows.nth(i).get_attribute("data-severity") not in ("low", "informational")
    assert page.is_checked("#hide-low-toggle")

    # Driving a control has to produce the same view — that is the submit wiring.
    page.goto(f"{live_server}/dashboard/it")
    page.select_option("#sev-filter", "CRITICAL")
    page.wait_for_url("**/dashboard/it?*severity=CRITICAL*")
    assert 0 < rows.count() < baseline


def test_alerts_table_pages_past_the_first_fifty(page, live_server, live_server_db):
    """A CRITICAL that fell past row 50 used to be unreachable by any control
    in the app: the table was capped at 50 and the filters ran in the browser
    over those same 50 rows."""
    for i in range(55):
        insert_alert(live_server_db, f"PAGING-DEVICE-{i:02d}")

    _login(page, live_server, IT_ADMIN)
    page.goto(f"{live_server}/dashboard/it")
    rows = page.locator("#alerts-tbody tr[data-alert-id]")
    assert rows.count() == 50, "page 1 should be exactly one page"
    page_one = {rows.nth(i).get_attribute("data-alert-id") for i in range(50)}
    assert "Showing 1–50 of" in page.locator("#pager-summary").text_content()

    page.click("a[rel='next']")
    page.wait_for_url("**/dashboard/it?*page=2*")
    page_two = {rows.nth(i).get_attribute("data-alert-id") for i in range(rows.count())}
    assert page_two, "page 2 rendered no rows"
    assert not (page_one & page_two), "page 2 repeated rows from page 1"

    # Paging keeps the filter. Rows this test seeds are all HIGH.
    page.goto(f"{live_server}/dashboard/it?severity=HIGH&page=2")
    assert page.input_value("#sev-filter") == "HIGH"
    assert "severity=HIGH" in page.get_attribute("a[rel='prev']", "href")


def test_manager_feed_pages_past_the_first_fifty(page, live_server, live_server_db):
    """The manager feed was a single 50-row window — limit=50, offset=0, no
    page parameter — so an alert past row 50 was counted in the KPI tiles above
    it and could not be opened from the page.

    The poll baseline assertion is the other half: data-latest-id used to be
    the first rendered row's id, which is only the newest alert while the feed
    is unpaged. On page 2 that is a mid-table id, and ui.js compares it against
    /api/alerts/latest every 15s — so the manager would be told a new alert had
    arrived, forever, on every page but the first.
    """
    for i in range(60):
        insert_alert(live_server_db, f"MGR-PAGING-{i:02d}")

    _login(page, live_server, MANAGER)
    page.goto(f"{live_server}/dashboard/manager")
    assert page.locator("#alerts-feed li").count() == 50
    assert "Showing 1–50 of" in page.locator("#pager-summary").text_content()
    latest_page_one = page.get_attribute("#alerts-feed", "data-latest-id")

    page.click("a[rel='next']")
    page.wait_for_url("**/dashboard/manager?*page=2*")
    assert page.locator("#alerts-feed li").count() > 0, "page 2 rendered no rows"

    api_latest = page.request.get(f"{live_server}/api/alerts/latest").json()["latest_id"]
    assert page.get_attribute("#alerts-feed", "data-latest-id") == latest_page_one
    assert page.get_attribute("#alerts-feed", "data-latest-id") == str(api_latest)

    # Out-of-range clamps to the last page rather than rendering an empty feed.
    page.goto(f"{live_server}/dashboard/manager?page=999")
    assert page.locator("#alerts-feed li").count() > 0


def test_severity_bars_populate_from_the_api(page, live_server):
    _login(page, live_server, IT_ADMIN)
    page.goto(f"{live_server}/dashboard/it")
    # Server-rendered as 0; the fetch fills it in. A non-zero total means the
    # whole path (route -> JSON -> DOM write) worked.
    page.wait_for_function(
        "parseInt(document.querySelector('#sev-total').textContent, 10) > 0"
    )
    assert page.locator("#sev-bars [data-sev]").count() == 5


@pytest.mark.parametrize("tab,heading", [
    ("service", "AI Providers"),
    ("audit", "Audit Log"),
    ("backups", "Database Backups"),
    ("errors", "Errors"),
])
def test_settings_tabs_each_render_their_partial(page, live_server, tab, heading):
    """The includes used to carry `ignore missing`, so a renamed partial would
    render an empty pane instead of failing."""
    _login(page, live_server, IT_ADMIN)
    page.goto(f"{live_server}/admin/settings?tab={tab}")
    assert page.get_by_text(heading).first.is_visible()


def test_add_provider_modal_opens_and_closes(page, live_server):
    _login(page, live_server, IT_ADMIN)
    page.goto(f"{live_server}/admin/settings?tab=service")
    modal = page.locator("#ai-provider-add-modal")
    assert modal.is_hidden()
    page.get_by_role("button", name="Add provider").first.click()
    assert modal.is_visible()
    page.keyboard.press("Escape")
    assert modal.is_hidden()


def test_it_acknowledge_round_trip(page, live_server):
    """The one seeded CRITICAL alert is open — ack it and watch the state flip."""
    _login(page, live_server, IT_ADMIN)
    page.goto(f"{live_server}/alert/1")
    page.get_by_role("button", name="IT acknowledge & stop escalation").click()
    page.locator("#it-ack-modal button[type=submit]").click()
    # data-async-submit: fetch, toast, then a delayed reload. The resolve
    # button only exists once the row is acknowledged, so waiting for it is
    # waiting for the whole round trip.
    page.get_by_role("button", name="Mark as resolved").wait_for(timeout=15000)


def test_backup_run_round_trip(page, live_server):
    _login(page, live_server, IT_ADMIN)
    page.goto(f"{live_server}/admin/settings?tab=backups")
    before = page.locator("table tbody tr").count()
    page.get_by_role("button", name="Run backup now").click()
    page.wait_for_url("**/admin/settings?tab=backups")
    # text_content, not is_visible: the flash seed div is display:none and
    # ui.js turns it into a transient toast.
    assert "Backup created" in page.locator("#flash-seed").text_content()
    assert page.locator("table tbody tr").count() == before + 1


def test_backup_delete_selected_and_restore_command(page, live_server):
    _login(page, live_server, IT_ADMIN)
    page.goto(f"{live_server}/admin/settings?tab=backups")
    # Two fresh snapshots, so deleting one never trips the keep-one guard.
    # The names carry seconds, so the second click has to land in a new one.
    page.get_by_role("button", name="Run backup now").click()
    page.wait_for_url("**/admin/settings?tab=backups")
    page.wait_for_timeout(1100)
    page.get_by_role("button", name="Run backup now").click()
    page.wait_for_url("**/admin/settings?tab=backups")

    rows = page.locator("table tbody tr")
    before = rows.count()
    newest = rows.first.locator("td.font-mono").text_content()

    page.get_by_role("button", name="Restore").first.click()
    cmd = page.locator("#restore-cmd")
    assert cmd.is_visible()
    assert f"backup restore backups/{newest}\n" in cmd.text_content()
    page.locator("#restore-modal").get_by_role("button", name="Close").click()

    # Playwright dismisses confirm() by default, which would cancel the submit.
    page.once("dialog", lambda d: d.accept())
    rows.first.locator('input[name="names"]').check()
    page.get_by_role("button", name="Delete selected").click()
    page.wait_for_url("**/admin/settings?tab=backups")
    assert "Deleted 1 backup(s)" in page.locator("#flash-seed").text_content()
    assert rows.count() == before - 1
    assert newest not in page.locator("table tbody").text_content()


# ── Security regressions ─────────────────────────────────────────────────────

def test_alert_detail_hides_it_only_sections_from_manager(page, live_server):
    _login(page, live_server, IT_ADMIN)
    page.goto(f"{live_server}/alert/2")
    for heading in ("Recommended Investigation Steps", "Forensic summary"):
        assert page.get_by_text(heading).first.is_visible()

    # /login redirects an authenticated user straight to their dashboard, so
    # the form _login fills would never appear without dropping the session.
    page.context.clear_cookies()
    _login(page, live_server, MANAGER)
    page.goto(f"{live_server}/alert/2")
    body = page.content()
    for heading in ("Recommended Investigation Steps", "Forensic summary"):
        assert heading not in body, f"manager can see the IT-only '{heading}' section"
    # Acknowledging is IT-only too, and the control is the whole gate.
    assert page.get_by_role("button", name="IT acknowledge & stop escalation").count() == 0


def test_webhook_rejects_a_payload_with_no_token(live_server):
    """This used to be skipped entirely whenever the token was unset."""
    payload = {"rule_id": "5710", "rule_level": 10, "device_name": "E2E-DEVICE"}
    status, _ = _post(live_server, "/wazuh-webhook", payload)
    assert status == 403

    status, _ = _post(live_server, "/wazuh-webhook", payload,
                      {"X-Webhook-Token": "wrong-" + WEBHOOK_TOKEN})
    assert status == 403

    status, body = _post(live_server, "/wazuh-webhook", payload,
                         {"X-Webhook-Token": WEBHOOK_TOKEN})
    assert status == 200 and "alert_id" in body


def test_live_alert_reaches_an_open_dashboard(page, live_server):
    """The SSE stream reads a database watermark rather than an in-process queue.

    That swap is only worth anything if a row ingested by the webhook still
    lands in an already-open dashboard — and it is the one behaviour that
    breaks invisibly, since the old queue registry failed by silently
    delivering nothing rather than by raising.
    """
    _login(page, live_server, IT_ADMIN)
    page.goto(f"{live_server}/dashboard/it")
    page.wait_for_selector("#alerts-tbody tr[data-alert-id]")

    status, body = _post(
        live_server, "/wazuh-webhook",
        {"rule_id": "5715", "rule_level": 10, "device_name": "SSE-LIVE-DEVICE"},
        {"X-Webhook-Token": WEBHOOK_TOKEN},
    )
    assert status == 200
    alert_id = json.loads(body)["alert_id"]

    # SSE_POLL_SECONDS is 2s plus up to 0.5s of jitter; 15s is slack for a
    # loaded CI box without being so long that a broken stream looks slow
    # rather than broken.
    page.wait_for_selector(f'#alerts-tbody tr[data-alert-id="{alert_id}"]', timeout=15_000)
    # Pushed into the live DOM, not delivered by the fallback's full reload.
    assert "/dashboard/it" in page.url
    assert page.locator('#alerts-tbody tr[data-alert-id]').first.get_attribute(
        "data-alert-id") == str(alert_id), "new row should be prepended, not appended"


def test_live_alert_from_another_process_reaches_the_dashboard(page, live_server, live_server_db):
    """The reason the SSE fan-out moved into the database.

    Under gunicorn with workers > 1, the process that ingests an alert is
    usually not the process holding a given browser's stream. The old
    in-memory subscriber registry could not cross that boundary, so roughly
    (N-1)/N of live alerts were dropped with no error anywhere. Writing the row
    from the test process — a genuinely separate OS process from the server —
    is that scenario, and it is testable on a dev box where gunicorn will not
    even run.
    """
    _login(page, live_server, IT_ADMIN)
    page.goto(f"{live_server}/dashboard/it")
    page.wait_for_selector("#alerts-tbody tr[data-alert-id]")

    alert_id = insert_alert(live_server_db, "OTHER-PROCESS-DEVICE")

    page.wait_for_selector(f'#alerts-tbody tr[data-alert-id="{alert_id}"]', timeout=15_000)
    assert page.get_by_text("OTHER-PROCESS-DEVICE").count() > 0


def test_webhook_rejects_oversized_field_values(live_server):
    status, body = _post(
        live_server, "/wazuh-webhook",
        {"rule_id": "5710", "rule_level": 10, "device_name": "D" * 500},
        {"X-Webhook-Token": WEBHOOK_TOKEN},
    )
    assert status == 400 and "device_name" in body


def test_provider_add_rejects_unsafe_base_urls(page, live_server):
    """base_url is a server-side request target, so http:// and private
    addresses are an SSRF primitive handed to whoever holds an IT session."""
    _login(page, live_server, IT_ADMIN)
    page.goto(f"{live_server}/admin/settings?tab=service")
    token = _csrf_token(page)
    rows = page.locator("li:has(form[action*='ai-providers'])")
    before = rows.count()

    for bad_url in ("http://example.com/v1", "https://169.254.169.254/latest",
                    "https://127.0.0.1:8080/v1", "https://localhost/v1"):
        result = page.request.post(
            f"{live_server}/admin/settings/ai-providers/add",
            form={
                "_csrf": token, "label": f"Evil-{bad_url}", "model": "m",
                "api_key": "k", "base_url": bad_url,
                "auth_header": "Authorization", "request_format": "openai_compat",
            },
        )
        assert result.status in (200, 302), f"{bad_url}: {result.status}"

    page.goto(f"{live_server}/admin/settings?tab=service")
    assert rows.count() == before, "an unsafe base_url made it into the chain"


def test_reveal_endpoint_is_rate_limited(page, live_server):
    _login(page, live_server, IT_ADMIN)
    page.goto(f"{live_server}/admin/settings?tab=service")
    token = _csrf_token(page)
    codes = [
        page.request.post(
            f"{live_server}/admin/settings/api-keys/telegram_it/reveal",
            form={"_csrf": token, "key_name": "BOT_TOKEN"},
        ).status
        for _ in range(7)
    ]
    assert 429 in codes, f"no rate limit hit on the reveal endpoint: {codes}"


def test_csv_exports_share_one_rate_limit(page, live_server):
    _login(page, live_server, IT_ADMIN)
    page.goto(f"{live_server}/dashboard/it")
    codes = [page.request.get(f"{live_server}/export.csv").status for _ in range(4)]
    codes += [page.request.get(f"{live_server}/admin/audit.csv").status for _ in range(4)]
    assert 429 in codes, f"CSV exports never rate-limited: {codes}"


def test_duplicate_provider_label_is_rejected_without_leaking_internals(page, live_server):
    """db.add_provider's docstring claimed a UNIQUE constraint that the schema
    never had, so duplicates piled up in the fallback chain indistinguishably.
    The flash is also the check that failure messages stay free of internals —
    they used to interpolate str(e)."""
    _login(page, live_server, IT_ADMIN)
    page.goto(f"{live_server}/admin/settings?tab=service")
    token = _csrf_token(page)
    provider = {
        "_csrf": token, "label": "DupeProbe", "model": "m", "api_key": "k",
        "base_url": "https://api.example.com/v1",
        "auth_header": "Authorization", "request_format": "openai_compat",
    }
    rows = page.locator("li:has(form[action*='ai-providers'])")
    before = rows.count()
    # max_redirects=0: following the 303 here would render the settings page
    # into a throwaway response and consume the flash before the assertion.
    for _ in range(2):
        page.request.post(f"{live_server}/admin/settings/ai-providers/add",
                          form=provider, max_redirects=0)

    page.goto(f"{live_server}/admin/settings?tab=service")
    assert rows.count() == before + 1, "the duplicate label was accepted"

    # Scoped to the flash region — the inlined Tailwind build contains strings
    # like ".py-1" that a whole-document search would trip on. text_content
    # rather than inner_text: the seed div is display:none by design.
    flashes = page.locator("#flash-seed").text_content()
    assert "already exists" in flashes, f"no rejection flash: {flashes!r}"
    for leak in ("Traceback", "sqlite3", ".py:", "IntegrityError", "insightshield.db"):
        assert leak not in flashes, f"flash leaked {leak!r}: {flashes}"
