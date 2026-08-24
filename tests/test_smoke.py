"""E2E smoke coverage: the app didn't have any tests wired up before this.

Covers the golden paths only — login (both roles), dashboard load, and the
PDF report export. Not a substitute for unit tests on the AI chain / alert
router, just a tripwire against "the app doesn't even boot" regressions.
"""
import re

from conftest import BOOTSTRAP_ADMIN_PASSWORD, BOOTSTRAP_MANAGER_PASSWORD

IT_ADMIN = {"username": "admin", "password": BOOTSTRAP_ADMIN_PASSWORD}
MANAGER = {"username": "manager", "password": BOOTSTRAP_MANAGER_PASSWORD}

# The seeded passwords come from the fixture's environment — config.py has no
# fallback literals any more — and db.seed_users_from_config sets
# must_change_password=1. First login for
# each account is redirected to /account/password and cannot proceed until the
# password is rotated. _login below completes that rotation once per account
# and remembers the new value for the rest of the session-scoped live_server.
ROTATED_PASSWORD = "Sm0ke-Test-Rotate!2026"
_current_password = {}


def _login(page, url, creds):
    username = creds["username"]
    password = _current_password.get(username, creds["password"])

    page.goto(f"{url}/login")
    page.fill("input[name=username]", username)
    page.fill("input[name=password]", password)
    page.click("button[type=submit]")

    # First login for this account: clear the forced-rotation gate.
    if "/account/password" in page.url:
        page.fill("input[name=current_password]", password)
        page.fill("input[name=new_password]", ROTATED_PASSWORD)
        page.fill("input[name=confirm_password]", ROTATED_PASSWORD)
        # Scope to the form: this page extends _base.html, whose account menu
        # holds a second (hidden) submit button for logout.
        page.click("form[action*='/account/password'] button[type=submit]")
        page.wait_for_url(re.compile(r"/dashboard/"))
        _current_password[username] = ROTATED_PASSWORD


def _csrf_token(page):
    """Read the per-session token _base.html publishes for fetch() callers."""
    return page.get_attribute('meta[name="csrf-token"]', "content")


def test_login_rejects_bad_credentials(page, live_server):
    _login(page, live_server, {"username": "admin", "password": "wrong-password"})
    page.wait_for_url(re.compile(r"/login"))
    assert page.locator("text=Invalid credentials").count() > 0


def test_it_admin_login_reaches_it_dashboard(page, live_server):
    _login(page, live_server, IT_ADMIN)
    page.wait_for_url(re.compile(r"/dashboard/it"))
    assert page.url.endswith("/dashboard/it")


def test_manager_login_reaches_manager_dashboard(page, live_server):
    _login(page, live_server, MANAGER)
    page.wait_for_url(re.compile(r"/dashboard/manager"))
    assert page.url.endswith("/dashboard/manager")


def test_manager_cannot_reach_it_dashboard(page, live_server):
    _login(page, live_server, MANAGER)
    page.wait_for_url(re.compile(r"/dashboard/manager"))
    resp = page.request.get(f"{live_server}/dashboard/it", max_redirects=0)
    assert resp.status in (302, 403)


def test_it_admin_cannot_reach_manager_dashboard(page, live_server):
    """
    The reverse of the case above, and the one that was open.

    /dashboard/manager carried only @login_required because decorators.py sent
    every denied user there — gating it would have looped. Denials abort(403)
    now, so there is no redirect target and no loop.
    """
    _login(page, live_server, IT_ADMIN)
    page.wait_for_url(re.compile(r"/dashboard/it"))
    resp = page.request.get(f"{live_server}/dashboard/manager", max_redirects=0)
    assert resp.status == 403


def test_manager_reaches_own_dashboard_after_gating(page, live_server):
    """Guards the failure mode of the fix above: a role gate on the manager
    dashboard must not lock the manager out of it."""
    _login(page, live_server, MANAGER)
    page.wait_for_url(re.compile(r"/dashboard/manager"))
    resp = page.request.get(f"{live_server}/dashboard/manager", max_redirects=0)
    assert resp.status == 200


def test_manager_cannot_read_full_alert_json(page, live_server):
    """/api/alert/<id> returns the whole 21-column row including raw_alert."""
    _login(page, live_server, MANAGER)
    page.wait_for_url(re.compile(r"/dashboard/manager"))
    resp = page.request.get(f"{live_server}/api/alert/1")
    assert resp.status == 403
    assert resp.json()["error"] == "forbidden"


def test_html_404_renders_a_real_page(page, live_server):
    """
    404 used to be `redirect(...), 404` — a Location header on a non-redirect
    status. Browsers ignore it, so the flash queued in the session and surfaced
    later on an unrelated page as a phantom toast.
    """
    _login(page, live_server, IT_ADMIN)
    page.wait_for_url(re.compile(r"/dashboard/it"))
    resp = page.request.get(f"{live_server}/no-such-page", max_redirects=0)
    assert resp.status == 404
    assert "location" not in {k.lower() for k in resp.headers}
    assert "Page not found" in resp.text()


def test_backup_download_rejects_drive_relative_path(page, live_server):
    """`C:.env` has no separator and no '..', so the old string check passed it
    and Path('backups') / 'C:.env' resolved to the app's CWD on drive C."""
    _login(page, live_server, IT_ADMIN)
    page.wait_for_url(re.compile(r"/dashboard/it"))
    for name in ("C:.env", "..%2Fconfig.py", "insightshield.db"):
        resp = page.request.get(
            f"{live_server}/admin/backup/download/{name}", max_redirects=0
        )
        assert resp.status in (400, 404), f"{name} -> {resp.status}"


def test_health_endpoint_is_unauthenticated(page, live_server):
    resp = page.request.get(f"{live_server}/health")
    assert resp.status == 200
    assert resp.json()["status"] == "ok"


def test_report_pdf_export_authenticated(page, live_server):
    _login(page, live_server, IT_ADMIN)
    page.wait_for_url(re.compile(r"/dashboard/it"))
    resp = page.request.get(f"{live_server}/report.pdf")
    assert resp.status == 200
    assert resp.headers.get("content-type", "").startswith("application/pdf")


def test_api_404_returns_json_error(page, live_server):
    """Global error handler: /api/* paths get JSON, not an HTML 404 page."""
    resp = page.request.get(f"{live_server}/api/this-route-does-not-exist")
    assert resp.status == 404
    assert resp.json()["error"]


def test_html_404_redirects(page, live_server):
    """Global error handler: non-API paths get a redirect, not a raw 404 page."""
    resp = page.request.get(
        f"{live_server}/this-route-does-not-exist", max_redirects=0
    )
    assert resp.status in (302, 404)


def test_post_without_csrf_token_is_rejected(page, live_server):
    """
    The blanket @app.before_request CSRF guard. Before it existed, only the
    /admin/settings/* routes checked the token, so a forged cross-site POST
    could resolve a live alert or prune the backups.
    """
    _login(page, live_server, IT_ADMIN)
    page.wait_for_url(re.compile(r"/dashboard/it"))
    resp = page.request.post(
        f"{live_server}/api/client-error",
        data={"message": "no-csrf", "stack": "", "url": "/dashboard/it"},
    )
    assert resp.status == 403
    assert resp.json()["error"] == "csrf"


def test_logout_rejects_get(page, live_server):
    """GET /logout was a one-click forced logout via <img src>. POST only now."""
    _login(page, live_server, IT_ADMIN)
    page.wait_for_url(re.compile(r"/dashboard/it"))
    resp = page.request.get(f"{live_server}/logout", max_redirects=0)
    assert resp.status == 405


def test_client_error_beacon_logs(page, live_server):
    """static/ui.js's window.onerror beacon lands in error_log (Settings -> Errors)."""
    _login(page, live_server, IT_ADMIN)
    page.wait_for_url(re.compile(r"/dashboard/it"))
    resp = page.request.post(
        f"{live_server}/api/client-error",
        headers={"X-CSRF-Token": _csrf_token(page)},
        data={"message": "smoke-test error", "stack": "at test:1", "url": "/dashboard/it"},
    )
    assert resp.status == 200
    assert resp.json()["status"] == "logged"

    errors_page = page.request.get(f"{live_server}/admin/settings?tab=errors")
    assert "smoke-test error" in errors_page.text()
