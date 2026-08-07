"""The endpoint-name strings that the blueprint split can silently break.

Three sets of hand-written endpoint names decide security behaviour, and every
one of them fails OPEN or fails SILENT if a name stops matching a real route:

  - web.csrf.CSRF_EXEMPT_ENDPOINTS — a stale name here means /wazuh-webhook is
    no longer exempt, and every Wazuh alert is rejected with a CSRF 403. The
    ingest just stops; nothing in the UI says so.
  - web.hooks.PASSWORD_GATE_EXEMPT — a stale name locks a user out of the very
    page they must reach to clear must_change_password, or (worse) exempts
    nothing and leaves them bounced in a loop.
  - decorators.dashboard_endpoint_for — a stale name raises BuildError from
    inside a redirect, so login itself 500s.
  - web.responses.safe_referrer's default fallback — same BuildError, on the
    CSRF-rejection path, which is exactly the path nobody exercises by hand.
  - request.endpoint comparisons in templates — these fail SILENT rather than
    loud: the branch simply never taken, so a stylesheet or a nav item just
    stops appearing.

Werkzeug does not validate any of these against the URL map, so a rename is
invisible until someone walks the path. This asserts them directly.

The first three sets are named explicitly. The last two are DISCOVERED, not
listed, because an audit that only checks the names it was told about is how
the two silent breakages this file now covers got through in the first place.
"""
import inspect
import re
from pathlib import Path

import pytest

from app import app
from decorators import ROLE_IT_ADMIN, ROLE_MANAGER, dashboard_endpoint_for
from web.csrf import CSRF_EXEMPT_ENDPOINTS
from web.hooks import PASSWORD_GATE_EXEMPT
from web.responses import safe_referrer

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


def _known_endpoints() -> set[str]:
    return {rule.endpoint for rule in app.url_map.iter_rules()}


def _template_endpoint_comparisons() -> list[tuple[str, str]]:
    """Every endpoint name a template compares request.endpoint against.

    Returns (template filename, endpoint name) pairs. Matches both shapes the
    templates use — `request.endpoint in ('a', 'b')` and
    `request.endpoint == 'a'` — and pulls each quoted name out of the tuple.
    """
    comparison = re.compile(
        r"request\.endpoint\s*(?:==|!=|in)\s*(\(?[^)]*?\)?)(?:\s*%\}|\s*-%\})"
    )
    quoted = re.compile(r"""['"]([A-Za-z_][A-Za-z0-9_.]*)['"]""")
    found = []
    for path in sorted(TEMPLATE_DIR.rglob("*.html")):
        text = path.read_text(encoding="utf-8")
        for match in comparison.finditer(text):
            for name in quoted.findall(match.group(1)):
                found.append((path.name, name))
    return found


@pytest.mark.parametrize("endpoint", sorted(CSRF_EXEMPT_ENDPOINTS))
def test_csrf_exempt_endpoint_exists(endpoint):
    assert endpoint in _known_endpoints()


@pytest.mark.parametrize("endpoint", sorted(PASSWORD_GATE_EXEMPT))
def test_password_gate_exempt_endpoint_exists(endpoint):
    assert endpoint in _known_endpoints()


@pytest.mark.parametrize("role", [ROLE_IT_ADMIN, ROLE_MANAGER, "manager", None])
def test_dashboard_endpoint_for_resolves(role):
    assert dashboard_endpoint_for(role) in _known_endpoints()


def test_the_webhook_is_the_only_csrf_exemption():
    """Every other mutating route is protected by the blanket before_request
    check. Widening this set is a security decision, not a refactor."""
    assert CSRF_EXEMPT_ENDPOINTS == frozenset({"webhook.wazuh_webhook"})


def test_safe_referrer_default_fallback_resolves():
    """Read the default off the signature rather than hardcoding it here.

    safe_referrer() is called bare from web.csrf._enforce_csrf, so its default
    is the endpoint every CSRF rejection without an on-host referrer lands on.
    It shipped as "login" after the blueprint split — url_for("login") raises
    BuildError, turning a 303 redirect into a 500 on a security path. Checking
    the signature catches the class of bug, not just the one instance.
    """
    default = inspect.signature(safe_referrer).parameters["fallback_endpoint"].default
    assert default in _known_endpoints(), (
        f"safe_referrer falls back to {default!r}, which is not a routed endpoint"
    )


def test_templates_only_compare_against_real_endpoints():
    """A template comparing request.endpoint against a dead name fails silent.

    _base.html gated the report stylesheet on ('report', 'report_pdf') and kept
    doing so after those endpoints became 'reports.report' / 'reports.report_pdf'.
    The condition went permanently false and the report simply rendered without
    its stylesheet — no error, no test failure, nothing in a log.
    """
    comparisons = _template_endpoint_comparisons()
    assert comparisons, "found no request.endpoint comparisons — has the regex rotted?"
    known = _known_endpoints()
    dead = [(tpl, name) for tpl, name in comparisons if name not in known]
    assert not dead, f"templates compare request.endpoint against dead endpoints: {dead}"


def test_url_rules_are_unchanged_by_the_split():
    """39 routes plus Flask's own /static. The blueprint split was allowed to
    rename endpoints and nothing else — a changed URL breaks nginx, the Wazuh
    integrator, scripts/smoke_test.sh and every bookmark."""
    assert len(list(app.url_map.iter_rules())) == 40
