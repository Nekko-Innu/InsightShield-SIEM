"""The Wazuh integrator's payload adapter.

wazuh_rules/custom-insightshield.py runs on the Wazuh manager under Wazuh's own
embedded Python, so it is never imported by the app and nothing else covers it.
Its one job is real though: a raw Wazuh alert nests everything under
rule/agent, while validate_payload requires flat fields and _extract_attack_trail
requires the nested ones. Getting that wrong means either 400s on every alert or
an empty Attack Trail on every detail page, and neither shows up until it is
running in production.
"""
import importlib.util
from pathlib import Path

import pytest

INTEGRATOR = Path(__file__).resolve().parent.parent / "wazuh_rules" / "custom-insightshield.py"


@pytest.fixture(scope="module")
def integrator():
    # Loaded by path: wazuh_rules/ is not a package and the file name has a
    # hyphen, so neither import nor importlib.import_module can reach it.
    spec = importlib.util.spec_from_file_location("custom_insightshield", INTEGRATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def wazuh_alert():
    """The shape wazuh-integratord writes to the temp file it hands the script."""
    return {
        "timestamp": "2026-08-02T19:00:00.000+0800",
        "rule": {
            "level": 13,
            "description": "New service installed",
            "id": "100013",
            "firedtimes": 1,
            "groups": ["windows", "insightshield_retail"],
        },
        "agent": {"id": "001", "name": "POS-TERMINAL-01", "ip": "192.168.100.40"},
        "manager": {"name": "vm-03"},
        "id": "1754120400.12345",
        "full_log": "raw windows event log line",
        "decoder": {"name": "windows_eventchannel"},
        "data": {"srcip": "10.0.0.9"},
        "location": "EventChannel",
    }


def test_flat_aliases_come_from_the_nested_blocks(integrator, wazuh_alert):
    payload = integrator.build_payload(wazuh_alert)
    assert payload["rule_id"] == "100013"
    assert payload["rule_level"] == 13
    assert payload["device_name"] == "POS-TERMINAL-01"
    assert payload["description"] == "New service installed"


def test_rule_level_is_an_int_and_no_severity_is_sent(integrator, wazuh_alert):
    """A `severity` key would bypass wazuh_receiver.LEVEL_MAP entirely, and a
    string rule_level fails validate_payload's int coercion."""
    payload = integrator.build_payload(wazuh_alert)
    assert isinstance(payload["rule_level"], int)
    assert "severity" not in payload


def test_nested_blocks_survive_for_the_attack_trail(integrator, wazuh_alert):
    payload = integrator.build_payload(wazuh_alert)
    for key in ("rule", "agent", "manager", "decoder", "location", "data", "full_log", "id"):
        assert payload[key] == wazuh_alert[key], f"{key} was lost or mutated"


def test_the_receiver_accepts_what_the_integrator_builds(integrator, wazuh_alert):
    """The assertion that matters — the two halves are written in different
    repos-worth of context and only meet in production."""
    import wazuh_receiver

    payload = integrator.build_payload(wazuh_alert)
    assert wazuh_receiver.validate_payload(dict(payload)) is None
    assert wazuh_receiver.map_level_to_severity(payload["rule_level"]) == "CRITICAL"
    trail = wazuh_receiver._extract_attack_trail(payload)
    assert trail is not None and "POS-TERMINAL-01" in trail


def test_missing_agent_name_does_not_crash(integrator, wazuh_alert):
    """Wazuh omits the agent block for manager-generated alerts. device_name is
    required, so a missing one has to become a placeholder rather than a 400."""
    del wazuh_alert["agent"]
    payload = integrator.build_payload(wazuh_alert)
    assert payload["device_name"] == "unknown-agent"

    import wazuh_receiver

    assert wazuh_receiver.validate_payload(dict(payload)) is None
