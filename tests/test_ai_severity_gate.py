"""AI severity gate: only HIGH/CRITICAL spend provider quota (config.AI_ENABLED_SEVERITIES).

Pure-logic test — no network, no Flask server. Sets the env config.py demands
(it sys.exits on a placeholder FLASK_SECRET_KEY) before the first import.
"""
import os

os.environ.setdefault("FLASK_SECRET_KEY", "test-only-" + "0" * 32)
os.environ.setdefault("BOOTSTRAP_ADMIN_PASSWORD", "test-Admin!2026")
os.environ.setdefault("BOOTSTRAP_MANAGER_PASSWORD", "test-Manager!2026")

import config
import groq_translator


def test_gate_membership():
    assert config.AI_ENABLED_SEVERITIES == {"HIGH", "CRITICAL"}
    assert "CRITICAL" in config.AI_ENABLED_SEVERITIES
    assert "HIGH" in config.AI_ENABLED_SEVERITIES
    # The whole point: everything below HIGH is excluded.
    for sev in ("MEDIUM", "LOW", "INFORMATIONAL"):
        assert sev not in config.AI_ENABLED_SEVERITIES


def test_ai_enabled_for_helper():
    # Single source of truth for the gate — translation and IT-rec call sites
    # both use it, so they can't drift apart.
    assert config.ai_enabled_for("HIGH") is True
    assert config.ai_enabled_for("CRITICAL") is True
    assert config.ai_enabled_for("critical") is True  # case-insensitive
    for sev in ("MEDIUM", "LOW", "INFORMATIONAL", "", None):
        assert config.ai_enabled_for(sev) is False


def test_it_recommender_off_by_default():
    # 4.2: second AI call stays off unless IT_RECOMMENDER_ENABLED is set.
    assert config.IT_RECOMMENDER_ENABLED is False


def test_use_ai_false_returns_static_without_network():
    # rule_id 60122 maps to the rdp_bruteforce template; use_ai=False must never
    # touch a provider. Asserting provider=="static" and the {device} token is
    # substituted is enough to prove the AI chain was skipped.
    text, provider, reasoning = groq_translator.translate(
        "60122", "RDP brute force detected", "POS-TERMINAL-01", use_ai=False
    )
    assert provider == "static"
    assert "POS-TERMINAL-01" in text
    assert "{device}" not in text
    assert "AI skipped" in reasoning


def test_use_ai_false_unmapped_rule_falls_to_generic():
    text, provider, _ = groq_translator.translate(
        "999999", "some novel alert", "BRANCH-SERVER", use_ai=False
    )
    assert provider == "static"
    assert "BRANCH-SERVER" in text
    assert "WHAT HAPPENED:" in text
