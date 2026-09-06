"""Rate-limit safety + provider-error clarity in the AI chain.

Pure-logic, no network: `_ai_chain._call_provider` is monkeypatched. Uses a
throwaway DB (rate_limit + cache are SQLite-backed) by pointing db.DB_PATH at a
temp file BEFORE the first connection is opened.
"""
import os
import tempfile

os.environ.setdefault("FLASK_SECRET_KEY", "test-only-" + "0" * 32)
os.environ.setdefault("ENCRYPTION_KEY", "")  # not needed for these tests
os.environ.setdefault("BOOTSTRAP_ADMIN_PASSWORD", "test-Admin!2026")
os.environ.setdefault("BOOTSTRAP_MANAGER_PASSWORD", "test-Manager!2026")

import pytest

import config
import db

# Redirect the DB before anything opens a connection.
_TMP_DB = os.path.join(tempfile.mkdtemp(prefix="is-chain-test-"), "test.db")
db.DB_PATH = _TMP_DB
db.init_db()

import _ai_chain
import rate_limit


def _provider(label="TestProv"):
    return {
        "label": label, "model": "test-model",
        "base_url": "https://example.invalid/", "api_key": "k",
        "auth_header": "Authorization", "auth_prefix": "Bearer ",
        "request_format": "openai_compat", "is_active": True,
    }


@pytest.fixture(autouse=True)
def _clean_rate():
    rate_limit.reset()
    yield
    rate_limit.reset()


def test_can_call_denies_past_limit():
    # Unknown label -> default cap. Allowed up to the cap, denied after.
    limit = config.AI_PROVIDER_RATE_LIMIT_DEFAULT
    for _ in range(limit):
        allowed, _ = rate_limit.can_call("testprov", limit)
        assert allowed
    allowed, retry_after = rate_limit.can_call("testprov", limit)
    assert allowed is False
    assert retry_after > 0


def test_run_chain_skips_saturated_provider(monkeypatch):
    called = {"n": 0}
    def _boom(*a, **k):
        called["n"] += 1
        raise AssertionError("provider must not be called when saturated")
    monkeypatch.setattr(_ai_chain, "_call_provider", _boom)

    rate_limit.saturate("testprov", config.AI_PROVIDER_RATE_LIMIT_DEFAULT)
    text, provider, reasoning = _ai_chain.run_chain(
        prompt="x", providers=[_provider()], validator_fn=lambda t: True,
    )
    assert provider == _ai_chain.AI_CHAIN_EXHAUSTED
    assert called["n"] == 0
    assert "SKIPPED by rate limiter" in reasoning


def test_429_backs_off_and_reads_distinct(monkeypatch):
    monkeypatch.setattr(_ai_chain, "_call_provider",
                        lambda *a, **k: (_ for _ in ()).throw(
                            _ai_chain.ProviderError(429, "rate limit")))
    text, provider, reasoning = _ai_chain.run_chain(
        prompt="x", providers=[_provider()], validator_fn=lambda t: True,
    )
    assert provider == _ai_chain.AI_CHAIN_EXHAUSTED
    assert "429" in reasoning and "rate_limited" in reasoning
    # A 429 saturates the window so the rest of a burst stops knocking.
    assert rate_limit.window_count("testprov") >= config.AI_PROVIDER_RATE_LIMIT_DEFAULT


def test_400_reads_as_config_error_not_ratelimit(monkeypatch):
    monkeypatch.setattr(_ai_chain, "_call_provider",
                        lambda *a, **k: (_ for _ in ()).throw(
                            _ai_chain.ProviderError(400, "model not found")))
    text, provider, reasoning = _ai_chain.run_chain(
        prompt="x", providers=[_provider()], validator_fn=lambda t: True,
    )
    assert provider == _ai_chain.AI_CHAIN_EXHAUSTED
    assert "[400" in reasoning
    assert "model not found" in reasoning
    assert "429" not in reasoning
    # A config error must NOT saturate the window (only the one attempt counts).
    assert rate_limit.window_count("testprov") < config.AI_PROVIDER_RATE_LIMIT_DEFAULT


def test_scrub_removes_key_shapes():
    dirty = "error Bearer sk-abc123DEF token AIzaSyXYZ gsk_secretval end"
    clean = _ai_chain._scrub(dirty)
    assert "sk-abc123DEF" not in clean
    assert "AIzaSyXYZ" not in clean
    assert "gsk_secretval" not in clean
    assert "[redacted]" in clean
