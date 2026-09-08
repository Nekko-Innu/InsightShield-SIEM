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


def test_first_provider_attempted_when_budget_equals_floor(monkeypatch):
    # Regression: with budget_s == AI_MIN_PROVIDER_S, the first provider must
    # still be attempted. The ingest path (AI_INGEST_BUDGET_S == AI_MIN_PROVIDER_S)
    # used to exhaust before any attempt, so every HIGH/CRITICAL manager
    # translation silently fell back to static.
    called = []
    monkeypatch.setattr(_ai_chain, "_call_provider",
                        lambda p, *a, **k: called.append(p["label"]) or "ok text")
    text, provider, reasoning = _ai_chain.run_chain(
        prompt="x", providers=[_provider("Groq")], validator_fn=lambda t: True,
        budget_s=config.AI_MIN_PROVIDER_S,
    )
    assert called == ["Groq"]
    assert provider == "Groq"
    assert text == "ok text"


def test_floor_still_skips_second_provider_on_tight_budget(monkeypatch):
    # The floor is not gone — it applies from the 2nd provider on. First provider
    # is attempted (fails validation), then the budget-equals-floor check stops
    # the chain before the second is tried.
    called = []
    monkeypatch.setattr(_ai_chain, "_call_provider",
                        lambda p, *a, **k: called.append(p["label"]) or "bad")
    text, provider, reasoning = _ai_chain.run_chain(
        prompt="x",
        providers=[_provider("Groq"), _provider("OpenRouter")],
        validator_fn=lambda t: False,  # force fall-through past the first
        budget_s=config.AI_MIN_PROVIDER_S,
    )
    assert called == ["Groq"]  # OpenRouter never attempted
    assert provider == _ai_chain.AI_CHAIN_EXHAUSTED
    assert "budget exhausted before OpenRouter" in reasoning.replace("\n", " ") \
        or "exhausted before OpenRouter" in reasoning


def test_scrub_removes_key_shapes():
    dirty = "error Bearer sk-abc123DEF token AIzaSyXYZ gsk_secretval end"
    clean = _ai_chain._scrub(dirty)
    assert "sk-abc123DEF" not in clean
    assert "AIzaSyXYZ" not in clean
    assert "gsk_secretval" not in clean
    assert "[redacted]" in clean


# ── Three-provider chain: every provider must actually get a turn ────────────
# The deployment runs Groq (groq/compound) -> Gemini (gemini-2.5-flash) ->
# OpenRouter (a :free model). Groq's compound endpoint is agentic and slow, so
# these pin the behaviour that a slow or broken FIRST provider cannot consume
# the whole budget or the whole chain.

class _FakeResponse:
    """Minimal stand-in for requests' Response."""
    def __init__(self, payload, status=200, text=""):
        self._payload = payload
        self.status_code = status
        self.text = text or str(payload)

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


def test_slow_first_provider_still_leaves_room_for_the_rest(monkeypatch):
    """A hanging provider used to eat the entire budget; now it gets a share."""
    import time as _time

    seen = []

    def _slow(provider, prompt, timeout_s=30.0):
        seen.append((provider["label"], round(timeout_s, 1)))
        # Simulate burning exactly the slice, the way a read timeout does.
        _time.sleep(0.01)
        raise _ai_chain.ProviderError(504, "gateway timeout")

    monkeypatch.setattr(_ai_chain, "_call_provider", _slow)
    _ai_chain.run_chain(
        prompt="x",
        providers=[_provider("Groq"), _provider("Gemini"), _provider("OpenRouter")],
        validator_fn=lambda t: True,
        budget_s=25.0,
    )
    labels = [s[0] for s in seen]
    assert labels == ["Groq", "Gemini", "OpenRouter"], \
        "every configured provider must get a turn on the retry budget"
    # 25s over three providers: roughly a third each, never the whole window.
    assert seen[0][1] < 12.0, f"first provider took the whole budget: {seen[0]}"


def test_ingest_budget_still_gives_the_first_provider_the_full_five_seconds(monkeypatch):
    """The fair-share slice must not shorten the 5s webhook attempt."""
    seen = []
    monkeypatch.setattr(
        _ai_chain, "_call_provider",
        lambda p, prompt, timeout_s=30.0: seen.append(round(timeout_s, 1)) or "bad",
    )
    _ai_chain.run_chain(
        prompt="x",
        providers=[_provider("Groq"), _provider("Gemini"), _provider("OpenRouter")],
        validator_fn=lambda t: False,
        budget_s=config.AI_INGEST_BUDGET_S,
    )
    assert seen[0] >= config.AI_MIN_PROVIDER_S - 0.1, \
        f"ingest slice shrank to {seen[0]}s; the floor should hold it at 5s"


def test_openrouter_200_with_error_body_reads_as_a_provider_error(monkeypatch):
    """OpenRouter answers 200 with {"error": ...} when a :free model is throttled."""
    monkeypatch.setattr(
        _ai_chain.requests, "post",
        lambda *a, **k: _FakeResponse({"error": {"code": 429, "message": "rate limited upstream"}}),
    )
    with pytest.raises(_ai_chain.ProviderError) as e:
        _ai_chain._call_openai_compat(_provider("OpenRouter"), "p", 5.0)
    assert e.value.status == 429
    assert "rate limited upstream" in e.value.snippet


def test_empty_content_names_the_finish_reason(monkeypatch):
    """A reasoning model can return content: null; that is not 'empty input'."""
    monkeypatch.setattr(
        _ai_chain.requests, "post",
        lambda *a, **k: _FakeResponse(
            {"choices": [{"message": {"content": None}, "finish_reason": "length"}]}
        ),
    )
    with pytest.raises(_ai_chain.ProviderError) as e:
        _ai_chain._call_openai_compat(_provider("Groq"), "p", 5.0)
    assert "finish_reason=length" in e.value.snippet


def test_missing_choices_does_not_raise_a_bare_keyerror(monkeypatch):
    monkeypatch.setattr(
        _ai_chain.requests, "post", lambda *a, **k: _FakeResponse({"id": "x"}),
    )
    with pytest.raises(_ai_chain.ProviderError) as e:
        _ai_chain._call_openai_compat(_provider("OpenRouter"), "p", 5.0)
    assert "no choices" in e.value.snippet
