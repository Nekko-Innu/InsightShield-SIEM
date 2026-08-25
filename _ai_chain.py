# _ai_chain.py
# Insight Shield — Generic, Data-Driven AI Provider Chain
# Purpose : Single chain runner reused by manager translator (Round 2),
#           IT recommender (Round 2), and audit-report executive summary
#           (Round 7). The chain iterates an arbitrary `providers: list[dict]`
#           — Round 2 reads config.DEFAULT_AI_PROVIDERS; Round 3 swaps the
#           source to db.get_active_providers_ordered(). Chain runner is
#           written ONCE; only the source of the list changes between rounds.
#
# Provider dict shape (canonical, also used by Round 3 schema):
#   label          str    "Groq" | "OpenAI" | client-supplied label
#   model          str    e.g. "llama-3.1-8b-instant"
#   base_url       str    full POST URL
#   api_key        str    plaintext (encryption is Round 3, decrypted before pass)
#   auth_header    str    "Authorization" | "x-api-key" | "x-goog-api-key"
#   auth_prefix    str    "Bearer " | ""
#   request_format str    "openai_compat" | "gemini_v1beta" | "anthropic_messages"
#   is_active      bool   skip when False

import logging
import os
import time
from typing import Callable, Optional

import requests

import config
import rate_limit
import validator

logger = logging.getLogger("insightshield._ai_chain")

# Sentinel returned when every active provider failed validation. Stored in DB
# verbatim by callers that have no static fallback (the IT recommender);
# callers that DO have a static fallback (the manager translator) check for
# this string and substitute their own template.
#
# Defined in config so cache.py can recognise it without importing this module;
# re-exported here because every existing caller says _ai_chain.AI_CHAIN_EXHAUSTED.
AI_CHAIN_EXHAUSTED = config.AI_CHAIN_EXHAUSTED


# ── Public surface ───────────────────────────────────────────────────────────

def run_chain(
    prompt: str,
    providers: list[dict],
    validator_fn: Callable[[str], bool],
    cache_get: Optional[Callable[[str], Optional[str]]] = None,
    cache_set: Optional[Callable[[str, str], None]] = None,
    cache_key: Optional[str] = None,
    budget_s: float = None,
) -> tuple[str, str, str]:
    """
    Run prompt through cache → each active provider in order → AI_CHAIN_EXHAUSTED.

    Returns (text, provider_used, reasoning).
    - provider_used = "cache" | <provider['label']> | AI_CHAIN_EXHAUSTED
    - Caller decides what to do on AI_CHAIN_EXHAUSTED:
        * Manager translator: substitute static template.
        * IT recommender: store the literal sentinel string.

    `budget_s` bounds the WHOLE chain, not each provider. Each provider gets
    whatever is left, capped at 30s. Callers on a request path should pass a
    value that fits inside whatever is waiting for them — see
    config.AI_INGEST_BUDGET_S for the tightest case.

    Caveat worth knowing: requests' `timeout` is per socket operation, not total
    elapsed, so a provider that drips a response slowly can overshoot its slice.
    The deadline is re-checked between providers, so the overshoot is bounded at
    one provider rather than compounding across the chain.
    """
    if budget_s is None:
        budget_s = config.AI_CHAIN_BUDGET_S
    deadline = time.monotonic() + budget_s
    reasoning: list[str] = []

    # IS_DEBUG_PROMPTS=1 in env logs the outgoing prompt at debug level. Useful
    # for verifying that obfuscation actually scrubbed real IPs before the
    # prompt left the perimeter. See verification §13.7.
    if os.environ.get("IS_DEBUG_PROMPTS"):
        logger.debug("AI prompt (key=%s):\n%s", cache_key, prompt)

    if cache_get and cache_key:
        cached = cache_get(cache_key)
        if cached == AI_CHAIN_EXHAUSTED:
            # Negative cache hit. Without this branch the sentinel would be
            # returned as the answer text, and a manager would read
            # "AI_CHAIN_EXHAUSTED" as their plain-English summary.
            reasoning.append(
                f"Negative cache HIT for key={cache_key} — the chain failed "
                f"within the last {config.AI_NEGATIVE_CACHE_S}s, not retrying."
            )
            logger.info("ai_chain: negative cache HIT for key=%s", cache_key)
            return AI_CHAIN_EXHAUSTED, AI_CHAIN_EXHAUSTED, "\n".join(reasoning)
        if cached is not None:
            reasoning.append(f"Cache HIT for key={cache_key}.")
            logger.info("ai_chain: cache HIT for key=%s", cache_key)
            return cached, "cache", "\n".join(reasoning)
        reasoning.append(f"Cache MISS for key={cache_key}. Iterating providers.")

    active = [p for p in providers if p.get("is_active", True) and p.get("api_key")]
    if not active:
        reasoning.append("No active providers configured (api_key missing or is_active=False).")
        logger.warning("ai_chain: no active providers")
        # Deliberately NOT negative-cached: this is a configuration state, not a
        # failure, and it flips the instant someone adds a provider in Settings.
        return AI_CHAIN_EXHAUSTED, AI_CHAIN_EXHAUSTED, "\n".join(reasoning)

    for provider in active:
        label = provider["label"]

        remaining = deadline - time.monotonic()
        if remaining < config.AI_MIN_PROVIDER_S:
            reasoning.append(
                f"Budget of {budget_s:.0f}s exhausted before {label} "
                f"({remaining:.1f}s left). Stopping chain."
            )
            logger.warning(
                "ai_chain: budget exhausted before %s key=%s", label, cache_key
            )
            break

        # Burst absorber: Groq's free-tier 30/min ceiling. Round 3 generalises
        # via a `rate_limit_per_min` column on ai_providers — for Round 2 the
        # inline check is honest about the only constraint we actually have.
        if label.lower() == "groq":
            allowed, retry_after = rate_limit.can_call("groq", config.GROQ_BUDGET_PER_MIN)
            if not allowed:
                window_calls = rate_limit.window_count("groq")
                reasoning.append(
                    f"Groq SKIPPED by burst absorber "
                    f"({window_calls}/{config.GROQ_BUDGET_PER_MIN} in last 60s, "
                    f"retry in {retry_after:.1f}s). Falling through."
                )
                logger.warning(
                    "ai_chain: Groq rate_limited key=%s window=%d retry=%.1fs",
                    cache_key, window_calls, retry_after,
                )
                _audit_burst_absorber(cache_key, window_calls, retry_after)
                continue

        try:
            timeout_s = min(remaining, 30.0)
            reasoning.append(
                f"Attempting {label} ({provider['model']}, {timeout_s:.0f}s)..."
            )
            text = _call_provider(provider, prompt, timeout_s)
            if validator_fn(text):
                fk = validator.compute_fk_grade(text)
                if cache_set and cache_key:
                    cache_set(cache_key, text)
                reasoning.append(f"{label} SUCCESS. FK={fk}. Validation passed. Cached.")
                logger.info("ai_chain: %s success key=%s fk=%.1f", label, cache_key, fk)
                return text, label, "\n".join(reasoning)
            reasoning.append(f"{label} output FAILED validation. Falling through.")
            logger.warning("ai_chain: %s output failed validation key=%s", label, cache_key)
        except NotImplementedError as e:
            reasoning.append(f"{label} SKIPPED ({e}). Falling through.")
            logger.warning("ai_chain: %s not implemented (key=%s): %s", label, cache_key, e)
        except Exception as e:
            # Class name only. `reasoning` is persisted to alerts.ai_reasoning
            # and rendered on the alert detail page; requests exceptions embed
            # the full request URL, and _call_openai_compat puts the API key in
            # a header whose value can surface in some transport errors. The
            # full message stays in the server log.
            reasoning.append(f"{label} FAILED [{type(e).__name__}]. Falling through.")
            logger.warning(
                "ai_chain: %s failed key=%s: %s", label, cache_key, e, exc_info=True
            )

    reasoning.append("All providers exhausted.")
    logger.warning("ai_chain: all providers exhausted key=%s", cache_key)
    if cache_set and cache_key:
        # Negative-cache the failure so a reload — or the next 40 alerts of a
        # burst — don't each re-run the whole dead chain at full budget. Stored
        # through the same injected setter as a real answer; cache._set gives
        # the sentinel the short TTL.
        cache_set(cache_key, AI_CHAIN_EXHAUSTED)
    return AI_CHAIN_EXHAUSTED, AI_CHAIN_EXHAUSTED, "\n".join(reasoning)


# ── Per-format dispatchers ───────────────────────────────────────────────────

def _call_provider(provider: dict, prompt: str, timeout_s: float = 30.0) -> str:
    """Dispatch by provider['request_format']. `timeout_s` is this provider's
    slice of run_chain's total budget."""
    fmt = provider.get("request_format", "openai_compat")
    if fmt == "openai_compat":
        return _call_openai_compat(provider, prompt, timeout_s)
    if fmt == "gemini_v1beta":
        return _call_gemini_v1beta(provider, prompt, timeout_s)
    if fmt == "anthropic_messages":
        return _call_anthropic_messages(provider, prompt)
    raise ValueError(f"Unknown request_format: {fmt!r}")


def _call_openai_compat(provider: dict, prompt: str, timeout_s: float = 30.0) -> str:
    """Single function serving Groq, OpenAI, DeepSeek, OpenRouter, and any
    Custom-template provider. Standard OpenAI chat-completions request shape."""
    headers = {
        "Content-Type": "application/json",
        provider["auth_header"]: provider["auth_prefix"] + provider["api_key"],
    }
    body = {
        "model": provider["model"],
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3,
        "max_tokens": 200,
    }
    # allow_redirects=False is load-bearing. _reject_unsafe_base_url validates
    # the hostname that was typed, and requests then follows redirects by
    # default — so https://attacker.tld/ passes the check and 302s to
    # 169.254.169.254 or 127.0.0.1. requests strips Authorization across a host
    # change but NOT custom headers, and both shipped provider templates use
    # x-api-key / x-goog-api-key, so the key would ride along to the target.
    r = requests.post(provider["base_url"], headers=headers, json=body,
                      timeout=timeout_s, allow_redirects=False)
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"].strip()


def _call_gemini_v1beta(provider: dict, prompt: str, timeout_s: float = 30.0) -> str:
    """Google Gemini using the google-genai SDK (already in requirements.txt)."""
    from google import genai
    from google.genai import types as genai_types

    # This was the only provider call with no timeout. A hung Gemini request
    # parked its handler until gunicorn's 120s `timeout` SIGKILLed the whole
    # worker, taking every other in-flight request — including open SSE
    # streams — down with it.
    client = genai.Client(
        api_key=provider["api_key"],
        # MILLISECONDS here, unlike requests' seconds. Passing seconds gives a
        # 25ms timeout and every Gemini call fails instantly.
        http_options=genai_types.HttpOptions(timeout=int(timeout_s * 1000)),
    )
    response = client.models.generate_content(
        model=provider["model"],
        contents=prompt,
    )
    return response.text.strip()


def _call_anthropic_messages(provider: dict, prompt: str) -> str:
    """Stub for Round 3. Anthropic's Messages API has a distinct request shape
    (system at top level, messages below, anthropic-version header). Implement
    when the first client adds an Anthropic provider via the Settings UI."""
    raise NotImplementedError(
        "Anthropic provider format pending Round 3 implementation."
    )


# ── Audit helper ─────────────────────────────────────────────────────────────

def _audit_burst_absorber(cache_key: Optional[str], window_calls: int, retry_after: float) -> None:
    """Best-effort audit trail when Groq is burst-absorbed. Imported lazily to
    avoid an import cycle (db.py doesn't import _ai_chain, but anyone importing
    _ai_chain must not require db at module load)."""
    try:
        import db
        db.log_audit(
            action="BURST_ABSORBER",
            actor="system",
            actor_role="system",
            target="groq",
            details={
                "cache_key": cache_key,
                "window_calls": window_calls,
                "limit_per_min": config.GROQ_BUDGET_PER_MIN,
                "retry_after_s": round(retry_after, 1),
            },
        )
    except Exception as e:
        logger.debug("audit log write (BURST_ABSORBER) failed: %s", e)
