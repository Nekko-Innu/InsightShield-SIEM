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
import re
import time
from typing import Callable, Optional

import requests

import config
import rate_limit
import validator

logger = logging.getLogger("insightshield._ai_chain")


class ProviderError(Exception):
    """A provider returned a non-2xx HTTP status.

    Carries the status and a short, key-scrubbed body snippet so run_chain can
    tell a configuration error (400 model-not-found, 401 bad key) apart from a
    rate limit (429) — the exact distinction that was lost when every failure
    logged as a bare `HTTPError` and a dead model id read as "rate limiting".
    """
    def __init__(self, status: int, snippet: str = ""):
        self.status = status
        self.snippet = snippet
        super().__init__(f"{status}: {snippet}")


# Redact anything key-shaped before a provider's response body enters
# `reasoning`, which is persisted to alerts.ai_reasoning and rendered in the UI.
# Bodies rarely echo the key, but some gateways do on auth errors — cheap insurance.
_KEY_RE = re.compile(r"(Bearer\s+\S+|sk-[A-Za-z0-9_\-]+|AIza[A-Za-z0-9_\-]+|gsk_[A-Za-z0-9_\-]+)")


def _scrub(text: str, limit: int = 200) -> str:
    """One-line, key-free, length-capped snippet of a provider error body."""
    if not text:
        return ""
    return _KEY_RE.sub("[redacted]", text)[:limit].replace("\n", " ").strip()

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
    ignore_negative_cache: bool = False,
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
        if cached == AI_CHAIN_EXHAUSTED and ignore_negative_cache:
            # The retry path (wazuh_receiver._upgrade_translation) deliberately
            # walks past its own poison. The inline attempt runs on a 5s webhook
            # budget and negative-caches whatever it could not finish in time;
            # without this, the background retry — the whole point of which is to
            # give the chain 25s and a real shot at the fallback provider — would
            # read that entry and give up instantly.
            reasoning.append(
                f"Negative cache entry for key={cache_key} ignored (retry path)."
            )
            logger.info("ai_chain: ignoring negative cache for key=%s", cache_key)
            cached = None
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

    for idx, provider in enumerate(active):
        label = provider["label"]

        remaining = deadline - time.monotonic()
        # The floor applies from the SECOND provider onward. It exists to avoid
        # starting provider #2/#3 with scraps of budget left — never to skip the
        # only attempt. Without the idx>0 guard, the ingest budget
        # (AI_INGEST_BUDGET_S == AI_MIN_PROVIDER_S == 5s) always exhausts here
        # before the first provider is tried, because a few ms elapse between
        # setting `deadline` and this check, so every HIGH/CRITICAL manager
        # translation silently fell back to static. The first provider gets
        # whatever budget there is, capped at 30s by _call_provider.
        if idx > 0 and remaining < config.AI_MIN_PROVIDER_S:
            reasoning.append(
                f"Budget of {budget_s:.0f}s exhausted before {label} "
                f"({remaining:.1f}s left). Stopping chain."
            )
            logger.warning(
                "ai_chain: budget exhausted before %s key=%s", label, cache_key
            )
            break

        # Burst absorber, now per-provider (was Groq-only). Every provider has a
        # per-minute ceiling (config.AI_PROVIDER_RATE_LIMITS, keyed by label);
        # translation, IT recommendation and exec summary all route through here
        # and share one window per label, so the cap bounds TOTAL outbound calls
        # to a provider per minute across all three sources. Past the cap the
        # provider is skipped and the chain falls to the next one, then static —
        # a HIGH/CRITICAL burst can never exceed the free tier.
        key = label.lower()
        limit = config.AI_PROVIDER_RATE_LIMITS.get(
            key, config.AI_PROVIDER_RATE_LIMIT_DEFAULT
        )
        allowed, retry_after = rate_limit.can_call(key, limit)
        if not allowed:
            window_calls = rate_limit.window_count(key)
            reasoning.append(
                f"{label} SKIPPED by rate limiter "
                f"({window_calls}/{limit} in last 60s, retry in {retry_after:.1f}s). "
                f"Falling through."
            )
            logger.warning(
                "ai_chain: %s rate_limited key=%s window=%d retry=%.1fs",
                label, cache_key, window_calls, retry_after,
            )
            _audit_burst_absorber(cache_key, window_calls, retry_after, provider=key)
            continue

        try:
            # Fair share, not "everything that is left". A hanging first
            # provider used to consume the entire budget — with three providers
            # configured and Groq read-timing-out at 4.99s of a 5s window, the
            # chain logged "budget exhausted before Gemini (-0.0s left)" and the
            # second and third providers had never run, on any call, ever.
            #
            # Each remaining provider gets budget/left, floored at
            # AI_MIN_PROVIDER_S so this can never shorten a slice below what the
            # old code gave: on the 5s ingest budget the floor wins and provider
            # one still gets the full 5s (unchanged behaviour), while on the 25s
            # retry three providers get ~8.3s each and every one of them
            # actually gets a turn.
            providers_left = len(active) - idx
            timeout_s = min(
                remaining, 30.0,
                max(remaining / providers_left, config.AI_MIN_PROVIDER_S),
            )
            reasoning.append(
                f"Attempting {label} ({provider['model']}, {timeout_s:.0f}s"
                f" of {remaining:.0f}s left)..."
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
        except ProviderError as e:
            if e.status == 429:
                # Provider explicitly said slow down. Saturate its window so the
                # rest of this burst stops knocking on it — otherwise 40 queued
                # alerts each re-learn the 429 the hard way.
                rate_limit.saturate(key, limit)
                reasoning.append(
                    f"{label} FAILED [429 rate_limited: {e.snippet}]. "
                    f"Backing off for the window, falling through."
                )
            else:
                # 400/401/404/5xx — a config or provider problem, NOT a quota
                # issue. Named distinctly so a dead model id can never again be
                # mistaken for rate limiting.
                reasoning.append(
                    f"{label} FAILED [{e.status} {e.snippet}]. Falling through."
                )
            logger.warning(
                "ai_chain: %s provider error key=%s status=%s: %s",
                label, cache_key, e.status, e.snippet,
            )
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
    model = provider.get("model", "")
    body = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3,
        # config, not a literal 200: a reasoning model burns the budget on its
        # reasoning channel before emitting the answer, so 200 returned empty
        # content and every alert fell to static. See config.AI_MAX_TOKENS.
        "max_tokens": config.AI_MAX_TOKENS,
    }
    # gpt-oss exposes a reasoning-effort knob (Groq honours it); "low" keeps the
    # reasoning short so the <=100-word answer lands inside the budget instead of
    # being crowded out. Sent ONLY to models that accept it — a plain OpenAI /
    # OpenRouter model would 400 on an unknown field, so this is gated on the slug.
    if "gpt-oss" in model:
        body["reasoning_effort"] = "low"
    # allow_redirects=False is load-bearing. _reject_unsafe_base_url validates
    # the hostname that was typed, and requests then follows redirects by
    # default — so https://attacker.tld/ passes the check and 302s to
    # 169.254.169.254 or 127.0.0.1. requests strips Authorization across a host
    # change but NOT custom headers, and both shipped provider templates use
    # x-api-key / x-goog-api-key, so the key would ride along to the target.
    r = requests.post(provider["base_url"], headers=headers, json=body,
                      timeout=timeout_s, allow_redirects=False)
    # Was r.raise_for_status(), which threw a bare HTTPError that run_chain
    # logged as class-name only — so a 400 "model not found" was
    # indistinguishable from a 429 quota hit. Carry the status + a scrubbed
    # body snippet instead.
    if r.status_code >= 400:
        raise ProviderError(r.status_code, _scrub(r.text))

    # A 200 is not proof of an answer. OpenRouter in particular returns HTTP 200
    # with {"error": {...}} and no `choices` when the upstream model is
    # unavailable or a :free variant is throttled, and reasoning models return
    # `content: null` with the text on a separate channel. Both used to reach the
    # caller as a bare KeyError / AttributeError, so ai_reasoning recorded
    # "FAILED [KeyError]" — a class name that tells the operator nothing about
    # which provider is misconfigured or why. Same ProviderError shape as a real
    # HTTP failure, so the chain falls through identically but says what happened.
    try:
        body = r.json()
    except ValueError:
        raise ProviderError(r.status_code, f"non-JSON body: {_scrub(r.text)}")

    if isinstance(body.get("error"), dict):
        err = body["error"]
        raise ProviderError(
            int(err.get("code") or r.status_code),
            _scrub(str(err.get("message") or err)),
        )

    choices = body.get("choices") or []
    if not choices:
        raise ProviderError(r.status_code, f"no choices in response: {_scrub(str(body))}")

    content = (choices[0].get("message") or {}).get("content")
    if not content or not content.strip():
        # Empty content with a finish_reason is the reasoning-model failure mode
        # AI_MAX_TOKENS=1024 exists to prevent; report it as itself rather than
        # letting the validator call it "empty input".
        finish = choices[0].get("finish_reason") or "unknown"
        raise ProviderError(
            r.status_code, f"empty content (finish_reason={finish})",
        )
    return content.strip()


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
    try:
        response = client.models.generate_content(
            model=provider["model"],
            contents=prompt,
        )
    except Exception as e:
        # google-genai raises APIError subclasses carrying a numeric `.code`
        # (e.g. 429 RESOURCE_EXHAUSTED, 400 INVALID_ARGUMENT). Map it to a
        # ProviderError so Gemini gets the same 429-vs-config distinction and
        # back-off as the OpenAI-compatible path; anything without a code
        # falls through to run_chain's generic handler unchanged.
        code = getattr(e, "code", None) or getattr(e, "status_code", None)
        if isinstance(code, int):
            raise ProviderError(code, _scrub(str(getattr(e, "message", e) or e)))
        raise
    # response.text is None when the model produced no usable candidate — a
    # safety block, or a thinking model (gemini-2.5-flash thinks by default)
    # spending its whole output budget before emitting an answer. .strip() on
    # None reached the chain as AttributeError, which reads like a bug in our
    # code rather than a provider outcome.
    text = getattr(response, "text", None)
    if not text or not text.strip():
        reason = "no candidates"
        try:
            candidates = getattr(response, "candidates", None) or []
            if candidates:
                reason = str(getattr(candidates[0], "finish_reason", reason))
        except Exception:
            pass
        raise ProviderError(200, f"empty response ({reason})")
    return text.strip()


def _call_anthropic_messages(provider: dict, prompt: str) -> str:
    """Stub for Round 3. Anthropic's Messages API has a distinct request shape
    (system at top level, messages below, anthropic-version header). Implement
    when the first client adds an Anthropic provider via the Settings UI."""
    raise NotImplementedError(
        "Anthropic provider format pending Round 3 implementation."
    )


# ── Audit helper ─────────────────────────────────────────────────────────────

def _audit_burst_absorber(cache_key: Optional[str], window_calls: int,
                          retry_after: float, provider: str = "groq") -> None:
    """Best-effort audit trail when a provider is burst-absorbed. Imported lazily
    to avoid an import cycle (db.py doesn't import _ai_chain, but anyone importing
    _ai_chain must not require db at module load)."""
    try:
        import db
        limit = config.AI_PROVIDER_RATE_LIMITS.get(
            provider, config.AI_PROVIDER_RATE_LIMIT_DEFAULT
        )
        db.log_audit(
            action="BURST_ABSORBER",
            actor="system",
            actor_role="system",
            target=provider,
            details={
                "cache_key": cache_key,
                "window_calls": window_calls,
                "limit_per_min": limit,
                "retry_after_s": round(retry_after, 1),
            },
        )
    except Exception as e:
        logger.debug("audit log write (BURST_ABSORBER) failed: %s", e)
