# it_recommender.py
# Insight Shield — IT-Only "Recommended Investigation Steps" Generator
# Purpose : Run a SECOND AI call per alert, against an obfuscated copy of the
#           raw Wazuh payload, producing structured INVESTIGATE / CHECK /
#           MITIGATE guidance for the IT admin. Never visible to managers,
#           never sent to Telegram / SMS / email.
# Used by : wazuh_receiver._kick_it_recommendation worker thread (Round 2).

import hashlib
import logging

import config
import cache
import validator
import _ai_chain
import _request_cache

logger = logging.getLogger("insightshield.it_recommender")

# ── Obfuscation map (master spec §1.2 — exactly four substitutions) ─────────
# Real values are replaced before the prompt leaves the perimeter; the
# response is deobfuscated before storage so the IT admin sees actionable
# identifiers (real IPs/processes) in the dashboard. Round 7 may grow this
# map for the executive summary; Round 2 matches the spec verbatim.
OBFUSCATION_MAP = {
    "192.168.100.40": "Device-A",
    "3389":           "Port-X",
    "mimikatz.exe":   "Tool-A",
    "lsass.exe":      "System-Process-1",
}

IT_SYSTEM_PROMPT = """You are a senior security engineer writing investigation steps for an IT admin.
Always reply in EXACTLY this format:

INVESTIGATE: [2-3 sentences naming specific data sources, log files, and time windows to review]
CHECK: [2-3 sentences listing concrete commands, queries, or tooling to run]
MITIGATE: [2-3 sentences with containment and remediation steps in priority order]

Maximum 100 words total. Use technical terms freely — your reader is an IT admin.
You may reference 'Device-A', 'Port-X', 'Tool-A', 'System-Process-1' as obfuscated identifiers.

Alert (obfuscated):
{raw_alert_obfuscated}
"""


def recommend(rule_id: str, raw_alert_json: str, device_name: str) -> tuple[str, str]:
    """
    Generate IT investigation steps for an alert.

    Returns (text, provider_used).
    - text is DEOBFUSCATED — Device-A is replaced with the real IP so IT sees
      actionable identifiers. The AI provider only ever saw the obfuscated form.
    - On AI_CHAIN_EXHAUSTED, returns the sentinel string verbatim so the
      caller can store it; the alert detail template renders a fallback
      message ("All AI providers were unavailable...").

    device_name is reserved for future per-device prompt customisation; for
    Round 2 it's accepted but not used (the device shows up inside the
    obfuscated raw_alert).
    """
    obfuscated = _obfuscate(raw_alert_json)
    prompt = IT_SYSTEM_PROMPT.format(raw_alert_obfuscated=obfuscated)
    # Key on the payload, not on rule_id. The prompt embeds the whole raw
    # alert — this host, these addresses, this process — so a rule_id key
    # served the FIRST alert's investigation steps, naming the wrong machine,
    # to every later alert sharing that rule inside the TTL. Hashing the
    # prompt lowers the hit rate and is worth it: stale-but-correct beats
    # fast-and-wrong when IT is chasing an incident.
    cache_key = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    # Round 3: providers come from the DB. Background-thread callers
    # (_kick_it_recommendation in wazuh_receiver) run outside a Flask
    # request context — _request_cache.cached_active_providers falls
    # through to a direct db.get_active_providers_ordered() in that case.
    text, provider, _reasoning = _ai_chain.run_chain(
        prompt=prompt,
        providers=_request_cache.cached_active_providers(),
        validator_fn=validator.validate_it_recommendation,
        cache_get=cache.get_itrec_cached,
        cache_set=cache.set_itrec_cached,
        cache_key=cache_key,
    )
    if provider == _ai_chain.AI_CHAIN_EXHAUSTED:
        logger.warning("it_recommender: chain exhausted for rule_id=%s", rule_id)
        return _ai_chain.AI_CHAIN_EXHAUSTED, _ai_chain.AI_CHAIN_EXHAUSTED
    return _deobfuscate(text), provider


def _obfuscate(text: str) -> str:
    """Replace real values with tokens before sending to the AI provider."""
    for real, token in OBFUSCATION_MAP.items():
        text = text.replace(real, token)
    return text


def _deobfuscate(text: str) -> str:
    """Replace tokens with real values after receiving the AI response.
    Stored in the DB this way so the IT admin sees actionable identifiers."""
    for real, token in OBFUSCATION_MAP.items():
        text = text.replace(token, real)
    return text
