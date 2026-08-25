# it_recommender.py
# Insight Shield — IT-Only "Recommended Investigation Steps" Generator
# Purpose : Run a SECOND AI call per alert, against an obfuscated copy of the
#           raw Wazuh payload, producing structured INVESTIGATE / CHECK /
#           MITIGATE guidance for the IT admin. Never visible to managers,
#           never sent to Telegram / SMS / email.
# Used by : wazuh_receiver._kick_it_recommendation worker thread (Round 2).

import hashlib
import ipaddress
import json
import logging
import re
import string

import config
import cache
import validator
import _ai_chain
import _request_cache

logger = logging.getLogger("insightshield.it_recommender")

# ── Obfuscation (master spec §1.2) ──────────────────────────────────────────
# Real values are replaced before the prompt leaves the perimeter; the
# response is deobfuscated before storage so the IT admin sees actionable
# identifiers (real IPs/processes) in the dashboard.
#
# This used to be a static four-entry dict keyed on one literal lab address.
# Two things were wrong with that. The address was a deployment constant, so on
# any other subnet the IP substitution never fired and real device addresses
# and hostnames went to the AI provider verbatim — the control silently
# protected nothing. And "3389" was replaced as a bare substring across the
# whole JSON, so it also mangled any four digits that happened to read 3389
# inside a PID, a byte count or an alert id, corrupting the payload the model
# then reasoned about.
#
# The map is now built per alert from the payload itself, and every
# substitution is anchored so it can only match a whole token.
STATIC_OBFUSCATION = {
    "mimikatz.exe": "Tool-A",
    "lsass.exe":    "System-Process-1",
    "3389":         "Port-X",
}

_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

IT_SYSTEM_PROMPT = """You are a senior security engineer writing investigation steps for an IT admin.
Always reply in EXACTLY this format:

INVESTIGATE: [2-3 sentences naming specific data sources, log files, and time windows to review]
CHECK: [2-3 sentences listing concrete commands, queries, or tooling to run]
MITIGATE: [2-3 sentences with containment and remediation steps in priority order]

Maximum 100 words total. Use technical terms freely — your reader is an IT admin.
Identifiers in the alert are obfuscated: 'Device-A', 'Device-B', ... are internal
IP addresses, 'Host-A', 'Host-B', ... are machine names, and 'Port-X', 'Tool-A',
'System-Process-1' stand in for a port, a tool and a process. Refer to them by
those labels — they are substituted back to the real values before the IT admin
reads your answer.

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
    mapping = _build_map(raw_alert_json, device_name)
    obfuscated = _obfuscate(raw_alert_json, mapping)
    prompt = IT_SYSTEM_PROMPT.format(raw_alert_obfuscated=obfuscated)
    # Key on the payload, not on rule_id. The prompt embeds the whole raw
    # alert — this host, these addresses, this process — so a rule_id key
    # served the FIRST alert's investigation steps, naming the wrong machine,
    # to every later alert sharing that rule inside the TTL. Hashing the
    # prompt lowers the hit rate and is worth it: stale-but-correct beats
    # fast-and-wrong when IT is chasing an incident.
    #
    # The prompt is hashed AFTER obfuscation, which is what makes a shared
    # entry safe: two POS terminals hitting the same rule now produce the same
    # obfuscated prompt, and the cached reply is deobfuscated through each
    # alert's OWN map on the way out. Same text, correct machine per reader.
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
    return _deobfuscate(text, mapping), provider


def _label(index: int) -> str:
    """A, B, C ... then plain numbers past Z rather than wrapping back to A."""
    if index < len(string.ascii_uppercase):
        return string.ascii_uppercase[index]
    return str(index)


def _is_internal(addr: str) -> bool:
    """True for RFC1918, loopback and link-local. Public addresses are left
    alone: an attacker's source IP is not ours to protect, and stripping it
    would cost the model the context it needs to give useful advice."""
    try:
        return ipaddress.ip_address(addr).is_private
    except ValueError:
        return False


def _build_map(raw_alert_json: str, device_name: str) -> dict[str, str]:
    """
    Build this alert's obfuscation map: real value -> token.

    Derived from the payload rather than hardcoded, so it covers whatever
    devices are actually enrolled — including ones added after deployment.
    Ordering is by first appearance so the labels are stable for a given
    payload, which keeps the cache key stable too.
    """
    text = raw_alert_json or ""
    mapping = dict(STATIC_OBFUSCATION)

    try:
        alert = json.loads(text)
    except (TypeError, ValueError):
        # A malformed payload still gets the IP and static substitutions below;
        # only the agent-name lookup is lost. Failing the whole obfuscation
        # here would send the raw alert to the provider instead.
        alert = {}
    agent = alert.get("agent") if isinstance(alert, dict) else None
    agent_name = agent.get("name") if isinstance(agent, dict) else None

    hosts: list[str] = []
    for candidate in (device_name, agent_name):
        # A hostname short enough to appear inside unrelated words would match
        # everywhere once anchored substitution runs; 3 characters is the floor.
        if isinstance(candidate, str) and len(candidate) >= 3 and candidate not in hosts:
            hosts.append(candidate)
    for i, host in enumerate(hosts):
        mapping[host] = f"Host-{_label(i)}"

    devices: list[str] = []
    for addr in _IPV4.findall(text):
        if addr not in devices and _is_internal(addr):
            devices.append(addr)
    for i, addr in enumerate(devices):
        mapping[addr] = f"Device-{_label(i)}"

    return mapping


def _sub_all(text: str, pairs: list[tuple[str, str]], boundary: str) -> str:
    """
    Whole-token substitution, longest key first.

    The lookarounds are what stopped "3389" from eating the middle of a PID or
    an epoch id. Longest-first matters for the same reason: without it
    "192.168.1.13" would consume the front of "192.168.1.137".
    """
    for real, token in sorted(pairs, key=lambda kv: len(kv[0]), reverse=True):
        text = re.sub(
            rf"(?<![{boundary}]){re.escape(real)}(?![{boundary}])", token, text
        )
    return text


def _obfuscate(text: str, mapping: dict[str, str]) -> str:
    """Replace real values with tokens before sending to the AI provider."""
    return _sub_all(text, list(mapping.items()), boundary=r"\w.")


def _deobfuscate(text: str, mapping: dict[str, str]) -> str:
    """Replace tokens with real values after receiving the AI response.
    Stored in the DB this way so the IT admin sees actionable identifiers."""
    reversed_pairs = [(token, real) for real, token in mapping.items()]
    # Hyphen is part of the token, so it has to count as a boundary character
    # or "Device-A" would match inside "Device-AB".
    return _sub_all(text, reversed_pairs, boundary=r"\w\-")
