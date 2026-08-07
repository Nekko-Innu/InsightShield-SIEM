# executive_summary.py
# Insight Shield — Round 7 (Part 7: Security Audit Report)
#
# Third caller of _ai_chain.run_chain (after Round 2's manager translator
# and IT recommender). Produces the audit-report Executive Summary — a 2-3
# paragraph narrative the manager and IT admin both read at the top of
# /report. Cached for 1h in the ai_cache table, keyed by a digest of
# (date_from, date_to, latest_alert_id_in_range) so any new in-range alert
# implicitly invalidates the prior summary on the next request.
#
# The summary follows the manager forbidden-word rules (it's user-facing
# to a non-technical reader) and is bounded at 150-400 words across >=2
# paragraphs by validator.validate_exec_summary.

import hashlib
import logging

import _ai_chain
import _request_cache
import cache
import validator

logger = logging.getLogger("insightshield.executive_summary")

EXEC_SYSTEM_PROMPT = """You are a security report generator for a retail SIEM. Write an Executive Summary for a non-technical retail manager.

CRITICAL CONSTRAINT — your response will be REJECTED if it contains ANY of these words anywhere: firewall, authentication, protocol, payload, exploit, IP address, TCP, NTLM, SMB, SSID, ARP, DHCP, DNS, ICMP, HTTP, FTP, SSH, RDP, buffer overflow.

You MUST substitute with these business-language synonyms:
- exploit / buffer overflow -> "method of attack" or "system weakness"
- firewall -> "network filtering"
- authentication -> "sign-in"
- payload -> "harmful data"
- protocol / TCP / HTTP / FTP / SSH / RDP / SMB / NTLM -> "network connection" or "remote access"
- IP address -> "network address"
- ARP / DHCP / DNS / ICMP / SSID -> "network configuration" or "WiFi name"

Before submitting, re-read your draft and rewrite any sentence that contains a forbidden word using the synonyms above. The forbidden list is enforced by an automated validator that rejects on any match.

Output EXACTLY four paragraphs, separated by a blank line. Each paragraph must start with the label in CAPS followed by a colon and a line break, then 2-3 bullets beginning with "- ":

KEY FINDINGS:
- 2-3 bullets describing what happened during this period: how many detections, the dominant themes, whether anything caused real harm. Plain business language.

CURRENT CHALLENGES:
- 1-2 bullets on what alerts remain unresolved or what monitoring gaps exist (e.g., agent offline). Factual, not alarming.

ACTIONS TAKEN:
- 1-2 bullets on operational follow-through — acknowledgment rate, response time. Positive, reassuring.

TOP RECOMMENDATIONS:
- 3 bullets with practical steps for next month. Use everyday words.

Total length 150-380 words.

Audit period: {date_from} to {date_to}
Total alerts: {total_alerts}
Severity breakdown: {severity_summary}
Top threats: {top_threats}
Posture score: {posture_score} / 100

Only output the four labeled paragraphs. No preamble, no greeting, no signature.
"""


def _make_cache_key(date_from: str, date_to: str, latest_alert_id: int) -> str:
    """Stable digest used as the exec-summary cache key.

    SHA-1 is fine here — it's a cache key, not a security primitive, and
    the digest length keeps the cache.get_stats() output readable.

    The "v2|" prefix is a prompt-version sentinel: bumping it on prompt
    structure changes (Round I shipped 4 labeled paragraphs replacing the
    earlier free-form prose) invalidates every entry cached under the old
    formula without requiring a Flask restart or manual cache flush.
    """
    raw = f"v2|{date_from}|{date_to}|{latest_alert_id}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def generate(
    date_from: str,
    date_to: str,
    summary: dict,
    top_threats: list[dict],
    posture_score: int,
    latest_alert_id: int,
) -> tuple[str, str]:
    """Generate (or cache-hit) the audit-report executive summary.

    Returns (text, provider_used).
    - provider_used = "cache" | <provider['label']> | AI_CHAIN_EXHAUSTED
    - On chain exhaustion the caller (the /report handler) renders a static
      fallback paragraph. The sentinel string itself is NOT shown to users
      — the template suppresses it and substitutes the fallback copy.
    """
    severity_summary = ", ".join(
        f"{k.lower()}={v}" for k, v in (summary or {}).get("severity", {}).items()
    ) or "no alerts"
    top_threats_str = ", ".join(
        f"{t['attack_type']} ({t['count']})" for t in top_threats
    ) or "none"

    prompt = EXEC_SYSTEM_PROMPT.format(
        date_from=date_from,
        date_to=date_to,
        total_alerts=summary.get("total", 0) if summary else 0,
        severity_summary=severity_summary,
        top_threats=top_threats_str,
        posture_score=posture_score,
    )

    cache_key = _make_cache_key(date_from, date_to, latest_alert_id)
    text, provider, _reasoning = _ai_chain.run_chain(
        prompt=prompt,
        providers=_request_cache.cached_active_providers(),
        validator_fn=validator.validate_exec_summary,
        cache_get=cache.get_exec_summary_cached,
        cache_set=cache.set_exec_summary_cached,
        cache_key=cache_key,
    )
    if provider == _ai_chain.AI_CHAIN_EXHAUSTED:
        logger.warning(
            "executive_summary: chain exhausted for %s..%s (latest_id=%d)",
            date_from, date_to, latest_alert_id,
        )
    else:
        logger.info(
            "executive_summary: %s for %s..%s (key=%s)",
            provider, date_from, date_to, cache_key,
        )
    return text, provider
