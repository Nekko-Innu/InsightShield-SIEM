# groq_translator.py
# Insight Shield — Manager-Facing Alert Translation
# Purpose : Translate raw Wazuh alerts into plain-language text that
#           non-technical store managers can understand and act on.
# Chain   : delegated to _ai_chain.run_chain. Provider list comes from
#           config.DEFAULT_AI_PROVIDERS in Round 2; Round 3 will swap the
#           source to db.get_active_providers_ordered() — this file does
#           not need to change.
# Used by : wazuh_receiver.process_alert()
#
# Static templates are the guaranteed last resort when every AI provider
# fails or returns invalid output. They never raise. The chain runner
# returns AI_CHAIN_EXHAUSTED in that case and we substitute the template.

import hashlib
import logging

import config
import cache
import validator
import _ai_chain
import _request_cache

logger = logging.getLogger("insightshield.groq_translator")

# ── Manager Translation Prompt (100 words / 2-3 sentences per section) ──────
# Master spec §1.1 — bumped from 80 to 100 words in Round 2.

SYSTEM_PROMPT = """You are a security alert translator for non-technical store managers at a supermarket.
Always reply in EXACTLY this format:

WHAT HAPPENED: [2-3 plain sentences, no technical terms]
HOW SERIOUS: [2 sentences explaining risk level simply]
WHAT TO DO: [2-3 sentences with clear action steps]

Maximum 100 words total. Use simple words a 12-year-old can understand.

CRITICAL CONSTRAINT — your response will be REJECTED if it contains ANY of these words anywhere: {forbidden}.

You MUST substitute with these synonyms when the underlying alert involves them:
- exploit / buffer overflow -> "method of attack" or "weakness"
- firewall -> "network filtering"
- authentication -> "sign-in"
- payload -> "harmful data"
- protocol / TCP / HTTP / FTP / SSH / RDP / SMB / NTLM -> "network connection" or "remote access"
- IP address -> "network address"
- ARP / DHCP / DNS / ICMP / SSID -> "network configuration" or "WiFi name"

Before submitting, re-read your three sections and rewrite any sentence that contains a forbidden word. The validator rejects on any case-insensitive substring match. This rule applies at every severity level — including MEDIUM alerts that may escalate to HIGH or CRITICAL on repeat occurrences.

Refer to the affected computer ONLY as the literal token {{device}} — write it exactly like that, braces included, every time you mention the machine. Never write a real device name and never guess one. The system replaces {{device}} with the actual name after your reply.

Example: "WHAT HAPPENED: Someone tried to sign in to {{device}} many times."
"""

# ── Static Templates (guaranteed fallback — NEVER fails) ─────────────────────

STATIC_TEMPLATES = {
    "lsass_dump": (
        "WHAT HAPPENED: Someone tried to read saved passwords from {device}'s "
        "memory.\n"
        "HOW SERIOUS: Stored sign-in credentials may have been stolen.\n"
        "WHAT TO DO: Sign out all users. Change your password from another "
        "computer. Do not enter passwords on this device. Call IT now."
    ),
    "rdp_bruteforce": (
        "WHAT HAPPENED: Someone tried to log in to {device} many times with "
        "wrong passwords.\n"
        "HOW SERIOUS: Someone may be trying to break into this computer.\n"
        "WHAT TO DO: Check if anyone unfamiliar is near the computer. Report "
        "to your manager. Do not share passwords."
    ),
    "syn_flood": (
        "WHAT HAPPENED: {device} is receiving an unusually large amount of "
        "network traffic.\n"
        "HOW SERIOUS: The computer or network may slow down or stop working.\n"
        "WHAT TO DO: Note the time this started. Do not restart the computer. "
        "Report to IT. Use manual receipts if the POS system is slow."
    ),
    "arp_mitm": (
        "WHAT HAPPENED: A suspicious device was detected on the network near "
        "{device}.\n"
        "HOW SERIOUS: Someone may be trying to intercept information on the "
        "network.\n"
        "WHAT TO DO: Stop any logins or payment transactions. Notify your "
        "manager and IT immediately. Check nearby devices too."
    ),
    # Default for any rule_id not in RULE_TO_TEMPLATE. Says only what is
    # actually known — that something was flagged — instead of asserting a
    # specific attack the app cannot identify.
    "generic": (
        "WHAT HAPPENED: Unusual activity was detected on {device}.\n"
        "HOW SERIOUS: This has not been identified yet, so treat it as "
        "possibly serious until IT confirms otherwise.\n"
        "WHAT TO DO: Note the time you saw this. Do not turn the computer off. "
        "Report it to your branch manager and IT now."
    ),
}

# rule_id -> template key. Only rules the template actually describes; the rest
# (after-hours admin, new account, POS file changes, new service, service
# crash, ransomware, port scan) get "generic" rather than a wrong story — a new
# user account used to read as a failed-login attempt.
RULE_TO_TEMPLATE = {
    "100010": "lsass_dump", "92900": "lsass_dump",
    "60122": "rdp_bruteforce", "60204": "rdp_bruteforce", "100001": "rdp_bruteforce",
    "100031": "syn_flood", "100040": "syn_flood", "100041": "syn_flood",
    "100020": "arp_mitm", "100021": "arp_mitm", "100022": "arp_mitm", "100023": "arp_mitm",
}


def translate(
    rule_id: str,
    description: str,
    device_name: str,
    use_ai: bool = True,
    budget_s: float | None = None,
    ignore_negative_cache: bool = False,
) -> tuple[str, str, str]:
    """
    Translate a Wazuh alert into plain English for the manager dashboard.

    Returns (plain_text, provider_used, ai_reasoning).
    Provider is one of: "cache", <provider['label']>, "static".
    ai_reasoning contains the translation pipeline details for the IT dashboard.

    Pipeline: cache → providers (in order from config.DEFAULT_AI_PROVIDERS) →
    static template. Static is the guaranteed last resort and never raises.

    use_ai=False skips the whole AI chain and returns the static template
    directly — the caller passes this for severities outside
    config.AI_ENABLED_SEVERITIES so free-tier quota is spent only on
    HIGH/CRITICAL alerts. The static path is identical to the AI-outage
    fallback, so a MEDIUM alert reads exactly as it would if every provider
    were down.
    """
    if not use_ai:
        text = _get_static_template(rule_id, device_name)
        return text, "static", (
            "AI skipped: severity below config.AI_ENABLED_SEVERITIES. "
            "Static template used (no provider call, no quota spent)."
        )

    prompt = _build_prompt(description)
    # Round 3: providers come from the DB (ai_providers table) instead of
    # config.DEFAULT_AI_PROVIDERS. The chain runner doesn't change — it
    # still consumes an opaque list[dict] in the canonical shape.
    # _request_cache memoises the read per Flask request; background-thread
    # callers fall through to a direct db.get_active_providers_ordered().
    text, provider, reasoning = _ai_chain.run_chain(
        prompt=prompt,
        providers=_request_cache.cached_active_providers(),
        validator_fn=validator.validate_manager_translation,
        cache_get=cache.get_cached,
        cache_set=cache.set_cached,
        # Versioned so entries written by an older prompt are never read back
        # (v2 fixed a prompt that baked the real device name into the reply).
        # v3: keyed on the PROMPT, not the rule id. The prompt embeds the
        # alert description, which arrives from the webhook, so keying on
        # rule_id alone meant the first description seen for a rule decided
        # what every later alert with that rule id displayed for the whole TTL
        # — a single crafted ingest could put chosen text on the dashboard, in
        # the Telegram and email bodies and in the CSV export for an hour.
        # it_recommender.py already hashes its full prompt; this matches it.
        cache_key="v3:" + hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
        # This runs inside the /wazuh-webhook POST, and the Wazuh integrator
        # gives up at TIMEOUT_S=10 (wazuh_rules/custom-insightshield.py) — with
        # notification routing still to come in the same request. Persisting the
        # alert is the job; the plain-English rewrite is decoration with a
        # guaranteed static fallback, so it gets the small end of that budget.
        #
        # 5s is also why the SECOND provider never ran here: provider one
        # consumes the window and the chain logs "budget exhausted before
        # Gemini (-0.0s left)" every time. The fallback only becomes real on the
        # retry path, which passes the full AI_CHAIN_BUDGET_S — see
        # wazuh_receiver._upgrade_translation.
        budget_s=budget_s or config.AI_INGEST_BUDGET_S,
        ignore_negative_cache=ignore_negative_cache,
    )
    if provider == _ai_chain.AI_CHAIN_EXHAUSTED:
        text = _get_static_template(rule_id, device_name)
        reasoning = reasoning + "\nFalling back to pre-written static template."
        return text, "static", reasoning
    # Cached entries hold the literal {device} placeholder (the prompt demands
    # it), so the same translation safely serves every device sharing a
    # rule_id and this substitution is what puts the right name on screen.
    text = text.replace("{device}", device_name)
    return text, provider, reasoning


def _get_static_template(rule_id: str, device_name: str) -> str:
    """
    Return a pre-written plain-language translation. NEVER raises an exception.
    This is the guaranteed last resort — it must always return a usable string.
    """
    # Unmapped rules fall to "generic", not "rdp_bruteforce". This path runs
    # during a total AI outage, so defaulting to a specific attack meant a
    # ransomware alert was described to the manager as a failed-login attempt —
    # a confident, wrong answer at the worst possible moment.
    template_key = RULE_TO_TEMPLATE.get(rule_id, "generic")
    template = STATIC_TEMPLATES.get(template_key, STATIC_TEMPLATES["generic"])
    return template.replace("{device}", device_name)


def _build_prompt(description: str) -> str:
    """
    Build the system prompt sent to all AI providers.

    Deliberately device-agnostic. The prompt used to interpolate the real
    device name, which meant the model's reply contained that name and
    _ai_chain cached it under rule_id alone — so the next device to fire the
    same rule within the TTL was shown the *previous* device's name. The
    caller substitutes {device} into the result instead.
    """
    forbidden_str = ", ".join(config.FORBIDDEN_WORDS)
    return SYSTEM_PROMPT.format(
        forbidden=forbidden_str,
    ) + f"\n\nAlert description: {description}"
