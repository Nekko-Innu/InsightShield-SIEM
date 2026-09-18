# config.py
# Insight Shield — Configuration Gateway
# Single source of truth for all env vars, thresholds, and shared constants.
# Every other module imports from here — never redefine constants locally.
# No logic lives here — just flat constants loaded once at import time.

import os
import logging
from dotenv import load_dotenv
from zoneinfo import ZoneInfo

logger = logging.getLogger("insightshield.config")

# Explicit CWD-relative path, matching db.py:29's DB_PATH convention. A bare
# load_dotenv() searches upward from THIS FILE's directory, not the process
# CWD — so the E2E suite, which runs the server with cwd=<tmpdir> precisely to
# get a throwaway DB, still loaded the developer's real .env. That seeded three
# live AI providers into the test database (making /report?generated=1 take
# 3 x 30s against Playwright's 30s limit) and let the suite send real Telegram
# messages and open real Gmail SMTP sessions.
load_dotenv(dotenv_path=os.path.join(os.getcwd(), ".env"))

# ── Timezone ─────────────────────────────────────────────────────────────────
# All datetime.now() calls MUST use PHT. Never use bare datetime.now().
PHT = ZoneInfo("Asia/Manila")

# ── API Keys (from .env) ─────────────────────────────────────────────────────
GROQ_API_KEY        = os.environ.get("GROQ_API_KEY", "")
GEMINI_API_KEY      = os.environ.get("GEMINI_API_KEY", "")
OPENROUTER_API_KEY  = os.environ.get("OPENROUTER_API_KEY", "")
TELEGRAM_BOT_TOKEN  = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID    = os.environ.get("TELEGRAM_CHAT_ID", "")
# Manager Telegram uses a dedicated bot + chat so managers only see
# HIGH/CRITICAL alerts and resolution notices — not the IT firehose.
TELEGRAM_MANAGER_BOT_TOKEN = os.environ.get("TELEGRAM_MANAGER_BOT_TOKEN", "")
TELEGRAM_MANAGER_CHAT_ID   = os.environ.get("TELEGRAM_MANAGER_CHAT_ID", "")
GMAIL_ADDRESS       = os.environ.get("GMAIL_ADDRESS", "")
GMAIL_APP_PASSWORD  = os.environ.get("GMAIL_APP_PASSWORD", "")
# Email channel kill switch. OFF by default: one ARP-spoof burst stored ~60
# CRITICAL rows, each emailed at ingest and again on every 5-minute escalation
# sweep, which exhausts a Gmail account's daily send limit in under an hour.
# Off also hides the Gmail card and the IT-admin-email field in Settings.
# EMAIL_ENABLED=1 in .env restores both; the stored credentials are untouched.
EMAIL_ENABLED = os.environ.get("EMAIL_ENABLED", "").lower() in ("1", "true", "yes")
# Recipient of alert emails; edited in the Gmail settings card.
IT_ADMIN_EMAIL      = os.environ.get("IT_ADMIN_EMAIL", "")
# ── Flask session signing key ────────────────────────────────────────────────
# Fail loud, the same way crypto_utils.get_master_key() does for ENCRYPTION_KEY.
# This used to fall back to a literal committed to this repo — anyone with the
# source could forge a session cookie (full auth bypass as IT_ADMIN) and forge
# the CSRF token, which lives inside that same signed session.
# The placeholder from .env.example is rejected too: it is non-empty, so a
# copy-the-example deploy would otherwise boot on a second published key.
_SECRET_KEY_PLACEHOLDERS = {
    "",
    "insightshield-dev-key-change-in-prod",
    "generate-a-random-secret-key-here",
}
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "")
if FLASK_SECRET_KEY.strip() in _SECRET_KEY_PLACEHOLDERS:
    import sys

    sys.stderr.write(
        "FATAL: FLASK_SECRET_KEY is unset or still the placeholder value.\n"
        "       Generate one with:  python -c \"import secrets;"
        " print(secrets.token_hex(32))\"\n"
        "       then set it in .env before starting the app.\n"
    )
    sys.exit(1)

# ── Report / PDF limits ──────────────────────────────────────────────────────
# /report.pdf launches a headless Chromium synchronously per request and is
# reachable by both roles, so it needs both a call budget and a bounded range.
REPORT_PDF_PER_MIN = int(os.environ.get("REPORT_PDF_PER_MIN", "4"))
REPORT_MAX_RANGE_DAYS = int(os.environ.get("REPORT_MAX_RANGE_DAYS", "366"))

# Max alerts itemized in the report's "Alert Details" + raw-JSON appendix.
# An audit report is a summary, not an event log: the aggregate sections cover
# every alert, but the itemized detail is capped (and scoped to actionable
# HIGH/CRITICAL severities in reports.py) so a busy period can't blow the PDF up
# to hundreds of pages. Raise it only if a specific audit needs deeper listing.
REPORT_DETAIL_CAP = int(os.environ.get("REPORT_DETAIL_CAP", "100"))

# Base URL Chromium resolves the report's relative /static/* URLs against.
# Pinned rather than taken from request.host_url: ProxyFix trusts a
# client-supplied X-Forwarded-Host, so the header could have pointed the PDF
# renderer at an attacker origin. Chromium runs on the same host as Flask, so
# the loopback bind is the right target — override only if that bind changes.
REPORT_ASSET_BASE_URL = os.environ.get(
    "REPORT_ASSET_BASE_URL", "http://127.0.0.1:5000/"
)

# ── Log retention ────────────────────────────────────────────────────────────
# Consumed by the 03:00 purge job in scheduler.py. Nothing deleted a row before
# this existed. Alerts are never purged — they are the evidence.
AUDIT_RETENTION_DAYS = int(os.environ.get("AUDIT_RETENTION_DAYS", "90"))
ERROR_RETENTION_DAYS = int(os.environ.get("ERROR_RETENTION_DAYS", "30"))

# ── Wazuh webhook shared secret ──────────────────────────────────────────────
# Sent by the Wazuh integrator script as the X-Webhook-Token header. Backs up
# the IP allowlist on /wazuh-webhook, which is forgeable on its own now that
# ProxyFix trusts a client-supplied X-Forwarded-For.
#
# Empty means every payload 403s — app.py's webhook fails closed, and the
# startup block logs it. Deliberately NOT a sys.exit like FLASK_SECRET_KEY:
# the unit sets Restart=always, so that would turn "Wazuh not wired up yet"
# into a 5-second crash loop, and every other page works without Wazuh.
# scripts/install.sh generates this and writes the same value into ossec.conf.
WAZUH_WEBHOOK_TOKEN = os.environ.get("WAZUH_WEBHOOK_TOKEN", "")

# ── Cookie transport ─────────────────────────────────────────────────────────
# Secure cookies are the default and must stay on in production. The E2E suite
# and local `flask run` serve plain HTTP, where a Secure cookie is never sent
# back and every login silently fails — those set INSIGHTSHIELD_ALLOW_HTTP_COOKIES=1.
COOKIES_REQUIRE_HTTPS = os.environ.get(
    "INSIGHTSHIELD_ALLOW_HTTP_COOKIES", ""
).lower() not in ("1", "true", "yes")

# ── AI Models ────────────────────────────────────────────────────────────────
# Every model is env-overridable. This is the load-bearing fix for the outage
# that read as "rate limiting": a hardcoded slug that a provider no longer
# serves returns HTTP 400, the chain treats it like any other failure and falls
# to the static template — silently. A stale constant should never be able to
# kill AI again, so the slug is a knob, not a literal, and KNOWN_BAD_AI_MODELS
# below lets the repair script and healthcheck name the ones we've already been
# burned by.
GROQ_MODEL       = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
GEMINI_MODEL     = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
# ':free' OpenRouter slugs drift as models are rotated out; override via env
# when one 404s rather than editing this line. meta-llama/llama-3.1-8b-instruct:free
# was retired (OpenRouter now 404s it and points at the paid slug), so the
# default moved to a currently-free model. See KNOWN_BAD_AI_MODELS below.
OPENROUTER_MODEL = os.environ.get("OPENROUTER_MODEL", "nvidia/nemotron-3.5-lightning:free")

# Output token ceiling for every provider request. Was hardcoded at 200 in
# _ai_chain._call_openai_compat, which is plenty for our <=100-word answers from
# an instruction model — but fatal for a REASONING model (Groq's gpt-oss / qwen3
# spend tokens on an internal reasoning channel first). At 200 the reasoning ate
# the whole budget and `content` came back empty, so the validator rejected it as
# "empty input" and the alert fell to the static template. 1024 leaves room for
# the reasoning plus the answer; instruction models still stop at their natural
# length, so raising it only ever helps. Kept well under the 8K TPM free-tier
# window so one call can't trip request_too_large on its own.
AI_MAX_TOKENS = int(os.environ.get("AI_MAX_TOKENS", "1024"))

# Slugs we have shipped or seeded that no provider actually serves. The one-shot
# scripts/repair_providers.py rewrites any ai_providers row on this list to the
# valid default for its label; scripts/healthcheck.sh warns if an active
# provider still carries one. Deliberately NOT including "llama-3.1-8b-instant":
# it may still be valid on some Groq tiers, and a false rewrite of a working row
# is worse than leaving it — only slugs that are definitely dead go here.
KNOWN_BAD_AI_MODELS = {
    "google/gemma-4-26b-a4b-it:free",       # gemma-4 does not exist
    "openrouter/free",                      # not a real model id
    "meta-llama/llama-3.1-8b-instruct:free",  # retired: OpenRouter 404s it, free tier gone
}

# Display label for the primary-provider KPI tile on the IT dashboard. Round 3
# replaces this with `db.get_active_providers_ordered()[0]['label']` once Settings
# is wired; until then, this env-driven default keeps the tile honest if the
# operator promotes Gemini or OpenRouter to the primary slot.
PRIMARY_AI_LABEL = os.environ.get("PRIMARY_AI_LABEL", "Groq")

# ── AI Provider Chain (Round 2 data source — Round 3 reads from DB instead) ──
# Each provider dict is the canonical shape consumed by _ai_chain.run_chain.
# Round 3's ai_providers table stores rows with the same column names so the
# chain runner is written ONCE; only the source of the list changes between rounds.
DEFAULT_AI_PROVIDERS = [
    {
        "label":          "Groq",
        "model":          GROQ_MODEL,
        "base_url":       "https://api.groq.com/openai/v1/chat/completions",
        "api_key":        os.environ.get("GROQ_API_KEY", ""),
        "auth_header":    "Authorization",
        "auth_prefix":    "Bearer ",
        "request_format": "openai_compat",
        "is_active":      True,
    },
    {
        "label":          "Gemini",
        "model":          GEMINI_MODEL,
        "base_url":       "https://generativelanguage.googleapis.com/v1beta/models/" + GEMINI_MODEL + ":generateContent",
        "api_key":        os.environ.get("GEMINI_API_KEY", ""),
        "auth_header":    "x-goog-api-key",
        "auth_prefix":    "",
        "request_format": "gemini_v1beta",
        "is_active":      True,
    },
    {
        "label":          "OpenRouter",
        "model":          OPENROUTER_MODEL,
        "base_url":       "https://openrouter.ai/api/v1/chat/completions",
        "api_key":        os.environ.get("OPENROUTER_API_KEY", ""),
        "auth_header":    "Authorization",
        "auth_prefix":    "Bearer ",
        "request_format": "openai_compat",
        "is_active":      True,
    },
]

# Pre-built provider templates consumed by Round 3's Settings UI dropdown. The
# client picks a vendor from this list and the base_url + auth fields auto-fill;
# only the api_key and model must be entered. "Custom" is a permissive default
# for any OpenAI-compatible endpoint not in the list. Round 3 reads this dict
# straight off the import.
PROVIDER_TEMPLATES = {
    "Groq":       {"base_url": "https://api.groq.com/openai/v1/chat/completions",
                   "auth_header": "Authorization", "auth_prefix": "Bearer ",
                   "request_format": "openai_compat"},
    "OpenAI":     {"base_url": "https://api.openai.com/v1/chat/completions",
                   "auth_header": "Authorization", "auth_prefix": "Bearer ",
                   "request_format": "openai_compat"},
    "Gemini":     {"base_url": "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
                   "auth_header": "x-goog-api-key", "auth_prefix": "",
                   "request_format": "gemini_v1beta"},
    "DeepSeek":   {"base_url": "https://api.deepseek.com/v1/chat/completions",
                   "auth_header": "Authorization", "auth_prefix": "Bearer ",
                   "request_format": "openai_compat"},
    "Anthropic":  {"base_url": "https://api.anthropic.com/v1/messages",
                   "auth_header": "x-api-key", "auth_prefix": "",
                   "request_format": "anthropic_messages"},
    "OpenRouter": {"base_url": "https://openrouter.ai/api/v1/chat/completions",
                   "auth_header": "Authorization", "auth_prefix": "Bearer ",
                   "request_format": "openai_compat"},
    "Custom":     {"base_url": "", "auth_header": "Authorization",
                   "auth_prefix": "Bearer ", "request_format": "openai_compat"},
}

# Groq free-tier ceiling is 30 req/min. Cap at 25 to leave retry headroom; the
# inline burst absorber in _ai_chain.run_chain reads this constant.
GROQ_BUDGET_PER_MIN = 25

# Per-provider outbound call ceiling (per minute), keyed by provider label
# lower-cased. The burst absorber in _ai_chain.run_chain now applies to EVERY
# provider, not just Groq, so a HIGH/CRITICAL burst — translation AND IT
# recommendation, which share one per-label window — can never exceed the free
# tier: past the cap the provider is skipped and the chain falls to static.
# Kept under each vendor's real free limit (Groq 30, OpenRouter ~20, Gemini ~15).
AI_PROVIDER_RATE_LIMITS = {
    "groq":       GROQ_BUDGET_PER_MIN,
    "openrouter": 18,
    "gemini":     15,
}
# Any provider not named above (a Custom endpoint from Settings) gets this.
AI_PROVIDER_RATE_LIMIT_DEFAULT = 15

# The IT recommender runs in fire-and-forget daemon threads (one per alert).
# A burst of criticals would otherwise spawn many concurrent chain calls that
# race past the per-minute window (the limiter's check-then-insert overshoot is
# bounded by concurrency, and threads multiply it). This bounds how many
# recommendation calls run at once; 1 serialises them, which is free because
# they are not on any request's critical path.
IT_RECOMMENDER_MAX_CONCURRENCY = int(
    os.environ.get("IT_RECOMMENDER_MAX_CONCURRENCY", "1")
)

# ── AI chain time budget ─────────────────────────────────────────────────────
# The provider chain had a 30s timeout PER PROVIDER and no total bound, so three
# configured providers could hold a request for 90s before falling back to the
# static summary. gunicorn's 120s timeout was the only ceiling, and reaching it
# SIGKILLs the worker.
#
# 25s is the default: comfortably inside 120s alongside the report's DB queries,
# and under the 30s a browser (and Playwright) will wait for a page load.
AI_CHAIN_BUDGET_S = 25.0
# Don't start a provider we cannot give a fair chance — better to stop the chain
# and fall back than to burn the remaining 2s on a request that will time out.
# Applied only from the SECOND provider onward (see _ai_chain.run_chain): the
# first active provider is always attempted, so an ingest budget equal to this
# floor still gets one real Groq call instead of exhausting before any attempt.
AI_MIN_PROVIDER_S = 5.0
# The ingest path is much tighter: groq_translator runs inside the
# /wazuh-webhook POST, and the Wazuh integrator gives up at TIMEOUT_S = 10
# (wazuh_rules/custom-insightshield.py). Notification sending happens in that
# same request, so the AI leg gets 5s and the static template covers the rest.
AI_INGEST_BUDGET_S = 5.0
# How long to remember that the whole chain failed. Without this, every reload
# of a report re-ran all providers at full budget. Short enough that fixing a
# key in Settings takes effect within five minutes; the "clear cache" button is
# the instant override.
AI_NEGATIVE_CACHE_S = 300
# Sentinel returned as BOTH text and provider when every provider failed. Lives
# here rather than in _ai_chain because cache.py has to recognise it to give it
# the short TTL above, and config is the one module everything already imports.
# _ai_chain re-exports it, so no caller had to change.
AI_CHAIN_EXHAUSTED = "AI_CHAIN_EXHAUSTED"

# ── AI severity gate ─────────────────────────────────────────────────────────
# Free-tier providers (Groq 30/min, Gemini/OpenRouter free quotas) cannot keep
# up with an AI call — two, once the IT recommender is on — on EVERY alert. Only
# these severities get an AI translation; INFORMATIONAL / LOW / MEDIUM fall
# straight to groq_translator's static template, which is instant and never
# rate-limited. The same set gates the IT recommender below. Reserving the
# budget for HIGH/CRITICAL is what lets the free tier actually serve the alerts
# that matter instead of burning quota on noise.
AI_ENABLED_SEVERITIES = {"HIGH", "CRITICAL"}

# Hard cap on live AI attempts per (rule_id, device) per rolling 24 h. A single
# noisy rule — a false-positive LSASS or ARP detection firing hourly — otherwise
# spends the whole free-tier budget on the same alert over and over: the manager
# translation, the retry, and the IT recommendation each fire per row, and the
# recommendation prompt embeds the raw alert so its cache never hits a repeat.
# Past the cap, that rule+device falls back to the static template and to reusing
# a sibling's recommendation; the alert is still stored, notified, and shown —
# only the AI spend is capped. Counted in rate_events (shared across workers and
# the scheduler) so failures count too, which is the point: a rule that only ever
# fails must stop being retried. 0 disables the cap.
AI_REPEAT_CAP = int(os.environ.get("AI_REPEAT_CAP", "5"))
AI_REPEAT_WINDOW_S = 86400

# The IT recommender fires a SECOND AI call per alert (IT-only investigation
# steps). OFF by default so it never competes with the manager translation for
# the free-tier budget — the alert detail page shows its static fallback line
# until this is turned on. Set IT_RECOMMENDER_ENABLED=1 in .env to re-enable it;
# it stays gated to AI_ENABLED_SEVERITIES even when on.
IT_RECOMMENDER_ENABLED = os.environ.get(
    "IT_RECOMMENDER_ENABLED", ""
).lower() in ("1", "true", "yes")

# ── IT recommendation: burst reuse + backfill ────────────────────────────────
# The recommendation prompt embeds the whole raw alert JSON — timestamps,
# full_log, file paths — so its sha256 cache key is unique per alert and the
# ai_cache NEVER hits on a repeat. Ten identical rule-100020 alerts therefore ran
# ten full provider chains, serialised through a semaphore of 1; alert four
# onward waited 30s, logged "recommender busy", and was left with a permanently
# NULL it_recommendation because nothing retried.
#
# Reuse closes that: before spending a call, take the newest recommendation from
# the same rule on the same device inside this window. 0 disables reuse and
# restores the exact previous behaviour — the kill switch for this feature.
IT_REC_REUSE_WINDOW_MIN = int(os.environ.get("IT_REC_REUSE_WINDOW_MIN", "15"))

# Backfill sweep for alerts that ended up blank anyway (a burst that outran the
# window, a provider outage, a worker restart mid-generation). Runs in
# insightshield-worker, which owns the scheduler, so it never competes with a
# live webhook for the gunicorn workers' semaphore. 0 disables the job.
IT_REC_BACKFILL_MIN = int(os.environ.get("IT_REC_BACKFILL_MIN", "10"))
# Alerts per sweep. Small on purpose: the point is to drain a backlog slowly
# inside the free tier, not to replay a burst at full speed.
IT_REC_BACKFILL_BATCH = int(os.environ.get("IT_REC_BACKFILL_BATCH", "3"))

# Retry a manager translation that fell back to static, in a background thread
# with the full AI_CHAIN_BUDGET_S instead of the webhook's 5s slice.
#
# The 5s slice is set by the Wazuh integrator's 10s timeout, and one slow
# provider eats all of it — the chain then logs "budget exhausted before
# <fallback> (-0.0s left)", which means the configured fallback provider has
# never once run on ingest. The retry is where the chain actually becomes a
# chain. TRANSLATION_RETRY=0 disables it and restores the previous behaviour.
TRANSLATION_RETRY_ENABLED = os.environ.get(
    "TRANSLATION_RETRY", "1"
).lower() in ("1", "true", "yes")

# Word ceiling for IT investigation steps, separate from MAX_WORDS.
# IT_SYSTEM_PROMPT asks for 100 words; models land at 103-104 often enough that
# the shared 100-word cap was rejecting BOTH providers and storing
# AI_CHAIN_EXHAUSTED after two real API calls. 120 is the tolerance band, not a
# new target — the prompt still says 100. MAX_WORDS stays 100 for the manager
# translation, which is deliberately short.
IT_REC_MAX_WORDS = int(os.environ.get("IT_REC_MAX_WORDS", "120"))


def ai_enabled_for(severity: str) -> bool:
    """True if this severity is eligible for a live AI call.

    Single source of truth for the gate so the manager-translation and the
    IT-recommendation call sites can't drift apart. The IT recommender adds its
    own IT_RECOMMENDER_ENABLED check on top of this.
    """
    return (severity or "").upper() in AI_ENABLED_SEVERITIES


# ── Alert lifecycle policy ───────────────────────────────────────────────────
# Only these severities carry the IT ack -> resolve lifecycle. Everything below
# HIGH is auto-closed at ingest (resolved by SYSTEM_ACTOR) — informational, no
# IT action required, so it never sits "Open / Pending" or inflates the
# open-alerts KPI. Kept SEPARATE from AI_ENABLED_SEVERITIES even though the
# values coincide today: AI-budget policy and lifecycle policy are different
# concerns and may diverge.
ACTIONABLE_SEVERITIES = {"HIGH", "CRITICAL"}

# Demo filter. When DEMO_FILTER=1 in .env, HIGH/CRITICAL alerts whose rule is
# NOT one of the five capstone-demo attacks are discarded at ingest — never
# stored, translated, or notified — so the dashboard shows only the demo
# attacks. Wazuh detection is untouched (this runs in the webhook, downstream
# of analysisd); lower-severity alerts also pass through unchanged.
# Toggle with scripts/demo_filter.sh on|off. The demo attacks (see attack_wazuh.sh):
#   brute force 100001 · ransomware 100044-100047 · LSASS 92900/100099
#   POS RAM scraping 100010 (same memory-read technique as LSASS, POS process
#   target — keeps its own "RAM scraping" label) · ARP MitM 100020-100023 ·
#   SYN flood 100031/100040/100041
DEMO_FILTER = os.environ.get("DEMO_FILTER", "").lower() in ("1", "true", "yes")
DEMO_ATTACK_RULES = frozenset({
    "100001",
    "100044", "100045", "100046", "100047",
    "92900", "100099",
    "100010",
    "100020", "100021", "100022", "100023",
    "100031", "100040", "100041",
})

# Sentinel actor + note for a system auto-close. resolved_by == SYSTEM_ACTOR is
# what the UI and reports use to tell an automatic closure from a human resolve.
SYSTEM_ACTOR = "system"
AUTO_CLOSE_NOTE = "Auto-closed: informational severity — no IT action required."


def requires_ack(severity: str) -> bool:
    """True if this severity needs a human IT ack/resolve lifecycle.

    False for MEDIUM/LOW/INFORMATIONAL, which are auto-closed at ingest.
    """
    return (severity or "").upper() in ACTIONABLE_SEVERITIES

# ── Thresholds ───────────────────────────────────────────────────────────────
BUSINESS_START          = 8       # 08:00 PHT — after-hours escalation boundary
BUSINESS_END            = 21      # 21:00 PHT
CACHE_TTL               = 3600    # 1-hour AI translation cache (seconds)
MAX_WORDS               = 100     # AI output word limit (master spec §1.1)
FK_GRADE_TARGET         = 6.0     # Readability target (log only — never a gate)
ESCALATION_INTERVAL_MIN = 5       # Critical alert repeat interval until ACK
# Stop escalating an alert nobody has acknowledged after this long. Not optional:
# escalation used to live in APScheduler's in-memory job store, so a restart
# quietly ended it. Driven from the database it would page IT forever, which is
# how a real alerting system trains people to ignore it.
ESCALATION_MAX_AGE_H = 24
# HIGH/CRITICAL notifications per (rule, device). An attack that repeats — an
# ARP spoof re-poisons every 2 s — is one incident, not sixty; the first alert
# notifies, the rest land on the dashboard only until the window passes.
NOTIFY_COOLDOWN_MIN = 10

# ── Session ──────────────────────────────────────────────────────────────────
# Flask session timeout in minutes — idle time, refreshed by real user requests
# but not by dashboard polling (see app._IdleTimeoutSessionInterface). The env
# override exists so the timeout can actually be tested: ST-009 otherwise needs
# a 30-minute wall-clock wait. Production leaves it unset.
PERMANENT_SESSION_LIFETIME_MIN = int(
    os.environ.get("INSIGHTSHIELD_SESSION_LIFETIME_MIN") or 30
)

# ── Known Devices ────────────────────────────────────────────────────────────
# Fallback only — shown with status "unknown" when the Wazuh API is unreachable.
# Names must match the agent names in the manager, or the dashboard shows two
# sets of tiles for the same machines once the API comes back.
KNOWN_DEVICES = ["wazuh-system", "Manager", "POSsys1", "POSsys2", "POSsys3"]

# ── Severity Levels (ordered low → high) ─────────────────────────────────────
SEVERITY_LEVELS = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

# ── Health Score Constants ───────────────────────────────────────────────────
DEDUCT = {"INFORMATIONAL": 0, "LOW": 2, "MEDIUM": 5, "HIGH": 10, "CRITICAL": 20}
BONUS  = {"within_10min": 5, "within_30min": 2}

# ── Forbidden Words for AI Output Validation (all 19) ────────────────────────
# Case-insensitive substring match. If ANY word is found, reject the AI output.
FORBIDDEN_WORDS = [
    "IP address", "TCP", "NTLM", "SMB", "protocol", "authentication",
    "payload", "exploit", "buffer overflow", "firewall", "SSID", "ARP",
    "DHCP", "DNS", "ICMP", "HTTP", "FTP", "SSH", "RDP",
]

# ── Wazuh Manager API (for agent status monitoring) ──────────────────────────
# Credentials will be added when Wazuh is deployed on VM-03.
# If unreachable, dashboard falls back to static KNOWN_DEVICES list.
WAZUH_API_URL      = os.environ.get("WAZUH_API_URL", "https://127.0.0.1:55000")
WAZUH_API_USER     = os.environ.get("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASSWORD  = os.environ.get("WAZUH_API_PASSWORD", "")
# TLS verification for the Wazuh API. Three accepted forms:
#   unset            -> True, verify against the system trust store
#   a filesystem path -> that CA bundle (what a self-signed lab manager wants)
#   0/false/no/off   -> False, no verification at all, warned about loudly
# This used to default to "" while every caller wrote
# `verify=config.WAZUH_API_VERIFY or False`, so the shipped default sent
# WAZUH_API_USER and WAZUH_API_PASSWORD over an unvalidated TLS channel. The
# callers now pass the value straight through — dropping `or False` is the
# load-bearing half of the fix.
_verify_raw = os.environ.get("WAZUH_API_VERIFY", "").strip()
if _verify_raw.lower() in ("0", "false", "no", "off"):
    WAZUH_API_VERIFY = False
    logger.warning(
        "WAZUH_API_VERIFY is disabled - Wazuh API credentials will cross an "
        "unverified TLS channel. Acceptable for a self-signed lab manager, "
        "never for production. Point it at the manager's CA bundle instead."
    )
elif _verify_raw:
    WAZUH_API_VERIFY = _verify_raw      # path to a CA bundle
else:
    WAZUH_API_VERIFY = True             # system trust store

# ── Authorization-probe detection (A09.7) ────────────────────────────────────
# The audit that prompted this fired ~200 hostile requests — SQL injection
# across 8 parameters, XSS, SSRF, forged session cookies and a full unauthorized
# sweep of every route — and raised no alert, because 403s, CSRF rejections and
# webhook auth failures were logger.warning and nothing else. Logging without
# alerting is what A09 was renamed to catch.
#
# Start the limit high and lower it once there is a baseline: A09 names
# false-positive volume as its own failure mode, and an operator who learns to
# ignore this alert is worse off than one who never had it.
AUTHZ_PROBE_LIMIT      = int(os.environ.get("AUTHZ_PROBE_LIMIT", "25"))
AUTHZ_PROBE_WINDOW_MIN = int(os.environ.get("AUTHZ_PROBE_WINDOW_MIN", "60"))
AUTHZ_PROBE_SWEEP_MIN  = int(os.environ.get("AUTHZ_PROBE_SWEEP_MIN", "10"))

# ── Hardcoded Users — BOOTSTRAP ONLY (Flask-Login) ───────────────────────────
# ⚠  Runtime authentication reads the `users` table in insightshield.db, not this dict.
#    This dict is consumed exactly once by db.seed_users_from_config() when the
#    users table is empty (first-run bootstrap). Editing these values after the
#    first run has no effect — change passwords through /account/password instead.
# Two roles: manager (read-only dashboard) and IT_ADMIN (full access)
# Role strings are compared case-insensitively (decorators.normalize_role), but
# they are stored verbatim, so keep the casing consistent here. "manager" was
# lower-case next to "IT_ADMIN" upper-case, which nothing caught only because
# every comparison in the app was an IT_ADMIN test with an implicit else.
# Bootstrap-only: db.seed_users_from_config() no-ops once users is non-empty, so
# changing this does NOT fix an already-seeded row.
# No literal fallbacks. These used to carry committed defaults, which meant a
# fresh install authenticated with a password anyone could read off the public
# repo for the whole window between first boot and first login — and IT_ADMIN
# can reveal every stored credential. db.seed_users_from_config() refuses to
# seed an empty password rather than substituting one. must_change_password=1
# still forces the first login through /account/password.
USERS = {
    "admin": {
        "password": os.environ.get("BOOTSTRAP_ADMIN_PASSWORD", ""),
        "role": "IT_ADMIN",
    },
    "manager": {
        "password": os.environ.get("BOOTSTRAP_MANAGER_PASSWORD", ""),
        "role": "MANAGER",
    },
}
