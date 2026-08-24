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
# Contact-record fields only (SMS channel retired Round J) — no longer read
# by any dispatch path; kept for the Notification Recipients settings card.
MANAGER_PHONE       = os.environ.get("MANAGER_PHONE",  "")
IT_ADMIN_PHONE      = os.environ.get("IT_ADMIN_PHONE", "")
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
GROQ_MODEL       = "llama-3.1-8b-instant"
GEMINI_MODEL     = "gemini-2.5-flash"
OPENROUTER_MODEL = "google/gemma-4-26b-a4b-it:free"

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

# ── Session ──────────────────────────────────────────────────────────────────
# Flask session timeout in minutes — idle time, refreshed by real user requests
# but not by dashboard polling (see app._IdleTimeoutSessionInterface). The env
# override exists so the timeout can actually be tested: ST-009 otherwise needs
# a 30-minute wall-clock wait. Production leaves it unset.
PERMANENT_SESSION_LIFETIME_MIN = int(
    os.environ.get("INSIGHTSHIELD_SESSION_LIFETIME_MIN") or 30
)

# ── Known Devices ────────────────────────────────────────────────────────────
KNOWN_DEVICES = ["POS-TERMINAL-01", "MANAGER-PC-01"]

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
