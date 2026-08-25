# notifier.py
# Insight Shield — Telegram + Email Notification Senders
# Purpose : Deliver alert notifications through 2 channels.
#           Telegram via Bot API, Gmail via SMTP. (SMS/Semaphore retired
#           Round J, 2026-07-29 — see REBUILD_SPEC.md Part 23.)
# Used by : alert_router.route_alert()
# Rule    : Each channel failure is logged but NEVER blocks other channels.

import logging
import smtplib
import ssl
import threading
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import requests

import config
import _request_cache


def _redact(text: str, *secrets) -> str:
    """Blank out secret values that may have been interpolated into `text`.

    The Telegram bot token is part of the request URL, and requests embeds the
    full URL in its exception strings — so `logger.error("...: %s", e)` on a
    DNS or TLS failure wrote the token verbatim into logs/insightshield.log and,
    through the stderr handler, into the gunicorn error log. A transient egress
    outage wrote it once per alert and once per escalation sweep. The Settings
    "Test" path already avoided this by logging only the exception class;
    dispatch keeps the message, minus the secret.
    """
    for secret in secrets:
        if secret:
            text = text.replace(str(secret), "***REDACTED***")
    return text

logger = logging.getLogger("insightshield.notifier")

# ── Service active-state cache (Round F §17.1c) ─────────────────────────────
# Read settings_kv `service_active.<svc>` to gate Telegram dispatch on
# the operator's toggle. 5-second TTL keeps the alert hot path fast — at
# normal traffic the alert router calls send_* a few times per minute, so
# the cache absorbs ~12 settings_kv reads per service per minute under
# heavy load. Default: enabled. Only the literal string "0" disables.
_ACTIVE_CACHE_TTL = 5  # seconds
_active_cache: dict = {"_ts": 0.0, "_data": {}}
_active_cache_lock = threading.Lock()


def _service_is_active(service_key: str) -> bool:
    """Return True if the operator hasn't deactivated this service.

    Round F §17.1c. Used by send_telegram, send_manager_telegram,
    send_manager_resolution_notification. The Test endpoint bypasses this
    via bypass_toggle=True so probes work even on a deactivated service.
    """
    import db
    now = time.time()
    with _active_cache_lock:
        if now - _active_cache["_ts"] > _ACTIVE_CACHE_TTL:
            _active_cache["_ts"] = now
            _active_cache["_data"] = {}
        if service_key not in _active_cache["_data"]:
            val = db.get_setting(f"service_active.{service_key}")
            _active_cache["_data"][service_key] = (val != "0")
        return _active_cache["_data"][service_key]


# ── Telegram Bot API ─────────────────────────────────────────────────────────

def _post_telegram(bot_token: str, chat_id: str, text: str,
                   parse_mode: str = "HTML", label: str = "Telegram") -> bool:
    """
    POST a plain Telegram sendMessage against the given bot + chat.

    Shared by send_telegram (IT group), send_manager_telegram, and
    send_manager_resolution_notification. Each caller validates its own
    config; this helper only reports the HTTP result.
    """
    if not bot_token or not chat_id:
        logger.warning("%s SKIPPED: missing bot_token or chat_id", label)
        return False
    try:
        response = requests.post(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            json={"chat_id": chat_id, "text": text, "parse_mode": parse_mode},
            timeout=15,
        )
        if response.status_code == 200:
            logger.info("%s sent (%d chars)", label, len(text))
            return True
        logger.warning(
            "%s failed: status=%d response=%s",
            label, response.status_code, response.text[:200],
        )
        return False
    except Exception as e:
        # Redacted: the token is in the URL and requests puts the URL in `e`.
        logger.error("%s error: %s: %s", label, type(e).__name__,
                     _redact(str(e), bot_token))
        return False


def send_telegram(alert: dict, bypass_toggle: bool = False) -> bool:
    """
    Send alert notification to Telegram IT group via Bot API.
    Returns True if sent, False if failed or skipped.

    Round F §17.1c: bypass_toggle=True skips the service_active.telegram_it
    check (Test endpoint sets this so probes work on deactivated services).
    """
    if not bypass_toggle and not _service_is_active("telegram_it"):
        logger.info(
            "Telegram(IT) SKIPPED: service_active.telegram_it=0 (operator deactivated) "
            "alert_id=%s", alert.get("id"),
        )
        return False
    message = (
        f"Insight Shield Alert\n"
        f"━━━━━━━━━━━━━━━━━━━\n"
        f"Severity: {alert.get('severity', 'N/A')}\n"
        f"Attack: {alert.get('attack_type', 'N/A')}\n"
        f"Device: {alert.get('device_name', 'N/A')}\n"
        f"━━━━━━━━━━━━━━━━━━━\n"
        f"{alert.get('plain_text', 'No translation available.')}\n"
        f"━━━━━━━━━━━━━━━━━━━\n"
        f"Provider: {alert.get('provider_used', 'N/A')} | "
        f"FK: {alert.get('fk_grade', 'N/A')}\n"
        f"Alert ID: {alert.get('id', 'N/A')}"
    )
    return _post_telegram(
        _request_cache.cached_api_key("telegram_it", "BOT_TOKEN"),
        _request_cache.cached_setting("telegram_it_chat_id"),
        message,
        label=f"Telegram(IT) alert_id={alert.get('id')}",
    )


def send_manager_telegram(alert: dict, bypass_toggle: bool = False) -> bool:
    """
    Send HIGH/CRITICAL alert to the manager's dedicated Telegram bot.

    Body is a trimmed version of the IT message — severity, device, and
    plain-language translation only (no provider/FK diagnostics).

    Round F §17.1c: bypass_toggle=True skips the service_active.telegram_manager
    check (Test endpoint sets this so probes work on deactivated services).
    """
    if not bypass_toggle and not _service_is_active("telegram_manager"):
        logger.info(
            "Telegram(Manager) SKIPPED: service_active.telegram_manager=0 "
            "(operator deactivated) alert_id=%s", alert.get("id"),
        )
        return False
    message = (
        f"Insight Shield Alert\n"
        f"━━━━━━━━━━━━━━━━━━━\n"
        f"Severity: {alert.get('severity', 'N/A')}\n"
        f"Device: {alert.get('device_name', 'N/A')}\n"
        f"━━━━━━━━━━━━━━━━━━━\n"
        f"{alert.get('plain_text', 'No translation available.')}"
    )
    return _post_telegram(
        _request_cache.cached_api_key("telegram_manager", "BOT_TOKEN"),
        _request_cache.cached_setting("telegram_manager_chat_id"),
        message,
        label=f"Telegram(Manager) alert_id={alert.get('id')}",
    )


def send_manager_resolution_notification(alert: dict,
                                         bypass_toggle: bool = False) -> bool:
    """
    Notify manager that IT has resolved an alert.

    Plain-text, short message — no severity banner, no diagnostics. Sent
    to the same manager bot + chat as send_manager_telegram. Returns False
    (without raising) if the manager bot is not configured.

    Round F §17.1c: bypass_toggle=True skips the service_active.telegram_manager
    check.
    """
    if not bypass_toggle and not _service_is_active("telegram_manager"):
        logger.info(
            "Telegram(Manager) resolution SKIPPED: service_active.telegram_manager=0 "
            "(operator deactivated) alert_id=%s", alert.get("id"),
        )
        return False
    text = (
        f"[Insight Shield] Alert #{alert.get('id')} "
        f"({alert.get('attack_type', 'alert')} on "
        f"{alert.get('device_name', '?')}) "
        f"has been resolved by IT. Normal operations may resume."
    )
    return _post_telegram(
        _request_cache.cached_api_key("telegram_manager", "BOT_TOKEN"),
        _request_cache.cached_setting("telegram_manager_chat_id"),
        text,
        parse_mode="",  # plain text — no HTML escaping surprises
        label=f"Telegram(Manager-resolve) alert_id={alert.get('id')}",
    )


# ── Gmail SMTP ───────────────────────────────────────────────────────────────

def send_email(alert: dict) -> bool:
    """
    Send alert notification via Gmail SMTP to IT admin.
    Uses App Password (not Gmail password).
    Returns True if sent, False if failed or skipped.
    """
    gmail_address = _request_cache.cached_setting("gmail_address")
    gmail_password = _request_cache.cached_api_key("gmail", "APP_PASSWORD")
    if not gmail_address or not gmail_password:
        logger.warning("Email SKIPPED: gmail_address or gmail app_password not configured")
        return False

    recipient = _request_cache.cached_setting("it_admin_email")
    if not recipient:
        logger.warning("Email SKIPPED: it_admin_email not configured")
        return False

    subject = (
        f"[Insight Shield] {alert.get('severity', 'ALERT')} — "
        f"{alert.get('attack_type', 'Security Alert')} on "
        f"{alert.get('device_name', 'Unknown Device')}"
    )

    body = (
        f"Insight Shield Security Alert\n"
        f"{'=' * 40}\n\n"
        f"Severity:    {alert.get('severity', 'N/A')}\n"
        f"Attack Type: {alert.get('attack_type', 'N/A')}\n"
        f"Device:      {alert.get('device_name', 'N/A')}\n"
        f"Time:        {alert.get('timestamp', 'N/A')}\n"
        f"Rule ID:     {alert.get('rule_id', 'N/A')}\n"
        f"Provider:    {alert.get('provider_used', 'N/A')}\n"
        f"FK Grade:    {alert.get('fk_grade', 'N/A')}\n"
        f"Alert ID:    {alert.get('id', 'N/A')}\n\n"
        f"{'=' * 40}\n"
        f"PLAIN-LANGUAGE TRANSLATION\n"
        f"{'=' * 40}\n\n"
        f"{alert.get('plain_text', 'No translation available.')}\n\n"
        f"{'=' * 40}\n"
        f"Log in to the Insight Shield dashboard to acknowledge this alert.\n"
    )

    msg = MIMEMultipart()
    msg["From"] = gmail_address
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        # timeout is not optional: without it a blackholed Gmail leaves the
        # escalation sweep blocked on connect() forever.
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=15) as server:
            # An explicit context is required. smtplib's starttls() with
            # context=None falls back to ssl._create_stdlib_context(), which is
            # check_hostname=False / verify_mode=CERT_NONE — so the Gmail app
            # password crossed a completely unverified channel on every alert.
            server.starttls(context=ssl.create_default_context())
            server.login(gmail_address, gmail_password)
            server.sendmail(gmail_address, recipient, msg.as_string())

        logger.info("Email sent to %s for alert_id=%s", recipient, alert.get("id"))
        return True

    except Exception as e:
        logger.error("Email error: %s: %s", type(e).__name__,
                     _redact(str(e), gmail_password))
        return False
