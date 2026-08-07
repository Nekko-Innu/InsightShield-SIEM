# alert_router.py
# Insight Shield — Severity Routing + After-Hours Escalation
# Purpose : Central routing logic. Apply after-hours escalation FIRST,
#           then route to notification channels based on severity.
#           Escalation logic lives ONLY here — never in notifier.py or
#           wazuh_receiver.py.
# Used by : wazuh_receiver.process_alert()

import logging
from datetime import datetime

import config
import _request_cache

logger = logging.getLogger("insightshield.alert_router")


def route_alert(severity: str, alert: dict) -> None:
    """
    Apply after-hours escalation, then route to notification channels.

    Channel matrix (after 2026-04-23 scope change):
      INFO/LOW   → dashboard only
      MEDIUM     → IT Telegram only (suppressed if same rule_id within 10 min)
      HIGH       → IT SMS (rate-limited 1/5min/device) + IT Telegram + IT Email
                   + Manager Telegram
      CRITICAL   → same as HIGH + 5-minute escalation scheduler

    Parameters
    ----------
    severity : str
        Original severity: INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL.
    alert : dict
        Full alert dict from db.get_alert() (all 20 columns).
    """
    # Import here to avoid circular imports (notifier imports config,
    # but alert_router is called from wazuh_receiver which also imports config)
    import notifier
    import rate_limit
    import scheduler

    original_severity = severity

    # Step 1: After-hours escalation
    if is_outside_hours():
        severity = escalate_one_tier(severity)
        if severity != original_severity:
            logger.info(
                "After-hours escalation: %s → %s for alert_id=%s",
                original_severity, severity, alert.get("id"),
            )

    # Step 2: Route by severity
    if severity in ("INFORMATIONAL", "LOW"):
        logger.info("Alert id=%s severity=%s: dashboard only", alert.get("id"), severity)
        return

    if severity == "MEDIUM":
        # Flood suppression: 1 Medium Telegram per rule_id per 10 min.
        rule_id = str(alert.get("rule_id") or "")
        allowed, retry_after = rate_limit.can_call(
            f"tg-medium:{rule_id}", limit_per_min=1, window_seconds=600,
        )
        if allowed:
            notifier.send_telegram(alert)
        else:
            logger.info(
                "Medium Telegram suppressed: rule_id=%s retry_after=%.0fs",
                rule_id, retry_after,
            )

    elif severity in ("HIGH", "CRITICAL"):
        # SMS leg retired in Round J (see REBUILD_SPEC.md Part 23) — Telegram
        # + Email are the complete active channel set for HIGH/CRITICAL.
        notifier.send_telegram(alert)
        notifier.send_email(alert)
        notifier.send_manager_telegram(alert)

        # CRITICAL escalation needs no registration: scheduler._escalation_sweep
        # finds unacknowledged CRITICALs by querying the alerts table. Storing
        # the row IS enrolling it.

    logger.info(
        "Alert routed: id=%s severity=%s (original=%s) channels=%s",
        alert.get("id"), severity, original_severity,
        _channels_for(severity),
    )


def is_outside_hours() -> bool:
    """
    Check if current Philippine time is outside business hours.
    Returns True if before 08:00 or at/after 21:00 PHT.
    """
    hour = datetime.now(tz=config.PHT).hour
    return hour < config.BUSINESS_START or hour >= config.BUSINESS_END


def escalate_one_tier(severity: str) -> str:
    """
    Promote severity one level for after-hours alerts.
    MEDIUM → HIGH, HIGH → CRITICAL.
    INFORMATIONAL, LOW, CRITICAL: unchanged (no double-escalation).
    """
    escalation = {
        "MEDIUM": "HIGH",
        "HIGH": "CRITICAL",
    }
    return escalation.get(severity, severity)


def _channels_for(severity: str) -> str:
    """Return a human-readable string of notification channels for logging."""
    channels = {
        "INFORMATIONAL": "dashboard",
        "LOW": "dashboard",
        "MEDIUM": "IT-Telegram(dedup)",
        "HIGH": "IT-Telegram+Email+Manager-Telegram",
        "CRITICAL": "IT-Telegram+Email+Manager-Telegram+Escalation",
    }
    return channels.get(severity, "unknown")
