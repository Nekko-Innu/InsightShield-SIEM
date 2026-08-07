# health_score.py
# Insight Shield — Daily Branch Security Score (0-100)
# Purpose : Calculate a security posture score based on alerts from the
#           last 24 hours. Deducts for alerts, rewards fast acknowledgment.
# Formula : Start at 100, deduct per severity, bonus for fast ACK.
# Used by : app.py dashboard GET routes, scheduler.py midnight reset.

import logging

import config
import db

logger = logging.getLogger("insightshield.health_score")


def calculate() -> int:
    """
    Compute the current health score (0-100).

    Formula:
    - Start at 100
    - For each alert in last 24h:
      - Subtract DEDUCT[severity]
    - For each HIGH/CRITICAL alert that was acknowledged:
      - If response_time_s <= 600 (10 min): add 5 bonus points
      - Elif response_time_s <= 1800 (30 min): add 2 bonus points
    - Clamp to range [0, 100]
    """
    alerts = db.get_alerts_last_24h()

    score = 100
    for alert in alerts:
        severity = alert.get("severity", "INFORMATIONAL")
        deduction = config.DEDUCT.get(severity, 0)
        score -= deduction

        # Bonus for fast acknowledgment of HIGH/CRITICAL
        if severity in ("HIGH", "CRITICAL") and alert.get("acknowledged"):
            resp_time = alert.get("response_time_s")
            if resp_time is not None:
                if resp_time <= 600:
                    score += config.BONUS["within_10min"]
                elif resp_time <= 1800:
                    score += config.BONUS["within_30min"]

    result = max(0, min(100, score))
    logger.info(
        "Health score calculated: %d (alerts_in_24h=%d)", result, len(alerts)
    )
    return result
