# web/blueprints/webhook.py
# /wazuh-webhook — the machine-to-machine ingest endpoint.
#
# The only CSRF-exempt route in the app (see web/csrf.py). It carries no
# browser session; an IP allowlist plus the X-Webhook-Token shared secret are
# what gate it.

import logging

from flask import Blueprint, jsonify, request

import config
import db
import rate_limit
import wazuh_receiver
from web.responses import rate_limited_response

logger = logging.getLogger("insightshield.web.webhook")

bp = Blueprint("webhook", __name__)


@bp.route("/wazuh-webhook", methods=["POST"])
def wazuh_webhook():
    """
    Receive Wazuh JSON payloads. Two independent gates, both required.

    This is the app's only unauthenticated write path, so a caller who gets
    through here can inject forged alerts, poison the alert history and the
    audit report, and fan out notifications to Telegram and email.

    1. IP allowlist. This existed but was void: with no ProxyFix, every request
       arriving through nginx looked like 127.0.0.1 — the first entry in the
       list — so the check passed for the entire internet. ProxyFix (see the
       app config block) restores it.
    2. Shared secret. X-Forwarded-For is client-supplied and forgeable, so the
       allowlist alone is not enough once we start trusting it. WAZUH_WEBHOOK_TOKEN
       is set in .env and sent by Wazuh's integrator script as one extra header.

    Gate 2 used to be skipped entirely when the token was unset, which left the
    forgeable allowlist as the only thing between the internet and a forged
    alert. It fails closed now: no token configured means no ingest. The startup
    check below makes that loud before the first payload arrives.
    """
    # Security: only accept from Wazuh Manager (same VM)
    allowed_ips = ["127.0.0.1", "::1", "192.168.100.30"]
    if request.remote_addr not in allowed_ips:
        logger.warning("Webhook rejected from unauthorized IP: %s", request.remote_addr)
        db.log_audit(
            action="WEBHOOK_AUTH_FAILED",
            actor="anonymous",
            target="wazuh-webhook",
            ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent", ""),
            details="reason=ip_not_allowlisted",
        )
        return jsonify({"error": "Unauthorized"}), 403

    import hmac as _hmac

    token = config.WAZUH_WEBHOOK_TOKEN
    # `not token` is load-bearing: compare_digest("", "") is True, so an unset
    # token would authenticate every anonymous POST instead of rejecting it.
    if not token or not _hmac.compare_digest(
        request.headers.get("X-Webhook-Token", ""), token
    ):
        logger.warning(
            "Webhook rejected: bad or missing X-Webhook-Token from %s",
            request.remote_addr,
        )
        db.log_audit(
            action="WEBHOOK_AUTH_FAILED",
            actor="anonymous",
            target="wazuh-webhook",
            ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent", ""),
            # Which gate failed matters: an allowlisted host with a bad token is
            # a misconfigured integrator or a compromised host, not a stranger.
            details="reason=bad_or_missing_token" if token else "reason=token_unset",
        )
        return jsonify({"error": "Unauthorized"}), 403

    # Wazuh sends one alert per POST. 120/min per source is ~2x the busiest
    # burst we have seen and still bounds a compromised-but-allowlisted host.
    allowed, retry_after = rate_limit.can_call(
        f"webhook:{request.remote_addr}", limit_per_min=120
    )
    if not allowed:
        return rate_limited_response(retry_after)

    # nginx caps bodies at 1m, but the E2E suite and any direct-to-Flask
    # deployment bypass nginx entirely.
    # Explicitly `is not None`: a chunked request reports None here, and the
    # truthiness test this used to be short-circuited straight past the cap.
    # app.config["MAX_CONTENT_LENGTH"] is the backstop that catches that case.
    if request.content_length is not None and request.content_length > 256_000:
        return jsonify({"error": "Payload too large"}), 413

    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({"error": "Invalid JSON"}), 400

    error = wazuh_receiver.validate_payload(payload)
    if error:
        logger.warning("Webhook validation failed: %s", error)
        return jsonify({"error": error}), 400

    alert_id = wazuh_receiver.process_alert(payload)
    if alert_id == -1:
        return jsonify({"status": "discarded", "reason": "low-level alert"}), 200
    if alert_id == -2:
        return jsonify({"error": "Alert processing failed — see error log"}), 500

    return jsonify({"status": "processed", "alert_id": alert_id}), 200
