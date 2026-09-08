# wazuh_receiver.py
# Insight Shield — Wazuh Webhook Receiver + Alert Pipeline Orchestrator
# Purpose : ONLY entry point for external data. Validates Wazuh JSON payloads,
#           maps rule_level to severity, orchestrates the full alert pipeline:
#           translate → validate → store → route → notify.
# Used by : Flask route POST /wazuh-webhook (in app.py).

import json
import logging
import re
import threading
from datetime import datetime, timedelta

import config
import db
import groq_translator
import it_recommender
import alert_router
import validator

logger = logging.getLogger("insightshield.wazuh_receiver")

# Bounds how many IT-recommendation chain calls run at once. Each alert kicks a
# fire-and-forget daemon thread, so a burst of criticals would otherwise fan out
# many concurrent provider calls that race past the per-minute rate window (the
# limiter's check-then-insert overshoot is bounded by concurrency). Serialising
# them (default 1) is free — recommendations are off any request's critical path.
_ITREC_SEMAPHORE = threading.BoundedSemaphore(config.IT_RECOMMENDER_MAX_CONCURRENCY)

# ── Severity Level Mapping ───────────────────────────────────────────────────
# Maps Wazuh integer rule_level to Insight Shield severity string.
# Uses .get() with default — never direct dict access.

# Moved to alerts_util (the leaf) so build_severity_array can read it without
# importing this module, which imports db, which imports alerts_util. Re-bound
# here because callers and tests say wazuh_receiver.LEVEL_MAP.
from alerts_util import LEVEL_MAP


def map_level_to_severity(rule_level: int) -> str | None:
    """
    Map Wazuh integer rule_level to Insight Shield severity string.
    Returns None for levels 0-1 (discard silently).
    Levels > 15 are treated as CRITICAL with a warning log.
    """
    if rule_level <= 1:
        return None  # Discard silently
    if rule_level > 15:
        logger.warning("Unexpected rule_level=%d, treating as CRITICAL", rule_level)
        return "CRITICAL"
    return LEVEL_MAP.get(rule_level, "INFORMATIONAL")


def validate_payload(payload: dict) -> str | None:
    """
    Validate incoming Wazuh webhook JSON.
    Returns error message string if invalid, None if valid.
    Required fields: rule_id, rule_level (or severity), device_name, timestamp.
    """
    required = ["rule_id", "device_name"]
    for field in required:
        if field not in payload:
            return f"Missing required field: {field}"

    # Presence was the only check here. Both fields land in the alerts table
    # and then on the dashboard, in the audit report, and in Telegram/email
    # bodies, so an unauthenticated-until-recently path could push a megabyte
    # of anything through as a device name.
    if not isinstance(payload["rule_id"], (str, int)) or len(str(payload["rule_id"])) > 32:
        return "Invalid rule_id: expected a string or integer of at most 32 characters"
    if not isinstance(payload["device_name"], str) or not 0 < len(payload["device_name"]) <= 128:
        return "Invalid device_name: expected a string of 1-128 characters"

    # Must have either rule_level or severity
    if "rule_level" not in payload and "severity" not in payload:
        return "Missing required field: rule_level or severity"

    if "rule_level" in payload:
        try:
            int(payload["rule_level"])
        except (TypeError, ValueError):
            return "Invalid rule_level: expected an integer"

    # severity was taken verbatim while its two neighbours were bounded, and it
    # is not a display string: alert_router dispatches on exact equality, so
    # lower-case "critical" matched no branch and produced an alert that was
    # stored and shown but notified nobody, while an inflated "CRITICAL" forced
    # the full HIGH fan-out plus escalation enrolment. A dict reached
    # conn.execute and 500'd the request.
    if "severity" in payload:
        severity = payload["severity"]
        if not isinstance(severity, str):
            return "Invalid severity: expected a string"
        if severity.upper() not in config.SEVERITY_LEVELS:
            return ("Invalid severity: expected one of "
                    + ", ".join(config.SEVERITY_LEVELS))
        payload["severity"] = severity.upper()

    # attack_type and description reach the dashboard, the notification bodies
    # and the AI prompt. Same treatment as device_name.
    for field, limit in (("attack_type", 64), ("description", 512)):
        if field in payload:
            if not isinstance(payload[field], str):
                return f"Invalid {field}: expected a string"
            if len(payload[field]) > limit:
                return f"Invalid {field}: at most {limit} characters"

    # Timestamp: use provided or generate.
    #
    # It used to be accepted verbatim whenever present, and it is not a label —
    # it is the ordering key and the predicate for the escalation sweep, the
    # 24h breakdown, the health score and paging. A CRITICAL alert stamped
    # 1970-01-01 fired its ingest notification and then sat permanently outside
    # get_unacked_critical_alerts' lower bound, never escalating and never
    # appearing in the 24h view; a far-future one pinned itself to page 1 and
    # poisoned the mean-time-to-acknowledge with a negative response time.
    supplied = payload.get("timestamp")
    if supplied is None:
        payload["timestamp"] = datetime.now(tz=config.PHT).isoformat()
    else:
        if not isinstance(supplied, str):
            return "Invalid timestamp: expected an ISO 8601 string"
        try:
            parsed = datetime.fromisoformat(supplied)
        except ValueError:
            return "Invalid timestamp: expected an ISO 8601 string"
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=config.PHT)
        now = datetime.now(tz=config.PHT)
        # Deliberately generous backwards: a manager that was down, or a queue
        # that backed up, legitimately replays alerts hours or days late, and
        # dropping those would lose real evidence to a clock check. Forward is
        # tight, because there is no legitimate reason to report the future and
        # a far-future stamp pins the row to page 1 permanently and drives
        # response_time_s negative, poisoning the mean-time-to-acknowledge.
        #
        # ponytail: this bounds the absurd cases (1970, 2099), not ordering
        # games inside the window — a backdate of 25 hours still lands outside
        # the escalation sweep's own ESCALATION_MAX_AGE_H bound. Fixing that
        # properly means storing an ingest time alongside the reported one and
        # sweeping on it; upgrade there if backdating inside the window ever
        # matters.
        if not (now - timedelta(days=7)) <= parsed <= (now + timedelta(minutes=5)):
            return ("Invalid timestamp: must be a recent ISO 8601 time, "
                    "not in the future")
        payload["timestamp"] = parsed.isoformat()

    return None


def _extract_attack_trail(payload: dict) -> str | None:
    """
    Build the forensic Attack Trail JSON string from a Wazuh payload.

    Surfaces the full set of fields the Alert Detail viewer
    (Tree / Table / Raw JSON / Forensic Summary) renders: agent
    identity, rule context (id/level/firedtimes/frequency/groups/
    description/mail), decoder, location, manager, full_log,
    wazuh_alert_id, and the complete `data` block (including
    technique-specific nested sub-blocks like data.arp, data.syscheck).

    Every extraction is `.get()`-guarded, so payloads missing a field
    simply omit it from the curated trail — the Tree tab's
    `or "—"` fallbacks then render sparse fields as an em-dash.

    Returns a JSON string ready for direct INSERT, or None if the
    payload contains nothing meaningful to trail.
    """
    trail: dict = {}

    # ── Agent identity (Wazuh agent block) ──────────────────────────
    if isinstance(payload.get("agent"), dict):
        trail["agent"] = {
            "id":   payload["agent"].get("id"),
            "name": payload["agent"].get("name"),
            "ip":   payload["agent"].get("ip"),
        }

    # ── Manager identity — tells the evaluator which Wazuh manager
    #    emitted the alert (useful when a branch has multiple). ─────
    if isinstance(payload.get("manager"), dict):
        name = payload["manager"].get("name")
        if name:
            trail["manager"] = {"name": name}

    # ── Rule context — the richest curated block. Exposes firedtimes
    #    / frequency so the evaluator sees whether this is a spike,
    #    and `groups` so MITRE-adjacent tagging is visible. ─────────
    rule_block = payload.get("rule") or {}
    if isinstance(rule_block, dict):
        rule_out: dict = {}
        for key in ("id", "level", "firedtimes", "frequency",
                    "description", "mail", "groups", "mitre"):
            if key in rule_block and rule_block[key] is not None:
                rule_out[key] = rule_block[key]
        if rule_out:
            trail["rule"] = rule_out
        # Legacy keys some templates read directly.
        if "level" in rule_block:
            trail["rule_level"] = rule_block["level"]
        if "description" in rule_block:
            trail["rule_description"] = rule_block["description"]

    # ── Decoder + location — evaluator asks "where was this read
    #    from?" (e.g., Sysmon channel vs iptables log). ─────────────
    decoder = payload.get("decoder")
    if isinstance(decoder, dict):
        dname = decoder.get("name")
        if dname:
            trail["decoder"] = {"name": dname}
    elif isinstance(decoder, str) and decoder:
        trail["decoder"] = {"name": decoder}

    if payload.get("location"):
        trail["location"] = payload["location"]

    # ── input.type (log, command, journald, …) ──────────────────────
    if isinstance(payload.get("input"), dict):
        itype = payload["input"].get("type")
        if itype:
            trail["input"] = {"type": itype}

    # ── Wazuh-assigned alert id (top-level `id` string) ─────────────
    wid = payload.get("id")
    if wid is not None:
        trail["wazuh_alert_id"] = str(wid)

    # ── Full log — the raw line Wazuh's decoder ingested. This is
    #    where the mimikatz command line / hydra output / iptables
    #    line lives. Cap the stored length so a runaway log doesn't
    #    bloat the attack_trail column. ──────────────────────────────
    full_log = payload.get("full_log")
    if isinstance(full_log, str) and full_log:
        trail["full_log"] = full_log[:4096]

    # ── Full data block — Sysmon eventdata, syscheck FIM, arp cache,
    #    iptables fields, etc. Copied wholesale so technique-specific
    #    sub-blocks (data.arp, data.syscheck) survive intact. ───────
    data_block = payload.get("data") or {}
    if isinstance(data_block, dict) and data_block:
        trail["data"] = data_block

    if not trail:
        return None
    return json.dumps(trail, ensure_ascii=False, default=str)


def process_alert(payload: dict) -> int:
    """
    Orchestrate the full alert pipeline: translate → store → route.
    Called by the real Wazuh webhook handler in app.py.

    Parameters
    ----------
    payload : dict
        Validated alert payload. Must contain:
        rule_id, severity (or rule_level), device_name, timestamp.
        May contain: description, attack_type, data.

    Returns
    -------
    int — the alert ID from the database.
    """
    rule_id = str(payload["rule_id"])
    device_name = payload["device_name"]
    description = payload.get("description", f"Wazuh alert rule_id={rule_id}")

    # Determine severity
    if "severity" in payload:
        severity = payload["severity"]
    else:
        severity = map_level_to_severity(int(payload["rule_level"]))
        if severity is None:
            logger.debug("Discarding low-level alert: rule_id=%s level=%s",
                         rule_id, payload["rule_level"])
            return -1

    # Determine attack type
    attack_type = payload.get("attack_type") or _infer_attack_type(rule_id)
    # Unmapped Wazuh rules have no STRIDE tag, and used to display the bare word
    # "Unknown". The integrator already sends the real Wazuh rule description as
    # `description` (custom-insightshield.py), so show that instead — e.g.
    # "Netstat listened ports status changed" beats "Unknown". Capped at the
    # attack_type column's 64 chars. Skipped when description is the integrator's
    # own "Wazuh rule <id>" placeholder (no rule description was available), since
    # that just repeats the rule id already shown next to it.
    if attack_type == "Unknown":
        desc = (payload.get("description") or "").strip()
        if desc and not desc.startswith(f"Wazuh rule {rule_id}"):
            attack_type = desc[:64]

    logger.info(
        "Processing alert: rule_id=%s severity=%s device=%s",
        rule_id, severity, device_name,
    )

    # Steps 1-3: translate, grade, store. These are the core pipeline steps —
    # a failure here (AI provider outage, DB lock) must not crash the webhook
    # with a raw 500; log it to error_log and signal the caller with -2 so
    # app.py's /wazuh-webhook route can return a clean 5xx JSON response.
    # AI is reserved for the severities that matter — free-tier providers can't
    # absorb a translation (plus an IT recommendation) on every INFORMATIONAL/
    # LOW/MEDIUM alert. Below the gate, the manager translation uses the static
    # template and the IT recommender does not run at all.
    ai_ok = config.ai_enabled_for(severity)

    try:
        # Step 1: AI translation (manager-facing), or static template when the
        # severity is below the AI gate.
        plain_text, provider_used, ai_reasoning = groq_translator.translate(
            rule_id, description, device_name, use_ai=ai_ok
        )

        # Step 2: Compute FK grade (log only — never reject)
        fk_grade = validator.compute_fk_grade(plain_text)

        # Step 3: Store in database. Compute raw_alert_str once so the IT-rec
        # worker thread can reuse the same JSON string without re-serialising.
        raw_alert_str = json.dumps(payload)
        alert_id = db.store_alert({
            "timestamp": payload.get("timestamp", datetime.now(tz=config.PHT).isoformat()),
            "rule_id": rule_id,
            "attack_type": attack_type,
            "severity": severity,
            "device_name": device_name,
            "raw_alert": raw_alert_str,
            "plain_text": plain_text,
            "ai_reasoning": ai_reasoning,
            "provider_used": provider_used,
            "fk_grade": fk_grade,
            "attack_trail": _extract_attack_trail(payload),
        })
    except Exception as e:
        import traceback as _tb
        logger.error("process_alert core pipeline failed (rule_id=%s): %s", rule_id, e)
        db.log_error(
            source="server", module="wazuh_receiver.process_alert",
            exc_type=type(e).__name__, message=str(e),
            path="/wazuh-webhook", traceback=_tb.format_exc(),
        )
        return -2

    # Step 3b: Auto-close sub-HIGH alerts. MEDIUM/LOW/INFORMATIONAL need no IT
    # ack or resolve (config.requires_ack), so they are closed here as a system
    # action instead of sitting "Open / Pending" forever and inflating the
    # open-alerts KPI. HIGH/CRITICAL keep the human ack -> resolve lifecycle.
    if not config.requires_ack(severity):
        db.auto_close_alert(alert_id)

    # Step 3a used to render the alert's table row and fan it out to in-process
    # SSE subscriber queues. Both jobs moved into /api/events/stream, which
    # notices the new row by polling the database: it works across gunicorn
    # workers, it costs nothing when no browser is watching, and it removed this
    # module's only reason to import back into app.py.

    # Step 4: Kick fire-and-forget IT recommendation worker. Webhook returns
    # 200 OK before the second AI call completes; the worker writes back to
    # alerts.it_recommendation when it's done. daemon=True so the thread
    # doesn't block process exit on gunicorn worker shutdown.
    #
    # Gated twice: only for AI-eligible severities (HIGH/CRITICAL) and only when
    # IT_RECOMMENDER_ENABLED is set. Off by default — it is a second AI call per
    # alert and the free tier can't afford it on top of the translation. The
    # alert detail page renders its static fallback line when it never ran.
    if ai_ok and config.IT_RECOMMENDER_ENABLED:
        threading.Thread(
            target=_kick_it_recommendation,
            args=(alert_id, raw_alert_str, device_name, rule_id),
            daemon=True,
            name=f"itrec-{alert_id}",
        ).start()
    else:
        logger.debug(
            "IT recommendation skipped (alert_id=%s ai_ok=%s enabled=%s)",
            alert_id, ai_ok, config.IT_RECOMMENDER_ENABLED,
        )

    # Step 5: Route to notification channels
    try:
        alert_data = db.get_alert(alert_id)
        alert_router.route_alert(severity, alert_data)
    except Exception as e:
        logger.error("Notification routing failed for alert_id=%s: %s", alert_id, e)

    logger.info(
        "Alert processed: id=%s provider=%s fk=%.1f severity=%s",
        alert_id, provider_used, fk_grade, severity,
    )
    return alert_id


def _kick_it_recommendation(
    alert_id: int,
    raw_alert_json: str,
    device_name: str,
    rule_id: str,
) -> None:
    """
    Worker thread body. Generates the IT-only "Recommended Investigation
    Steps" via a second AI call, then persists to alerts.it_recommendation.

    Never raises — errors only surface in logs because the webhook handler
    has already returned 200 OK by the time this runs. Round 4's SSE will
    surface a "rec failed, click to retry" UI for the silent-error case.
    """
    # Bracketed by a start and a terminal line. This is a daemon thread, so a
    # worker shutdown kills it outright — no exception, no finally, nothing to
    # log from. Previously that left it_recommendation NULL with no record that
    # it had ever been attempted, indistinguishable from an alert nobody asked
    # about. A start line with no matching "complete" or "failed" is now the
    # signal that the process went away mid-generation.
    logger.info("IT recommendation start (alert_id=%s)", alert_id)

    # Burst reuse, BEFORE the semaphore. The ai_cache cannot help here: the
    # recommendation prompt embeds the whole raw alert, so every repeat hashes
    # to a new key and runs a full chain. Ten identical criticals therefore
    # queued on a semaphore of 1, and everything past the third timed out into
    # "recommender busy" with a permanently NULL recommendation.
    #
    # Same rule, same device, minutes apart is the same investigation, so copy
    # the sibling's steps instead of buying them again. Ahead of the acquire so
    # a burst never occupies the slot at all — which is what turned a 30s wait
    # into a blank card.
    if _reuse_sibling_recommendation(alert_id, rule_id, device_name):
        return

    # Serialise the actual chain call so a burst of criticals doesn't launch
    # many concurrent provider requests at once (see _ITREC_SEMAPHORE). Bounded
    # wait: if the slot doesn't free within the window, skip rather than pile up
    # threads — scheduler._it_rec_backfill picks up whatever was skipped.
    acquired = _ITREC_SEMAPHORE.acquire(timeout=config.AI_CHAIN_BUDGET_S + 5.0)
    if not acquired:
        logger.warning("IT recommendation skipped (alert_id=%s): recommender busy", alert_id)
        return
    try:
        text, provider = it_recommender.recommend(rule_id, raw_alert_json, device_name)
        db.update_it_recommendation(alert_id, text, provider_used=provider)
        logger.info("IT recommendation complete (alert_id=%s provider=%s)",
                    alert_id, provider)
    except Exception as e:
        logger.error(
            "IT recommendation failed (alert_id=%s): %s",
            alert_id, e,
        )
    finally:
        _ITREC_SEMAPHORE.release()


def _reuse_sibling_recommendation(
    alert_id: int,
    rule_id: str,
    device_name: str,
) -> bool:
    """
    Copy a recent recommendation from the same rule + device onto this alert.

    Returns True when one was found and stored, False to fall through to a real
    AI call. Shared by the ingest worker thread and scheduler._it_rec_backfill,
    so both spend quota under the same rule.

    The copied text was deobfuscated through the SOURCE alert's map, so it names
    that alert's identifiers. Same rule on the same machine makes that
    near-identical; a different attacker IP is the case where it would not be,
    which is why the stored text carries a provenance line naming the source
    alert instead of passing itself off as freshly written. (alerts.provider_used
    holds the manager translation's provider and is not ours to overwrite; the
    provenance has to live in the text.)
    """
    try:
        sibling = db.get_recent_it_recommendation(
            rule_id, device_name, config.IT_REC_REUSE_WINDOW_MIN
        )
    except Exception as e:
        logger.warning("sibling lookup failed (alert_id=%s): %s", alert_id, e)
        return False
    if not sibling:
        return False

    source_id, text = sibling
    # Idempotent under the backfill sweep: strip any provenance line the source
    # itself carried, so a chain of reuses never stacks headers.
    body = _REUSE_HEADER_RE.sub("", text, count=1).lstrip()
    stamped = (
        f"(Reused from alert #{source_id} — same rule on the same device within "
        f"{config.IT_REC_REUSE_WINDOW_MIN} minutes.)\n\n{body}"
    )
    db.update_it_recommendation(
        alert_id, stamped, provider_used=f"reused:#{source_id}"
    )
    logger.info(
        "IT recommendation reused (alert_id=%s source=%s rule_id=%s device=%s)",
        alert_id, source_id, rule_id, device_name,
    )
    return True


# Matches the provenance line written above, so reuse-of-a-reuse replaces the
# header rather than nesting one inside another.
_REUSE_HEADER_RE = re.compile(r"^\(Reused from alert #\d+[^)]*\)\s*", re.DOTALL)


def _infer_attack_type(rule_id: str) -> str:
    """Infer STRIDE-tagged attack type from rule_id using the Wazuh rule mapping."""
    rule_map = {
        "87701": "[I] LSASS Credential Dump",
        "87702": "[I] LSASS Credential Dump",
        "87710": "[I] LSASS Credential Dump",
        "60122": "[S] RDP Brute-force",
        "60204": "[S] RDP Brute-force",
        "60106": "[S] RDP Brute-force",
        "31151": "[D] SYN-flood",
        "31152": "[D] SYN-flood",
        "31153": "[D] SYN-flood",
        "5402":  "[T] ARP-MitM",
        "5403":  "[T] ARP-MitM",
        "5404":  "[T] ARP-MitM",
        "100044": "[T/D] Ransomware",
        "100045": "[T/D] Ransomware",
        "100046": "[T/D] Ransomware",
        "554":   "[T/D] Ransomware",  # Wazuh syscheck FIM baseline rule
        "550":   "[T/D] Ransomware",
    }
    # Also check custom rule ranges (100001-100049)
    rid = int(rule_id) if rule_id.isdigit() else 0
    if 100001 <= rid <= 100009:
        return "[S] RDP Brute-force"
    if 100010 <= rid <= 100019:
        return "[I] LSASS Credential Dump"
    if 100020 <= rid <= 100029:
        return "[T/D] Ransomware"
    if 100030 <= rid <= 100039:
        return "[T] ARP-MitM"
    if 100040 <= rid <= 100043:
        return "[D] SYN-flood"
    if 100044 <= rid <= 100049:
        return "[T/D] Ransomware"

    return rule_map.get(rule_id, "Unknown")
