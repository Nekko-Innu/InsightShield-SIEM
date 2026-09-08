# scheduler.py
# Insight Shield — every recurring job in the system.
#
# Five jobs, all on a fixed schedule and all driven by the database rather than
# by in-process state:
#   escalation_sweep    every ESCALATION_INTERVAL_MIN — re-notify unacked CRITICALs
#   agent_status_poll   every 30s — refresh the Wazuh snapshot
#   midnight_health_reset  00:00 PHT
#   daily_db_backup        02:00 PHT
#   retention_purge        03:00 PHT
#
# EXACTLY ONE PROCESS MAY RUN THIS. In production that is
# insightshield-worker.service; the gunicorn workers do not call
# init_scheduler(). Two schedulers means two concurrent 02:00 backups of the
# same SQLite file, two retention purges, N Wazuh polls every 30s, and doubled
# escalation notifications.
#
# Used by : worker.py (production), app.create_app() when
#           INSIGHTSHIELD_RUN_SCHEDULER=1 (single-process dev convenience)

import logging
import os
from apscheduler.events import EVENT_JOB_ERROR
from apscheduler.schedulers.background import BackgroundScheduler

import config

logger = logging.getLogger("insightshield.scheduler")

_scheduler = None


def init_scheduler() -> None:
    """
    Create and start the BackgroundScheduler and register every job.
    Call once per deployment — see the module docstring.
    """
    global _scheduler
    if _scheduler is not None:
        return

    # Logged at startup so that if two processes ever do start a scheduler,
    # `journalctl -u insightshield -u insightshield-worker | grep "Scheduler
    # starting"` shows two PIDs instead of one and the duplication is obvious.
    logger.info("Scheduler starting in pid=%s", os.getpid())

    _scheduler = BackgroundScheduler(timezone="Asia/Manila")

    # Midnight health score reset — must use Asia/Manila timezone
    _scheduler.add_job(
        _midnight_reset,
        trigger="cron",
        hour=0,
        minute=0,
        id="midnight_health_reset",
        replace_existing=True,
    )

    # Daily SQLite hot-backup at 02:00 PHT (F7). Import lazily so scheduler.py
    # can still load on systems where the backup module is absent.
    try:
        from backup import run_daily_backup
        _scheduler.add_job(
            run_daily_backup,
            trigger="cron",
            hour=2,
            minute=0,
            id="daily_db_backup",
            replace_existing=True,
        )
    except Exception as e:
        logger.warning("Could not register daily backup job: %s", e)

    # Round 5: 30s agent-status poll. Refreshes the cached snapshot served
    # by /api/status and publishes an AGENT_STATUS event for SSE consumers.
    # next_run_time=now means the first refresh fires at scheduler start
    # so /api/status returns real data within ~1s of boot instead of the
    # initial "Status unavailable — checking…" red snapshot.
    try:
        import agent_status as _agent_status_mod
        from datetime import datetime as _dt
        _scheduler.add_job(
            _agent_status_mod.refresh,
            trigger="interval",
            seconds=30,
            id="agent_status_poll",
            replace_existing=True,
            next_run_time=_dt.now(),
            max_instances=1,
            coalesce=True,
        )
    except Exception as e:
        logger.warning("Could not register agent-status poller: %s", e)

    # Daily retention purge at 03:00 PHT — after the 02:00 backup, so the
    # backup still captures the pre-purge state. Nothing deleted a row before
    # this: audit_log grew on every mutating request, error_log on every
    # exception, and the backup copied the growing file every night.
    try:
        _scheduler.add_job(
            _retention_purge,
            trigger="cron",
            hour=3,
            minute=0,
            id="retention_purge",
            replace_existing=True,
        )
    except Exception as e:
        logger.warning("Could not register retention purge job: %s", e)

    # CRITICAL escalation. One sweep over the database, not one job per alert.
    try:
        _scheduler.add_job(
            _escalation_sweep,
            trigger="interval",
            minutes=config.ESCALATION_INTERVAL_MIN,
            id="escalation_sweep",
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
    except Exception as e:
        logger.warning("Could not register escalation sweep: %s", e)

    # Authorization-probe detection. Sweeps more often than the window is long,
    # so a campaign is caught while it is still running rather than after it.
    try:
        _scheduler.add_job(
            _authz_probe_sweep,
            trigger="interval",
            minutes=config.AUTHZ_PROBE_SWEEP_MIN,
            id="authz_probe_sweep",
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
    except Exception as e:
        logger.warning("Could not register authz probe sweep: %s", e)

    # IT-recommendation backfill. Ingest is fire-and-forget: a burst that outran
    # the reuse window, a provider outage, or a worker restart mid-generation all
    # leave it_recommendation NULL with nothing to retry it. This sweep is that
    # retry. Registered only when both the recommender and the interval are on,
    # so IT_REC_BACKFILL_MIN=0 is a complete kill switch.
    if config.IT_RECOMMENDER_ENABLED and config.IT_REC_BACKFILL_MIN > 0:
        try:
            _scheduler.add_job(
                _it_rec_backfill,
                trigger="interval",
                minutes=config.IT_REC_BACKFILL_MIN,
                id="it_rec_backfill",
                replace_existing=True,
                max_instances=1,
                coalesce=True,
            )
        except Exception as e:
            logger.warning("Could not register IT recommendation backfill: %s", e)

    # Job failures used to be invisible: only the escalation job wrapped itself,
    # so an exception in the backup or agent-status job surfaced in
    # APScheduler's own logger and never reached error_log or the Errors tab.
    _scheduler.add_listener(_on_job_error, EVENT_JOB_ERROR)

    _scheduler.start()
    logger.info(
        "Scheduler started: midnight reset + daily 02:00 backup + 03:00 "
        "retention purge registered (Asia/Manila timezone)"
    )


def _retention_purge() -> None:
    """Daily audit_log / error_log purge + WAL checkpoint."""
    import db

    db.purge_old_rows(
        audit_days=config.AUDIT_RETENTION_DAYS,
        error_days=config.ERROR_RETENTION_DAYS,
    )


def _on_job_error(event) -> None:
    """
    EVENT_JOB_ERROR listener: record any scheduled-job crash in error_log so it
    shows up in Settings -> Errors alongside request-path exceptions.
    """
    import traceback as _tb

    logger.error("Scheduled job %s raised: %s", event.job_id, event.exception)
    try:
        import db

        db.log_error(
            source="scheduler",
            module=str(event.job_id),
            exc_type=type(event.exception).__name__,
            message=str(event.exception),
            path=None,
            actor=None,
            traceback="".join(
                _tb.format_exception(
                    type(event.exception), event.exception, event.exception.__traceback__
                )
            ),
        )
    except Exception:
        # Never let the error reporter raise inside the scheduler's own
        # listener — that would take the scheduler thread down.
        logger.exception("Failed to record scheduled-job error for %s", event.job_id)


def _authz_probe_sweep() -> None:
    """Turn a run of authorization failures from one source into an alert.

    Twenty-five denied requests from one IP in an hour is a campaign, not a
    typo. The audit that prompted this issued roughly two hundred hostile
    requests — role-denied routes, forged CSRF tokens, webhook auth failures —
    and every one of them produced a log line and nothing else, so the operator
    had no way to know it was happening.

    A sweep rather than a check at each rejection site, for the same reason
    _escalation_sweep is a sweep: the counting belongs in the database, where
    every worker process can see it, not in the memory of whichever worker
    happened to serve the request that crossed the threshold.

    Dedupe lives in alert_router.dispatch_internal_alert, so a campaign that
    keeps running produces one alert per window, not one per sweep.
    """
    import alert_router
    import db

    sources = db.probe_sources_in_window(
        since_minutes=config.AUTHZ_PROBE_WINDOW_MIN,
        min_count=config.AUTHZ_PROBE_LIMIT,
    )
    if not sources:
        return

    logger.warning("AUTHZ PROBE: %d source(s) over threshold", len(sources))
    for ip, count in sources:
        try:
            alert_router.dispatch_internal_alert(
                attack_type="authorization_probe",
                rule_id="ISH-AZP-001",
                source_ip=ip,
                plain_text=(
                    f"{count} authorization failures from {ip} in "
                    f"{config.AUTHZ_PROBE_WINDOW_MIN} min — denied roles, rejected "
                    f"CSRF tokens and webhook auth failures combined. Consistent "
                    f"with someone mapping what this account can reach."
                ),
                evidence={"count": count,
                          "window_min": config.AUTHZ_PROBE_WINDOW_MIN},
                dedupe_minutes=config.AUTHZ_PROBE_WINDOW_MIN,
            )
        except Exception as e:
            # One bad source must not abandon the rest of the sweep.
            logger.error("Authz probe alert failed for ip=%s: %s", ip, e)


def _it_rec_backfill() -> None:
    """Fill in IT recommendations that ingest left blank.

    Runs in insightshield-worker, which owns the scheduler, so it never competes
    with a live webhook for the web workers' _ITREC_SEMAPHORE — and a slow
    provider here delays nothing a browser is waiting on.

    Same two-step order as ingest: reuse a sibling first, spend a call only if
    there is nothing to copy. IT_REC_BACKFILL_BATCH per sweep on purpose — this
    drains a backlog slowly inside the free tier rather than replaying a burst at
    full speed, and _ai_chain's per-provider rate limiter is still the hard
    ceiling underneath.
    """
    import db
    import it_recommender
    import wazuh_receiver

    alerts = db.get_alerts_missing_it_recommendation(
        max_age_hours=24, limit=config.IT_REC_BACKFILL_BATCH,
    )
    if not alerts:
        return

    logger.info("IT rec backfill: %d alert(s) without recommendations", len(alerts))
    for alert in alerts:
        alert_id = alert["id"]
        rule_id = str(alert.get("rule_id") or "")
        device_name = alert.get("device_name") or ""
        try:
            if wazuh_receiver._reuse_sibling_recommendation(
                alert_id, rule_id, device_name
            ):
                continue
            text, provider = it_recommender.recommend(
                rule_id, alert.get("raw_alert") or "", device_name
            )
            if provider == config.AI_CHAIN_EXHAUSTED:
                # Leave the row NULL rather than writing the sentinel: the next
                # sweep should try again once the negative cache expires, and
                # a stored sentinel would make this alert invisible to the very
                # query that found it.
                logger.warning(
                    "IT rec backfill: chain exhausted (alert_id=%s), leaving blank",
                    alert_id,
                )
                continue
            db.update_it_recommendation(alert_id, text, provider_used=provider)
            logger.info(
                "IT rec backfill: filled alert_id=%s provider=%s", alert_id, provider,
            )
        except Exception as e:
            # One bad alert must not abort the rest of the batch.
            logger.warning("IT rec backfill failed (alert_id=%s): %s", alert_id, e)


def _escalation_sweep() -> None:
    """Re-notify every CRITICAL alert still sitting unacknowledged.

    Replaces one interval job per alert plus an {alert_id: job_id} index. That
    design put the escalation state in the memory of whichever process handled
    the webhook — so moving the scheduler into its own service would have made
    register_escalation a no-op in the web workers and stopped CRITICAL
    escalation dead, with nothing but a log line to say so. It also meant a
    restart silently cancelled every pending escalation.

    The database already knew which alerts were unacknowledged. Asking it is
    both less code and the only version that works with more than one process.

    Trade-off: escalation now fires on a global cadence rather than on each
    alert's own anniversary, so the first repeat lands between
    ESCALATION_INTERVAL_MIN and 2x that after ingest.
    """
    import db
    import notifier
    import rate_limit

    alerts = db.get_unacked_critical_alerts(
        min_age_minutes=config.ESCALATION_INTERVAL_MIN,
        max_age_hours=config.ESCALATION_MAX_AGE_H,
    )
    if not alerts:
        return

    logger.warning("ESCALATION: %d unacknowledged CRITICAL alert(s)", len(alerts))
    for alert in alerts:
        try:
            notifier.send_telegram(alert)
            notifier.send_email(alert)
            # Nudge the manager ONCE per alert (the manager channel is low-noise
            # by design — not the per-sweep repeat IT gets). limit_per_min=1 over
            # the whole escalation lifetime means the first sweep to see this
            # unacked CRITICAL notifies the manager; later sweeps are denied.
            allowed, _ = rate_limit.can_call(
                f"mgr-escal:{alert.get('id')}", limit_per_min=1,
                window_seconds=config.ESCALATION_MAX_AGE_H * 3600,
            )
            if allowed:
                notifier.send_manager_escalation(alert)
        except Exception as e:
            # One bad alert must not abandon the rest of the sweep. The
            # EVENT_JOB_ERROR listener only sees an exception that escapes the
            # whole job, so record this one here.
            logger.error("Escalation failed for alert_id=%s: %s", alert.get("id"), e)
            import traceback as _tb
            db.log_error(
                source="scheduler", module="scheduler._escalation_sweep",
                exc_type=type(e).__name__, message=str(e),
                traceback=_tb.format_exc(),
            )


def _midnight_reset() -> None:
    """
    Called at midnight PHT. The health score naturally resets because
    the 24-hour window moves forward. This job just logs the event.
    """
    logger.info("Midnight health score reset triggered (24h window moved forward)")


def shutdown() -> None:
    """Gracefully shut down the scheduler."""
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
        logger.info("Scheduler shut down")
