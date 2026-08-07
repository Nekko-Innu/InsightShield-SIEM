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
