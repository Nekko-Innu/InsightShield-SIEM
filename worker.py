# worker.py
# Insight Shield — the one process that owns APScheduler.
#
# Run by insightshield-worker.service:
#     /opt/insightshield/venv/bin/python worker.py
#
# Why a separate process rather than a flag on one of the gunicorn workers:
# every scheduled job here must run exactly once. gunicorn has no notion of a
# "first" worker, so the only ways to get exactly-once inside the web tier are
# workers=1 (which is what this whole change exists to undo) or a distributed
# lock with heartbeats and a story for the holder dying mid-job. A second
# systemd unit is exactly-once by definition and needs no coordination code.
#
# It shares the database with the web tier and nothing else. Web workers read
# what this writes — the agent-status snapshot, alert acknowledgements — through
# SQLite, so neither side needs to know the other is running.

import logging
import threading

import scheduler
# The module-level instance, not create_app(): importing app already built and
# bootstrapped one, and create_app() now returns a NEW application object every
# call, so calling it here would leave the worker holding two.
from app import app

logger = logging.getLogger("insightshield.worker")


def main() -> None:
    # Held for the process lifetime: jobs reach into Flask (render_template,
    # current_app) and would otherwise fail outside a request with a "working
    # outside of application context" error, on a schedule, in a log nobody
    # reads until something is already wrong.
    with app.app_context():
        scheduler.init_scheduler()
        logger.info("Worker running — scheduler owns this process")
        # BackgroundScheduler runs its own thread and returns immediately, so
        # without this the process would exit and systemd's Restart=always would
        # turn a clean exit into a crash loop that reads as "running".
        threading.Event().wait()


if __name__ == "__main__":
    main()
