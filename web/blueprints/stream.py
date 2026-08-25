# web/blueprints/stream.py
# The Server-Sent Events stream behind the IT dashboard's live updates.

import json as _json
import logging
import threading

from flask import Blueprint, Response, jsonify, render_template
from flask_login import current_user, login_required

import agent_status as agent_status_mod
import config
import db
from alerts_util import build_severity_array, derive_attacker_ip
from decorators import role_required

logger = logging.getLogger("insightshield.web.stream")

bp = Blueprint("stream", __name__)


# Each open stream holds one of gunicorn's 16 threads for as long as the tab
# stays open, so an authenticated user with a loop could starve the whole app.
# A sliding-window rate limit does not help here — the cost is concurrency,
# not request frequency — so this counts live streams per user instead.
#
# Deliberately NOT moved to SQLite with the rest of the shared state: a DB-backed
# connection count needs heartbeats and a reaper, and a SIGKILLed worker would
# leak a count that locks a user out of their own dashboard until someone edits
# the table. So the cap is PER WORKER — the real ceiling a user can reach is
# workers x SSE_MAX_PER_USER, which is 9 of the 48 available threads at
# workers=3. The pool, not this number, is the actual bound.
_sse_conns = {}
_sse_lock = threading.Lock()
SSE_MAX_PER_USER = 3  # three browser tabs is normal use; a script is not

# How often an open stream checks the database for new alerts. 2s is the
# latency a user perceives as "live" and costs one two-probe query per stream
# per tick — cheaper than the 1s queue wakeup this replaced.
SSE_POLL_SECONDS = 2.0

# A stream authenticates once, at connect, and then runs a `while True` for as
# long as the socket holds. Nothing inside it re-checks the session, so an open
# IT dashboard kept receiving live alert rows long after its session had idled
# out — the one hole left by making polling stop refreshing the cookie. Ending
# the generator after one session lifetime bounds that: the browser's
# EventSource reconnects by itself, and the reconnect is a fresh, gated request
# that either gets a new stream or a redirect to /login.
SSE_MAX_STREAM_SECONDS = config.PERMANENT_SESSION_LIFETIME_MIN * 60

@bp.route("/api/events/stream")
@login_required
@role_required("IT_ADMIN")
def api_events_stream():
    """
    Server-Sent Events for the IT-admin dashboard's live updates. IT_ADMIN-only.
    Returns text/event-stream. A comment line on every poll tick keeps the
    connection alive through nginx's idle timeout and, more importantly, is
    what makes a closed tab's stream notice and release its slot.

    The stream polls the database for a watermark rather than subscribing to an
    in-process queue. The queue registry only existed inside one Python process,
    so a browser attached to worker A never saw an alert ingested by worker B —
    silently, with no error anywhere. The database is the one thing every worker
    shares, so it is what the stream reads.

    Wire protocol is unchanged (event names, payload shapes), so sse.js and
    dashboard-it-realtime.js need no changes.
    """
    import time as _time
    import random as _random
    from flask import stream_with_context

    username = current_user.username
    # Snapshotted at connect so the generator can notice a revocation later.
    # The generator authenticates exactly once, when the response is created;
    # Flask-Login's user_loader never runs again for an open response body, so
    # without this the stream outlived logout by up to SSE_MAX_STREAM_SECONDS.
    opened_epoch = (db.get_user(username) or {}).get("session_epoch", 0)
    with _sse_lock:
        if _sse_conns.get(username, 0) >= SSE_MAX_PER_USER:
            return jsonify({"error": "too_many_streams"}), 429

    @stream_with_context
    def generator():
        # Counted here rather than above so the decrement is guaranteed by the
        # same frame's finally.
        # ponytail: check-then-increment is not atomic across the Response
        # boundary, so a burst of simultaneous opens can briefly exceed the cap
        # by the number of racing threads. Ceiling: 16, the thread count, which
        # is the bound the cap exists to enforce anyway. Upgrade: only if
        # `threads` is ever raised well above 16 — then the overshoot stops
        # being self-limiting and the check-and-increment needs to move under
        # _sse_lock as one critical section.
        with _sse_lock:
            _sse_conns[username] = _sse_conns.get(username, 0) + 1
        try:
            # Initial comment lets the client confirm the stream opened.
            yield ": connected\n\n"
            status_key = agent_status_mod.SNAPSHOT_KEY
            last_id, last_status_ts = db.get_stream_watermark(status_key)
            hard_deadline = _time.monotonic() + SSE_MAX_STREAM_SECONDS

            while _time.monotonic() < hard_deadline:
                # Jitter keeps a poolful of streams from phase-locking into a
                # query herd every SSE_POLL_SECONDS.
                _time.sleep(SSE_POLL_SECONDS + _random.uniform(0, 0.5))

                # Revocation check, once per tick. bump_session_epoch (logout,
                # and password change through the hash) invalidates COOKIES,
                # and load_user only runs on a new request — an already-open
                # response body is never revisited. So an attacker on a
                # hijacked session could open this stream, go quiet, and keep
                # receiving every rendered alert row for the full 30 minutes
                # AFTER the victim logged out, defeating the exact primitive
                # session_epoch exists to provide. One extra indexed read per
                # tick, on a loop that is already querying.
                current = db.get_user(username)
                if not current or current.get("session_epoch", 0) != opened_epoch:
                    logger.info(
                        "SSE closed for %s: session revoked mid-stream", username
                    )
                    return

                latest_id, status_ts = db.get_stream_watermark(status_key)

                if latest_id > last_id:
                    for alert in db.get_alerts_since(last_id):
                        # Rendered here, not by the producer: the webhook used
                        # to build this HTML on every ingest whether or not
                        # anyone was watching, and had to reach back into app.py
                        # to do it.
                        row_html = render_template(
                            "_alert_row.html",
                            a=alert,
                            derive_attacker_ip=derive_attacker_ip,
                        )
                        payload = {
                            "id": alert["id"],
                            "severity": alert["severity"],
                            "row_html": row_html,
                        }
                        yield f"event: new_alert\ndata: {_json.dumps(payload)}\n\n"
                        # Advance inside the loop so a burst larger than the
                        # fetch limit resumes correctly on the next tick.
                        last_id = alert["id"]

                    breakdown = build_severity_array(db.get_severity_breakdown(hours=24))
                    yield (f"event: severity_update\n"
                           f"data: {_json.dumps({'breakdown': breakdown})}\n\n")

                if status_ts != last_status_ts:
                    last_status_ts = status_ts
                    snapshot = agent_status_mod.get_snapshot()
                    yield f"event: agent_status\ndata: {_json.dumps(snapshot)}\n\n"

                # A comment line every tick, not a heartbeat every 30s. Clients
                # ignore it, but the *write* is what raises once the tab is
                # gone: without it a stream whose browser has closed keeps
                # sleeping, holding a slot against SSE_MAX_PER_USER and a
                # thread against `threads = 16`, for up to a full heartbeat
                # interval. Reloading the dashboard three times used to cost a
                # user their live updates for 30s. Three bytes per stream per
                # 2s is nothing next to the 48-thread ceiling it protects, and
                # it still defeats nginx's proxy_read_timeout.
                yield ": \n\n"
        except (GeneratorExit, ConnectionError):
            # Client disconnected — the finally below still runs. ConnectionError
            # covers BrokenPipeError (Linux), ConnectionAbortedError (Windows)
            # and ConnectionResetError, all of which the per-tick write can raise.
            return
        finally:
            with _sse_lock:
                remaining = _sse_conns.get(username, 1) - 1
                if remaining > 0:
                    _sse_conns[username] = remaining
                else:
                    _sse_conns.pop(username, None)

    return Response(
        generator(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # belt-and-suspenders for nginx
            "Connection": "keep-alive",
        },
    )
