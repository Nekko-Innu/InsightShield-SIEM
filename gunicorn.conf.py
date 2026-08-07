# gunicorn.conf.py
# Insight Shield — Gunicorn Production Configuration
# Used by: systemd service (ExecStart)
# Deploy to: /opt/insightshield/gunicorn.conf.py on VM-03

bind = "127.0.0.1:5000"   # Loopback only — nginx on 443 is the public entrypoint

# Everything that used to be a process-local module global now lives in SQLite
# (WAL, synchronous=NORMAL, busy_timeout=10000, thread-local connections — see
# db.py:_get_conn), so a second worker no longer silently breaks anything:
#   - SSE fan-out   -> /api/events/stream polls a database watermark instead of
#                      an in-process queue registry, so every worker sees every
#                      alert regardless of which one ingested it.
#   - escalation    -> one interval sweep over unacknowledged CRITICALs, run by
#                      insightshield-worker.service. No per-worker job state, and
#                      acknowledging works because the sweep re-reads the row.
#   - rate limiting -> the rate_events table. One shared window across workers,
#                      with a small bounded overshoot documented in rate_limit.py.
#   - AI cache      -> the ai_cache table, so "50 identical alerts = 1 API call"
#                      holds across the whole tier and survives a restart.
#   - scheduled jobs-> a separate systemd unit, so the 02:00 backup and the 03:00
#                      purge each run exactly once no matter how many workers.
#
# 3 is chosen for /report.pdf: it launches Chromium synchronously inside a
# request thread, and a PDF render must not be able to stall the dashboard for
# everyone else. It also leaves 2 serving through a crash or rolling restart.
# Budget ~120 MB per worker plus a transient ~250 MB Chromium — drop to 2 on a
# VM with less than 2 GB RAM.
#
# Do NOT set preload_app: db.py's connections are thread-local and created
# lazily, so forking after import would hand children a parent-created SQLite
# file descriptor.
workers = 3
threads = 16              # Per worker. Each SSE stream holds one for the life of
                          # the tab. Requires the thread-local sqlite connections
                          # in db.py.
timeout = 120              # Allow time for AI API calls (Groq/Gemini/OpenRouter)
graceful_timeout = 30
keepalive = 5
accesslog = "/var/log/insightshield/access.log"
errorlog = "/var/log/insightshield/error.log"
loglevel = "info"
