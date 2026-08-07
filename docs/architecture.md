# Architecture

Orientation for a developer new to this codebase. Current code only.

For the round-by-round history, the rationale behind older design decisions, and the full
data model, see `../SYSTEM_DESIGN.md` one level up. This file does not repeat it.

---

## 1. Three layers

```
app.py                    application factory — wires, nothing else (~148 lines)
  └── web/                request infrastructure
        └── blueprints/   routes
```

The split exists because `app.py` had grown to hold every route, filter, hook and helper
in the application. Nothing about the URL surface changed: only endpoint names gained a
blueprint prefix, so `url_for('login')` became `url_for('auth.login')`. nginx,
`smoke_test.sh` and existing bookmarks were unaffected.

### `app.py`

Builds the app and returns it. Called at import for `app:app` (gunicorn, `conftest.py`)
and imported by `worker.py`.

It validates `ENCRYPTION_KEY` at module import, before anything else — `crypto_utils.get_master_key()`
calls `sys.exit(1)` on a missing or invalid key, so systemd reports the unit as failed and
the operator sees the cause immediately. Running with a broken key would silently emit
empty or corrupt API keys to providers, which is worse.

### `web/` — infrastructure

Every module here exposes `init_app(app)`.

| Module | Owns |
|---|---|
| `csrf.py` | Hand-rolled per-session CSRF token + the blanket `before_request` check |
| `hooks.py` | The `must_change_password` gate and the audit middleware |
| `errors.py` | Uncaught-exception handler — logs to `logs/insightshield.log` *and* the `error_log` table, then shapes the response |
| `filters.py` | Jinja filters and globals |
| `auth_user.py` | Flask-Login wiring: the `User` model, session-revocation token, user loader |
| `responses.py` | Shared response helpers. Imported, not `init_app`'d — it touches no app object |

### `web/blueprints/` — routes

| Blueprint | Owns |
|---|---|
| `auth.py` | `/`, `/login`, `/logout`, password change, the login throttle |
| `dashboards.py` | `/dashboard` router plus both role dashboards |
| `alerts.py` | Alert detail, acknowledge, resolve |
| `reports.py` | `/report`, `/report.pdf`, `/export.csv` |
| `api.py` | Dashboard JSON endpoints, `/health`, `/api/status`, the client-error beacon |
| `stream.py` | `/api/events/stream` (SSE) |
| `webhook.py` | `/wazuh-webhook` — the one CSRF-exempt route. See `webhook-contract.md` |
| `admin_ops.py` | Backups and audit log |
| `admin_settings.py` | `/admin/settings` and every mutating endpoint under it |

---

## 2. Registration order is load-bearing

In `create_app()`:

```python
csrf.init_app(app)
hooks.init_app(app)
errors.init_app(app)
filters.init_app(app)
auth_user.init_app(app)
```

**Do not reorder the first two.** Flask runs `before_request` functions in registration
order. If `hooks` registered first, a request rejected for a bad CSRF token would still be
written to `audit_log` as though it had succeeded — the audit trail would record forged
requests as legitimate ones.

The same ordering puts CSRF ahead of the password-rotation gate, so a user who must change
their password cannot bypass CSRF on the way there.

---

## 3. Two processes

The web tier and the scheduler worker run **the same application object**. The only
difference is whether `init_scheduler()` is called.

| Process | Unit | Scheduler |
|---|---|---|
| Web tier | `insightshield.service` — gunicorn, 3 workers × 16 threads | No |
| Worker | `insightshield-worker.service` — `python worker.py` | Yes |

The gate is `INSIGHTSHIELD_RUN_SCHEDULER=1`, set on the worker unit and deliberately absent
from the gunicorn unit. It is a single-process dev convenience and how the E2E suite gets
an agent-status snapshot without a second process.

**Why a separate process rather than a flag on one gunicorn worker:** every scheduled job
must run exactly once. gunicorn has no notion of a "first" worker, so exactly-once inside
the web tier means either `workers=1` — which is what the whole refactor exists to undo —
or a distributed lock with heartbeats and a story for the holder dying mid-job. A second
systemd unit is exactly-once by definition and needs no coordination code.

`worker.py` imports the module-level `app`, **not** `create_app()`. Importing `app` already
built and bootstrapped one, and `create_app()` returns a new application object on every
call, so calling it there would leave the worker holding two.

The five scheduled jobs:

| Job | Trigger |
|---|---|
| `midnight_health_reset` | cron, 00:00 |
| `daily_db_backup` | cron, 02:00 |
| `retention_purge` | cron, 03:00 |
| `agent_status_poll` | interval, 30s |
| `escalation_sweep` | interval, `config.ESCALATION_INTERVAL_MIN` |

Deploy the web unit without the worker unit and you get a system with no escalations, no
agent-status updates, no nightly backup and no retention purge — and nothing says so.

---

## 4. Shared state lives in SQLite, not process memory

Three gunicorn workers plus a worker process means four processes. Anything held in a
module-level dict is per-process, and every place that happened was silently wrong:

| Now | Was | The failure |
|---|---|---|
| `ai_cache` table | three dicts in `cache.py` | "50 alerts = 1 API call" became one call *per worker*, and the whole cache was lost on restart |
| `rate_events` table | an in-process counter | each worker enforced its own quota, so the real limit was 3× the configured one |
| DB watermark poll in `stream.py` | `queue.Queue` registry in `events.py` | a browser attached to worker A never saw an alert ingested by worker B — silently, no error anywhere |
| `agent_status.snapshot` settings row | module-level dict + `threading.Lock` | the scheduler writes it from a different *process* than the workers that serve `/api/status` |
| `error_log` table | nothing | new surface; backend and browser errors in one queryable place |

`events.py` was deleted outright. The database is the one thing all four processes share,
so it is where shared state goes.

Every bootstrap step is idempotent, because on a cold start all four processes run it at
once: `init_db` uses `CREATE TABLE IF NOT EXISTS`, `bootstrap_settings_from_env` has its
`bootstrap_complete` sentinel, and `seed_users_from_config` swallows the `IntegrityError`
the losers of the race get from `users.username UNIQUE`.

---

## 5. Request lifecycle

1. **nginx** terminates TLS, proxies to `127.0.0.1:5000`.
2. **`ProxyFix(x_for=1, x_proto=1, x_host=1)`** rewrites the request from the
   `X-Forwarded-*` headers. Without it every request looks like loopback, which voids the
   webhook IP allowlist, collapses the login throttle into one global bucket, and writes
   `127.0.0.1` into every `audit_log.ip` row. `x_for=1` trusts exactly one hop — nginx.
   Do not raise it.
3. **`before_request` chain**, in registration order: CSRF check → password-rotation gate
   → audit middleware. The audit hook only considers `POST/PUT/PATCH/DELETE`, and skips the
   high-frequency polling paths in `AUDIT_SKIP_PREFIXES`.
4. **Route**, in a blueprint. `@login_required` then `@role_required(...)` — the latter
   stacks under the former and only ever sees authenticated users.
5. **Response**, often via `web/responses.py`. Auth and rate-limit failures dispatch on
   path: `/api/*` and `/export*` get JSON, everything else gets a flash and a redirect.

---

## 6. Where do I add…

| Thing | File |
|---|---|
| A new route | The matching `web/blueprints/*.py`. Register nothing — the blueprint is already registered |
| A whole new route group | New module in `web/blueprints/`, then add it to the import and the loop in `app.py` |
| A new scheduled job | `scheduler.py`, inside `init_scheduler()`. Set `max_instances=1` and `coalesce=True` unless you want overlap |
| A new Jinja filter or global | `web/filters.py` |
| A new `before_request` hook | `web/hooks.py` — mind the ordering in §2 |
| A new setting | `config.py` to read it, `.env.example` to document it, and `db.bootstrap_settings_from_env` if it should migrate into the database on first boot |
| A new external service probe | `web/blueprints/admin_settings.py`, `_test_service_probe` |
| A new shared helper | A leaf module (`alerts_util.py` is the model) — importing `app` from a helper is what the layering exists to prevent |

---

**See also:** `webhook-contract.md` (ingest contract), `runbook.md` (operating a running
system), `deployment-ubuntu.md` (install), `../SYSTEM_DESIGN.md` (full design and history).
