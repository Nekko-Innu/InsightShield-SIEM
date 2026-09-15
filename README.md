<div align="center">

# Insight Shield

**A Wazuh-fed SIEM dashboard that explains itself.**

Security alerts arrive as raw decoder output. Insight Shield stores them, translates them into
plain language for a branch manager and into investigation steps for an IT administrator, routes
the urgent ones out through Telegram and email, and turns any date range into a printable audit
report.

[Quick start](#quick-start) · [Architecture](#architecture) · [Security](#security) · [Documentation](#documentation) · [License](#license)

</div>

---

## What it does

A Wazuh manager forwards every alert to `POST /wazuh-webhook`. From there:

```text
Wazuh agent ──▶ Wazuh manager ──▶ /wazuh-webhook ──▶ validate ──▶ AI translation ──▶ SQLite (WAL)
                                                                                          │
                                        ┌─────────────────────────────────────────────────┤
                                        ▼                                                 ▼
                            severity routing                                   dashboards + report
                        Telegram · email · escalation                       SSE push · audit PDF
```

Two audiences, one database. The manager sees a plain-language feed, a health score and monitored
devices. The IT administrator sees the same alerts with decoder internals, recommended next steps,
and the controls to acknowledge and resolve.

## Highlights

| | |
|---|---|
| **AI-translated alerts** | Every alert is summarised in under 100 words for the manager and split into INVESTIGATE / CHECK / MITIGATE steps for IT, through a provider chain (Groq → Gemini → OpenRouter → static fallback) that is reordered and re-keyed from the Settings UI without a restart. |
| **Real-time IT dashboard** | Server-Sent Events push new alerts and severity updates to connected admins. The stream polls a database watermark, so every worker sees every alert; a 15-second polling fallback engages after three SSE failures. |
| **Live agent status** | The login page polls a public status snapshot every 30 s and lights an indicator per Wazuh manager and agent reachability — without naming any device to an anonymous visitor. |
| **Encrypted credentials** | API keys, bot tokens and the SMTP password are stored Fernet-encrypted in the database. Only the master `ENCRYPTION_KEY` lives in `.env`. Plaintext is reachable only through a 10-second click-to-reveal in Settings, itself rate-limited and audit-logged. |
| **Brute-force detection** | `POST /login` throttles per IP (5 per 15 min) and per username (10 per 60 min). Twenty failures from one source in an hour raises a HIGH `credential_brute_force` alert that fans out to IT. |
| **Encrypted backups** | Nightly Fernet-encrypted SQLite snapshots, restored transparently by the same key that wraps the credential store. |
| **Security audit report** | Any date range becomes a six-section report — executive summary, methodology, metrics, NIST CSF 2.0 Detect coverage, per-alert detail, and a raw-payload appendix for IT — rendered to A4 PDF through headless Chromium. |

## Quick start

Requires Python 3.10 or newer — deployment targets Ubuntu 24.04 and its Python 3.12 — and a Wazuh
manager to feed it. The app runs and is fully navigable without one; the alert feed simply stays
empty.

```bash
cp .env.example .env
pip install -r requirements.txt

# Master encryption key — one-time, and irrecoverable if lost.
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# Paste it into ENCRYPTION_KEY= in .env, then back it up somewhere else.

# Chromium for PDF rendering (~111 MB, one-time).
# Without it, /report.pdf raises "Executable doesn't exist".
python -m playwright install chromium

# app.py is a pure application factory — no app.run(), no __main__ block —
# so `python app.py` imports and exits silently. Use the Flask CLI.
flask run
```

Open <http://127.0.0.1:5000>.

The scheduler (escalation sweep, midnight reset, agent-status refresh, nightly backup) runs in its
own process in production. For one dev process that also does that work:

```bash
INSIGHTSHIELD_RUN_SCHEDULER=1 flask run
```

Bootstrap accounts, both forced through a password change on first login:

| Role     | Username  | First-boot password           |
|----------|-----------|-------------------------------|
| IT Admin | `admin`   | `BOOTSTRAP_ADMIN_PASSWORD`    |
| Manager  | `manager` | `BOOTSTRAP_MANAGER_PASSWORD`  |

Both must be set in `.env` before the first run. There are no defaults: seeding
refuses to run without them, because a password published here would own the
IT_ADMIN role until somebody logged in and changed it.

Serving over plain HTTP will drop the session cookie, because `Secure` is on by default. For local
work without TLS, set `INSIGHTSHIELD_ALLOW_HTTP_COOKIES=1` — and never set it in production.

**Tests**

```bash
python -m pytest              # full suite, including a real 70-second idle-timeout test
python -m pytest -m "not slow"  # skip the wall-clock wait
```

## Architecture

```text
.
├── app.py                    Application factory — logging, ProxyFix, cookie and session
│                             policy, blueprint registration, first-boot bootstrap.
├── worker.py                 The one process that owns APScheduler in production.
├── web/                      Flask-tier infrastructure, no routes: auth_user.py (user model,
│                             loader, password-derived session-revocation token), csrf.py
│                             (per-session token + blanket before_request check), errors.py,
│                             filters.py, hooks.py (password-rotation gate, audit middleware),
│                             responses.py
├── web/blueprints/           Nine blueprints, 39 routes: auth, dashboards, alerts, reports,
│                             api, stream (SSE), webhook, admin_ops, admin_settings
├── decorators.py             @role_required factory — 27 applications across the blueprints
├── config.py                 Env-var gateway, thresholds, level→severity map
├── crypto_utils.py           Fernet encrypt/decrypt, master-key validation
├── db.py                     SQLite, nine tables: alerts (21 cols), users, audit_log, api_keys,
│                             settings, ai_providers, error_log, rate_events, ai_cache
├── _ai_chain.py              Generic provider-chain runner, three callers
├── groq_translator.py        Manager translation          (chain caller 1)
├── it_recommender.py         IT investigation steps       (chain caller 2)
├── executive_summary.py      Audit-report exec summary    (chain caller 3)
├── alert_router.py           Severity-routing matrix
├── notifier.py               Telegram + Gmail outbound
├── wazuh_receiver.py         Webhook validator + pipeline orchestrator
├── wazuh_api.py              Outbound calls to the Wazuh REST API
├── agent_status.py           Cached agent-status snapshot + poller hook
├── health_score.py           Compliance score
├── rate_limit.py             Burst absorber and flood control
├── scheduler.py              Escalation, midnight reset, agent status, nightly backup
├── backup.py                 Encrypted SQLite hot-backup helpers
├── validator.py              Output validation for all three AI surfaces
├── templates/  static/       Jinja2 views, design tokens, Bureau report stylesheet
├── nginx/  logrotate/  scripts/   Deployment assets and the idempotent Ubuntu installer
├── tests/                    pytest suite — Playwright end-to-end plus HTTP-level security tests
└── wazuh_rules/              31 custom retail rules: unauthorized access, POS malware,
                              MitM/ARP, ransomware, DoS, recon, baseline, noise
                              suppression — plus 3 stock arpwatch overrides
```

Both systemd units run the same application object. The only difference is that `worker.py` calls
`init_scheduler()` — which is why scheduled work happens exactly once no matter how many web
workers are running.

## Security

The controls below are exercised by a 30-case test suite run against a live instance; the full
evidence, including what failed before it was fixed, is in
[docs/security-test-audit-2026-08-13.md](docs/security-test-audit-2026-08-13.md).

| Control | How it works |
|---|---|
| **Authentication** | Session cookie only — no persistent "remember me" cookie exists, so nothing outlives the session. Cookies are `Secure`, `HttpOnly`, `SameSite=Lax`. |
| **Idle timeout** | 30 minutes, and it means it: dashboard polling and SSE do not count as activity, so a browser left open does time out. Streams end after one session lifetime rather than running unbounded. |
| **Session revocation** | The session id embeds a token derived from the password hash, so changing a password invalidates every other session for that account immediately. |
| **Authorization** | `@role_required` on every IT-only route. Machine paths get 403 JSON, browser paths a 403 page. Read surfaces suppress IT-only content — raw payloads, forensic detail, investigation steps — for managers on both the alert detail page and the audit report. |
| **CSRF** | Blanket `before_request` check on every mutating request, so a new route is protected by default. One exemption: the webhook, which carries no browser session. |
| **Webhook** | Two independent gates — a source-IP allowlist and a shared-secret header — and it fails closed if the secret is unset. |
| **Rate limiting** | Per-IP and per-username login throttles, 30/min on the status API, 120/min per source on the webhook, and tighter budgets on credential reveal and PDF export. |
| **Password storage** | scrypt with a per-record salt, via Werkzeug. Bootstrap accounts cannot reach any route except the change-password form until they rotate. |
| **Audit trail** | Every login, logout, acknowledgement, resolution, password change and dispatch is recorded with actor, role, source IP and timestamp — and verified not to contain passwords, tokens or key material. |

Found something? Open an issue with reproduction steps rather than a pull request, and do not
include live credentials in the report.

## Documentation

| Document | What it covers |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Module layering and import rules |
| [docs/deployment-ubuntu.md](docs/deployment-ubuntu.md) | Ubuntu 24.04 install — gunicorn, nginx, systemd, rule verification |
| [docs/runbook.md](docs/runbook.md) | Operating a running system: AI chain exhausted, token rotation, locked-out accounts, backup restore |
| [docs/webhook-contract.md](docs/webhook-contract.md) | The `/wazuh-webhook` request contract |
| [docs/security-audit-report.md](docs/security-audit-report.md) | Architecture reference for `/report` and `/report.pdf` |
| [docs/security-test-audit-2026-08-13.md](docs/security-test-audit-2026-08-13.md) | Security test execution and evidence, 30 cases |
| [SYSTEM_DESIGN.md](SYSTEM_DESIGN.md) · [REBUILD_SPEC.md](REBUILD_SPEC.md) | Full system design and the master build spec |

For a production install, `scripts/install.sh` automates most of the Ubuntu guide and is safe to
re-run. To deploy an update, run `sudo scripts/deploy.sh` — it runs `update.sh` (app tier) then
`install.sh` (rules + Wazuh) and verifies the result (ruleset compiles, token in sync, services
up, live webhook returns 200). See `docs/runbook.md` § "Deploying an update".

## Release history

**v1.5.0** (2026-07-29) — SMS channel retired: notification fan-out is Telegram and email only, the
Service Configuration UI drops to four live probes, and the IT dashboard KPI strip settles at four
cards. Phone numbers survive as contact-record fields, read by no dispatch path.

**Unreleased, in the working tree** — two rounds. A structural one for multi-worker correctness:
routes moved out of `app.py` into nine blueprints and infrastructure into `web/`; SSE rebuilt as a
database-watermark poll so every worker sees every alert; three tables replacing per-worker
in-memory state; the scheduler moved into its own process. Then a security round closing six
defects found by live testing — logout leaving a valid cookie behind, an idle timeout that could
never fire, raw decoder payloads reaching managers through the audit report, an unbounded event
stream, and a login timing side-channel that revealed which usernames exist. Since then (September
2026): the unread phone-number settings are gone and the IT admin email lives in the Gmail card, and
POS memory-scraping and ransomware alerts carry their own plain-language fallback text — the
memory-scraping alert used to tell cashiers to change passwords.

| Round | What landed |
|-------|-------------|
| 1–3   | Schema, design tokens, AI translation chain, Settings console, Fernet encryption |
| 4–6   | Server-Sent Events, public status endpoint, live login-page indicator, polling fallback |
| 7–8   | Security audit report — exec summary, posture score, top threats; `@role_required` policy |
| 9–10  | Navigation, deployment guide, smoke test, verification sign-off, `v1.0.0` |
| A–D   | UI rework — header dropdown, dashboard filters, sticky sidebar, report as document |
| E     | Login throttle and brute-force escalation; encrypted SQLite backups |
| F     | Service Configuration redesign — live Test and Toggle probes, shared edit modal |
| G     | Audit report redesign — deferred AI summary, cover and TOC, Playwright PDF endpoint |
| H     | Cross-surface parity — filters, search bags, Appendix expand-all, print rules |
| I     | Methodology and scope section, restructured exec summary, tightened AI prompts |
| J     | SMS retirement, four-probe service config, `v1.5.0` |

Every round shipped as per-file commits behind verification gates.

## Reference codebase

Insight Shield is a clean break from **WatchPost**, which is frozen at its final commit as a
historical reference. Nothing here depends on it.

## License

[MIT](LICENSE) — Copyright (c) 2026 The Insight Shield team.
