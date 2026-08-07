# Insight Shield

A Wazuh-fed SIEM dashboard for retail-branch monitoring — clean-break rebuild of the WatchPost reference codebase. Real-time SSE updates, AI-translated alert summaries (manager-facing) and investigation steps (IT-facing), encrypted credential store, role-aware access control, printable security audit reports.

**Status:** v1.5.0 — Round J shipped 2026-07-29. Built on the v1.4.1-audit-methodology Round I release. Retires the Semaphore PH SMS channel outright: `send_sms`, `get_sms_balance`, the SMS templates and the `sms:<device>` rate-limit bucket are gone, the Service Configuration UI drops to four live probes (`telegram_it`, `telegram_manager`, `gmail`, `wazuh`), the IT dashboard KPI strip becomes a fixed 4-card layout with no conditional SMS-credits tile, and the `credential_brute_force` escalation fans out to Telegram + email only. `MANAGER_PHONE` / `IT_ADMIN_PHONE` survive in Notification Recipients as contact-record fields — still displayed, still editable, read by no dispatch path. Originating from the v1.0.0 thesis-ready baseline (all 14 Part-11 verification items signed off, Round 10 closed 2026-04-29). The working tree carries an unreleased structural round on top of v1.5.0 — see the last changelog row.

## Highlights

- **AI-translated alerts** — every Wazuh alert is summarised in plain language for the manager and translated into INVESTIGATE/CHECK/MITIGATE steps for IT, via a data-driven multi-provider chain (Groq → Gemini → OpenRouter → static fallback). Provider list is editable through the Settings UI without restart.
- **Real-time IT dashboard** — Server-Sent Events push new alerts and severity-chart updates to connected admins; a 15-second polling fallback engages after three SSE failures so demo continues even when long-lived connections are blocked.
- **Live agent status** — the login page polls a public `/api/status` snapshot every 30 s and lights a `.dot` indicator green/amber/red per Wazuh manager + agent reachability.
- **Encrypted credentials** — every API key, bot token, and SMTP password is stored Fernet-encrypted in the database; only the master `ENCRYPTION_KEY` lives in `.env`. The Settings UI is the only path that reveals plaintext, and only briefly via a 10-second click-to-reveal.
- **Login throttle + brute-force alerting** — POST `/login` rate-limits per-IP (5/15min) and per-username (10/60min); a 20-failures-in-60-min escalation emits a `credential_brute_force` HIGH alert that fans out to IT via Telegram + email. Audit log captures every attempt for chain-of-custody review (Round E).
- **Encrypted SQLite backups** — `backup.py` writes Fernet-encrypted `.db.enc` snapshots; restore decrypts transparently. Same `ENCRYPTION_KEY` powers credential storage and backup wrapping (Round E).
- **Service Configuration UI** — `/admin/settings?tab=service` shows status / Test / Edit / Toggle for each external service (Telegram IT, Telegram Manager, Gmail, Wazuh API, Notification Recipients). Test endpoint live-probes credentials without sending notifications. Toggle mutes a service without deleting credentials. AI providers section keeps its existing reorder/activate/delete UI (Round F).
- **Role-aware access** — a `@role_required("IT_ADMIN")` decorator gates 26 routes across the nine blueprints. Manager hits 403 JSON for `/api/*` blocked routes and 302 to `/dashboard/manager` with a flash for HTML routes. The Security Audit Report is the one admin-adjacent surface a manager can read.
- **Security Audit Report (web + PDF)** — `/report` is a Bureau-styled HTML view with six id-anchored sections after Round I:
    1. **§01 Executive Summary** — AI-generated, restructured into four labeled paragraphs (KEY FINDINGS · CURRENT CHALLENGES · ACTIONS TAKEN · TOP RECOMMENDATIONS) so the same surface speaks to manager, IT, and auditor audiences. Cached 1h by SHA-1 of `(v2|date_from|date_to|latest_alert_id)` — the `v2|` version sentinel invalidates prior-formula cache entries automatically. Followed by a static Highlights line citing live agent coverage that renders regardless of chain state.
    2. **§02 Methodology & Scope** *(Round I)* — Audit Objectives, Scope (live agent counts), Methodology (Wazuh decode → AI chain → SQLite WAL → severity routing → posture score), Limitations, and Framework Alignment with a NIST CSF 2.0 chip row (Detect filled, others outlined out of scope). Renders even on empty date windows.
    3. **§03 Summary Metrics** — 4-up KPI strip (total alerts · acknowledged · mean response · posture score) + 3-up secondary grid (resolved · avg FK · AI providers) + top-3 threats numbered list.
    4. **§04 NIST CSF 2.0 — Detect** — Detection coverage (agent sensor table, severity distribution, top attacker IPs, auth metrics) + detection follow-through (acknowledgment, MTTA, audit log pointer). Single CSF anchor; other functions out-of-scope per thesis.
    5. **§05 Alert Details** — per-alert cards with AI translation, lifecycle pip dots, deep links to alert detail pages.
    6. **§06 Appendix A — Raw Wazuh JSON** — collapsed `<details>` per alert with Expand all / Collapse all toggle. Long URLs / base64 / file paths wrap inside the card after Round I's `pre.raw-json code` cascade fix.

    The AI executive summary only fires on explicit Generate click (preserves AI provider quota on bookmark hits). Cache attribution distinguishes cache-hit (`Served from cache (originally AI-generated, 1h TTL).`) from fresh AI generation (`Generated by <provider>.`).

    **AI prompt discipline** *(Round I)* — both the exec_summary and manager-translator prompts ship explicit synonym maps for every `config.FORBIDDEN_WORDS` entry (`exploit → "method of attack"`, `firewall → "network filtering"`, `IP address → "network address"`, `TCP/HTTP/FTP/SSH/RDP/SMB/NTLM → "network connection"`, etc.) plus a self-check instruction so the model has both the rule and a substitution path.

    **`/report.pdf`** drives headless Chromium via Playwright to produce an A4 PDF with a Marker cover (96pt typographic title), TOC, page-numbered footer, and force-opened Appendix A. The two-surface print model is intentional: Ctrl+P prints only operator-expanded entries; `/report.pdf` force-opens all `<details>` for archival completeness.

    Architecture deep-dive (Rounds G + H + I) in [docs/security-audit-report.md](docs/security-audit-report.md). Section 16 of that doc covers the Round I delta.

## Quick start (development)

```bash
cd insightshield
cp .env.example .env
pip install -r requirements.txt

# Generate the master encryption key (one-time, irrecoverable if lost)
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# Paste the output into ENCRYPTION_KEY= in .env. BACK IT UP.

# Round G one-time install: Chromium binary for /report.pdf rendering
# (~111MB Chromium Headless Shell, downloaded to ~/.cache/ms-playwright/
# on Linux or ~/AppData/Local/ms-playwright/ on Windows). Without this
# step, hitting /report.pdf raises 'Executable doesn't exist'.
python -m playwright install chromium

# app.py is a pure application factory ending at `app = create_app()` — no
# app.run(), no __main__ block, so `python app.py` imports and exits silently.
# Use the Flask CLI; it auto-discovers `app` in app.py.
flask run

# Production runs APScheduler in its own process (insightshield-worker.service),
# so web workers never start one. For a single dev process that also gets
# escalation / midnight reset / agent-status refresh / nightly backup:
INSIGHTSHIELD_RUN_SCHEDULER=1 flask run
```

Open <http://127.0.0.1:5000>. Bootstrap credentials (forced password change on first login):

| Role     | Username  | Password            |
|----------|-----------|---------------------|
| IT Admin | `admin`   | `insightshield2026` |
| Manager  | `manager` | `branch2026`        |

For production install (Ubuntu 24.04, gunicorn + nginx + systemd, `wazuh-analysisd -t` rule verification), see [`docs/deployment-ubuntu.md`](docs/deployment-ubuntu.md) — or `scripts/install.sh`, which automates §§3.4, 4.1, 4.2 and 5.1–5.8 of it.

Operating a running system — AI chain exhausted, token rotation, locked-out accounts, backup restore — is in [`docs/runbook.md`](docs/runbook.md). The `/wazuh-webhook` request contract is in [`docs/webhook-contract.md`](docs/webhook-contract.md), and the current module layering in [`docs/architecture.md`](docs/architecture.md).

## Architecture

```text
.
├── app.py                 148-line application factory — logging, ProxyFix, cookie
│                          policy, blueprint registration, first-boot bootstrap.
│                          "Build and wire the app. Nothing else lives here."
├── worker.py              The one process that owns APScheduler in production.
│                          Same create_app() as the web tier, plus init_scheduler()
├── web/                   Flask-tier infrastructure, none of it routes — auth_user.py
│                          (Flask-Login User model, user loader, session-revocation
│                          token), csrf.py (per-session token + blanket
│                          before_request check), errors.py (uncaught-exception net →
│                          logs + error_log table, JSON or error page), filters.py
│                          (Jinja filters and globals), hooks.py (password-rotation
│                          gate + audit middleware), responses.py (shared helpers)
├── web/blueprints/        The nine blueprints registered in create_app() — auth
│                          (login / logout / password rotation / login throttle),
│                          dashboards (/dashboard router + both role dashboards),
│                          alerts (detail / acknowledge / resolve), reports (/report,
│                          /report.pdf, /export.csv), api (dashboard JSON + /health),
│                          stream (SSE), webhook (/wazuh-webhook, the one CSRF-exempt
│                          route), admin_ops (backups + audit log), admin_settings
│                          (/admin/settings and every mutating endpoint under it).
│                          URL rules are unchanged by the split — only endpoint names
│                          gained a blueprint prefix
├── web/blueprints/stream.py  SSE for the IT dashboard — polls a DB watermark
│                             (db.get_stream_watermark) roughly every 2s, so every
│                             gunicorn worker sees every alert. Replaces events.py's
│                             per-process Queue registry, which only reached browsers
│                             attached to the worker that ingested the alert
├── decorators.py          @role_required factory (Round 8 RBAC)
├── config.py              Env-var gateway + thresholds + level→severity map
├── crypto_utils.py        Fernet encrypt/decrypt + master-key validation
├── db.py                  SQLite (9 tables — alerts (21 cols), users, audit_log,
│                          api_keys, settings, ai_providers, error_log, rate_events,
│                          ai_cache) + report helpers
├── _ai_chain.py           Generic provider-chain runner — 3 callers
├── _request_cache.py      Per-Flask-request memoisation for hot DB reads
├── groq_translator.py     Manager translation (1st chain caller)
├── it_recommender.py      IT investigation steps (2nd chain caller)
├── executive_summary.py   Audit-report exec summary (3rd chain caller)
├── alert_router.py        Severity-routing matrix
├── notifier.py            Telegram + Gmail outbound
├── wazuh_receiver.py      Webhook validator + alert pipeline orchestrator
├── wazuh_api.py           Outbound calls to the Wazuh manager's REST API — importable
│                          from the scheduler process, which has no Flask routes
├── alerts_util.py         Leaf helpers for reading an alert row (derive_attacker_ip,
│                          build_severity_array). Imports nothing from this app
├── agent_status.py        Cached agent-status snapshot + 30s poller hook
├── health_score.py        Compliance score (deduct/bonus formula)
├── cache.py               Thread-safe AI translation/exec-summary cache
├── rate_limit.py          Burst absorber + flood control
├── scheduler.py           APScheduler — escalation, midnight reset, agent-status, daily backup
├── backup.py              SQLite hot-backup helpers
├── validator.py           Output validation (manager / IT-rec / exec-summary)
├── insightshield.service     systemd unit for the gunicorn web tier
├── insightshield-worker.service  systemd unit for worker.py — exactly-once by
│                                 definition, which is why the scheduler lives there
├── nginx/insightshield.conf  Reverse-proxy (TLS, SSE block, rate limit)
├── logrotate/insightshield   Rotation for gunicorn's two files (the app log
│                             self-rotates via RotatingFileHandler)
├── scripts/install.sh        Idempotent Ubuntu installer, run as root on the target
├── scripts/firewall.sh       Host firewall rules (LAN_CIDR override for multi-homed)
├── scripts/healthcheck.sh    Deployment smoke check (run on VM)
├── scripts/smoke_test.sh     End-to-end webhook→dashboard→report flow
├── static/                Tailwind CDN + offline fallback, design-tokens.css
├── static/report-bureau.css  Bureau body + Marker print stylesheet — conditionally
│                             loaded only on /report and /report.pdf endpoints (Round G)
├── static/js/             sse.js, login-status.js, dashboard-it-realtime.js,
│                          settings.js (Round F service-config controllers)
├── templates/             Jinja2 with _icon.html macro, _alert_row.html partial
├── templates/_report_print.html   Cover + TOC partial driven by Jinja sections
│                                  list (single source of truth for TOC + body
│                                  anchors). 96pt Marker cover treatment (Round G).
│                                  Sections list grew to 6 entries after Round I
│                                  added methodology-scope at index 1
├── templates/_settings_edit_modal.html   Shared service-edit modal (Round F)
├── docs/security-audit-report.md   908-line architecture reference for /report
│                                   and /report.pdf (Round G baseline §§1-15,
│                                   Round H + Round I delta in §16)
├── tests/                 pytest suite
└── wazuh_rules/custom_retail_rules.xml   27 custom retail-SIEM rules
                                          (Unauthorized Access ×4, POS Malware ×5,
                                          MitM/ARP ×3, Ransomware ×4, DoS ×4,
                                          Baseline ×7 — verified in Round I)
```

## Round-by-round changelog

| Round | What landed                                                                                          |
|-------|------------------------------------------------------------------------------------------------------|
| 1     | Scaffolding, 21-col schema, design tokens, Heroicons, no-emoji rule                                  |
| 2     | AI translation expansion (100w), IT recommender, multi-provider chain                                |
| 3     | Settings admin console, Fernet encryption, `.env` bootstrap, `ai_providers` table                    |
| 4     | Server-Sent Events, in-memory pub/sub, 30 s heartbeat, SSE-block nginx config                        |
| 5     | Public `/api/status`, 30 s background poller, login-page live indicator                              |
| 6     | `/api/severity-breakdown` array shape, `.dot` per row, MEDIUM `(N/M)` badge, real polling fallback   |
| 7     | Security Audit Report — exec summary, posture score, top threats / IPs / auth metrics                |
| 8     | `@role_required` decorator factory; 21 inline checks → centralised policy                            |
| 9     | Header nav order, DEPLOYMENT.md, README rewrite, smoke test script, ossec-logtest hook               |
| 10    | Part-11 checklist sign-off, residual emoji removed, `v1.0.0` tagged                                  |
| A–C   | UI rework rounds — header dropdown, dashboard filters, sticky sidebar, hold-to-show password         |
| D     | Raw JSON tab wraps, Report renders as document (toolbar collapsed), CSS Grid `min-w-0` fix           |
| E     | Login throttle (5/15min IP, 10/60min user, 20/60min escalation → brute-force HIGH alert), Fernet-encrypted SQLite backups |
| F     | Service Configuration redesign — completeness helpers, live `Test`/`Toggle` endpoints, shared edit modal, Bureau-style cards. Brand recolor cyan→navy, Prism Tomorrow dark theme on Raw JSON. `v1.2.0-services-redesign` tagged 2026-05-09 |
| G     | Security Audit Report redesign — defer AI summary until `Generate`, cover + TOC + Detect-anchored layout, Playwright PDF endpoint at `/report.pdf`, Bureau body + Marker cover treatment, Download PDF button. `v1.3.0-audit-report` tagged 2026-05-10 |
| H     | Cross-surface polish — manager dashboard filter parity (status / severity / hide-low / search), search bags expanded to cover every visible field (severity, ISO + humanised timestamps, status), SMS KPI hidden when service deactivated, Appendix A Expand-all toggle + Ctrl+P partial-print rule (only expanded entries print), screen-mode cover layout, Back-to-Dashboard button parity across alert detail / settings / change-password. `v1.4.0-cross-surface-parity` tagged 2026-05-10 |
| I     | Security audit report tweaks — new Methodology & Scope §02 section (Audit Objectives / Scope / Methodology / Limitations / Framework Alignment), §-marker renumber across the four following sections, AI executive summary restructured to 4 labeled paragraphs (KEY FINDINGS / CURRENT CHALLENGES / ACTIONS TAKEN / TOP RECOMMENDATIONS), exec-summary cache key versioned to `v2\|` prefix, Highlights line in the exec summary card citing live agent coverage, AI prompts tightened with explicit synonym mapping + self-check (both exec_summary and manager translator), cache attribution UX reworded to `Served from cache (originally AI-generated, 1h TTL)`, raw-JSON wrap on `<code>` to defeat Prism cascade so Appendix A entries stay inside their card. `v1.4.1-audit-methodology` tagged 2026-05-12 |

| J     | Semaphore PH SMS channel retired outright — `send_sms` / `get_sms_balance` / SMS templates / the `sms:<device>` rate-limit bucket removed, Service Configuration drops to four live probes, IT dashboard KPI strip fixed at 4 cards, `credential_brute_force` fans out to Telegram + email only. `MANAGER_PHONE` / `IT_ADMIN_PHONE` survive as contact-record fields read by no dispatch path. `v1.5.0` 2026-07-29 |
| —     | **Unreleased, in the working tree.** Structural round for multi-worker correctness: routes moved out of `app.py` into the nine `web/blueprints/` modules and infrastructure into `web/` (`app.py` is now a ~148-line factory); `events.py` deleted and SSE rebuilt as a DB-watermark poll in `web/blueprints/stream.py`; three new tables (`error_log`, `rate_events`, `ai_cache`) replacing per-worker in-memory state; APScheduler moved into its own `worker.py` process under `insightshield-worker.service`; settings pages merged into one with a fourth Errors tab; alert detail rebuilt and manager acknowledgement removed; PDF export replaced with print on unsupported paths; dashboards gained widgets, health score and agent status |

Each round shipped as per-file commits with verification gates. See [REBUILD_SPEC.md](REBUILD_SPEC.md) for the full master spec and [SYSTEM_DESIGN.md](SYSTEM_DESIGN.md) for architecture and round history; [docs/security-audit-report.md](docs/security-audit-report.md) is the Round G architecture reference for `/report`.

## Reference codebase

Insight Shield is a clean break from **WatchPost**. WatchPost is frozen at its current commit as the historical reference; Insight Shield evolves independently here.

## License

See [LICENSE](LICENSE) (TBD).
