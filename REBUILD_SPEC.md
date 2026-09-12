# Insight Shield — Rebuild Specification

This document is the master spec for the Insight Shield rebuild from WatchPost. The literal user-supplied master prompt was approved on 2026-04-26; this file captures it as the implementation contract for Rounds 2–10.

> **Standing directives** (override the literal text of any spec section below):
>
> - **No emoji, no Unicode glyph icons.** Dots use the `.dot` CSS class with `var(--TOKEN)` colors from `static/design-tokens.css`. Icons use Heroicons inline-SVG via the `templates/_icon.html` macro. Never Tailwind utility classes (`rounded-full bg-rose-500`) for status colors — they bypass design-tokens.css.
> - **Two phone numbers.** `MANAGER_PHONE` is the actual manager's phone; `IT_ADMIN_PHONE` is the IT admin's phone. Contact-record fields in Notification Recipients only as of Round J (2026-07-29) — neither `alert_router` nor `notifier` reads them for dispatch since the SMS channel was retired; see Part 23.
> - **GitHub remote.** `https://github.com/Nekko-Innu/InsightShield-SIEM-Dashboard.git`.

---

> **Module layout has changed since these rounds were written.** Parts 1–23 below cite
> `app.py` for routes, Jinja filters and login helpers, because that is where they lived
> at the time each round shipped. `app.py` is now a ~148-line application factory that
> wires and nothing else. When a round below says "`app.py` `POST /login`", build it here
> instead:
>
> | Round text says | Current home |
> |---|---|
> | `app.py` — any route | `web/blueprints/{auth,dashboards,alerts,reports,api,stream,webhook,admin_ops,admin_settings}.py` |
> | `app.py` — Jinja filters / globals | `web/filters.py` |
> | `app.py` — login setup | `web/auth_user.py` |
> | `app.py` — audit / before_request middleware | `web/hooks.py` |
> | `app.py` — CSRF | `web/csrf.py` |
> | `app.py` — error handlers | `web/errors.py` |
> | `events.py` | deleted — see Part 4 |
>
> Route URLs are unchanged by the split; only endpoint names gained a blueprint prefix
> (`url_for('login')` → `url_for('auth.login')`). See `insightshield/docs/architecture.md`
> for the current layering and the load-bearing hook registration order.

---

## Part 0 — Product identity & global changes

- Brand: every `WatchPost` → `Insight Shield`; every `watchpost` → `insightshield`. Database: `insightshield.db`. systemd unit: `insightshield.service`. nginx config: `insightshield.conf`.
- Footer (every page): left = `Build 0.1.0`, right = `Insight Shield v1.0 · DLSL-IT Cybersecurity Capstone`.
- Session timeout: 30 minutes of inactivity (already enforced via `PERMANENT_SESSION_LIFETIME_MIN`).
- **Removed:** `/simulate`, `/simulate/types`, `simulation.py`, the simulation panel UI on the IT dashboard, the `is_simulated` column, the `[SIM]` badge, all `WHERE is_simulated = 0` filters.
- **Removed:** `/alert/<id>/manager-acknowledge`, `db.manager_acknowledge_alert`, the `manager_acknowledged*` columns, and all manager-ACK UI (button, modal, action queue).
- Every non-dashboard page (`/alert/<id>`, `/account/password`, `/admin/settings`, `/admin/audit`, `/admin/backups`, `/report`) carries the same Back-to-Dashboard link in the same position with the same styling — `templates/_icon.html` macro `arrow-left` SVG + "Back to Dashboard" label.

## Part 1 — AI translation enhancements (Round 2)

- `MAX_WORDS = 100` (was 80). Each of the three sections (WHAT HAPPENED, HOW SERIOUS, WHAT TO DO) gains one sentence.
- New column `it_recommendation TEXT` (already added in Round 1 schema). Populated by a second AI call after the manager translation succeeds.
- Obfuscation map (built per alert by `it_recommender._build_map`): every internal IPv4 found in the payload → `Device-A`, `Device-B`, …; the agent/device name → `Host-A`, `Host-B`, …; plus a static tail of port `3389` → `Port-X`, `mimikatz.exe` → `Tool-A`, `lsass.exe` → `System-Process-1`. Public addresses are deliberately left alone — an attacker's source IP is not ours to protect and the model needs it. Apply before sending to provider; substitution is anchored on whole tokens, never bare substrings.
- IT recommendation rendered ONLY on the alert detail page, gated to `current_user.role == 'IT_ADMIN'`. NEVER included in any external notification (Telegram, email).

## Part 2 — Database schema (clean break, Round 1 — done)

- Fresh `insightshield.db`. NO migration framework.
- `alerts` (21 cols): id, timestamp, rule_id, attack_type, severity, device_name, raw_alert, plain_text, ai_reasoning, provider_used, fk_grade, acknowledged, acknowledged_by, acknowledged_at, response_time_s, attack_trail, resolved, resolved_by, resolved_at, resolve_note, **it_recommendation**.
- `users`, `audit_log`: as in WatchPost v5/v6.
- `api_keys` (Round 3 consumer): id, service, key_name, encrypted_value, is_active, created_at, updated_at. Fernet-encrypted.
- `settings` (Round 3 consumer): key, value, updated_at. Plain-text non-secret config.

## Part 3 — Settings admin console (Round 3)

- Route `/admin/settings`, IT_ADMIN only. Header nav uses Heroicons `cog-6-tooth` SVG (NOT emoji `⚙`) + "Settings" label, replacing standalone Audit Log + Backups header links.
- Vertical tab layout in `templates/settings.html`: left sidebar with top-level tabs — Service Configuration | Audit Log | Backups. Right panel reuses the existing `audit.html` and `backups.html` templates as Jinja includes. (A fourth tab, **Errors**, was added later off the `error_log` table; `settings.html` now whitelists `('service', 'audit', 'backups', 'errors')` and `web/blueprints/admin_settings.py` serves it.)
- Service Configuration sub-sections (per-section Save buttons):
  1. **AI Providers** — **dynamic add/remove/reorder** list. Each row stores label, model, base_url, encrypted api_key, auth_header, auth_prefix, request_format, is_active, position. Reorder via up/down arrows; toggle active/inactive. Pre-built templates dropdown (Groq, OpenAI, Gemini, DeepSeek, Anthropic, OpenRouter, Custom) auto-fills base_url + auth fields — see `config.PROVIDER_TEMPLATES` shipped in Round 2. The chain runner (`_ai_chain.run_chain`) was written in Round 2 to consume an opaque `providers: list[dict]`; Round 3 just swaps the source from `config.DEFAULT_AI_PROVIDERS` to `db.get_active_providers_ordered()`.
  2. **Telegram – IT Group** — Bot token (encrypted) + Chat ID (plain text).
  3. **Telegram – Manager** — Bot token (encrypted) + Chat ID (plain text).
  4. **Gmail SMTP** — Email address (plain text) + App Password (encrypted).
  5. **Notification Recipients** — Manager Phone Number (plain text), IT Admin Phone Number (plain text), IT Admin Email (plain text). Two distinct phones.
  6. **Wazuh API** — URL, Username (plain text) + Password (encrypted).

  > SMS Gateway (Semaphore PH) sub-section removed in Round J (2026-07-29) — see Part 23. Phone numbers remain in Notification Recipients for contact-record purposes only; they no longer drive any dispatch path.
- Encryption: `cryptography.fernet.Fernet`. Master key in `.env` as `ENCRYPTION_KEY`. Fail loud at startup if missing or invalid.
- Bootstrap: on first boot when both `api_keys` and `settings` are empty, populate from `.env` once. After that, the app reads from the DB; `.env` is only used for `FLASK_SECRET_KEY` and `ENCRYPTION_KEY`.
- All Settings POSTs logged to `audit_log` (encrypted values logged as `(encrypted, last4=XXXX)` only).

### Round 3 schema — `ai_providers` table (NEW)

The flexible multi-provider architecture (decided 2026-04-27) stores AI providers in a dedicated table, separate from the existing `api_keys` table which keeps non-AI service credentials (Telegram, Gmail).

```sql
CREATE TABLE IF NOT EXISTS ai_providers (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    label               TEXT    NOT NULL,           -- "Groq" | "OpenAI" | "MyCustom"
    model               TEXT    NOT NULL,           -- e.g. "llama-3.1-8b-instant"
    api_key_encrypted   TEXT    NOT NULL,           -- Fernet-encrypted
    base_url            TEXT    NOT NULL,           -- full POST URL
    auth_header         TEXT    NOT NULL,           -- "Authorization" | "x-api-key" | "x-goog-api-key"
    auth_prefix         TEXT    NOT NULL DEFAULT '',-- "Bearer " | ""
    request_format      TEXT    NOT NULL,           -- "openai_compat" | "gemini_v1beta" | "anthropic_messages"
    is_active           INTEGER NOT NULL DEFAULT 1,
    position            INTEGER NOT NULL,           -- chain order (lower = earlier)
    created_at          TEXT    NOT NULL,
    updated_at          TEXT    NOT NULL
);
CREATE UNIQUE INDEX idx_ai_providers_label ON ai_providers(label);
CREATE INDEX idx_ai_providers_active_position ON ai_providers(is_active, position);
```

`db.get_active_providers_ordered()` returns rows where `is_active = 1` ordered by `position`, decrypts `api_key_encrypted` via `crypto_utils.decrypt_value`, and returns dicts in the canonical shape `_ai_chain.run_chain` already expects (label, model, base_url, api_key, auth_header, auth_prefix, request_format, is_active). The chain runner does not change.

**Bootstrap from Round 2's `config.DEFAULT_AI_PROVIDERS`:** on first boot when `ai_providers` is empty, seed three rows from `config.DEFAULT_AI_PROVIDERS` so the chain keeps working before the IT admin opens Settings. After seeding, edits go through the Settings UI; `config.DEFAULT_AI_PROVIDERS` is read no more.

**Known gap — Anthropic format:** `_ai_chain._call_anthropic_messages` raises `NotImplementedError` in Round 2. A client adding Anthropic via the Settings UI in Round 3 would see the chain skip Anthropic and fall through to the next provider. Implement the Anthropic-specific request shape (system at top level, messages below, `anthropic-version` header) when the first client actually uses it.

**Known gap — per-provider rate limits:** Round 2's `_ai_chain.run_chain` has an inline `if label.lower() == "groq"` check for the burst absorber. Round 3 should add a `rate_limit_per_min INTEGER NULL` column to `ai_providers` and generalise the burst gate to consult it. NULL means no rate limit; a value caps that provider's calls per minute via `rate_limit.can_call(label, value)`.

## Part 4 — Real-time updates via SSE (Round 4)

- New endpoint `GET /api/events/stream` in `web/blueprints/stream.py`. `@login_required` **and** `@role_required("IT_ADMIN")` — the manager dashboard does not stream. Returns `text/event-stream`.
- **No in-process registry.** The stream polls a database watermark: `db.get_stream_watermark(status_key)` each tick, `db.get_alerts_since(last_id)` for the new rows. `SSE_POLL_SECONDS = 2.0` plus `random.uniform(0, 0.5)` of jitter, so a poolful of streams does not phase-lock into a query herd.
- `SSE_MAX_PER_USER = 3`; the fourth concurrent stream for a username gets `429 {"error": "too_many_streams"}`. The slot is released in the generator's `finally`, which is why a comment line is emitted on *every* tick — that write is what makes a closed tab's stream notice it is gone.
- Alert HTML is rendered **in the stream**, from `_alert_row.html`. The producer does not build it.
- Event types: `new_alert`, `severity_update`, `agent_status`. JSON payloads.

> **Do not rebuild this as an in-memory queue.** The original design was a `queue.Queue`
> singleton in `events.py` with `wazuh_receiver.process_alert` as producer. That registry
> only existed inside one Python process, so with more than one gunicorn worker a browser
> attached to worker A never saw an alert ingested by worker B — silently, with no error
> anywhere. `events.py` has been deleted. The database is the one thing every worker shares,
> so it is what the stream reads.
>
> The wire protocol is unchanged — same event names, same payload shapes — so
> `static/js/sse.js` and `static/js/dashboard-it-realtime.js` need no changes.
- Frontend: IT dashboard listens via SSE. Polling fallback to `/api/alerts/latest` every 15 s if SSE disconnects (3-retry exponential backoff).
- Manager dashboard continues 15s polling only (no SSE).
- `nginx/insightshield.conf`: `proxy_buffering off; proxy_read_timeout 3600s;` for the SSE location block.

## Part 5 — Dynamic agent status (Round 5)

- Public endpoint `GET /api/status` (no auth required). Returns `{manager_status, summary, dot_color, agents_online, agents_total}`.
- Refreshed by background thread every 30s; consumers read the cached snapshot — never call Wazuh on the request path.
- Three states: `green` (manager + all agents online) / `amber` (manager online, ≥1 agent offline) / `red` (manager unreachable).
- Login page: 30s `setInterval` polls `/api/status`. Render `<span class="dot dot--sm" style="background-color: var(--status-online);">` (etc.) + summary text.
- Manager dashboard "Monitored Devices" section uses the same `.dot` class (NOT emoji `🟢🟡🔴`).

## Part 6 — Severity bar chart (Round 6)

- `GET /api/severity-breakdown` returns a JSON ARRAY (not dict) in fixed order: crit, high, med, low, info. Each entry: `{key, label, count, levels}`. The `dot` and `color` fields from the literal master prompt are dropped — color is sourced from CSS variables (`--sev-${key}-border`) on the client. Pure data on the wire.
- Render: `<li>` per row using shared `.dot` class — `<span class="dot" style="background-color: var(--sev-crit-border);">`. Same class as Round 5 status dots.
- 24h / 7d / 30d range buttons above the chart (active = `bg-teal-600 text-white`, inactive = `bg-slate-100 text-slate-600`).
- Medium-frequency `(N/M)` badge: when severity = MEDIUM and the rule has a `<frequency>` block, render the count badge with `title="N out of M occurrences needed to escalate to HIGH"`.

## Part 7 — Security Audit Report (Round 7)

- `/report` accessible to both IT_ADMIN and Manager. IT toolbar button labeled "Security Audit Report" (replaces "Export Report"). Manager dashboard has a header link.
- Date-range picker (From / To). Default = last 7 days.
- Sections (proper H1/H2/H3 hierarchy):
  1. Header — "Insight Shield — Security Audit Report" with date range
  2. **Executive Summary** — AI-generated 2–3 paragraphs (third use of the shared `_ai_call` helper from Round 2)
  3. Summary Metrics — total alerts, top-3 threats, security posture score
  4. Agent Compliance & Health
  5. Incident Breakdown — alerts by severity, top attacking IPs, auth success/failures
  6. Vulnerability Detection — conditional (only if Wazuh VA data is exposed)
- `@media print` CSS: hide nav/toolbar, page break before each H2.
- AI exec summary cached by `hash(date_from, date_to, latest_alert_id_in_range)` for 1h.

## Part 8 — RBAC hardening (Round 8)

- `@role_required("IT_ADMIN")` decorator factory in new `decorators.py`. Stacks with `@login_required`. Returns 403 JSON for `/api/*`, redirects to `/dashboard/manager` with flash for HTML routes.
- Manager-allowed: `/dashboard/manager`, `/alert/<id>` (read-only), `/account/password`, `/report`, `/api/health-score`, `/api/alerts/latest`, `/api/status` (public anyway).
- Manager-blocked (403): all `/admin/*`, `/api/cache-stats`, `/api/agents`, `/export/*`.

## Part 9 — Final polish (Round 9)

- IT header nav order: Dashboard | Security Audit Report | Export CSV | [gear] Settings | Change Password | Logout.
- Manager header nav: Dashboard | Security Audit Report | Change Password | Logout.
- DEPLOYMENT.md rewrite: Insight Shield service/path names, ENCRYPTION_KEY generation walkthrough, Settings bootstrap procedure.
- README.md project overview + quick-start.
- `custom_retail_rules.xml` carry-over verification via `ossec-logtest -t`.
- End-to-end smoke test: fresh DB → `.env` populated → bootstrap → submit webhook → IT dashboard updates via SSE → severity bar updates → status dot stays green → IT alert detail shows manager translation + IT recommendation → resolve → manager Telegram receives resolution notice → `/report` generates with executive summary → manager logs in → cannot access Settings → can view Report.

## Part 10 — Sign-off & rehearsal (Round 10)

Walk the verification checklist (Part 11) end-to-end with the user. Address failures. Rehearse demo flow on the actual VM. Tag `v1.0.0`.

---

## Part 11 — Verification checklist

All 14 items signed off in Round 10 on 2026-04-29. v1.0.0 tagged.

- [x] `insightshield.db` created with 21-column `alerts`, `users`, `audit_log`, `api_keys`, `settings` tables (Round 1). The schema now has **nine** tables — `ai_providers` arrived in Round 3, and `error_log`, `rate_events` and `ai_cache` came with the multi-worker refactor (see `db.py` `init_db`).
- [x] Settings page (gear icon) with vertical tabs: Service Configuration | Audit Log | Backups (Round 3; Errors tab added later)
- [x] IT recommendation generated for every alert, visible only on IT detail page (Round 2)
- [x] SSE pushes new alerts to IT dashboard in real time with polling fallback (Round 4)
- [x] Login page shows live agent status (`.dot` class with `--status-*` token) updated every 30s (Round 5)
- [x] Severity bar chart: Critical at top, Informational at bottom, with `.dot` class + token colors (Round 6)
- [x] Security Audit Report generates AI Executive Summary + structured metrics (Round 7)
- [x] Manager cannot access Settings, Audit Log, Backups, or ACK alerts (Round 8)
- [x] Footer: "Build 0.1.0" (left), "Insight Shield v1.0 · DLSL-IT Cybersecurity Capstone" (right) (Round 1)
- [x] Every non-dashboard page has a consistent "Back to Dashboard" link with Heroicons SVG (Round 1)
- [x] No references to "WatchPost" remain (Round 1)
- [x] No simulation or manager-acknowledgment functionality (Round 1)
- [x] Session expires after 30 minutes (already enforced)
- [x] No emoji anywhere in the dashboard UI (Round 1 standing rule — Round 10 sign-off caught one residual `🔒` in password_change.html and replaced it with the Heroicons `lock-closed` SVG)

---

## Post-v1.0 Extensions (Rounds A through J)

Parts 12–24 below extend the v1.0.0 baseline (Parts 0–11) with the nine rounds shipped between 2026-05-01 and 2026-07-29: Rounds A–C UI rework (Parts 12–14), Round D document-mode tweaks (Part 15), Round E security hardening (Part 16), Round F service-config redesign (Part 17), Round G security audit report redesign + Playwright PDF (Part 18), Round H cross-surface parity polish (Part 19), Round I audit report Methodology section + AI prompt tightening (Parts 21–22, with verification checklist), Round J SMS/Semaphore retirement (Parts 23–24). Each Part follows the same style as Parts 1–10: an implementation contract, not a narrative. Standing directives at the top of this file still apply (no emoji, two phone numbers as contact-record only, GitHub remote).

## Part 12 — UI rework foundation (Round A)

- Save-points before any change: `git tag -a v1.0.0-ui-baseline` annotating HEAD `cd5e08a` + filesystem snapshot at `ui-fallback-pre-rework/` (gitignored).
- `static/design-tokens.css` additions:
  - Switch `.sev-accent-{info,low,med,high,crit}` from `border-left: 4px solid var(--sev-{key}-border)` to `box-shadow: inset 4px 0 0 var(--sev-{key}-border)` — no layout jitter on SSE prepend.
  - `.table-scroll { max-height: 420px; overflow-y: auto; }` — IT alerts table cap.
  - `.agents-scroll { max-height: 300px; overflow-y: auto; }` — agents side panel cap.
  - `.detail-right { position: sticky; top: 1rem; }` — pins ACK/Resolve while user scrolls forensic detail.
  - `.health-score-number { font-size: 2.5rem; font-weight: 800; line-height: 1; font-variant-numeric: tabular-nums; }`.
  - `.line-clamp-2` standard 2-line `-webkit-box` clamp.
- Single commit. Backend impact: zero.

## Part 13 — Header dropdown (Round B)

- Replace 6-link header nav row with: clickable logo (links `/dashboard`), Report icon button (`document-text`), Export CSV icon button (`arrow-down-tray`, IT only), Cog dropdown (`cog-6-tooth`), Role badge.
- Cog dropdown menu: Settings (IT only) → Change password → Sign out (hidden form `POST /logout` so existing CSRF wiring is preserved).
- `templates/_icon.html` — three new Heroicons branches: `arrow-down-tray`, `document-text`, `arrow-right-on-rectangle`.
- `static/ui.js` — new IIFE controller, gated on `[data-menu-toggle]`: open/close on click, close on click-outside, close on Escape.
- Manager dashboard body has zero hits for `/admin/settings` (the cog-menu Settings entry is IT-only).

## Part 14 — Page-level refinements (Round C)

- **IT toolbar** (`templates/dashboard_it.html`): two `<select>` dropdowns (`id="status-filter"`, `id="sev-filter"`) + `Hide low severity` toggle. Drop the legacy `[data-filter="sim"]` Simulated button.
- **IT side panel**: Agents card below the existing severity bar chart, consuming the existing `agents` template variable already passed by `dashboard_it()` route handler. No route change.
- **Manager dashboard**: swap literal `#10b981` / `#f59e0b` / `#dc2626` for `var(--status-online)` / `var(--status-degraded)` / `var(--status-offline)`; apply `.health-score-number` to health number; add `.line-clamp-2` to alert-feed description `<p>`.
- **Alert detail**: wrap right column in `<aside class="detail-right">`; Tree / Table / Raw JSON tab switcher for the `attack_trail` block (vanilla JS, gated on `[data-trail-tabs]`).
- **Login password**: convert `data-toggle-password` from click-to-toggle to hold-to-show via `mousedown` / `mouseup` / `mouseleave` + `touchstart` / `touchend`.

## Part 15 — Document-mode tweaks (Round D)

- `app.py`: register `pretty_json` Jinja filter — `json.dumps(json.loads(v), indent=2, ensure_ascii=False)`; falls through to `str(v)` on parse failure. Sits alongside `_from_json_filter` at line 127.
- `app.py`: helper `_humanize_seconds(s)` — renders seconds as `"4m 30s"` / `"1h 12m"` / `"3d 6h"`. Consumed by MTTA KPI and reused by Round E throttle flash.
- `static/design-tokens.css`: `pre.raw-json { white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-word; tab-size: 2; }`.
- `templates/alert_detail.html` line 212: `<pre class="raw-json">{{ alert.raw_alert | default(alert.attack_trail, true) | pretty_json }}</pre>`.
- `templates/report.html` lines 26–48: collapse in-page toolbar into `<details class="no-print"><summary>Adjust date range</summary>…</details>`. Drop Print button and Back-to-Dashboard link.
- Layout-stability safety nets (Round D follow-up):
  - `templates/alert_detail.html:39` — add `min-w-0` Tailwind utility to left column `<div class="space-y-4">`. Root cause: CSS Grid implicit `min-width: auto` refused to shrink the `1fr` track below unbreakable `callTrace` strings.
  - `templates/dashboard_it.html:79` — add `min-w-0` defensively (same `[1fr_320px]` grid pattern).
  - `static/design-tokens.css`: `aside.detail-right { min-width: 0; overflow-wrap: break-word; }`; `main { overflow-x: hidden; }`.

## Part 16 — Security hardening (Round E)

- `db.py`: `failed_logins_in_window(ip, username, since_minutes) -> tuple[int, int]` — two indexed `COUNT(*)` queries against `audit_log` filtered by `action='LOGIN_FAILURE'`.
- `app.py` `POST /login` — pre-credential-check throttle gate, three tiers:

  | Layer | Threshold | Action on trip |
  |---|---|---|
  | Per-IP | 5 LOGIN_FAILURE in 15 min | 429 + `Retry-After` header + flash via `_humanize_seconds` |
  | Per-username | 10 LOGIN_FAILURE in 60 min | Same 429 path |
  | Per-IP escalation | 20 LOGIN_FAILURE in 60 min | Emit `credential_brute_force` HIGH alert via `alert_router.dispatch` (IT Telegram + Email) |

- `backup.py` `backup_db()` — after `Connection.backup()` writes the snapshot file, wrap bytes with `Fernet(config.INSIGHT_SHIELD_KEY).encrypt(...)` and write `.db.enc`. Legacy `.db` still readable.
- `backup.py` `restore_db(path)` — detect `.enc` suffix; decrypt before `shutil.copy2`.
- `templates/login.html` — flash-message copy "Too many attempts. Try again in *N* minutes." when the `error` flash category is set.
- Key reuse: existing `INSIGHT_SHIELD_KEY` wraps backups. No separate `BACKUP_KEY`.

## Part 17 — Service Configuration redesign + brand recolor (Round F)

- `db.py`: `get_service_completeness(service_key) -> dict[str, bool]` — required-fields check per service reading `api_keys` + `settings_kv`.
- `app.py` `POST /admin/settings/test/<service>` — four probe variants, **none send a real notification**:
  - `telegram_it` / `telegram_manager` → Bot API `getMe` (validates token only).
  - `gmail` → `smtplib.SMTP(...).starttls().login().quit()` — no message sent.
  - `wazuh` → `GET /agents?limit=1` with basic auth.
- Test rate limit: in-memory dict keyed by `(service, request.remote_addr)`; reject second test within 60s as `429`.
- `app.py` `POST /admin/settings/toggle/<service>` — flip `settings_kv` key `service_active.<service>`. Only `telegram_it`, `telegram_manager` qualify (Gmail / Wazuh / Recipients are not toggleable).
- `notifier.py` — `_service_is_active(svc)` with 5s TTL cache. `send_telegram_it` / `send_telegram_manager` signatures extended with `bypass_toggle: bool = False`. When `not bypass_toggle and not _service_is_active(svc)`, return `SkipResult("service deactivated")`. Test endpoint passes `bypass_toggle=True`.
- `static/design-tokens.css`: new utilities `.service-card`, `.status-row`, `.test-result`, `.toggle-btn[--active|--inactive]`, `.spinner` keyframe. Brand recolor: `--brand-500: #2563eb` (was cyan).
- `templates/_settings_service_config.html` — replace inline sections (Telegram IT/Mgr, Gmail, Wazuh) with the new card layout: status dot + masked summary + Test button + Edit button + (Telegram only) Active toggle. AI Providers and Notification Recipients keep their existing inline shape.

> Round F originally shipped a fifth probe/toggle for a SMS Gateway (Semaphore PH) service, with `notifier.send_sms()`. That service was retired in Round J (2026-07-29, Part 23) — Telegram is now the only toggleable/testable notification channel. The bullets above reflect current state; see Part 23 for the removal record.
- `static/js/settings.js` (NEW) — modal open/close, field population, hold-to-reveal eye, AJAX Test, AJAX Toggle, status-row update, toast.
- `templates/_settings_edit_modal.html` (NEW) — single shared modal partial, populated per-service by JS.
- Audit-log actions added (uppercase-underscored): `SERVICE_TEST_RUN`, `SERVICE_TOGGLE`, `SERVICE_UPDATE`.
- Visual: Raw JSON tab gets Prism Tomorrow dark theme via CDN-with-fallback inline script in `templates/alert_detail.html`.

## Part 18 — Security Audit Report redesign + Playwright PDF (Round G)

- `app.py` `/report` — accept `generated = request.args.get("generated") == "1"`. Call `executive_summary.generate(...)` ONLY when both `from`/`to` present AND `generated=1`. Empty state otherwise.
- `templates/report.html` — hidden `<input type="hidden" name="generated" value="1">` inside the Generate form. Body sections wrapped in `{% if generated %}` with empty-state CTA otherwise. Five id-anchored `<section>` tags: `executive-summary`, `summary-metrics`, `detect-csf`, `alert-details`, `appendix-raw`. Inline JS Expand-all/Collapse-all toggle for Appendix A `<details>`.
- `templates/_report_print.html` (NEW) — cover (`.rb-cover` — 96pt typographic title, navy accent bar, "NIST CSF 2.0 alignment: Detect") + TOC partial driven by Jinja `sections` list (single source: TOC iterates `sections`; section bodies use `id="{{ s.id }}"`).
- `templates/_base.html` — conditional `<link>` for Bureau stylesheet, only on `request.endpoint in ('report', 'report_pdf')`.
- `static/report-bureau.css` (NEW, ~800 lines) — Bureau body + Marker print. Severity palette nuance (pill fg/bg + bar separately). Components: `.rb-h2` section markers (§ 01 through § 05), `.rb-strip` KPI grid, `.rb-csf` chip row, `.rb-sev-bar`/`.rb-sev-row`, `.rb-ip-row`, `.rb-auth__success/failure/bar`, `.rb-threats`, `.rb-alert` per-alert cards, `.rb-lifecycle` pip dots, `.rb-agents` 2-col grid. `@media print` block: paper white, transparent cards with grey borders, `:has()` rule hiding whole appendix when nothing expanded, `details:not([open])` hiding collapsed entries from Ctrl+P, cover at 96pt print / 56px screen.
- `requirements.txt` — add `playwright>=1.45`. One-time install on the deploy VM: `python -m playwright install chromium` (~111MB Chromium Headless Shell).
- `app.py` `/report.pdf` (NEW) — eight-step pipeline:
  1. Same data-fetch as `/report` (`db.get_alerts_by_date_range`, `get_top_threats`, `get_top_attacker_ips`, `get_auth_metrics`, `get_posture_score`, `get_agent_status`).
  2. Same `generated=1` gate — empty PDF (cover + CTA) otherwise.
  3. `render_template("report.html", ..., is_pdf=True)` → HTML string. `is_pdf` branch in template swaps `url_for('static', ...)` to absolute URLs.
  4. Inject `<base href="{{ request.host_url }}">` so relative `/static/*` URLs resolve.
  5. `page.set_content(html, wait_until="networkidle")` — covers Prism CDN+fallback.
  6. `page.evaluate("document.querySelectorAll('details').forEach(d => d.setAttribute('open',''))")` — force-open every disclosure so Appendix A prints fully.
  7. `page.emulate_media(media="print")` then `page.pdf(format="A4", print_background=True, prefer_css_page_size=True, margin={top:"1.5cm", bottom:"1.5cm", left:"1.5cm", right:"1.5cm"})`.
  8. `db.log_audit(action="REPORT_PDF_EXPORT", ...)` + return `Response(pdf_bytes, mimetype="application/pdf", headers={"Content-Disposition": 'attachment; filename="…"' })`.
- NIST CSF 2.0 scope (locked): **Detect only — single anchor**. Cover label and TOC entry both read "NIST CSF 2.0 alignment: Detect (scope of this audit)". Detection-coverage subsections (severity, IPs, auth) and detection-follow-through subsections (ack counts, MTTA, response time) live as H3 inside the single Detect H2.
- Reference: `insightshield/docs/security-audit-report.md` — architecture deep-dive for `/report` + `/report.pdf`.

## Part 19 — Cross-surface parity polish (Round H)

- `templates/dashboard_manager.html` — new filter toolbar with `#status-filter`, `#sev-filter`, `#hide-low-toggle`, `#search` (same IDs as IT). Per-`<li>` `data-severity` / `data-status` / `data-search` attributes.
- `static/ui.js` — filter handler generalised: `const filterTarget = tbody || document.getElementById('alerts-feed')` (variable rename: was `feed`, collided with line-305 `const feed`). `apply()` queries `[data-severity]` (no tag prefix) so it matches both `<tr>` (IT) and `<li>` (manager). Row-click navigation stays scoped to `#alerts-tbody` so clicking a manager `<li>` does not navigate.
- Search-bag expansion (both surfaces) — `data-search` now contains, lowercase-joined: severity + ISO timestamp + `forensic_ts` humanised + device + attacker IP + rule + attack_type + plain_text + status. So `"may 4"`, `"2026-05-04"`, `"high"`, `"resolved"`, attacker IP all match.
- `templates/_alert_row.html` — `sev_short` updated: `'high':'HIGH'` (4 chars, was `HI`/`HGH`). MEDIUM stays `MID`, CRITICAL stays `CRIT`, etc.
- `app.py` `dashboard_it` route — historically injected `sms_service_active = notifier._service_is_active("semaphore")` into context (removed in Round J, Part 23, alongside the SMS service itself).
- `templates/dashboard_it.html` — 5-card KPI strip becomes 4-card when `not sms_service_active` (historical — Round J removed the SMS KPI card outright, so the strip is a fixed 4-card layout today).
- Back-to-Dashboard parity — `templates/alert_detail.html`, `templates/settings.html`, `templates/password_change.html`: replace text link with outlined navy button matching settings styling.
- `templates/report.html` — Appendix A: shortened intro copy; Expand-all/Collapse-all button (inline JS). Two-surface print model:
  - **Ctrl+P (operator-curated)**: `@media print` rule `details:not([open]) { display: none }` hides collapsed entries; `:has()` rule hides whole Appendix `<section>` when no `<details>` is open.
  - **`/report.pdf` (full archive)**: pipeline step 6 force-opens every `<details>` so all entries render regardless of UI state.
- `templates/_report_print.html` — cover screen-mode (when not `@media print`): centered, no full-page break, smaller 56px title vs 96pt print.

---

## Part 20 — Verification checklist (Rounds A–H)

All 14 Part-11 items remain green. The new items below mirror Part 11's style.

- [x] Severity rows do not jitter horizontally when SSE prepends a new row (Round A — `box-shadow` swap)
- [x] Cog dropdown opens on click, closes on click-outside, closes on Escape (Round B)
- [x] Manager sees no Settings entry in the cog dropdown (Round B)
- [x] IT toolbar shows Status + Severity selects and Hide-low toggle, not button group (Round C)
- [x] Alert detail right sidebar pins on scroll on a 1440px viewport (Round C + Round D `min-w-0` fix)
- [x] Login password reveals on hold (`mousedown`) and masks on release/`mouseleave` (Round C)
- [x] Raw JSON tab on `/alert/<id>` wraps long URLs and base64 blobs — no horizontal scroll (Round D)
- [x] `/report` opens with empty document + Generate CTA when no date range chosen — AI chain does not fire (Round G)
- [x] 6th wrong-credential POST `/login` within 15min from one IP returns 429 (Round E)
- [x] `python -m backup` produces a `.db.enc` Fernet-encrypted file; `restore_db` round-trips it back to a working DB (Round E)
- [x] Service Configuration tab shows status dot + Test + Edit + Active toggle for Telegram IT / Telegram Manager (Round F; SMS row removed in Round J)
- [x] SMS service fully removed: no SMS KPI, no Semaphore settings card, brute-force HIGH alert routes via Telegram/Email only (Round J, formerly Round F + H deactivation behavior)
- [x] `/report?generated=1` PDF download produces a multi-page A4 file with cover (page 1 alone), TOC (page 2), then content sections (Round G)
- [x] `/report.pdf` force-opens every Appendix A `<details>`; Ctrl+P from browser respects the operator's open/closed state (Round G + H)
- [x] Manager dashboard filter toolbar has parity with IT (status + severity + hide-low + search) (Round H)
- [x] Search bag on both surfaces matches by severity, timestamp (both ISO and humanised), device, attacker IP, rule, attack_type, description, status (Round H)
- [x] Back-to-Dashboard appears as outlined navy button (not text link) on alert detail / settings / change-password (Round H)
- [x] `v1.4.0-cross-surface-parity` tagged on origin (`Nekko-Innu/InsightShield-SIEM-Dashboard`)

---

## Part 21 — Security Audit Report tweaks (Round I)

Round I is a follow-up round on top of v1.4.0. Scope is strictly the `/report` and `/report.pdf` surfaces plus their feeding AI prompts; **NO** changes to `app.py`, `validator.py`, `config.py`, `_ai_chain.py`, `cache.py`, `db.py`, or any dashboard / login / settings / alert detail template. (This is a statement of Round I's scope **as of 2026-05-12**, not a claim about the current code — `app.py`, `cache.py` and `db.py` have all since been rewritten by the multi-worker refactor.) The sub-parts below give a from-scratch rebuilder enough to reconstruct Round I deterministically — verbatim prompt text, verbatim section markup, exact synonym table, exact commit order.

### Part 21.1 — `executive_summary.py` (commit 1 of 3 core)

Replace lines 25-40 (the original `EXEC_SYSTEM_PROMPT` triple-quoted string) with the verbatim block below. Preserve the six `.format()` placeholders verbatim — any rename raises `KeyError` at the `.format()` call on line 76.

```python
EXEC_SYSTEM_PROMPT = """You are a security report generator for a retail SIEM. Write an Executive Summary for a non-technical retail manager.

CRITICAL CONSTRAINT — your response will be REJECTED if it contains ANY of these words anywhere: firewall, authentication, protocol, payload, exploit, IP address, TCP, NTLM, SMB, SSID, ARP, DHCP, DNS, ICMP, HTTP, FTP, SSH, RDP, buffer overflow.

You MUST substitute with these business-language synonyms:
- exploit / buffer overflow -> "method of attack" or "system weakness"
- firewall -> "network filtering"
- authentication -> "sign-in"
- payload -> "harmful data"
- protocol / TCP / HTTP / FTP / SSH / RDP / SMB / NTLM -> "network connection" or "remote access"
- IP address -> "network address"
- ARP / DHCP / DNS / ICMP / SSID -> "network configuration" or "WiFi name"

Before submitting, re-read your draft and rewrite any sentence that contains a forbidden word using the synonyms above. The forbidden list is enforced by an automated validator that rejects on any match.

Output EXACTLY four paragraphs, separated by a blank line. Each paragraph must start with the label in CAPS followed by a colon and a line break, then 2-3 bullets beginning with "- ":

KEY FINDINGS:
- 2-3 bullets describing what happened during this period: how many detections, the dominant themes, whether anything caused real harm. Plain business language.

CURRENT CHALLENGES:
- 1-2 bullets on what alerts remain unresolved or what monitoring gaps exist (e.g., agent offline). Factual, not alarming.

ACTIONS TAKEN:
- 1-2 bullets on operational follow-through — acknowledgment rate, response time. Positive, reassuring.

TOP RECOMMENDATIONS:
- 3 bullets with practical steps for next month. Use everyday words.

Total length 150-380 words.

Audit period: {date_from} to {date_to}
Total alerts: {total_alerts}
Severity breakdown: {severity_summary}
Top threats: {top_threats}
Posture score: {posture_score} / 100

Only output the four labeled paragraphs. No preamble, no greeting, no signature.
"""
```

Replace `_make_cache_key` at lines 43-50 with the version-sentinel variant:

```python
def _make_cache_key(date_from: str, date_to: str, latest_alert_id: int) -> str:
    """Stable digest used as the exec-summary cache key.

    SHA-1 is fine here — it's a cache key, not a security primitive, and
    the digest length keeps the cache.get_stats() output readable.

    The "v2|" prefix is a prompt-version sentinel: bumping it on prompt
    structure changes (Round I shipped 4 labeled paragraphs replacing the
    earlier free-form prose) invalidates every entry cached under the old
    formula without requiring a Flask restart or manual cache flush.
    """
    raw = f"v2|{date_from}|{date_to}|{latest_alert_id}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]
```

Validator math: this prompt produces 4 paragraphs separated by `\n\n`, satisfying `validate_exec_summary`'s `≥ 2 paragraphs` requirement. Word count is capped at 380 inside the prompt, 20 words under the 400 ceiling. Forbidden-word discipline is enforced by the model via the constraint + synonym map + self-check.

### Part 21.2 — Synonym map reference (load-bearing for prompt discipline)

Both `executive_summary.py:EXEC_SYSTEM_PROMPT` AND `groq_translator.py:SYSTEM_PROMPT` carry the SAME mapping. Substitution behavior consistent across both manager-facing channels.

| Forbidden term(s) (from `config.FORBIDDEN_WORDS`) | Business-language substitute | Notes |
|---|---|---|
| `exploit`, `buffer overflow` | "method of attack" or "system weakness" | Both are core security vocabulary the model reaches for naturally. The substitute preserves the meaning without the jargon |
| `firewall` | "network filtering" | Strip product nouns |
| `authentication` | "sign-in" | User-facing term retail staff use |
| `payload` | "harmful data" | Preserves threat framing without TCP/IP jargon |
| `protocol`, `TCP`, `HTTP`, `FTP`, `SSH`, `RDP`, `SMB`, `NTLM` | "network connection" or "remote access" | Eight network-layer terms collapsed to two register-appropriate substitutes |
| `IP address` | "network address" | Same concept, no acronym |
| `ARP`, `DHCP`, `DNS`, `ICMP`, `SSID` | "network configuration" or "WiFi name" | Network plumbing substituted by their effect |

All 19 entries in `config.FORBIDDEN_WORDS` (= `["IP address", "TCP", "NTLM", "SMB", "protocol", "authentication", "payload", "exploit", "buffer overflow", "firewall", "SSID", "ARP", "DHCP", "DNS", "ICMP", "HTTP", "FTP", "SSH", "RDP"]`) are covered.

### Part 21.3 — `groq_translator.py` (commit 5 of follow-ups, mirror-tightening)

Replace lines 28-37 (the original `SYSTEM_PROMPT` triple-quoted string) with the verbatim block below. The `{forbidden}` placeholder is filled at runtime via `_build_prompt` at line 147 (which does `forbidden_str = ", ".join(config.FORBIDDEN_WORDS)`). The `{device}` placeholder is filled with the alert's `device_name`.

```python
SYSTEM_PROMPT = """You are a security alert translator for non-technical store managers at a supermarket.
Always reply in EXACTLY this format:

WHAT HAPPENED: [2-3 plain sentences, no technical terms]
HOW SERIOUS: [2 sentences explaining risk level simply]
WHAT TO DO: [2-3 sentences with clear action steps]

Maximum 100 words total. Use simple words a 12-year-old can understand.

CRITICAL CONSTRAINT — your response will be REJECTED if it contains ANY of these words anywhere: {forbidden}.

You MUST substitute with these synonyms when the underlying alert involves them:
- exploit / buffer overflow -> "method of attack" or "weakness"
- firewall -> "network filtering"
- authentication -> "sign-in"
- payload -> "harmful data"
- protocol / TCP / HTTP / FTP / SSH / RDP / SMB / NTLM -> "network connection" or "remote access"
- IP address -> "network address"
- ARP / DHCP / DNS / ICMP / SSID -> "network configuration" or "WiFi name"

Before submitting, re-read your three sections and rewrite any sentence that contains a forbidden word. The validator rejects on any case-insensitive substring match. This rule applies at every severity level — including MEDIUM alerts that may escalate to HIGH or CRITICAL on repeat occurrences.

Device name: {device}"""
```

The MEDIUM→HIGH/CRITICAL escalation note is load-bearing: per Round 6, a MEDIUM alert can escalate via frequency badge `(N/M)`. The manager translation cache is keyed by `rule_id`, so the SAME cached translation displays at MEDIUM, at MEDIUM-frequency warning, AND after escalation. A forbidden-word trip at MEDIUM time blocks display through the entire severity transition. The new prompt makes the model aware of this so it treats the constraint as load-bearing regardless of the alert's stated severity.

### Part 21.4 — `templates/report.html` — Methodology section markup (commit 3 of 3 core)

Insert the verbatim block below at `report.html:158`, between `</section>` of `#executive-summary` (line 157) and `{% if alerts %}` (line 159). Placement OUTSIDE the `{% if alerts %}` gate is structural — Methodology must render on zero-alert windows because it explains the audit methodology, not the audit data.

```html
<section id="methodology-scope" class="rb-panel mb-6">
  <header class="rb-h2">
    <span class="rb-h2__marker">§ 02</span>
    <h2 class="rb-h2__title">Methodology &amp; Scope</h2>
    <span class="rb-h2__rule"></span>
  </header>

  <p class="rb-body">
    <strong>Audit Objectives.</strong>
    This report evaluates detection coverage and operational follow-through of the Insight Shield SIEM during the reporting period {{ date_from }} &rarr; {{ date_to }}. It covers every alert Wazuh forwarded over the integration webhook &mdash; both the 31 custom detection rules deployed in <span class="rb-meta">custom_retail_rules.xml</span> and any stock Wazuh rule that fired at level 2 or above.
  </p>

  <p class="rb-body" style="margin-top:14px;">
    <strong>Scope.</strong>
    {{ agents | selectattr('status', 'equalto', 'active') | list | length }} of {{ agents | length }} monitored endpoints were active during the reporting window; remaining endpoints were offline for planned maintenance or were not yet deployed. Alerts were ingested exclusively through the loopback-restricted webhook at <span class="rb-meta">/wazuh-webhook</span>.
  </p>

  <p class="rb-body" style="margin-top:14px;">
    <strong>Methodology.</strong>
    Each Wazuh alert was decoded, enriched with an AI-generated plain-language translation (Groq &rarr; Gemini &rarr; OpenRouter &rarr; static-template fallback chain), and validated by <span class="rb-meta">validator.py</span> against a structure, word-count, and forbidden-term filter. Valid translations were stored in SQLite (WAL mode) with a PHT timestamp. Severity routing followed the matrix in <span class="rb-meta">alert_router.py</span>, including after-hours escalation (business window 08:00&ndash;21:00 PHT). The daily security posture score was calculated by <span class="rb-meta">health_score.py</span> and reset at midnight PHT.
  </p>

  <p class="rb-body" style="margin-top:14px;">
    <strong>Limitations.</strong>
    This audit is scoped exclusively to the NIST CSF 2.0 &mdash; Detect function; Identify, Protect, Respond, Recover, and Govern are out of scope per the project thesis. The report includes only events that matched a Wazuh rule of level 2 or above, which is the integrator's forwarding threshold; endpoint-native events that matched no rule, and rules deliberately silenced at level 0, are excluded. AI-generated summaries are cached for at most one hour; cold-cache generation may add 2&ndash;4 seconds of latency to the first request. Raw Wazuh JSON payloads in Appendix A preserve the original decoder output for independent verification.
  </p>

  <p class="rb-body" style="margin-top:14px;">
    <strong>Framework Alignment.</strong> Aligned with the NIST Cybersecurity Framework 2.0:
  </p>
  <div class="rb-csf" style="margin-top:8px;">
    <span>Identify &mdash; out of scope</span>
    <span>Protect &mdash; out of scope</span>
    <span class="is-on">Detect &middot; in scope</span>
    <span>Respond &mdash; out of scope</span>
    <span>Recover &mdash; out of scope</span>
    <span>Govern &mdash; out of scope</span>
  </div>
</section>
```

After inserting, manually renumber the §-markers in the four sections below it (each is one search-and-replace per existing marker span):

| Section id | Old marker | New marker | Approx line after insert |
|---|---|---|---|
| `summary-metrics` | `§ 02` | `§ 03` | ~221 |
| `detect-csf` | `§ 03` | `§ 04` | ~301 |
| `alert-details` | `§ 04` | `§ 05` | ~494 |
| `appendix-raw` | `§ 05` | `§ 06` | ~633 |

The `<h2>` title text for "Appendix A — Raw Wazuh JSON" keeps the "A" letter — only the §-marker shifts.

### Part 21.5 — `templates/report.html` — Highlights paragraph

Insert the verbatim block below inside `#executive-summary`, AFTER the AI-text-or-fallback `{% endif %}` at line 156 and BEFORE `</section>` at line 157. Placement OUTSIDE the `{% if exec_summary_text %}` branches is structural — the Highlights line must render regardless of whether the AI chain returned `AI_CHAIN_EXHAUSTED` or normal text.

```html
{# Round I: Highlights paragraph — always renders regardless of whether
   the AI chain returned exhausted-sentinel or normal text. Cites the
   agent-coverage figure directly from the `agents` context list. #}
<p class="rb-body" style="margin-top:10px;">
  <strong>Highlights.</strong>
  {{ agents | selectattr('status', 'equalto', 'active') | list | length }} of {{ agents | length }} monitored endpoints reported continuously through the period.
</p>
```

### Part 21.6 — `templates/report.html` — Cache attribution conditional

Replace the current single `<p>` attribution line at `report.html:145-147`:

```html
<p class="mt-3 text-xs text-slate-400">
  Generated by {{ exec_summary_provider }}.
</p>
```

with the conditional version:

```jinja
{# Round I follow-up: distinguish cache-hit attribution from fresh
   AI-generation attribution. The chain returns provider_used="cache"
   on hits to the in-memory _exec_cache (cache.py 1h TTL). Naively
   rendering "Generated by cache" reads as if cache itself is an AI
   provider — misleading. The cache only ever stores AI-validated
   output, so a cache hit IS still AI-generated content, just
   memo-served. #}
<p class="mt-3 text-xs text-slate-400">
  {% if exec_summary_provider == 'cache' %}
    Served from cache (originally AI-generated, 1h TTL).
  {% else %}
    Generated by {{ exec_summary_provider }}.
  {% endif %}
</p>
```

### Part 21.7 — `templates/_report_print.html` — Sections list

Insert at INDEX 1 (between `executive-summary` and `summary-metrics`) of the `{% set sections = [...] %}` list at lines 20-26:

```jinja
{% set sections = [
  {"id": "executive-summary", "label": "Executive Summary"},
  {"id": "methodology-scope", "label": "Methodology & Scope"},
  {"id": "summary-metrics",   "label": "Summary Metrics"},
  {"id": "detect-csf",        "label": "NIST CSF 2.0 — Detect"},
  {"id": "alert-details",     "label": "Alert Details"},
  {"id": "appendix-raw",      "label": "Appendix A — Raw Wazuh JSON"}
] %}
```

The TOC partial iterates `sections`, so the cover-page TOC auto-renders 6 entries after this change. The `id` strings here must exactly match the `<section id="...">` strings in `report.html` (gate Part 22 item 3).

### Part 21.8 — `static/design-tokens.css` — raw-JSON cascade fix (commit 7 of follow-ups)

Replace the Round D `pre.raw-json` rule at lines 256-261 with the extended version that also targets the inner `<code>`:

```css
pre.raw-json,
pre.raw-json code {
  white-space: pre-wrap !important;
  overflow-wrap: anywhere !important;
  word-break: break-word;
  tab-size: 2;
}
pre.raw-json code {
  display: block;
  max-width: 100%;
}
```

CSS specificity analysis (why `!important` is needed): Prism's CDN stylesheet ships `code[class*="language-"] { white-space: pre; }` — specificity 11 (one attribute selector + one element). `pre.raw-json code` is also specificity 11 (one class + one element). When specificity ties, cascade order decides. Prism's `<link>` loads after `design-tokens.css` (the conditional Bureau stylesheet load on `/report` puts Prism last via its inline-CDN-with-fallback `<script>` shim). So Prism wins without `!important`.

`display: block; max-width: 100%` ensures the inner `<code>` has deterministic box geometry. Prism wraps tokens in `<span class="token ...">` and may apply `display: inline-block` or other inline-layout changes; the block + max-width pair guarantees the `<code>` cannot grow past its parent regardless of what Prism does.

Single rule fixes both raw-JSON surfaces in the codebase: `templates/alert_detail.html:292` (Round D Raw JSON tab) AND `templates/report.html:668` (Round G Appendix A entries).

### Part 21.9 — `templates/_base.html` — In-app footer (commit 12 of bumps)

Replace lines 171-172:

```html
<span>Build 0.1.0</span>
<span>Insight Shield v1.0 &middot; DLSL-IT Cybersecurity Capstone</span>
```

with the v1.4.1 strings:

```html
<span>Build 0.4.1</span>
<span>Insight Shield v1.4.1 &middot; DLSL-IT Cybersecurity Capstone</span>
```

This closes a long-standing drift: the footer text was the Round 1 protected-decision spec and stayed frozen through v1.1, v1.2, v1.3, v1.4 releases. Future releases should bump these two spans alongside the git tag.

### Part 21.10 — Commit sequence (14 commits over 2026-05-12)

| # | Commit | File | Stage |
|---|---|---|---|
| 1 | `3d894c4` | `executive_summary.py` | Core — prompt restructure + cache key v2 sentinel |
| 2 | `2c116c4` | `templates/_report_print.html` | Core — sections list entry at index 1 |
| 3 | `c1b5df6` | `templates/report.html` | Core — Methodology section + §-marker renumber + Highlights paragraph |
| 4 | `7b30df8` | `executive_summary.py` | Follow-up — synonym map + self-check (live-AI fix after Groq returned "exploit") |
| 5 | `e0eafe8` | `groq_translator.py` | Follow-up — mirror-tighten with escalation note |
| 6 | `d82b6b3` | `templates/report.html` | Follow-up — cache attribution conditional |
| 7 | `dd7852f` | `static/design-tokens.css` | Follow-up — raw-JSON cascade fix |
| 8 | `9e8399b` | `README.md` | Docs — status header + Round I changelog row |
| 9 | `cf37698` | `SYSTEM_DESIGN.md` | Docs — §16.9 v1 (later expanded) |
| 10 | `0606259` | `REBUILD_SPEC.md` | Docs — Part 21 v1 (later expanded — this file's current state) |
| 11 | `6949d44` | `DEPLOYMENT.md` | Docs — status bump |
| 12 | `e3704a3` | `templates/_base.html` | UI — in-app footer bump (closes v1.0 drift) |
| 13 | `9668505` | `insightshield/docs/security-audit-report.md` | Docs — §16 delta layer |
| 14 | `4ae3b5c` | `README.md` | Docs — Highlights detail + architecture-tree drift fixes |

**Tag**: `v1.4.1-audit-methodology` annotates commit `e3704a3` (the last code-state-affecting commit). The two doc-detail commits (`9668505`, `4ae3b5c`) sit past the tag intentionally — doc-only changes don't justify re-tagging.

### Part 21.11 — Pre-existing bugs Round I surfaced (out of scope)

Round I's diagnostic work surfaced two pre-existing bugs that are explicitly out of scope but flagged for future cleanup rounds:

1. **`RULE_TO_TEMPLATE` mapping drift** at `groq_translator.py:81-92`. Rule_id `100020` (ARP Spoofing) maps to `wifi` template (should be `arp_mitm`); rule_id `100030` (Bulk File Rename) maps to `arp_mitm` (no good template — ransomware-adjacent); rule_id `ISH-CBF-001` (Round E credential brute-force) has no entry and falls through to default `rdp_bruteforce`. Only matters when AI chain exhausts; with AI working (primary path), users see AI's dynamic output regardless of rule_id.

2. **Round E credential_brute_force alerts have NULL `it_recommendation`**. The brute-force escalation path in `app.py` builds the alert row directly and calls `alert_router.dispatch` — does NOT go through `wazuh_receiver.process_alert()`, which is the only path that spawns the fire-and-forget IT recommender thread. Round I backfilled alert id=8 via a one-off diagnostic; future brute-force alerts will repeat the issue.

Custom rule count is pinned by `tests/test_mitm_rules.py::test_rule_count`, not restated here — it was 27 at Round I and is 31 custom (plus 3 stock arpwatch overrides) as of 2026-09-12, and every doc that hand-copied the old figure went stale silently. Read the test. MITRE ATT&CK coverage metric explicitly out of scope — no real rule-to-MITRE mapping in code today.

---

## Part 22 — Verification checklist (Round I)

- [x] Body §-markers in strict sequence — exactly `§ 01` through `§ 06` in `templates/report.html` after the renumber
- [x] TOC count — `_report_print.html` `sections` list has 6 entries
- [x] TOC ↔ body cross-check — every `{"id": "..."}` in the sections list has exactly one matching `id="..."` body anchor in `report.html`
- [x] Cache key versioned — `"v2|"` prefix present in `_make_cache_key` digest input
- [x] Forbidden words only in legitimate locations — every `config.FORBIDDEN_WORDS` entry appearing in either prompt sits inside the constraint declaration or the synonym map, not in instructional prose the model might echo
- [x] Validator non-regression — captured live 4-paragraph AI output passes `validate_exec_summary` (≥ 2 paragraphs split on `\n\n`, 150-400 words, no forbidden words)
- [x] AI chain proven end-to-end — `it_recommender.recommend()` produces valid 735-char output for alert id=8 via Groq, persists to DB, validator passes
- [x] Untouched surfaces **as of Round I** — `git diff` confined to: `executive_summary.py`, `groq_translator.py`, `templates/report.html`, `templates/_report_print.html`, `static/design-tokens.css`, `templates/_base.html`, plus docs. **Zero** changes in `app.py`, `validator.py`, `config.py`, `_ai_chain.py`, every dashboard / login / settings template. (Historical scope record — several of those files have been rewritten in later rounds.)
- [x] Manual web view — `/report?generated=1` renders 6 sections in order: cover → TOC (6 entries) → §01 Exec Summary with 4 labeled paragraphs + Highlights line → §02 Methodology with 5 blocks + CSF chips (Detect filled) → §03 Summary Metrics → §04 Detect → §05 Alert Details → §06 Appendix A
- [x] Manual empty range — Methodology section still renders on a date window with zero alerts (placement outside `{% if alerts %}` is the structural fix)
- [x] Manual Ctrl+P print preview — §02 lands cleanly with no orphan headers, no overlap with §03
- [x] Manual `/report.pdf` download — PDF cover → TOC → exec + Highlights → Methodology → §03 onward, Appendix A force-opened per Round G pipeline step 6
- [x] Manual no-regression — `/dashboard/it`, `/dashboard/manager`, `/alert/3`, `/admin/settings?tab=service`, `/login` all render identically to v1.4.0
- [x] Raw-JSON wrap — Appendix A `<details>` entries with long URLs / base64 / device paths wrap inside the card boundary; alert-detail Raw JSON tab continues to wrap as in Round D
- [x] Cache attribution UX — when `exec_summary_provider == 'cache'`, attribution reads `Served from cache (originally AI-generated, 1h TTL).` instead of `Generated by cache.`
- [x] In-app footer — `Build 0.4.1` appears on every rendered page (was stuck at `Build 0.1.0` since v1.0)
- [x] `v1.4.1-audit-methodology` tagged on origin (`Nekko-Innu/InsightShield-SIEM-Dashboard`)

---

## Part 23 — SMS/Semaphore retirement (Round J)

Round J removes the SMS notification channel entirely. Telegram (IT group + Manager bot) plus Gmail SMTP backup are the only outbound notification channels going forward. Scope: `notifier.py`, `app.py` (Settings test/toggle endpoints, `dashboard_it` route), `templates/_settings_service_config.html`, `templates/dashboard_it.html`, `db.py` (`get_service_completeness`), `config.py` (env var seeds), `DEPLOYMENT.md`, `SYSTEM_DESIGN.md`.

- `notifier.py` — remove `send_sms`, `get_sms_balance`, `SMS_TEMPLATES`, `build_sms`, `_enforce_limit` (155-char truncation), and the `sms:<device>` rate-limit bucket in `rate_limit.py`. `_service_is_active("semaphore")` call sites removed.
- `app.py` `POST /admin/settings/test/<service>` — drop the `semaphore` probe branch (`get_sms_balance()`). Four probes remain: `telegram_it`, `telegram_manager`, `gmail`, `wazuh`.
- `app.py` `POST /admin/settings/toggle/<service>` — drop `semaphore` from the qualifying set. Only `telegram_it` / `telegram_manager` remain toggleable.
- `app.py` `dashboard_it` route — remove `sms_service_active` context injection.
- `templates/dashboard_it.html` — KPI strip becomes a fixed 4-card layout (Open alerts, 24h MTTA, Active agents, `<provider>` used). No conditional SMS card.
- `templates/_settings_service_config.html` — remove the SMS Gateway (Semaphore PH) card entirely. Telegram IT/Mgr, Gmail, Wazuh cards remain; AI Providers and Notification Recipients keep their existing shape.
- `db.py` `get_service_completeness` — drop the `semaphore` service key.
- `api_keys` table — existing `service='semaphore'` rows (API key) are orphaned data, not actively read. No migration framework, so no automated cleanup; a manual `DELETE FROM api_keys WHERE service='semaphore'` is optional housekeeping, not required for correctness.
- `alert_router.py` — the `credential_brute_force` HIGH-alert escalation path (Round E) now dispatches Telegram + Email only, no SMS leg.
- `MANAGER_PHONE` / `IT_ADMIN_PHONE` — remain in the Notification Recipients settings sub-section as contact-record fields (still displayed, still editable) but are no longer read by any dispatch path. Standing directive at the top of this file updated to reflect this.
- `config.PROVIDER_TEMPLATES` and `config.DEFAULT_AI_PROVIDERS` are untouched — this round does not touch the AI provider chain, only the non-AI notification service list.
- Docs updated in the same round: `DEPLOYMENT.md` (drop Semaphore prereq row + `.env` seed block), `SYSTEM_DESIGN.md` (drop SMS from architecture diagram, tech stack, routing matrix, KPI table, rate-limit buckets, protected-decisions table, §7.6 SMS templates section).

## Part 24 — Verification checklist (Round J)

- [x] `grep -ri semaphore insightshield/*.py` returns no hits outside historical comments/docs
- [x] `notifier.py` has no `send_sms`, `get_sms_balance`, `SMS_TEMPLATES` symbols
- [x] `/admin/settings?tab=service` shows exactly 4 service cards: Telegram IT, Telegram Manager, Gmail, Wazuh — no SMS Gateway card
- [x] IT dashboard KPI strip renders 4 cards unconditionally — no SMS credits card, no layout gap
- [x] `credential_brute_force` HIGH alert (Round E throttle escalation) still reaches Telegram + Email with SMS leg absent — no exception raised by a missing `send_sms` call site
- [x] Notification Recipients sub-section still shows Manager Phone / IT Admin Phone / IT Admin Email fields (contact-record only) and still saves correctly
- [x] No regression on `/dashboard/it`, `/dashboard/manager`, `/report`, `/admin/settings?tab=ai-providers` — AI provider chain unaffected (9/9 pytest suite green, 2026-07-30)

---

**Spec version**: 2.3 (extends Parts 0–22 with Part 23–24 Round J SMS/Semaphore retirement)
**Application version**: Insight Shield v1.5.0 (Build 0.5.0)
**Last updated**: 2026-07-29 (Round J — SMS/Semaphore channel retired, Telegram-only notifications)
**Revision history**: v1.0 (2026-04-29, Parts 0–11 v1.0.0 baseline) → v2.0 (2026-05-10, Parts 12–20 Rounds A–H) → v2.1 (2026-05-12, Parts 21–22 Round I initial coverage) → v2.2 (2026-05-12, Part 21 expanded with verbatim content for from-scratch rebuild) → v2.3 (2026-07-29, Parts 23–24 Round J SMS/Semaphore retirement).
