# Security Audit Report — Architecture & Design

**Status:** baseline through Round G stage G3 (2026-05-10); Round H polish (2026-05-10) and Round I tweaks (2026-05-12) layered on top — see §16 for the delta.
**Scope:** complete reference for the `/report` and `/report.pdf` features in Insight Shield. Covers visual layout, data flow, code map, performance characteristics, and verification.
**Audience:** future maintainers (the thesis panel, anyone extending the report after the capstone defence, anyone porting the pattern to another Flask SIEM).
**Reading order:** §§ 1–15 describe the v1.3.0 (Round G) baseline. §16 documents the Round H + Round I deltas on top. To reconstruct the current v1.4.1 state from scratch, read §§ 1–15 first, then apply §16's diff list.

---

## 1. What it is

A two-surface security audit report:

1. **`/report`** — interactive HTML view used inside the dashboard for browsing the audit. Loaded only after an explicit Generate click; bare visits show an empty-state CTA. Both `IT_ADMIN` and `Manager` can access it.
2. **`/report.pdf`** — server-rendered downloadable PDF of the same content, driven by a headless Chromium (Playwright) under the hood. Same gating, same data, same visual treatment but optimised for paged-media output (cover, TOC, page-numbered footer, Appendix A force-opened).

Both routes share:
- The same `templates/report.html` template (with conditional `is_pdf` branches handled at render time).
- The same data-prep helpers in [`db.py`](../db.py) and [`executive_summary.py`](../executive_summary.py).
- The same `?generated=1` gate that defers AI-chain spend until the user explicitly chose a date range and clicked Generate.

The report is **anchored on NIST CSF 2.0 — Detect** and only Detect. The thesis explicitly scopes Insight Shield as a detection-focused SIEM; the other five CSF 2.0 functions (Identify, Protect, Respond, Recover, Govern) are documented as out-of-scope on the cover page so the report reads as honest about its coverage rather than a half-empty framework checklist.

---

## 2. NIST CSF 2.0 alignment philosophy

| CSF 2.0 function | Status | Why |
|---|---|---|
| **Detect** | ✅ Anchor — the only section the report claims | Insight Shield's whole value proposition is detection. Alerts, severity distribution, attacker IPs, agent sensor coverage, authentication detection — all live here. |
| Identify | ❌ Out of scope | No asset inventory or attack-surface enumeration is collected. |
| Protect | ❌ Out of scope | No compliance-control state or hardening data is collected. |
| Respond | ❌ Out of scope (operational data lives under Detect) | The acknowledgment / resolution workflow is real, but it sits *under Detect* as **Detection follow-through (operational metrics)** rather than as a separate Respond section. Single CSF anchor keeps the thesis claim defensible. |
| Recover | ❌ Out of scope | No restoration / availability data collected. |
| Govern | ❌ Out of scope (audit log is supporting evidence, not framing) | The `audit_log` table is referenced in the report ("see `/admin/settings?tab=audit` for chain-of-custody") but doesn't get its own CSF section. |

Cover page and TOC both say "**NIST CSF 2.0 alignment: Detect (scope of this audit)**" verbatim — the visible thesis claim.

---

## 3. Visual structure (rendered output)

### 3.1 Browser view at `/report?from=...&to=...&generated=1`

```
┌────────────────────────────────────────────────────────┐
│ [global header: logo · Report · Cog · Role badge]     │ ← from _base.html
├────────────────────────────────────────────────────────┤
│ Insight Shield — Security Audit Report      [Print]   │ ← screen-only chrome
│ Date Range: 2026-05-01 → 2026-05-31                   │   (.no-print, hidden in PDF)
│ Generated: May 9, 2026 @ 23:55:59.218                 │
│                                                        │
│ ▶ Adjust date range          (collapsed disclosure)   │ ← screen-only toolbar
│                                                        │
│ ┌──────────────────────────────────────────────┐     │
│ │ ▌ INSIGHT SHIELD SIEM                        │     │ ← Cover card (also in PDF)
│ │   Security Audit Report                      │     │
│ │   Reporting period: ...                      │     │
│ │   NIST CSF 2.0 alignment: Detect (...)       │     │
│ └──────────────────────────────────────────────┘     │
│ ┌──────────────────────────────────────────────┐     │
│ │ Table of Contents                            │     │ ← TOC card
│ │   1. Executive Summary                       │     │
│ │   2. Summary Metrics                         │     │
│ │   3. NIST CSF 2.0 — Detect                   │     │
│ │   4. Alert Details                           │     │
│ │   5. Appendix A — Raw Wazuh JSON             │     │
│ └──────────────────────────────────────────────┘     │
│ <section id="executive-summary">                      │
│   <h2>Executive Summary</h2>                         │
│   ...AI-generated 2-3 paragraphs...                   │
│ </section>                                             │
│ <section id="summary-metrics">                        │
│   <h2>Summary Metrics</h2>                            │
│   [7-card KPI grid]                                  │
│ </section>                                             │
│ <section id="detect-csf">                             │
│   <h2>NIST CSF 2.0 — Detect</h2>                     │
│   <h3>Detection coverage</h3>                         │
│     <h4>Agent sensor coverage</h4>                    │
│     <h4>Alerts by severity</h4>                       │
│     <h4>Top attacker IPs</h4>                         │
│     <h4>Authentication detection</h4>                 │
│     <h4>Vulnerability detection</h4> (conditional)    │
│   <h3>Detection follow-through (operational metrics)</h3>
│     ...                                                │
│ </section>                                             │
│ <section id="alert-details">                          │
│   <h2>Alert Details</h2>                              │
│   [per-alert article cards]                           │
│ </section>                                             │
│ <section id="appendix-raw">                           │
│   <h2>Appendix A — Raw Wazuh JSON</h2>                │
│   [collapsed <details> per alert]                     │
│ </section>                                             │
└────────────────────────────────────────────────────────┘
```

### 3.2 PDF view at `/report.pdf?from=...&to=...&generated=1`

A4 portrait, 1.5cm side margins, 1.8cm bottom margin (room for footer):

```
Page 1 — Cover
  [navy --brand-500 accent stripe]
  INSIGHT SHIELD SIEM
  Security Audit Report
  Reporting period: 2026-05-01 → 2026-05-31
  Generated: ...
  NIST CSF 2.0 alignment: Detect (scope of this audit). ...
  Confidential — internal use. Generated by admin (IT_ADMIN).
  [footer: "Page 1 of N"]

Page 2 — Table of Contents
  1. Executive Summary
  2. Summary Metrics
  3. NIST CSF 2.0 — Detect
  4. Alert Details
  5. Appendix A — Raw Wazuh JSON
  [footer: "Page 2 of N"]

Page 3 — Executive Summary
  Heading with brand-color underline.
  AI-generated 2-3 paragraphs OR static fallback if AI chain exhausted.

Page 4 — Summary Metrics
  Total / Acknowledged / Resolved / Avg FK / Avg Response / Posture / Top 3 Threats / AI Providers

Page 5 — NIST CSF 2.0 — Detect
  Brief intro paragraph.
  H3 Detection coverage — top hairline divider
    H4 Agent sensor coverage  (with dotted bottom rule)
    H4 Alerts by severity     (with dotted bottom rule)
    H4 Top attacker IPs       (with dotted bottom rule)
    H4 Authentication detection (with dotted bottom rule)
    H4 Vulnerability detection (conditional)
  H3 Detection follow-through (operational metrics)
    Single paragraph with ack/resolved counts + MTTA + audit-log pointer.

Pages 6-N-2 — Alert Details
  Per-alert articles flowing across pages naturally.
  Each card: severity badge, device, timestamp, AI translation, forensic detail, lifecycle.
  Thin grey bottom rule between alerts. No page-break-inside:avoid (long blocks
  span pages, multiple alerts share a page where they fit).

Pages N-1 to N — Appendix A — Raw Wazuh JSON
  Per-alert <details> force-opened so payloads render.
  Pretty-printed JSON in black-on-white with thin grey border.
  Long payloads span pages naturally.
```

### 3.3 Heading hierarchy (visual specificity, top to bottom)

| Level | Visual treatment | Example |
|---|---|---|
| `h1` (cover only) | 28pt bold, no underline | "Security Audit Report" |
| `h2` (top-level section) | 16pt bold, **2px solid navy underline**, page-break-before:always | "NIST CSF 2.0 — Detect" |
| `h3` (subsection cluster) | 13pt bold, **1px solid grey top hairline**, extra top margin | "Detection coverage" |
| `h4` (subsection leaf) | 11pt bold, slight letter-spacing, dotted bottom rule on parent | "Agent sensor coverage" |
| Body `p` | 10pt, 1.5 line-height, widows/orphans:3 | — |

This is a **3-tier structural divider system**: thick navy underline (H2) → solid grey hairline (H3) → dotted hairline (H4 wrappers). The visual weight tracks the heading hierarchy in HTML.

---

## 4. Routes (entry points)

### 4.1 `/report` — HTML view

| Aspect | Value |
|---|---|
| Defined at | [`report()` in web/blueprints/reports.py](../web/blueprints/reports.py) |
| Auth | `@login_required`. Open to both `IT_ADMIN` and `Manager` (no role gate). |
| Method | `GET` |
| Query params | `from=YYYY-MM-DD` (default: 7 days ago), `to=YYYY-MM-DD` (default: today), `generated=1` (the gate flag, set by the Generate form) |
| Audit log | Always emits `REPORT_VIEW` with `details={"from":..., "to":..., "generated":bool}` regardless of the gate flag |
| Short-circuit | When `generated != "1"`, returns an empty document with the CTA card. Skips all DB queries and the AI chain. |
| Full render | When `generated == "1"`, runs 6 DB SELECTs + the AI executive-summary chain, then renders the full template. |

### 4.2 `/report.pdf` — Playwright PDF download

| Aspect | Value |
|---|---|
| Defined at | [`report_pdf()` in web/blueprints/reports.py](../web/blueprints/reports.py) |
| Auth | `@login_required`. Same as `/report`. |
| Method | `GET` |
| Query params | Identical to `/report` |
| Audit log | Emits `REPORT_PDF_EXPORT` (distinct from `REPORT_VIEW`) so PDF downloads are visibly separable in the audit trail |
| Render path | Synchronous Playwright API: launch headless Chromium → `set_content(html)` → `page.evaluate` to force-open `<details>` → `emulate_media("print")` → `page.pdf()` |
| Output | A4, 1.5cm margins (1.8cm bottom for footer), `print_background=True` (preserves navy accents + severity pill fills) |
| Filename | `insightshield-audit-{date_from}_{date_to}.pdf` (e.g., `insightshield-audit-2026-05-01_2026-05-31.pdf`) |

### 4.3 `/admin/settings?tab=audit` — supporting surface

Not part of the report module per se, but referenced from the **Detection follow-through** subsection as the canonical chain-of-custody pointer. Reviewers can cross-reference report timestamps against per-actor audit events there.

---

## 5. Data sources

### 5.1 Database helpers (all in [`db.py`](../db.py))

| Helper | Returns | Role in the report |
|---|---|---|
| [`get_alerts_by_date_range(date_from, date_to)`](../db.py) | `list[dict]` of full alert rows | Powers Alert Details (per-alert articles) and Appendix A (raw JSON) |
| [`get_report_summary(date_from, date_to)`](../db.py) | dict with `total`, `severity` breakdown, `avg_fk`, `avg_response`, `providers`, `ack_count`, `resolved_count` | Drives the 7-card Summary Metrics grid + the Detection follow-through paragraph |
| [`get_top_threats(date_from, date_to, n=3)`](../db.py) | `list[dict]` of `{attack_type, count}` | Top 3 Threats card + AI executive-summary prompt input |
| [`get_top_attacker_ips(date_from, date_to, n=5)`](../db.py) | `list[dict]` of `{ip, count}` | Top attacker IPs subsection inside Detection coverage |
| [`get_auth_metrics(date_from, date_to)`](../db.py) | dict with `success`, `failure` counts | Authentication detection subsection |
| [`get_posture_score(date_from, date_to)`](../db.py) | `int` 0-100 | Posture Score KPI card; also fed to the AI prompt |
| [`get_latest_alert_id_in_range(date_from, date_to)`](../db.py) | `int` (highest alert id, or 0) | Cache invalidation key for the AI executive summary |
| `get_agent_status()` (defined in [wazuh_api.py](../wazuh_api.py)) | `list[dict]` | Agent sensor coverage subsection (active/inactive list with status dots) |

All helpers are stateless reads — no side effects, safe to call repeatedly, suitable for caching at higher layers.

### 5.2 AI executive summary

Module: [`executive_summary.py`](../executive_summary.py) (104 lines).

| Step | What happens |
|---|---|
| 1. Format prompt | `EXEC_SYSTEM_PROMPT` template at [executive_summary.py:25](../executive_summary.py#L25) is substituted with `date_from`, `date_to`, `total_alerts`, `severity_summary`, `top_threats`, `posture_score` |
| 2. Compute cache key | `_make_cache_key(date_from, date_to, latest_alert_id)` returns first 16 chars of SHA-1. Cache invalidates whenever a new in-range alert lands (latest id changes) |
| 3. Run AI chain | `_ai_chain.run_chain()` walks active providers (Groq, Google Gemini, etc.) until one validates against `validator.validate_exec_summary` (150-400 words, ≥2 paragraphs, no banned jargon) |
| 4. Cache hit / miss | Returns `(text, provider)` where `provider` is `"cache"` for hits, the provider's label for fresh generation, or `"AI_CHAIN_EXHAUSTED"` if every provider failed |
| 5. Template handling | `report.html` checks the provider sentinel and renders a static fallback paragraph instead of the exhausted-chain marker |

Cache TTL: **1 hour** via `cache.get_exec_summary_cached` / `set_exec_summary_cached`. Combined with the `latest_alert_id` cache key, this means a fresh in-range alert forces re-generation on the next /report visit but otherwise the AI provider isn't called repeatedly for the same window.

### 5.3 Why the Generate gate matters

Before Round G, [`report()`](../web/blueprints/reports.py) called `executive_summary.generate(...)` **on every page load**, even bare `/report` visits with no params. This burned AI provider quota on every dashboard back-link traversal and bookmark hit. Round G's `?generated=1` gate (the `generated` gate in [`report()`](../web/blueprints/reports.py)) short-circuits before the AI chain is touched, preserving provider quota for explicit user-driven generation.

---

## 6. Template structure

### 6.1 [`templates/_base.html`](../templates/_base.html) (page shell)

What it loads (in order, in `<head>`):

1. **Vendored Tailwind** — `static/vendor/tailwindcss-3.4.3.min.js`, loaded directly via `url_for('static', ...)`. This was originally the Tailwind Play CDN with an `onerror` handler that `document.write()`'d the local copy on failure; the CDN is gone entirely now, because it could serve arbitrary script into an admin console and the CSP had to allow-list it. `nginx/insightshield.conf` sets `script-src 'self' 'unsafe-inline'`, so a CDN load would be blocked outright anyway. See `static/vendor/VERSIONS.md`.
2. **`design-tokens.css`** ([static/design-tokens.css](../static/design-tokens.css)) — the global stylesheet, linked on every page. Carries:
   - `--brand-*` navy blue palette (Round F)
   - `--surface-*`, `--sev-*`, `--status-*` semantic tokens
   - the Round G `@media print { ... }` block — covered in §7
3. **`report-bureau.css`** ([static/report-bureau.css](../static/report-bureau.css)) — linked **conditionally**, only when `request.endpoint` is `reports.report` or `reports.report_pdf`, so the rest of the dashboard isn't shipped the report-only CSS. Layered on top of `design-tokens.css`, never replacing it — see §7.3.
4. **Tailwind config inline `<script>`** — wires the `--brand-*` CSS custom properties to Tailwind utilities like `bg-brand-500`, `text-brand-700`
5. `{% block head_extra %}{% endblock %}` — children inject Prism.js, Inter font, etc.

> **Critical implementation detail**: print and responsive rules only fire from a stylesheet that is actually linked. Round G stage G2's print rules silently did nothing because they were written to a `static/style.css` that no template ever loaded; commit `2280766` moved them into `design-tokens.css` and `style.css` has since been deleted. Add global print/responsive rules to `design-tokens.css`, and report-only ones to `report-bureau.css`. `templates/_base.html` links both.

### 6.2 [`templates/report.html`](../templates/report.html)

The orchestrator. Conditionally renders cover/TOC/body or the empty-state CTA based on `generated`.

Key structure, in source order. (Named blocks rather than line numbers — this file grows every round; grep the marker in the left column.)

| Marker | Block | Purpose |
|---|---|---|
| `{% block head_extra %}` | head extras | Prism.js core + JSON grammar + **Tomorrow dark theme** (Round F → carried into G2) |
| `<div class="no-print">` | screen-only chrome | H1 + Print / Download PDF buttons + date meta. Wrapped so PDF output uses the cover as title |
| `<details class="no-print ...">` | toolbar | Date range picker + hidden `<input name="generated" value="1">` + Generate submit |
| `{% if not generated %}` | CTA | Empty-state card; renders when bare /report is visited |
| `{% else %}` | — | Branch into the document body |
| `{% include "_report_print.html" %}` | cover + TOC partial | §6.3 |
| `<section id="executive-summary">` | § 01 | AI-generated narrative or static fallback, plus the Highlights paragraph (§16.3.4) |
| `<section id="methodology-scope">` | § 02 | Round I addition. Deliberately **outside** the `{% if alerts %}` gate — see §16.2.1 |
| `{% if alerts %}` | gate | The four data-driven sections below only render when the range has alerts |
| `<section id="summary-metrics">` | § 03 | 7-card KPI grid |
| `<section id="detect-csf">` | § 04 | The big NIST CSF 2.0 — Detect anchor; contains the `_has_va` conditional (§14 item 5) |
| `<section id="alert-details">` | § 05 | Per-alert article cards |
| `<section id="appendix-raw">` | § 06 | Per-alert raw-JSON `<details>` + the Round H expand-all/collapse-all script |
| `{% else %}` | — | "No alerts found" empty-state for in-range zero-alert windows |
| `{% endif %}{# alerts #}{% endif %}{# generated #}` | — | Both wrappers close |

### 6.3 [`templates/_report_print.html`](../templates/_report_print.html)

Cover + TOC partial. Included once by `report.html` when `generated=1`.

Structure:

```jinja
{# Sections list — single source of truth. The TOC iterates this list,
   the body uses literal IDs that match each entry. Drift is impossible
   because the verification gate G2.3 grep-loop checks every TOC href
   has a matching id="..." in the body. #}
{% set sections = [
  {"id": "executive-summary", "label": "Executive Summary"},
  {"id": "summary-metrics",   "label": "Summary Metrics"},
  {"id": "detect-csf",        "label": "NIST CSF 2.0 — Detect"},
  {"id": "alert-details",     "label": "Alert Details"},
  {"id": "appendix-raw",      "label": "Appendix A — Raw Wazuh JSON"}
] %}

<section class="report-cover ...">
  <div style="background-color: var(--brand-500);"></div>  {# accent bar #}
  <h1>Security Audit Report</h1>
  <p>Reporting period: ... → ...</p>
  <p>NIST CSF 2.0 alignment: Detect (scope of this audit). ...</p>
  <p>Confidential — internal use. Generated by {{ user.username }} ({{ user.role }}).</p>
</section>

<section class="report-toc ...">
  <h2>Table of Contents</h2>
  <ol>{% for s in sections %}<li><a href="#{{ s.id }}">{{ s.label }}</a></li>{% endfor %}</ol>
</section>
```

Two `<section>` elements (`.report-cover` and `.report-toc`). Both get `page-break-after: always` + `height: 100vh` in `@media print` so each fills exactly one page in the PDF.

---

## 7. Stylesheets

### 7.1 [`static/design-tokens.css`](../static/design-tokens.css) (704 lines)

Three logical zones:

| Lines | Zone | Role |
|---|---|---|
| 1-200 | Tokens + base resets | `--brand-*`, `--surface-*`, `--sev-*`, `--status-*`, `body { font-family: ... }`, `.skip-link`, `.dot`, severity badges |
| 201-381 | UI rework Rounds A-F additions | `.health-score-number`, `.table-scroll`, `.detail-right`, `.line-clamp-2`, `pre.raw-json`, Round F service-card utilities |
| **382-602** | **Round G `@media print` block** | The print-mode document treatment |

Within the `@media print` block:

| Selector group | What it does |
|---|---|
| `body > header, body > nav, .no-print, [role=dialog], .skip-link, .toast-region` | Hide screen-only chrome |
| `@page` | A4 size, 1.5/1.8cm margins, page-numbered footer via `@bottom-right` counter |
| `body, main` | Reset bg/color/padding for paper |
| `section, article, .report-summary, .report-card, details` | Strip card UI globally — no bg, no border, no shadow, no border-radius, no padding |
| `article.report-card` | Per-alert thin bottom rule, NO `page-break-inside:avoid` (long blocks flow across pages) |
| `main h2` | 16pt + brand-color underline + `page-break-before: always` |
| `#executive-summary > h2`, cover/TOC headings | Override of the page-break-before rule (don't add an extra blank page after the TOC's page-break-after) |
| `main h3` | 13pt + grey top hairline + extra margin (clear sub-section divider) |
| `main h2 + h3` | Drop the H3 top hairline when right after H2 (dedup with H2's brand-color underline) |
| `main h4` | 11pt bold + letter-spacing |
| `h2 + *`, `h3 + *`, `h4 + *` | Heading-orphan prevention: any element after any heading gets `page-break-before: avoid` |
| `.report-cover, .report-toc` | `page-break-after: always` + `height: 100vh` (each fills one page) |
| `#detect-csf > section, #summary-metrics > section` | **Dotted bottom hairline** between H4-led subsections (visual delimiters) |
| `#detect-csf .flex.flex-wrap, #summary-metrics .flex.flex-wrap` | Severity pill row gets explicit `margin-bottom` so it doesn't merge into the next H4 |
| `details` | Force-opened (CSS belt + JS evaluate braces). NO `page-break-inside:avoid` (long JSON spans pages) |
| `.badge, span[class*=bg-...]` | `-webkit-print-color-adjust: exact` so severity pill fills survive Chromium's "save toner" defaults |
| `#appendix-raw pre.raw-json, #appendix-raw .token` | Recolour from the screen's near-black `bg-[#0a0e1a]` + Prism Tomorrow → black-on-white with thin border for paper-print |

### 7.2 `static/style.css` — deleted

This file no longer exists. It carried an older `@media print` block, responsive
`@media (max-width: 768px)` rules and `.modal-footer`, and was **never linked from any
template**, so none of it fired. Commit `2280766` moved the print rules into
`design-tokens.css`; the dead file has since been removed.

The current `static/` tree is `design-tokens.css`, `report-bureau.css`, `ui.js`, plus
`fonts/`, `images/`, `js/` and `vendor/`.

---

## 8. PDF rendering pipeline

The `/report.pdf` route is the most novel piece of the report module. Walkthrough:

```python
# 1. Same data prep as /report (gated on ?generated=1)
context = {"generated": generated, "date_from": ..., "date_to": ..., ...}
if generated:
    context["alerts"] = db.get_alerts_by_date_range(...)
    # ... 5 more DB queries
    context["exec_summary_text"], context["exec_summary_provider"] = exec_summary.generate(...)

# 2. Render template in-process to an HTML string
html = render_template("report.html", **context)

# 3. Inject <base href="..."> so relative /static/* URLs resolve to
#    the running Flask server when Chromium fetches them. Without
#    this, set_content treats relative URLs as relative to about:blank
#    and silently drops them.
#
#    The base URL comes from config, NOT from the request. This used to
#    interpolate request.host_url, which derives from the Host header —
#    and ProxyFix(x_host=1) makes a client-supplied X-Forwarded-Host
#    authoritative, with no SERVER_NAME allowlist to check it against.
#    A forged header would point headless Chromium at an attacker origin
#    for every relative /static/* URL in the report: attacker CSS/JS
#    executing inside the renderer with the report content in the DOM.
#    Pin to the configured value and escape it before it lands in markup.
html = html.replace(
    "<head>",
    f'<head>\n  <base href="{escape(config.REPORT_ASSET_BASE_URL)}">',
    1,
)

# 4. Drive headless Chromium
with sync_playwright() as p:
    browser = p.chromium.launch()
    try:
        page = browser.new_page()
        page.set_content(html, wait_until="networkidle")

        # 5. Force-open every <details> so Appendix A renders payloads
        page.evaluate(
            "document.querySelectorAll('details').forEach(d => d.setAttribute('open', ''))"
        )

        # 6. Activate @media print rules (without this, screen styles win)
        page.emulate_media(media="print")

        # 7. Generate PDF
        pdf_bytes = page.pdf(
            format="A4",
            print_background=True,  # preserve navy accent + severity pill fills
            prefer_css_page_size=True,  # honour report-bureau.css's @page A4 + 18/16/22mm
            margin={"top":"1.5cm","bottom":"1.5cm","left":"1.5cm","right":"1.5cm"},
            display_header_footer=False,  # we use @page @bottom-right CSS instead
        )
    finally:
        browser.close()

# 8. Audit log + Response
db.log_audit(action="REPORT_PDF_EXPORT", actor=..., details={...})
return Response(pdf_bytes, mimetype="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="..."'})
```

### 8.1 The four critical lines that "look obvious but are easy to forget"

| Line | What breaks without it |
|---|---|
| `<base href="{escape(config.REPORT_ASSET_BASE_URL)}">` injection | All `/static/*` URLs would resolve against `about:blank` and silently drop. PDF would be unstyled black-on-white text. **The value must come from config, never from `request.host_url`** — see §8.1.1. |
| `page.evaluate(...details...d.setAttribute('open', ''))` | Appendix A entries would only show their summary lines. Forensic JSON payloads would be missing. |
| `page.emulate_media(media="print")` | `@media print` rules wouldn't activate. Cover/TOC `page-break-after` wouldn't fire. PDF would be one continuous scrollable page. `.no-print` chrome would render. |
| `print_background=True` | Navy `--brand-500` cover stripe would vanish. Severity pill fills (`bg-red-100`, etc.) would default to white. Appendix A's near-black background would disappear (intentional — that one is overridden in print CSS anyway). |

#### 8.1.1 Why the `<base>` value is pinned to config, not `request.host_url`

An earlier revision of this route interpolated `request.host_url` into the injected `<base>` tag. That is a **request-controlled value**: `request.host_url` derives from the `Host` header, and the app runs behind `ProxyFix(x_host=1)`, which promotes a client-supplied `X-Forwarded-Host` to authoritative — with no `SERVER_NAME` allowlist to check it against.

A single forged header on a `/report.pdf` request therefore repointed *every* relative `/static/*` URL in the document at an attacker-controlled origin, and headless Chromium then fetched and executed that CSS/JS inside the renderer with the full report content already in the DOM.

The fix (`web/blueprints/reports.py`, `report_pdf`) is two-part and both parts are load-bearing:

1. **Pin the origin** — `config.REPORT_ASSET_BASE_URL` (env `REPORT_ASSET_BASE_URL`, default `http://127.0.0.1:5000/`). It names where the renderer may fetch assets from; nothing on the request can move it.
2. **Escape it** — `escape(...)` before it goes into markup, so a stray quote in a misconfigured value can't break out of the `href="..."` attribute and inject additional tags.

If you change this line, keep both. Re-introducing `request.host_url` re-opens the hole, and dropping `escape()` turns a config typo into markup injection. When deploying behind a real hostname, set `REPORT_ASSET_BASE_URL` to that origin in the environment — do not "fix" the PDF's missing styles by reading the host off the request.

### 8.2 Why in-process render + `set_content` instead of `page.goto(url)`

| Approach | Trade-off |
|---|---|
| `page.goto("http://127.0.0.1:5000/report?...")` (URL fetch) | Chromium would have to authenticate. Either we'd set a session cookie programmatically (auth dance + cookie-domain matching with `0.0.0.0` vs `127.0.0.1`) or open the route to anonymous access (security risk). |
| **`render_template(...)` + `page.set_content(html)`** (in-process) | Render runs inside the same Flask process with `current_user` already authenticated. Chromium never needs a session cookie. Static assets resolve via the `<base>` trick. Auth-stays-auth, simpler, more robust. |

The plan locked Approach 2 for these reasons. The `<base>` injection is the only price — and it carries the caveat in §8.1.1: the injected origin must come from configuration, because the whole point of the approach is that Chromium trusts whatever that tag says.

### 8.3 Synchronous Playwright API trade-off

`playwright.sync_api` blocks the request worker for the entire PDF render (~2-5s warm, ~5-10s cold). For the single-user thesis app under gunicorn with `workers >= 2`, this is acceptable. If the app ever scales past one operator, the upgrade path is:

- Switch to `playwright.async_api` + Flask async views, OR
- Move PDF generation behind a background job queue (Celery / RQ) with the route returning a 202 + polling URL

Neither is needed for the thesis. Documented in the route docstring so future maintainers see the call-out.

### 8.4 Per-host Chromium install

`pip install playwright>=1.45` is in [`requirements.txt`](../requirements.txt) but **the Chromium binary is a separate, per-host one-time install**:

```
python -m playwright install chromium
```

Downloads ~111MB of Chromium Headless Shell to `~/AppData/Local/ms-playwright/` on Windows (or `~/.cache/ms-playwright/` on Linux). Not committed to the repo. **Without this step, the `/report.pdf` route raises `playwright._impl._errors.Error: Executable doesn't exist`.** Future deployment runbooks must include this command after `pip install`.

---

## 9. Performance characteristics

### 9.1 Latency by request shape

| Request | Cold latency | Warm latency | Notes |
|---|---|---|---|
| `/report` (no `generated=1`) | ~50ms | ~30ms | Renders empty-state CTA only. No DB queries, no AI chain. Fastest path. |
| `/report?from=...&to=...&generated=1` (first call for that range) | 30-60s | — | AI chain hits real provider (Groq, Google). Heavy. |
| `/report?from=...&to=...&generated=1` (within 1h, no new alerts) | ~150ms | — | Cache hit on AI summary; only 6 DB SELECTs run. |
| `/report.pdf` (no `generated=1`) | ~4.5s | ~2s | Chromium cold-start dominates. PDF is 1-page CTA only. |
| `/report.pdf?from=...&to=...&generated=1` (warm AI cache) | ~2s | ~1.5s | DB queries + Chromium. AI cache makes repeated downloads quick. |
| `/report.pdf?from=...&to=...&generated=1` (cold AI cache) | 35-65s | — | First call kicks the AI chain inside Playwright. Avoidable by warming via `/report` first. |

Recommended workflow for the operator preparing a quarterly audit: hit `/report?from=...&to=...&generated=1` first to warm the AI cache, then `/report.pdf?from=...&to=...&generated=1` for the downloadable artefact. The route docstring documents this ordering.

### 9.2 Caching layers

| Layer | What it caches | TTL | Key |
|---|---|---|---|
| AI executive summary | Generated narrative text | 1 hour | SHA-1 of `(date_from, date_to, latest_alert_id_in_range)` |
| Active providers | List of `ai_providers` rows where `is_active=1` | 5 seconds (in-process) | n/a (no key — single global list) |
| Service-active flags | `settings_kv.service_active.*` | 5 seconds (in-process) | service name |

Database queries are **not cached** — they're cheap (SQLite local + small dataset) and caching them would risk staleness against concurrent writes.

---

## 10. Security & access control

### 10.1 Authentication

Both routes are `@login_required`. Anonymous visits redirect to `/login` per the existing Flask-Login wiring in [web/auth_user.py](../web/auth_user.py).

### 10.2 Authorization (RBAC)

`/report` and `/report.pdf` are both **role-open** — no `@role_required('IT_ADMIN')` guard. Both `IT_ADMIN` and `Manager` users can access. This is intentional per [`report()`'s Round 7 docstring](../web/blueprints/reports.py): the audit report is the manager's primary audit-review surface.

Compare to the more restrictive routes:
- `/admin/settings` and `/admin/audit.csv` are gated by `@role_required('IT_ADMIN')` (there is no `/admin/settings.csv` route)
- `/dashboard/manager` is `@role_required('MANAGER')`
- `/dashboard/it` is `@role_required('IT_ADMIN')`
- **`/report` is open to both** — deliberate

### 10.3 CSRF

Neither route requires CSRF protection because both are GET-only. The Generate form at [report.html:47-71](../templates/report.html#L47-L71) submits via GET, which is correct semantically (the form doesn't change server state — it requests a new view).

### 10.4 Audit trail

Every visit produces an audit row:

| Action | Emitted when | Captures |
|---|---|---|
| `REPORT_VIEW` | Any `/report` GET (including bare visits to the CTA) | `details = {"from": ..., "to": ..., "generated": bool}` |
| `REPORT_PDF_EXPORT` | Any `/report.pdf` GET | `details = {"from": ..., "to": ..., "generated": bool}` |

The `generated` boolean lets reviewers distinguish CTA visits from full-report renders. Useful for telling apart casual dashboard back-link traversal vs. an operator deliberately producing audit evidence.

Both actions show up in `/admin/settings?tab=audit` (filterable by action) and in the `/admin/audit.csv` export (IT-only).

---

## 11. Verification & testing

### 11.1 Live HTTP smoke (any seed environment)

```bash
# Login as IT
curl -sS --cookie-jar /tmp/c.txt \
  -d 'username=admin&password=insightshield2026' \
  http://127.0.0.1:5000/login -o /dev/null -w "login: %{http_code}\n"

# G1: bare /report shows the CTA, no AI chain runs
curl -sS --cookie /tmp/c.txt http://127.0.0.1:5000/report \
  -o /tmp/bare.html -w "%{http_code}\n"
grep -c "Choose a date range" /tmp/bare.html  # → 1
grep -c "Executive Summary" /tmp/bare.html    # → 0 (gated)

# G2 / G3 full document, with seed alerts in range
curl -sS --cookie /tmp/c.txt --max-time 60 \
  "http://127.0.0.1:5000/report?from=2026-05-01&to=2026-05-31&generated=1" \
  -o /tmp/full.html -w "%{http_code}\n"
grep -c "id=\"executive-summary\"" /tmp/full.html  # → 1
grep -c "id=\"summary-metrics\""   /tmp/full.html  # → 1
grep -c "id=\"detect-csf\""        /tmp/full.html  # → 1
grep -c "id=\"alert-details\""     /tmp/full.html  # → 1
grep -c "id=\"appendix-raw\""      /tmp/full.html  # → 1

# G3.2 PDF endpoint produces a real PDF
curl -sS --cookie /tmp/c.txt --max-time 120 \
  "http://127.0.0.1:5000/report.pdf?from=2026-05-01&to=2026-05-31&generated=1" \
  -o /tmp/full.pdf -w "%{http_code} bytes=%{size_download}\n"
file /tmp/full.pdf  # → "PDF document, version 1.4, N page(s)"

# G3.4 Audit log shows both flag values
sqlite3 insightshield.db \
  "SELECT action, json_extract(details,'$.generated') FROM audit_log
   WHERE action IN ('REPORT_VIEW', 'REPORT_PDF_EXPORT')
   ORDER BY id DESC LIMIT 5"
# Expect rows with generated=true and generated=false captured
```

### 11.2 Visual checks (browser)

1. Open `/report` (no params) → centered "Choose a date range to generate the report" card visible. No KPI cards, no Detect section.
2. Click "Adjust date range" disclosure → date pickers + Generate button visible.
3. Pick a range covering seed alerts and click Generate → URL becomes `?from=...&to=...&generated=1`. Cover card, TOC card, all 5 sections render. Executive Summary shows AI text or static fallback. Appendix A entries collapsed (click to expand).
4. Hit the Print button (top-right) → browser's print preview shows: cover page 1, TOC page 2, body sections from page 3, Appendix A force-opened (CSS rule does the work — Playwright's `page.evaluate` is a PDF-only path), navy-on-white styling preserved, no global header/toolbar leaked.

### 11.3 Visual checks (PDF)

Open `pdf-samples/insightshield-audit-2026-05-01_2026-05-31.pdf` (regenerated by curl above):

- Page 1: cover with navy accent stripe, NIST scope paragraph
- Page 2: TOC with 5 numbered links
- Page 3+: each H2 section starts on its own page
- Page-numbered footer "Page N of M" on every page
- Per-alert articles flow naturally across pages (no forced one-per-page)
- Appendix A: raw JSON payloads visible (force-opened)
- No global header / no Adjust date range disclosure / no card chrome bleeding through

### 11.4 Text-extraction verification (when visual eyeball is unavailable)

```python
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
from pypdf import PdfReader
r = PdfReader('pdf-samples/insightshield-audit-2026-05-01_2026-05-31.pdf')
print(f"Total pages: {len(r.pages)}")
for i, p in enumerate(r.pages):
    txt = p.extract_text() or ''
    print(f"--- Page {i+1} ({len(txt)} chars) ---")
    print(txt[:300])
```

Look for these markers in expected pages:
- Page 1: `INSIGHT SHIELD SIEM`, `NIST CSF 2.0 alignment: Detect`
- Page 2: `Table of Contents`
- Page 3: `Executive Summary`
- Last page: `{` (JSON content from Appendix)

If the text extraction shows scrambled severity pills or content interleaving across subsections, the visual rendering is fine — pypdf walks the PDF content stream in instruction-order, which can interleave text from flex-wrap layouts. Trust the visual rendering over the text extraction for layout questions.

---

## 12. Code map (where to look for what)

| Concern | File:lines |
|---|---|
| HTML view route | [`report()` in web/blueprints/reports.py](../web/blueprints/reports.py) |
| PDF endpoint route | [`report_pdf()` in web/blueprints/reports.py](../web/blueprints/reports.py) |
| AI executive-summary chain | [executive_summary.py](../executive_summary.py) (whole file, 104 lines) |
| Database read helpers | [db.py](../db.py) — search for `get_alerts_by_date_range`, `get_report_summary`, `get_top_threats`, `get_top_attacker_ips`, `get_auth_metrics`, `get_posture_score`, `get_latest_alert_id_in_range` |
| Page shell + Tailwind config | [_base.html](../templates/_base.html) |
| Report orchestrator template | [report.html](../templates/report.html) |
| Cover + TOC partial | [_report_print.html](../templates/_report_print.html) |
| Brand tokens (navy `--brand-*`) | [design-tokens.css:1-100](../static/design-tokens.css#L1-L100) |
| Round F service-card utilities (used by /admin/settings) | [design-tokens.css:283-381](../static/design-tokens.css#L283-L381) |
| Round G `@media print` block | [design-tokens.css:382-602](../static/design-tokens.css#L382-L602) |
| Audit log helper | `db.log_audit(...)` in [db.py](../db.py) |
| Login decorator | `flask_login.login_required` |
| Role decorator (NOT used on report routes) | [decorators.py](../decorators.py) — `role_required('IT_ADMIN' / 'MANAGER')` |
| Master plan / round history | `../SYSTEM_DESIGN.md` §16 and `../REBUILD_SPEC.md` |

---

## 13. Round / version history

| Round | Date | Headline change | Commit(s) | Tag |
|---|---|---|---|---|
| Round 7 | (early) | Initial Security Audit Report shipped — H1, AI executive summary, 7-card KPI grid, agent compliance, incident breakdown, per-alert cards | (pre-baseline) | — |
| Round D | 2026-05 | Toolbar collapsed into `<details class="no-print">` disclosure. Print button kept. Raw JSON `pre.raw-json` wrap utility introduced. | various | — |
| Round F | 2026-05 | Brand recolor cyan → navy `--brand-500: #2563eb`. Prism Tomorrow dark theme switched in for Raw JSON tab. Service Configuration redesign (separate scope). | various | `v1.2.0-services-redesign` |
| **Round G stage G1** | 2026-05-09 | Defer AI executive-summary chain until Generate click. Empty-state CTA on bare /report. | `83559f9`, `5522792` | — |
| **Round G stage G2** | 2026-05-09 | Cover + TOC partial. Id-anchored sections. NIST CSF 2.0 — Detect anchor consolidating Round 7's three sibling H2s. Appendix A. Prism Tomorrow swapped in for /report. | `d454967`, `4a1a98a`, `e7e1fc2` | — |
| **Round G stage G3** | 2026-05-09 | Playwright PDF endpoint at `/report.pdf`. Headless Chromium, in-process HTML render, `<base>` injection, `emulate_media('print')`, force-open `<details>`. | `5583480`, `f21c19f`, `c3d37e4` | — |
| **Round G stage G3 follow-ups** | 2026-05-09 to 2026-05-10 | Print CSS moved to `design-tokens.css` (was dead-code in `style.css`). Heading hierarchy + dotted subsection delimiters. Long-content flow (drop `page-break-inside: avoid` on per-alert cards + `<details>`). | `2280766`, `9072c0a`, `6afa9a8` | — |
| **Round G complete** | 2026-05-10 | G4: Download PDF button wired into the report toolbar; Round G sign-off tag created. | (G4 commit batch) | `v1.3.0-audit-report` |
| **Round H** | 2026-05-10 | Appendix A Expand-all / Collapse-all toggle. `@media print :has(details[open])` rule to hide whole appendix when nothing is expanded. Cover screen-mode scaling (56px screen / 96pt print). Cross-surface parity polish for the dashboards (out of report scope, mentioned here because the date-range search bag enhancement affects the report's filter too). | various | `v1.4.0-cross-surface-parity` |
| **Round I** | 2026-05-12 | New Methodology & Scope §02 section (Audit Objectives / Scope / Methodology / Limitations / Framework Alignment with CSF chip row). §-marker renumber across the four sections below it. AI executive summary restructured to 4 labeled paragraphs (KEY FINDINGS / CURRENT CHALLENGES / ACTIONS TAKEN / TOP RECOMMENDATIONS). Cache key bumped to `v2\|` version sentinel. Highlights paragraph citing live agent coverage. Both exec_summary and manager-translator prompts tightened with explicit synonym mapping + self-check. Cache attribution reworded `Generated by cache` → `Served from cache (originally AI-generated, 1h TTL)`. Raw-JSON wrap fix on inner `<code>` to defeat Prism cascade. In-app footer drift from v1.0 strings to v1.4.1 / Build 0.4.1 closed. | `3d894c4`, `2c116c4`, `c1b5df6`, `7b30df8`, `e0eafe8`, `d82b6b3`, `dd7852f`, `e3704a3` (+ docs `9e8399b`, `cf37698`, `0606259`, `6949d44`, `9668505`, `4ae3b5c`, `b6eb368`, `1b070ac`, `aa282e2`) | `v1.4.1-audit-methodology` |

---

## 14. Known limitations & future work

1. **AI chain blocks the request thread.** A first-time render of a new date range can wait 30-60 seconds on real LLM providers. Mitigation: warm the cache via `/report?...&generated=1` before hitting `/report.pdf?...&generated=1`. Long-term fix: background job + polling, or async Playwright + async views. Out of thesis scope.
2. **Per-host Chromium install required.** ~111MB binary, not committed to the repo. Documented in the `report_pdf()` route docstring (`web/blueprints/reports.py`) + `requirements.txt` line comment, but a deployment-runbook addition is still pending.
3. **Empty NIST functions are skipped, not stubbed.** The thesis scope is Detect-only and the cover paragraph names this explicitly. If a future thesis or production deployment wants to claim coverage for Identify / Respond / Govern, the `_report_print.html` `sections` list grows + corresponding body sections need to be added to `report.html`.
4. ~~**`style.css` legacy file still present.**~~ Resolved — the unlinked file has been deleted. See §7.2.
5. **Vulnerability detection is conditional and currently empty for seed data.** The `_has_va` flag at [report.html:264-273](../templates/report.html#L264-L273) checks for `attack_trail.data.vulnerability` payloads. Until a Wazuh VA module ingests data, the H4 stays hidden. By design.
6. **Per-alert raw JSON in Appendix A duplicates the Alert Details body.** Each alert appears once in §4 (with AI translation + lifecycle) and once in §5 (with the raw payload). Larger PDFs (50+ alerts) will repeat content. Considered intentional — analyst ergonomics over byte-count.
7. **No PDF customisation surface.** Operators can't override the cover label, organisation name, or classification banner from the UI. All hard-coded in `_report_print.html`. Would be a small future feature: pull from a `report_settings` row in `settings_kv`.

---

## 15. How to extend

### 15.1 Add a new TOC entry + body section

1. Edit `_report_print.html` `sections` list — append `{"id": "your-id", "label": "Your Section"}`.
2. Edit `report.html` — add `<section id="your-id" class="mb-6"> <h2>Your Section</h2> ... </section>` inside the `{% if alerts %}` block (or above it if it should show in zero-alert ranges).
3. Run G2.3-style verification: every TOC `href="#X"` should match an `id="X"` in the body.
4. The print CSS automatically applies (page-break-before on the new H2, dotted hairlines if the section uses sibling subsections).

### 15.2 Add a new severity / status pill colour

1. Add the variable in `design-tokens.css`'s `:root { ... }` block: `--sev-newkind-bg`, `--sev-newkind-fg`, `--sev-newkind-border`.
2. Add the `.badge-newkind` class definition right after the existing severity badges.
3. Add the `--status-newkind` token if it's a status colour.
4. Update the Tailwind config in `_base.html` if you need utility-class access (`bg-sev-newkind`, etc.).

### 15.3 Add a new DB helper backing a section

1. Add the function to `db.py` (next to existing `get_top_threats` etc.). Match the signature `(date_from, date_to, **kwargs) -> dict | list`.
2. Wire it into both `/report` and `/report.pdf` in `web/blueprints/reports.py`. Both routes' data-prep blocks must call it identically — they're deliberately duplicated to avoid coupling the gating logic.
3. Use the result in the body section's Jinja template.
4. If the result feeds the AI executive summary, also update `executive_summary.generate(...)`'s prompt template at [executive_summary.py:25](../executive_summary.py#L25).

### 15.4 Tweak the print-mode visual

All print rules live in [`design-tokens.css`](../static/design-tokens.css) lines 382-602 inside the `@media print { ... }` block. Hot reload works in dev (Flask debug=True watches CSS via static-file refresh on next page load). Test in the browser via Ctrl+P print-preview AND in the PDF via curl + `file` + pypdf — both paths use the same `@media print` rules but `print_background:true` only carries on the Playwright PDF path.

---

## 16. Post-Round-G additions (Round H + Round I)

§§ 1–15 above document the v1.3.0-audit-report state (Round G stages G1–G4). Two follow-up rounds shipped on top before the v1.4.1 release:

- **Round H** (2026-05-10, tag `v1.4.0-cross-surface-parity`) — Appendix A expand-all/collapse-all toggle, Ctrl+P partial-print rule, screen-mode cover sizing tweak, manager dashboard filter parity (out of report scope but mentioned here because the date-range search bag expansion affects the report's own filter behaviour).
- **Round I** (2026-05-12, tag `v1.4.1-audit-methodology`) — new Methodology & Scope §02 section, restructured AI executive summary, AI prompt tightening, raw-JSON wrap fix, cache attribution UX.

### 16.1 Round H additions

| Change | File | Purpose |
|---|---|---|
| Appendix A `Expand all` / `Collapse all` toggle | `templates/report.html` inline `<script defer>` at bottom of `#appendix-raw` section | Operators previewing the report can choose what to print via Ctrl+P |
| `@media print` rule `#appendix-raw:not(:has(details[open])) { display: none !important; }` | `static/report-bureau.css:920-926` | Ctrl+P with zero entries expanded hides the whole Appendix A section so the print doesn't end with a one-line section header and nothing else |
| `@media print` rule `details:not([open]) { display: none; }` on appendix entries | `static/report-bureau.css` print block | Collapsed entries don't print; only what the operator expanded |
| Screen-mode cover scaling | `static/report-bureau.css:620` `.rb-cover__title { font-size: 56px }` while print stays at 96pt | Browser preview reads as a banner card, not an empty waste page |
| `/report.pdf` pipeline step 6 force-opens every `<details>` | `web/blueprints/reports.py` `report_pdf` route — `page.evaluate("document.querySelectorAll('details').forEach(d => d.setAttribute('open',''))")` | PDF is the FULL archive intent; force-open contradicts Ctrl+P's operator-curated behaviour intentionally |

**Two-surface print model after Round H** (this is the load-bearing design idea — internalize it before editing):

| Surface | Behaviour | Reasoning |
|---|---|---|
| **Ctrl+P from browser** | Only entries the operator expanded print; whole Appendix A hidden if none open | Operator-curated. Printing 50 raw-JSON payloads when you only care about 3 is wasteful |
| **`/report.pdf` download** | Every Appendix A entry force-opened by Playwright before `page.pdf()` fires | Archival intent — the PDF is the long-term forensic record |

Both surfaces use the **same `@media print` CSS rules**. The split is created by Playwright's `page.evaluate()` running between `set_content()` and `pdf()` — for that single render the DOM state diverges from a browser-print path. Don't try to replicate the divergence with CSS; the JS DOM mutation is the cleaner contract.

### 16.2 Round I — Methodology section (new §02)

Insertion point: between `#executive-summary` and the `{% if alerts %}` gate in `report.html` (so Methodology renders even on empty date windows). After the insert, the body §-marker sequence is `§01, §02 NEW, §03, §04, §05, §06` — every section below Methodology shifts one number.

#### 16.2.1 Why outside the `{% if alerts %}` gate

The data-heavy sections (Summary Metrics, Detect, Alert Details, Appendix) are wrapped in `{% if alerts %}` so an empty date window renders only the cover + TOC + Executive Summary + an empty-state card. Methodology is documentation about *what was monitored and how* — that's true regardless of whether alerts fired during the window. Place it outside the gate so a zero-alert report still explains itself.

#### 16.2.2 Markup pattern (matches existing Bureau sections)

```html
<section id="methodology-scope" class="rb-panel mb-6">
  <header class="rb-h2">
    <span class="rb-h2__marker">§ 02</span>
    <h2 class="rb-h2__title">Methodology &amp; Scope</h2>
    <span class="rb-h2__rule"></span>
  </header>

  <p class="rb-body"><strong>Audit Objectives.</strong> ...27 custom detection rules in custom_retail_rules.xml...</p>
  <p class="rb-body" style="margin-top:14px;"><strong>Scope.</strong> ...{{ agents | selectattr('status', 'equalto', 'active') | list | length }} of {{ agents | length }}...</p>
  <p class="rb-body" style="margin-top:14px;"><strong>Methodology.</strong> ...Wazuh decode → AI translation (Groq → Gemini → OpenRouter → static template) → SQLite WAL → severity routing → posture score...</p>
  <p class="rb-body" style="margin-top:14px;"><strong>Limitations.</strong> ...NIST CSF 2.0 Detect only; rule-matched events only; 1h AI cache; raw payloads in Appendix A...</p>
  <p class="rb-body" style="margin-top:14px;"><strong>Framework Alignment.</strong> NIST CSF 2.0:</p>
  <div class="rb-csf" style="margin-top:8px;">
    <span>Identify — out of scope</span>
    <span>Protect — out of scope</span>
    <span class="is-on">Detect · in scope</span>
    <span>Respond — out of scope</span>
    <span>Recover — out of scope</span>
    <span>Govern — out of scope</span>
  </div>
</section>
```

#### 16.2.3 Reuse, not addition

- `.rb-csf` chip row already exists at `static/report-bureau.css:281-301` from Round G — no new CSS class needed.
- `.rb-panel { break-inside: avoid }` at `static/report-bureau.css:874-879` already covers print-mode page-break behaviour for the new section — no panel-specific rule needed.
- `27 custom detection rules` is the verified count from `wazuh_rules/custom_retail_rules.xml`: Unauthorized Access ×4, POS Malware ×5, MitM/ARP ×3, Ransomware ×4, DoS ×4, Baseline ×7. Quote this number, not the 18 figure that appeared in the original recommendation document.

#### 16.2.4 TOC partial change

`_report_print.html` `sections` list gains one entry at **index 1** (between `executive-summary` and `summary-metrics`):

```jinja
{% set sections = [
  {"id": "executive-summary", "label": "Executive Summary"},
  {"id": "methodology-scope", "label": "Methodology & Scope"},  ← NEW
  {"id": "summary-metrics",   "label": "Summary Metrics"},
  {"id": "detect-csf",        "label": "NIST CSF 2.0 — Detect"},
  {"id": "alert-details",     "label": "Alert Details"},
  {"id": "appendix-raw",      "label": "Appendix A — Raw Wazuh JSON"}
] %}
```

The cover-page TOC iterates this list, so the rendered TOC now shows 6 entries — that's the verification gate (`grep -c '"id":' _report_print.html` → expect 6).

### 16.3 Round I — Restructured AI Executive Summary

#### 16.3.1 Before / after the prompt rewrite

| Field | Round G | Round I |
|---|---|---|
| Output shape | 2-3 paragraphs of free-form prose | 4 labeled paragraphs separated by blank lines |
| Section labels | none (prose only) | `KEY FINDINGS:`, `CURRENT CHALLENGES:`, `ACTIONS TAKEN:`, `TOP RECOMMENDATIONS:` |
| Bullet structure | none | `- ` bullets inside each paragraph (2-3 per section) |
| Word count | 150-400 | 150-380 (capped 20 under the 400 ceiling for margin) |
| Avoid-list discipline | "Avoid TCP, RDP, SMB, port numbers, process names, CVE IDs" — generic | Every entry in `config.FORBIDDEN_WORDS` listed explicitly + explicit synonym map + self-check instruction |
| Validator behaviour | `validate_exec_summary` requires ≥ 2 paragraphs split on `\n\n` | Unchanged — the 4-paragraph structure satisfies the 2-paragraph minimum naturally |

#### 16.3.2 Cache invalidation across prompt-version changes

`_make_cache_key` digest input now prefixed with a version sentinel: `f"v2|{date_from}|{date_to}|{latest_alert_id}"`. SHA-1 of the prefixed input produces a completely different cache key from the unprefixed Round G formula. Every entry cached under the old formula becomes unreachable — they stay in memory until the 1h TTL expires but are never read again.

**Future prompt revisions should bump the sentinel** (`v3|`, `v4|`, …) at the same time the prompt body changes. This avoids needing a Flask restart or manual `cache.clear_all()` call to flush stale shapes.

#### 16.3.3 Synonym map (the load-bearing part)

The original Round G prompt told the model "avoid these words" — and the model used them anyway. Live test with Groq on 2026-05-12 produced output containing "exploit"; validator rejected; chain exhausted. Round I added an **explicit synonym map** so the model has a substitution path, not just a prohibition:

| Forbidden | Substitute |
|---|---|
| `exploit`, `buffer overflow` | "method of attack" or "system weakness" |
| `firewall` | "network filtering" |
| `authentication` | "sign-in" |
| `payload` | "harmful data" |
| `protocol`, `TCP`, `HTTP`, `FTP`, `SSH`, `RDP`, `SMB`, `NTLM` | "network connection" or "remote access" |
| `IP address` | "network address" |
| `ARP`, `DHCP`, `DNS`, `ICMP`, `SSID` | "network configuration" or "WiFi name" |

Plus a self-check instruction: *"Before submitting, re-read your draft and rewrite any sentence that contains a forbidden word. The forbidden list is enforced by an automated validator that rejects on any match."*

#### 16.3.4 Highlights paragraph

After the AI summary inside the same `<section id="executive-summary">`, a static Highlights paragraph renders unconditionally:

```html
<p class="rb-body" style="margin-top:10px;">
  <strong>Highlights.</strong>
  {{ agents | selectattr('status', 'equalto', 'active') | list | length }} of {{ agents | length }} monitored endpoints reported continuously through the period.
</p>
```

**Placement is load-bearing**: after the `{% endif %}` that closes the AI-text-or-fallback if-else, before `</section>`. This guarantees it renders regardless of whether the AI chain returned exhausted-sentinel or a normal response.

### 16.4 Round I — Manager translator mirror-tightening

The manager-translator prompt at `groq_translator.py:28-37` carried the **same vulnerability** as the original exec summary prompt — listed forbidden words inline but gave the model no substitutes. Round I mirror-tightened it with the same synonym map.

**Important coupling with Round 6 frequency escalation**: the manager translation cache is keyed by `rule_id`, so the **same cached translation displays at MEDIUM, at MEDIUM-frequency `(N/M)` warning, AND post-escalation HIGH/CRITICAL on repeat occurrences**. A forbidden-word trip at MEDIUM time blocks the translation from ever displaying through the full severity transition. The new prompt calls this out explicitly: *"This rule applies at every severity level — including MEDIUM alerts that may escalate to HIGH or CRITICAL on repeat occurrences."*

No cache key version bump on this prompt — existing manager-translation cached entries had already passed the older (looser) validator, so they're forbidden-word-clean by definition. New translations after the change use the tighter prompt; old ones continue to serve until their 1h TTL expires.

### 16.5 Round I — Cache attribution UX

The Round G template rendered `Generated by {{ exec_summary_provider }}.` unconditionally. When the chain returned `provider_used = "cache"` on a cache hit, the attribution read `Generated by cache.` — which parses as if "cache" were the AI provider, not a memo-layer.

Round I makes the attribution conditional:

```jinja
{% if exec_summary_provider == 'cache' %}
  Served from cache (originally AI-generated, 1h TTL).
{% else %}
  Generated by {{ exec_summary_provider }}.
{% endif %}
```

The cache stores only validated outputs from the AI chain, so a cache hit IS still AI-generated content. The new wording makes that explicit instead of implying cache itself produced the text.

### 16.6 Round I — Raw-JSON wrap fix (the silent killer)

#### 16.6.1 The cascade bug

`design-tokens.css` had this rule from Round D:

```css
pre.raw-json {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  word-break: break-word;
  tab-size: 2;
}
```

Both alert-detail (`alert_detail.html:292`) and report appendix (`report.html:668`) use `<pre class="raw-json"><code class="language-json">...</code></pre>`. Prism's syntax-highlighter ships its own rule `code[class*="language-"] { white-space: pre; }` from the CDN stylesheet. **That `code` selector wins over the parent `pre.raw-json` cascade** — so the inner `<code>` retained `white-space: pre` (no wrap) even though the parent `<pre>` had `pre-wrap`.

Why alert-detail seemed to work: its `<pre>` sits inside `<aside class="detail-right">` which has `min-w-0` plus `overflow-wrap: break-word` at `design-tokens.css:278-281` as a safety net. That parent-level rule rescued the overflow.

Why audit-report appendix didn't: each `<details>` is a direct child of `<section id="appendix-raw">` with no equivalent rescue. Long URLs / base64 / Windows paths pushed the card wide.

#### 16.6.2 The fix

Extend `pre.raw-json` to also target its `<code>` child with `!important` to defeat the Prism cascade:

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

`!important` is scoped narrowly (`pre.raw-json code` only) so it doesn't pollute the global cascade. `max-width: 100%; display: block` give the `<code>` a deterministic box geometry regardless of what Prism does to its inline layout.

**Single rule fixes both surfaces.** Alert detail now wraps via the proper rule, not the lucky aside-rescue. Report appendix wraps for the first time.

#### 16.6.3 Print behaviour

The print stylesheet at `report-bureau.css:932-939` only sets max-height / background / color / print-color-adjust on `details pre.raw-json` — it does NOT override `white-space`, `overflow-wrap`, or `word-break`. So the new wrap rule carries through into `@media print` and `/report.pdf` output without further work.

### 16.7 Updated section numbering reference

After Round I's insertion + renumber, the body markers and TOC labels read:

| Position | Section id | §-marker | TOC label |
|---|---|---|---|
| 1 | `executive-summary` | § 01 | Executive Summary |
| 2 | `methodology-scope` | § 02 | Methodology & Scope (NEW) |
| 3 | `summary-metrics` | § 03 | Summary Metrics (was § 02) |
| 4 | `detect-csf` | § 04 | NIST CSF 2.0 — Detect (was § 03) |
| 5 | `alert-details` | § 05 | Alert Details (was § 04) |
| 6 | `appendix-raw` | § 06 | Appendix A — Raw Wazuh JSON (was § 05; the "A" letter in the title stays) |

Any future section inserted at position N must (a) be added to the `_report_print.html` sections list at the matching index, (b) have its body `<section id="...">` markup added to `report.html` at the matching position with the correct `§ NN` marker, and (c) all sections below shift their `§-marker` and TOC label by +1.

### 16.8 Verification gates (cumulative)

Round G shipped gates G1–G4 (§13). Round H added the expand-all toggle gates. Round I adds these gates on top:

| Gate | Check | Pass |
|---|---|---|
| I.1 | `grep -n "§ 0[1-6]" templates/report.html` | 6 lines in strict sequence |
| I.2 | `grep -c '"id":' templates/_report_print.html` | 6 |
| I.3 | TOC ↔ body cross-check loop: each `id` in sections list has exactly 1 `id="..."` body match | every id matches |
| I.4 | `grep -n '"v2' executive_summary.py` | sentinel present in `_make_cache_key` |
| I.5 | Forbidden-word discipline programmatic check: each `config.FORBIDDEN_WORDS` entry appears only in legitimate locations (constraint declaration + synonym map) | pass for both `EXEC_SYSTEM_PROMPT` and `groq_translator.SYSTEM_PROMPT` |
| I.6 | Captured live AI output: `validator.validate_exec_summary(text)` | `True` |
| I.7 | `git diff --stat HEAD` | only `executive_summary.py`, `groq_translator.py`, `templates/report.html`, `templates/_report_print.html`, `static/design-tokens.css`, `templates/_base.html` + docs |
| I.8 | Manual web view at `/report?from=…&to=…&generated=1` | 6 sections in order, exec summary 4 paragraphs + Highlights, Methodology 5 blocks + CSF chips |
| I.9 | Manual empty-range load | Methodology still renders, no template error |
| I.10 | Manual Ctrl+P preview | §02 lands cleanly |
| I.11 | Manual `/report.pdf` download | PDF cover → TOC → exec + Highlights → Methodology → §03 onward |
| I.12 | Manual no-regression on `/dashboard/it`, `/dashboard/manager`, `/alert/3`, `/admin/settings?tab=service`, `/login` | render identically to v1.4.0 |
| I.13 | Cache version check via direct DB write | cache invalidates properly |

### 16.9 Known limitations carried forward

The seven §14 Round G limitations still apply unchanged. Round I diagnostic work surfaced two additional limitations — these extend §14 (treat them as items 8 and 9 of the same conceptual list, renumbered from 1 here so the markdown ordered-list renders cleanly):

1. **`RULE_TO_TEMPLATE` static-fallback mapping has drift bugs.** The `RULE_TO_TEMPLATE` dict in `groq_translator.py` was last touched in Round 2 and doesn't accurately reflect the current `custom_retail_rules.xml`. Visible drift: rule_id `100020` (ARP Spoofing) maps to `wifi` template (should be `arp_mitm`); rule_id `100030` (Bulk File Rename) maps to `arp_mitm` (no good template — this is ransomware-adjacent); rule_id `ISH-CBF-001` (Round E credential brute-force) has no entry at all and falls through to the default `rdp_bruteforce`. These only matter when the AI chain exhausts; with AI working (the primary path), users see the AI's dynamic output regardless of rule_id. Marked as out-of-scope for Round I; future cleanup round should reconcile the static-template map with the v1.4 rule taxonomy.

2. **Round E credential_brute_force alerts have NULL `it_recommendation`.** The brute-force escalation path (`_maybe_dispatch_brute_force_alert` in `web/blueprints/auth.py`) builds the alert row directly and calls `alert_router.dispatch` — it does NOT go through `wazuh_receiver.process_alert()`, which is the only code path that spawns the fire-and-forget IT recommender thread. Consequence: every credential_brute_force alert has NULL `it_recommendation` and the alert detail page stays at the "Generating investigation steps… refresh in a few seconds" placeholder forever. Alert id=8 was backfilled via a diagnostic script during Round I; future brute-force alerts will repeat the issue until the brute-force path is patched to spawn the IT recommender too. Marked as out-of-scope for Round I; should be addressed in a Round E follow-up.
