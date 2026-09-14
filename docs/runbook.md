# Operations runbook

What to do when a **running** system misbehaves.

Install-time problems are in `deployment-ubuntu.md` §8. This file starts after the system
came up successfully at least once.

> **Before any step that deletes or overwrites:** take a backup. Settings → Backups →
> "Back up now", or `sudo -u insightshield /opt/insightshield/venv/bin/python -c
> "import backup; print(backup.backup_db())"`. Nothing in this file drops a table or
> deletes the database, and nothing here should be the first destructive thing you try.

---

## Alerts arrive untranslated / executive summary is blank or stale

**What you are seeing.** Alert rows show the static fallback text instead of an AI summary,
or `/report`'s Executive Summary renders the fallback paragraph.

**Diagnosis.** The provider chain ran out of budget or every provider failed.

- The chain walks providers in `ai_providers` order until one succeeds.
- Total wall-clock budget is `AI_CHAIN_BUDGET_S = 25.0` seconds. When it is exhausted the
  chain stops and returns the static fallback — the `AI_CHAIN_EXHAUSTED` sentinel never
  reaches rendered HTML.
- A provider that fails is put in a **negative cache for `AI_NEGATIVE_CACHE_S = 300`
  seconds**. This is the one that fools people: *after you fix a provider it still looks
  broken for up to five minutes.*
- Successful translations are cached in the `ai_cache` table for `CACHE_TTL = 3600`
  seconds.

**Fix.**

1. Settings → Service Configuration. Check each provider's status and use **Test** — the
   probe reports the real error (401, quota, DNS).
2. Fix the key, or deactivate the dead provider so the chain stops spending budget on it.
3. **Wait out the negative cache, or clear it.** Settings → Service Configuration →
   clear cache. Do not conclude the fix failed before five minutes have passed.
4. Re-check `/report?...&generated=1`. A cached summary is served for up to an hour; the
   cache key includes the latest alert id in range, so a new in-range alert invalidates it.

**Verify.** A newly ingested alert renders with AI text, and the alert detail page shows
the provider name rather than the fallback attribution.

---

## Bootstrap seeded placeholder credentials

**What you are seeing.** Three AI providers listed and active but every Test returns 401.
Telegram/Gmail/Wazuh configured but no notification ever arrives and no error is shown.
Every ingest is slow (the chain spends its full 25s budget before falling back).

**Diagnosis.** First boot imported `.env` placeholders as real credentials.

`.env.example` ships **non-empty** placeholders (`GROQ_API_KEY=your-groq-api-key-here` and
friends). `db.bootstrap_settings_from_env` skips only *empty* values — the provider loop
tests `if not p.get("api_key")`, and `_bootstrap_api_key` / `_bootstrap_setting` test
`if plaintext:`. A placeholder is a non-empty string, so it was imported. `scripts/install.sh`
does not help: its `ensure_secret` helper regenerates only `FLASK_SECRET_KEY`,
`ENCRYPTION_KEY` and `WAZUH_WEBHOOK_TOKEN`.

Confirm it:

```bash
cd /opt/insightshield/insightshield
sudo -u insightshield grep -nE '=(your-|generate-a-|change-me)' .env
```

**The import is one-shot.** It is guarded by a `bootstrap_complete` row in `settings`, so
editing `.env` now changes nothing.

### Fix A — through the UI (preferred)

1. Settings → Service Configuration.
2. Delete each bogus AI provider, or Edit it and paste a real key.
3. For Telegram / Gmail / Wazuh, either enter real credentials or delete the stored key.
4. Blank the placeholders in `.env` too, so a future rebuild from scratch does not repeat
   this.

Nothing needs restarting — the app reads these from the database.

### Fix B — re-run the bootstrap

Only if you want first-boot behaviour back. **Take a backup first** — this discards the
credentials currently stored.

1. Blank or fill every placeholder in `.env`.
2. Stop the services: `sudo systemctl stop insightshield insightshield-worker`.
3. Delete the seeded rows and the sentinel. Verify the table names against `db.py` before
   running anything:

```sql
-- sqlite3 /opt/insightshield/insightshield/insightshield.db
DELETE FROM settings WHERE key = 'bootstrap_complete';
DELETE FROM ai_providers;   -- only if every provider row is bogus
DELETE FROM api_keys;       -- only if every stored credential is bogus
```

4. Start the services. First boot re-imports `.env`.

**Verify.** Settings → Service Configuration shows only real providers, and Test passes on
each. Ingest latency returns to normal.

---

## Rotating `WAZUH_WEBHOOK_TOKEN` without dropping alerts

The token appears in two places that must agree: `.env` on the app host, and `<api_key>`
in the Wazuh manager's `ossec.conf`. There is no overlap window — the app accepts exactly
one value — so the gap is unavoidable and the goal is to make it short.

**Order: Wazuh last.** Update the app first, then the manager. The reverse leaves the
manager sending a token the app does not know, which is the same failure but for longer if
the app restart is slow.

1. Generate: `python3 -c "import secrets; print(secrets.token_hex(32))"`.
2. Set `WAZUH_WEBHOOK_TOKEN=` in `/opt/insightshield/insightshield/.env`. This one is read
   from the environment on **every** boot — it does not live in the database.
3. `sudo systemctl restart insightshield` (the web tier serves the webhook; the worker
   does not need restarting for this).
4. Immediately re-sync the manager. The simplest way is `sudo scripts/install.sh`, which
   copies `WAZUH_WEBHOOK_TOKEN` from `.env` into the `<api_key>` block (it does this only
   when exactly one `<api_key>` exists) and restarts `wazuh-manager`. Or edit `<api_key>`
   in `ossec.conf` by hand and `sudo systemctl restart wazuh-manager`.

**Drift guard.** `scripts/deploy.sh` and `scripts/update.sh` both compare the `ossec.conf`
token against `.env` and flag a mismatch — the failure mode where you rotate `.env`, restart
the app, and forget the manager, after which every real alert is rejected while a manual
`curl` (which reads `.env`) still returns 200.

**What the gap looks like.** Between steps 3 and 4 the integrator logs a 403 per alert in
`/var/ossec/logs/integrations.log`. Those alerts are **lost** — the integrator does not
retry. Rotate during a quiet window.

**Verify.**

```bash
tail -f /var/ossec/logs/integrations.log   # 403s stop
```

Then confirm a fresh alert appears on the IT dashboard, or send a test payload per
`webhook-contract.md` §9.

---

## A user cannot log in

Two different causes look identical to the user.

### Cause 1 — login throttle

Thresholds in `web/blueprints/auth.py`, counted from `LOGIN_FAILURE` rows in `audit_log`:

| Tier | Threshold | Window |
|---|---|---|
| Per IP | 5 failures | 15 min |
| Per username | 10 failures | 60 min |
| Per IP escalation | 20 failures | 60 min |

The first two return `429` with `Retry-After`. The escalation tier additionally emits a
HIGH `credential_brute_force` alert through `alert_router` — at most one per IP per window.

`Retry-After` reports the **full window length**, which is conservative: the real quiet
time is shorter because the oldest failure rolls out of the window first.

**To clear it before the window expires,** delete the counted failures. Take a backup
first — this edits the audit trail:

```sql
-- confirm what you are about to remove
SELECT ts, actor, ip FROM audit_log
 WHERE action = 'LOGIN_FAILURE' AND ip = '<the ip>'
 ORDER BY ts DESC LIMIT 30;
```

Prefer waiting out the window. Deleting audit rows to unblock a login is a last resort, and
if the failures were not yours, the block is doing its job.

### Cause 2 — forced password change

A user with `must_change_password = 1` is bounced to the password form from every page.
That is by design on first login (bootstrap credentials) and after an admin reset. If they
are stuck in a loop, they are failing the new-password rules, not the login.

To clear the flag:

```sql
UPDATE users SET must_change_password = 0 WHERE username = '<user>';
```

**Verify.** The user reaches their dashboard. Check `audit_log` for a `LOGIN_SUCCESS` row.

---

## No escalations, no nightly backup, no agent-status updates

**Diagnosis.** The scheduler is not running, or is running in the wrong place.

Exactly one process may call `init_scheduler()`. In production that is
`insightshield-worker.service`, never a gunicorn worker.

```bash
systemctl is-active insightshield insightshield-worker    # both should be active
sudo journalctl -u insightshield-worker -n 20 --no-pager | grep "scheduler owns this process"
```

The five jobs it owns:

| Job | Trigger |
|---|---|
| `midnight_health_reset` | cron, 00:00 |
| `daily_db_backup` | cron, 02:00 |
| `retention_purge` | cron, 03:00 (`AUDIT_RETENTION_DAYS`=90, `ERROR_RETENTION_DAYS`=30) |
| `agent_status_poll` | interval, 30s |
| `escalation_sweep` | interval, `ESCALATION_INTERVAL_MIN` = 5 min |

**Two common failures:**

1. **Worker unit never installed.** The most likely cause on a hand-followed deploy. The
   web tier comes up fine and nothing reports the absence. Install it —
   `deployment-ubuntu.md` §5.6a.
2. **`INSIGHTSHIELD_RUN_SCHEDULER=1` set on the *web* unit.** Now every gunicorn worker
   runs a scheduler. Three schedulers means three nightly backups racing on the same SQLite
   file at 02:00. Remove it from `insightshield.service` — that variable belongs only on
   the worker unit (and on a single-process dev run).

**Verify.** Watch for the `agent_status_poll` effect: the login page status dot updates
within 30s of the Wazuh manager changing state.

---

## Dashboard is not updating live / "too many streams"

**Diagnosis.** `SSE_MAX_PER_USER = 3` in `web/blueprints/stream.py`. The fourth concurrent
stream for one username gets `429 {"error": "too_many_streams"}`.

Slots are released in the stream generator's `finally`. A comment line is written on every
poll tick (~2s) specifically so a closed tab's stream notices and releases — a browser that
went away without a clean close is reclaimed within a tick or two, not minutes.

Total concurrent streams across the tier are bounded by `workers × threads` = 3 × 16.

**Fix.** Usually the user has stale tabs open. Close them and wait a few seconds. If
`429`s persist with no tabs open, restart the web tier —
`sudo systemctl restart insightshield` — which drops every stream and clears the counters.

The dashboard falls back to 15s polling after three SSE failures, so live-update loss
degrades rather than breaking the page. A dashboard that is not updating *at all* is a
different problem — check the browser console and Settings → Errors.

---

## Backup and restore

**Where.** `/opt/insightshield/backups/insightshield-YYYYMMDD-HHMMSS.db.enc`.

**What.** `backup.backup_db()` takes a consistent snapshot through SQLite's online backup
API — not a file copy — then Fernet-encrypts it in place with the master key. Old copies
are pruned by `run_daily_backup`.

> **Restoring requires the same `ENCRYPTION_KEY`.** Lose that key and every backup is
> permanently unreadable, along with every credential stored in `api_keys`. Back it up
> off-box, somewhere that is not this server.

**Restore.** `backup.restore_db(path)` decrypts `.db.enc` before restoring (it also still
accepts legacy plain `.db` files). Full procedure in `deployment-ubuntu.md` §9.2 — stop the
services first; restoring under a running app races the WAL.

---

## Where the logs are

| What | Where |
|---|---|
| Application log | `logs/insightshield.log`, relative to the unit's `WorkingDirectory` (`/opt/insightshield/insightshield/`). Rotating, 5 MB × 5 |
| gunicorn access / error | `/var/log/insightshield/access.log`, `/var/log/insightshield/error.log` |
| Backend exceptions | `error_log` table → Settings → Errors |
| Browser-side errors | same `error_log` table, `source = 'client'` — posted by the `/api/client-error` beacon |
| Who did what | `audit_log` table → Settings → Audit Log, CSV at `/admin/audit.csv` |
| Wazuh integrator | `/var/ossec/logs/integrations.log` (on the manager) |

> `/var/log/insightshield/app.log` **does not exist**, despite being named in at least one
> script's failure hint. Use `error.log` in that directory, or the application log above.

---

## Deploying an update

One command, run as root from the app tree, does the whole Ubuntu deploy and then
verifies it:

```bash
cd /opt/insightshield/insightshield
sudo scripts/deploy.sh
```

`deploy.sh` is a thin orchestrator over the two scripts that do the real work, in the
order that matters:

1. **`scripts/update.sh`** — app tier: `git pull --ff-only` (as the service user),
   `pip install --require-hashes`, redeploy the nginx site (this is where 8444 lands),
   re-apply the firewall, run the idempotent data migrations, restart both units.
2. **`scripts/install.sh`** — rules + Wazuh: install `custom_retail_rules.xml` and the
   integrator, re-sync the `<api_key>`, validate the ruleset with `wazuh-analysisd -t`,
   restart `wazuh-manager`. This is the only script that touches the ruleset.

Then `deploy.sh` **verifies**: ruleset compiles, deployed rules match the repo, rule count
matches what the tests pin, the `ossec.conf` token matches `.env`, all four services are
active, and a live webhook POST with the `.env` token is accepted. The probe is a level-1
alert, which the receiver discards, so a deploy stores nothing and pages no one. Any
failure is printed and the script exits non-zero.

```bash
sudo scripts/deploy.sh --verify   # run only the checks, change nothing
sudo scripts/deploy.sh --app      # app tier only, skip the ruleset
```

**Local edits block the pull.** If the host tree has uncommitted changes,
`git pull --ff-only` fails and `update.sh` stops. Back them up and discard before
deploying: `sudo -u insightshield git -C /opt/insightshield/insightshield stash`,
or `diff > patch` then `checkout --`. Never pipe a `git show` into `install`/`tee` over a
live file — a failed command in that pipe once installed an empty ruleset.

### Changing a detection rule

Edit the repo, never `/var/ossec/etc/rules/` directly — `deploy.sh` fails check 4b when
the deployed file differs from the checkout, and a host-only edit is lost on the next
deploy.

```bash
# Dev machine
python -m pytest tests/test_mitm_rules.py -q      # count, parents, patterns vs live field values
git commit -am "rules: <what and why>" && git push

# Wazuh host
cd /opt/insightshield/insightshield
sudo scripts/deploy.sh                            # pull, install, analysisd -t, restart, verify
```

A new rule changes the count pinned in `test_rule_count`; `deploy.sh` reads that number,
so update the test in the same commit. Match Windows paths with `\\+` per separator —
eventchannel fields arrive with doubled backslashes (see *Querying alerts from the shell*),
and an anchored single-`\\` pattern silently never matches.

---

## Querying alerts from the shell

```bash
DB=/opt/insightshield/insightshield/insightshield.db
sudo -u insightshield sqlite3 -header -column "$DB" <<'SQL'
SELECT rule_id, device_name, COUNT(*) n, MAX(timestamp) last_seen
FROM alerts
WHERE timestamp >= strftime('%Y-%m-%dT%H:%M:%S', 'now', '+8 hours', '-24 hours')
GROUP BY rule_id, device_name ORDER BY n DESC;
SQL
```

Four things that produced wrong answers during the 2026-09 triage:

- **Time windows.** `alerts.timestamp` is ISO text with a `T` and `+08:00`.
  `datetime('now', ...)` returns a *space*-separated value, and `'T' > ' '`, so every row
  on the cutoff's date passes — a "last 24 hours" query returned 35-hour-old rows. Build
  the bound with `strftime('%Y-%m-%dT%H:%M:%S', 'now', '+8 hours', ...)` as above
  (independent of the host time zone). Day-granularity `date('now', ...)` is fine.
- **Event fields.** `json_extract(raw_alert, '$.data.win.eventdata.<field>')`. Security
  4688 (rule `100014`) names the parent `parentProcessName`; `parentImage` is the Sysmon
  Event 1 name and comes back blank on 4688 rows. Sysmon Event 11 (`92213`) has no parent
  at all — its `image` is the process that wrote the file.
- **Backslashes.** Values print as `C:\\Windows\\...` because they *are* doubled in the
  stored event. `LIKE '%cleanmgr.exe'` works; `= 'C:\Windows\System32\cleanmgr.exe'`
  never matches.
- **Host identity.** The POS VMs share one Windows computer name. Group by `device_name`
  (the Wazuh agent name), never by `$.data.win.system.computer`.

---

## A rule is burning the AI quota

A noisy rule that fires often (a false-positive LSASS or ARP detection, hourly) can spend
the whole free-tier AI budget re-analysing the same alert: the manager translation, the
static-retry, and the IT recommendation each run per row, and the recommendation prompt
embeds the raw alert so its cache never hits on a repeat.

Two controls, both in `.env` (see `config.py`):

- **`AI_REPEAT_CAP`** (default 5) — max live AI attempts per `(rule_id, device)` per 24 h,
  counted in `rate_events` so failures count too. Past the cap the pair falls back to the
  static template and to reusing a sibling's recommendation; the alert is still stored,
  notified, and shown. `0` disables the cap.
- **`IT_REC_BACKFILL_MIN`** (default 10) — interval of the sweep that fills blank
  recommendations. When the providers are exhausted, set it to `0` to stop the sweep from
  burning quota retrying rows that keep failing, then restart the worker:
  `sudo systemctl restart insightshield-worker`.

To see which pair is spending the most, and how much is reused vs. blank:

```bash
sudo -u insightshield sqlite3 -header -column /opt/insightshield/insightshield/insightshield.db "
SELECT rule_id, device_name, COUNT(*) n,
  SUM(provider_used IS NOT NULL AND provider_used NOT IN ('cache','static')) live,
  SUM(it_recommendation LIKE '(Reused from alert #%') reused,
  SUM(it_recommendation IS NULL OR it_recommendation='AI_CHAIN_EXHAUSTED') blank
FROM alerts WHERE severity IN ('HIGH','CRITICAL')
  AND timestamp >= date('now','localtime','-7 day')
GROUP BY rule_id, device_name HAVING n > 5 ORDER BY n DESC LIMIT 15;"
```

The real fix is always to tune the rule so it stops firing — the cap is the safety net, not
the cure.

---

## One-shot maintenance scripts

Everything in `scripts/` that is not `install.sh` runs by hand, as the service
user, **through the venv interpreter**. A bare `python3` has none of the
dependencies:

```bash
cd /opt/insightshield/insightshield
sudo -u insightshield /opt/insightshield/venv/bin/python scripts/<name>.py --help
```

| Script | What it does | Safe to re-run? |
|---|---|---|
| `bulk_resolve_alerts.py` | Closes open HIGH/CRITICAL rows left over from test activity, as a named IT admin with a note and one audit-log row. Filter with `--since` / `--until` / `--rules`. | Yes — it only touches rows still open |
| `relabel_alerts.py` | Re-derives `attack_type` on existing rows so old alerts show what a fresh ingest would show. | Yes — idempotent by design, and tested for it |
| `backfill_autoclose.py` | Auto-closes sub-HIGH alerts as the system actor. | Yes |
| `normalize_timestamps.py` | Rewrites stored timestamps to the canonical offset. | Once per drift event |
| `repair_providers.py` | Fixes `provider_used` on rows written during an AI-chain failure. | Yes |

**`bulk_resolve_alerts.py` is a dry run unless you pass `--yes`.** Run it
without the flag first, read the count it prints, then repeat with `--yes`:

```bash
sudo -u insightshield /opt/insightshield/venv/bin/python scripts/bulk_resolve_alerts.py \
  --by <it-admin-username> --note "Test activity, not an attack" \
  --rules 92213,92900,100014 --since "2026-09-12T00:00:00+08:00"
```

It deliberately leaves `it_recommendation` and `response_time_s` alone, and
keeps an existing human acknowledgement — see the header comment in the file
for why each of those would corrupt a different report if it did not.

---

## Dependency review

Dependencies are declared in `requirements.txt` and **installed from
`requirements.lock`**, which pins every transitive package to an exact version
and SHA-256. `scripts/install.sh` uses `--require-hashes`, so a wheel that does
not match the recorded hash fails the install rather than shipping.

**Never install `requirements.txt` directly on a server.** It is the input to
the lock, not an install manifest — unconstrained resolution pulls whatever is
newest that day, which is neither reproducible nor verified. It also produces a
misleading audit: scanning the unpinned file reports a clean bill of health for
a resolution nobody ever installed, while the closure actually running carries
advisories. That gap is exactly what this arrangement closes.

The lock is resolved for the deployment target, so it cannot be installed on a
Windows or macOS development machine — the pinned wheels are Linux ones. Develop
against `requirements.txt`; the lock governs servers.

### Cadence

| When | Do |
|---|---|
| Monthly | `pip-audit -r requirements.lock` and review the result |
| Any advisory rated High or above in a direct dependency | Act immediately — do not wait for the monthly pass |
| After editing `requirements.txt` | Regenerate the lock and re-run the suite before shipping |

### Commands

```bash
# Audit the set that actually gets installed.
pip-audit -r requirements.lock

# Regenerate after changing requirements.txt. The platform and version flags are
# load-bearing: the target is Ubuntu 24.04 / Python 3.12, and a lock resolved on
# a developer's machine pins a different, wrong dependency set.
uv pip compile requirements.txt -o requirements.lock --generate-hashes     --python-platform x86_64-unknown-linux-gnu --python-version 3.12

# Then, always:
python -m pytest
```

Version floors in `requirements.txt` are security minimums and cite the advisory
that forced them. Lowering one re-opens the vulnerability it names.

---

**See also:** `deployment-ubuntu.md` (install and §8 install-time troubleshooting),
`webhook-contract.md` (ingest contract and its own troubleshooting table),
`architecture.md` (why state lives where it does).
