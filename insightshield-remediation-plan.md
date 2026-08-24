# InsightShield SIEM — Remediation Plan

**Target:** `InsightShield-SIEM-main` — Flask 3.1 + SQLite, 125 files, 40 routes
**Source:** OWASP Top 10:2025 bullet-by-bullet assessment, 2026-08-24 (97 bullets, 14 failing)
**Prepared:** 2026-08-24
**Completed:** 2026-08-25
**Status:** applied — all ten items closed in the working tree, uncommitted

Test suite: 106 passing (93 before this work). Every fix below was verified
against a running instance, not only against unit tests.

---

## Contents

1. [Summary](#summary)
2. [Sequencing](#sequencing)
3. [R-01 — CSV formula injection](#r-01--csv-formula-injection)
4. [R-02 — Logout does not revoke a captured session](#r-02--logout-does-not-revoke-a-captured-session)
5. [R-03 — Wazuh API TLS verification disabled by default](#r-03--wazuh-api-tls-verification-disabled-by-default)
6. [R-04 — Security headers absent from the application tier](#r-04--security-headers-absent-from-the-application-tier)
7. [R-05 — Dependency supply chain](#r-05--dependency-supply-chain)
8. [R-06 — Published bootstrap credentials](#r-06--published-bootstrap-credentials)
9. [R-07 — Log injection via CRLF](#r-07--log-injection-via-crlf)
10. [R-08 — Hostile traffic raises no alert](#r-08--hostile-traffic-raises-no-alert)
11. [R-09 — Unbounded alert id returns HTTP 500](#r-09--unbounded-alert-id-returns-http-500)
12. [R-10 — No MFA on the credential-revealing role](#r-10--no-mfa-on-the-credential-revealing-role)
13. [Also worth doing](#also-worth-doing-not-failing-bullets)
14. [Verification](#verification)
15. [Regression risk](#regression-risk)
16. [Findings that may still occur](#findings-that-may-still-occur)
17. [Corrections to this plan](#corrections-to-this-plan)

---

## Summary

Fourteen OWASP Top 10:2025 bullets failed. They consolidate into **ten remediation items**, because the four A03 supply-chain bullets share one fix and the two header bullets (A02.8, A04.4) share another.

| ID | Bullets closed | Finding | Severity | Status |
|----|---------------|---------|----------|--------|
| R-01 | A05.6 | CSV formula injection in both export paths | **High** | Fixed |
| R-02 | A07.11 | Captured session cookie survives logout | **High** | Fixed |
| R-03 | A04.5 | Wazuh API TLS verification off by default | **High** | Fixed |
| R-04 | A02.8, A04.4 | Security headers only in nginx | **High** | Fixed |
| R-05 | A03.1, A03.2, A03.3, A03.8 | No pinning, lockfile, scanning or cadence | **High** | Fixed |
| R-06 | A07.3 | Bootstrap credentials published | **Medium** | Fixed |
| R-07 | A09.8 | CRLF in `device_name` forges a log line | **Medium** | Fixed |
| R-08 | A09.7 | ~200 hostile requests raised no alert | **Medium** | Fixed |
| R-09 | A10.1 | `/alert/<2**63>` returns HTTP 500 | **Low** | Fixed |
| R-10 | A07.7 | No MFA on the credential-revealing role | **Low** | Accepted and recorded |

Thirteen bullets fixed in code, one (A07.7) closed as a documented accepted risk
in `SYSTEM_DESIGN.md` §15.1 AR-01.

Six of the ten (R-01, R-03, R-04, R-06, R-09, and the config half of R-05) are each under ten lines of code.

---

## Sequencing

**Sitting one — quick wins, low regression risk.**
R-01 → R-03 → R-09 → R-06 → R-04. Each is small, independent, and testable in isolation. R-01 first because it is the only *confirmed exploit* in the report.

**Sitting two — the core mechanism.**
R-02 alone. It touches session identity, so it gets its own commit and its own test written **before** the change.

**Sitting three — infrastructure.**
R-05 then R-07 then R-08. R-08 is the largest and depends on nothing else, so it can slip without blocking.

**Separately.**
R-10 is a decision, not a task. Record the outcome either way.

---

## R-01 — CSV formula injection

**Status: Fixed.** `csv_safe()` in `web/responses.py`, applied at both writers.

**Closes:** A05.6 · **CWE-1236** · **Severity: High** · *This is the only finding reproduced end-to-end.*

### Problem

A payload posted to `/wazuh-webhook` as `device_name` is emitted unescaped by `/export.csv`:

```
1,2026-08-24T18:43:21+08:00,HIGH,=cmd|' /C calc'!A1,[S] RDP Brute-force,...
```

`csv.writer` handles quoting, not formula neutralisation. Excel, LibreOffice and Google Sheets evaluate the cell on open. The delivery path is a security-evidence export an analyst is *expected* to open in a spreadsheet.

`/admin/audit.csv` is the worse of the two: `user_agent` and `details` are attacker-influenced and reach the same sink.

### Fix

Add one helper to `web/responses.py`:

```python
def csv_safe(value):
    """Neutralise spreadsheet formula injection (CWE-1236).

    Excel, LibreOffice and Sheets evaluate any cell whose first character is
    one of = + - @ TAB CR. Prefixing with an apostrophe forces text.
    """
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s
```

Apply at both writers:

```python
# web/blueprints/reports.py:71
w.writerow([csv_safe(row.get(k, "")) for k in cols])

# web/blueprints/admin_ops.py:163
w.writerow([csv_safe(r.get(k, "")) for k in cols])
```

Import `csv_safe` alongside the existing `reject_csv_flood` import in both blueprints.

### Verify

```bash
# after seeding an alert with device_name = "=cmd|' /C calc'!A1"
curl -s ... /export.csv | python3 -c "
import csv,sys
rows=list(csv.reader(sys.stdin))
print([v for r in rows[1:] for v in r if v[:1] in '=+-@'])"
# expected: []
```

`_probe2.py` bullet **A05.6** should flip to PASS.

---

## R-02 — Logout does not revoke a captured session

**Status: Fixed.** `users.session_epoch` folded into the session digest; the missing test was written first and reproduced the defect before the fix.

**Closes:** A07.11 · **CWE-613** · **Severity: High**

### Problem

Capture the session cookie, log out, replay it from a fresh client → **HTTP 200, manager dashboard**.

Sessions are stateless itsdangerous-signed cookies with no server-side revocation. `logout()` calls `session.clear()` and `logout_user()`, which clears *the browser's copy*. A cookie captured beforehand stays valid until the 30-minute signature lifetime expires.

The existing `session_token` mechanism already does exactly the right thing for password changes — it embeds a digest of the password hash, so changing the password invalidates every other session. Logout has no equivalent event to hang off.

**Note on the existing test.** `tests/test_logout_session.py` asserts the *same client* is locked out after logout, and that `session=;` is sent. Both are true and both pass. It never replays a separately captured cookie value. That gap in the test is why the gap in the control survived — worth saying plainly in the write-up.

### Fix

Give each user an epoch that logout increments, and fold it into the digest that already exists.

**Step 1 — schema.** Idempotent column add, consistent with the project's no-migration-framework pattern:

```python
# db.py — call from init_db() after CREATE_USERS_SQL
def _ensure_session_epoch_column(conn) -> None:
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)")}
    if "session_epoch" not in cols:
        conn.execute(
            "ALTER TABLE users ADD COLUMN session_epoch INTEGER NOT NULL DEFAULT 0"
        )

def bump_session_epoch(username: str) -> None:
    """Invalidate every existing session for this account."""
    conn = _get_conn()
    conn.execute(
        "UPDATE users SET session_epoch = session_epoch + 1 WHERE username = ?",
        (username,),
    )
    conn.commit()
```

Add `session_epoch` to the column list returned by `get_user()`.

**Step 2 — digest.** `web/auth_user.py`:

```python
def session_token(password_hash: str | None, session_epoch: int = 0) -> str:
    """Opaque token embedded in the Flask-Login user id.

    Derived from the password hash AND a logout counter, so BOTH a password
    change and a logout invalidate every cookie minted before them.
    """
    raw = f"{password_hash or ''}|{session_epoch}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
```

Thread it through:

```python
class User(UserMixin):
    def __init__(self, username, role, must_change_password=0,
                 password_hash=None, session_epoch=0):
        ...
        self.session_token = session_token(password_hash, session_epoch)
```

```python
@login_manager.user_loader
def load_user(user_id):
    ...
    expected = session_token(user_data.get("password_hash"),
                             user_data.get("session_epoch", 0))
    if not hmac.compare_digest(token, expected):
        logger.info("Rejecting stale session for %s (password change or logout)",
                    username)
        return None
    return User(username, user_data["role"],
                must_change_password=user_data.get("must_change_password", 0),
                password_hash=user_data.get("password_hash"),
                session_epoch=user_data.get("session_epoch", 0))
```

**Step 3 — logout.** `web/blueprints/auth.py:logout()`, **before** `session.clear()`:

```python
db.bump_session_epoch(current_user.username)
```

Placement matters — `current_user` must still be populated.

### Verify

Extend `tests/test_logout_session.py` with the assertion that was missing:

```python
def test_captured_cookie_is_dead_after_logout(live_server, live_server_db):
    """Logout must revoke the cookie itself, not just the browser's copy.

    Clearing the client cookie is not revocation: a value captured before
    logout is a complete, still-signed credential.
    """
    s = requests.Session()
    # ... log in as manager ...
    stolen = s.cookies["session"]
    assert s.get(f"{live_server}/dashboard/manager").status_code == 200
    # ... POST /logout with CSRF ...

    replay = requests.Session()
    replay.cookies.set("session", stolen, domain="127.0.0.1", path="/")
    r = replay.get(f"{live_server}/dashboard/manager", allow_redirects=False)
    assert r.status_code == 302 and "/login" in r.headers["Location"], (
        "a session cookie captured before logout still authenticates"
    )
```

`_probe2.py` bullet **A07.11** should flip to PASS.

### Side effects

- Existing sessions are invalidated once on deploy. Intended, and identical to how the `session_token` change already behaved.
- One extra column read per request — already inside the existing `get_user()` query, so no additional round trip.

---

## R-03 — Wazuh API TLS verification disabled by default

**Status: Fixed.** Default inverted; `or False` dropped at **four** call sites, not the two this plan named.

**Closes:** A04.5 · **CWE-295** · **Severity: High**

### Problem

`config.py:268` — `WAZUH_API_VERIFY` defaults to `""`, and both call sites use `verify=config.WAZUH_API_VERIFY or False`. Out of the box, `wazuh_api.py` sends `WAZUH_API_USER` and `WAZUH_API_PASSWORD` over a TLS connection with **no certificate validation**. The comment documents this as a lab convenience, but the default is what ships.

### Fix

Invert the default and make the opt-out explicit and loud:

```python
# config.py
_verify_raw = os.environ.get("WAZUH_API_VERIFY", "").strip()
if _verify_raw.lower() in ("0", "false", "no", "off"):
    WAZUH_API_VERIFY = False
    logging.getLogger("insightshield.config").warning(
        "WAZUH_API_VERIFY is disabled — Wazuh API credentials will cross an "
        "unverified TLS channel. Acceptable for a self-signed lab manager, "
        "never for production."
    )
elif _verify_raw:
    WAZUH_API_VERIFY = _verify_raw      # path to a CA bundle
else:
    WAZUH_API_VERIFY = True             # verify against the system trust store
```

Then in `wazuh_api.py`, both call sites (lines 45 and 54):

```python
verify=config.WAZUH_API_VERIFY,     # was: config.WAZUH_API_VERIFY or False
```

Dropping `or False` is the load-bearing part — it is what currently converts `""` into "don't verify".

### Also

- Update `.env.example` to document the three accepted values
- Have `scripts/install.sh` copy the manager's CA certificate into `/opt/insightshield/certs/` and set `WAZUH_API_VERIFY` to that path
- Note the lab exception in `docs/deployment-ubuntu.md`

---

## R-04 — Security headers absent from the application tier

**Status: Fixed.** `web/responses.init_app()` sets all six; `Permissions-Policy` added to nginx as well.

**Closes:** A02.8, A04.4 · **Severity: High**

### Problem

Probing a live authenticated response found **no** `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` or `Permissions-Policy`.

`nginx/insightshield.conf` sets the first five correctly (lines 28–37). The posture therefore holds **only** behind that exact reverse proxy, and is absent for `flask run`, direct-to-gunicorn, containers, alternate proxies, and the E2E suite. `Permissions-Policy` is missing at both layers.

The webhook handler already reasons this way about body caps — *"nginx caps bodies at 1m, but the E2E suite and any direct-to-Flask deployment bypass nginx entirely"* — and compensates in the app. Headers deserve the same treatment.

### Fix

```python
# web/responses.py
import config

# Matches nginx/insightshield.conf:37 exactly. Keep the two in sync — if they
# diverge, whichever layer is in front silently wins.
CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
       "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "connect-src 'self'; font-src 'self' data:; frame-ancestors 'none'")

def init_app(app) -> None:
    @app.after_request
    def _security_headers(resp):
        # setdefault, not assignment: where nginx already set a header its
        # value wins, so this is a floor rather than an override.
        resp.headers.setdefault("Content-Security-Policy", CSP)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault(
            "Permissions-Policy",
            "geolocation=(), camera=(), microphone=(), payment=(), usb=()")
        if config.COOKIES_REQUIRE_HTTPS:
            resp.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains")
        return resp
```

Register it in `app.py:create_app()` alongside the other `init_app` calls. `web/responses.py` currently has no `init_app`, so this adds one.

HSTS is gated on `COOKIES_REQUIRE_HTTPS` so a local HTTP dev session doesn't pin the browser to HTTPS for a year.

Add to `nginx/insightshield.conf` after line 31:

```nginx
add_header Permissions-Policy "geolocation=(), camera=(), microphone=(), payment=(), usb=()" always;
```

### Verify

```bash
curl -sI http://127.0.0.1:5000/login | grep -iE \
  'content-security|strict-transport|x-frame|x-content-type|referrer|permissions'
```

All six present. `_probe2.py` bullets **A02.8** and **A04.4** flip to PASS.

---

## R-05 — Dependency supply chain

**Status: Fixed.** `requirements.lock` pins 49 packages with hashes, resolved for the Ubuntu 24.04 / Python 3.12 target.

**Closes:** A03.1, A03.2, A03.3, A03.8 · **Severity: High**

### Problem

`requirements.txt` declares 11 packages: **0 pinned**, 2 with open-ended floors. No lockfile, no hashes, no SBOM, no scanning.

This produces a misleading result: `pip-audit -r requirements.txt` reports **no known vulnerabilities**, because unconstrained resolution pulls today's latest. That is not reproducible and not a guarantee. The **actually installed closure** carries advisories:

| Package | Installed | Advisories | Fixed in |
|---|---|---|---|
| `cryptography` | 46.0.6 | 5 (incl. GHSA-537c-gmf6-5ccf) | 46.0.7 → 50.0.0 |
| `urllib3` | 2.6.3 | 2 (PYSEC-2026-141/142) | 2.7.0 |
| `setuptools` | 68.1.2 | 3 (incl. PYSEC-2026-3447) | 83.0.0 |
| `click` | 8.3.1 | 1 (PYSEC-2026-2132) | 8.3.3 |
| `idna` | 3.11 | 1 (PYSEC-2026-215) | 3.15 |

`cryptography` matters most — it is the entire credential-at-rest story.

### Fix

**Lock with hashes:**

```bash
pip install uv
uv pip compile requirements.txt -o requirements.lock --generate-hashes
pip install --require-hashes -r requirements.lock
```

(`pip-compile --generate-hashes` from `pip-tools` works identically if you prefer.)

**Bump the vulnerable direct dependency** by adding a floor before compiling:

```
cryptography>=46.0.7   # was >=42.0 — PYSEC-2026-36, GHSA-537c-gmf6-5ccf
```

Transitives resolve forward on their own once the lock is regenerated.

**Install from the lock.** `scripts/install.sh` currently installs `requirements.txt`; point it at `requirements.lock` with `--require-hashes`.

**Scan on a schedule:**

```bash
pip-audit -r requirements.lock
```

Add it as a CI step, or as a documented pre-release gate in `docs/runbook.md` if there is no pipeline.

**Extend the manifest pattern you already have.** `static/vendor/VERSIONS.md` documents origin, version, size and SHA-256 for every browser asset, and all five hashes verify. Extend it to cover the pinned Playwright Chromium revision and a SHA-256 for `scripts/install.sh`.

**State a cadence** in `docs/runbook.md` — e.g. monthly review, plus immediate action on any advisory rated High or above in a direct dependency.

---

## R-06 — Published bootstrap credentials

**Status: Fixed.** Literals removed everywhere; seeding refuses to run without the env vars, guarded on the empty-table path.

**Closes:** A07.3 · **CWE-1392, CWE-798** · **Severity: Medium**

### Problem

`admin` / `insightshield2026` and `manager` / `branch2026` appear in `README.md` and `config.py:288`, and both authenticate on a fresh install.

The `must_change_password` gate is real and verified — pre-rotation, every route redirects to `/account/password`. So the window is "first boot until first login". In that window, anyone reaching the login page owns the IT_ADMIN role, which can reveal every stored credential.

### Fix

`.env.example` already declares `BOOTSTRAP_ADMIN_PASSWORD` and `BOOTSTRAP_MANAGER_PASSWORD`. Make them mandatory, mirroring how `crypto_utils.get_master_key()` refuses to start without a key:

```python
# db.py — seed_users_from_config(), before seeding
missing = [k for k in ("BOOTSTRAP_ADMIN_PASSWORD", "BOOTSTRAP_MANAGER_PASSWORD")
           if not os.environ.get(k)]
if missing:
    logger.error(
        "Refusing to seed default accounts: %s not set. Set them in .env — "
        "shipping known bootstrap passwords is how an install gets owned "
        "between first boot and first login.", ", ".join(missing))
    sys.exit(1)
```

Guard it so it only fires when the `users` table is actually empty — an existing install must not be blocked at boot by a missing var it no longer needs.

Then remove the literals from `config.py:288` and the credentials table in `README.md`, replacing them with a pointer to the env vars.

---

## R-07 — Log injection via CRLF

**Status: Fixed.** Implemented as a `logging.Formatter` subclass rather than the Filter proposed below — see Corrections.

**Closes:** A09.8 · **CWE-117** · **Severity: Medium**

### Problem

A `device_name` containing CRLF produced a genuine forged entry in `logs/insightshield.log`:

```
2026-01-01 00:00:00 [insightshield.auth] INFO: LOGIN_SUCCESS admin
```

An attacker who can reach the webhook can write arbitrary lines into the log an investigator later reads. The DB-backed `audit_log` is unaffected — values are bound parameters — so the file log is the whole exposure.

### Fix

Cleanest version is a logging filter, applied once, so no call site can forget:

```python
# app.py, near the logging setup
_CTRL = re.compile(r"[\r\n\x00-\x08\x0b\x0c\x0e-\x1f]")

class _ControlCharFilter(logging.Filter):
    """Escape control characters in log arguments (CWE-117).

    Applied at the handler so every call site is covered — attacker-controlled
    values reach the log from the webhook, the audit middleware and the error
    handler, and any one of them forgetting is a forged log line.
    """
    def filter(self, record):
        if record.args:
            record.args = tuple(
                _CTRL.sub(lambda m: f"\\x{ord(m.group()):02x}", a)
                if isinstance(a, str) else a
                for a in record.args
            )
        if isinstance(record.msg, str):
            record.msg = _CTRL.sub(
                lambda m: f"\\x{ord(m.group()):02x}", record.msg)
        return True

_file_handler.addFilter(_ControlCharFilter())
_stream_handler.addFilter(_ControlCharFilter())
```

Handle the dict-args form of `record.args` too if any call site uses it.

### Verify

Post a webhook payload with `device_name` containing `\r\n` plus a plausible log prefix, then:

```bash
grep -c '^2026-01-01 00:00:00' logs/insightshield.log   # expected: 0
```

---

## R-08 — Hostile traffic raises no alert

**Status: Fixed.** Audit rows at three rejection sites, a scheduled per-source sweep, and one HIGH alert per source per window.

**Closes:** A09.7 · **Severity: Medium**

### Problem

This audit issued roughly 200 hostile requests — SQL injection across 8 parameters, XSS payloads, SSRF attempts, four forged session cookies, and a full unauthorized sweep of every route. **None raised an alert.** 403s, CSRF rejections and webhook auth failures are `logger.warning` only: no audit row, no alert, no dashboard surface.

A09's 2025 rename exists precisely for this — logging without alerting is of minimal value. A sustained authorization-probing campaign is currently invisible to the operator.

### Fix

The machinery already exists: `db.failed_logins_in_window` plus the `credential_brute_force` escalation. Generalise it.

**Step 1 — make the failures auditable.** Add `db.log_audit` calls with a distinct action at three sites:

| Site | Action |
|---|---|
| `web/csrf.py:_enforce_csrf` (rejection branch) | `CSRF_REJECTED` |
| `web/errors.py:_handle_forbidden` | `AUTHZ_DENIED` |
| `web/blueprints/webhook.py` (both 403 branches) | `WEBHOOK_AUTH_FAILED` |

Record actor where known, IP always.

**Step 2 — count them.** Generalise the existing window query:

```python
# db.py — alongside failed_logins_in_window
def security_events_in_window(actions: tuple[str, ...], ip: str,
                              minutes: int = 60) -> int:
    ...
```

**Step 3 — sweep and alert.** In `scheduler.py`, alongside `_escalation_sweep`:

```python
def _authz_probe_sweep() -> None:
    """N authorization failures from one source in an hour is a campaign,
    not a mistake. Routes through the same path as credential_brute_force."""
```

Raise a HIGH alert through `alert_router.route_alert` so it inherits the existing Telegram and email fan-out.

**Step 4 — tune the threshold.** Start high (e.g. 25/hour/IP) and lower it once you have a baseline. A09 explicitly warns that false-positive volume is its own failure mode.

### Verify

Re-run `_probe2.py`, then check `/admin/audit` for `AUTHZ_DENIED` rows and the alerts table for a raised probe alert. Bullet **A09.7** flips to PASS. This is the one fix that turns the product on the traffic this audit generated.

---

## R-09 — Unbounded alert id returns HTTP 500

**Status: Fixed.** Bounded on the URL converter rather than in the view bodies — see Corrections.

**Closes:** A10.1 · **CWE-20** · **Severity: Low**

### Problem

`GET /alert/9223372036854775808` → **HTTP 500**. SQLite rejects the out-of-range integer and the exception escapes to the global handler. The custom error page renders (no traceback leaks), but a 500 on well-formed input is a reachable unhandled condition — 1 failure out of 21 abnormal inputs tested.

### Fix

```python
# web/blueprints/alerts.py and web/blueprints/api.py
# Flask's <int:> converter accepts arbitrarily large values; SQLite does not.
if not 0 < alert_id <= 2**31 - 1:
    abort(404)
```

Applies to `/alert/<int:alert_id>`, its two POST children, and `/api/alert/<int:alert_id>`. A shared helper or a custom URL converter avoids repeating it four times.

---

## R-10 — No MFA on the credential-revealing role

**Status: Accepted and recorded.** Option A taken. `SYSTEM_DESIGN.md` §15.1 AR-01 records the exposure, eight verified compensating controls, and the four conditions that reverse the decision.

**Closes:** A07.7 · **CWE-308** · **Severity: Low (design decision)**

### Problem

Single-factor authentication on a role that can decrypt every stored credential via `/admin/settings/api-keys/<service>/reveal`.

### Options

**A. Accept the risk.** Defensible for a two-user single-branch deployment. Record it in `SYSTEM_DESIGN.md` with the reasoning, the compensating controls (5/min reveal cap, audit row per reveal with `last4` only, 30-minute idle timeout, brute-force escalation), and the conditions that would change the answer. An explicitly accepted risk is a legitimate answer to an OWASP bullet; an unmentioned one is not.

**B. Step-up on the sensitive action.** Cheaper than full MFA and closes most of the gap: require password re-entry before `/admin/settings/api-keys/<service>/reveal` returns plaintext. Roughly one form and one session flag.

**C. Full TOTP.** `pyotp` plus a secret column and an enrolment flow. Correct for a multi-tenant or internet-exposed deployment; probably disproportionate here.

**Recommendation:** B if there is time, A if there is not. Do not leave it unrecorded.

---

## Also worth doing (not failing bullets)

These are PARTIAL findings — controls that work but are incomplete. None are urgent; all are cheap.

- **A05.1 — validate `severity`.** `validate_payload` checks `rule_id` and `device_name` types and lengths, but a payload supplying `severity` directly has it taken verbatim. Add a membership check against `config.SEVERITY_LEVELS`. It propagates into routing, the health score and the severity chart.
- **A09.1 — audit the audit export. DONE.** `/admin/audit.csv` now writes an
  `EXPORT_AUDIT_CSV` row with actor, IP, row count, a `truncated` flag and the
  active filters. Original note follows.
- **A09.1 (original note).** `/export.csv` writes an `EXPORT_CSV` row; `/admin/audit.csv` writes nothing. The one action that copies the evidence out of the system is the one action not recorded. Mirror the `db.log_audit` call, including active filters and row count.
- **A08.5 — drop the plaintext restore branch.** `backup.restore_db` accepts a legacy plaintext `.db` by direct `shutil.copy2` with no integrity check. The `.db.enc` path is covered (Fernet is authenticated encryption). Remove the legacy branch, or gate it behind an explicit flag.
- **A09.3 — audit log tamper-evidence.** `audit_log` is an ordinary table. No route deletes from it, but DB-level write access would. A hash chain over `(id, ts, actor, action, target)` would make tampering detectable.
- **A10.7 — record IT-recommendation thread failure.** `_kick_it_recommendation` is a daemon thread that dies silently on worker shutdown, leaving `it_recommendation` NULL with nothing saying it was attempted. A `WARN` on abort would help operators.
- **A04.2 — separate the backup key.** One `ENCRYPTION_KEY` wraps the credential store *and* the database snapshots, so one key compromise yields both. Consider a separate backup key or envelope encryption. Also: no rotation path exists today.

---

## Verification

After each sitting:

```bash
# 1. Project suite must stay green
python -m pytest -m "not slow"        # expect 93 passed

# 2. Re-run the bullet-mapped probes
python3 _probe2.py                     # expect failing bullets to flip

# 3. Round-1 probes for the confirmed exploit
python3 _probe.py
```

Bullet status:

| Bullet | Status |
|---|---|
| A05.6 CSV formula injection | PASS |
| A07.11 session invalidation | PASS |
| A04.5 certificate validation | PASS |
| A02.8 security headers | PASS |
| A04.4 encryption directives | PASS |
| A03.1 / A03.2 / A03.3 / A03.8 | PASS ×4 |
| A07.3 default passwords | PASS |
| A09.8 log encoding | PASS |
| A09.7 DAST alerting | PASS |
| A10.1 abnormal input | PASS |
| A07.7 MFA | Accepted risk, recorded — `SYSTEM_DESIGN.md` §15.1 AR-01 |
| A09.1 audit export coverage | PASS (was PARTIAL) |

**97 bullets, 0 FAIL.**

### What was actually run

| Check | Result |
|---|---|
| `python -m pytest` (full, including the slow idle-timeout test) | 106 passed |
| Live instance against a **migrated** copy of the real database | 14 checks, all pass |
| Migration branch on an old-shape `users` table, run twice | Column added, data intact, idempotent |
| `pip-audit -r requirements.lock` | No known vulnerabilities |

The migrated-database run matters because every test fixture builds a fresh DB,
so the `ALTER TABLE` path that a real upgrade depends on is never exercised by
the suite. It covered: an existing install booting with `BOOTSTRAP_*` unset, a
user row predating `session_epoch` logging in, a captured cookie dying at
logout, all six headers present with no nginx in front, and re-login working
after the epoch bump.

One caveat on A02.8 and A04.4 — the probes run without nginx in front. That isolation is deliberate and is why those bullets failed in the first place, so after R-04 they should pass *without* the proxy. If they only pass behind nginx, the fix did not land.

---

## Regression risk

| Item | Risk | Mitigation |
|---|---|---|
| R-01 | Very low — output formatting only | CSV consumers see a leading `'` on affected cells; document it |
| R-02 | **Moderate — touches session identity** | Own commit, test first, verify all 93 tests still pass. Invalidates existing sessions once on deploy (intended) |
| R-03 | Low, but **will break a self-signed lab manager** until `WAZUH_API_VERIFY=0` or a CA path is set. Call this out in the deploy notes |
| R-04 | Low — CSP is copied verbatim from the working nginx policy. Watch for console errors on the settings page, which uses inline handlers |
| R-05 | Low, but resolves new versions — run the full suite before shipping the lock |
| R-06 | Low. Guard on empty `users` table so existing installs don't fail at boot |
| R-07 | Very low — log formatting only |
| R-08 | Low functionally; **tune the threshold** or the operator gets alert fatigue, which A09 names as its own failure |
| R-09 | Very low |
| R-10 | Decision only |

---

## Findings that may still occur

Nothing here is a failing bullet. These are the things that can bite later:
work deliberately deferred, ceilings knowingly accepted inside the fixes above,
and maintenance that decays if nobody does it.

### Deferred — real gaps, none urgent

| ID | Finding | Why it matters | Cost |
|---|---|---|---|
| A05.1 | `severity` from a webhook payload is taken verbatim; `validate_payload` checks `rule_id` and `device_name` but not this | Propagates into routing, the health score and the severity chart, so a crafted payload can steer notifications | Membership check against `config.SEVERITY_LEVELS`, minutes |
| A08.5 | `backup.restore_db` accepts a legacy plaintext `.db` by direct `shutil.copy2`, no integrity check | The `.db.enc` path is authenticated (Fernet); this branch is not, so a swapped file restores silently | Delete the branch, or gate it behind an explicit flag |
| A09.3 | `audit_log` is an ordinary table with no tamper evidence | No route deletes from it, but DB-level write access would, and the audit trail is the evidence | Hash chain over `(id, ts, actor, action, target)` |
| A10.7 | `_kick_it_recommendation` is a daemon thread that dies silently on worker shutdown | Leaves `it_recommendation` NULL with nothing recording that it was attempted | One `WARN` on abort |
| A04.2 | One `ENCRYPTION_KEY` wraps both the credential store and the database snapshots | One key compromise yields both; no rotation path exists | Separate backup key or envelope encryption |

### Ceilings accepted inside the fixes

| Where | Ceiling | When it becomes a problem | Upgrade path |
|---|---|---|---|
| R-02 | `session_epoch` is per **user**, not per session, so logging out of one browser signs the account out everywhere | Only once sessions per device are wanted; harmless for two accounts | Session-id table, digest keyed off that. Marked `ponytail:` in `db.bump_session_epoch` |
| R-08 | One `audit_log` write per rejected request, unthrottled | A sustained flood is also a flood of small writes. Bounded by the 90-day `AUDIT_RETENTION_DAYS` purge, and the flood is what the sweep alerts on | Per-IP write cap — but capping blindly blinds the detector. Marked `ponytail:` in `web/errors.py` |
| R-08 | `AUTHZ_PROBE_LIMIT` defaults to 25/hour/IP, set high on purpose | Too high and a real campaign is missed; too low and the operator learns to ignore the alert, which A09 names as its own failure | Lower it once there is a baseline. Env-overridable, no code change |
| R-04 | The CSP is duplicated between `web/responses.py` and `nginx/insightshield.conf` | If they drift, whichever layer is in front silently wins | Comments in both point at each other; `setdefault` makes the app tier a floor, not an override |
| R-01 | Affected CSV cells gain a leading apostrophe | Visible to anyone opening the export; may surprise a consumer parsing it | Document it for report readers |

### Maintenance that decays

- **The lock goes stale.** `requirements.lock` was clean on 2026-08-25 and will
  not stay that way. `docs/runbook.md` sets the cadence: monthly
  `pip-audit -r requirements.lock`, and immediate action on any advisory rated
  High or above in a direct dependency.
- **The lock is Linux-only.** It is resolved for Ubuntu 24.04 / Python 3.12, so
  it cannot be installed on a Windows or macOS dev machine. Development still
  runs against unpinned `requirements.txt`; only servers are pinned.
- **First boot now fails without `BOOTSTRAP_*`.** Intended, but it means a fresh
  deployment that skips `.env` will not start. `docs/deployment-ubuntu.md` §5.8
  says so; an operator who does not read it will meet a `sys.exit(1)`.
- **The brute-force escalation is barely reachable.** `_THROTTLE_IP_LIMIT` is 5
  failures per 15 minutes and returns 429 *before* writing a `LOGIN_FAILURE`
  row, while `_THROTTLE_ESCALATE_LIMIT` needs 20 such rows per IP per hour. Only
  an attacker pacing themselves to roughly 5 per 15-minute window trips it. This
  predates the work above and was left alone deliberately — retuning a live
  throttle is an operational decision, not a remediation.
- **A07.7 is a decision with an expiry.** `SYSTEM_DESIGN.md` §15.1 AR-01 lists
  four conditions that reverse it, the first being internet exposure. Re-read it
  before any change to where this deployment sits on the network.

---

## Corrections to this plan

Written down because the plan was accurate enough to work from, and the places
it was wrong are the places a future reader would trip.

| Item | The plan said | Actually |
|---|---|---|
| R-03 | Two call sites use `verify=... or False` | **Four** — `wazuh_api.py` ×2 and `web/blueprints/admin_settings.py` ×2. Fixing two would have left credentials crossing an unverified channel from the settings page |
| R-05 | `cryptography` fixed in 46.0.7 | 46.0.7 has since picked up PYSEC-2026-3552/3553/3554 and GHSA-537c-gmf6-5ccf. The floor is **50.0.0**. Re-run the audit; do not trust a version number in a document |
| R-02 | The idempotent column add is "consistent with the project's no-migration-framework pattern" | There was no such pattern — `_ensure_session_epoch_column` is the first migration helper in the codebase |
| R-07 | Use a `logging.Filter` on both handlers, mutating `record.args` and `record.msg` | Implemented as a `Formatter` subclass overriding `formatMessage`. Escaping the whole formatted record would flatten every exception traceback onto one line |
| R-09 | Add a bounds check to four view bodies | Bounded on the URL converter instead: `<int(min=1, max=2147483647):alert_id>`. Werkzeug already supports it, so out-of-range fails to match and 404s with no code in any view |
| R-08 | Add `_authz_probe_sweep` alongside the existing escalation | The existing `_maybe_dispatch_brute_force_alert` was generalised into `alert_router.dispatch_internal_alert` and both callers now use it, rather than duplicating seventy lines of dedupe/store/route/audit |
| R-05 | Add a SHA-256 of `scripts/install.sh` to `static/vendor/VERSIONS.md` | Skipped. It invalidates on every edit to that file for no real gain once the dependency set is hash-pinned |

---

*Derived from the OWASP Top 10:2025 bullet-by-bullet assessment dated 2026-08-24. Line numbers refer to the archive as supplied and will drift as changes land.*
