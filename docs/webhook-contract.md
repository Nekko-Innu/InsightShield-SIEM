# `/wazuh-webhook` — request contract

The ingest endpoint. Wazuh's integrator daemon POSTs one alert per request; the app
validates it, translates it through the AI chain, stores it and fans out notifications.

This is the application's **only unauthenticated write path**. A caller who gets through
can inject forged alerts, poison the alert history and the audit report, and trigger
Telegram and email notifications. Both gates below are required — neither alone is
sufficient.

Implementation: `web/blueprints/webhook.py`, `wazuh_receiver.py`, `alerts_util.py`.
Sender: `wazuh_rules/custom-insightshield.py`.

---

## 1. Endpoint

```
POST /wazuh-webhook
Content-Type: application/json
X-Webhook-Token: <shared secret>
```

The only CSRF-exempt route in the app (`web/csrf.py`). It carries no browser session.

## 2. Gate 1 — source IP allowlist

`request.remote_addr` must be one of:

| Address | What it is |
|---|---|
| `127.0.0.1` | Wazuh manager on the same host |
| `::1` | same, IPv6 |
| `192.168.1.159` | the Wazuh manager VM on the lab LAN |

Anything else gets `403 {"error": "Unauthorized"}`.

**This gate depends on `ProxyFix`.** nginx terminates TLS and proxies to `127.0.0.1:5000`,
so without `ProxyFix(x_for=1)` in the app config every request arrives looking like
`127.0.0.1` — the first entry in the list — and the allowlist passes for the entire
internet. `x_for=1` means "trust exactly one proxy hop". Do not raise it: each extra hop
trusted is one an attacker can forge.

## 3. Gate 2 — shared secret

`X-Webhook-Token` must equal `config.WAZUH_WEBHOOK_TOKEN`, compared with
`hmac.compare_digest`. Set it in `.env`:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

The same value goes in `ossec.conf` as the integration's `<api_key>`.

Gate 2 exists because gate 1 is not enough once `X-Forwarded-For` is trusted — that header
is client-supplied and forgeable.

**Unset token fails closed.** With no token configured, every payload is rejected 403.
The `not token` check is load-bearing: `compare_digest("", "")` returns `True`, so without
it an unset token would authenticate every anonymous POST instead of rejecting it. `app.py`
logs an error at boot when the variable is missing, so this shows up before the first
payload rather than as a wall of 403s in `integrations.log`.

## 4. Rate limit and body cap

| Limit | Value | Response |
|---|---|---|
| Requests per source IP | 120/min | `429` + `Retry-After` |
| Body size | 256,000 bytes | `413 {"error": "Payload too large"}` |

120/min is roughly twice the busiest burst observed and still bounds a
compromised-but-allowlisted host. The body cap is enforced in the app because nginx's
`client_max_body_size 1m` is bypassed by the E2E suite and by any direct-to-Flask
deployment.

## 5. Payload

Required:

| Field | Type | Constraint |
|---|---|---|
| `rule_id` | string or integer | ≤ 32 characters as a string |
| `device_name` | string | 1–128 characters |
| `rule_level` **or** `severity` | integer / string | at least one must be present |

Optional:

| Field | Behaviour if absent |
|---|---|
| `timestamp` | generated server-side, `datetime.now(tz=config.PHT).isoformat()` |
| `description` | defaults to `"Wazuh alert rule_id=<id>"`. Over 512 characters it is **truncated** to 512 (warning logged), not rejected — Wazuh fills descriptions from event fields, and a deep path used to bounce a real attack's alert |
| `attack_type` | inferred from `rule_id` — see §7. Must be a string of at most 64 characters; longer is rejected `400` |
| nested Wazuh blocks (`agent`, `rule`, `manager`, `decoder`, `location`, `input`, `id`, `full_log`, `data`) | Attack Trail is built from whatever is present |

`rule_id` and `device_name` are length-bounded because both land in the alerts table and
from there on the dashboard, in the audit report, and in Telegram and email bodies.

The integrator sends the **original nested Wazuh alert unchanged, with flat aliases added
on top**. `validate_payload` reads the flat fields; `_extract_attack_trail` reads the
nested blocks. Both get what they expect and nothing is lost.

## 6. Severity derivation

Used only when the payload has no explicit `severity`. `alerts_util.LEVEL_MAP`:

| `rule_level` | Severity |
|---|---|
| 0–1 | *discarded* — `200 {"status": "discarded"}` |
| 2–4 | INFORMATIONAL |
| 5–7 | LOW |
| 8–9 | MEDIUM |
| 10–12 | HIGH |
| 13–15 | CRITICAL |
| > 15 | CRITICAL, with a warning logged |

## 7. `attack_type` derivation

`wazuh_receiver.attack_label(rule_id, payload)`: an explicit `attack_type` in the payload
wins; otherwise the rule id is looked up in `wazuh_receiver.ATTACK_LABELS`, one label per
rule in the form `<plain name> · <STRIDE category>`. A rule not in the map stores Wazuh's
own rule `description` **in full** (up to the 512 cap in §5; no 64-character cut). Only when
that is missing, or is the integrator's `"Wazuh rule <id>"` placeholder, does it fall back
to `"Unknown"`.

Rules defined at **level 0** are absent from this table on purpose. `wazuh-analysisd`
stops processing an event the moment a level-0 rule matches it, so the integrator never
posts one and there is nothing to label — `100090` (Defender's own LSASS scan) is the
current example. Adding an entry for one would be harmless but misleading.

| Rule id | Attack type |
|---|---|
| 100001 | Brute-force login attempt · Spoofing |
| 100002 | Admin login after business hours · Spoofing |
| 100003 | New user account created · Elevation of privilege |
| 100004 | User added to Administrators · Elevation of privilege |
| 100010 | POS memory scraping (card data theft) · Information disclosure |
| 100011 | POS program files changed · Tampering |
| 100012 | Program dropped into POS folder · Tampering |
| 100013 | New Windows service installed · Elevation of privilege |
| 100014 | Suspicious program launched · Tampering |
| 100020 | ARP spoofing (man-in-the-middle) · Spoofing |
| 100021 | Duplicate IP address (possible MitM) · Spoofing |
| 100022 | New device seen on network · Information disclosure¹ |
| 100023 | Gateway address hijacked on this PC (ARP spoofing) · Spoofing |
| 100030 | Port scan · Information disclosure¹ |
| 100031 | SYN flood on this PC · Denial of service |
| 100040 | Network flood (SYN) · Denial of service |
| 100041 | Sustained network flood · Denial of service |
| 100042 | POS service crashed · Denial of service |
| 100043 | POS service stopped · Denial of service |
| 100044 | File changed in POS shared folder · Tampering |
| 100045 | Ransomware-style file rename · Tampering |
| 100046 | Ransomware: mass file changes · Tampering, Denial of service |
| 100047 | Ransomware: encryption confirmed · Tampering, Denial of service |
| 100050 | Baseline: login in business hours |
| 100051 | Baseline: service started |
| 100052 | Baseline: Windows Update |
| 100053 | Baseline: USB storage |
| 100054 | Baseline: password reset |
| 100055 | Baseline: scheduled task |
| 100056 | Baseline: explicit credentials |
| 60122 (stock) | Failed login · Spoofing |
| 60204 (stock) | Repeated failed logins · Spoofing |
| 92900 (stock) | Credential dumping (LSASS) · Information disclosure |
| 100099 | Credential dumping (LSASS) · Information disclosure |

Note: 100099 shares 92900's label on purpose — same threat, so the dashboard, AI prompt, and report aggregate them as one category. 100099 is the mask-independent custom rule that catches procdump's `0x1FFFFF` open, which 92900's `(0x1010\|0x40)` substring filter misses.

¹ STRIDE has no reconnaissance category; "Information disclosure" is the closest fit.

Every other stock rule is deliberately unmapped and shows Wazuh's own description —
the ids once mapped here were other things entirely: `5402–5404` sudo,
`87701/87702` pfSense, `60106` a successful logon, `31151–31153` web-log rules,
`550/554` every FIM change.

## 8. Responses

| Status | Body | Meaning |
|---|---|---|
| `200` | `{"status": "processed", "alert_id": <int>}` | stored; translation and notification dispatched |
| `200` | `{"status": "discarded", "reason": "low-level alert"}` | `rule_level` ≤ 1 — intentional, not an error |
| `400` | `{"error": "Invalid JSON"}` | body did not parse |
| `400` | `{"error": "<validation message>"}` | see §5; message names the offending field |
| `403` | `{"error": "Unauthorized"}` | source IP not allowlisted, **or** bad/missing token |
| `413` | `{"error": "Payload too large"}` | body over 256 KB |
| `429` | rate-limit body + `Retry-After` | over 120/min for this source IP |
| `500` | `{"error": "Alert processing failed — see error log"}` | AI outage or DB failure during processing; the payload was accepted but not stored |

`403` is deliberately identical for both gates — it does not tell an unauthenticated caller
which one they failed.

## 9. Worked example

```bash
curl -sS -X POST http://127.0.0.1:5000/wazuh-webhook \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Token: $WAZUH_WEBHOOK_TOKEN" \
  -d '{
        "rule_id": "100001",
        "rule_level": 12,
        "device_name": "POS-TERMINAL-01",
        "description": "Multiple failed RDP logon attempts",
        "data": {"srcip": "192.168.1.77"}
      }'
```

```json
{"status": "processed", "alert_id": 42}
```

`rule_level: 12` maps to HIGH. Use `13` for CRITICAL if you want to exercise the escalation
path.

## 10. The Wazuh side

`wazuh_rules/custom-insightshield.py` is the integrator. Wazuh's integrator daemon writes
each matching alert to a temp file and calls the script with three positional arguments:

| argv | Source | Purpose |
|---|---|---|
| `argv[1]` | — | path to the alert JSON file |
| `argv[2]` | `<api_key>` in ossec.conf | becomes the `X-Webhook-Token` header |
| `argv[3]` | `<hook_url>` in ossec.conf | the `/wazuh-webhook` URL |

Install:

```bash
sudo cp custom-insightshield.py /var/ossec/integrations/
sudo cp custom-insightshield    /var/ossec/integrations/
sudo chmod 750 /var/ossec/integrations/custom-insightshield*
sudo chown root:wazuh /var/ossec/integrations/custom-insightshield*
# add the <integration> block to ossec.conf — see deployment-ubuntu.md §4.2
sudo systemctl restart wazuh-manager
```

The script is stdlib-only (`urllib`, not `requests`) because Wazuh's bundled Python does
not ship `requests`. Its timeout is 10s. It logs to `/var/ossec/logs/integrations.log`.

## 11. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `403` on every payload | `WAZUH_WEBHOOK_TOKEN` unset in `.env` — fails closed | Set it, restart the service. Check the boot log; `app.py` says so explicitly at startup |
| `403` on every payload, token *is* set | `<api_key>` in ossec.conf does not match | Compare both values. See `runbook.md` for rotating them without dropping alerts |
| `403`, both values match | Source IP not allowlisted, or `ProxyFix` not applied | Check `request.remote_addr` in the app log against §2 |
| `429` | Over 120/min from one source | Expected under a rule storm. If sustained, a rule is too noisy — tune it in Wazuh, not here |
| `413` | Alert body over 256 KB | Usually an enormous `full_log`. `_extract_attack_trail` caps `full_log` at 4096 bytes on storage, but the cap here applies to the whole request |
| Alerts arrive with `attack_type = "Unknown"` | Rule id not in `ATTACK_LABELS` **and** no usable `description` in the payload | See §7; check the integrator is sending `description` |
| Nothing arrives, no log lines at all | Integrator not installed or not firing | `tail /var/ossec/logs/integrations.log`; confirm the `<integration>` block and `systemctl status wazuh-manager` |

---

**See also:** `deployment-ubuntu.md` §4.2 (integrator install), `runbook.md` (token
rotation), `architecture.md` (where the webhook sits in the request flow).
