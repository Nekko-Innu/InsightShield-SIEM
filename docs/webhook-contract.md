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
| `192.168.100.30` | the Wazuh manager VM on the lab LAN |

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
| `description` | defaults to `"Wazuh alert rule_id=<id>"` |
| `attack_type` | inferred from `rule_id` — see §7 |
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

`wazuh_receiver._infer_attack_type(rule_id)` checks custom rule ranges first, then a
static map of stock Wazuh rule ids, then falls back to `"Unknown"`.

| Rule id range | Attack type |
|---|---|
| 100001–100009 | `[S] RDP Brute-force` |
| 100010–100019 | `[I] LSASS Credential Dump` |
| 100020–100029 | `[T/D] Ransomware` |
| 100030–100039 | `[T] ARP-MitM` |
| 100040–100043 | `[D] SYN-flood` |
| 100044–100049 | `[T/D] Ransomware` |

Stock Wazuh ids mapped individually: `87701/87702/87710` (LSASS), `60122/60204/60106`
(RDP), `31151/31152/31153` (SYN-flood), `5402/5403/5404` (ARP-MitM), `554/550`
(ransomware via syscheck FIM).

> ### Known gap — rules 100050–100056 land as "Unknown"
>
> The ranges stop at `100049`, but `custom_retail_rules.xml` defines seven baseline rules
> at **100050–100056**. All seven fall through to `rule_map.get(rule_id, "Unknown")`.
>
> This is not cosmetic: `attack_type` feeds `db.get_top_threats` and the AI
> executive-summary prompt, so the mislabelling propagates into the audit report.
>
> Fix is one more branch alongside the others. Separately, note that 100020–100029 is
> mapped to Ransomware while 100020–100022 are the ARP/MitM rules in the XML — those three
> are mislabelled too.

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
        "data": {"srcip": "192.168.100.77"}
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
| Alerts arrive with `attack_type = "Unknown"` | Rule id outside every mapped range — most likely 100050–100056 | See §7 |
| Nothing arrives, no log lines at all | Integrator not installed or not firing | `tail /var/ossec/logs/integrations.log`; confirm the `<integration>` block and `systemctl status wazuh-manager` |

---

**See also:** `deployment-ubuntu.md` §4.2 (integrator install), `runbook.md` (token
rotation), `architecture.md` (where the webhook sits in the request flow).
