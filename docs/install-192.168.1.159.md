# Insight Shield — install on the existing Wazuh box (192.168.1.159)

Every command below runs **on the Ubuntu server**, as your normal user with
`sudo`.

Companion to `docs/deployment-ubuntu.md` — that one is the full runbook with the
reasoning. This one is the short path for *this* lab: the address, the agent
names and the line-ending rules are all committed to `main`, so a clone lands
ready to install and §2 is verification rather than patching.

> **⚠ Port topology — this runbook's `8443` is stale.** Live state: the **Wazuh
> dashboard keeps `443`**, **Insight Shield's nginx is on `8444`**. The tables
> and steps below that say "dashboard → 8443, Insight Shield → 443" describe an
> earlier plan; the scripts and the running box do the reverse. Canonical URLs:
> Insight Shield `https://192.168.1.159:8444`, Wazuh dashboard
> `https://192.168.1.159`. `sudo scripts/deploy.sh --verify` confirms the ports.

---

## 0. Pre-flight — what you have and what changes

### Already working

| Host | IP | Role |
|---|---|---|
| Wazuh Server (Ubuntu) | `192.168.1.159` | manager + indexer + dashboard, agent `wazuh-system` |
| Manager (Windows) | `192.168.1.188` | agent `Manager` |
| POSsys1 (Windows) | `192.168.1.137` | agent `POSsys1` |
| POSsys2 (Windows) | `192.168.1.185` | agent `POSsys2` |
| POSsys3 (Windows) | `192.168.1.186` | agent `POSsys3` |

Insight Shield goes on `192.168.1.159`, alongside the manager. Wazuh's
integrator daemon pushes alerts to it over loopback — nothing crosses the
network.

### What the install changes on this box

| Change | Before | After |
|---|---|---|
| Wazuh dashboard port | `https://192.168.1.159` (443) | **`https://192.168.1.159:8443`** |
| Port 443 | Wazuh dashboard | nginx → Insight Shield |
| `/var/ossec/etc/ossec.conf` | as-is | one `<ossec_config>` block appended (backup taken) |
| `/var/ossec/etc/rules/` | stock | `+ custom_retail_rules.xml` (rule IDs 100001-100099, plus three stock arpwatch rules overwritten to level 3) |
| `/var/ossec/integrations/` | stock | `+ custom-insightshield`, `+ custom-insightshield.py` |
| ufw | probably inactive | enabled, default deny incoming |

**Write down the new dashboard URL now.** Losing track of it is the single most
common "I broke Wazuh" moment during this install. Nothing is broken — it moved.

### The two things that actually break

1. **Blank bootstrap passwords crash-loop the app.**
   `db.seed_users_from_config()` calls `sys.exit(1)` when
   `BOOTSTRAP_ADMIN_PASSWORD` / `BOOTSTRAP_MANAGER_PASSWORD` are empty, and
   `install.sh` does **not** generate them. With `Restart=always` +
   `RestartSec=5` that is a restart every five seconds forever. Fill `.env`
   *before* running the installer. → **§3**
2. **`ufw` does not flush conntrack.** Your four agents are connected right now
   and will survive `firewall.sh` on established sessions — any mistake in the
   1514/1515 rules only surfaces at the next reconnect, possibly hours later.
   Force a reconnect and verify. → **§4.2**

### Time budget

30-45 minutes, most of it `pip install` and the Chromium download.

---

## 1. Prerequisites

### 1.1 Check the box can take it

```bash
python3 --version      # need >= 3.10; requirements.lock is resolved for 3.12
lsb_release -a         # 22.04 or 24.04
free -g                # 8 GB minimum — the Wazuh indexer alone wants 4 GB heap
df -h /                # 50 GB+
nproc                  # 4 vCPU
```

> **If `python3 --version` says 3.10** (Ubuntu 22.04): `requirements.lock` was
> compiled with `--python-version 3.12`. It will most likely install cleanly. If
> `pip` errors on an environment marker or a missing backport, **stop** — do not
> fall back to `requirements.txt`. `scripts/install.sh:117` refuses that path on
> purpose: the lock is hash-verified, `requirements.txt` resolves to whatever is
> newest that day.

### 1.2 Packages

```bash
sudo apt update && sudo apt install -y \
  python3 python3-venv python3-pip \
  nginx openssl \
  sqlite3 jq curl git dos2unix \
  tzdata ufw logrotate \
  build-essential libssl-dev libffi-dev python3-dev
```

`tzdata` is **not** optional. Every timestamp in the app uses
`ZoneInfo("Asia/Manila")`; without the tz database `config.py` raises
`ZoneInfoNotFoundError` at import and nothing starts.

`dos2unix` is only a fallback for §2.2 — a clean clone should not need it.

### 1.3 Timezone and clock

```bash
sudo timedatectl set-timezone Asia/Manila
sudo timedatectl set-ntp true
timedatectl status
```

Want: `System clock synchronized: yes` and `NTP service: active`. The webhook
rejects any alert timestamped more than 5 minutes in the future or more than
7 days in the past — a drifting clock silently drops alerts.

### 1.4 Confirm the IP is static, not a DHCP lease

```bash
ip -4 addr show scope global | grep 'inet 192.168.1.159/'
ip -4 route
```

If it came from DHCP, pin it. Ubuntu **Desktop** (NetworkManager):

```bash
nmcli -t -f NAME,DEVICE connection show      # get the exact profile name

sudo nmcli connection modify "Wired connection 1" \
  ipv4.method manual \
  ipv4.addresses 192.168.1.159/24 \
  ipv4.gateway 192.168.1.1 \
  ipv4.dns "192.168.1.1 1.1.1.1" \
  ipv4.ignore-auto-dns yes \
  connection.autoconnect yes

sudo nmcli connection up "Wired connection 1"
```

> **Ubuntu Desktop: do not use netplan for this.** A static block in
> `/etc/netplan/*.yaml` on a Desktop install appears to work — `netplan apply`
> exits 0 — then NetworkManager and the GUI hold conflicting views of the device
> and the address is lost at the next NM restart. Every "Ubuntu static IP"
> tutorial online is written for Server.

Ubuntu **Server** only (`renderer: networkd`):

```yaml
# /etc/netplan/01-static.yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3:                       # match `ip -br link`
      dhcp4: no
      addresses: [192.168.1.159/24]
      routes:
        - to: default
          via: 192.168.1.1
      nameservers:
        addresses: [192.168.1.1, 1.1.1.1]
```

```bash
sudo chmod 600 /etc/netplan/01-static.yaml
sudo netplan apply
```

> Changing the address **after** Wazuh is installed means regenerating Wazuh's
> certificates and re-enrolling agents. If it is already `192.168.1.159` and
> agents are connected, leave the networking alone.

### 1.5 `/etc/hosts`

```bash
grep -q insightshield.local /etc/hosts || \
  echo "192.168.1.159  insightshield.local" | sudo tee -a /etc/hosts

getent hosts insightshield.local     # must print 192.168.1.159
```

Leave Ubuntu's stock `127.0.1.1 <hostname>` line alone — removing it makes every
`sudo` hang for several seconds.

The TLS cert covers both `insightshield.local` and `192.168.1.159`, but the POS
PCs have no such hosts entry, so staff browse to `https://192.168.1.159`. To use
the name there too, add the same line to each Windows box's
`C:\Windows\System32\drivers\etc\hosts`.

---

## 2. Clone and patch

### 2.1 Clone into `/opt/insightshield/insightshield`

The path is **load-bearing**, not a preference:

- both systemd units set `WorkingDirectory=/opt/insightshield/insightshield`
- nginx does `alias /opt/insightshield/insightshield/static/`
- `db.py` resolves `insightshield.db` **relative to the working directory**, so
  starting the worker anywhere else silently creates a second empty database

```bash
sudo mkdir -p /opt/insightshield
sudo git clone https://github.com/Nekko-Innu/InsightShield-SIEM.git \
  /opt/insightshield/insightshield

cd /opt/insightshield/insightshield
ls -la          # sanity: app.py, config.py, db.py, scripts/, wazuh_rules/
```

Private repo → git prompts for credentials. Use a GitHub **personal access
token** as the password (your account password will be rejected), or run
`gh auth login` first.

### 2.2 Confirm the line endings

The repo is authored LF and `.gitattributes` pins `*.sh`, `*.py`, `*.service`,
`*.conf`, `logrotate/insightshield` and the integrator wrapper to `eol=lf`, so a
clone on Linux lands correct. One command to be sure:

```bash
git ls-files --eol | grep -E '\.(sh|py|service|conf)$|custom-insightshield|logrotate' | grep -v 'w/lf'
```

Prints nothing → everything is LF, move on. Anything listed came in as CRLF
(a clone made through a Windows share, or a file edited on Windows and copied
over) — fix just those:

```bash
sudo dos2unix <the files it listed>
```

Why it matters: a `\r` in a shell script gives
`bad interpreter: /usr/bin/env bash^M`, and a `\r` in a `.service` file stays
*inside* the quoted value — `Environment="PLAYWRIGHT_BROWSERS_PATH=…\r"` points
at a path that does not exist, so `/report.pdf` fails while healthcheck check 15
still passes, because the variable IS set.

### 2.3 Verify the IP — already correct in `main`

`192.168.1.159` is committed to `main`, so a fresh clone lands ready. This is a
check, not a step. The first command must print a dozen-ish hits, the second
must print **nothing**:

```bash
cd /opt/insightshield/insightshield
grep -rn "192\.168\.1\.159" web/ nginx/ scripts/ config.py
grep -rn "192\.168\.100\.30" web/ nginx/ scripts/ config.py
```

What each hit is:

| File | Line | What it is |
|---|---|---|
| `web/blueprints/webhook.py` | 46 | `allowed_ips = ["127.0.0.1", "::1", "192.168.1.159"]` — gate 1 of the webhook |
| `nginx/insightshield.conf` | 10, 17 | `server_name` in the `:80` redirect and the `:443` server block |
| `scripts/install.sh` | 192 | `-addext "subjectAltName=DNS:insightshield.local,IP:192.168.1.159"` |
| `scripts/healthcheck.sh` | 382-391 | check 20 — asserts the address is on an interface and resolves |
| `scripts/healthcheck.sh` | 337, 344, 379 | comments only, kept accurate |
| `scripts/firewall.sh` | 37 | comment only |

The `127.0.0.1` and `::1` entries in the allowlist stay. The integrator posts
over loopback, so those are the ones that carry production traffic.

> **If you ever move the box to a different address**, the same five files need
> changing — and note that check 20 writes the address **twice**: once plain,
> once regex-escaped inside a `grep` pattern (`inet 192\.168\.1\.159/`) at line
> 382. A plain `sed s/old/new/g` silently misses the escaped copy, and check 20
> then fails against a correctly configured host. This handles both forms:
>
> ```bash
> sudo python3 - <<'EOF'
> import pathlib
> OLD, NEW = "192.168.1.159", "<the new address>"
> for name in ["web/blueprints/webhook.py", "nginx/insightshield.conf",
>              "scripts/install.sh", "scripts/healthcheck.sh",
>              "scripts/firewall.sh"]:
>     p = pathlib.Path(name); s = p.read_text()
>     n = s.replace(OLD, NEW).replace(OLD.replace(".", r"\."),
>                                     NEW.replace(".", r"\."))
>     if n != s:
>         p.write_text(n); print("patched", name)
> EOF
> ```
>
> Then re-issue the TLS certificate — `install.sh` will not replace an existing
> one, so delete it first: `sudo rm /etc/nginx/ssl/insightshield.{crt,key}` and
> re-run the installer.

### 2.4 Agent names in the fallback list — already correct

`config.py:240` is the static device list the dashboard falls back to when the
Wazuh API is unreachable. `main` already carries your five real agent names:

```python
KNOWN_DEVICES = ["wazuh-system", "Manager", "POSsys1", "POSsys2", "POSsys3"]
```

Not purely cosmetic: when the API call fails these names are what the dashboard
renders, and if they do not match the real agent names you get duplicate device
tiles the moment the API recovers. Confirm they still match:

```bash
sudo /var/ossec/bin/agent_control -l
grep -A1 KNOWN_DEVICES /opt/insightshield/insightshield/config.py | tail -1
```

### 2.5 Upgrading later

Everything in §2.3 and §2.4 is committed to `main`, so upgrades are a plain
pull — no stashing, no re-patching:

```bash
cd /opt/insightshield/insightshield
sudo -u insightshield /opt/insightshield/venv/bin/python -m backup   # always first
sudo git pull
sudo scripts/install.sh          # idempotent — re-run after every pull
sudo scripts/healthcheck.sh
```

The only file that is never touched by a pull is `.env` — it is gitignored, so
your secrets and the generated `WAZUH_WEBHOOK_TOKEN` survive.

---

## 3. Fill `.env` — before the installer, not after

This ordering is the whole point. `install.sh` creates `.env` from
`.env.example` if it is missing, generates three secrets into it, then
**immediately starts the services** — and a `.env` with blank bootstrap
passwords makes that start fail. Create it first and the install runs clean end
to end.

### 3.1 Create the file

```bash
cd /opt/insightshield/insightshield
sudo cp .env.example .env
sudo chmod 600 .env
```

### 3.2 Get the `wazuh-wui` password

This is what the app authenticates with against `https://127.0.0.1:55000` for
live agent status.

```bash
# from wherever you ran wazuh-install.sh — usually ~ or /root
sudo tar -O -xf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt \
  | grep -B2 -A2 'wazuh-wui'
```

Tarball gone? Reset it instead:

```bash
sudo /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh \
  -u wazuh-wui -p '<new-strong-password>'
```

### 3.3 Edit

```bash
sudo nano .env
```

**Fill these:**

| Variable | Value | Why |
|---|---|---|
| `BOOTSTRAP_ADMIN_PASSWORD` | strong password | **Required.** No default exists. Forced change at first login. |
| `BOOTSTRAP_MANAGER_PASSWORD` | strong password | **Required.** Same. |
| `WAZUH_API_PASSWORD` | from §3.2 | Live agent tiles. Without it the dashboard shows `KNOWN_DEVICES` with status `unknown`. |
| `WAZUH_API_URL` | `https://127.0.0.1:55000` | Already the default — leave it. |
| `WAZUH_API_USER` | `wazuh-wui` | Already the default — leave it. |
| `WAZUH_API_VERIFY` | `0` | See the security note below. |
| `GROQ_API_KEY` | your key | Optional. Primary AI provider. |
| `GEMINI_API_KEY` | your key | Optional. Fallback. |
| `OPENROUTER_API_KEY` | your key | Optional. Second fallback. |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` | your values | Optional. IT group gets all MEDIUM+. |
| `TELEGRAM_MANAGER_BOT_TOKEN` / `TELEGRAM_MANAGER_CHAT_ID` | your values | Optional. Manager gets HIGH/CRITICAL + resolutions. |
| `GMAIL_ADDRESS` / `GMAIL_APP_PASSWORD` | your values | Optional. Use a Google **App Password**, not the account password. |
| `IT_ADMIN_EMAIL` | your address | Optional. Email recipient. |

**Leave these blank —** `install.sh` generates all three and never overwrites a
value that is already set:

```
ENCRYPTION_KEY=
FLASK_SECRET_KEY=
WAZUH_WEBHOOK_TOKEN=
```

**Leave every other line blank.** Blank values are skipped at first boot;
placeholder text like `your-key-here` gets stored as a **live credential**, and
flips the one-shot `bootstrap_complete` sentinel so every later `.env` edit
becomes a no-op.

> **Security note on `WAZUH_API_VERIFY=0`.** This disables TLS certificate
> verification on the app → Wazuh API call, which sends the `wazuh-wui`
> credentials over an unvalidated channel. `config.py` logs a warning about it
> at every boot. It is acceptable here only because the connection never leaves
> the box (`127.0.0.1:55000`) — an attacker would already need local access.
> This is a lab setting; do not carry it to a real deployment. The alternative
> is pointing it at a CA bundle path for the manager's self-signed cert.

> `WAZUH_API_URL` can **only** be set here, never later through the Settings UI.
> The SSRF guard at `web/blueprints/admin_settings.py:253` rejects loopback and
> private addresses, so `https://127.0.0.1:55000` cannot be re-entered in the
> browser once changed.

### 3.4 Sanity check

```bash
sudo grep -nE '=(your-|generate-a-|change-me)' .env     # must print NOTHING
sudo grep -c '^BOOTSTRAP_ADMIN_PASSWORD=.\+' .env       # must print 1
sudo grep -c '^BOOTSTRAP_MANAGER_PASSWORD=.\+' .env     # must print 1
```

---

## 4. Install

### 4.1 The installer

```bash
sudo /opt/insightshield/insightshield/scripts/install.sh
```

Ten sections, idempotent, safe to re-run any number of times:

| § | What it does |
|---|---|
| 1 | Preflight — root, app tree sanity, required binaries, detect `/var/ossec` |
| 2 | Creates the `insightshield` system user and `/var/log/insightshield`; sets ownership; gives nginx traverse on the tree; strips world-read bits off everything except `static/` |
| 3 | Builds `/opt/insightshield/venv`, installs `requirements.lock` with `--require-hashes` (any tampered wheel fails the install) |
| 4 | Generates `FLASK_SECRET_KEY`, `ENCRYPTION_KEY`, `WAZUH_WEBHOOK_TOKEN` into `.env` — **only if empty**; `chmod 600` |
| 5 | Chromium into `/opt/insightshield/ms-playwright` (relocated because the units set `ProtectHome=true`) + `install-deps` |
| 6 | Self-signed cert at `/etc/nginx/ssl/`, installs the vhost, removes the stock `default` site, `nginx -t`, reload |
| 7 | Copies rules + integrator into `/var/ossec`, appends the `<integration>` block to `ossec.conf`, validates with `wazuh-analysisd -t`, restarts the manager |
| 8 | Moves the Wazuh dashboard 443 → 8443 and restarts it |
| 9 | Installs, enables and starts both systemd units |
| 10 | Result — exit 0 only if every step passed |

Every line should read `[PASS]`. `[WARN]` is informational. Any `[FAIL]` exits 1
— fix it and re-run.

There is deliberately **no `--force`**: regenerating `ENCRYPTION_KEY` would make
every stored credential and every existing backup permanently unrecoverable.

What §7 appended to `/var/ossec/etc/ossec.conf` (a timestamped backup was taken
first):

```xml
<!-- Insight Shield — added by scripts/install.sh. Delete this whole
     <ossec_config> block to remove the integration. -->
<ossec_config>
  <integration>
    <name>custom-insightshield</name>
    <hook_url>http://127.0.0.1:5000/wazuh-webhook</hook_url>
    <api_key>…your generated WAZUH_WEBHOOK_TOKEN…</api_key>
    <level>2</level>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
```

`level 2` means every alert of level ≥ 2 is forwarded. The integrator posts
straight to gunicorn on loopback, bypassing nginx and its self-signed cert.

**Wazuh dashboard is now `https://192.168.1.159:8443`.**

### 4.2 The firewall

Separate from the installer on purpose — enabling a packet filter is a different
class of action, and keeping it out means re-running `install.sh` after a code
update can never cut your session.

```bash
sudo /opt/insightshield/insightshield/scripts/firewall.sh
```

It derives `192.168.1.0/24` from the routing table (no hardcoded subnet), then:

| Rule | Port | Reason |
|---|---|---|
| allow from LAN | 80 | HTTP → HTTPS redirect |
| allow from LAN | 443 | Insight Shield |
| allow from LAN | 1514 | Wazuh agent events |
| allow from LAN | 1515 | Wazuh agent enrollment |
| allow from LAN | 8443 | Wazuh dashboard (read back from its own config) |
| allow from LAN | 22 | **only if** sshd is actually listening |
| **deny** | 55000 | Wazuh API — reached over loopback, nothing on the LAN needs it |
| **deny** | 9200 | Wazuh indexer — same |

No rule for 5000: gunicorn binds `127.0.0.1:5000` and ufw does not filter
loopback, so a rule there would be theatre. The `X-Webhook-Token` gate is what
protects the webhook.

Multi-homed box, wrong subnet derived? Override per-run instead of editing:

```bash
LAN_CIDR=192.168.1.0/24 sudo -E scripts/firewall.sh
```

**Then immediately verify the agents.** ufw does not flush conntrack, so the
four established agent sessions survive regardless — a broken 1514 rule would
only show up at the next reconnect:

```bash
sudo /var/ossec/bin/agent_control -l        # all 4 should still be Active
```

Force a real reconnect on one Windows box to prove enrollment still works:

```powershell
# on POSsys1 (192.168.1.137), as Administrator
Restart-Service WazuhSvc
```

Then back on the server, confirm it came back:

```bash
sudo /var/ossec/bin/agent_control -i 001    # or whatever ID POSsys1 has
```

> If the manager is configured for **UDP** on 1514, `firewall.sh` prints a
> `[WARN]` — agents die silently on enrollment with only the TCP rule. Wazuh 4.x
> defaults to TCP so this is unlikely. Fix if warned:
> `sudo ufw allow from 192.168.1.0/24 to any port 1514 proto udp`

---

## 5. Verify

### 5.1 Services

```bash
systemctl status insightshield insightshield-worker --no-pager
```

Both `active (running)`. `insightshield` serves HTTP on 3 gunicorn workers;
`insightshield-worker` owns APScheduler and **must** be the only process running
it, or the 02:00 backup takes concurrent copies of a live SQLite file.

Restarting every 5 seconds? Almost always one of:

```bash
journalctl -u insightshield -n 50 --no-pager
```

| Log says | Cause |
|---|---|
| exits during `seed_users_from_config` | blank `BOOTSTRAP_ADMIN_PASSWORD` / `BOOTSTRAP_MANAGER_PASSWORD` |
| exits in `crypto_utils` | `ENCRYPTION_KEY` missing or not a valid Fernet key |
| complains about the secret key | `FLASK_SECRET_KEY` empty or still a placeholder |
| `Permission denied` on a log | `/var/log/insightshield` ownership — re-run `install.sh` |

### 5.2 Healthcheck — 20 checks

```bash
sudo /opt/insightshield/insightshield/scripts/healthcheck.sh
```

Root is required: six checks read root-owned files (`.env` is `chmod 600`,
`/var/ossec/{etc,integrations,logs}` are 750). `[WARN]` never means broken —
only `[FAIL]` sets the exit code.

Checks 10-15 cover the port-443 collision, the integrator, `.env` ↔ `ossec.conf`
token parity, and Playwright. Checks 16-20 cover ufw, the clock, and — the one
§2.3 was for — that `192.168.1.159` is on an interface and
`insightshield.local` resolves to it.

### 5.3 End-to-end smoke test

Walks webhook → DB → AI chain → API → report → RBAC.

```bash
cd /opt/insightshield/insightshield
export SMOKE_WEBHOOK_TOKEN="$(sudo sed -n 's/^WAZUH_WEBHOOK_TOKEN=//p' .env | head -1)"
export SMOKE_ADMIN_PASSWORD='<the one you set in §3.3>'
export SMOKE_MANAGER_PASSWORD='<the one you set in §3.3>'
sudo -E ./scripts/smoke_test.sh https://127.0.0.1
```

Exits 0 on full pass, 1 on first failure.

> These are the **bootstrap** passwords. Once you log in through the browser and
> change them (forced at first login), export the new values instead.

### 5.4 A real alert from a real agent

The webhook is push-only — the app never polls. If the integrator is not firing,
no alert ever arrives and the dashboard just stays empty.

Terminal 1, on the server:

```bash
sudo tail -f /var/ossec/logs/integrations.log
```

Terminal 2 — on **POSsys1** (192.168.1.137), fail a Windows login 3-4 times
(wrong password at the lock screen, or a bad RDP attempt).

Within a few seconds `integrations.log` should show the POST. Then confirm it
landed in the database:

```bash
sudo -u insightshield sqlite3 /opt/insightshield/insightshield/insightshield.db \
  "SELECT id, device_name, severity, rule_id, timestamp
   FROM alerts ORDER BY id DESC LIMIT 5;"
```

Level → severity mapping (`wazuh_receiver.LEVEL_MAP`):

| Wazuh level | Insight Shield severity |
|---|---|
| ≤ 1 | discarded, never stored |
| 2-4 | `INFORMATIONAL` |
| 5-7 | `LOW` |
| 8-9 | `MEDIUM` |
| 10-12 | `HIGH` |
| 13-15 | `CRITICAL` |

Nothing arriving? In order:

```bash
grep -c 'custom-insightshield' /var/ossec/etc/ossec.conf     # want >= 1
ls -l /var/ossec/integrations/custom-insightshield*          # want 750 root:wazuh
sudo tail -50 /var/ossec/logs/ossec.log | grep -i integrat
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:5000/health   # want 200
sudo tail -50 /var/log/insightshield/error.log
```

A `403` in `integrations.log` means the token in `ossec.conf` and the one in
`.env` disagree — re-run `install.sh`, which re-syncs them.

### 5.5 The UI

Browse to **`https://192.168.1.159`**. The self-signed cert warning is expected
— the SAN now covers this IP because of §2.3.

Log in as `admin`, then as `manager`. Both are forced through
`/account/password` on first login. Confirm:

- [ ] **Agent tiles show the five real agent names** — proves the Wazuh API
      credentials work. Placeholder names from `KNOWN_DEVICES` mean the API call
      is failing; check `WAZUH_API_PASSWORD`.
- [ ] **The alert from §5.4 is on the dashboard** with the right severity.
- [ ] **`/report.pdf` downloads and renders** — proves Playwright and
      `PLAYWRIGHT_BROWSERS_PATH` resolve correctly. This is the check that
      catches a stray CRLF in a `.service` file (§2.2) — nothing else surfaces
      it, healthcheck included.
- [ ] **The dashboard updates live without a refresh** — proves SSE is passing
      through nginx's dedicated `/api/events/stream` block.
- [ ] **`manager` cannot reach `/admin/settings`** (302s away) — RBAC.

From a POS PC:

```
https://192.168.1.159         → Insight Shield login    ✓ works
https://192.168.1.159:8443    → Wazuh dashboard         ✓ works
https://192.168.1.159:55000   → Wazuh API               ✗ MUST time out
http://192.168.1.159:9200     → indexer                 ✗ MUST time out
```

---

## 6. Directory layout after install

### Inside `/opt/insightshield/`

```
/opt/insightshield/                       owner insightshield:insightshield
├── venv/                                 the virtualenv (install.sh §3)
│   └── bin/{python,pip,gunicorn}
├── ms-playwright/                        Chromium — relocated out of ~/.cache
│   └── chromium-*/                       because the units set ProtectHome=true
└── insightshield/                        ← the git clone, and the WorkingDirectory
    ├── app.py                            Flask factory; gunicorn target `app:app`
    ├── worker.py                         the ONLY process allowed to own APScheduler
    ├── config.py                         env-var gateway, thresholds, KNOWN_DEVICES
    ├── db.py                             SQLite layer + schema DDL (no ORM)
    ├── crypto_utils.py                   Fernet / MultiFernet, key rotation
    ├── backup.py                         encrypted hot-backup + CLI
    ├── scheduler.py                      the cron/interval job definitions
    ├── wazuh_receiver.py                 payload validation, level→severity map
    ├── wazuh_api.py                      outbound REST client (agent status)
    ├── agent_status.py                   30s poller, snapshot into `settings`
    ├── alert_router.py                   severity → notification fan-out
    ├── notifier.py                       Telegram + Gmail dispatch
    ├── rate_limit.py                     SQLite-backed, no Redis
    ├── health_score.py                   the health KPI
    ├── _ai_chain.py                      Groq → Gemini → OpenRouter fallback
    ├── groq_translator.py                plain-English alert translation
    ├── it_recommender.py                 remediation suggestions
    ├── executive_summary.py              manager-facing summary
    ├── gunicorn.conf.py                  bind 127.0.0.1:5000, 3 workers, 16 threads
    ├── insightshield.service             ← copied to /etc/systemd/system/
    ├── insightshield-worker.service      ← copied to /etc/systemd/system/
    ├── requirements.txt                  INPUT to the lock — never install this
    ├── requirements.lock                 hash-pinned, THIS is the install manifest
    ├── .env                              chmod 600, all secrets  ⚠ BACK THIS UP
    ├── .env.example                      the template
    ├── insightshield.db                  ← SQLite, created on first boot ⚠ BACK UP
    ├── insightshield.db-wal              WAL mode
    ├── insightshield.db-shm
    ├── backups/                          *.db.enc, 14 kept, written 02:00 PHT
    │   └── insightshield-YYYYMMDD-HHMMSS.db.enc
    ├── logs/
    │   └── insightshield.log             app log, self-rotating 5 MB × 5
    ├── web/
    │   ├── auth_user.py  csrf.py  errors.py  filters.py  hooks.py  responses.py
    │   └── blueprints/                   39 routes across 9 blueprints
    │       ├── auth.py            /login, /logout, /account/password
    │       ├── dashboards.py      IT and manager dashboards
    │       ├── alerts.py          alert list, detail, acknowledge
    │       ├── reports.py         /report, /report.pdf
    │       ├── api.py             /api/* JSON
    │       ├── stream.py          /api/events/stream (SSE)
    │       ├── webhook.py         /wazuh-webhook   ← the IP allowlist is here
    │       ├── admin_ops.py       audit log, error log, backups
    │       └── admin_settings.py  /admin/settings, credential management
    ├── templates/                        18 Jinja2 templates
    ├── static/                           ← the only world-readable subtree
    │   ├── ui.js  design-tokens.css  report-bureau.css
    │   ├── js/                    dashboard-it-realtime.js, sse.js, settings.js, …
    │   ├── vendor/                Tailwind 3.4.3 + Prism 1.29.0, self-hosted
    │   ├── fonts/  images/
    ├── nginx/insightshield.conf          ← copied to /etc/nginx/sites-available/
    ├── logrotate/insightshield           ← copied to /etc/logrotate.d/
    ├── wazuh_rules/
    │   ├── custom_retail_rules.xml       ← copied to /var/ossec/etc/rules/
    │   ├── custom-insightshield          ← copied to /var/ossec/integrations/
    │   └── custom-insightshield.py       ← copied to /var/ossec/integrations/
    ├── scripts/
    │   ├── install.sh                    the installer
    │   ├── healthcheck.sh                20 checks
    │   ├── firewall.sh                   ufw policy
    │   └── smoke_test.sh                 end-to-end curl walk
    ├── tests/                            pytest + Playwright
    └── docs/
        ├── deployment-ubuntu.md          the full runbook
        ├── runbook.md                    day-2 operations, key rotation
        ├── architecture.md
        ├── webhook-contract.md
        └── install-192.168.1.159.md      ← this file
```

### Everything the installer drops outside that tree

| Path | Mode / owner | Source |
|---|---|---|
| `/etc/systemd/system/insightshield.service` | root | `insightshield.service` |
| `/etc/systemd/system/insightshield-worker.service` | root | `insightshield-worker.service` |
| `/etc/nginx/sites-available/insightshield` | root | `nginx/insightshield.conf` |
| `/etc/nginx/sites-enabled/insightshield` | symlink | → sites-available |
| `/etc/nginx/sites-enabled/default` | **removed** | it is a `:80` catch-all and shadows the redirect |
| `/etc/nginx/ssl/insightshield.crt` | 644 root | `openssl req -x509`, 825 days |
| `/etc/nginx/ssl/insightshield.key` | **600** root | same |
| `/etc/logrotate.d/insightshield` | 644 root | `logrotate/insightshield` |
| `/var/log/insightshield/access.log` | insightshield | gunicorn |
| `/var/log/insightshield/error.log` | insightshield | gunicorn |
| `/var/log/nginx/insightshield.access.log` | root | nginx |
| `/var/log/nginx/insightshield.error.log` | root | nginx |
| `/var/ossec/etc/rules/custom_retail_rules.xml` | **660 root:wazuh** | `wazuh_rules/` |
| `/var/ossec/integrations/custom-insightshield` | **750 root:wazuh** | `wazuh_rules/` |
| `/var/ossec/integrations/custom-insightshield.py` | **750 root:wazuh** | `wazuh_rules/` |
| `/var/ossec/etc/ossec.conf` | modified | one `<ossec_config>` block appended |
| `/var/ossec/etc/ossec.conf.pre-insightshield.<epoch>` | root | backup taken before the append |
| `/etc/wazuh-dashboard/opensearch_dashboards.yml` | modified | `server.port: 443` → `8443` |

### Ports

| Port | Bound by | Reachable from |
|---|---|---|
| 5000 | gunicorn | **loopback only** — never exposed |
| 80 | nginx | LAN — 301 redirect to 443 |
| 443 | nginx | LAN — Insight Shield |
| 8443 | wazuh-dashboard | LAN — Wazuh GUI |
| 1514 / 1515 | wazuh-manager | LAN — agents |
| 55000 | wazuh-api | **loopback only** — ufw denies from LAN |
| 9200 | wazuh-indexer | **loopback only** — ufw denies from LAN |

### The nine SQLite tables

| Table | Holds |
|---|---|
| `alerts` | every ingested alert, its severity, AI translation, ack state |
| `users` | accounts, scrypt hashes, roles, `must_change_password`, session epoch |
| `audit_log` | who did what, retention `AUDIT_RETENTION_DAYS` (default 90) |
| `api_keys` | Fernet-encrypted service credentials |
| `settings` | key/value config, including the agent-status snapshot |
| `ai_providers` | provider chain, encrypted keys, enable/disable |
| `error_log` | server-side errors, retention `ERROR_RETENTION_DAYS` (default 30) |
| `rate_events` | the rate limiter's ledger |
| `ai_cache` | AI response cache |

### Scheduled jobs (`insightshield-worker.service`, `Asia/Manila`)

| When | Job |
|---|---|
| 00:00 daily | health score reset |
| 02:00 daily | encrypted database backup → `backups/` |
| 03:00 daily | retention purge (audit + error logs) |
| every 30s | Wazuh agent status poll |
| periodic | unacknowledged-CRITICAL escalation sweep |
| every 10 min | authz-probe sweep |

---

## 7. Day-to-day commands

```bash
# service control
sudo systemctl restart insightshield insightshield-worker
sudo systemctl status  insightshield insightshield-worker --no-pager

# logs
sudo journalctl -u insightshield -f
sudo tail -f /var/log/insightshield/error.log
sudo tail -f /opt/insightshield/insightshield/logs/insightshield.log
sudo tail -f /var/ossec/logs/integrations.log      # is Wazuh actually pushing?
sudo tail -f /var/log/nginx/insightshield.error.log

# manual backup (do this before ANY change)
cd /opt/insightshield/insightshield
sudo -u insightshield /opt/insightshield/venv/bin/python -m backup
ls -lh backups/

# query the database directly
sudo -u insightshield sqlite3 /opt/insightshield/insightshield/insightshield.db \
  "SELECT severity, COUNT(*) FROM alerts GROUP BY severity;"

# re-verify at any time — both are safe to re-run
sudo /opt/insightshield/insightshield/scripts/install.sh
sudo /opt/insightshield/insightshield/scripts/healthcheck.sh
```

### Back these up off the box

1. **`.env`** — losing `ENCRYPTION_KEY` makes every stored credential *and*
   every existing `.db.enc` backup permanently unrecoverable. There is no
   recovery path. Copy it somewhere safe now.
2. **`backups/*.db.enc`** — useless without the key above, so store them
   separately from it.

> The `.env.example` comments describe `BACKUP_ENCRYPTION_KEY` — an optional
> second key that encrypts the snapshots separately, so one disclosure does not
> open both the live credentials and every historical copy of them. The
> installer does not generate it; it is opt-in. Unset means the snapshots use
> `ENCRYPTION_KEY`, which is what you will have. `docs/runbook.md` covers
> rotation via the `*_OLD` variables.

---

## 8. Known repo issues — not bugs you introduced

Hit these and you have not broken anything:

| Where | Issue |
|---|---|
| `docs/deployment-ubuntu.md` §1.1 | Says the TLS SAN is derived from your IP. It is hardcoded at `scripts/install.sh:192`. §2.3 above covers it. |
| `docs/deployment-ubuntu.md` §5.2 | Says `pip install -r requirements.txt`. `install.sh:114` correctly uses `--require-hashes -r requirements.lock`. Trust the script. |
| `docs/deployment-ubuntu.md` §2 | Quotes `cryptography>=42.0`; `requirements.txt` now says `>=50.0.0`. |
| `docs/deployment-ubuntu.md` §5.6 | Warns that `.env.example` ships non-empty placeholders. It no longer does — every credential value is genuinely blank. |
| `docs/deployment-ubuntu.md` line 568 | Says "empty `WAZUH_API_VERIFY` = TLS verification off". Backwards — empty now means verify against the system trust store. |
| `db.py:87` | Comment says "5 tables". There are 9. |
| `gunicorn.conf.py` header | Says deploy to `/opt/insightshield/gunicorn.conf.py`. The unit actually loads `/opt/insightshield/insightshield/gunicorn.conf.py`. Cosmetic. |
| `logrotate/insightshield` comment | Says `workers = 1`. It is 3. |

---

## 9. Rollback

Full removal:

```bash
sudo systemctl stop    insightshield insightshield-worker
sudo systemctl disable insightshield insightshield-worker
sudo rm /etc/systemd/system/insightshield*.service
sudo systemctl daemon-reload

# nginx — restore the stock default site
sudo rm /etc/nginx/sites-enabled/insightshield /etc/nginx/sites-available/insightshield
sudo ln -sfn /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx

# Wazuh — restore the pre-install ossec.conf
ls -t /var/ossec/etc/ossec.conf.pre-insightshield.* | head -1
sudo cp /var/ossec/etc/ossec.conf.pre-insightshield.<epoch> /var/ossec/etc/ossec.conf
sudo rm -f /var/ossec/integrations/custom-insightshield*
sudo rm -f /var/ossec/etc/rules/custom_retail_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager

# give the dashboard 443 back
sudo sed -i 's/^server\.port: 8443/server.port: 443/' \
  /etc/wazuh-dashboard/opensearch_dashboards.yml
sudo systemctl restart wazuh-dashboard
```

Keep `/opt/insightshield/` until you are certain — it holds the database, the
backups, and `.env`.
