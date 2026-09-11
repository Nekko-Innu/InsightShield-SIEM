# Insight Shield — Ubuntu LTS Deployment Runbook

Target: **one Ubuntu Desktop LTS machine ("VM-03")** running the Wazuh manager,
indexer and dashboard *and* Insight Shield. Desktop rather than Server so both
Wazuh and Insight Shield can be driven from a GUI as well as the terminal.

Monitored endpoints are Windows POS/manager PCs running the Wazuh agent.

---

## 0. Read this first — the five things that break a fresh install

These are not hypothetical. Each one is a hard stop on this exact stack.

**The first four are handled by `scripts/install.sh`** (§5) and detected by
`scripts/healthcheck.sh` checks 10–15. **The fifth is handled by
`scripts/firewall.sh`** (§7) and detected by checks 16–20. Read this section
anyway — when a check fails, this is what it is telling you.

### 0.1 Wazuh dashboard and Insight Shield both want port 443

The Wazuh dashboard binds `0.0.0.0:443` by default. `nginx/insightshield.conf`
also listens on 443. Whichever starts second dies with
`Port 443 is already in use`.

**Resolution used by this runbook: move the Wazuh dashboard to 8443**, leaving
443 for Insight Shield (whose CSP and HSTS both assume the standard port). See
§3.4. `REPORT_ASSET_BASE_URL` is unaffected — it defaults to
`http://127.0.0.1:5000/`, gunicorn's loopback bind, deliberately not the public
port: Chromium renders the PDF on the same host, and pinning the value is what
stops a forged `X-Forwarded-Host` redirecting the asset fetch.

### 0.2 There was no integrator, so no alert ever reached the app

`/wazuh-webhook` is a *push* endpoint — Insight Shield never polls Wazuh for
alerts. Nothing shipped that does the pushing. Two files now exist for it:

- `wazuh_rules/custom-insightshield.py` — reads the alert, flattens
  `rule.id`/`rule.level`/`agent.name` into the `rule_id`/`rule_level`/
  `device_name` the webhook validates on, keeps every nested block so the
  forensic Attack Trail still populates, POSTs with the `X-Webhook-Token`
  header. Stdlib only.
- `wazuh_rules/custom-insightshield` — the shell wrapper Wazuh's integrator
  actually executes.

Install both (§4.2) or the dashboard stays empty forever.

### 0.3 The webhook now fails closed

`WAZUH_WEBHOOK_TOKEN` unset = 403 on every payload, by design. It must be set
in **two** places with the same value: the app's `.env`, and `<api_key>` in the
Wazuh `<integration>` block. The app logs an error at boot when it is missing.

### 0.4 `/report.pdf` will fail under systemd unless Playwright is relocated

`insightshield.service` sets `ProtectHome=true`, which masks `/home`. Playwright
puts Chromium in `~/.cache/ms-playwright/`. The unit therefore cannot see the
browser it needs, and PDF export dies with `Executable doesn't exist`.

Fixed: `insightshield.service` now ships
`Environment="PLAYWRIGHT_BROWSERS_PATH=/opt/insightshield/ms-playwright"`, and
`install.sh` installs the browser there. `ReadWritePaths=/opt/insightshield`
already covered the path. Nothing to do by hand.

### 0.5 There is no firewall until you run one, and turning one on blindly is worse

Two failures, opposite directions, same missing step.

**Leave ufw off** and the Wazuh all-in-one installer's defaults stand: the API
binds `0.0.0.0:55000` and the indexer `9200`. Both are then reachable from every
POS terminal on the LAN. Neither needs to be — Insight Shield talks to the API
over loopback (`WAZUH_API_URL=https://127.0.0.1:55000`) and the dashboard talks
to the indexer over loopback.

**Turn ufw on without §7** and `ufw default deny incoming` kills agent
enrolment on 1514/1515. The nastiest part is the delay: existing agent
connections survive the change because conntrack is not flushed, so everything
looks fine until agents next reconnect — possibly hours later, possibly after
you have moved on and stopped suspecting the firewall.

Fixed: `scripts/firewall.sh` (§7) writes the whole policy in one pass. It is
deliberately **not** part of `install.sh` — see §5.0.

---

## 1. Machine prerequisites

| Item | Requirement | Why |
|---|---|---|
| OS | Ubuntu 22.04 or 24.04 LTS **Desktop** | 24.04 preferred (Python 3.12). Desktop gives the browser for the Wazuh dashboard and Insight Shield GUIs. |
| RAM | **8 GB minimum, 16 GB comfortable** | Wazuh indexer alone wants 4 GB heap. Adding GNOME + Chromium (PDF export) to the 4 GB Wazuh all-in-one minimum will swap. |
| CPU | 4 vCPU | Wazuh all-in-one asks for 2; PDF renders and the AI chain compete for the rest. |
| Disk | 50 GB+ | Indexer retention dominates. |
| Static IP | **`192.168.1.159`** | Hardcoded in five places — see §1.1. Assigned in §1.2.1. |
| Network | **Inbound from the LAN:** 80, 443 (Insight Shield), 1514/1515 (agents), 8443 (Wazuh dashboard). **Outbound:** 443 (Groq/Gemini/OpenRouter, Telegram, apt, PyPI, Wazuh repos), 587 (Gmail SMTP), 53, 123. **Never inbound:** 55000, 9200. | Alerts and notifications. The policy is §7. |

### 1.1 If your IP is not 192.168.1.159

Five edits, or the webhook, TLS names and healthcheck will not match:

- `web/blueprints/webhook.py` — the webhook IP allowlist
  `["127.0.0.1", "::1", "192.168.1.159"]`
- `nginx/insightshield.conf` — `server_name` in both server blocks
- `scripts/install.sh` — the certificate `subjectAltName` (line 192). This one
  is **not** derived from anything; it is a literal in the `openssl req` call.
- `/etc/hosts` — map `insightshield.local` to the address (§1.2.4)
- `scripts/healthcheck.sh` check 20 — asserts the address is on an interface and
  that `insightshield.local` resolves to it

The loopback entries stay regardless; the integrator posts over loopback.

> Check 20 writes the address **twice**: once plain, and once regex-escaped
> inside a `grep` pattern (`inet 192\.168\.1\.159/`). A plain
> `sed s/<old>/<new>/g` over the file silently misses the escaped copy and the
> check then fails against a correctly configured host. Substitute both forms,
> or edit line 382 by hand.

Assign the address itself in §1.2.1. `scripts/firewall.sh` and checks 16–18
need no edit — they derive the LAN subnet from the routing table. If this host
is multi-homed and the derived subnet is the wrong one, override it per-run
rather than editing the script:

```bash
LAN_CIDR=10.0.0.0/24 sudo -E scripts/firewall.sh
```

### 1.2 Network, hostname and time

Do this **before** §3. The Wazuh installer bakes this host's address into the
certificates it generates, agents enrol against it, and `apt` needs working DNS
to get anywhere at all. Fixing the address afterwards means regenerating Wazuh's
certificates.

#### 1.2.1 Static IP — Ubuntu **Desktop** (NetworkManager)

Desktop installs render the network through **NetworkManager**, not
systemd-networkd. Use `nmcli` or the GUI:

```bash
nmcli -t -f NAME,DEVICE connection show      # find the profile name

sudo nmcli connection modify "Wired connection 1" \
  ipv4.method manual \
  ipv4.addresses 192.168.1.159/24 \
  ipv4.gateway 192.168.1.1 \
  ipv4.dns "192.168.1.1 1.1.1.1" \
  ipv4.ignore-auto-dns yes \
  connection.autoconnect yes

sudo nmcli connection up "Wired connection 1"
```

GUI equivalent: **Settings → Network → wired gear icon → IPv4 → Manual**,
Address `192.168.1.159`, Netmask `255.255.255.0`, Gateway `192.168.1.1`,
DNS `192.168.1.1, 1.1.1.1` → **Apply**, then toggle the connection off and on.

Verify:

```bash
ip -4 addr show          # inet 192.168.1.159/24
ip -4 route              # default via 192.168.1.1
resolvectl status        # DNS Servers listed under the right link
```

> **Do not paste a netplan static block into a Desktop install.**
> `/etc/netplan/01-network-manager-all.yaml` on Desktop contains only
> `renderer: NetworkManager` and an empty `ethernets:`. Adding a static address
> there *appears* to work — `netplan apply` exits 0 — but NetworkManager and the
> GUI then hold conflicting views of the same device, and the address is lost on
> the next NM restart or GUI edit. Every "Ubuntu static IP" tutorial you will
> find is written for Server. This is §1.2.2.

#### 1.2.2 Static IP — Ubuntu **Server** only (netplan)

If you deliberately installed Server rather than Desktop (`renderer: networkd`):

```yaml
# /etc/netplan/01-static.yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3:                       # match your device from `ip -br link`
      dhcp4: no
      addresses: [192.168.1.159/24]
      routes:
        - to: default
          via: 192.168.1.1
      nameservers:
        addresses: [192.168.1.1, 1.1.1.1]
```

```bash
sudo chmod 600 /etc/netplan/01-static.yaml   # 24.04 warns loudly otherwise
sudo netplan apply
```

Note that Desktop gives you a browser for the Wazuh dashboard and Insight
Shield GUIs, which is why §1's table calls for it.

#### 1.2.3 DNS

The host needs outbound DNS for `apt`, PyPI, the Wazuh repositories, and — at
runtime — the AI providers, Telegram and Gmail. Both `nmcli` and the netplan
block above set it. Confirm resolution actually works before continuing:

```bash
resolvectl query packages.wazuh.com
curl -sI https://pypi.org | head -1
```

#### 1.2.4 Hostname and `/etc/hosts`

```bash
sudo hostnamectl set-hostname vm-03

grep -q insightshield.local /etc/hosts || \
  echo "192.168.1.159  insightshield.local vm-03" | sudo tee -a /etc/hosts

getent hosts insightshield.local     # must print 192.168.1.159
```

- **Leave Ubuntu's stock `127.0.1.1 <hostname>` line alone.** Removing it breaks
  `sudo`'s name resolution and every command starts with a several-second
  timeout. The line added above coexists with it fine.
- The certificate `install.sh` mints carries
  `subjectAltName=DNS:insightshield.local,IP:192.168.1.159`, so both names work
  in a browser — **but only on this host**. A POS PC has no `insightshield.local`
  entry, so staff browse to `https://192.168.1.159` unless you add the same
  line to each Windows machine's `C:\Windows\System32\drivers\etc\hosts`.

#### 1.2.5 Time sync and timezone

```bash
sudo timedatectl set-timezone Asia/Manila
sudo timedatectl set-ntp true
timedatectl status    # want: "System clock synchronized: yes", "NTP service: active"
```

Why this is a deployment step and not an assumption:

- Alert correlation compares timestamps written by Windows agents, the Wazuh
  manager and this host. A skewed clock makes an attack trail read out of order.
- `scheduler.py` runs a `BackgroundScheduler(timezone="Asia/Manila")` — the
  02:00 backup and the midnight health-score reset fire against the system
  clock.
- Wazuh's own TLS fails on a badly skewed clock with a **"certificate is not yet
  valid"** error that reads nothing like "your clock is wrong", and costs an
  afternoon.

Two things that mislead here:

- The **timezone** setting is for the journal, `ossec.log` and the Wazuh
  dashboard's time picker. Insight Shield is already timezone-independent —
  `config.py` pins `ZoneInfo("Asia/Manila")` on every timestamp it writes. So a
  wrong system timezone is a legibility problem, not a correctness one, and
  `healthcheck.sh` reports it as `[WARN]`. Clock *sync* is `[FAIL]`.
- `set-ntp true` drives `systemd-timesyncd`, the 22.04/24.04 default. If chrony
  is installed it takes over and `timedatectl` defers to it — that is fine, and
  is why check 19 tests the kernel's *synchronized* bit rather than a service
  name. NTP is udp/123 outbound, which §7 leaves open.

### 1.3 Python

**Minimum 3.10.** The code uses PEP 604 unions (`str | None`) in runtime
signatures without `from __future__ import annotations`, so 3.9 fails at import.
22.04 ships 3.10, 24.04 ships 3.12 — both fine.

### 1.4 APT packages

```bash
sudo apt update && sudo apt install -y \
  python3 python3-venv python3-pip \
  nginx openssl \
  sqlite3 jq curl \
  tzdata ufw logrotate \
  build-essential libssl-dev libffi-dev python3-dev
```

- `sqlite3` (CLI) and `jq` — `scripts/healthcheck.sh` and `scripts/smoke_test.sh` shell out to them.
- `tzdata` — the scheduler and every timestamp use `ZoneInfo("Asia/Manila")`; without the system tz database, import raises `ZoneInfoNotFoundError`.
- `ufw` — `scripts/firewall.sh` (§7). Present on a stock Ubuntu but inactive; listed so a minimal image does not surprise you.
- `logrotate` — `install.sh` drops a config for gunicorn's two log files (§5.8). Also normally present.
- `build-essential`/`libssl-dev`/`libffi-dev` — only needed if `cryptography` has no matching wheel; harmless otherwise.

---

## 2. Python dependencies

`requirements.txt` (only two are pinned — everything else floats):

```
flask  flask-login  python-dotenv  groq  google-genai  requests
apscheduler  textstat  gunicorn
cryptography>=42.0     # Fernet encryption for the api_keys table
playwright>=1.45       # headless Chromium for /report.pdf
```

**`pip install playwright` is not enough.** The browser binary is a separate
~111 MB download plus system libraries — see §5.4.

---

## 3. Install Wazuh

### 3.1 All-in-one

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

10–20 minutes. It installs indexer + manager + dashboard and prints the
generated `admin` password at the end — **save that output**, it is not
recoverable later without `wazuh-passwords-tool.sh`.

### 3.2 Verify

```bash
systemctl status wazuh-indexer wazuh-manager wazuh-dashboard
```

### 3.3 API credentials for Insight Shield

The app authenticates to the Wazuh API at `https://127.0.0.1:55000` to populate
agent status. The default `wazuh-wui` account works, but it is the dashboard's
own account — prefer a dedicated read-only RBAC user, and set its password to
something meeting Wazuh's policy (**8–64 chars, at least one uppercase,
lowercase, number and symbol** — the manager refuses to start otherwise).

Whatever you choose goes into Insight Shield's `.env` as `WAZUH_API_USER` /
`WAZUH_API_PASSWORD`, and can be changed later through Settings → Service
Configuration without a restart.

### 3.4 Move the dashboard off 443 (§0.1)

```bash
sudo systemctl stop wazuh-dashboard
sudo sed -i 's/^server.port: 443/server.port: 8443/' /etc/wazuh-dashboard/opensearch_dashboards.yml
sudo systemctl start wazuh-dashboard
```

Wazuh GUI is now `https://192.168.1.159:8443`, Insight Shield stays on
`https://192.168.1.159`.

`scripts/firewall.sh` and `healthcheck.sh` check 17 both read `server.port` back
out of this file rather than assuming 8443, so if you pick a third value the
firewall opens that one instead. The one value neither will accept is `443` —
`firewall.sh` refuses to run and tells you to run `install.sh` first.

---

## 4. Wire Wazuh to Insight Shield

### 4.1 Custom rules

```bash
sudo cp wazuh_rules/custom_retail_rules.xml /var/ossec/etc/rules/
sudo chown root:wazuh /var/ossec/etc/rules/custom_retail_rules.xml
sudo chmod 660 /var/ossec/etc/rules/custom_retail_rules.xml
sudo /var/ossec/bin/wazuh-logtest -t     # must exit 0
sudo systemctl restart wazuh-manager
```

30 rules in ids `100001`–`100056`, group `insightshield_retail`. Level mapping
matches `wazuh_receiver.LEVEL_MAP` exactly:

| Wazuh level | Insight Shield severity |
|---|---|
| ≤ 1 | discarded (webhook returns `200 {"status":"discarded"}`) |
| 2–4 | INFORMATIONAL |
| 5–7 | LOW |
| 8–9 | MEDIUM |
| 10–12 | HIGH |
| 13–15 | CRITICAL |

### 4.2 Integrator

```bash
sudo cp wazuh_rules/custom-insightshield     /var/ossec/integrations/
sudo cp wazuh_rules/custom-insightshield.py  /var/ossec/integrations/
sudo chmod 750 /var/ossec/integrations/custom-insightshield*
sudo chown root:wazuh /var/ossec/integrations/custom-insightshield*
```

Then add to `/var/ossec/etc/ossec.conf`, inside `<ossec_config>`:

```xml
<integration>
  <name>custom-insightshield</name>
  <hook_url>http://127.0.0.1:5000/wazuh-webhook</hook_url>
  <api_key>PASTE_THE_SAME_VALUE_AS_WAZUH_WEBHOOK_TOKEN</api_key>
  <level>2</level>
  <alert_format>json</alert_format>
</integration>
```

```bash
sudo systemctl restart wazuh-manager
```

Notes on those values:

- **`hook_url` goes straight to gunicorn on loopback**, not through nginx. It
  skips the self-signed-certificate problem entirely, and `127.0.0.1` is the
  first entry in the app's IP allowlist. Use `https://127.0.0.1/wazuh-webhook`
  instead only if you want nginx's `10r/s` zone in front of it.
- **`api_key` is the shared secret**, arriving as `argv[2]` and sent as
  `X-Webhook-Token`. It must equal `WAZUH_WEBHOOK_TOKEN` in `.env`.
- **`<level>2</level>`** forwards everything level 2 and up. Level 0–1 would be
  discarded by the receiver anyway; filtering here saves the round trip.
  Narrow to `<rule_id>100001,100002,...</rule_id>` or
  `<group>insightshield_retail</group>` if the volume is too high.
- The app rate-limits the webhook to **120 alerts/min per source IP** and
  returns 429 above that. A noisy fleet may need that raised in
  `web/blueprints/webhook.py`.

Watch it work: `sudo tail -f /var/ossec/logs/integrations.log`

### 4.3 Windows agents

On each POS / manager PC (as Administrator):

```
msiexec.exe /i wazuh-agent-4.14.7-1.msi /q ^
  WAZUH_MANAGER="192.168.1.159" ^
  WAZUH_AGENT_NAME="POS-TERMINAL-01"
NET START WazuhSvc
```

Config lives at `C:\Program Files (x86)\ossec-agent\ossec.conf`.
Ports 1514 (events) and 1515 (enrollment) must reach the manager — see §7 once
ufw is enabled. **Agents going silent after a firewall change is the single most
common post-deploy symptom**, and it is delayed: established connections survive
`ufw enable`, so the breakage only shows up when an agent next reconnects.

**Agent names matter.** They become `device_name` on every alert, and
`config.py`'s `KNOWN_DEVICES = ["POS-TERMINAL-01", "MANAGER-PC-01"]` is the
fallback list shown on the login page when the Wazuh API is unreachable. Keep
the two in sync.

Two rule groups need agent-side setup, or they can never fire:

- **Sysmon** with the SwiftOnSecurity config — rule `100010` (POS RAM scraping)
  keys on Sysmon Event 10 (ProcessAccess).
- **File integrity monitoring** — rules `100011`, `100012`, `100044`–`100047`
  need a `<syscheck>` block watching `C:\POS\shared` in realtime or at
  `<frequency>30</frequency>`.

The MitM rules `100020`–`100022` need **arpwatch** on the manager instead,
watching the branch LAN interface and logging to syslog, which Wazuh already
reads (`sudo apt install arpwatch`, then `sudo systemctl enable --now
arpwatch@<iface>`). They escalate the stock arpwatch rules 7201, 7202, 7204 and
7209; without arpwatch they stay silent.

#### Agent setup for the attack rules

`wazuh_rules/agent.conf` is installed by `scripts/install.sh` to
`/var/ossec/etc/shared/default/agent.conf` and synced to agents automatically.
It adds the Sysmon channel, realtime FIM on `C:\POS` and `C:\POS\shared`, and
two command monitors: `arp-gateway` (rule `100023`, watches the gateway's MAC,
every 30 s) and `syn-watch` (rule `100031`, half-open connections / segments
per second, every 10 s).

Once per Windows host, in an admin PowerShell — Wazuh refuses manager-pushed
commands until the agent opts in:

```powershell
$c = "C:\Program Files (x86)\ossec-agent\local_internal_options.conf"
if (-not (Select-String -Path $c -Pattern "remote_commands" -Quiet)) {
  Add-Content $c "logcollector.remote_commands=1"
}
Restart-Service WazuhSvc
```

Then check, on the same host:

- **Gateway.** `(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort RouteMetric | Select -First 1).NextHop`
  must be the LAN gateway, not a Tailscale hop.
- **Sysmon Event 10.** `Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -FilterXPath "*[System[EventID=10]]" -MaxEvents 1`.
  If it returns nothing, add
  `<ProcessAccess onmatch="include"><TargetImage condition="end with">lsass.exe</TargetImage></ProcessAccess>`
  to the Sysmon config and reload it with `Sysmon64.exe -c <config>`. Rule
  `100010` and stock `92900` depend on it.
- **Audit policy.** Set by GUID so it works on any Windows display language,
  then verify with `auditpol /get /category:*`. Works on Windows 10 Home too —
  only the `secpol.msc` GUI is missing there.

  ```powershell
  auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable  # Logon
  auditpol /set /subcategory:"{0CCE921B-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable  # Special Logon
  auditpol /set /subcategory:"{0CCE9235-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable  # User Account Management
  auditpol /set /subcategory:"{0CCE9237-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable  # Security Group Management
  auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable  # Process Creation
  auditpol /set /subcategory:"{0CCE9227-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable  # Other Object Access Events
  auditpol /set /subcategory:"{0CCE9248-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable  # Plug and Play Events
  ```
- **Edition.** `(Get-ComputerInfo).WindowsEditionId` — Home has no RDP host,
  so test brute force over SMB (445) there.

**Optional manager sensors** — only if the Proxmox bridge lets `wazuh-system`
see POS traffic. Check with `tcpdump` on the LAN interface while running an
`nmap` against a POS host. If it passes: arpwatch (above), and Suricata with
`eve.json` read by Wazuh in `ossec.conf`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

plus two local Suricata rules, whose `msg` prefixes rules `100030`/`100040` match:

```
# Renaming a msg here means renaming the <field name="alert.signature"> in custom_retail_rules.xml.
alert tcp any any -> $HOME_NET any (msg:"InsightShield SYN flood"; flags:S,12; flow:stateless; threshold: type both, track by_dst, count 100, seconds 1; classtype:attempted-dos; sid:9100040; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"InsightShield port scan"; flags:S,12; flow:stateless; threshold: type both, track by_src, count 20, seconds 3; classtype:attempted-recon; sid:9100030; rev:1;)
```

Test the port scan with `nmap -sS`, not `--rand-source` — random sources defeat
`track by_src`. If the bridge check fails, `100020`–`100022`, `100030` and
`100040` stay silent; the victim-side `100023` and `100031` still cover ARP
spoofing and SYN flood.

---

## 5. Install Insight Shield

### 5.0 The short version

Place the tree, then run the installer:

```bash
sudo mkdir -p /opt/insightshield
sudo cp -r InsightShield-SIEM /opt/insightshield/insightshield
sudo /opt/insightshield/insightshield/scripts/install.sh
```

That does §§3.4, 4.1, 4.2 and 5.1–5.8 — service user, directories and
ownership, virtualenv, `.env` with generated secrets, Playwright, nginx and its
certificate, log rotation, the Wazuh rules and integrator, the `<integration>`
block with a matching token, the dashboard port move, and the systemd unit.

It is **idempotent and safe to re-run**. It never overwrites a secret that
already has a value, never re-issues an existing certificate, and never touches
the database. There is no `--force`.

It does **not** configure the firewall. That is §7, and the separation is
deliberate: enabling a packet filter is the one action here that can sever the
session you are typing into, and this script's whole value is that you can
re-run it after any code update without thinking about it. Keeping them apart
preserves that.

It deliberately does **not** copy application code — you place the tree
yourself, which is exactly why re-running cannot clobber a live deployment. Run
it again after any code update.

Run it before Wazuh is installed if you like: the Wazuh steps skip themselves
with a warning, and you re-run once `wazuh-install.sh -a` has finished.

The rest of §5 is what the script does, in case you need to do it by hand or
debug a `[FAIL]` line.

### 5.1 User, directories, ownership

```bash
sudo useradd --system --home /opt/insightshield --shell /usr/sbin/nologin insightshield
sudo mkdir -p /opt/insightshield /var/log/insightshield
sudo cp -r InsightShield-SIEM /opt/insightshield/insightshield
sudo chown -R insightshield:insightshield /opt/insightshield /var/log/insightshield
```

`/var/log/insightshield` must exist and be writable **before first start** —
gunicorn writes `access.log`/`error.log` there and refuses to boot otherwise.

Every other runtime path is **relative to the working directory**
(`/opt/insightshield/insightshield`): the SQLite file and its `-wal`/`-shm`
sidecars, `logs/`, `backups/`. This is deliberate (it is what lets the test
suite run against a throwaway directory) but it means `WorkingDirectory` in the
unit file is load-bearing — starting gunicorn from anywhere else silently
creates a second, empty database.

Give nginx traverse access to the static tree:

```bash
sudo chmod o+x /opt/insightshield /opt/insightshield/insightshield
sudo chmod -R o+rX /opt/insightshield/insightshield/static
```

### 5.2 Virtualenv

```bash
sudo -u insightshield python3 -m venv /opt/insightshield/venv
sudo -u insightshield /opt/insightshield/venv/bin/pip install -r /opt/insightshield/insightshield/requirements.txt
```

### 5.3 `.env`

```bash
cd /opt/insightshield/insightshield
sudo -u insightshield cp .env.example .env
sudo chmod 600 .env
```

Generate and fill the three that matter:

```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"  # ENCRYPTION_KEY
python3 -c "import secrets; print(secrets.token_hex(32))"                                   # FLASK_SECRET_KEY
python3 -c "import secrets; print(secrets.token_hex(32))"                                   # WAZUH_WEBHOOK_TOKEN
```

> ### Blank every placeholder you are not filling in — before first boot
>
> `.env.example` ships **non-empty** placeholders:
> `GROQ_API_KEY=your-groq-api-key-here`, `GEMINI_API_KEY=…`,
> `OPENROUTER_API_KEY=…`, `TELEGRAM_BOT_TOKEN=…`,
> `GMAIL_APP_PASSWORD=your-app-password-here`, `WAZUH_API_PASSWORD=…`.
>
> First boot imports `.env` into the database and **skips only *empty* values** —
> `bootstrap_settings_from_env` tests `if not p.get("api_key")` for providers and
> `if plaintext:` for credentials. A placeholder is a non-empty string, so it is
> imported as though it were real. The result is three AI providers seeded
> `is_active=1` with keys that 401, plus fake Telegram/Gmail/Wazuh credentials.
>
> Symptoms: every ingest and every `/report` burns the full `AI_CHAIN_BUDGET_S`
> walking dead providers before falling back to static templates, and every
> notification fails silently.
>
> The import is one-shot behind a `bootstrap_complete` sentinel row, so **editing
> `.env` afterwards does not undo it.** `scripts/install.sh` does not protect you
> here either — its `ensure_secret` helper regenerates only `FLASK_SECRET_KEY`,
> `ENCRYPTION_KEY` and `WAZUH_WEBHOOK_TOKEN`.
>
> ```bash
> # confirm nothing is left as a placeholder before starting the service
> sudo -u insightshield grep -nE '=(your-|generate-a-|change-me)' .env
> # ...should print nothing. Blank the value (KEY=) for anything it lists.
> ```
>
> Already booted with placeholders? See `runbook.md` → "Bootstrap seeded
> placeholder credentials" for the cleanup.

| Variable | Consequence if wrong/missing |
|---|---|
| `FLASK_SECRET_KEY` | **`sys.exit(1)` at boot.** Also rejects the placeholder `.env.example` ships. Combined with `Restart=always`, a bad value is a 5-second restart loop. |
| `ENCRYPTION_KEY` | **`sys.exit(1)` at boot.** Lose it after go-live and every encrypted credential *and every backup* is unrecoverable. Back it up off-box. |
| `WAZUH_WEBHOOK_TOKEN` | 403 on every alert. Must match `<api_key>` in ossec.conf. |
| `WAZUH_API_URL` / `_USER` / `_PASSWORD` | Agent status falls back to the static `KNOWN_DEVICES` list with status "unknown". |
| `GROQ_/GEMINI_/OPENROUTER_API_KEY` | Optional individually; all three empty means no AI translation and no executive summary. |
| `TELEGRAM_*`, `GMAIL_*` | Optional. No notifications without them. |
| `WAZUH_API_VERIFY` | Empty = TLS verification off (needed for Wazuh's self-signed cert). Point it at a CA bundle to turn verification on. |
| `INSIGHTSHIELD_ALLOW_HTTP_COOKIES` | **Leave unset in production.** Set only for plain-HTTP testing — without it, cookies are `Secure` and login over HTTP silently fails. |

Credentials and service settings are read from `.env` **once**, on first boot,
then migrated into the encrypted `api_keys`/`settings` tables. After that, edit
through Settings → Service Configuration; changing `.env` has no effect on them.

Not everything migrates. `FLASK_SECRET_KEY` and `ENCRYPTION_KEY` are read from
the environment on every boot, and so are the runtime knobs that never had a
Settings UI: `WAZUH_WEBHOOK_TOKEN`, `WAZUH_API_VERIFY`,
`INSIGHTSHIELD_ALLOW_HTTP_COOKIES`, `REPORT_PDF_PER_MIN`,
`REPORT_MAX_RANGE_DAYS`, `REPORT_ASSET_BASE_URL`, `AUDIT_RETENTION_DAYS`,
`ERROR_RETENTION_DAYS` and `INSIGHTSHIELD_RUN_SCHEDULER`. Changing one of those
requires a service restart, not a Settings edit.

### 5.4 Playwright browser (§0.4)

```bash
sudo -u insightshield PLAYWRIGHT_BROWSERS_PATH=/opt/insightshield/ms-playwright \
  /opt/insightshield/venv/bin/python -m playwright install chromium
sudo /opt/insightshield/venv/bin/python -m playwright install-deps chromium
```

The matching `Environment="PLAYWRIGHT_BROWSERS_PATH=..."` line already ships in
`insightshield.service`, and `ReadWritePaths=/opt/insightshield` already covers
the path — no edit needed. Install the browser anywhere else and everything
works except PDF export.

### 5.5 nginx + TLS

```bash
sudo mkdir -p /etc/nginx/ssl
sudo openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/insightshield.key \
  -out    /etc/nginx/ssl/insightshield.crt \
  -subj "/CN=insightshield.local" \
  -addext "subjectAltName=DNS:insightshield.local,IP:192.168.1.159"

sudo cp /opt/insightshield/insightshield/nginx/insightshield.conf /etc/nginx/sites-available/insightshield
sudo ln -s /etc/nginx/sites-available/insightshield /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default        # frees port 80
sudo nginx -t && sudo systemctl reload nginx
```

The config already handles the two things that are easy to get wrong: a
dedicated `location = /api/events/stream` block with `proxy_buffering off` and
a 1-hour read timeout (the catch-all's 60s would kill the live alert feed), and
`X-Forwarded-For` on every proxy block, which the app's `ProxyFix` consumes.

### 5.6 systemd

Two units. The web tier and the scheduled jobs are separate processes.

```bash
sudo cp /opt/insightshield/insightshield/insightshield.service        /etc/systemd/system/
sudo cp /opt/insightshield/insightshield/insightshield-worker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now insightshield insightshield-worker
sudo systemctl status insightshield insightshield-worker
```

**`workers = 3` in `gunicorn.conf.py`.** Every piece of state that used to be a
process-local dict now lives in SQLite, so the workers no longer have to be a
single process: the SSE stream polls a database watermark instead of an
in-process queue, rate limits count rows in `rate_events`, the AI cache is the
`ai_cache` table, and escalation is a sweep over unacknowledged CRITICALs rather
than a per-alert timer. 3 is sized for `/report.pdf`, which launches Chromium
synchronously inside a request thread — with one worker that stalled the whole
dashboard for everyone. Drop to 2 on a VM under 2 GB of RAM. Do **not** set
`preload_app`: `db.py`'s SQLite connections are thread-local, so forking after
import would share a parent-created file descriptor with every child.
`threads = 16` is per worker; each open SSE stream holds one for the life of
the tab.

### 5.6a The scheduler worker

`insightshield-worker.service` runs `worker.py`, which owns APScheduler and
nothing else: the escalation sweep, the 30-second Wazuh agent poll, the 00:00
health reset, the 02:00 database backup and the 03:00 retention purge.

**Exactly one process may run the scheduler.** Two means two concurrent backups
of the same live SQLite file at 02:00, two retention purges at 03:00, doubled
Wazuh polling, and duplicate escalation messages. The gunicorn workers do not
start one — `app.create_app()` only calls `scheduler.init_scheduler()` when
`INSIGHTSHIELD_RUN_SCHEDULER=1`, which is a single-process development
convenience and **must not** be set on the web unit in production.

The two units are deliberately independent: no `After=`, no `PartOf=`. A worker
crash must not take the dashboard down, and a dashboard restart must not
interrupt the nightly backup.

```bash
journalctl -u insightshield-worker -f            # follow the job log
journalctl -u insightshield-worker | grep "Scheduler starting"   # must be ONE pid
```

To confirm it is not merely running but actually ticking, check the freshness of
the agent-status snapshot it rewrites every 30 seconds — `scripts/healthcheck.sh`
does this (check 7a), and the login page's status dot turns red on its own if
that snapshot goes older than 90 seconds:

```bash
sudo sqlite3 /opt/insightshield/insightshield/insightshield.db \
  "SELECT updated_at FROM settings WHERE key='agent_status.snapshot';"
```

### 5.7 Log rotation

```bash
sudo install -m 644 /opt/insightshield/insightshield/logrotate/insightshield \
  /etc/logrotate.d/insightshield
sudo logrotate -d /etc/logrotate.d/insightshield    # dry run — must parse clean
```

This covers exactly two files, and only those two:
`/var/log/insightshield/access.log` and `error.log`, which gunicorn writes and
nothing rotates. Everything else on the host is already handled — `app.py` uses
a `RotatingFileHandler` (5 MB × 5) for `logs/insightshield.log`, and the distro
ships `/etc/logrotate.d/nginx`.

The config uses `copytruncate` rather than a `postrotate` signal. gunicorn holds
both file descriptors open for the life of the worker, so a plain rename orphans
them: the files stop growing while the disk keeps filling. `copytruncate` costs
a tiny window in which one log line can be lost; the alternative is
`systemctl kill -s USR1`, and a mishandled reopen takes workers — and every SSE
stream they hold — down with them.

### 5.8 First login

Browse to `https://192.168.1.159`. The seeded accounts are `admin` and
`manager`, and their first-boot passwords come from `BOOTSTRAP_ADMIN_PASSWORD`
and `BOOTSTRAP_MANAGER_PASSWORD` in `.env`. **Both must be set before the first
boot** — seeding calls `sys.exit(1)` rather than falling back, so a fresh
install with them unset will not start. There are deliberately no defaults:
a password published in this repo would own the IT_ADMIN role for the whole
window between first boot and first login. Both accounts are still **forced
through a password change on first login**.

---

## 6. Verify end to end

```bash
sudo /opt/insightshield/insightshield/scripts/healthcheck.sh

export SMOKE_WEBHOOK_TOKEN="<same as WAZUH_WEBHOOK_TOKEN>"
export SMOKE_ADMIN_PASSWORD="<post-rotation admin password>"
export SMOKE_MANAGER_PASSWORD="<post-rotation manager password>"
/opt/insightshield/insightshield/scripts/smoke_test.sh https://127.0.0.1
```

**`healthcheck.sh` must run as root** — six checks read files that are chmod 600
or in a 750 directory, and `ss -p` only names processes the caller owns. It
refuses to run unprivileged rather than reporting everything it cannot read as
broken. Both scripts use three severities:

| | Meaning | Affects exit code |
|---|---|---|
| `[PASS]` | verified working | — |
| `[WARN]` | could not be checked here — not applicable, or a tool is absent | no |
| `[FAIL]` | verified broken | yes |

A `[WARN]` is not a problem to fix. Running before Wazuh is installed, for
example, warns once and skips the Wazuh checks — the same state `install.sh`
supports.

`healthcheck.sh` checks 10–15 are the ones that catch §0.1–§0.4:
port 443 ownership, integrator files and permissions, the `<integration>` block,
token parity between `.env` and ossec.conf, a live webhook probe, and whether
the systemd unit can actually see Playwright's browser. `smoke_test.sh` §9
fetches `/report.pdf` and asserts the bytes start with `%PDF` — the only check
that proves Chromium runs inside the sandbox.

Checks 16–20 catch §0.5 and §1.2: ufw active, every required port allowed,
55000/9200 *not* allowed, the clock synchronized, and the address plus
`insightshield.local` resolving. **They are expected to fail at this point** —
the firewall is §7. Run this section now to confirm the application stack is
sound, apply §7, then re-run and expect all twenty green. That is the acceptance
gate.

Idempotency proof for the installer:

```bash
sha256sum /opt/insightshield/insightshield/.env
sudo /opt/insightshield/insightshield/scripts/install.sh
sha256sum /opt/insightshield/insightshield/.env
```

Identical hashes and zero `[FAIL]` lines. That is specifically the proof that
`ENCRYPTION_KEY` was not regenerated — if it ever were, every backup and every
stored credential would be unrecoverable.

Manual proof the whole chain works — trigger a real detection rather than a
synthetic POST: fail an RDP login five times on a monitored POS terminal
(rule 100001), then confirm the alert appears in the Wazuh dashboard *and* on
the Insight Shield IT dashboard within seconds. Watch it move with
`sudo tail -f /var/ossec/logs/integrations.log`.

Full test suite (dev machine, not the server):

```bash
python -m pytest -q       # run from the repo root
```

---

## 7. Firewall

Do this **after** §6 is green. Get the stack working on an open box, then close
the doors, then verify again. Agents enrolled in §4.3 stay enrolled — this
section opens the ports that keep them connected.

### 7.1 The policy

| Port | Direction | Who | Why |
|---|---|---|---|
| 80/tcp | inbound | LAN subnet | nginx's 301 to HTTPS |
| 443/tcp | inbound | LAN subnet | Insight Shield |
| 1514/tcp | inbound | LAN subnet | Wazuh agent events |
| 1515/tcp | inbound | LAN subnet | Wazuh agent enrollment |
| 8443/tcp | inbound | LAN subnet | Wazuh dashboard (§3.4) |
| 22/tcp | inbound | LAN subnet | **only if sshd is listening** |
| 55000/tcp | **denied** | — | Wazuh API — the app uses loopback |
| 9200/tcp | **denied** | — | Wazuh indexer — the dashboard uses loopback |
| everything else outbound | allowed | — | 443, 587, 53, 123 |

Four decisions worth understanding before you run it:

- **There is no rule for port 5000.** gunicorn binds `127.0.0.1:5000` and ufw
  does not filter loopback — `/etc/ufw/before.rules` accepts `-i lo`
  unconditionally. A `deny 5000` rule would change nothing while reading as
  though it protected the webhook. What actually protects `/wazuh-webhook` is
  the `X-Webhook-Token` gate (§0.3) plus the IP allowlist, not the firewall.
- **Egress is unrestricted, on purpose.** The app needs 443 for the AI providers
  and Telegram, 587 for Gmail, 53 and 123 for the basics; `apt` and `pip` need
  more. An egress allowlist on a single lab host breaks package management for
  no realistic gain and needs re-editing every time a provider changes CDN.
- **Inbound IPv6 is closed, on purpose.** Every allow rule is scoped
  `from <LAN subnet>`, which is IPv4, so nginx's `listen [::]:443` becomes
  unreachable from the LAN. Nothing is lost — staff browse to the literal IPv4
  address, and the webhook's `::1` entry is loopback, which ufw does not filter.
  Leave `IPV6=yes` in `/etc/default/ufw`; setting it to `no` stops ufw managing
  the v6 chains at all and leaves them open on some kernels.
- **The two `deny` rules are technically redundant** against
  `default deny incoming`. They are a tripwire: the day somebody adds a blanket
  `ufw allow from 192.168.1.0/24` to debug something, the denies still win
  because ufw matches in order and the first match wins. They also make
  `ufw status numbered` self-documenting about the two ports that must never be
  opened.

### 7.2 Apply it

```bash
sudo /opt/insightshield/insightshield/scripts/firewall.sh
```

The script derives the LAN subnet from the routing table and reads the Wazuh
dashboard's port back out of `opensearch_dashboards.yml`, so there is nothing to
edit. Two overrides exist:

```bash
LAN_CIDR=10.0.0.0/24 sudo -E scripts/firewall.sh   # multi-homed, or wrong subnet derived
```

It opens **22/tcp only when sshd is actually listening**. Ubuntu Desktop ships
without `openssh-server`, so on a stock box nothing is opened; where someone
installed it, you cannot lock yourself out. This is a Desktop machine with a
console either way — if a rule does go wrong, walk to it.

Re-running is safe. `ufw allow` is idempotent and prints "Skipping adding
existing rule".

### 7.3 Verify

```bash
sudo ufw status verbose
sudo /opt/insightshield/insightshield/scripts/healthcheck.sh    # all 20 checks
```

Checks 16–18 assert on the ufw **rules**, not on a live probe, and that is
deliberate: a `curl` from this host to `https://192.168.1.159:55000` is routed
over `lo`, which ufw accepts unconditionally, so a self-probe would pass even
when the firewall is correctly blocking every terminal on the LAN.

The real proof has to come from somewhere else. **From a POS PC:**

```bash
curl -m 3 -k https://192.168.1.159            # login page   -> works
curl -m 3 -k https://192.168.1.159:8443       # Wazuh GUI    -> works
curl -m 3 -k https://192.168.1.159:55000      # Wazuh API    -> MUST time out
curl -m 3    http://192.168.1.159:9200        # indexer      -> MUST time out
```

Then restart the Wazuh agent on that PC and confirm it re-enrols and reports.
That is the only test that proves 1514/1515 survived, because established
connections would otherwise mask a broken rule.

### 7.4 Pitfalls

- **Agents go quiet hours later, not immediately.** `ufw enable` does not flush
  conntrack, so existing agent connections keep working. A wrong 1514 rule
  surfaces at the next reconnect. Always do the agent-restart test in §7.3.
- **Check the agent protocol.** Wazuh 4.x defaults to TCP and the script writes
  TCP rules. If the manager is configured for UDP, agents fail enrolment
  silently:
  ```bash
  grep -A5 '<remote>' /var/ossec/etc/ossec.conf     # look for <protocol>udp</protocol>
  sudo ufw allow from 192.168.1.0/24 to any port 1514 proto udp
  ```
  `firewall.sh` warns if it sees this, but cannot safely guess for you.
- **Changing the dashboard port later leaves the old rule behind.** The script
  adds, it never prunes. `sudo ufw status numbered`, then
  `sudo ufw delete <n>`. Deliberately not automated — auto-pruning firewall
  rules is how you delete the one you needed.
- **"Wazuh API unreachable" in the Insight Shield UI after §7 is not caused by
  the firewall.** The app reaches the API over loopback. Look at
  `WAZUH_API_USER`/`_PASSWORD` in Settings → Service Configuration instead.
- **`ERROR: Bad source address`** means the derived `LAN_CIDR` is malformed —
  usually no default route yet. Finish §1.2.1, or pass `LAN_CIDR=` explicitly.

---

## 8. Troubleshooting

Symptom → cause → where the fix is written. Every one of these has been hit on
this stack.

| Symptom | Cause | Fix |
|---|---|---|
| nginx will not start, `Port 443 is already in use` | Wazuh dashboard took 443 first | §3.4 — move it to 8443 |
| Wazuh dashboard unreachable after enabling the firewall | 8443 not allowed, or the port was changed after `firewall.sh` ran | §7.4 — re-run `firewall.sh`, delete the stale rule |
| Agents show **Disconnected**, nothing in the dashboard | 1514 blocked, or the manager speaks UDP and only a TCP rule exists | §7.4 |
| Insight Shield dashboard stays empty forever, Wazuh shows the alerts | Integrator not installed, or wrong mode/owner | §0.2, §4.2 — healthcheck 11/12 |
| Same symptom, `403` in `integrations.log` | `<api_key>` and `WAZUH_WEBHOOK_TOKEN` have drifted | §0.3 — healthcheck 13 |
| Service restart-loops every 5 seconds | `FLASK_SECRET_KEY` or `ENCRYPTION_KEY` missing/placeholder — `sys.exit(1)` plus `Restart=always` | §5.3 — `journalctl -u insightshield -n 50` |
| `/report.pdf` returns 500, log says `Executable doesn't exist` | Chromium outside `PLAYWRIGHT_BROWSERS_PATH`, masked by `ProtectHome=true` | §0.4, §5.4 — healthcheck 15 |
| Login submits and silently returns to the login page | Serving plain HTTP; the session cookie is `Secure` so the browser never sends it back | Use HTTPS. `INSIGHTSHIELD_ALLOW_HTTP_COOKIES=1` is for testing only (§5.3) |
| Timestamps disagree between the Wazuh dashboard and Insight Shield | System timezone is not `Asia/Manila` (cosmetic), or the clock is unsynchronized (real) | §1.2.5 — healthcheck 19 |
| "Wazuh API unreachable" banner after enabling the firewall | **Not the firewall** — the app uses loopback. Bad API credentials | §3.3, Settings → Service Configuration |
| `ufw: ERROR: Bad source address` | No default route, so `LAN_CIDR` derived empty | §1.2.1, or pass `LAN_CIDR=` |
| `bad interpreter: /usr/bin/env bash^M` | CRLF line endings from a Windows copy | §11 — `file scripts/*.sh`, `dos2unix` |
| `/var` fills up | logrotate config not installed | §5.7 |
| Healthcheck 7: "alerts table has N columns (expected 21)" | Schema changed and `db.init_db()` has not run | §9.3 |

Where to look, in order: `sudo journalctl -u insightshield -n 50`,
`/var/log/insightshield/error.log`, `sudo tail -f /var/ossec/logs/integrations.log`,
`/var/log/nginx/insightshield.error.log`.

---

## 9. Operations: backups, restore, upgrade, uninstall

### 9.1 Backups

Already running — nothing to install. `backup.py` takes a WAL-safe snapshot via
`sqlite3.Connection.backup()`, fired daily at 02:00 PHT by the scheduler, keeping
the last 14. There is also a button in the Settings UI and a manual path:

```bash
cd /opt/insightshield/insightshield
sudo -u insightshield /opt/insightshield/venv/bin/python -m backup
ls -lh backups/
```

**`ENCRYPTION_KEY` is part of the backup.** A snapshot restored onto a host with
a different key is unreadable — every stored credential in it decrypts to
nothing. Copying the database off-box without also copying that key off-box
produces a backup that cannot be restored. Store the key separately from the
snapshots, not alongside them.

### 9.2 Restore

```bash
# Both units — the worker holds its own connection to the database and its
# 02:00 backup job would write to the file you are replacing.
sudo systemctl stop insightshield insightshield-worker
cd /opt/insightshield/insightshield

# Move the live database AND its sidecars aside — restoring the .db alone while
# a -wal file remains replays stale pages over the snapshot.
sudo mv insightshield.db     insightshield.db.old
sudo mv insightshield.db-wal insightshield.db-wal.old 2>/dev/null
sudo mv insightshield.db-shm insightshield.db-shm.old 2>/dev/null

sudo cp backups/insightshield-YYYYMMDD-HHMMSS.db insightshield.db
sudo chown insightshield:insightshield insightshield.db

sudo systemctl start insightshield insightshield-worker
sudo scripts/healthcheck.sh          # check 7 confirms the schema
```

Confirm the restored data is readable before deleting the `.old` files — if
Settings shows empty API credentials, the `ENCRYPTION_KEY` does not match this
snapshot and you have restored the wrong pair.

### 9.3 Upgrade

```bash
cd /opt/insightshield/insightshield
sudo -u insightshield /opt/insightshield/venv/bin/python -m backup   # first, always
sudo git pull
sudo scripts/install.sh
sudo scripts/healthcheck.sh
scripts/smoke_test.sh https://127.0.0.1
```

Re-running `install.sh` is the whole upgrade: it reinstalls requirements,
re-syncs the nginx config and the systemd unit, and reloads only what actually
changed. It does **not** overwrite `.env`, re-issue the certificate, or touch
the database — §6's `sha256sum` idempotency proof is the evidence.

One gotcha: a schema change needs `db.init_db()` to run, and healthcheck 7's
21-column assertion is what tells you it did not.

```bash
sudo -u insightshield /opt/insightshield/venv/bin/python -c "import db; db.init_db()"
```

Rollback is `sudo git checkout <previous-tag>` followed by `install.sh` again.
That is a **code** rollback, not a data one — which is why the backup comes
first.

### 9.4 Uninstall

There is deliberately no `uninstall.sh`. An uninstaller with a bug deletes the
database, and this runs at most once.

```bash
# 1. Get the data out first. Do not skip this.
sudo cp /opt/insightshield/insightshield/.env             ~/insightshield-env.bak
sudo cp /opt/insightshield/insightshield/insightshield.db ~/insightshield-db.bak

# 2. Services (both of them)
sudo systemctl disable --now insightshield insightshield-worker
sudo rm /etc/systemd/system/insightshield.service
sudo rm /etc/systemd/system/insightshield-worker.service
sudo systemctl daemon-reload

# 3. Wazuh integration — install.sh stamped a comment on the block it appended
sudo nano /var/ossec/etc/ossec.conf      # delete the marked <ossec_config> block
#   or restore the backup it took:  ls /var/ossec/etc/ossec.conf.pre-insightshield.*
sudo rm -f /var/ossec/integrations/custom-insightshield*
sudo rm -f /var/ossec/etc/rules/custom_retail_rules.xml
sudo systemctl restart wazuh-manager

# 4. nginx, TLS, logrotate
sudo rm -f /etc/nginx/sites-enabled/insightshield /etc/nginx/sites-available/insightshield
sudo rm -f /etc/nginx/ssl/insightshield.{crt,key}
sudo rm -f /etc/logrotate.d/insightshield
sudo nginx -t && sudo systemctl reload nginx

# 5. Firewall — only if the box is being repurposed
sudo ufw reset

# 6. Files and user — last, and only after step 1
sudo rm -rf /opt/insightshield /var/log/insightshield
sudo userdel insightshield
```

Moving the Wazuh dashboard back to 443 (`sed -i 's/^server.port: 8443/server.port: 443/'`)
is optional and only matters if you want the GUI on the default port again.

---

## 10. Known path discrepancies

`scripts/healthcheck.sh` had three of these and they are now fixed: it checked
the database one directory too high (reporting a missing DB on a healthy
install), checked a log filename nothing has ever written, and called
`ossec-logtest`, which Wazuh deprecated in 4.1 and no longer ships — so check 9
failed on every 4.x deployment regardless of whether the ruleset was fine.

Still outstanding, both cosmetic:

| Where | Says | Reality |
|---|---|---|
| `gunicorn.conf.py` header | deploy to `/opt/insightshield/gunicorn.conf.py` | The unit loads `/opt/insightshield/insightshield/gunicorn.conf.py` |

---

## 11. Copy-to-Linux checklist

- Do **not** `scp` the whole Windows working directory — it carries the dev
  `insightshield.db`, `logs/`, `backups/` and a Windows-generated `.env`. Use
  `git clone`, then let `install.sh` generate `.env`.
- **Line endings are NOT yet handled — commit `.gitattributes` first.** The file
  exists in the working tree but is untracked (`git ls-files .gitattributes`
  returns nothing), so a fresh `git clone` gets none of its protection and a
  Windows checkout still produces `bad interpreter: /usr/bin/env bash^M`.
  `git add .gitattributes && git commit` before cloning anywhere.

  It also currently covers only `*.sh` and the integrator. Add
  `insightshield.service`, `insightshield-worker.service` and
  `nginx/insightshield.conf`: a CRLF in a unit file puts a trailing `\r` inside
  `Environment="PLAYWRIGHT_BROWSERS_PATH=/opt/insightshield/ms-playwright"`,
  which breaks `/report.pdf` while healthcheck 15 still passes.

  Either way this only protects files that came through git — a direct `scp`
  from a Windows editor can still carry CRLF, so check `file scripts/*.sh` if a
  script refuses to run.
- `chmod +x scripts/*.sh` after copying.

## Sources

- [Wazuh — External API integration (custom integrations)](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html)
- [Wazuh — Windows agent package](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html)
- [Wazuh — Password management](https://documentation.wazuh.com/current/user-manual/user-administration/password-management.html)
- [Wazuh — Dashboard troubleshooting (port 443 in use)](https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/troubleshooting.html)
- [Wazuh — Dashboard step-by-step installation](https://documentation.wazuh.com/current/installation-guide/wazuh-dashboard/step-by-step.html)
