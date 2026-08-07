#!/var/ossec/framework/python/bin/python3
"""
custom-insightshield.py
Insight Shield — Wazuh integrator: pushes matching alerts to POST /wazuh-webhook.

INSTALLATION (on the Wazuh manager, VM-03):
  sudo cp custom-insightshield.py /var/ossec/integrations/
  sudo cp custom-insightshield    /var/ossec/integrations/
  sudo chmod 750 /var/ossec/integrations/custom-insightshield*
  sudo chown root:wazuh /var/ossec/integrations/custom-insightshield*
  # add the <integration> block from docs/deployment-ubuntu.md to ossec.conf
  sudo systemctl restart wazuh-manager

Wazuh's integrator daemon writes each matching alert to a temp file and calls
this script with three positional arguments:

    argv[1]  path to the alert JSON file
    argv[2]  <api_key> from ossec.conf  -> our WAZUH_WEBHOOK_TOKEN
    argv[3]  <hook_url> from ossec.conf -> the /wazuh-webhook URL

WHY THIS SCRIPT EXISTS
  A raw Wazuh alert nests everything (rule.id, rule.level, agent.name), but
  wazuh_receiver.validate_payload requires flat rule_id / rule_level /
  device_name. Meanwhile wazuh_receiver._extract_attack_trail reads the NESTED
  blocks (agent, rule, manager, decoder, location, input, id, full_log, data)
  to build the forensic Attack Trail. So this sends the original alert
  unchanged, with the four flat aliases added on top — both readers get what
  they expect and nothing is lost.

STDLIB ONLY. The interpreter above is Wazuh's bundled Python, which does not
ship `requests`; urllib is always there and this script is 60 lines of POST.
"""
import json
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime

LOG_FILE = "/var/ossec/logs/integrations.log"
TIMEOUT_S = 10


def log(message: str) -> None:
    """Append to the integrator log. Never raises — a logging failure must not
    lose the alert."""
    try:
        stamp = datetime.now().astimezone().isoformat(timespec="seconds")
        with open(LOG_FILE, "a", encoding="utf-8") as handle:
            handle.write(f"{stamp} custom-insightshield: {message}\n")
    except OSError:
        pass


def build_payload(alert: dict) -> dict:
    """Original alert + the flat aliases the webhook validates on."""
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}

    payload = dict(alert)
    payload["rule_id"] = str(rule.get("id", ""))
    payload["device_name"] = agent.get("name") or "unknown-agent"
    payload["description"] = rule.get("description") or f"Wazuh rule {payload['rule_id']}"
    # rule.level is the only severity source; wazuh_receiver.LEVEL_MAP turns it
    # into INFORMATIONAL/LOW/MEDIUM/HIGH/CRITICAL. Deliberately not sending a
    # `severity` key — that would bypass the map entirely.
    if rule.get("level") is not None:
        payload["rule_level"] = int(rule["level"])
    # alert["timestamp"] passes through untouched when present; the receiver
    # stamps PHT now() when it is not.
    return payload


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        log(f"expected 3 arguments (alert_file, api_key, hook_url), got {len(argv) - 1}")
        return 1

    alert_file, api_key, hook_url = argv[1], argv[2], argv[3]

    try:
        with open(alert_file, encoding="utf-8") as handle:
            alert = json.load(handle)
    except (OSError, ValueError) as exc:
        log(f"could not read alert file {alert_file}: {type(exc).__name__}")
        return 1

    payload = build_payload(alert)
    request = urllib.request.Request(
        hook_url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            # The shared secret. Matches app.py's X-Webhook-Token gate, which
            # fails closed — an empty or wrong value is a 403.
            "X-Webhook-Token": api_key,
        },
    )

    # nginx fronts the app with a self-signed lab certificate. Verification is
    # skipped only because the hook_url is loopback/LAN to a host we control;
    # point hook_url at a name with a real certificate and drop this.
    context = ssl._create_unverified_context() if hook_url.startswith("https") else None

    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_S, context=context) as resp:
            body = resp.read().decode("utf-8", "replace")[:200]
            log(f"rule {payload.get('rule_id')} -> HTTP {resp.status} {body}")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:200]
        # 403 here almost always means WAZUH_WEBHOOK_TOKEN in the app's .env
        # and <api_key> in ossec.conf have drifted apart.
        log(f"rule {payload.get('rule_id')} -> HTTP {exc.code} {detail}")
        return 1
    except (urllib.error.URLError, OSError) as exc:
        log(f"rule {payload.get('rule_id')} -> unreachable: {type(exc).__name__}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
