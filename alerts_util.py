# alerts_util.py
# Insight Shield — pure helpers for reading an alert row.
#
# A leaf module on purpose: it imports nothing from this app. derive_attacker_ip
# lived in app.py, which meant db.get_top_attacker_ips had to do
# `from app import _derive_attacker_ip` *inside the function* to dodge a circular
# import — app imports db at module load, so db could only reach back at call
# time. That workaround, not the file size, was what pinned every helper into a
# 2,700-line module.

import json
import re

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def derive_attacker_ip(alert_row):
    """Return a best-effort attacker IP for a display row, or None if unknown.
    Derivation order: attack_trail.data.srcip → raw_alert.data.srcip/src_ip/
    source_ip → raw_alert.data.arp.sender_ip → regex scrape of full_log.
    Never raises — runs inside Jinja render."""
    try:
        if not isinstance(alert_row, dict):
            try:
                alert_row = dict(alert_row)
            except Exception:
                return None
        trail = alert_row.get("attack_trail")
        if isinstance(trail, str):
            try:
                trail = json.loads(trail)
            except (ValueError, TypeError):
                trail = None
        if isinstance(trail, dict):
            data = trail.get("data") if isinstance(trail.get("data"), dict) else {}
            ip = data.get("srcip")
            if ip:
                return ip
        raw = alert_row.get("raw_alert")
        doc = json.loads(raw) if isinstance(raw, str) else (raw or {})
        if not isinstance(doc, dict):
            doc = {}
        data = doc.get("data") if isinstance(doc.get("data"), dict) else {}
        for key in ("srcip", "src_ip", "source_ip"):
            if data.get(key):
                return data[key]
        arp = data.get("arp") if isinstance(data.get("arp"), dict) else {}
        if arp.get("sender_ip"):
            return arp["sender_ip"]
        full_log = data.get("full_log") or doc.get("full_log") or ""
        m = _IPV4_RE.search(full_log) if full_log else None
        return m.group(0) if m else None
    except Exception:
        return None


# Wazuh rule level -> Insight Shield severity. Lived in wazuh_receiver, which
# imports db, which imports this module — so build_severity_array below could
# not reach it without a cycle. It is a pure constant with no dependencies, so
# it belongs in the leaf: wazuh_receiver imports it back from here and there is
# still exactly one copy.
LEVEL_MAP = {
    2: "INFORMATIONAL", 3: "INFORMATIONAL", 4: "INFORMATIONAL",
    5: "LOW", 6: "LOW", 7: "LOW",
    8: "MEDIUM", 9: "MEDIUM",
    10: "HIGH", 11: "HIGH", 12: "HIGH",
    13: "CRITICAL", 14: "CRITICAL", 15: "CRITICAL",
}

# Round 6: Sequence used by /api/severity-breakdown and the SSE producer.
# Order is fixed crit -> info so the IT dashboard renders critical at the top
# (per master spec Part 6) without any client-side sorting. `label` is the
# short label the bar chart shows; `levels` is the rule-level range that
# falls in the bucket — derived from LEVEL_MAP so the API auto-updates if the
# mapping ever shifts.
SEVERITY_BUCKETS = (
    ("crit", "Crit", "CRITICAL"),
    ("high", "High", "HIGH"),
    ("med",  "Med",  "MEDIUM"),
    ("low",  "Low",  "LOW"),
    ("info", "Info", "INFORMATIONAL"),
)


def build_severity_array(breakdown: dict) -> list[dict]:
    """Convert the db's {SEVERITY: count} dict into the wire-format array.

    Reverse-derives `levels` from LEVEL_MAP so a future re-band of the level
    mapping doesn't drift the API contract.
    """
    levels_for: dict[str, list[int]] = {
        "INFORMATIONAL": [], "LOW": [], "MEDIUM": [], "HIGH": [], "CRITICAL": [],
    }
    for level, sev in LEVEL_MAP.items():
        if sev in levels_for:
            levels_for[sev].append(level)
    for k in levels_for:
        levels_for[k].sort()

    return [
        {
            "key":    short,
            "label":  label,
            "count":  int(breakdown.get(uppercase, 0) or 0),
            "levels": levels_for[uppercase],
        }
        for (short, label, uppercase) in SEVERITY_BUCKETS
    ]
