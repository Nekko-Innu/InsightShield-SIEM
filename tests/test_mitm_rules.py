"""Custom rules once hung off stock rules that meant something else: 100020-100022
off the sudo rules 5402-5404, so every root `sudo` raised a CRITICAL "ARP
poisoning" alert; others off pfSense/logoff/web-log ids, so they never fired.
Pin the parents, and the labels the app gives each rule.
"""
import json
import os
import runpy
import tempfile
import xml.etree.ElementTree as ET

os.environ.setdefault("FLASK_SECRET_KEY", "test-only-" + "0" * 32)
os.environ.setdefault("ENCRYPTION_KEY", "")
os.environ.setdefault("BOOTSTRAP_ADMIN_PASSWORD", "test-Admin!2026")
os.environ.setdefault("BOOTSTRAP_MANAGER_PASSWORD", "test-Manager!2026")

import db
import groq_translator
import wazuh_receiver

# Throwaway DB, set before the first connection (as test_alert_lifecycle.py).
db.DB_PATH = os.path.join(tempfile.mkdtemp(prefix="is-mitm-test-"), "test.db")
db.init_db()

RULES = os.path.join(os.path.dirname(__file__), "..", "wazuh_rules", "custom_retail_rules.xml")
MITM = ("100020", "100021", "100022", "100023")

# Stock Wazuh v4.8.2 parents, each checked against the v4.8.2 ruleset source.
# A parent not in here is either a custom rule or a guess — and the guesses were
# the bug: 5402 is sudo, 87701 pfSense, 31151 a web 400, 87710 doesn't exist.
STOCK_PARENTS = {
    "530", "550", "554",                    # command output, FIM changed/added
    "7201", "7202", "7204", "7209",         # arpwatch
    "60103", "60106", "60109", "60118", "60119", "60122", "60154",  # Windows security
    "61100", "61102", "61107", "61138", "61612",                    # Windows system, Sysmon 10
    "86601",                                # Suricata alert
}


def _rules():
    return list(ET.parse(RULES).getroot().iter("rule"))


def _parents(rule):
    return [p for tag in ("if_sid", "if_matched_sid") for p in (rule.findtext(tag) or "").split(",") if p]


def test_rule_count():
    assert len(_rules()) == 30


def test_mitm_rules_hang_off_arpwatch_not_sudo():
    parents = {r.get("id"): r.findtext("if_sid") for r in _rules()}
    assert {rid: parents[rid] for rid in MITM} == {
        "100020": "7204,7209", "100021": "7202", "100022": "7201", "100023": "530"}


def test_every_parent_is_verified_stock_or_custom():
    ids = {r.get("id") for r in _rules()}
    bad = {r.get("id"): p for r in _rules() for p in _parents(r) if p not in STOCK_PARENTS | ids}
    assert bad == {}


def test_every_rule_has_a_parent():
    # A parentless custom rule sits behind Wazuh's own top-level Windows group
    # rule, which matches first — it loads, but never fires.
    assert [r.get("id") for r in _rules() if not _parents(r)] == []


def test_no_rule_hides_its_alert():
    # no_log on 100001 kept every brute force out of alerts.json.
    assert [r.get("id") for r in _rules() if r.findtext("options") == "no_log"] == []


def test_victim_side_rules_fire_once_per_change():
    # The agent resends command output every interval; without check_diff
    # 100031 fires every 10 s for the whole flood. One <match> each: Wazuh joins
    # several into one pattern and the rule would never match.
    for r in _rules():
        if r.get("id") in ("100023", "100031"):
            assert r.find("check_diff") is not None, r.get("id")
            assert len(r.findall("match")) == 1, r.get("id")


def test_every_custom_rule_has_a_label_that_fits():
    for r in _rules():
        label = wazuh_receiver._infer_attack_type(r.get("id"))
        assert label != "Unknown", r.get("id")
        assert len(label) <= 64, label  # attack_type's payload limit


def test_mitm_rules_use_the_arp_template():
    for rid in MITM:
        assert groq_translator.RULE_TO_TEMPLATE[rid] == "arp_mitm"


def test_stock_ids_that_are_not_attacks_stay_unlabelled():
    # sudo, pfSense drop, logon success, web SQLi, FIM file added
    for rid in ("5402", "87701", "60106", "31152", "554"):
        assert wazuh_receiver._infer_attack_type(rid) == "Unknown", rid
        assert rid not in groq_translator.RULE_TO_TEMPLATE, rid


def test_unmapped_rule_keeps_full_wazuh_description():
    desc = "Sysmon - Event 1: Process creation from a long and descriptive Wazuh stock rule title"
    assert wazuh_receiver.attack_label("61603", {"description": desc}) == desc
    assert wazuh_receiver.attack_label("61603", {"description": "Wazuh rule 61603"}) == "Unknown"
    assert wazuh_receiver.attack_label("100001", {"description": desc}).startswith("Brute-force")


def test_long_description_is_cut_not_rejected():
    payload = {"rule_id": "100010", "device_name": "POSsys1", "rule_level": 15,
               "description": "D" * 1000}
    assert wazuh_receiver.validate_payload(payload) is None
    assert payload["description"] == "D" * 512


def test_relabel_fixes_old_wazuh_rows_and_leaves_internal_alerts():
    def store(rule_id, attack_type, raw):
        return db.store_alert({
            "timestamp": "2026-09-11T10:00:00+08:00", "rule_id": rule_id,
            "attack_type": attack_type, "severity": "HIGH", "device_name": "POSsys1",
            "raw_alert": json.dumps(raw), "plain_text": "x", "ai_reasoning": "",
            "provider_used": "static", "fk_grade": 1.0, "attack_trail": None,
        })

    long_desc = "Sysmon - Event 1: Process creation from a long and descriptive Wazuh stock rule title"
    old = store("100044", "[T/D] Ransomware", {"rule_id": "100044", "description": "x"})
    cut = store("61603", long_desc[:64], {"rule_id": "61603", "description": long_desc})
    internal = store("ISH-CBF-001", "credential_brute_force",
                     {"rule": {"id": "ISH-CBF-001"}, "data": {}})

    relabel = runpy.run_path(os.path.join(os.path.dirname(__file__), "..", "scripts", "relabel_alerts.py"))
    for _ in range(2):  # second run must be a no-op
        assert relabel["main"]() == 0
        assert db.get_alert(old)["attack_type"] == "File changed in POS shared folder · Tampering"
        assert db.get_alert(cut)["attack_type"] == long_desc
        assert db.get_alert(internal)["attack_type"] == "credential_brute_force"
