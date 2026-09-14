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
    "7200", "7201", "7202", "7204", "7209",  # arpwatch (7200: group, overwrites)
    "60103", "60106", "60109", "60118", "60119", "60122", "60154",  # Windows security
    "61100", "61102", "61107", "61138", "61612",                    # Windows system, Sysmon 10
    "86601",                                # Suricata alert
    "92205",                                # PowerShell exe creation (92800-sysmon; suppressed by 100096)
    "92212", "92213",                       # PowerShell archive, exe in user Temp (0830-sysmon_id_11.xml)
    "92900",                                # LSASS read (0945-sysmon_id_10.xml)
}


def _rules():
    return list(ET.parse(RULES).getroot().iter("rule"))


def _parents(rule):
    return [p for tag in ("if_sid", "if_matched_sid") for p in (rule.findtext(tag) or "").split(",") if p]


def test_no_xml_declaration():
    # Wazuh's own parser (os_xml.c) only special-cases "<!"; it reads
    # <?xml ... ?> as an element, hits the "?" after the last attribute and
    # refuses the whole file: "Bad attribute closing for 'encoding'".
    for path in (RULES, os.path.join(os.path.dirname(RULES), "agent.conf")):
        with open(path, encoding="utf-8") as f:
            assert "<?" not in f.read(), path


def test_rule_count():
    # 31 custom (100xxx) + 3 stock overrides (7202/7204/7209) + 100096/100099/100100
    # + suppressors 100101/100102/100103. scripts/deploy.sh reads this number.
    assert len(_rules()) == 40


def test_mitm_rules_hang_off_arpwatch_not_sudo():
    parents = {r.get("id"): r.findtext("if_sid") for r in _rules()}
    assert {rid: parents[rid] for rid in MITM} == {
        "100020": "7204,7209", "100021": "7202", "100022": "7201", "100023": "530"}


def test_arp_spoof_alerts_once_per_window_and_repeats_are_informational():
    # Live 2026-09-11: one 30 s arpspoof stored ~60 CRITICAL 100020 rows, each
    # paged by Telegram and email. ignore= silences the rule after it fires, and
    # Wazuh then reports the event under the stock parent — which at stock level
    # 9 is MEDIUM (HIGH after hours). Level 3 is Informational: no page, no score.
    rules = {r.get("id"): r for r in _rules()}
    for rid in ("100020", "100021"):
        assert int(rules[rid].get("ignore", 0)) >= 300, rid
    for rid, match in (("7202", "flip flop "), ("7204", "changed ethernet address "),
                       ("7209", "ethernet mismatch")):
        r = rules[rid]
        assert r.get("overwrite") == "yes" and int(r.get("level")) <= 4, rid
        assert r.findtext("match") == match, rid  # verbatim from stock v4.8.2
        assert r.findtext("if_sid") == "7200", rid
        assert "arpwatch" in r.findtext("group"), rid


def test_every_parent_is_verified_stock_or_custom():
    ids = {r.get("id") for r in _rules()}
    bad = {r.get("id"): p for r in _rules() for p in _parents(r) if p not in STOCK_PARENTS | ids}
    assert bad == {}


def test_every_rule_has_a_parent():
    # A parentless custom rule sits behind Wazuh's own top-level Windows group
    # rule, which matches first — it loads, but never fires. if_group is a valid
    # anchor too (100099 hangs off sysmon_event_10, exactly as stock 92900 does).
    assert [r.get("id") for r in _rules()
            if not _parents(r) and not r.findtext("if_group")] == []


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


def test_suspicious_program_rule_ignores_the_agents_own_commands():
    # Live on the Manager PC: 100014 fired every 10 s on the syn-watch monitor.
    import re
    rule = next(r for r in _rules() if r.get("id") == "100014")
    pattern = re.compile(next(f.text for f in rule.iter("field")
                              if f.get("name") == "win.eventdata.newProcessName"))
    for own in (r"C:\\Windows\\SysWOW64\\cmd.exe",
                r"C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe"):
        assert not pattern.search(own), own
    assert pattern.search(r"C:\\Users\\cashier\\AppData\\Local\\Temp\\mimikatz.exe")
    # OneDrive lives in AppData and raised a HIGH on every sync.
    negated = [re.compile(f.text) for f in rule.iter("field")
               if f.get("name") == "win.eventdata.newProcessName" and f.get("negate") == "yes"]
    for onedrive in (r"C:\\Users\\cashier\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
                     r"C:\Users\cashier\AppData\Local\Microsoft\OneDrive\OneDrive.exe"):
        assert pattern.search(onedrive) and any(n.search(onedrive) for n in negated), onedrive
    assert not any(n.search(r"C:\\Users\\cashier\\AppData\\Local\\Temp\\mimikatz.exe") for n in negated)


def test_time_windows_are_written_in_utc():
    # wazuh-analysisd checks <time> in UTC (alerts stamped +0000) even though
    # the host clock is PHT; PHT windows fired 8 hours off.
    windows = {r.get("id"): r.findtext("time") for r in _rules() if r.findtext("time")}
    assert windows == {"100002": "13:00 - 00:00", "100043": "00:00 - 13:00",
                       "100050": "00:00 - 13:00", "100051": "00:00 - 13:00",
                       "100056": "00:00 - 13:00"}


def test_fim_path_matchers_are_case_insensitive():
    # Wazuh hands the rule engine the syscheck path lowercased (live event:
    # "c:\pos\shared\test_48.txt") and w_expression_compile passes no
    # PCRE2_CASELESS, so the uppercase patterns 100011/100012/100044 shipped
    # with never matched one event — 100044 through 100047 had never fired.
    # Only the syscheck "file" field is lowercased; 4688's newProcessName
    # (100014) keeps the OS casing and is deliberately left case-sensitive,
    # since (?i) there would newly match C:\Windows\TEMP and add noise.
    import re
    for r in _rules():
        for f in r.iter("field"):
            pat = f.text or ""
            if f.get("name") == "file" and re.search(r"[A-Za-z]:\\\\", pat):
                assert pat.startswith("(?i)"), (r.get("id"), pat)


def test_pos_directory_rule_leaves_the_shared_folder_to_the_ransomware_chain():
    # Siblings are evaluated level-high-first (_OS_AddRule) and the first match
    # wins (OS_CheckIfRuleMatch's child loop), so 100011 at level 13 outranks
    # 100045 (12) and 100044 (8) and would take every event they exist to
    # escalate. 100046/100047 hang off those two and would stay unreachable.
    r = next(x for x in _rules() if x.get("id") == "100011")
    neg = [f.text for f in r.iter("field") if f.get("negate") == "yes"]
    assert neg == [r"(?i)C:\\POS\\shared"], neg


def test_noise_suppressors_are_level_zero_and_nothing_else_is():
    # level 0 is the whole mechanism: analysisd breaks out of the rule loop on
    # it, before the integrator, the frequency lists and the dashboard. It also
    # means a suppressor cannot feed if_matched_sid — which is why 100044 stays
    # at level 8 and its own alerts get bulk-resolved instead of silenced.
    suppressors = [r.get("id") for r in _rules() if r.get("level") == "0"]
    assert suppressors == ["100090", "100100", "100096", "100101", "100102", "100103"], suppressors
    for r in _rules():
        if r.get("id") in suppressors:
            assert "insightshield_noise" in r.findtext("group"), r.get("id")


def test_field_patterns_are_single_line():
    # eventchannel field text includes the element's own whitespace, so a
    # pattern split across lines with ^...$ anchors would never match —
    # silently disabling the rule. Guard every field value in the file.
    for r in _rules():
        for f in r.iter("field"):
            assert "\n" not in (f.text or ""), (r.get("id"), f.get("name"), repr(f.text))
            assert (f.text or "") == (f.text or "").strip(), (r.get("id"), f.get("name"))


def _fields(rid):
    """{field name: compiled pattern} for one rule; negates keyed 'name!'."""
    import re
    r = next(x for x in _rules() if x.get("id") == rid)
    return {f.get("name") + ("!" if f.get("negate") == "yes" else ""): re.compile(f.text)
            for f in r.iter("field")}


def _matches(rid, event):
    # analysisd semantics for <field>: every positive must match, every negate
    # must not. Missing field = no match.
    for key, p in _fields(rid).items():
        name, neg = key.rstrip("!"), key.endswith("!")
        hit = name in event and bool(p.search(event[name]))
        if hit == neg:
            return False
    return True


# Field values exactly as json_extract() returned them from the live DB,
# 2026-09-14: eventchannel doubles every backslash.
_EV = "win.eventdata."


def test_lsass_rule_excludes_the_wazuh_agent_as_the_field_really_arrives():
    # The anchored single-backslash pattern never matched the doubled field:
    # 100099 paged HIGH on every agent scan (POSsys1 11:28, POSsys3 11:50).
    agent = r"C:\\Program Files (x86)\\ossec-agent\\wazuh-agent.exe"
    base = {_EV + "targetImage": r"C:\\Windows\\system32\\lsass.exe", _EV + "grantedAccess": "0x1410"}
    assert not _matches("100099", {**base, _EV + "sourceImage": agent})
    # Same binary name anywhere else is still a dumper.
    assert _matches("100099", {**base, _EV + "sourceImage": r"C:\\Users\\POS\\AppData\\Local\\Temp\\wazuh-agent.exe"})
    assert _matches("100099", {**base, _EV + "sourceImage": r"C:\\Users\\POS\\AppData\\Local\\Temp\\procdump\\procdump64.exe",
                               _EV + "grantedAccess": "0x1FFFFF"})


def test_disk_cleanup_suppressors_match_cleanmgr_only():
    guid = r"C:\\Users\\POS\\AppData\\Local\\Temp\\A61911AF-A947-49F2-B24D-5A9774E5ACBB\\"
    cleanmgr_lower = r"C:\\Windows\\system32\\cleanmgr.exe"   # Sysmon 11 casing
    cleanmgr_upper = r"C:\\Windows\\System32\\cleanmgr.exe"   # 4688 casing
    ps = r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # 100101 under 92213: cleanmgr's own drop is suppressed...
    assert _matches("100101", {_EV + "image": cleanmgr_lower, _EV + "targetFilename": guid + "TransmogProvider.dll"})
    # ...the same set written by PowerShell (DISM cmdlets, or a UAC-bypass plant) is not,
    assert not _matches("100101", {_EV + "image": ps, _EV + "targetFilename": guid + "LogProvider.dll"})
    # ...nor cleanmgr writing outside a GUID folder, nor a renamed cleanmgr.
    assert not _matches("100101", {_EV + "image": cleanmgr_lower,
                                   _EV + "targetFilename": r"C:\\Users\\POS\\AppData\\Local\\Temp\\procdump\\procdump64.exe"})
    assert not _matches("100101", {_EV + "image": r"C:\\Users\\POS\\Desktop\\cleanmgr.exe",
                                   _EV + "targetFilename": guid + "DismHost.exe"})

    # 100102 under 100014: DismHost started by cleanmgr only.
    assert _matches("100102", {_EV + "parentProcessName": cleanmgr_upper, _EV + "newProcessName": guid + "DismHost.exe"})
    assert not _matches("100102", {_EV + "parentProcessName": ps, _EV + "newProcessName": guid + "DismHost.exe"})
    assert not _matches("100102", {_EV + "parentProcessName": cleanmgr_upper, _EV + "newProcessName": guid + "evil.exe"})
    # Defender's signature update also lands in 100014 but is not this rule's business.
    assert not _matches("100102", {
        _EV + "parentProcessName": r"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.26080.3-0\\MpCmdRun.exe",
        _EV + "newProcessName": r"C:\\Windows\\Temp\\52BA2E30-4CFE-41F0-B735-10199344C75FMpCommU\\mpam-d_bd_1.459.173.0.exe"})


def test_powershell_policy_probe_suppressor_is_exact():
    ps64 = r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    ps32 = r"C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe"
    for image, f in ((ps32, r"C:\\Windows\\SystemTemp\\__PSScriptPolicyTest_5raagwig.rar.ps1"),   # 92212, Manager
                     (ps64, r"C:\\Users\\POS\\AppData\\Local\\Temp\\__PSScriptPolicyTest_emfa4ikm.fd1.ps1")):  # 92213
        assert _matches("100103", {_EV + "image": image, _EV + "targetFilename": f}), f
    # Real PowerShell drops under 92213 stay visible (procdump staging, 2026-09-12).
    assert not _matches("100103", {_EV + "image": ps64,
                                   _EV + "targetFilename": r"C:\\Users\\POS\\AppData\\Local\\Temp\\procdump\\procdump64.exe"})
    # Probe-looking name from another writer, or a longer name, still alerts.
    assert not _matches("100103", {_EV + "image": r"C:\\Users\\POS\\AppData\\Local\\Temp\\x\\powershell.exe",
                                   _EV + "targetFilename": r"C:\\Users\\POS\\AppData\\Local\\Temp\\__PSScriptPolicyTest_abcd1234.zip.ps1"})
    assert not _matches("100103", {_EV + "image": ps64,
                                   _EV + "targetFilename": r"C:\\Users\\POS\\AppData\\Local\\Temp\\__PSScriptPolicyTest_payload-stage2.zip.ps1"})


def test_lsass_rule_catches_procdump_mask_and_skips_the_benign_ones():
    # The whole point of 100099: fire on procdump's 0x1FFFFF, stay silent on the
    # query-only masks that made 92900's substring match noisy.
    import re
    r = next(x for x in _rules() if x.get("id") == "100099")
    mask_neg = next(f.text for f in r.iter("field")
                    if f.get("name") == "win.eventdata.grantedAccess" and f.get("negate") == "yes")
    p = re.compile(mask_neg)
    assert not p.fullmatch("0x1fffff".upper()) and not p.fullmatch("0x1FFFFF")  # procdump -> fires
    assert not p.fullmatch("0x1410") and not p.fullmatch("0x1010")             # read masks -> fire
    for benign in ("0x1000", "0x100000", "0x101000"):
        assert p.fullmatch(benign), benign                                    # query-only -> suppressed


def test_every_rule_in_the_file_has_a_label_that_fits():
    for r in _rules():
        if r.get("level") == "0":
            continue  # analysisd drops it before the integrator: no alert to label
        label = wazuh_receiver._infer_attack_type(r.get("id"))
        assert label != "Unknown", r.get("id")
        assert len(label) <= 64, label  # attack_type's payload limit


def test_ai_repeat_cap_stops_after_n_attempts_per_rule_and_device():
    # A noisy rule firing hourly must not spend the free-tier budget on the same
    # alert forever: the (rule, device) pair gets config.AI_REPEAT_CAP live AI
    # slots per window, then falls back to static. A different device is its own
    # budget. 0 disables the cap entirely.
    import config
    orig = config.AI_REPEAT_CAP
    try:
        config.AI_REPEAT_CAP = 3
        # Unique ids so this test's rows never collide with another test's.
        rule, dev_a, dev_b = "T-CAP-1", "capdev-A", "capdev-B"
        assert [wazuh_receiver._ai_repeat_ok(rule, dev_a) for _ in range(5)] == \
            [True, True, True, False, False]
        # Second device untouched by the first's budget.
        assert wazuh_receiver._ai_repeat_ok(rule, dev_b) is True
        # 0 = disabled: always allowed.
        config.AI_REPEAT_CAP = 0
        assert all(wazuh_receiver._ai_repeat_ok(rule, dev_a) for _ in range(3))
    finally:
        config.AI_REPEAT_CAP = orig


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
