# tests/test_obfuscation.py
# Guards the AI-boundary obfuscation in it_recommender.
#
# This is the perimeter control on the second AI call: the raw Wazuh payload
# goes to Groq/Gemini/OpenRouter, so anything not substituted here leaves the
# network. The three cases below are the three ways the previous static-dict
# implementation failed.

import json

import it_recommender as itr

PAYLOAD = {
    "agent": {"id": "002", "name": "POSsys1", "ip": "192.168.1.137"},
    "rule": {"id": "100011", "level": 10, "description": "Credential dump"},
    "data": {"pid": "33891", "bytes": 233890, "dstport": "3389",
             "srcip": "192.168.1.185", "process": "mimikatz.exe"},
    "id": "1756233897.4521",
}
RAW = json.dumps(PAYLOAD)


def _obfuscated():
    mapping = itr._build_map(RAW, "POSsys1")
    return mapping, itr._obfuscate(RAW, mapping)


def test_real_identifiers_do_not_leave_the_perimeter():
    """The whole point: no real hostname or internal IP in the outbound prompt."""
    _, sent = _obfuscated()
    for secret in ("POSsys1", "192.168.1.137", "192.168.1.185", "mimikatz.exe"):
        assert secret not in sent, f"{secret} reached the AI provider"


def test_payload_is_not_corrupted_by_substring_matches():
    """
    "3389" as a bare substring also hit the PID, the byte count and the alert
    id, so the model received malformed JSON. Anchored substitution means the
    port is replaced and nothing else is.
    """
    _, sent = _obfuscated()
    assert json.loads(sent), "obfuscated payload is no longer valid JSON"
    assert "33891" in sent, "PID was mangled by the port substitution"
    assert "233890" in sent, "byte count was mangled by the port substitution"
    assert "1756233897.4521" in sent, "alert id was mangled"
    assert '"dstport": "Port-X"' in sent, "the actual port was not obfuscated"


def test_round_trip_restores_this_alert_s_real_values():
    """
    The old code mapped Device-A back to a hardcoded address that existed on
    no real network, so IT was told to isolate a host that does not exist.
    """
    mapping, _ = _obfuscated()
    reply = "MITIGATE: Isolate Device-A and Host-A, block Port-X, kill Tool-A."
    restored = itr._deobfuscate(reply, mapping)
    assert "192.168.1.137" in restored
    assert "POSsys1" in restored
    assert "3389" in restored
    assert "mimikatz.exe" in restored
    assert "Device-A" not in restored and "Host-A" not in restored


def test_public_addresses_are_left_alone():
    """An external attacker IP is not ours to protect, and the model needs it."""
    raw = json.dumps({"agent": {"name": "POSsys1"}, "data": {"srcip": "8.8.8.8"}})
    mapping = itr._build_map(raw, "POSsys1")
    assert "8.8.8.8" in itr._obfuscate(raw, mapping)


def test_malformed_payload_still_obfuscates_addresses():
    """A payload that will not parse must not fall through unobfuscated."""
    raw = '{"agent": {"name": "POSsys1", "ip": "192.168.1.137"'  # truncated
    mapping = itr._build_map(raw, "POSsys1")
    sent = itr._obfuscate(raw, mapping)
    assert "192.168.1.137" not in sent
    assert "POSsys1" not in sent


def test_two_devices_share_a_cache_entry_but_not_an_answer():
    """
    Identical alerts from different terminals obfuscate to the same prompt, so
    they share a cached reply — which must still deobfuscate per device.
    """
    a = json.dumps({"agent": {"name": "POSsys1", "ip": "192.168.1.137"}})
    b = json.dumps({"agent": {"name": "POSsys2", "ip": "192.168.1.185"}})
    map_a, map_b = itr._build_map(a, "POSsys1"), itr._build_map(b, "POSsys2")
    assert itr._obfuscate(a, map_a) == itr._obfuscate(b, map_b)

    cached = "MITIGATE: Isolate Device-A."
    assert "192.168.1.137" in itr._deobfuscate(cached, map_a)
    assert "192.168.1.185" in itr._deobfuscate(cached, map_b)
