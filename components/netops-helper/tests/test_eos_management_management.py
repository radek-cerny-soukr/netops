"""Replay independently captured and anonymized cEOS 4.36.1F SSH output."""
import json
from dataclasses import replace
from pathlib import Path

import pytest

from conftest import _target
from netops_helper import engine
from netops_helper.query_catalog.arista import QUERIES
from netops_helper.read_policy import render_read_query

FIXTURES = Path(__file__).parent / "fixtures/real/arista_eos"
CAPTURES = json.loads((FIXTURES / "eos_management_ceos_4.36.1F/index.json").read_text())
VERSION = (FIXTURES / "eos_ports_ceos_4.36.1F/version_ro.out").read_text()
PLATFORM = "arista_eos"
INVENTORY = {"interfaces": ("Ethernet1",), "diagnostic_names": ("localhost.localdomain", "example.invalid")}


def replay(monkeypatch, row, text=None, *, expected_command=None):
    query, parameters = row["query"], row["parameters"]
    command = expected_command or QUERIES[query].command.format_map(parameters)
    calls = []

    def read(_auth, platform, actual):
        assert platform == PLATFORM
        calls.append(actual)
        if actual == "show version":
            return 0, VERSION
        assert actual == command
        return row["rc"], row["text"] if text is None else text

    monkeypatch.setattr(engine, "read_from_device", read)
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    auth = replace(_target(PLATFORM, "version"), enabled_queries=("version", query), read_inventory=INVENTORY)
    result = engine.ssh_read(auth, PLATFORM, query, parameters, 0, 16000)
    assert calls[-1] == command
    return result


@pytest.mark.parametrize("case", CAPTURES)
def test_real_eos_reads(monkeypatch, case):
    row = CAPTURES[case]
    result = replay(monkeypatch, row)
    assert result["rc"] == row["rc"]
    if row["rc"]:
        assert not result["ok"]
        assert result["status"] == "permission_denied"
    else:
        assert result["ok"]
        if row["text"]:
            assert result["untrusted_device_output"].strip()
        else:
            assert result["status"] == "empty"


def test_acl_reports_bindings_and_hit_counters(monkeypatch):
    rules = replay(monkeypatch, CAPTURES["ipv4_access_lists_admin"])["untrusted_device_output"]
    summary = replay(monkeypatch, CAPTURES["ipv4_access_lists_summary_admin"])["untrusted_device_output"]
    assert "default-control-plane-acl" in rules and "[match " in rules
    assert "Active on     Ingress: control-plane(default VRF)" in summary


def test_eos_relay_rows_and_incomplete_last_row(monkeypatch):
    row = CAPTURES["dhcp_relay_counters_admin"]
    complete = replay(monkeypatch, row)["dhcp_relay_counters"]
    assert complete["complete"]
    assert [(r["interface"], r["received"], r["forwarded"], r["dropped"]) for r in complete["rows"]] == [
        ("All Req", 0, 0, 0), ("All Resp", 0, 0, 0),
    ]

    # End the capture at the start of the final real row.
    truncated = row["text"].split("All Resp", 1)[0] + "All Resp"
    incomplete = replay(monkeypatch, row, truncated)["dhcp_relay_counters"]
    assert incomplete == {"complete": False, "rows": complete["rows"][:1]}


def test_dns_reports_resolution_separately(monkeypatch):
    resolved = replay(monkeypatch, CAPTURES["dns_lookup_admin"])["dns_lookup"]
    assert resolved == {"name": "localhost.localdomain", "resolved": True, "address": "127.0.0.1"}
    failed = replay(monkeypatch, CAPTURES["dns_lookup_unresolved"])["dns_lookup"]
    assert failed == {"name": "example.invalid", "resolved": False, "address": None}
    with pytest.raises(ValueError):
        render_read_query(PLATFORM, "dns_lookup", {"name": "unlisted.example"}, INVENTORY)


def test_dns_reports_ipv6_resolution_and_temporary_dns_failure(monkeypatch):
    # Derived variants of the two captures: ping6 omits the whitespace before the address,
    # and getaddrinfo can report a temporary name resolution error.
    success = CAPTURES["dns_lookup_admin"]
    ipv6 = success["text"].replace("                (127.0.0.1)", "(::1)")
    result = replay(monkeypatch, success, ipv6)["dns_lookup"]
    assert result == {"name": "localhost.localdomain", "resolved": True, "address": "::1"}
    failure = CAPTURES["dns_lookup_unresolved"]
    transient = failure["text"].replace("Name or service not known", "Temporary failure in name resolution")
    result = replay(monkeypatch, failure, transient)["dns_lookup"]
    assert result == {"name": "example.invalid", "resolved": False, "address": None}


def test_logging_status_filters_buffer_on_the_switch(monkeypatch):
    command = "show logging | include ^(Syslog|Buffer|Console|Monitor|Persistent|Trap|Logging to)"
    result = replay(monkeypatch, CAPTURES["logging_status_admin"], expected_command=command)
    assert result["ok"] and "Syslog logging: enabled" in result["untrusted_device_output"]


@pytest.mark.parametrize("case", ["radius_admin", "tacacs_admin"])
def test_backend_status_retains_aligned_numeric_counters_only(monkeypatch, case):
    row = CAPTURES[case]
    # Derived populated backend counters appended to the real empty-backend answer.
    reply = row["text"] + "\nConnection opens   : 2\nSend failures: 1\nSend failures: redaction-canary\n"
    result = replay(monkeypatch, row, reply)
    assert result["ok"] and "Connection opens   : 2" in result["untrusted_device_output"]
    assert "Send failures: 1" in result["untrusted_device_output"]
    assert "redaction-canary" not in json.dumps(result)


@pytest.mark.parametrize("case", ["snmp_status_admin", "snmp_targets_admin", "radius_admin",
                                 "tacacs_admin", "logging_status_admin", "radius_status_admin",
                                 "dhcp_server_admin", "dot1x_clients_admin"])
def test_secret_bearing_management_lines_never_leave_capture(monkeypatch, case):
    row = CAPTURES[case]
    # Synthetic credential canaries appended to the real output, including the documented
    # SNMP v2c "user" field, a shared-key line, and a syslog event.
    fake_secret = "canary-value-EOS-MANAGEMENT"
    additional = (
        "\nNotification host: 192.0.2.10    udp-port: 162   type: trap   refresh: True"
        f"\nuser: {fake_secret}        security model: v2c"
        f"\nShared key: {fake_secret}"
        f"\nTFTP file: https://user:{fake_secret}@example.invalid/image"
        f"\nArista-WebAuth: {fake_secret}"
        f"\nNov 17 08:00:00 device message {fake_secret}\n"
    )
    result = replay(monkeypatch, row, row["text"] + additional)
    assert result["ok"]
    body = result["untrusted_device_output"]
    assert fake_secret not in json.dumps(result)
    if case == "snmp_targets_admin":
        assert "Notification host: 192.0.2.10" in body
    else:
        assert row["text"].splitlines()[0] in body


def test_named_acl_can_read_all_rules_without_a_name():
    assert render_read_query(PLATFORM, "ipv4_access_lists", {}, INVENTORY) == (
        PLATFORM, "show ip access-lists",
    )


def test_populated_radius_monitor_table(monkeypatch):
    # Arista EOS User Security, "show monitor server radius", with RFC 5737 addresses.
    output = (
        "Probe method: Status-Server packet\n"
        "RADIUS Server  Messages Sent   Messages Accepted   Messages Dropped   Status\n"
        "-------------  -------------   -----------------   ----------------   ---------\n"
        "192.0.2.101      48              35                  1                  alive\n"
        "192.0.2.102      48              29                  1                  not alive\n"
    )
    result = replay(monkeypatch, CAPTURES["radius_status_admin"], output)
    assert result["untrusted_device_output"] == output


def test_unknown_snmp_target_format_is_reported_as_incomplete(monkeypatch):
    result = replay(monkeypatch, CAPTURES["snmp_targets_admin"], "Undocumented credential line\n")
    assert result["ok"] is False
    assert result["error_code"] == "incomplete_output"
    assert "Undocumented credential line" not in json.dumps(result)


def test_eos_dns_with_malformed_response_address_stays_unverified(monkeypatch):
    sample = CAPTURES["dns_lookup_admin"]
    answer = replay(monkeypatch, sample, sample["text"].replace("127.0.0.1", "127.0.0.999"))
    assert answer["dns_lookup"] == {"name": "localhost.localdomain", "resolved": None, "address": None}
