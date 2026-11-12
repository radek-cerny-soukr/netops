from dataclasses import replace
import json

import pytest

from conftest import (
    EXEC_CLIENT,
    FORTIOS_STATUS,
    PASSWORD,
    READ_QUERIES,
    _plain_query,
    _target,
    _write_client,
)
import netops_helper.engine as engine
from netops_helper import inventory


@pytest.mark.parametrize("platform,output,code", [
    ("extreme_exos", "This user does not have permissions for this command.\n", 254),
    ("extreme_exos", "%% Invalid input detected at '^' marker.\n", 254),
    ("extreme_exos", "Method is not implemented on this platform.\n\n", 250),
    ("cisco_ios", 'Line has invalid autocommand "show env all"\r\n', 0),
    ("cisco_xe", 'Line has invalid autocommand "show interfaces status"\r\n', 0),
    ("arista_eos", "> show system environment all\n% Invalid input at line 1\n", 1),
    ("arista_eos", "> show running-config\n% Invalid input (privileged mode required) at line 1\n", 1),
    ("juniper_junos", "error: syntax error, expecting <command>: foo\n", 0),
    ("juniper_junos", "error: permission denied: system\n", 0),
    ("juniper_junos_els", "error: unknown command: configure\n", 0),
    ("juniper_junos_els", "error: the virtual-chassis-control subsystem is not running\n", 0),
    ("cisco_nxos", "Syntax error while parsing 'show vpc brief'\n\n\nCmd exec error.\n", 16),
    ("cisco_nxos", "% Permission denied for the role\n\nCmd exec error.\n", 30),
])
def test_cli_refusal_is_failed_without_caching_and_valid_next_read_works(wire, monkeypatch, platform, output, code):
    events = []
    monkeypatch.setattr(engine, "record", lambda event, **fields: events.append(fields))
    query, _ = _plain_query(platform)
    target = _target(platform, query)
    payload = "x" * 2000 + "\n" + output + PASSWORD
    _write_client(wire["binaries"], "ssh", EXEC_CLIENT.format(log=str(wire["log"]), output=payload, code=code))
    answer = engine.ssh_read(target, platform, query, {}, 0, 1000)
    assert answer["ok"] is False
    assert answer["rc"] == code
    assert answer["error_code"] == "device_cli_error"
    assert PASSWORD not in json.dumps(answer)
    assert events[-1]["status"] == "failed"
    assert not engine._SSH_PAGE_CACHE
    _write_client(wire["binaries"], "ssh", EXEC_CLIENT.format(log=str(wire["log"]), output="valid query result\n", code=0))
    answer = engine.ssh_read(target, platform, query, {}, 0, 1000)
    assert answer["ok"] is True
    assert events[-1]["status"] == "ok"


@pytest.mark.parametrize("query_name", [
    None, "conserve_state", "cpu_cores", "fortiguard_communication",
])
@pytest.mark.parametrize("output", [
    "Command fail. Return code -7622\n",
    "command parse error before 'status'\n",
    "Unknown action 0\n",
])
def test_fortios_cli_refusal_after_a_verified_identity_is_failed_without_caching(
    wire, monkeypatch, output, query_name,
):
    events = []
    monkeypatch.setattr(engine, "record", lambda event, **fields: events.append(fields))
    query = query_name or next(
        name for name, item in sorted(READ_QUERIES["fortinet"].items())
        if not item.slots and item.command != engine._IDENTITY_COMMAND
    )
    target = _target("fortinet", query)
    state = {"body": "x" * 2000 + "\n" + output + PASSWORD}
    sent = []

    def fake_read(auth, platform, command):
        sent.append(command)
        if command == engine._IDENTITY_COMMAND:
            return 0, FORTIOS_STATUS
        return 0, state["body"]

    monkeypatch.setattr(engine, "read_from_device", fake_read)
    answer = engine.ssh_read(target, "fortinet", query, {}, 0, 1000)
    assert answer["ok"] is False
    assert answer["rc"] == 0
    assert answer["error_code"] == "device_cli_error"
    assert PASSWORD not in json.dumps(answer)
    assert sent[0] == engine._IDENTITY_COMMAND and len(sent) == 2
    assert events[-1]["status"] == "failed"
    assert not engine._SSH_PAGE_CACHE
    state["body"] = "Version: valid\n"
    answer = engine.ssh_read(target, "fortinet", query, {}, 0, 1000)
    assert answer["ok"] is True
    assert events[-1]["status"] == "ok"


@pytest.mark.parametrize("platform,output,code", [
    ("extreme_exos", "VLAN Interface with name Users created by user\n802.1Q Tag 10\n", 250),
    ("extreme_exos", "Stacking support: Method is not implemented on this platform.\n", 250),
    ("fortinet", "Errors: 0\nLast error: Command fail. Return code -61\n", 0),
    ("linux", "Command fail. Return code -61\n", 0),
    ("cisco_xe", "% Route not found\r\n", 0),
    ("cisco_ios", "% BGP not active\r\n", 0),
    ("cisco_ios", 'Description: set by "Line has invalid autocommand"\r\n', 0),
    ("arista_eos", "% There seem to be no power supplies connected. at line 1\nSystem temperature status is: Unknown\n", 1),
    ("juniper_junos", "Warning: License key missing; requires 'BGP' license\nGroups: 2 Peers: 2 Down peers: 0\n", 0),
    ("juniper_junos_els", "Spanning-tree is not enabled at global level.\n", 0),
    ("linux", "error: permission denied: system\n", 0),
    ("cisco_nxos", "ERROR: No neighbour information\n\n\nCmd exec error.\n", 244),
    ("cisco_nxos", "Description: Syntax error while parsing 'x'\n", 0),
])
def test_device_specific_classifier_preserves_valid_status_and_data(wire, platform, output, code):
    payload = output
    if platform == "fortinet":
        query = "system_status"
        payload = FORTIOS_STATUS + output
    else:
        query, _ = _plain_query(platform)
    _write_client(wire["binaries"], "ssh", EXEC_CLIENT.format(log=str(wire["log"]), output=payload, code=code))
    answer = engine.ssh_read(_target(platform, query), platform, query, {}, 0, 1000)
    assert answer["ok"] is True
    assert answer["rc"] == code
    # FortiOS and the normalized switch/router profiles unify CRLF to LF; other platforms keep it.
    expected = payload.replace("\r\n", "\n") if platform in engine._LINE_END_PLATFORMS else payload
    assert answer["untrusted_device_output"] == expected


@pytest.mark.parametrize("query,slot,peer,refusal", [
    ("bgp_received_ipv4", "peer", "192.0.2.20",
     "Inbound soft reconfiguration not enabled"),
    ("bgp_received_ipv6", "peer6", "2001:db8::20",
     "% Inbound soft reconfiguration not enabled"),
])
def test_bgp_received_unavailable_is_failed_without_caching(
    wire, monkeypatch, query, slot, peer, refusal,
):
    events = []
    monkeypatch.setattr(engine, "record", lambda event, **fields: events.append(fields))
    target = replace(_target("fortinet", query), read_inventory={"addresses": (peer,)})
    parameters = {slot: peer}
    state = {"body": refusal + "\nNo prefix for neighbor " + peer + "\n" + PASSWORD}
    sent = []

    def fake_read(auth, platform, command):
        sent.append(command)
        if command == engine._IDENTITY_COMMAND:
            return 0, FORTIOS_STATUS
        return 0, state["body"]

    monkeypatch.setattr(engine, "read_from_device", fake_read)
    answer = engine.ssh_read(target, "fortinet", query, parameters, 0, 1000)
    assert answer["ok"] is False
    assert answer["rc"] == 0
    assert answer["error_code"] == "device_cli_error"
    assert refusal in answer["untrusted_device_output"]
    assert PASSWORD not in json.dumps(answer)
    assert sent == [
        engine._IDENTITY_COMMAND,
        READ_QUERIES["fortinet"][query].command.format_map(parameters),
    ]
    assert events[-1]["status"] == "failed"
    assert not engine._SSH_PAGE_CACHE
    state["body"] = "Total number of prefixes 1\n"
    answer = engine.ssh_read(target, "fortinet", query, parameters, 0, 1000)
    assert answer["ok"] is True
    assert events[-1]["status"] == "ok"


def test_policy_lookup_route_error_is_failed_without_caching(wire, monkeypatch):
    events = []
    monkeypatch.setattr(engine, "record", lambda event, **fields: events.append(fields))
    query = "policy_lookup_ipv6"
    parameters = {
        "src_ip": "2001:db8::10", "src_port": "40000",
        "dst_ip": "2001:db8::20", "dst_port": "443",
        "protocol": "6", "device": "port2", "pol_type": "policy",
    }
    target = replace(_target("fortinet", query), read_inventory={
        "addresses": ("2001:db8::10", "2001:db8::20"),
        "flow_ports": ("40000", "443"), "ip_protocols": ("6",),
        "interfaces": ("port2",), "policy_types": ("policy",),
    })
    state = {"body": "No authentication.\nError code: err_route\n" + PASSWORD}
    sent = []

    def fake_read(auth, platform, command):
        sent.append(command)
        return (0, FORTIOS_STATUS) if command == engine._IDENTITY_COMMAND else (0, state["body"])

    monkeypatch.setattr(engine, "read_from_device", fake_read)
    answer = engine.ssh_read(target, "fortinet", query, parameters, 0, 1000)
    assert answer["ok"] is False
    assert answer["error_code"] == "device_cli_error"
    assert "route" in answer["error"]
    assert "Error code: err_route" in answer["untrusted_device_output"]
    assert PASSWORD not in json.dumps(answer)
    assert events[-1]["status"] == "failed"
    assert not engine._SSH_PAGE_CACHE
    assert sent == [engine._IDENTITY_COMMAND, READ_QUERIES["fortinet"][query].command.format_map(parameters)]
    state["body"] = "No policy matched\nsec_default_action: deny\nfirewall policy id: 0\n"
    answer = engine.ssh_read(target, "fortinet", query, parameters, 0, 1000)
    assert answer["ok"] is True
    assert events[-1]["status"] == "ok"


WIFI_QUERIES = sorted(n for n, q in READ_QUERIES["fortinet"].items() if q.read_only_account == "refused")


REFUSAL_LF = "command parse error before 'wireless-controller'\nCommand fail. Return code -61\n"
REFUSAL_CRLF = (
    "diagnose wireless-controller wlac -c sta\r\n"
    "command parse error before 'wireless-controller'\r\n"
    "Command fail. Return code -61\r\n"
    "fw-lab # "
)


def _wifi_answer(monkeypatch, query, output):
    target = _target("fortinet", query)
    params = {}
    if query == "wifi_client_detail":
        target = replace(target, read_inventory={"wireless_clients": ("00:00:5e:00:53:01",)})
        params = {"mac": "00:00:5e:00:53:01"}
    monkeypatch.setattr(
        engine, "read_from_device",
        lambda auth, platform, command: (0, FORTIOS_STATUS if command == engine._IDENTITY_COMMAND else output),
    )
    return engine.ssh_read(target, "fortinet", query, params, 0, 1000)


def test_wifi_queries_match_catalog_metadata():
    assert WIFI_QUERIES == sorted(
        ["wifi_clients", "wifi_client_detail", "wifi_access_points", "wifi_ap_detail", "wifi_ssid_mapping"]
    )
    assert tuple(WIFI_QUERIES) == tuple(sorted(inventory.FORTIOS_READ_ONLY_REFUSED_QUERIES))
    for name in WIFI_QUERIES:
        assert READ_QUERIES["fortinet"][name].requires_device_permission == "wifi read-write"


@pytest.mark.parametrize("output", [REFUSAL_LF, REFUSAL_CRLF], ids=["lf", "crlf-prompt"])
@pytest.mark.parametrize("query", WIFI_QUERIES)
def test_wifi_permission_refusal(wire, monkeypatch, query, output):
    answer = _wifi_answer(monkeypatch, query, output)
    assert answer["ok"] is False
    assert answer["error_code"] == "permission_denied"
    assert "wifi read-write" in answer["error"]
    assert "admin-bounded" in answer["error"]
    assert "enabled_queries" in answer["error"]
    assert "Return code -61" in answer["untrusted_device_output"]


@pytest.mark.parametrize("output", [
    "Unknown action 0\n",
    "command parse error before 'wireless-controller'\n",
    "Command fail. Return code -61\n",
    "command parse error before 'other'\nCommand fail. Return code -61\n",
], ids=["unknown-action", "parse-only", "fail-only", "other-token"])
def test_wifi_other_refusals_stay_device_cli_error(wire, monkeypatch, output):
    answer = _wifi_answer(monkeypatch, "wifi_clients", output)
    assert answer["ok"] is False
    assert answer["error_code"] == "device_cli_error"
    assert "untrusted_device_output" in answer


def test_wifi_signature_on_other_query_is_generic(wire, monkeypatch):
    output = "command parse error before 'wireless-controller'\nCommand fail. Return code -61\n"
    monkeypatch.setattr(engine, "read_from_device", lambda auth, platform, command: (0, FORTIOS_STATUS if command == engine._IDENTITY_COMMAND else output))
    answer = engine.ssh_read(_target("fortinet", "conserve_state"), "fortinet", "conserve_state", {}, 0, 1000)
    assert answer["error_code"] == "device_cli_error"
