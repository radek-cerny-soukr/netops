"""LINK-DISCOVERY operator checks over actual parser output from the read-only lab."""
from dataclasses import replace
from pathlib import Path
import json
import sys

import httpx
import pytest

from conftest import _target
from netops import cli
from netops import intent as cli_intent
from netops_admin import notify
from netops_helper import engine, inventory
from netops_helper.auth import EgressPolicy


FIXTURES = Path(__file__).parent / "fixtures"
LINK_DISCOVERY = FIXTURES / "real/link-discovery"
SERIAL = "S000SSSS00000001"
PLAN = "daily"
EXOS = {
    "lag": [{"name": "5", "active_members": ["5"]}],
    "vlan": [{"port": "3", "vlan_id": 304, "membership": "tagged"}],
    "poe": [{"port": "1", "min_w": 0, "max_w": 5}],
}
KUF = {"vlan": [{"port": "port3", "vlan_id": 100, "membership": "untagged", "managed_switch": SERIAL}]}


def replay(monkeypatch, source="exosvm", overrides=None):
    fortios = source == "fortigate-ha"
    platform = "fortinet" if fortios else "extreme_exos"
    exos = {"show sharing": (250, "lag"), "show vlan detail": (250, "vlan"),
            "show ports no-refresh": (0, "ports"), "show inline-power info ports 1": (0, "poe")}
    fortigate_ha = {f"show switch-controller managed-switch {SERIAL}": (0, "ports"),
            "show system interface": (0, "vlan-ids")}
    responses = {command: (rc, (LINK_DISCOVERY / f"{source}-{filename}.out").read_text())
                 for command, (rc, filename) in (fortigate_ha if fortios else exos).items()}
    if fortios:
        responses["get system status"] = (0, (FIXTURES / "fortios_80f_802_flow_status.txt").read_text())
        queries = ("system_status", "managed_switch_port_vlans", "interface_vlan_ids")
        read_inventory = {"managed_switches": (SERIAL,)}
    else:
        responses["show version"] = (0, (FIXTURES / "identity/extreme_exos.txt").read_text())
        queries = ("version", "lag_summary", "vlan_detail", "ports", "inline_power_port")
        read_inventory = {"interfaces": ("1",)}
    responses.update(overrides or {})
    calls = []

    def transport(auth, profile, command, **kwargs):
        assert (auth.alias, profile) == (source, platform)
        calls.append(command)
        return responses[command]

    monkeypatch.setattr(engine, "_exec_read", transport)
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    auth = replace(_target(platform, queries[0]), alias=source, enabled_queries=queries, read_inventory=read_inventory,
                   device_types=("switch",) if not fortios else ("firewall",),
                   egress=EgressPolicy(addresses=("127.0.0.1",), tcp_ports=(2222,)))

    def read(args):
        args = dict(args)
        assert args.pop("target") == source
        return engine.switch_read(auth, **args)

    return read, calls


def test_real_exos_match_and_all_three_mismatches(monkeypatch):
    read, _ = replay(monkeypatch)
    result = engine.check_intent(PLAN, [("exosvm", "extreme_exos", EXOS)], read)
    assert result["status"] == "pass", result
    assert [check["actual"] for check in result["checks"]] == [["5"], "tagged", 0]
    changed = {"lag": [{"name": "5", "active_members": ["5", "6"]}],
               "vlan": [{"port": "3", "vlan_id": 304, "membership": "untagged"}],
               "poe": [{"port": "1", "min_w": 1, "max_w": 5}]}
    result = engine.check_intent(PLAN, [("exosvm", "extreme_exos", changed)], read)
    assert result["status"] == "fail"
    assert [check["status"] for check in result["checks"]] == ["fail"] * 3


def test_real_fortiswitch_config_membership_and_read_reuse(monkeypatch):
    read, calls = replay(monkeypatch, "fortigate-ha")
    other = {**KUF["vlan"][0], "vlan_id": 4093, "membership": "untagged"}
    result = engine.check_intent(PLAN, [("fortigate-ha", "fortinet", {"vlan": [KUF["vlan"][0], other]})], read)
    assert result["status"] == "pass", result
    assert [check["actual"] for check in result["checks"]] == ["untagged", "untagged"]
    assert calls.count(f"show switch-controller managed-switch {SERIAL}") == 1
    assert calls.count("show system interface") == 1


@pytest.mark.parametrize("command,output,rc", [
    ("show sharing", (LINK_DISCOVERY / "exosvm-lag.out").read_text().split("Number of load sharing trunks:")[0], 250),
    ("show sharing", "", 0),
    ("show inline-power info ports 1", "--More--\n", 0),
    ("show inline-power info ports 1", (LINK_DISCOVERY / "exosvm-poe.out").read_text().replace("1 ", "2 ", 1), 0),
    ("show vlan detail", "Permission denied\n", 0),
    ("show vlan detail", (LINK_DISCOVERY / "exosvm-vlan.out").read_text().replace("       Tag:        *3\n", "", 1), 250),
    ("show ports no-refresh", "Permission denied\n", 0),
])
def test_read_failure_preserves_other_observations_without_claiming_a_mismatch(monkeypatch, command, output, rc):
    read, _ = replay(monkeypatch, overrides={command: (rc, output)})
    result = engine.check_intent(PLAN, [("exosvm", "extreme_exos", EXOS)], read)
    assert result["status"] == "incomplete"
    assert sorted(check["status"] for check in result["checks"]) == ["incomplete", "pass", "pass"], result
    assert notify.discord_intent("fixture-webhook", result) == "not_needed"


def test_forti_vlan_unresolved_is_incomplete(monkeypatch):
    original = (LINK_DISCOVERY / "fortigate-ha-vlan-ids.out").read_text()
    read, _ = replay(monkeypatch, "fortigate-ha", {"show system interface": (0, original.replace("fixture-vlan-003", "another-vlan"))})
    result = engine.check_intent(PLAN, [("fortigate-ha", "fortinet", KUF)], read)
    assert result["status"] == "incomplete", result


@pytest.mark.parametrize("bad", [
    {"daily": {}},
    {"daily": {"lag": [{"name": "5", "active_members": ["5", "5"]}]}},
    {"daily": {"vlan": [{"port": "1", "vlan_id": True, "membership": "tagged"}]}},
    {"daily": {"poe": [{"port": "1", "min_w": 2, "max_w": 1}]}},
    {"daily": {"poe": [{"port": "1", "min_w": 0, "max_w": float("inf")}]}},
])
def test_invalid_plan_rejected_during_inventory_validation(bad):
    with pytest.raises(inventory.InventoryError):
        inventory._checked_intent(bad)


def test_one_run_through_cli_sends_once_on_mismatch(monkeypatch, tmp_path, capsys):
    from test_proxy_contracts import _device, _inventory, _section
    read, calls = replay(monkeypatch)
    section = _section()
    section.update(ssh_platform="exos", device_types=["switch"],
                   enabled_queries=["inline_power_port"], read_inventory={"interfaces": ["1"]},
                   intent={PLAN: {"poe": [{"port": "1", "min_w": 1, "max_w": 3}]}})
    section["egress"]["tcp_ports"].append(22)
    device = _device(section, "exos")
    device["name"] = "exosvm"
    source = tmp_path / "inventory.json"
    source.write_text(json.dumps(_inventory(device)))
    token = tmp_path / "token"
    token.write_text("fixture-mcp-" + "a" * 40)
    protocol = []

    def response(request):
        assert request.headers["authorization"] == "Bearer " + token.read_text()
        incoming = json.loads(request.content)
        protocol.append(incoming["method"])
        if incoming["method"] == "notifications/initialized":
            return httpx.Response(202)
        if incoming["method"] == "initialize":
            body = {"protocolVersion": cli_intent.PROTOCOL}
        else:
            assert incoming["params"]["name"] == "switch_read"
            body = {"structuredContent": read(incoming["params"]["arguments"])}
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": incoming["id"], "result": body})

    http_client = httpx.Client
    monkeypatch.setattr(cli_intent.httpx, "Client", lambda **options: http_client(transport=httpx.MockTransport(response), **options))
    monkeypatch.setattr(cli_intent.ssl, "create_default_context", lambda *, cafile: None)
    payloads = []
    monkeypatch.setattr(notify, "_deliver", lambda data: payloads.append(data) or "sent")
    monkeypatch.setenv("NETOPS_DISCORD_WEBHOOK", "https://discord.com/api/webhooks/123/fixture-only")
    monkeypatch.setattr(sys, "argv", ["netops", "check-intent", PLAN, "--inventory", str(source), "--endpoint",
                                     "https://test.example/mcp", "--ca", "fixture-ca", "--token-file", str(token), "--notify"])
    assert cli.main() == 1
    output = capsys.readouterr().out
    result = json.loads(output)
    assert result["notification"] == "sent" and result["status"] == "fail"
    assert calls == ["show version", "show inline-power info ports 1"]
    assert protocol == ["initialize", "notifications/initialized", "tools/call"]
    assert len(payloads) == 1 and "exosvm: poe 1" in payloads[0]["json"]["content"]
    assert "fixture-only" not in output and token.read_text() not in output


@pytest.mark.parametrize('measured, status', [(None, 'incomplete'), (0.0, 'pass'), (11.0, 'fail')])
def test_ios_poe_intent_requires_measured_power(monkeypatch, measured, status):
    from test_ios_ports_router_ports import doc, transport

    output = doc('power_inline_detail')
    if measured is not None:
        # DERIVED: add an instantaneous reading using the documented label.
        output += f' Measured at the port: {measured}\n'
    command = 'show power inline GigabitEthernet0/0/0 detail'
    auth, calls = transport(monkeypatch, {command: output}, enabled=('version', 'power_inline_detail'))
    plan = {'poe': [{'port': 'Gi0/0/0', 'min_w': 0, 'max_w': 10}]}
    result = engine.check_intent(PLAN, [(auth.alias, auth.ssh_platform, plan)],
                                 lambda args: engine.switch_read(auth, **{k: v for k, v in args.items() if k != 'target'}))
    check, = result['checks']
    assert result['status'] == check['status'] == status, result
    assert check.get('actual') == measured
    if status == 'incomplete':
        assert notify.discord_intent('fixture-webhook', result) == 'not_needed'
    assert calls[-1] == command


@pytest.mark.parametrize('voice, expected, status, actual', [
    ('20 (voice)', 'tagged', 'pass', 'tagged'),
    ('20 (voice)', 'absent', 'fail', 'tagged'),
    ('none', 'absent', 'pass', 'absent'),
    ('missing', 'absent', 'incomplete', None),
    ('denied', 'absent', 'incomplete', None),
    ('paged', 'absent', 'incomplete', None),
    ('unavailable', 'absent', 'incomplete', None),
    ('dscp', 'absent', 'incomplete', None),
])
def test_ios_access_voice_vlan_intent(monkeypatch, voice, expected, status, actual):
    from test_ios_ports_router_ports import transport

    real = FIXTURES / 'real/cisco_ios/iosvl2_15.2.20200924'
    # DERIVED: use the captured access port and IOS-SWITCHPORTS voice capture with data VLAN 10 and voice VLAN 20.
    status_text = (real / 'interfaces.txt').read_text().replace('connected    99', 'connected    10', 1)
    ios_switchports = FIXTURES.parents[2] / 'netops-admin/tests/fixtures/ios_ios_switchports/switchport-voice.txt'
    switchport = ios_switchports.read_text().replace('Gi1/0', 'Gi0/0').replace('3780 (netops-ios-switchports)', '10 (data)')
    voice_line = 'Voice VLAN: 3781 (netops-ios-switchports-voice)'
    switchport = switchport.replace(voice_line, '' if voice == 'missing' else f'Voice VLAN: {voice}')
    if voice == 'denied':
        switchport = '% Authorization failed.\n'
    if voice == 'paged':
        switchport = switchport.replace('Voice VLAN: paged', 'Voice VLAN: none') + '\n--More--'
    command = 'show interfaces GigabitEthernet0/0 switchport'
    outputs = {'show interfaces trunk': (real / 'interfaces_trunk.txt').read_text(),
               'show interfaces status': status_text, command: switchport}
    queries = ('version', 'interfaces_trunk', 'interfaces')
    if voice != 'unavailable':
        queries += ('interface_switchport',)
    auth, calls = transport(monkeypatch, outputs, enabled=queries, inventory={'interfaces': ('Gi0/0',)})
    plan = {'vlan': [{'port': 'Gi0/0', 'vlan_id': 20, 'membership': expected}]}
    result = engine.check_intent(PLAN, [(auth.alias, auth.ssh_platform, plan)],
                                 lambda args: engine.switch_read(auth, **{k: v for k, v in args.items() if k != 'target'}))
    check, = result['checks']
    assert result['status'] == check['status'] == status, result
    assert check.get('actual') == actual
    assert (command in calls) == (voice != 'unavailable')
