"""Catalyst 9800 reads across MCP, proxy policy and the Helper transport boundary."""

import asyncio
import json
from pathlib import Path

import pytest

from netops import worker
from netops_helper import endpoint_worker, engine, proxy, server
from netops_helper.query_catalog.cisco import C9800_QUERIES
from test_g72_ios_xe_health import HEALTH, command, docs, lab
from test_proxy_contracts import _device, _egress, _inventory, _write

REAL = Path(__file__).parent / "fixtures/real"
FIXTURES = REAL / "c9800_g87"
PROFILE = "cisco_xe"


def output(name):
    return (FIXTURES / f"{name}.out").read_text()


@pytest.fixture
def public(tmp_path, monkeypatch):
    private = tmp_path / "helper"
    private.mkdir()
    _write(private / "vault.json", {"version": 2, "credentials": {
        "device-a-account": {"kind": "password", "login": "reader", "value": "fixture-password"},
    }}, 0o600)
    path = tmp_path / "inventory.json"
    monkeypatch.setattr(worker, "STATE", tmp_path)
    monkeypatch.setattr(proxy, "INVENTORY", path)
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    replies = {"show version": (0, output("version"))}
    calls = []

    def transport(auth, profile, command, **kwargs):
        assert profile == PROFILE
        calls.append(command)
        return replies[command]

    monkeypatch.setattr(engine, "_exec_read", transport)
    bridge = worker.HelperBridge()

    def ask(tool="ssh_read", *, enabled=None, switch=None, **args):
        section = {
            "account_role": "read-only", "ssh_platform": PROFILE, "device_types": [],
            "enabled_queries": enabled if enabled is not None else ["version", *C9800_QUERIES],
            "read_inventory": {}, "egress": {**_egress(), "tcp_ports": [22]},
            "rate_limit": {"requests": 60, "window_seconds": 60},
        }
        devices = [_device(section, PROFILE)]
        if switch is not None:
            devices.append({
                **_device({**section, **switch}, "cisco_ios"),
                "name": "access-switch", "address": "192.0.2.11",
            })
        _write(path, _inventory(*devices))
        if tool == "ssh_read":
            args["platform"] = PROFILE
        if tool == "locate_endpoint":
            args["targets"] = [device["name"] for device in devices]
        else:
            args["target"] = "device-a"
        result = asyncio.run(bridge.call(server.mcp, tool, args))
        return result.get("structuredContent") or json.loads(result["content"][0]["text"])

    return ask, replies, calls


def replay_locate(monkeypatch, replies, *, in_process=False):
    if in_process:
        def transport(auth, profile, command, **kwargs):
            return 0, replies[profile][command]

        def run(targets, endpoint, auth_context):
            return engine._locate_endpoint_run(endpoint_worker.decode(targets, auth_context), endpoint)

        monkeypatch.setattr(engine, "_exec_read", transport)
        monkeypatch.setattr(endpoint_worker, "call", run)
        return
    bootstrap = endpoint_worker.command()
    roots = bootstrap[-1].split("; from netops_helper.endpoint_worker import main; main()")[0]
    replay = f"""
from netops_helper import engine
replies = {replies!r}
engine.read_from_device = lambda auth, profile, command: (0, replies[profile][command])
engine.record = lambda *args, **kwargs: None
from netops_helper.endpoint_worker import main
main()
"""
    monkeypatch.setattr(endpoint_worker, "command", lambda: bootstrap[:-1] + [roots + "\n" + replay])


@pytest.mark.parametrize(("name", "field", "expected", "complete"), [
    ("aps", "state", "Registered", True),
    ("clients", "state", "Run", True),
    ("client_stats", "section", "Protocol Statistics", True),
    ("radio_24", "channel", "(Sensor)", True),
    ("radio_5", "channel", "161", True),
    ("ap_load", "total_slots", 3, True),
    ("wlans", "vlan_id", 137, True),
    ("ap_tags", "source", "Filter", True),
    ("policy_profiles", "status", "ENABLED", False),
    ("client_deletes", "section", "Controller deletes", True),
    ("exclusions", "remaining_seconds", 59, True),
    ("rogue_aps", "rssi", -85, False),
    ("redundancy", "communications", "Up", True),
    ("chassis_rmi", "local", True, True),
])
def test_public_catalogue_reads(public, name, field, expected, complete):
    ask, replies, _ = public
    query = f"c9800_{name}"
    replies[C9800_QUERIES[query].command] = 0, output(name)
    result = ask(query=query, max_bytes=48000)
    assert result["ok"], result
    assert result["wifi"]["records"][0][field] == expected
    assert result["wifi"]["complete"] is complete
    assert result["status"] == ("ok" if complete else "incomplete")
    if name == "client_deletes":
        assert any(row["name"] == "Wrong_PSK" and row["count"] == 0 for row in result["wifi"]["records"])


@pytest.mark.parametrize("malformed", [False, True])
def test_policy_profile_rows_preserve_optional_description(public, malformed):
    ask, replies, _ = public
    query = "c9800_policy_profiles"
    sample = output("policy_profiles").splitlines()
    sample[0] = f"Number of Policy Profiles: {3 if malformed else 2}"
    rows = ["staff    Staff  wireless    ENABLED", "guest    DISABLED"]
    if malformed:
        rows.append("broken" + " " * 20_000 + "invalid")
    replies[C9800_QUERIES[query].command] = 0, "\n".join(sample[:4] + rows) + "\n"

    result = ask(query=query, max_bytes=48_000)
    assert result["status"] == ("incomplete" if malformed else "ok")
    assert result["wifi"]["complete"] is (not malformed)
    assert result["wifi"]["records"] == [
        {"profile": "staff", "description": "Staff  wireless", "status": "ENABLED"},
        {"profile": "guest", "status": "DISABLED"},
    ]


@pytest.mark.parametrize(("query", "fixture", "field", "value", "complete"), [
    ("c9800_aps", "aps_extended", "location", "default location", True),
    ("c9800_clients", "clients_exclusions", "method", "FT-SAE", True),
    ("c9800_radio_5", "radio_5_extended", "channel", "(60)", True),
    ("c9800_ap_joins", "ap_joins", "state", "Joined", True),
    ("c9800_ap_joins", "ap_joins_not_joined", "state", "Not Joined", False),
])
def test_documented_controller_variants(public, query, fixture, field, value, complete):
    ask, replies, _ = public
    replies[C9800_QUERIES[query].command] = 0, output(fixture)
    result = ask(query=query)
    assert result["ok"] and result["wifi"]["complete"] is complete
    assert result["wifi"]["records"][0][field] == value


def test_client_resultant_vlan_and_reported_rf(public):
    ask, replies, _ = public
    dotted = output("client_detail_rf").splitlines()[0].split()[-1]
    replies[f"show wireless client mac-address {dotted} detail"] = 0, output("client_detail_rf")
    result = ask(query="c9800_client_detail", parameters={"mac": dotted})
    client, = result["wifi"]["records"]
    assert client["vlan"] == "1" and client["data_switching"] == "Local"
    assert client["rssi"] == -45 and client["key_management"] == "SAE"
    assert result["status"] == "incomplete"  # Cisco marks omitted detail sections.


def test_blank_client_listing_is_incomplete(public):
    ask, replies, _ = public
    replies["show wireless client summary"] = 0, ""
    result = ask(query="c9800_clients")
    assert result["status"] == "incomplete" and not result["complete"]


def test_ap_policy_vlan_mapping(public):
    ask, replies, _ = public
    replies["show ap name AP2802-01 tag detail"] = 0, output("ap_tag_detail")
    result = ask(query="c9800_ap_tag_detail", parameters={"ap_name": "AP2802-01"})
    assert result["wifi"]["complete"]
    assert result["wifi"]["records"][0]["bindings"][0]["vlan"] == "VLAN0210"


def test_scope_rejection_and_incomplete_count(public):
    ask, replies, calls = public
    result = ask(query="c9800_client_detail", parameters={"mac": "all"})
    assert not result.get("ok") and not calls
    result = ask(query="c9800_aps", enabled=["version"])
    assert not result.get("ok") and not calls
    command = "show wireless client summary"
    replies[command] = 0, "\n".join(output("clients").splitlines()[:-1])
    result = ask(query="c9800_clients")
    assert result["status"] == "incomplete" and not result["complete"]
    replies[command] = 0, "% Authorization failed\n"
    result = ask(query="c9800_clients")
    assert not result["ok"] and result["status"] == "permission_denied"


def test_public_wifi_triage_preserves_client_on_missing_ap(public):
    ask, replies, calls = public
    dotted = output("client_detail").splitlines()[0].split()[-1]
    mac = ":".join(dotted.replace(".", "")[i:i+2] for i in range(0, 12, 2))
    replies[f"show wireless client mac-address {dotted} detail"] = 0, output("client_detail")
    replies["show wireless stats client detail"] = 0, output("client_stats")
    result = ask("wifi_triage", mac=mac, enabled=["version", "c9800_client_detail", "c9800_client_stats"])
    assert result["ok"] and result["verdict"] == "incomplete"
    assert result["client"]["mac"] == mac and result["client"]["authentication"] == "Open System"
    assert result["controller_statistics"]
    assert {"step": "c9800_aps", "reason": "permission_denied"} in result["missing"]
    assert "show ap summary" not in calls


def test_public_ha_checks_both_versions_and_chassis(public):
    ask, replies, _ = public
    replies["show redundancy"] = 0, output("redundancy")
    replies["show chassis rmi"] = 0, output("chassis_rmi")
    result = ask("triage_health")
    assert result["ok"] and result["ha"]["state"] == "degraded"
    # The separately published version and redundancy samples report different image versions.
    assert result["identity"]["os_version"] != result["ha"]["redundancy"]["processors"][0]["version"]
    replies["show chassis rmi"] = 0, output("chassis_rmi").splitlines()[0]
    result = ask("triage_health")
    assert result["verdict"] == "incomplete" and result["ha"]["state"] == "incomplete"


@pytest.mark.parametrize("ha", [
    ("c9800_redundancy", "c9800_chassis_rmi"), ("c9800_redundancy",), ("c9800_chassis_rmi",),
])
def test_r2_health_retains_standard_checks_with_ha(public, ha):
    ask, replies, calls = public
    # Cisco's G87 version excerpt omits the uptime line required by standard triage.
    uptime = next(line for line in lab("version").splitlines() if " uptime is " in line)
    replies["show version"] = 0, output("version") + "\n" + uptime
    for query in ("cpu", "memory"):
        replies[command(query)] = 0, lab(query)
    for query in ("environment", "platform_resources", "ntp_status", "ntp_associations"):
        replies[command(query)] = 0, docs(query)
    for query in ha:
        replies[C9800_QUERIES[query].command] = 0, output(query.removeprefix("c9800_"))

    normal = ask("triage_health", enabled=list(HEALTH))
    assert normal["verdict"] == "fault_found", normal["missing"]
    assert any(item["rule"] == "environment_alarm" for item in normal["findings"])
    calls.clear()
    result = ask("triage_health", enabled=[*HEALTH, *ha])

    for field in ("cpu", "memory", "environment", "platform_resources", "ntp"):
        assert result.get(field) == normal[field], field
    assert all(item in result["findings"] for item in normal["findings"])
    assert calls == [*map(command, HEALTH), *(C9800_QUERIES[query].command for query in ha)]
    if len(ha) == 2:
        assert result["complete"] and result["verdict"] == "fault_found"
        assert result["ha"]["state"] == "degraded"
    else:
        assert not result["complete"] and result["verdict"] == result["ha"]["state"] == "incomplete"
        assert any(item["reason"] == "permission_denied" and item["step"].startswith("c9800_")
                   for item in result["missing"])


@pytest.mark.parametrize("paired", [False, True])
def test_public_locate_decodes_c9800_and_correlates_ap(public, monkeypatch, paired):
    ask, _, _ = public
    fixture = "clients_paired" if paired else "clients"
    dotted = output(fixture).splitlines()[4].split()[0]
    mac = ":".join(dotted.replace(".", "")[i:i+2] for i in range(0, 12, 2))
    replies = {
        "show version": output("version"), "show wireless client summary": output(fixture),
        f"show wireless client mac-address {dotted} detail": (
            "% Authorization failed\n" if paired else output("client_detail")
        ),
        "show ap summary": output("aps_extended" if paired else "aps"),
    }
    replay_locate(monkeypatch, {PROFILE: replies})
    result = ask("locate_endpoint", endpoint=mac)
    assert result["ok"] and result["verdict"] == "incomplete"
    assert result["wireless"]["client"]["mac"] == mac
    assert result["wireless"]["ap_port"] is None
    if paired:
        assert result["wireless"]["ap"]["name"] == "host01"
        assert result["wireless"]["ap"]["mac"] == "00:00:5e:00:53:01"
        assert any(item["table"] == "wifi_ap_backhaul" for item in result["missing"])
    else:
        assert any(item["table"] == "wifi_ap" for item in result["missing"])


@pytest.mark.parametrize("diagnostics", ["all", "restricted", "budget"])
def test_r2_locate_ap_port_with_untyped_controller(public, monkeypatch, diagnostics):
    ask, _, _ = public
    switch = REAL / "lab_endpoints_20261110/iosvl2"
    ports = REAL / "cisco_ios/iosvl2_15.2.20200924_g53"
    port = "GigabitEthernet0/3"
    # Put the paired G87 AP on the lab switch's spare access port.
    macs = (switch / "mac_table.txt").read_text().replace("0000.5e00.5301    DYNAMIC     Gi0/1",
                                                          "0000.5e00.5301    DYNAMIC     Gi0/3")
    interfaces = (switch / "interfaces.txt").read_text().replace("notconnect   1 ", "connected    10")
    replay_locate(monkeypatch, {
        PROFILE: {
            "show version": output("version"),
            "show wireless client summary": output("clients_paired"),
            "show wireless client mac-address 0000.5e00.5303 detail":
                output("client_detail").replace("AP MAC Address : 0000.5e00.5305",
                                                "AP MAC Address : 0000.5e00.5302"),
            "show ap summary": output("aps_extended"),
        },
        "cisco_ios": {
            "show version": (ports / "version.out").read_text(),
            "show mac address-table": macs,
            "show lldp neighbors detail": (switch / "lldp_neighbors.txt").read_text(),
            "show interfaces status": interfaces,
            f"show cdp neighbors {port} detail": (ports / "cdp_neighbor_interface_gi03.out").read_text(),
            f"show power inline {port} detail": (ports / "power_inline_detail_gi01.out").read_text().replace(
                "GigabitEthernet0/1", port),
            f"show interfaces {port}": (ports / "interface_details_gi03.out").read_text(),
        },
    }, in_process=diagnostics != "all")
    queries = ["version", "mac_table", "lldp_neighbors", "interfaces",
               "cdp_neighbor_interface", "power_inline_detail", "interface_details"]
    if diagnostics == "restricted":
        queries.remove("interface_details")
    result = ask("locate_endpoint", endpoint="00:00:5e:00:53:03", switch={
        "ssh_platform": "cisco_ios",
        "device_types": ["switch"],
        "egress": {**_egress(), "addresses": ["192.0.2.11"], "tcp_ports": [22]},
        "enabled_queries": queries,
        "rate_limit": {"requests": 6 if diagnostics == "budget" else 60, "window_seconds": 60},
        "read_inventory": {"interfaces": [port]},
    })
    assert result["ok"], result
    wireless = result["wireless"]
    location = wireless["ap_location"]
    edge, = [item for item in location["findings"] if item["edge"]]
    assert edge["port"] == port
    assert location["verdict"] == "located", location["missing"]
    ap_port = wireless["ap_port"]
    assert (ap_port["vantage"], ap_port["port"], ap_port["vlan_id"]) == ("access-switch", port, 10)
    if diagnostics != "all":
        assert ap_port["diagnostics"]["interface_errors"] == {
            "status": "permission_denied" if diagnostics == "restricted" else "target_read_limit",
            "complete": False,
        }
        return
    assert ap_port["diagnostics"]["cdp_neighbor"]["complete"]
    assert not ap_port["diagnostics"]["poe_port"]["complete"]  # IOSvL2 does not support PoE.
    assert ap_port["diagnostics"]["interface_errors"]["complete"]


@pytest.mark.parametrize("aligned", [True, False], ids=["aligned", "misaligned"])
def test_r2_exclusion_description_is_separate_from_reason(public, aligned):
    ask, replies, _ = public
    sample = output("exclusions")
    header = next(line for line in sample.splitlines() if line.startswith("MAC Address"))
    row = sample.splitlines()[-1]
    start = header.index("Description")
    if aligned:
        row = row[:start] + "Servis" + row[start + len("Servis"):]
    else:
        row = "0000.5e00.5312  Servis  Client Policy  failure  59"
    replies[C9800_QUERIES["c9800_exclusions"].command] = 0, sample.rsplit("\n", 2)[0] + "\n" + row + "\n"
    result = ask(query="c9800_exclusions")

    if aligned:
        assert result["status"] == "ok" and result["wifi"]["complete"]
        record, = result["wifi"]["records"]
        assert record["reason"] == "Client Policy  failure"
        assert record["description"] == "Servis"
        assert record["remaining_seconds"] == 59
    else:
        assert result["status"] == "incomplete"
        assert not result["wifi"]["complete"] and result["wifi"]["records"] == []


@pytest.mark.parametrize("failure, reason, expected_reads", [
    ("product", "identity_os_mismatch", 1),
    ("identity_transport", "disconnected", 1),
    ("client_transport", "disconnected", 2),
    ("client_budget", "target_read_limit", 1),
    ("identity_deadline", "timeout", 0),
])
def test_locate_c9800_failed_reads_do_not_claim_client_absence(monkeypatch, failure, reason, expected_reads):
    from dataclasses import replace
    from conftest import _target
    from netops_helper import locate

    commands = []

    def transport(auth, profile, command, **kwargs):
        assert profile == PROFILE
        commands.append(command)
        if (failure, command) in (("identity_transport", "show version"),
                                  ("client_transport", "show wireless client summary")):
            raise engine.core_session.SessionError("fixture private detail", code="disconnected")
        if command == "show version":
            return 0, "Malformed " + output("version").splitlines()[-1] if failure == "product" else output("version")
        raise AssertionError(command)

    monkeypatch.setattr(engine, "_exec_read", transport)
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    if failure == "identity_deadline":
        # The operation starts and enters the serialized controller read before its first budget charge expires.
        budget = locate.Budget
        times = iter((0, 0))
        monkeypatch.setattr(locate, "Budget", lambda: budget(now=lambda: next(times, locate.MAX_SECONDS)))

    auth = replace(_target(PROFILE, "version"),
                   enabled_queries=("version", "c9800_clients"),
                   locate_read_limit=1 if failure == "client_budget" else 40)
    result = engine._locate_endpoint_run([auth], "00:00:5e:00:53:03")
    assert result["verdict"] == "incomplete"
    assert any(item["vantage"] == auth.alias and item["reason"] == reason for item in result["missing"]), result
    assert result["reads"] == expected_reads == len(commands)
    assert "fixture private detail" not in str(result)


def test_locate_c9800_keeps_client_evidence_when_optional_reads_are_unenrolled(public, monkeypatch):
    ask, _, _ = public
    replies = {"show version": output("version"), "show wireless client summary": output("clients_paired")}
    replay_locate(monkeypatch, {PROFILE: replies}, in_process=True)
    result = ask("locate_endpoint", endpoint="00:00:5e:00:53:03", enabled=["version", "c9800_clients"])
    assert result["verdict"] == "incomplete"
    assert result["wireless"]["client"]["mac"] == "00:00:5e:00:53:03"
    assert result["wireless"]["ap_port"] is None and result["reads"] == 2
    assert any(item["reason"] == "permission_denied" for item in result["missing"])
