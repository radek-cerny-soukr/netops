"""G96 diagnostics through the public SSH read route with device and Cisco captures."""
import asyncio
import json
from pathlib import Path

import pytest

from netops_helper import engine, proxy, server
from test_proxy_contracts import _configure, _device, _inventory, _request, _section, _write


PROFILE = "cisco_nxos"
FIXTURES = Path(__file__).parent / "fixtures"
CAPTURES = FIXTURES / "real/cisco_nxos/g96"
VERSION = (CAPTURES.parent / "nexus9300v_9.3.12/version.txt").read_text()
COMMANDS = {
    "qos_queues": "show queuing interface {interface}",
    "qos_policy": "show policy-map interface {interface}",
    "priority_flow_control": "show interface priority-flow-control",
    "tcam_utilization": "show hardware access-list resource utilization",
    "hardware_capacity": "show hardware capacity",
}


def capture(name):
    return (CAPTURES / f"{name}.out").read_text()


@pytest.fixture
def nxos(tmp_path, monkeypatch):
    for attr in ("INVENTORY", "VAULT", "EGRESS_POLICY", "RUNNER"):
        monkeypatch.setattr(proxy, attr, getattr(proxy, attr))
    inventory, _, _, _ = _configure(proxy, tmp_path)
    monkeypatch.setattr(engine, "host_key_line", lambda *args: "pinned-test-key")
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)

    def invoke(query, output, *, parameters=None, rc=0, stderr="", version=VERSION,
               enabled=True, max_bytes=16000):
        calls = []

        def execute(auth, address, known_hosts_line, credential, command, profile):
            assert profile == PROFILE
            calls.append(command)
            code, stdout, errors = (0, version, "") if command == "show version" else (rc, output, stderr)
            return engine.core_ssh.Result(rc=code, stdout=stdout.encode(), stderr=errors.encode(),
                                          said="", started_at="", finished_at="")

        monkeypatch.setattr(engine, "_exec_command", execute)
        section = dict(_section(), ssh_platform=PROFILE,
                       enabled_queries=["interface_details", query] if enabled else ["interface_details"],
                       snmp_credential=None, read_inventory={
                           "interfaces": ["Ethernet1/2", "Ethernet2/2", "Ethernet1/999", "Loopback1",
                                          "Ethernet1/2.10", "Port-channel1"],
                       })
        section["egress"]["tcp_ports"].append(22)
        _write(inventory, _inventory(_device(section, PROFILE)))
        gateway = proxy.Proxy()
        emitted = []
        gateway._emit = emitted.append
        forwarded = gateway.request(_request(96, "ssh_read", {
            "target": "device-a", "platform": PROFILE, "query": query, "parameters": parameters or {},
            "max_bytes": max_bytes,
        }))
        if forwarded is None:
            assert calls == []
            return emitted[-1]
        request = json.loads(forwarded)["params"]
        result = asyncio.run(server.mcp.call_tool(request["name"], request["arguments"]))
        outbound = {"jsonrpc": "2.0", "id": 96, "result": {
            "structuredContent": result.structured_content, "isError": result.is_error,
            "content": [item.model_dump() for item in result.content],
        }}
        body = json.loads(gateway.response(json.dumps(outbound).encode()))["result"]
        assert "structuredContent" in body, body
        reply = body["structuredContent"]
        assert calls == ["show version", COMMANDS[query].format_map(parameters or {})]
        return reply

    return invoke


def test_physical_queue_counters(nxos):
    reply = nxos("qos_queues", capture("queues_cisco"), parameters={"interface": "Ethernet2/2"})
    assert reply["status"] == "ok" and reply["complete"]
    groups = {row["qos_group"]: row for row in reply["normalized"]["records"] if "qos_group" in row}
    assert set(range(8)) <= groups.keys()
    assert groups[0]["counters"]["wred_afd_tail_drop_packets"] == {"unicast": 53390604466, "multicast": 27573307}
    assert groups[0]["bandwidth_percent"] == 100 and groups[7]["priority_level"] == 1


@pytest.mark.parametrize("fixture", ["policy", "policy_b04"])
def test_effective_policy(nxos, fixture):
    reply = nxos("qos_policy", capture(fixture), parameters={"interface": "Ethernet1/2"})
    assert reply["status"] == "ok" and reply["complete"]
    row, = reply["normalized"]["records"]
    assert (row["name"], row["policy_type"], row["direction"], row["statistics_enabled"]) == (
        "default-out-policy", "queuing", "output", True,
    )
    assert [item["rules"] for item in row["classes"]] == [
        ["priority level 1"], ["bandwidth remaining percent 0"],
        ["bandwidth remaining percent 0"], ["bandwidth remaining percent 100"],
    ]
    assert row.get("snmp_policy_index") == (301990695 if fixture == "policy" else None)


def test_cisco_pfc_preserves_available_values_and_publisher_truncation(nxos):
    reply = nxos("priority_flow_control", capture("pfc_cisco"))
    assert reply["status"] == "incomplete" and not reply["complete"]
    ports = {row["interface"]: row for row in reply["normalized"]["records"]}
    assert ports["Ethernet1/1"] == {
        "interface": "Ethernet1/1", "admin_mode": "on", "oper_mode": "on",
        "vl_bitmap": 8, "rx_pause_frames": 9638881, "tx_pause_frames": 12024,
    }
    assert ports["Ethernet1/5"]["vl_bitmap"] is None and ports["Ethernet1/5"]["oper_mode"] == "off"
    assert ports["Ethernet1/5"]["tx_pause_frames"] == 0
    assert len(ports) == 6 and reply["normalized"]["unparsed"]


def test_hardware_tcam_region_and_breakdown(nxos):
    reply = nxos("tcam_utilization", capture("tcam_cisco"))
    assert reply["status"] == "ok" and reply["complete"]
    rows = {row["resource"]: row for row in reply["normalized"]["records"]}
    assert rows["Ingress SUP"] == {"module": 1, "instance": 0, "resource": "Ingress SUP",
                                  "used": 446, "free": 10, "utilization_percent": 97.80}
    assert rows["Ingress SUP IPv6"]["used"] == 180
    assert rows["Ingress SUP IPv6"]["free"] is None
    assert rows["Ingress SUP IPv6"]["utilization_percent"] == 39.47


@pytest.mark.parametrize("query,fixture,parameters,rc,missing,count", [
    ("qos_queues", "queues_virtual", {"interface": "Ethernet1/2"}, 0, "queue_groups", 0),
    ("priority_flow_control", "pfc_virtual", {}, 244, "pfc_counters", 0),
    ("tcam_utilization", "tcam_virtual", {}, 244, "tcam_regions", 18),
    ("hardware_capacity", "capacity_virtual", {}, 0, "tcam_regions", 18),
])
def test_virtual_limitations_preserve_available_counters(nxos, query, fixture, parameters, rc, missing, count):
    reply = nxos(query, capture(fixture), parameters=parameters, rc=rc)
    assert reply["status"] == "incomplete" and not reply["complete"]
    diagnostic = reply["normalized"]
    assert missing in diagnostic["coverage"]["missing_fields"]
    assert diagnostic["coverage"]["parsed_records"] == count
    if count:
        row = next(row for row in diagnostic["records"] if row["resource"] == "Protocol CAM")
        assert (row["used"], row["free"], row["utilization_percent"]) == (0, 246, 0.0)


def test_real_device_refusal(nxos):
    reply = nxos("qos_policy", capture("invalid_port"), parameters={"interface": "Ethernet1/999"}, rc=16)
    assert not reply["ok"] and reply["status"] == "unsupported" and not reply["complete"]
    assert "records" not in reply["normalized"]


def test_permission_denial_on_stderr(nxos):
    reply = nxos("tcam_utilization", "", stderr="% Permission denied for the role", rc=16)
    assert not reply["ok"] and reply["status"] == "permission_denied" and not reply["complete"]


@pytest.mark.parametrize("interface", ["Ethernet1/7", "Loopback1", "Ethernet1/2.10", "Port-channel1", "Ethernet1/2; show version"])
def test_unenrolled_or_non_ethernet_scope(nxos, interface):
    reply = nxos("qos_queues", "", parameters={"interface": interface})
    assert reply["error"]["data"]["category"] == "policy_scope"


def test_query_must_be_enabled(nxos):
    reply = nxos("tcam_utilization", "", enabled=False)
    assert reply["error"]["data"]["category"] == "policy_scope"


def test_wrong_interface_is_incomplete(nxos):
    reply = nxos("qos_policy", capture("policy"), parameters={"interface": "Ethernet2/2"})
    assert reply["status"] == "incomplete" and not reply["complete"]
    assert reply["normalized"]["records"] == []


def test_queue_missing_groups_keeps_available_rows(nxos):
    output = capture("queues_cisco").split("|                              QOS GROUP 1", 1)[0]
    reply = nxos("qos_queues", output, parameters={"interface": "Ethernet2/2"})
    assert reply["status"] == "incomplete" and not reply["complete"]
    assert reply["normalized"]["coverage"]["missing_fields"] == ["queue_groups"]
    assert [row["qos_group"] for row in reply["normalized"]["records"]] == [0]


def test_queue_pager_and_api_page_do_not_report_complete(nxos):
    parameters = {"interface": "Ethernet2/2"}
    paged = nxos("qos_queues", capture("queues_cisco")[:900] + "\n--More--", parameters=parameters)
    assert paged["status"] == "truncated" and not paged["complete"]
    limited = nxos("qos_queues", capture("queues_cisco"), parameters=parameters, max_bytes=1000)
    assert limited["next_offset"] and not limited["complete"] and not limited["normalized"]["coverage"]["complete"]


def test_firmware_warning_allows_query(nxos):
    version = VERSION.replace("9.3(12)", "9.3(13)")
    reply = nxos("qos_policy", capture("policy"), parameters={"interface": "Ethernet1/2"}, version=version)
    assert reply["status"] == "ok" and reply["complete"]
    assert reply["firmware_support"]["status"] == "untested"
