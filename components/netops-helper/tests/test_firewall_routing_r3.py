"""FortiOS FIREWALL-ROUTING follow-up regressions through the engine with fake SSH."""
import json

import pytest

from conftest import FORTIOS_STATUS
from netops_helper import engine, proxy
from netops_helper.auth import TargetAuth
import test_proxy_contracts as contracts
from test_firewall_routing_fortigate_routing import SIXTY, _fake, _read, _table
from test_firewall_routing_r2 import FIXTURES, LIVE


SWITCH = json.loads((FIXTURES / "r3-local-switch.json").read_text())


@pytest.mark.parametrize("failed_sample", [1, 2, 3], ids=["counter-before", "packet-rate", "counter-after"])
def test_interface_list_keeps_link_state_when_telemetry_transport_fails(monkeypatch, failed_sample):
    stats = LIVE["60f"]
    outputs = {
        engine._IDENTITY_COMMAND: FORTIOS_STATUS,
        "diagnose netlink interface list": SIXTY["interface_list"],
        "diagnose netlink device list": stats["netlink-device"],
        "diagnose netlink interface packet-rate": stats["packet-rate"],
    }
    samples = []

    def fake_read(auth, platform, command):
        if command in {"diagnose netlink device list", "diagnose netlink interface packet-rate"}:
            samples.append(command)
            if len(samples) == failed_sample:
                raise TimeoutError("private transport details")
        return 0, outputs[command]

    monkeypatch.setattr(engine, "read_from_device", fake_read)
    monkeypatch.setattr(engine, "record", lambda event, **fields: None)
    answer = _read("interface_list", max_bytes=48_000)
    assert answer["ok"] is True
    listing = answer["interfaces"]
    assert listing["state"] == "incomplete"
    assert listing["reason"] == "traffic_sample_incomplete"
    assert "private transport details" not in json.dumps(answer)
    assert len(samples) == 3
    fortilink = next(row for row in listing["interfaces"] if row["name"] == "fortilink")
    assert fortilink["link"] == "up"
    if failed_sample == 2:
        assert fortilink["speed_bps"] is None and fortilink["rx_bytes"] == 5_715_881_028
    else:
        assert fortilink["rx_bps"] is None and fortilink["speed_bps"] == 1_000_000_000


def test_interface_list_stops_optional_reads_after_disconnect(monkeypatch):
    sent = []

    def fake_read(auth, platform, command):
        sent.append(command)
        if command == engine._IDENTITY_COMMAND:
            return 0, FORTIOS_STATUS
        if command == "diagnose netlink interface list":
            return 0, SIXTY["interface_list"]
        raise ConnectionResetError("private transport details")

    monkeypatch.setattr(engine, "read_from_device", fake_read)
    monkeypatch.setattr(engine, "record", lambda event, **fields: None)
    result = _read("interface_list", max_bytes=48_000)
    assert result["ok"] and result["interfaces"]["reason"] == "traffic_sample_incomplete"
    assert sent == [engine._IDENTITY_COMMAND, "diagnose netlink interface list",
                    engine._IDENTITY_COMMAND, "diagnose netlink device list"]


def test_interface_list_proxy_reserves_its_identity_and_telemetry_reads(tmp_path, monkeypatch):
    sent = _fake(monkeypatch, {
        "diagnose netlink interface list": SIXTY["interface_list"],
        "diagnose netlink device list": LIVE["60f"]["netlink-device"],
        "diagnose netlink interface packet-rate": LIVE["60f"]["packet-rate"],
    })
    inventory, _, _, _ = contracts._configure(proxy, tmp_path)
    section = contracts._section()
    section.update(ssh_platform="fortios", enabled_queries=["interface_list"],
                   rate_limit={"requests": 8, "window_seconds": 60})
    contracts._write(inventory, contracts._inventory(contracts._device(section, "fortios")))
    handler = proxy.Proxy()
    errors = []
    handler._emit = errors.append
    arguments = {"target": "device-a", "platform": "fortios", "query": "interface_list"}
    forwarded = handler.request(contracts._request(1, "ssh_read", arguments))
    args = json.loads(forwarded)["params"]["arguments"]
    auth = TargetAuth.decode(args["target"], args["auth_context"])
    assert engine.ssh_read(auth, args["platform"], args["query"], {}, 0, 16_000)["ok"]
    assert len(sent) == 8
    assert handler.request(contracts._request(2, "ssh_read", arguments)) is None
    assert errors[-1]["error"]["data"]["category"] == "rate_limit"


def test_fortios_local_trunk_does_not_inherit_access_vlans(monkeypatch):
    sent = _fake(monkeypatch, {
        "show system virtual-switch": SWITCH["virtual-switch"],
        "get system interface": SWITCH["switch-interfaces"],
    })
    result = _table("port_vlan", ["local_switch_vlans"])
    assert sent[-1] == "get system interface" and "show system virtual-switch" in sent
    records = {row["port"]: row for row in result["records"]}
    assert records["internal1"]["access_vlan"] == records["internal2"]["access_vlan"] == 10
    trunk = records["internal5"]
    assert (trunk["mode"], trunk["access_vlan"], trunk["native_vlan"], trunk["tagged_vlans"]) == (
        "trunk", None, None, None)
    assert result["coverage"]["complete"] is False
    assert any("trunk VLAN membership unavailable" in row["text"] for row in result["unparsed"])


@pytest.mark.parametrize("with_root", [True, False], ids=["fortinet-example", "missing-root"])
def test_fortios_active_stp_port_requires_bridge_root(monkeypatch, with_root):
    body = SWITCH["stp-active"]
    if not with_root:
        body = "\n".join(line for line in body.splitlines() if not line.startswith("root "))
    sent = _fake(monkeypatch, body)
    result = _table("stp_port", ["local_stp_ports"])
    assert sent[-1] == "get system stp list"
    assert result["coverage"]["complete"] is with_root
    if not with_root:
        assert result["status"] == "unparsed"
        assert any("port 'port1'" in row["text"] for row in result["unparsed"])
    else:
        assert result["records"] == [{"instance": "lab-bridge", "port": "port1", "role": "designated",
                                      "state": "forwarding", "cost": 2000}]
