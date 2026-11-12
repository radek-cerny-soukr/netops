"""Administrator-facing failures found during the 1.0.7 live check."""
from dataclasses import replace
import re

import pytest

from conftest import _target
from netops_helper import engine


@pytest.fixture(autouse=True)
def audit(monkeypatch):
    monkeypatch.setattr(engine, "record", lambda *a, **k: None)


@pytest.mark.parametrize("tool,args", [
    ("triage_health", ()), ("triage_routing", ("192.0.2.1",)),
    ("triage_vpn", ("vpn",)), ("triage_wifi", ("aa:bb:cc:dd:ee:ff",)),
])
@pytest.mark.parametrize("error,code", [(OSError("SSH closed synthetic-secret"), "ssh_unavailable"),
                                       (TimeoutError("synthetic-secret"), "timeout")])
def test_triage_failed_identity_is_structured(monkeypatch, tool, args, error, code):
    auth = replace(_target("fortinet", "system_status"), read_inventory={"addresses": ["192.0.2.1"]})
    def failed(*a, **k):
        raise error
    monkeypatch.setattr(engine, "read_from_device", failed)
    result = getattr(engine, tool)(auth, *args)
    assert result["ok"] is False
    assert result["error_code"] == code
    assert result["failed_step"] == "system_status"
    assert result["missing"][0]["step"] == "system_status"
    assert result["vantage"]["device"] == auth.alias and result["vantage"]["packets_sent"] is False
    assert "synthetic-secret" not in str(result)


def test_health_unsupported_identity_is_structured(monkeypatch):
    monkeypatch.setattr(engine, "read_from_device", lambda *a: (0, "Version: FortiGate-80F v8.0.2,build0252,260928 (GA.F)\n"))
    result = engine.triage_health(_target("fortinet", "system_status"))
    assert result["error_code"] == "config_platform_not_supported"
    assert result["failed_step"] == "system_status"


def test_schema_without_registry_never_contacts_device(monkeypatch):
    monkeypatch.delenv("NETOPS_SCHEMA_REGISTRY", raising=False)
    monkeypatch.setattr(engine, "read_from_device", lambda *a: pytest.fail("device contacted"))
    result = engine.schema_read(_target("fortinet", "system_status"), "firewall address", "show", None, None, 0, 1000)
    assert result["ok"] is False
    assert result["error_code"] == "unsupported"
    assert result["reason"] == "schema_registry_missing"


def test_schema_continuation_without_registry_is_unsupported_not_expired(monkeypatch):
    monkeypatch.delenv("NETOPS_SCHEMA_REGISTRY", raising=False)
    monkeypatch.setattr(engine, "read_from_device", lambda *a: pytest.fail("device contacted"))
    result = engine.schema_read(_target("fortinet", "system_status"), "firewall address", "show", None, None,
                                1000, 1000, "0" * 64)
    assert result["ok"] is False
    assert result["error_code"] == "unsupported"
    assert result["reason"] == "schema_registry_missing"


@pytest.mark.parametrize("tool,args,field,hint", [
    ("wifi_triage", {}, "mac/ip/name", "exactly one"),
    ("wifi_triage", {"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.0.2.1"}, "mac/ip/name", "exactly one"),
    ("wifi_triage", {"mac": "AA:BB"}, "mac", "aa:bb:cc:dd:ee:ff"),
    ("wifi_clients", {"mac": "AA:BB"}, "mac", "aa:bb:cc:dd:ee:ff"),
    ("wifi_triage", {"ip": "invalid"}, "ip", "IPv4"),
    ("wifi_clients", {"ssid": "valid", "ap": "bad\nAP"}, "ap", "printable"),
    # ssh_read, switch_read and locate_endpoint name the field like the Wi-Fi tools (live 1.0.7 check)
    ("ssh_read", {"platform": "fortios", "query": "system_status", "max_bytes": 300}, "max_bytes", "1000 to 48000"),
    ("ssh_read", {"platform": "fortios", "query": "system_status", "offset": -1}, "offset", "next_offset"),
    ("ssh_read", {"platform": "AA:BB", "query": "system_status"}, "platform", "read_query_catalog"),
    ("ssh_read", {"platform": "fortios", "query": "AA:BB"}, "query", "read_query_catalog"),
    ("ssh_read", {"platform": "fortios", "query": "system_status", "parameters": {"a": "AA:BB\n"}}, "parameters", "printable"),
    ("ssh_read", {"platform": "fortios", "query": "system_status", "offset": 1000, "content_sha256": "AA:BB"},
     "content_sha256", "64 lower-case"),
    ("switch_read", {"table": "AA:BB"}, "table", "mac_entry"),
    ("switch_read", {"table": "vlan", "vlan_id": "AA:BB"}, "vlan_id", "1 to 4094"),
    ("switch_read", {"table": "mac_entry", "mac": "AA:BB"}, "mac", "MAC address literal"),
    ("switch_read", {"table": "route", "ip": "AA:BB"}, "ip", "IPv4 or IPv6"),
    ("switch_read", {"table": "lag", "mac": "00:00:5e:00:53:01"}, "mac", "mac filters mac_entry and neighbor_l3"),
    ("switch_read", {"table": "lag", "mac": "00:00:5e:00:53:01", "ip": "192.0.2.1"}, "mac/ip", "ip filters neighbor_l3 and route"),
])
def test_argument_errors_name_field_and_hint(tool, args, field, hint):
    from netops_helper.proxy import Proxy, ToolArgumentsError
    with pytest.raises(ToolArgumentsError) as failure:
        Proxy._validate_tool_arguments(tool, {"target": "device-a", **args})
    assert failure.value.code == -32602
    assert failure.value.data["field"] == field
    assert hint in failure.value.data["hint"]
    assert "AA:BB" not in str(failure.value.data)


DIAGNOSTIC = {"recipe": "session_list", "address": "VS_ONE", "interface": ""}


@pytest.mark.parametrize("args,accepted", [
    # live 1.0.7: session_list count=20 was refused by a shared 1-8 bound although the recipe takes 1-50
    ({**DIAGNOSTIC, "count": 20}, True), ({**DIAGNOSTIC, "count": 50}, True),
    ({**DIAGNOSTIC, "recipe": "persistence_list", "count": 50}, True),
    ({"recipe": "system_event_logs", "address": "", "interface": "", "count": 20}, True),
    ({"recipe": "waf_attack_logs", "address": "", "interface": "", "count": 20, "max_bytes": 16384}, True),
    ({"recipe": "health_check_verify", "address": "192.0.2.1", "interface": "", "count": 5,
      "health_check": "HC_ONE", "timeout": 60}, True),
    ({"recipe": "ping", "address": "192.0.2.1", "interface": "port1", "count": 8}, True),
    ({**DIAGNOSTIC, "count": 51}, False), ({**DIAGNOSTIC, "count": 0}, False),
    ({"recipe": "system_event_logs", "address": "", "interface": "", "count": 21}, False),
    ({"recipe": "ping", "address": "192.0.2.1", "interface": "port1", "count": 9}, False),
    ({"recipe": "traceroute", "address": "192.0.2.1", "interface": "port1", "count": 4}, False),
    ({"recipe": "ping", "address": "192.0.2.1", "interface": "", "count": 4}, False),
    ({"recipe": "health_check_verify", "address": "192.0.2.1", "interface": "", "count": 6,
      "health_check": "HC_ONE"}, False),
])
def test_diagnostic_count_follows_the_recipe_and_names_the_field(monkeypatch, args, accepted):
    from netops_helper import inventory as helper_inventory
    from netops_helper.proxy import Proxy, ToolArgumentsError
    monkeypatch.setattr(helper_inventory, "validate_inventory_item", lambda category, value: value)
    arguments = {"target": "device-a", **args}
    if accepted:
        assert Proxy._validate_tool_arguments("fortios_diagnostics", arguments)["count"] == args["count"]
        return
    with pytest.raises(ToolArgumentsError) as failure:
        Proxy._validate_tool_arguments("fortios_diagnostics", arguments)
    assert (failure.value.code, failure.value.data["field"]) == (-32602, "count")
    # The hint states the bound of the named recipe, never the refused value.
    assert re.fullmatch(r"count (is 3|is a whole number from 1 to (50|20|8|5|3)) for recipe " + args["recipe"],
                        failure.value.data["hint"])


@pytest.mark.parametrize("name,value,bound", [
    ("timeout", 11, "1 to 10"), ("timeout", 0, "1 to 10"), ("max_bytes", 16385, "1000 to 16384"),
    ("max_bytes", 999, "1000 to 16384"),
])
def test_diagnostic_timeout_and_size_name_the_field(name, value, bound):
    from netops_helper.proxy import Proxy, ToolArgumentsError
    with pytest.raises(ToolArgumentsError) as failure:
        Proxy._validate_tool_arguments("fortios_diagnostics", {"target": "device-a", **DIAGNOSTIC, name: value})
    assert (failure.value.code, failure.value.data["field"]) == (-32602, name)
    assert bound in failure.value.data["hint"]


def test_published_count_bounds_cover_every_recipe_and_icmp_probe():
    import asyncio
    from netops_helper import server
    tools = {tool.name: tool.parameters for tool in asyncio.run(server.mcp.list_tools())}
    count = tools["fortios_diagnostics"]["properties"]["count"]
    assert (count["minimum"], count["maximum"]) == (1, 50)
    assert "session_list and persistence_list 1-50" in count["description"]
    assert (tools["icmp_probe"]["properties"]["count"]["minimum"], tools["icmp_probe"]["properties"]["count"]["maximum"]) == (1, 8)
    timeout, size = (tools["fortios_diagnostics"]["properties"][name] for name in ("timeout", "max_bytes"))
    assert (timeout["minimum"], timeout["maximum"], size["minimum"], size["maximum"]) == (1, 60, 1000, 16384)
    assert timeout["default"] == 10
    from netops_helper.proxy import Proxy
    normalized = Proxy._validate_tool_arguments("fortios_diagnostics", {
        "target": "device-a", "recipe": "nslookup", "address": "update.fortiguard.net", "interface": "",
    })
    assert "timeout" not in normalized  # the proxy leaves omitted arguments to the published server default


@pytest.mark.parametrize("args,field,hint", [
    ({"targets": ["device-%d" % index for index in range(65)], "endpoint": "192.0.2.1"}, "targets", "1 to 64 distinct"),
    ({"targets": ["device-a", "device-a"], "endpoint": "192.0.2.1"}, "targets", "1 to 64 distinct"),
    ({"targets": ["AA:BB with space"], "endpoint": "192.0.2.1"}, "targets", "enrolled target aliases"),
    ({"targets": ["device-a"], "endpoint": "AA:BB.example"}, "endpoint", "not a host name"),
    ({"targets": ["device-a"], "endpoint": "192.0.2.1", "extra": 1}, "arguments", "documented optional fields"),
])
def test_locate_endpoint_argument_errors_name_field_and_hint(args, field, hint):
    from netops_helper.proxy import Proxy, ToolArgumentsError
    with pytest.raises(ToolArgumentsError) as failure:
        Proxy._validate_tool_arguments("locate_endpoint", args)
    assert (failure.value.code, failure.value.data["field"]) == (-32602, field)
    assert hint in failure.value.data["hint"]
    assert "AA:BB" not in str(failure.value.data)


def test_an_invalid_target_alias_names_the_target_field():
    from netops_helper.proxy import Proxy, ToolArgumentsError
    with pytest.raises(ToolArgumentsError) as failure:
        Proxy._validate_tool_arguments("switch_read", {"target": "AA:BB with space", "table": "vlan"})
    assert failure.value.data["field"] == "target"
    assert "AA:BB" not in str(failure.value.data)


def test_enrollment_warning_distinguishes_ssh_and_rest():
    from types import SimpleNamespace
    from netops_helper.inventory import section_warnings
    section = SimpleNamespace(account_role="read-only", ssh_platform="fortios", enabled_queries=("wifi_clients",))
    warning, = section_warnings("device-a", section)
    assert "SSH query" in warning
    assert "REST tool wifi_clients" in warning


def test_health_later_ssh_failure_retains_step_and_partial_facts(monkeypatch):
    from test_triage_health import outputs, COMMANDS, _enrolled
    texts = outputs()
    calls = []
    def read(auth, platform, command, **kwargs):
        query = COMMANDS[command]
        calls.append(query)
        if query == "conserve_state":
            raise OSError("synthetic-secret")
        return 0, texts[query]
    monkeypatch.setattr(engine, "read_from_device", read)
    result = engine.triage_health(_enrolled(*COMMANDS.values()))
    assert result["ok"] is True
    assert result["error_code"] == "ssh_unavailable"
    assert result["failed_step"] == "conserve_state"
    assert {"step": "conserve_state", "reason": "device_cli_error"} in result["missing"]
    assert result["chain"]["resources"]["performance"]
    assert len(calls) > 2
    assert "synthetic-secret" not in str(result)


def test_health_later_timeout_keeps_ok_and_reports_the_step(monkeypatch):
    from test_triage_health import outputs, COMMANDS, _enrolled
    texts = outputs()

    def read(auth, platform, command, **kwargs):
        if COMMANDS[command] == "ntp_status":
            raise TimeoutError("synthetic-secret")
        return 0, texts[COMMANDS[command]]
    monkeypatch.setattr(engine, "read_from_device", read)
    result = engine.triage_health(_enrolled(*COMMANDS.values()))
    assert result["ok"] is True
    assert (result["error_code"], result["failed_step"]) == ("timeout", "ntp_status")
    assert "synthetic-secret" not in str(result)


def test_wifi_docs_describe_the_current_fields():
    from pathlib import Path
    root = Path(__file__).resolve().parents[3]
    tools = (root / "components/netops-helper/docs/tools.md").read_text(encoding="utf-8")
    rest = (root / "docs/fortios-wifi-rest.md").read_text(encoding="utf-8")
    assert "device local time" not in tools
    assert "`join_time` always `null`" in tools
    assert "maximum clients" not in rest
    assert "band/type/channel" not in rest and "`phy_mode`" in rest
