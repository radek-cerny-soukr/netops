"""EOS-DHCP Admin transactions over cEOSLab 4.36.1F operational fixtures."""
import json
import re
from pathlib import Path

import pytest

from fake_eos import FIRMWARE, FakeEos
from test_eos import make_runtime, request, steps
from test_eos_eos_access_control import raw as acl_fixture

from netops_admin import eos_dhcp as dhcp, execute
from netops_admin.access import AccessError
from netops_admin.engine import build_plan, verify

FIXTURES = Path(__file__).parent / "fixtures" / "eos_eos_dhcp"
INTERFACE = "Vlan3950"
TARGET = f"{INTERFACE}:192.0.2.2"
SUBNET = "192.0.2.0/24"
POOL = {"range": "192.0.2.100 192.0.2.150", "default-gateway": "192.0.2.1",
        "lease-minutes": 90, "reservations": "0000.5e00.5301=192.0.2.35"}


def raw(name):
    return (FIXTURES / name).read_text(encoding="utf-8")


class DhcpLab(FakeEos):
    def __init__(self, *, parent=False, target=False):
        super().__init__()
        self.route_interface = "Management0"
        self.read_failure = None
        self.lines[self.lines.index("end"):self.lines.index("end")] = [
            "vlan 3950", "!", *raw("relay-config.txt").splitlines()[:3 if target else 2], "!",
        ]
        if parent:
            self.lines.insert(self.lines.index("end"), "dhcp server")
        self.saved = list(self.lines)

    def query(self, command):
        if re.fullmatch(r"show ip route vrf \S+ 192\.0\.2\.36 \| json", command):
            vrf = command.split()[4]
            route = json.loads(acl_fixture("management-route", "json"))["vrfs"]["default"]
            route["routes"]["192.0.2.0/24"]["vias"][0]["interface"] = self.route_interface
            return json.dumps({"vrfs": {vrf: route}})
        return super().query(command)

    def query_status(self, command):
        if command == dhcp.SERVER_SHOW and self.read_failure == "unsupported":
            return 1, raw("server-invalid-exec.txt")
        return super().query_status(command)

    def check_query(self, command):
        self._fire()
        if command not in (dhcp.RELAY_SHOW, dhcp.SERVER_SHOW):
            return super().check_query(command)
        self.check_queries.append(command)
        if self.read_failure == "timeout":
            raise AccessError("query timed out")
        if self.read_failure == "unsupported":
            return raw("server-invalid-exec.txt")
        if self.read_failure == "cut":
            return raw("server-set.json")[:200]
        if command == dhcp.RELAY_SHOW:
            return raw("relay-set.json" if "ip helper-address 192.0.2.2" in self.interface(INTERFACE)
                       else "single-relay-empty.json")
        if f"   subnet {SUBNET}" not in self.lines:
            return raw("single-server-empty.json")
        if "            ipv4-address 192.0.2.35" in self.lines:
            return raw("server-set.json")
        if "      range 192.0.2.100 192.0.2.150" in self.lines:
            return raw("server-no-options.json")
        return raw("server-empty-pool.json")

    def _line(self, line, mode):
        if mode[0] == f"interface:{INTERFACE}" and re.fullmatch(r"(no )?ip helper-address 192\.0\.2\.2", line):
            pattern = re.compile(r"^ip helper-address 192\.0\.2\.2$")
            self._set(INTERFACE, pattern, None if line.startswith("no ") else line)
            return ""
        if line == "dhcp server":
            if line not in self.lines:
                self.lines.insert(self.lines.index("end"), line)
            mode[0] = "dhcp"
            return ""
        if line == "no dhcp server":
            start, end = self._block("dhcp server")
            del self.lines[start:end]
            return ""
        if mode[0] == "dhcp" and line == f"subnet {SUBNET}":
            if "   " + line not in self.lines:
                self.lines.insert(self.lines.index("dhcp server") + 1, "   " + line)
            mode[0] = "subnet"
            return ""
        if mode[0] == "dhcp" and line == f"no subnet {SUBNET}":
            index = self.lines.index(f"   subnet {SUBNET}")
            while index + 1 < len(self.lines) and self.lines[index + 1].startswith("      "):
                del self.lines[index + 1]
            del self.lines[index]
            return ""
        if mode[0] in ("range", "reservations", "reservation") and line == "exit":
            mode[0] = "reservations" if mode[0] == "reservation" else "subnet"
            return ""
        if mode[0] == "subnet" and (line.startswith(("range ", "default-gateway ", "lease time "))
                                    or line == "reservations"):
            index = self.lines.index(f"   subnet {SUBNET}") + 1
            self.lines.insert(index, "      " + line)
            if line.startswith("range"):
                mode[0] = "range"
            elif line == "reservations":
                mode[0] = "reservations"
            return ""
        if mode[0] == "reservations" and line == "mac-address 00:00:5e:00:53:01":
            index = self.lines.index("      reservations") + 1
            self.lines.insert(index, "         mac-address 0000.5e00.5301")
            mode[0] = "reservation"
            return ""
        if mode[0] == "reservation" and line == "ipv4-address 192.0.2.35":
            index = self.lines.index("         mac-address 0000.5e00.5301") + 1
            self.lines.insert(index, "            " + line)
            return ""
        return super()._line(line, mode)


def change(table, key, *, op="create", changes=None, impact=False):
    return request(table=table, key=key, op=op, changes=changes or {},
                   request_id=f"eos-dhcp-{table}-{op}", **({"endpoint_impact": key} if impact else {}))


@pytest.mark.parametrize("table,key,changes", [(dhcp.RELAY, TARGET, {}), (dhcp.POOL, SUBNET, POOL)])
def test_mcp_dhcp_apply_requires_approved_hash(tmp_path, monkeypatch, table, key, changes):
    from netops_admin import mcp_server

    device = DhcpLab()
    runtime = make_runtime(tmp_path, device)
    monkeypatch.setattr(mcp_server, "configured_runtime", lambda: runtime)
    result = mcp_server.admin_apply(
        "lab-ceos", table, "create", key, changes, "Verify approval requirement",
        "Set up test DHCP", "dhcp-without-approved-hash",
        **({"endpoint_impact": key} if table == dhcp.POOL else {}),
    )
    assert result["result"] == "rejected" and result["reason_codes"] == ["plan_changed"], result
    assert not device.applied_blocks


def test_new_pool_on_existing_svi_needs_impact_and_warns_about_external_dhcp(tmp_path):
    device = DhcpLab(parent=True)
    runtime = make_runtime(tmp_path, device)
    preview = execute.preview(runtime, "lab-ceos", change(dhcp.POOL, SUBNET, changes=POOL))
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["endpoint_impact_required"], preview
    preview = execute.preview(runtime, "lab-ceos", change(dhcp.POOL, SUBNET, changes=POOL, impact=True))
    assert preview["result"] == "ready", preview
    assert any("external DHCP server" in item for item in preview["prechecks"]), preview
    assert not device.applied_blocks


@pytest.mark.parametrize("table,key,changes,parent", [
    (dhcp.RELAY, TARGET, {}, False),
    (dhcp.POOL, SUBNET, POOL, False),
    (dhcp.POOL, SUBNET, POOL, True),
    (dhcp.POOL, SUBNET, {}, True),
])
def test_preview_apply_readback_and_exact_undo(tmp_path, table, key, changes, parent):
    device = DhcpLab(parent=parent)
    baseline = list(device.lines)
    runtime = make_runtime(tmp_path, device)
    req = change(table, key, changes=changes, impact=table == dhcp.POOL)
    preview = execute.preview(runtime, "lab-ceos", req)
    assert preview["result"] == "ready", preview
    assert device.lines == baseline and not device.applied_blocks
    applied = execute.apply(runtime, "lab-ceos", req, expected_plan_sha256=preview["plan_sha256"])
    assert applied["result"] == "confirmed", applied
    assert "check_identity_passed" in steps(applied)
    assert device.lines == device.saved != baseline
    undo = execute.preview_undo(runtime, applied["change_id"], "Restore the test configuration", issue=True)
    assert undo["result"] == "ready", undo
    if table == dhcp.POOL:
        assert ("no dhcp server" in undo["commands"]) is not parent
    result = execute.undo(runtime, applied["change_id"], "Restore the test configuration",
                          expected_plan_sha256=undo["plan_sha256"])
    assert result["result"] == "confirmed", result
    assert device.lines == device.saved == baseline
    assert not device.timer and not device.sessions
    expected_query = dhcp.SERVER_SHOW if table == dhcp.POOL else dhcp.RELAY_SHOW
    assert expected_query in device.check_queries
    assert all("running-config" not in line for line in device.check_queries)


@pytest.mark.parametrize("failure,code", [
    ("cut", "eos_dhcp_readback_unreadable"),
    ("timeout", "eos_dhcp_read_timeout"),
    ("unsupported", "eos_dhcp_unsupported"),
])
def test_unavailable_operational_read_prevents_writes(tmp_path, failure, code):
    device = DhcpLab()
    device.read_failure = failure
    runtime = make_runtime(tmp_path, device)
    preview = execute.preview(runtime, "lab-ceos", change(dhcp.POOL, SUBNET, changes=POOL, impact=True))
    assert preview["result"] == "rejected" and preview["reason_codes"] == [code]
    assert not device.applied_blocks


def test_occupied_and_management_svis_refuse_before_any_write(tmp_path):
    device = DhcpLab(target=True)
    runtime = make_runtime(tmp_path, device)
    for req, reason in [
        (change(dhcp.POOL, SUBNET, changes=POOL, impact=True), "eos_dhcp_conflict"),
        (change(dhcp.RELAY, TARGET, op="delete"), "endpoint_impact_required"),
    ]:
        preview = execute.preview(runtime, "lab-ceos", req)
        assert preview["result"] == "rejected" and preview["reason_codes"] == [reason]
    device.route_interface = INTERFACE
    preview = execute.preview(runtime, "lab-ceos", change(dhcp.RELAY, TARGET, op="delete", impact=True))
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["port_management_interface"]
    assert not device.applied_blocks


def test_adjacent_commands_and_empty_parent_are_preserved_by_prediction():
    text = DhcpLab(parent=True).snapshot().replace("dhcp server\n", raw("server-config.txt"))
    scope = text.replace("dhcp server\n", "dhcp server\n   subnet 198.51.100.0/24\n")
    req = change(dhcp.POOL, SUBNET, op="delete", impact=True)
    plan = build_plan("eos", scope.encode(), req, firmware=FIRMWARE)
    assert plan["commands"] == ["configure terminal", "dhcp server", f"no subnet {SUBNET}", "end"]
    assert verify(plan, scope.encode(), expect="before")["result"] == "match"
    without = scope.replace(raw("server-config.txt").removeprefix("dhcp server\n"), "")
    assert verify(plan, without.encode())["result"] == "match"
    assert verify(plan, without.replace("   subnet 198.51.100.0/24\n", "").encode())["result"] == "mismatch"
    single = build_plan("eos", text.encode(), req, firmware=FIRMWARE)
    parentless = text.replace(raw("server-config.txt"), "")
    result = verify(single, parentless.encode())
    assert result["result"] == "mismatch" and result["rest_matches"] and not result["object_matches"]


def test_undo_refuses_to_delete_new_configuration_under_a_created_parent(tmp_path):
    device = DhcpLab()
    runtime = make_runtime(tmp_path, device)
    req = change(dhcp.POOL, SUBNET, changes=POOL, impact=True)
    preview = execute.preview(runtime, "lab-ceos", req)
    applied = execute.apply(runtime, "lab-ceos", req, expected_plan_sha256=preview["plan_sha256"])
    device.lines.insert(device.lines.index("dhcp server") + 1, "   dns server ipv4 192.0.2.53")
    device.saved = list(device.lines)
    preview = execute.preview_undo(runtime, applied["change_id"], "Preserve someone else's settings", issue=True)
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["eos_dhcp_conflict"]


def test_untested_firmware_keeps_the_firmware_warning():
    firmware = "4.36.2F"
    text = DhcpLab().snapshot().replace(FIRMWARE, firmware)
    plan = build_plan("eos", text.encode(), change(dhcp.RELAY, TARGET), firmware=firmware)
    assert plan["firmware_support"]["status"] == "untested"


def test_relay_named_destination_vrf_uses_scoped_inverse_and_operational_vrf():
    text = DhcpLab().snapshot().replace("vlan 3950\n", "vrf instance client-service\n!\nvlan 3950\n")
    req = change(dhcp.RELAY, TARGET, changes={"vrf": "client-service"})
    plan = build_plan("eos", text.encode(), req, firmware=FIRMWARE)
    assert plan["commands"][-2] == "ip helper-address 192.0.2.2 vrf client-service"
    assert plan["inverse"][-2] == "no ip helper-address 192.0.2.2"
    # The lab has only the default VRF. Change the measured helper's destination
    # VRF name to exercise the operator syntax documented by Arista.
    observed = raw("relay-set.json").replace('"vrf": "default"', '"vrf": "client-service"')
    assert dhcp.operational_relay(observed, TARGET) == plan["predicted"]["after"]
