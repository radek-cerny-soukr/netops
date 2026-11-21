"""G79 through Admin's real preview/apply, timer, readback and return paths."""

from dataclasses import replace
from pathlib import Path
import re

import pytest

from fake_ios import FakeIos
from test_ios import make_runtime, request, steps
from test_mcp_server import call

from netops_admin import engine, exec_ios, execute, ios_cycle, mcp_server
from netops_admin.access import AccessError

TARGET = "lab-ios"
PORT = "Ethernet2/3"
CATALYST_PORT = "GigabitEthernet1/0/4"
SHOW_PORT = "show interfaces %s status"
SHOW_SWITCHPORT = "show interfaces %s switchport"
SHOW_POE = "show power inline %s"
FIXTURES = Path(__file__).parent / "fixtures" / "ios_g79"


def fixture(name):
    return (FIXTURES / (name + ".txt")).read_text()


class Switch(FakeIos):
    def __init__(self, *, link=True, poe=False):
        super().__init__("iolxe-l2")
        self.port = CATALYST_PORT if poe else PORT
        self.has_poe = poe
        self.active = link
        self.link_returns = True
        self.power_returns = True
        self.was_disabled = False
        self.was_unpowered = False
        if poe:
            self.lines[self.lines.index("interface " + PORT)] = "interface " + self.port
        self.saved = list(self.lines)

    def _line(self, line, mode):
        if mode[0] == "interface:" + self.port:
            if line == "shutdown":
                self.was_disabled = True
            if self.has_poe and line.startswith("power inline "):
                if line == "power inline never":
                    self.was_unpowered = True
                self._set(self.port, re.compile(r"^power inline (?:auto|never|static)(?: max [0-9]+)?$"),
                          line if line != "power inline auto" else None)
                return ""
        return super()._line(line, mode)

    def _interface_query(self, command):
        if command == SHOW_SWITCHPORT % self.port:
            text = fixture("iosxe-l2-dynamic-access")
            text = re.sub(r"^Name: Et2/3$", "Name: " + self.port.replace("GigabitEthernet", "Gi", 1),
                          text, flags=re.MULTILINE) if self.has_poe else text
            if "switchport mode access" in self.interface(self.port):
                text = text.replace("Administrative Mode: dynamic auto", "Administrative Mode: static access")
            return text
        if command == SHOW_PORT % self.port:
            if "shutdown" in self.interface(self.port):
                text = fixture("iosxe-l2-disabled").replace("Et0/1", "Et2/3")
            else:
                text = fixture("iosxe-l2-connected")
                if not self.active or self.was_disabled and not self.link_returns:
                    text = text.replace("connected ", "notconnect")
            return text.replace("Et2/3 ", "Gi1/0/4", 1) if self.has_poe else text
        if command == SHOW_POE % self.port:
            if not self.has_poe:
                return fixture("iosxe-l2-poe-refused")
            configured = next((line for line in self.interface(self.port)
                               if line.startswith("power inline ") and not line.startswith("power inline port ")),
                              "power inline auto")
            mode = configured.split()[2]
            kind = {"auto": "doc-auto-on", "never": "derived-never-off", "static": "derived-static-on"}[mode]
            text = fixture("show-power-inline-Gi1-0-4__" + kind)
            if mode != "never" and self.was_unpowered and not self.power_returns:
                text = text.replace(" on ", " off")
            return text
        return super()._interface_query(command)


def bounce(impact=None, port=PORT, request_id="g79-bounce-0001"):
    return ios_cycle.request(ios_cycle.BOUNCE, TARGET, port, "Restart the lab link",
                             "Cycle the selected interface", request_id, impact)


def cycle(port=CATALYST_PORT, impact=CATALYST_PORT):
    return ios_cycle.request(ios_cycle.POE, TARGET, port, "Restart power", "Restart the powered endpoint",
                             "g79-power-0001", impact)


def setting(device, changes, impact=None):
    return request(device, table="inline-power", changes=changes, endpoint_impact=impact)


def preview(runtime, wanted):
    if wanted.table in ios_cycle.TABLES.values():
        return ios_cycle.preview(runtime, TARGET, wanted.table, wanted)
    return execute.preview(runtime, TARGET, wanted)


def apply(runtime, wanted, plan):
    assert plan["result"] == "ready", plan
    if wanted.table in ios_cycle.TABLES.values():
        return ios_cycle.apply(runtime, TARGET, wanted.table, wanted, expected_plan_sha256=plan["plan_sha256"])
    return execute.apply(runtime, TARGET, wanted, expected_plan_sha256=plan["plan_sha256"])


def test_mcp_bounce_binds_active_free_port_and_restores_configuration(tmp_path, monkeypatch):
    device = Switch()
    initial = device.snapshot()
    rt = make_runtime(tmp_path, device, seconds=300)
    monkeypatch.setattr(mcp_server, "configured_runtime", lambda: rt)
    args = dict(device=TARGET, table="port-bounce", op="update", key=PORT, changes={"admin-state": "disabled"},
                reason="Test a lab port", user_request="Restart the port", request_id="g79-mcp-0001")
    refused = call("admin_preview", args)
    assert refused["reason_codes"] == ["endpoint_impact_required"]
    approved = dict(args, endpoint_impact=PORT)
    plan = call("admin_preview", approved)
    assert plan["result"] == "ready", plan
    assert plan["cycle_state"] == {"link": "connected", "lldp": "False", "learned_macs": "0"}
    assert plan["cycle_commands"][2] == "shutdown" and plan["cycle_commands"][-2] == "no shutdown"
    assert call("admin_apply", approved)["reason_codes"] == ["plan_changed"]
    assert not device.applied_blocks
    record = call("admin_apply", dict(approved, expected_plan_sha256=plan["plan_sha256"]))
    assert record["result"] == "confirmed", record
    assert record["cycle"] == {"before": {"status": "connected"}, "off": {"status": "disabled"},
                               "after": {"status": "connected"}}
    assert record["steps"].index("off_held") < record["steps"].index("port_enable_applied")
    assert device.snapshot() == initial and device.timer is None and device.saves == 0


def test_link_that_stays_down_is_not_confirmed(tmp_path):
    device = Switch()
    device.link_returns = False
    rt = make_runtime(tmp_path, device, seconds=300)
    wanted = bounce(PORT)
    record = apply(rt, wanted, preview(rt, wanted))
    assert record["result"] == "reverted", record
    assert record["reason"] == ios_cycle.LINK_NOT_BACK and record["cycle"]["after"] == {"status": "notconnect"}
    assert device.lines == device.saved and device.timer is None and device.saves == 0


def test_management_vlan_is_protected_on_operational_trunk(tmp_path):
    device = Switch()
    text = fixture("iosxe-l2-dynamic-access").replace("Operational Mode: static access", "Operational Mode: trunk")
    device.query_override[SHOW_SWITCHPORT % PORT] = text
    rt = make_runtime(tmp_path, device, seconds=300)
    assert preview(rt, bounce(PORT))["reason_codes"] == ["port_management_vlan"]
    assert not device.applied_blocks


def test_inventory_protected_interface_applies_to_bounce(tmp_path):
    device = Switch()
    rt = make_runtime(tmp_path, device, seconds=300)
    rt.config.devices[TARGET] = replace(rt.config.devices[TARGET], protected={"interface": [PORT]})
    assert preview(rt, bounce(PORT))["reason_codes"] == ["port_protected"]
    assert not device.applied_blocks


@pytest.mark.parametrize("reply", ["", "Port", "--More--"])
def test_bounce_refuses_incomplete_status(tmp_path, reply):
    device = Switch()
    device.check_override = {SHOW_PORT % PORT: reply}
    rt = make_runtime(tmp_path, device, seconds=300)
    assert preview(rt, bounce(PORT))["reason_codes"] == ["port_usage_unreadable"]
    assert not device.applied_blocks


def test_preflight_reports_read_timeout_separately(tmp_path):
    class ExpiredRead(Switch):
        def _interface_query(self, command):
            if command == SHOW_PORT % self.port:
                raise AccessError("ssh to switch did not finish within 10.0 seconds")
            return super()._interface_query(command)

    rt = make_runtime(tmp_path, ExpiredRead(), seconds=300)
    assert preview(rt, bounce(PORT))["reason_codes"] == ["ios_port_read_timeout"]


def test_router_port_has_no_switchport_or_poe(tmp_path):
    class Router(FakeIos):
        def _interface_query(self, command):
            if command == SHOW_SWITCHPORT % self.port:
                return fixture("iosxe-routed-switchport-refused")
            if command == SHOW_POE % self.port:
                return fixture("iosxe-routed-poe-refused")
            return super()._interface_query(command)

    device = Router("iolxe")
    device.port = "Ethernet0/3"
    device._set(device.port, re.compile(r"^shutdown$"))
    device.saved = list(device.lines)
    rt = make_runtime(tmp_path, device, seconds=300)
    assert preview(rt, bounce(device.port, device.port))["reason_codes"] == ["port_routed"]
    assert preview(rt, cycle(device.port, device.port))["reason_codes"] == ["poe_not_capable"]
    assert preview(rt, setting(device, {"mode": "never"}, device.port))["reason_codes"] == ["poe_not_capable"]
    assert not device.applied_blocks


def test_disabled_switch_port_refused(tmp_path):
    device = Switch()
    device.check_override = {SHOW_PORT % "Ethernet0/1": fixture("iosxe-l2-disabled")}
    rt = make_runtime(tmp_path, device, seconds=300)
    assert preview(rt, bounce(port="Ethernet0/1"))["reason_codes"] == ["port_disabled"]
    assert not device.applied_blocks


@pytest.mark.parametrize("table", ["inline-power", "poe-cycle"])
def test_preview_refuses_switch_without_poe(tmp_path, table):
    device = Switch()
    rt = make_runtime(tmp_path, device, seconds=300)
    wanted = cycle(PORT, PORT) if table == "poe-cycle" else setting(device, {"mode": "never"}, PORT)
    assert preview(rt, wanted)["reason_codes"] == ["poe_not_capable"]
    assert not device.applied_blocks


@pytest.mark.parametrize("changes, before, expected", [
    ({"mode": "never"}, None, "power inline never"),
    ({"mode": "static", "max-milliwatts": "15400"}, None, "power inline static max 15400"),
    ({"mode": "auto", "max-milliwatts": None}, "power inline static max 15400", "power inline auto"),
])
def test_permanent_poe_requires_hash_and_undo_restores_exact_setting(tmp_path, changes, before, expected):
    device = Switch(poe=True)
    device._set(device.port, re.compile(r"^power inline "), before)
    device.saved = list(device.lines)
    initial = device.snapshot()
    rt = make_runtime(tmp_path, device, seconds=300)
    wanted = setting(device, changes, device.port)
    plan = preview(rt, wanted)
    assert plan["result"] == "ready", plan
    assert plan["firmware_support"]["status"] == "untested"
    assert plan["commands"][-2] == expected and not device.applied_blocks
    with pytest.raises(execute.Rejected) as exc:
        execute.apply(rt, TARGET, wanted)
    assert exc.value.reason_codes == ["plan_changed"] and not device.applied_blocks
    result = apply(rt, wanted, plan)
    assert result["result"] == "confirmed", (result.get("reason"), steps(result))
    assert SHOW_POE % device.port in device.check_queries
    undo = execute.preview_undo(rt, result["change_id"], "Restore setting", issue=True)
    assert undo["result"] == "ready", undo
    returned = execute.undo(rt, result["change_id"], "Restore setting", expected_plan_sha256=undo["plan_sha256"])
    assert returned["result"] == "confirmed", returned.get("reason")
    assert device.snapshot() == initial and device.lines == device.saved and device.timer is None


@pytest.mark.parametrize("power_returns", [True, False])
def test_poe_cycle_restores_previous_limit_and_checks_power_return(tmp_path, power_returns):
    device = Switch(poe=True)
    device.power_returns = power_returns
    device._set(device.port, re.compile(r"^power inline "), "power inline static max 15400")
    device.saved = list(device.lines)
    initial = device.snapshot()
    rt = make_runtime(tmp_path, device, seconds=300)
    wanted = cycle()
    plan = preview(rt, wanted)
    assert not device.applied_blocks
    assert plan["firmware_support"]["status"] == "untested"
    assert plan["cycle_commands"][-2] == "power inline static max 15400"
    record = apply(rt, wanted, plan)
    assert record["result"] == ("confirmed" if power_returns else "reverted"), record
    assert record["cycle"]["off"]["oper"] == "off"
    assert record["cycle"]["after"]["oper"] == ("on" if power_returns else "off")
    assert device.snapshot() == initial and device.timer is None and device.saves == 0
    with pytest.raises(execute.Rejected) as exc:
        execute.undo(rt, record["change_id"], "Verify undo contract")
    assert exc.value.reason_codes == ["undo_not_applicable"]


def test_recovery_rechecks_link_after_interrupted_confirmation(tmp_path, monkeypatch):
    device = Switch()
    rt = make_runtime(tmp_path, device, seconds=300)
    wanted = bounce(PORT)
    plan = preview(rt, wanted)
    finish = execute._finish

    class Interrupted(BaseException):
        pass

    def disconnect(*args, **kwargs):
        raise Interrupted

    monkeypatch.setattr(execute, "_finish", disconnect)
    with pytest.raises(Interrupted):
        apply(rt, wanted, plan)
    monkeypatch.setattr(execute, "_finish", finish)
    assert device.timer is None
    device.link_returns = False
    [record] = execute.recover(rt, TARGET)
    assert record["result"] == "reverted" and record["reason"] == ios_cycle.LINK_NOT_BACK
    assert device.lines == device.saved and device.saves == 0


@pytest.mark.parametrize("inventory_field", ["protected", "audit_policy"])
@pytest.mark.parametrize("action", ["bounce", "poe-cycle", "inline-power"])
def test_inventory_management_vlan_on_operational_trunk_refuses_even_with_impact(tmp_path, inventory_field, action):
    device = Switch(poe=action != "bounce")
    port = device.port
    answer = device._interface_query(SHOW_SWITCHPORT % port)
    answer = answer.replace("Operational Mode: static access", "Operational Mode: trunk")
    answer = answer.replace("Trunking VLANs Enabled: ALL", "Trunking VLANs Enabled: 777")
    device.query_override[SHOW_SWITCHPORT % port] = answer
    rt = make_runtime(tmp_path, device, seconds=300)
    field = "vlan" if inventory_field == "protected" else "management_vlans"
    target = replace(rt.config.devices[TARGET], **{inventory_field: {field: ["777"]}})
    wanted = {"bounce": bounce(port, port), "poe-cycle": cycle(port, port),
              "inline-power": setting(device, {"mode": "never"}, port)}[action]
    snapshot = device.snapshot()
    planned = engine.build_plan("iosxe", snapshot.encode(), wanted, firmware=device.firmware)
    with pytest.raises(execute.Rejected) as refusal:
        exec_ios.plan_prechecks(device, target, planned, snapshot)
    assert refusal.value.reason_codes == ["port_management_vlan"]
    assert not device.applied_blocks
