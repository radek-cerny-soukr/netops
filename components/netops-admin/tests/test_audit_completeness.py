from __future__ import annotations

from dataclasses import replace

import pytest
from enrollment_helpers import certify
from fake_020 import ExosMembership
from fake_exos import FakeExos
from fake_fortios import FakeFortiOS
from test_execute import make_runtime, request, steps
from test_execute_exos import make_runtime as make_exos_runtime
from test_execute_exos import request as exos_request

from netops_admin import execute
from netops_admin.errors import Rejected

UPM = "#\n# Module upm configuration."
ALL_PORTS = ('create vlan "v10"', "configure vlan v10 tag 100", "configure vlan v10 add ports all tagged")
SLOT_RANGE = ('create vlan "v10"', "configure vlan v10 tag 100", "configure vlan v10 add ports 1:1-2:4 tagged")
NO_MODE = ('create vlan "v10"', "configure vlan v10 tag 100", "configure vlan v10 add ports 5")
ROUTER_PORTS = "configure vr VR-Default add ports 1-16"
MEMBERSHIP_REQUESTS = [
    {"table": "ports", "op": "update", "key": "5", "changes": {"display-string": "desk"}},
    {"table": "vlan-membership", "op": "update", "key": "5", "changes": {"tagged": ["spare"]}},
]


class ShapedExos(FakeExos):
    def __init__(self, extra=(), tail=""):
        super().__init__()
        self.extra, self.tail, self.open_profile = list(extra), tail, False

    def snapshot(self):
        text = super().snapshot()
        if self.extra:
            text = text.replace(UPM, "\n".join(self.extra) + "\n" + UPM, 1)
        if self.open_profile and self.profiles:
            assert text.count("\n\n.\n") == 1
            text = text.replace("\n\n.\n", "\n", 1)
        return text + self.tail


class ShapedFortiOS(FakeFortiOS):
    def __init__(self):
        super().__init__()
        self.shape = None

    def snapshot(self):
        text = super().snapshot()
        if self.shape == "global":
            header, rest = text.split("\n", 1)
            return header + "\nconfig global\n" + rest + "end\n"
        if self.shape == "vdom":
            header, rest = text.split("\n", 1)
            return header + "\nconfig vdom\nedit root\n" + rest + "next\nend\n"
        if self.shape == "truncated":
            return text.split("config firewall policy\n", 1)[0]
        return text


def at_change(action):
    def hook(fake, lines):
        if len(fake.applied_blocks) == 2:
            action(fake)
    return hook


@pytest.mark.parametrize("lines", [ALL_PORTS, SLOT_RANGE, NO_MODE])
@pytest.mark.parametrize("fields", MEMBERSHIP_REQUESTS)
def test_unresolvable_port_list_refuses_a_port_change_without_a_traceback(tmp_path, lines, fields):
    device = ShapedExos(lines)
    runtime = make_exos_runtime(tmp_path, device)
    answer = execute.preview(runtime, "sw", exos_request(**fields))
    assert answer["result"] == "rejected" and answer["reasons"] == ["VLAN membership cannot be evaluated from this snapshot"]
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "sw", exos_request(**fields))
    assert caught.value.reasons == ["VLAN membership cannot be evaluated from this snapshot"]
    assert device.applied_blocks == []


@pytest.mark.parametrize("lines", [ALL_PORTS, SLOT_RANGE, NO_MODE])
def test_unresolvable_port_list_leaves_only_an_advisory_rule_unevaluated_for_a_vlan_change(tmp_path, lines):
    device = ShapedExos(lines)
    record = execute.apply(make_exos_runtime(tmp_path, device), "sw",
                           exos_request(op="update", key="spare", changes={"description": "parked"}))
    assert record["result"] == "confirmed", (record["result"], record.get("reason"), steps(record)[-3:])
    assert device.vlans["spare"]["description"] == "parked"
    assert record["audit_coverage"]["port-native"] == "not-evaluated"


def test_unterminated_upm_profile_before_the_change_refuses_as_an_incomplete_evaluation(tmp_path):
    device = ShapedExos(tail="create upm profile foreign\nenable cli-config-logging\n")
    with pytest.raises(Rejected) as caught:
        execute.apply(make_exos_runtime(tmp_path, device), "sw", exos_request())
    assert "evaluation is not complete" in caught.value.reasons[0], caught.value.reasons
    assert "unterminated-upm-profile" in caught.value.reasons[0]
    assert device.applied_blocks == []


def test_unterminated_upm_profile_after_the_change_stops_the_confirmation(tmp_path):
    device = ShapedExos()
    device.on_apply = at_change(lambda fake: setattr(fake, "open_profile", True))
    runtime = make_exos_runtime(tmp_path, device)
    record = execute.apply(runtime, "sw", exos_request())
    assert runtime.store.blocked("sw") is None
    assert "postcheck_passed" in steps(record)
    assert record["result"] == "reverted" and record["reason"] == "audit incomplete", (record["result"], record["reason"])
    assert any(step["step"] == "audit_incomplete" and "unterminated-upm-profile" in step.get("detail", "")
               for step in record["steps"]), record["steps"]
    assert "guest" not in device.vlans


@pytest.mark.parametrize("shape", ["global", "vdom", "truncated"])
def test_wrapped_or_truncated_fortios_dump_after_the_change_stops_the_confirmation(tmp_path, shape):
    device = ShapedFortiOS()
    device.on_apply = at_change(lambda fake: setattr(fake, "shape", shape))
    record = execute.apply(make_runtime(tmp_path, device), "lab", request())
    assert record["result"] != "confirmed"
    assert "postcheck_failed" in steps(record)
    assert "new-host" not in device.addresses


class AllPortsExos(ExosMembership):
    def __init__(self, lines):
        super().__init__()
        self.extra = list(lines)

    def _modes(self, port):
        modes = super()._modes(port)
        modes["tagged"].add("v10")
        return modes

    def snapshot(self):
        text = super().snapshot()
        assert text.count("# Module upm configuration.") == 1
        return text.replace("# Module upm configuration.", "\n".join(self.extra) + "\n# Module upm configuration.")


def membership_runtime(tmp_path, target):
    runtime = make_exos_runtime(tmp_path, target)
    vlans = ["Default", "spare", "v10"]
    policy = {"version": 1, "platform": "exos", "port_vlans": {"5": {"tagged": vlans, "untagged": vlans}},
              "protected_ports": [], "management_vlans": ["Mgmt"]}
    device = replace(runtime.config.devices["sw"], audit_policy=policy)
    runtime.config = replace(runtime.config, devices={"sw": device})
    return certify(runtime, target, "sw")


@pytest.mark.parametrize("fields", [
    {"table": "vlan-membership", "op": "update", "key": "5", "changes": {"tagged": ["spare", "v10"]}},
    {"table": "ports", "op": "update", "key": "5", "changes": {"display-string": "desk"}},
])
def test_port_list_all_is_expanded_from_the_router_ports_of_the_snapshot(tmp_path, fields):
    device = AllPortsExos(ALL_PORTS + (ROUTER_PORTS,))
    runtime = membership_runtime(tmp_path, device)
    preview = execute.preview(runtime, "sw", exos_request(**fields))
    assert preview["result"] != "rejected", preview
    record = execute.apply(runtime, "sw", exos_request(**fields))
    assert (record["result"], record["reason"]) == ("confirmed", None), steps(record)[-3:]
    assert record["audit_coverage"]["port-native"] == "evaluated"
    if fields["table"] == "vlan-membership":
        assert record["plan"]["predicted"]["before"] == {"untagged": "Default", "tagged": "v10"}
        assert record["plan"]["commands"] == ["configure vlan spare add ports 5 tagged"]
        assert device.memberships["5"] == {"untagged": "Default", "tagged": {"spare", "v10"}}
    else:
        assert device.port_strings["5"] == "desk"
    undone = execute.undo(runtime, record["change_id"], "restore example")
    assert (undone["result"], undone["reason"]) == ("confirmed", None), steps(undone)[-3:]
    assert device._modes("5") == {"untagged": "Default", "tagged": {"v10"}} and "5" not in device.port_strings


def test_cross_slot_range_with_the_router_ports_is_evaluated_for_a_vlan_change(tmp_path):
    device = ShapedExos(SLOT_RANGE + ("configure vr VR-Default add ports 1:1-1:4,2:1-2:4",))
    record = execute.apply(make_exos_runtime(tmp_path, device), "sw",
                           exos_request(op="update", key="spare", changes={"description": "parked"}))
    assert record["result"] == "confirmed", (record["result"], record.get("reason"), steps(record)[-3:])
    assert record["audit_coverage"]["port-native"] == "evaluated"
