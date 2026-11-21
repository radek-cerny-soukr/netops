"""G46 uses real EXOS 33.6.1.14 answers from fixtures/exos_g46."""
from pathlib import Path

import pytest
from conftest import request_bytes
from test_exos_g45 import G45Exos, runtime_for

from netops_admin import engine, execute
from netops_admin.access import AccessError
from netops_admin.errors import Rejected
from netops_admin.request import parse_request

FIXTURES = Path(__file__).parent / "fixtures" / "exos_g46"
VLAN = "netops-g46"
AREA = "0.0.0.15"
PEER = "198.51.100.2"


def fixture(name):
    return (FIXTURES / (name + ".out")).read_text()


def request(table, op, key, changes=None, **fields):
    return parse_request(request_bytes(table=table, op=op, key=key, changes=changes or {},
                                       request_id=f"g46-{table}-{op}-{key.replace(':', '-')}", **fields))


class RoutingExos(G45Exos):
    """Serve measured snapshots and CLI output for the states visited by actual Admin commands."""

    def __init__(self):
        super().__init__()
        self.routing = dict.fromkeys(("ospf", "ospfv3", "bgp"), "absent")
        self.local_as = "0"
        self.policy = ""
        self.policy_loaded = False
        self.break_command = ""
        self.timeout = None

    def snapshot(self):
        text = super().snapshot()
        vlan = "\n".join(line for line in fixture("before-config-vlan").splitlines() if not line.startswith("#"))
        modules = "".join(fixture(f"{state}-config-{proto}") for proto, state in self.routing.items())
        if self.local_as != "0":
            # The vendor AS-number reference documents the command and reset value. The empty BGP module is measured.
            modules += f"configure bgp AS-number {self.local_as}\n"
        if self.policy:
            modules += f"configure bgp neighbor {PEER} route-policy in {self.policy}\n"
        text = text.replace("# Module ems", vlan + "\n# Module ems")
        return text.replace("# Module upm", modules + "# Module upm")

    def _command(self, words, automatic):
        if len(words) < 2 or words[1] not in self.routing:
            return super()._command(words, automatic)
        action, proto, *args = words
        state = self.routing[proto]
        if proto == "bgp":
            if action == "configure" and args[:1] == ["AS-number"] and state == "absent":
                self.local_as = args[1]
                self.unsaved = True
                return True
            if action == "configure" and args[:4] == ["neighbor", PEER, "route-policy", "in"] and state != "absent":
                self.policy = args[4] if args[4] != "none" else ""
                self.unsaved = True
                return True
            next_states = {
                ("absent", "create", "neighbor", PEER, "remote-AS-number", "65146"): "created",
                ("created", "enable", "neighbor", PEER): "enabled",
                ("enabled", "disable", "neighbor", PEER): "created",
                ("created", "delete", "neighbor", PEER): "absent",
            }
        else:
            next_states = {
                ("absent", "create", "area", AREA): "area",
                ("area", "configure", "add", "vlan", VLAN, "area", AREA, "passive"): "passive",
                ("passive", "configure", "vlan", VLAN, "cost", "42"): "metric",
                ("metric", "enable"): "enabled",
                ("enabled", "disable"): "metric",
                ("metric", "configure", "vlan", VLAN, "cost", "automatic"): "passive",
                ("passive", "configure", "delete", "vlan", VLAN): "area",
                ("area", "delete", "area", AREA): "absent",
            }
        next_state = next_states.get((state, action, *args))
        if next_state is None:
            return False
        self.routing[proto] = next_state
        self.unsaved = True
        return True

    def query_status(self, command):
        if command != "check policy g46-prefix":
            return super().query_status(command)
        return ((0, fixture("valid-check-policy")) if self.policy_loaded else
                (250, fixture("missing-check-policy")))

    def check_query_status(self, command):
        if command == self.break_command:
            if self.timeout:
                raise AccessError(self.timeout)
            return 0, "\n".join(fixture("absent-show-ospf-area").splitlines()[:2])
        _, proto, *args = command.split()
        state = self.routing[proto]
        if proto == "bgp":
            if not args:
                base = fixture("absent-show-bgp")
                return 0, base.replace("AS                  : 0", f"AS                  : {self.local_as}")
            if args == ["neighbor"]:
                return 0, fixture(f"{state}-show-bgp-neighbor")
            text = fixture(f"{state}-show-bgp-peer")
            if self.policy:
                text = text.replace("In Policy         : None", f"In Policy         : {self.policy}", 1)
            return 0, text
        if args == ["area", AREA]:
            assert state == "absent"
            return 250, fixture(f"absent-show-{proto}-area-detail")
        if args == ["area"]:
            return 0, fixture(f"{'absent' if state == 'absent' else 'area'}-show-{proto}-area")
        if args == ["interfaces", "vlan", VLAN]:
            mode = {"absent": "absent", "area": "absent", "passive": "passive", "metric": "metric", "enabled": "metric"}
            return (250 if mode[state] == "absent" else 0), fixture(f"{mode[state]}-show-{proto}-interface")
        assert not args
        return 0, fixture(f"{'enabled' if state == 'enabled' else 'absent'}-show-{proto}")


def apply(runtime, device, change):
    before = device.snapshot()
    writes = len(device.applied_blocks)
    preview = execute.preview(runtime, "sw", change)
    assert preview["result"] == "ready", preview
    assert device.snapshot() == before and len(device.applied_blocks) == writes
    record = execute.apply(runtime, "sw", change, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", record
    assert "configuration_saved" in {step["step"] for step in record["steps"]}
    return record


def undo(runtime, device, record):
    before = device.snapshot()
    preview = execute.preview_undo(runtime, record["change_id"], "restore test scope", issue=True)
    assert preview["result"] == "ready", preview
    assert device.snapshot() == before
    undone = execute.undo(runtime, record["change_id"], "restore test scope",
                          expected_plan_sha256=preview["plan_sha256"])
    assert undone["result"] == "confirmed", undone


@pytest.mark.parametrize("proto", ["ospf", "ospfv3"])
def test_area_interface_metric_and_process_round_trip(tmp_path, proto):
    device = RoutingExos()
    runtime = runtime_for(tmp_path, device)
    runtime.config.limits["changes_per_device_per_hour"] = 10
    before = device.snapshot()
    area = apply(runtime, device, request("ospf-area", "create", f"{proto}:{AREA}"))
    member = apply(runtime, device, request("ospf-interface", "create", f"{proto}:{VLAN}", {"area": AREA, "passive": "yes"}))
    metric = apply(runtime, device, request("ospf-interface", "update", f"{proto}:{VLAN}", {"cost": 42}))
    live = apply(runtime, device, request("ospf", "update", proto, {"admin-state": "enabled"}))
    blocked = execute.preview(runtime, "sw", request("ospf-area", "delete", f"{proto}:{AREA}"))
    assert blocked["reason_codes"] == ["exos_routing_scope"]
    assert device.routing[proto] == "enabled"
    for record in (live, metric, member, area):
        undo(runtime, device, record)
    assert device.snapshot() == before and not device.profiles and not device.timers


def test_bgp_peer_round_trip_and_policy_refusal(tmp_path):
    device = RoutingExos()
    runtime = runtime_for(tmp_path, device)
    before = device.snapshot()
    create = request("bgp-neighbor", "create", PEER, {"remote-as": 65146})
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "sw", create)
    assert caught.value.reason_codes == ["plan_changed"] and not device.applied_blocks
    peer = apply(runtime, device, create)
    missing = request("bgp-neighbor", "update", PEER, {"import-policy": "g46-prefix"}, endpoint_impact=PEER)
    writes = len(device.applied_blocks)
    denied = execute.preview(runtime, "sw", missing)
    assert denied["reason_codes"] == ["exos_routing_scope"] and len(device.applied_blocks) == writes
    enabled = apply(runtime, device, request("bgp-neighbor", "update", PEER,
                                             {"admin-state": "enabled"}, endpoint_impact=PEER))
    undo(runtime, device, enabled)
    undo(runtime, device, peer)
    assert device.snapshot() == before and not device.profiles and not device.timers


def test_bgp_local_as_and_policy_field_through_apply_and_undo(tmp_path):
    device = RoutingExos()
    runtime = runtime_for(tmp_path, device)
    before = device.snapshot()
    local = apply(runtime, device, request("bgp", "update", "VR-Default", {"local-as": 65551}))
    peer = apply(runtime, device, request("bgp-neighbor", "create", PEER, {"remote-as": 65146}))
    device.policy_loaded = True
    policy = apply(runtime, device, request("bgp-neighbor", "update", PEER,
                                            {"import-policy": "g46-prefix"}, endpoint_impact=PEER))
    assert device.policy == "g46-prefix"
    for record in (policy, peer, local):
        undo(runtime, device, record)
    assert device.local_as == "0" and device.snapshot() == before


@pytest.mark.parametrize(("timeout", "code"), [
    (None, "exos_routing_readback_unreadable"),
    ("SSH connection timed out", "exos_routing_read_timeout"),
    ("SSH did not finish within 12.0 seconds", "exos_routing_read_timeout"),
])
def test_incomplete_operational_area_is_refused_without_write(tmp_path, timeout, code):
    device = RoutingExos()
    device.break_command = "show ospf area"
    device.timeout = timeout
    preview = execute.preview(runtime_for(tmp_path, device), "sw", request("ospf-area", "create", f"ospf:{AREA}"))
    assert preview["reason_codes"] == [code] and not device.applied_blocks


def test_metric_is_reset_before_detach_and_firmware_warns():
    fake = RoutingExos()
    fake.routing["ospf"] = "metric"
    snapshot = fake.snapshot().encode()
    change = request("ospf-interface", "delete", f"ospf:{VLAN}")
    plan = engine.build_plan("exos", snapshot, change, firmware="33.7.1.6")
    assert plan["firmware_support"]["status"] == "untested"
    assert plan["commands"] == [f"configure ospf vlan {VLAN} cost automatic", f"configure ospf delete vlan {VLAN}"]
    assert plan["inverse"] == [f"configure ospf add vlan {VLAN} area {AREA} passive", f"configure ospf vlan {VLAN} cost 42"]
    with pytest.raises(Rejected) as caught:
        engine.build_plan("exos", snapshot, change, firmware=fake.firmware, protected={"vlan": [VLAN]})
    assert caught.value.reason_codes == ["exos_routing_scope"]


@pytest.mark.parametrize(("table", "op", "key", "changes"), [
    ("ospf", "update", "ospf", {"admin-state": "enabled"}),
    ("ospf-area", "create", f"ospf:{AREA}", {}),
    ("ospf-interface", "create", f"ospf:{VLAN}", {"area": AREA}),
    ("bgp", "update", "VR-Default", {"local-as": 65146}),
    ("bgp-neighbor", "create", PEER, {"remote-as": 65146}),
])
def test_g46_apply_requires_preview_hash(tmp_path, table, op, key, changes):
    device = RoutingExos()
    runtime = runtime_for(tmp_path, device)
    snapshot = device.snapshot()
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "sw", request(table, op, key, changes))
    assert caught.value.reason_codes == ["plan_changed"]
    assert device.snapshot() == snapshot and not device.applied_blocks


@pytest.mark.parametrize(("op", "changes"), [
    ("update", {"admin-state": "disabled"}),
    ("update", {"import-policy": "g46-prefix"}),
    ("update", {"export-policy": "g46-prefix"}),
    ("delete", {}),
])
def test_existing_bgp_neighbor_requires_endpoint_impact(op, changes):
    device = RoutingExos()
    device.routing["bgp"] = "enabled"
    snapshot = device.snapshot().encode()
    with pytest.raises(Rejected) as caught:
        engine.build_plan("exos", snapshot, request("bgp-neighbor", op, PEER, changes),
                          firmware=device.firmware)
    assert caught.value.reason_codes == ["endpoint_impact_required"]
    plan = engine.build_plan("exos", snapshot, request("bgp-neighbor", op, PEER, changes, endpoint_impact=PEER),
                             firmware=device.firmware)
    assert engine._read_plan(plan)["endpoint_impact"] == PEER
