from __future__ import annotations

import json
from dataclasses import replace

import pytest
from conftest import FIXTURES, request_bytes
from enrollment_helpers import certify
from fake_020 import ExosMembership
from test_execute_exos import make_runtime as make_exos_runtime
from test_operations_020 import request

from netops_admin import audit_gate, engine, execute, exos, prediction, readiness
from netops_admin.cli import EXIT_REJECTED, main
from netops_admin.errors import Rejected
from netops_admin.request import parse_request

MEASURED_PORTS = 'Port Summary\nPort     Display              VLAN Name           Port  Link  Speed  Duplex\n#        String               (or # VLANs)        State State Actual Actual\n===========================================================================\n1                             Default             E     R                               \n2                             Default             E     R                               \n3                             Default             E     R                               \n4                             Default             E     R                               \n5                             Default             E     R                               \n6                             Default             E     R                               \n7                             Default             E     R                               \n8                             Default             E     R                               \n9                             Default             E     R                               \n10                            Default             E     R                               \n11                            Default             E     R                               \n12                            Default             E     R                               \n========================================================================\n   Port State: D-Disabled, E-Enabled, F-Disabled by link-flap detection,\n               L-Disabled due to licensing\n   Link State: A-Active, R-Ready, NP-Port not present, L-Loopback,\n               D-ELSM enabled but not up,\n               d-Ethernet OAM enabled but not up,\n               B-MACsec enabled but blocked awaiting authentication\n'
FIRMWARE = "33.6.1.14"
TWELVE = [str(number) for number in range(1, 13)]
FACTORY = (
    "#\n# Module devmgr configuration.\n#\nconfigure snmp sysName \"lab-switch\"\n"
    "#\n# Module vlan configuration.\n#\n"
    "create vlan \"guest\"\nconfigure vlan guest tag 3068\n"
    "configure vlan Mgmt ipaddress 192.0.2.18 255.255.255.0\n"
)
AGGREGATED = (
    "#\n# Module vlan configuration.\n#\n"
    "configure vlan default delete ports all\n"
    "create vlan \"users\"\nconfigure vlan users tag 10\n"
    "enable sharing 12 grouping 12-13 algorithm address-based L3_L4 lacp\n"
    "configure vlan users add ports 1-11,14-16 untagged\n"
)
LAG_REFUSAL = "VLAN membership changes on link aggregation ports are unsupported"


def plan(snapshot, table, key, changes, ports=None):
    body = parse_request(request_bytes(table=table, op="update", key=key, changes=changes))
    return engine.build_plan("exos", snapshot.encode(), body, firmware=FIRMWARE, ports=ports)


def test_measured_port_summary_lists_the_switch_ports():
    assert exos.switch_ports(MEASURED_PORTS) == TWELVE


@pytest.mark.parametrize("text", ["", "%% Invalid input detected at '^' marker.\n", "Port Summary\n=====\n"])
def test_unrecognised_port_list_is_refused(text):
    with pytest.raises(Rejected, match="port list of the switch is not recognised"):
        exos.switch_ports(text)


def test_factory_port_listed_by_the_switch_is_in_the_default_vlan():
    document = plan(FACTORY, "vlan-membership", "5", {"tagged": ["guest"]}, TWELVE)
    assert document["predicted"] == {"before": {"untagged": "Default"},
                                     "after": {"untagged": "Default", "tagged": "guest"}}
    assert document["commands"] == ["configure vlan guest add ports 5 tagged"]
    assert document["inverse"] == ["configure vlan guest delete ports 5"]
    assert document["ports"] == TWELVE


def test_native_move_of_a_factory_port_returns_it_to_the_default_vlan():
    document = plan(FACTORY, "vlan-membership", "6", {"untagged": "guest"}, TWELVE)
    assert document["commands"] == ["configure vlan guest add ports 6 untagged"]
    assert document["inverse"] == ["configure vlan Default add ports 6 untagged"]


def test_display_string_on_a_factory_port_is_planned():
    document = plan(FACTORY, "ports", "5", {"display-string": "desk"}, TWELVE)
    assert document["commands"] == ["configure ports 5 display-string desk"]
    assert document["inverse"] == ["unconfigure ports 5 display-string"]


def test_factory_port_without_a_port_list_stays_unknown():
    with pytest.raises(Rejected, match="object '5' does not exist"):
        plan(FACTORY, "vlan-membership", "5", {"tagged": ["guest"]})


@pytest.mark.parametrize("table, changes", [("vlan-membership", {"tagged": ["guest"]}),
                                            ("ports", {"display-string": "desk"})])
def test_port_the_switch_does_not_list_is_refused(table, changes):
    with pytest.raises(Rejected, match="port 13 is not reported by the switch"):
        plan(FACTORY, table, "13", changes, TWELVE)


@pytest.mark.parametrize("key", ["12", "13"])
@pytest.mark.parametrize("ports", [None, [str(number) for number in range(1, 17)]])
def test_aggregated_port_is_refused_as_link_aggregation(key, ports):
    with pytest.raises(Rejected) as refused:
        plan(AGGREGATED, "vlan-membership", key, {"tagged": ["users"]}, ports)
    assert refused.value.reasons == [LAG_REFUSAL]


def test_listed_port_without_a_native_vlan_in_an_explicit_configuration_is_refused():
    with pytest.raises(Rejected, match="exactly one known native VLAN"):
        plan(AGGREGATED, "vlan-membership", "17", {"tagged": ["users"]}, [str(number) for number in range(1, 18)])


def test_verify_accepts_both_renderings_of_the_default_vlan():
    document = plan(FACTORY, "vlan-membership", "6", {"untagged": "guest"}, TWELVE)
    explicit = FACTORY.replace("create vlan", "configure vlan default delete ports all\ncreate vlan", 1)
    moved = explicit + "configure vlan Default add ports 1-5,7-12 untagged\nconfigure vlan guest add ports 6 untagged\n"
    assert engine.verify(document, moved.encode())["result"] == "match"
    returned = explicit + "configure vlan Default add ports 1-12 untagged\n"
    assert engine.verify(document, returned.encode(), expect="before")["result"] == "match"
    assert engine.verify(document, FACTORY.encode(), expect="before")["result"] == "match"
    other = explicit + "configure vlan Default add ports 1-4,7-12 untagged\nconfigure vlan guest add ports 5-6 untagged\n"
    assert engine.verify(document, other.encode())["differences"] == ["configuration outside the planned object changed"]


EXOS_VM_RENDERING = "configure vr VR-Default delete ports 1-12\n"
HARDWARE_RENDERING = "configure vr VR-Default delete ports 1-12\nconfigure vr VR-Default add ports 1-12\n"
RECOVERY = "#\n# Module devmgr configuration.\n#\nconfigure sys-recovery-level switch reset\n"


def explicit(router, extra=""):
    text = RECOVERY + FACTORY.replace("create vlan", "configure vlan default delete ports all\n" + router + "create vlan", 1)
    return text + extra


@pytest.mark.parametrize("router", [EXOS_VM_RENDERING, HARDWARE_RENDERING])
def test_verify_accepts_the_explicit_default_vlan_the_switch_prints_after_the_first_change(router):
    tagged = plan(FACTORY, "vlan-membership", "5", {"tagged": ["guest"]}, TWELVE)
    added = explicit(router, "configure vlan Default add ports 1-12 untagged\nconfigure vlan guest add ports 5 tagged\n")
    assert engine.verify(tagged, added.encode())["result"] == "match"
    returned = explicit(router, "configure vlan Default add ports 1-12 untagged\n")
    assert engine.verify(tagged, returned.encode(), expect="before")["result"] == "match"
    moved = plan(FACTORY, "vlan-membership", "6", {"untagged": "guest"}, TWELVE)
    after = explicit(router, "configure vlan Default add ports 1-5,7-12 untagged\nconfigure vlan guest add ports 6 untagged\n")
    assert engine.verify(moved, after.encode())["result"] == "match"
    assert engine.verify(moved, returned.encode(), expect="before")["result"] == "match"


@pytest.mark.parametrize("line", [
    "configure vr VR-Default delete ports 1-11\n",
    "configure vr VR-Default add ports 5\n",
    "configure vr VR-Mgmt delete ports 1-12\n",
    "configure sys-recovery-level switch none\n",
    "configure sys-recovery-level switch shutdown\n",
])
def test_verify_compares_router_ports_and_recovery_lines_that_are_not_the_default_rendering(line):
    tagged = plan(FACTORY, "vlan-membership", "5", {"tagged": ["guest"]}, TWELVE)
    added = explicit(EXOS_VM_RENDERING, line + "configure vlan Default add ports 1-12 untagged\nconfigure vlan guest add ports 5 tagged\n")
    assert engine.verify(tagged, added.encode())["differences"] == ["configuration outside the planned object changed"]


def test_router_ports_of_the_default_rendering_count_only_with_a_port_list():
    snapshot = AGGREGATED.replace("create vlan \"users\"", "create vlan \"guest\"\nconfigure vlan guest tag 20\ncreate vlan \"users\"")
    document = plan(snapshot, "vlan-membership", "5", {"tagged": ["guest"]})
    changed = snapshot + "configure vr VR-Default delete ports 1-16\n"
    assert engine.verify(document, changed.encode(), expect="before")["differences"] == [
        "configuration outside the planned object changed"]


@pytest.mark.parametrize("router", [EXOS_VM_RENDERING, HARDWARE_RENDERING])
def test_display_string_on_a_factory_port_accepts_the_explicit_default_vlan_the_switch_prints(router):
    document = plan(FACTORY, "ports", "5", {"display-string": "desk"}, TWELVE)
    after = explicit(router, "configure vlan Default add ports 1-12 untagged\nconfigure ports 5 display-string desk\n")
    assert engine.verify(document, after.encode())["result"] == "match"
    returned = explicit(router, "configure vlan Default add ports 1-12 untagged\n")
    assert engine.verify(document, returned.encode(), expect="before")["result"] == "match"
    assert engine.verify(document, (RECOVERY + FACTORY).encode(), expect="before")["result"] == "match"


@pytest.mark.parametrize("membership", [
    "configure vlan Default add ports 1-5,7-12 untagged\nconfigure vlan guest add ports 6 untagged\n",
    "configure vlan Default add ports 1-12 untagged\nconfigure vlan guest add ports 6 tagged\n",
    "configure vlan Default add ports 1-11 untagged\n",
    "configure vlan Default add ports 1-12 untagged\nconfigure vlan guest add ports 5 tagged\n",
])
def test_display_string_on_a_factory_port_still_compares_the_membership_of_the_ports(membership):
    document = plan(FACTORY, "ports", "5", {"display-string": "desk"}, TWELVE)
    after = explicit(EXOS_VM_RENDERING, membership + "configure ports 5 display-string desk\n")
    assert engine.verify(document, after.encode())["differences"] == ["configuration outside the planned object changed"]


def test_display_string_plan_without_a_port_list_compares_the_lines_as_before():
    snapshot = AGGREGATED.replace("configure vlan users add ports 1-11,14-16 untagged\n", "")
    document = plan(snapshot, "ports", "5", {"display-string": "desk"})
    assert "ports" not in document
    explicit_form = snapshot + "configure vlan Default add ports 1-16 untagged\nconfigure ports 5 display-string desk\n"
    assert engine.verify(document, explicit_form.encode())["differences"] == [
        "configuration outside the planned object changed"]


@pytest.mark.parametrize("table, key, changes", [("ports", "5", {"display-string": "desk"}),
                                                 ("vlan-membership", "5", {"tagged": ["guest"]})])
def test_audit_text_of_a_factory_port_holds_its_implicit_default_vlan(table, key, changes):
    document = plan(FACTORY, table, key, changes, TWELVE)
    text = prediction.audited(FACTORY, document)
    assert text == FACTORY + "".join("configure vlan Default add ports %s untagged\n" % port for port in TWELVE)
    assert prediction.audited(FACTORY, dict(document, table="vlan")) == FACTORY
    without = {name: value for name, value in document.items() if name != "ports"}
    assert prediction.audited(FACTORY, without) == FACTORY


def test_verify_of_a_tagged_addition_keeps_the_implicit_default_vlan():
    document = plan(FACTORY, "vlan-membership", "5", {"tagged": ["guest"]}, TWELVE)
    after = FACTORY + "configure vlan guest add ports 5 tagged\n"
    assert engine.verify(document, after.encode())["result"] == "match"
    assert engine.verify(document, FACTORY.encode())["result"] == "mismatch"


def test_plan_without_a_port_list_keeps_its_format():
    snapshot =AGGREGATED.replace("create vlan \"users\"", "create vlan \"guest\"\nconfigure vlan guest tag 20\ncreate vlan \"users\"")
    document = plan(snapshot, "vlan-membership", "5", {"tagged": ["guest"]})
    assert "ports" not in document
    assert engine.verify(document, snapshot.encode(), expect="before")["result"] == "match"
    with pytest.raises(Rejected, match="invalid port list"):
        engine.verify(dict(document, ports="1-12"), snapshot.encode())


def test_port_list_is_refused_for_fortios():
    body = parse_request(request_bytes())
    with pytest.raises(Rejected, match="applies only to ExtremeXOS"):
        engine.build_plan("fortios", (FIXTURES / "fortios_8_0_0.conf").read_bytes(), body, ports=["1"])


def test_offline_plan_takes_the_port_list(tmp_path, capsys):
    snapshot = tmp_path / "switch.cfg"
    snapshot.write_text(FACTORY, encoding="utf-8")
    body = tmp_path / "request.json"
    body.write_bytes(request_bytes(table="vlan-membership", op="update", key="5", changes={"tagged": ["guest"]}))
    arguments = ["plan", "--platform", "exos", "--snapshot", str(snapshot), "--request", str(body),
                 "--firmware", FIRMWARE]
    assert main(arguments + ["--ports", "1-12"]) == 0
    assert json.loads(capsys.readouterr().out)["ports"] == TWELVE
    assert main(arguments + ["--ports", "1-x"]) == EXIT_REJECTED
    assert json.loads(capsys.readouterr().out)["reasons"] == ["--ports is not a port list"]


class Aggregated(ExosMembership):
    def snapshot(self):
        return super().snapshot().replace(
            "# Module upm configuration.",
            "enable sharing 12 grouping 12-13 algorithm address-based L3_L4 lacp\n# Module upm configuration.")


def switch_runtime(tmp_path, target):
    runtime = make_exos_runtime(tmp_path, target)
    vlans = ["Default", "guest", "users", "staging"]
    policy = {"version": 1, "platform": "exos",
              "port_vlans": {port: {"tagged": vlans, "untagged": vlans} for port in ("5", "6", "12", "13")},
              "protected_ports": [], "management_vlans": ["Mgmt"]}
    device = replace(runtime.config.devices["sw"], audit_policy=policy)
    runtime.config = replace(runtime.config, devices={"sw": device})
    certify(runtime, target, "sw")
    return runtime


@pytest.mark.parametrize("router_verbs", [("delete",), ("delete", "add")])
@pytest.mark.parametrize("key, changes", [("5", {"tagged": ["guest"]}), ("6", {"untagged": "staging"})])
def test_factory_port_is_changed_and_undone(tmp_path, key, changes, router_verbs):
    target = ExosMembership()
    target.router_verbs = router_verbs
    runtime = switch_runtime(tmp_path, target)
    record = execute.apply(runtime, "sw", request("vlan-membership", key, changes))
    assert (record["result"], record["reason"]) == ("confirmed", None)
    assert record["plan"]["ports"] == target.port_numbers
    undone = execute.undo(runtime, record["change_id"], "restore example")
    assert (undone["result"], undone["reason"]) == ("confirmed", None)
    assert target.memberships[key] == {"untagged": "Default", "tagged": set()}
    assert engine.verify(record["plan"], target.snapshot().encode(), expect="before")["result"] == "match"


def test_display_string_on_a_factory_port_in_the_audit_policy_is_changed_and_undone(tmp_path):
    target = ExosMembership()
    runtime = switch_runtime(tmp_path, target)
    record = execute.apply(runtime, "sw", request("ports", "5", {"display-string": "desk"}))
    assert (record["result"], record["reason"]) == ("confirmed", None)
    assert target.port_strings["5"] == "desk"
    undone = execute.undo(runtime, record["change_id"], "restore example")
    assert (undone["result"], undone["reason"]) == ("confirmed", None)
    assert "5" not in target.port_strings


def test_doctor_audits_a_factory_switch_with_the_default_vlan_that_apply_audits(tmp_path):
    target = ExosMembership()
    runtime = switch_runtime(tmp_path, target)
    policy = runtime.config.devices["sw"].audit_policy
    text = target.snapshot()
    raw = audit_gate.findings("exos", text, "sw", policy)
    applied = audit_gate.findings("exos", prediction.audited(text, {
        "table": "vlan-membership", "ports": target.port_numbers, "firmware": target.firmware}), "sw", policy)
    assert "exos.management.port-native" in {rule for rule, _severity, _evidence in raw.values()}
    assert "exos.management.port-native" not in {rule for rule, _severity, _evidence in applied.values()}
    report = readiness.doctor(runtime, "sw")
    found = {item["check"]: item for item in report["checks"]}
    assert found["audit policy"]["status"] == readiness.OK
    assert found["audit policy"]["detail"] == "%d findings on the current configuration" % len(applied)
    assert target.applied_blocks == [] and target.saves == 0


@pytest.mark.parametrize("key, changes", [("5", {"tagged": ["guest"]}), ("6", {"untagged": "staging"})])
def test_safeguard_returns_a_factory_port_to_the_default_vlan(tmp_path, key, changes):
    target = ExosMembership()
    runtime = switch_runtime(tmp_path, target)

    def fail_after_change(fake, _lines):
        if len(fake.applied_blocks) == 2:
            fake.check_unreadable = True

    target.on_apply = fail_after_change
    record = execute.apply(runtime, "sw", request("vlan-membership", key, changes))
    assert (record["result"], record["reason"]) == ("reverted", "check identity unavailable")
    assert target.memberships[key] == {"untagged": "Default", "tagged": set()}


@pytest.mark.parametrize("key, table, changes, reason", [
    ("12", "vlan-membership", {"tagged": ["guest"]}, LAG_REFUSAL),
    ("13", "vlan-membership", {"tagged": ["guest"]}, LAG_REFUSAL),
    ("17", "vlan-membership", {"tagged": ["guest"]}, "port 17 is not reported by the switch"),
    ("17", "ports", {"display-string": "desk"}, "port 17 is not reported by the switch"),
])
def test_preview_refuses_aggregated_and_unlisted_ports(tmp_path, key, table, changes, reason):
    target = Aggregated()
    runtime = switch_runtime(tmp_path, target)
    result = execute.preview(runtime, "sw", request(table, key, changes))
    assert (result["result"], result["reasons"]) == ("rejected", [reason])
    assert not target.applied_blocks
