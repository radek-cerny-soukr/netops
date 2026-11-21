"""IOS XE clear through Admin with measured IOL EXEC output and the G67 fake transport."""
from dataclasses import replace
from pathlib import Path
import re

import pytest

from netops_admin import execute, notify
from netops_admin.access import AccessError
from netops_admin.errors import Rejected

from test_access import Shell, device_access
from test_ios import make_runtime, request
from test_ios_g67 import G67Ios, emulate_non_iol_xe, without_row

FIXTURES = Path(__file__).parent / "fixtures" / "ios_g85"
COUNTERS = "show interfaces Ethernet0/1"
COUNTERS_CLEAR = "clear counters Ethernet0/1"
MAC = "show mac address-table dynamic"
ARP = "show ip arp vrf blue"
ND = "show ipv6 neighbors vrf blue"
IP4 = "192.0.2.1"
IP6 = "2001:db8:1::1"


def fixture(name):
    return (FIXTURES / f"xe-{name}.out").read_text()


def mac_on_test_port():
    # Move one measured row to the access port. The real management table is used for the denial test.
    return fixture("mac-before").replace("99    0000.5e00.53e1    DYNAMIC     Et0/0",
                                         " 1    0000.5e00.53e1    DYNAMIC     Et0/1")


@pytest.mark.parametrize("table,key,changes,read,command,before,after", [
    ("port-counters", "Et0/1", {}, COUNTERS, COUNTERS_CLEAR, fixture("counters-before"),
     fixture("counters-after")),
    ("fdb", "00:00:5e:00:53:e1", {}, MAC, "clear mac address-table dynamic address 0000.5e00.53e1",
     mac_on_test_port(), without_row(mac_on_test_port(), "0000.5e00.53e1")),
    ("iparp", IP4, {"vrf": "blue"}, ARP, f"clear arp-cache vrf blue {IP4}",
     fixture("arp-before"), without_row(fixture("arp-before"), IP4 + " ")),
])
def test_scoped_preview_apply_readback_and_no_undo(tmp_path, table, key, changes, read, command, before, after):
    node = "iolxe-l2" if table in ("port-counters", "fdb") else "iolxe"
    device = G67Ios(node, read, before, after, command)
    device.query_override[COUNTERS + " switchport"] = fixture("switchport")
    runtime = make_runtime(tmp_path, device)
    initial = device.snapshot()
    fields = dict(op="clear", table=table, key=key, changes=changes)
    if table != "port-counters":
        no_impact = execute.preview(runtime, "lab-ios", request(device, **fields))
        assert no_impact["reason_codes"] == ["endpoint_impact_required"]
        fields["endpoint_impact"] = key
    change = request(device, **fields)
    preview = execute.preview(runtime, "lab-ios", change)
    assert preview["result"] == "ready", preview
    assert preview["commands"] == [command]
    assert preview["return_mechanism"] == "irreversible"
    if table == "port-counters":
        assert preview["firmware_support"]["status"] == "tested"
    assert device.clears == [] and runtime.store.records() == []
    with pytest.raises(Rejected) as error:
        execute.apply(runtime, "lab-ios", change)
    assert error.value.reason_codes == ["clear_preview_required"]
    assert not device.clears
    applied = execute.apply(runtime, "lab-ios", change, expected_plan_sha256=preview["plan_sha256"])
    assert applied["result"] == "confirmed", applied["steps"]
    if table == "port-counters":
        assert applied["readback"]["last_clearing"] == "00:00:01"
    else:
        assert applied["readback"]["entries"] == []
        assert applied["readback"]["other_entries"]
        assert applied["readback"]["other_entries"] == preview["predicted"]["before"]["other_entries"]
        assert applied["plan"]["endpoint_impact"] == preview["key"]
    for undo in (execute.preview_undo, execute.undo):
        with pytest.raises(Rejected) as error:
            undo(runtime, applied["change_id"], "Check the operational action's return")
        assert error.value.reason_codes == ["undo_not_applicable"]
    assert device.clears == [command]
    assert device.snapshot() == initial and not device.saves and device.timer is None


@pytest.mark.parametrize("iol_l2", [True, False])
def test_port_mac_clear_capability_before_plan(tmp_path, iol_l2):
    before = mac_on_test_port()
    command = "clear mac address-table dynamic interface Ethernet0/1"
    device = G67Ios("iolxe-l2", MAC, before, without_row(before, "0000.5e00.53e1"), command)
    device.query_override[COUNTERS + " switchport"] = fixture("switchport")
    if not iol_l2:
        device.query_override["show version"] = device.query("show version").replace(
            "X86_64BI_LINUX_L2-ADVENTERPRISEK9-M", "CAT9K_IOSXE")
    runtime = make_runtime(tmp_path, device)
    change = request(device, op="clear", table="fdb", key="port:Et0/1", changes={}, endpoint_impact="port:Et0/1")
    preview = execute.preview(runtime, "lab-ios", change)
    if iol_l2:
        assert preview["result"] == "rejected" and preview["reason_codes"] == ["iosxe_iol_mac_port_clear_unsupported"]
        assert "plan_sha256" not in preview
        assert device.reads == 0 and not device.clears and not runtime.store.records()
    else:
        assert preview["commands"] == [command]
        applied = execute.apply(runtime, "lab-ios", change, expected_plan_sha256=preview["plan_sha256"])
        assert applied["result"] == "confirmed" and device.clears == [command]


def test_arp_age_reset_alone_does_not_prove_clear(tmp_path):
    device = G67Ios("iolxe", ARP, fixture("arp-before"), fixture("arp-after"), f"clear arp-cache vrf blue {IP4}")
    runtime = make_runtime(tmp_path, device)
    change = request(device, op="clear", table="iparp", key=IP4, changes={"vrf": "blue"}, endpoint_impact=IP4)
    preview = execute.preview(runtime, "lab-ios", change)
    result = execute.apply(runtime, "lab-ios", change, expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "unknown" and result["reason"] == "clear readback mismatch"
    assert result["readback"]["age_reset"] and result["readback"]["entries"][0]["age"] == 0


def test_connected_counters_require_impact(tmp_path):
    # An active link with the same measured IOL counters.
    before = fixture("counters-before").replace("administratively down, line protocol is down (disabled)",
                                                "up, line protocol is up (connected)")
    device = G67Ios("iolxe-l2", COUNTERS, before)
    runtime = make_runtime(tmp_path, device)
    fields = dict(op="clear", table="port-counters", key="Et0/1", changes={})
    preview = execute.preview(runtime, "lab-ios", request(device, **fields))
    assert preview["reason_codes"] == ["endpoint_impact_required"]
    preview = execute.preview(runtime, "lab-ios", request(device, **fields, endpoint_impact="Et0/1"))
    assert preview["result"] == "ready"
    assert not device.clears


@pytest.mark.parametrize("config_changed", [False, True])
def test_unchanged_recent_clear_at_send_is_unverified(tmp_path, config_changed):
    baseline = fixture("counters-before")
    recent = fixture("counters-after")
    class Transport(G67Ios):
        def snapshot(self):
            config = super().snapshot()
            if config_changed and self.clears:
                return config.replace("\nend", "\nntp master 5\nend")
            return config

    device = Transport("iolxe-l2", COUNTERS, baseline, recent, COUNTERS_CLEAR)
    device.next_before = recent
    runtime = make_runtime(tmp_path, device)
    notifications = []

    def send(record):
        notifications.append(notify.message(record)[1])
        return "sent"

    runtime.notifier = send
    change = request(device, op="clear", table="port-counters", key="Et0/1", changes={})
    preview = execute.preview(runtime, "lab-ios", change)
    result = execute.apply(runtime, "lab-ios", change, expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "unknown"
    assert device.clears == [COUNTERS_CLEAR]
    if config_changed:
        assert result["reason"] == "foreign change" and runtime.store.blocked("lab-ios")
    else:
        assert result["reason"] == "clear readback mismatch" and not runtime.store.blocked("lab-ios")
        next_change = replace(change, request_id="g85-next-clear")
        assert execute.preview(runtime, "lab-ios", next_change)["result"] == "ready"
    stored = runtime.store.operation(result["change_id"])
    _, body = notify.message(stored)
    assert notifications == [body]
    blocked_line = "the device is blocked until a person investigates it"
    uncertain_line = "the result is uncertain and the device is not blocked"
    if config_changed:
        assert blocked_line in body.splitlines() and uncertain_line not in body.splitlines()
    else:
        assert uncertain_line in body.splitlines() and blocked_line not in body.splitlines()


@pytest.mark.parametrize("before,code", [
    (fixture("counters-refused"), "clear_readback_unreadable"),
    (fixture("counters-before").split("packets output")[0], "clear_readback_unreadable"),
    (None, "clear_read_timeout"),
])
def test_refused_partial_and_timed_out_read(tmp_path, before, code):
    class Transport(G67Ios):
        def check_query_status(self, command):
            if self.before is None:
                raise AccessError("SSH exec timed out")
            return super().check_query_status(command)

    device = Transport("iolxe-l2", COUNTERS, before)
    runtime = make_runtime(tmp_path, device)
    result = execute.preview(runtime, "lab-ios", request(device, op="clear", table="port-counters",
                                                          key="Et0/1", changes={}))
    assert result["reason_codes"] == [code]
    assert not device.clears


@pytest.mark.parametrize("table,key,read,before,changes,protected", [
    ("fdb", "0000.5e00.53e1", MAC, fixture("mac-before"), {}, "et0/0"),
    ("iparp", IP4, ARP, fixture("arp-before"), {"vrf": "blue"}, "et0/2"),
    ("neighbor-discovery", "2001:db8:2::1", "show ipv6 neighbors", fixture("nd-global"),
     {"interface": "Et0/1.10"}, "et0/1"),
])
def test_inventory_protects_interface_and_subinterface(tmp_path, table, key, read, before, changes, protected):
    device = G67Ios("iolxe-l2" if table == "fdb" else "iolxe", read, before)
    if table == "neighbor-discovery":
        emulate_non_iol_xe(device)
    runtime = make_runtime(tmp_path, device)
    runtime.config.devices["lab-ios"] = replace(
        runtime.config.devices["lab-ios"], protected={"interface": [protected]},
    )
    change = request(device, op="clear", table=table, key=key, changes=changes, endpoint_impact=key)
    preview = execute.preview(runtime, "lab-ios", change)
    assert preview["reason_codes"] == ["clear_protected_target"], preview
    assert not device.clears


@pytest.mark.parametrize("key,changes,read,answer", [
    (IP6, {"vrf": "blue"}, ND, "nd-before"),
    ("2001:db8:2::1", {"interface": "Et0/1.10"}, "show ipv6 neighbors", "nd-global"),
])
@pytest.mark.parametrize("node", ["iolxe", "iolxe-l2"])
def test_iol_xe_refuses_per_address_neighbor_clear_before_a_write(tmp_path, node, key, changes, read, answer):
    device = G67Ios(node, read, fixture(answer))
    runtime = make_runtime(tmp_path, device)
    change = request(device, op="clear", table="neighbor-discovery", key=key,
                     changes=changes, endpoint_impact=key)
    preview = execute.preview(runtime, "lab-ios", change)
    assert preview["reason_codes"] == ["iosxe_iol_nd_clear_unsupported"], preview
    assert device.reads == 0 and not device.clears


def test_empty_neighbor_has_no_entry(tmp_path):
    device = G67Ios("iolxe", ND, fixture("nd-empty"))
    emulate_non_iol_xe(device)
    runtime = make_runtime(tmp_path, device)
    change = request(device, op="clear", table="neighbor-discovery", key=IP6, changes={"vrf": "blue"})
    assert execute.preview(runtime, "lab-ios", change)["reason_codes"] == ["clear_no_entry"]


def test_neighbor_command_refusal_from_ssh(tmp_path):
    class Transport(G67Ios):
        def apply(self, steps, spec):
            prompt = b"\r\nd-lab#"
            reply = self.command.encode() + b"\r\n" + fixture("nd-refused").strip().encode() + prompt
            shell = Shell([prompt, reply])
            transport = device_access(shell)
            try:
                transport.apply(steps, replace(spec, anchor=b"\nd-lab"))
            finally:
                self.last_answers = transport.last_answers
                self.clears.extend(shell.sent)

    command = f"clear ipv6 neighbors vrf blue {IP6}"
    device = Transport("iolxe", ND, fixture("nd-before"), fixture("nd-after"), command)
    emulate_non_iol_xe(device)
    runtime = make_runtime(tmp_path, device)
    change = request(device, op="clear", table="neighbor-discovery", key=IP6, changes={"vrf": "blue"},
                     endpoint_impact=IP6)
    preview = execute.preview(runtime, "lab-ios", change)
    applied = execute.apply(runtime, "lab-ios", change, expected_plan_sha256=preview["plan_sha256"])
    assert applied["result"] == "rejected" and applied["reason_codes"] == ["clear_command_refused"]
    assert device.clears == [command]
    assert not runtime.store.blocked("lab-ios")


def test_disconnect_on_clear_send_blocks_without_retry_or_configuration_write(tmp_path):
    class ClearWire(G67Ios):
        def apply(self, steps, spec):
            accepted = super().apply(steps, spec)
            raise AccessError("synthetic private clear diagnostic", accepted)

    command = f"clear arp-cache vrf blue {IP4}"
    before = fixture("arp-before")
    device = ClearWire("iolxe", ARP, before, without_row(before, IP4 + " "), command)
    runtime = make_runtime(tmp_path, device)
    change = request(device, op="clear", table="iparp", key=IP4, changes={"vrf": "blue"}, endpoint_impact=IP4)
    preview = execute.preview(runtime, "lab-ios", change)
    assert preview["result"] == "ready"
    initial = device.snapshot()

    record = execute.apply(runtime, "lab-ios", change, expected_plan_sha256=preview["plan_sha256"])

    assert (record["result"], record["reason"]) == ("unknown", "clear command acceptance unverified")
    assert runtime.store.blocked("lab-ios")["change_id"] == record["change_id"]
    assert execute.recover(runtime, "lab-ios") == []
    assert device.clears == [command] and device.snapshot() == initial and not device.saves and device.timer is None
    assert "synthetic private clear diagnostic" not in repr(runtime.store.records())


def test_empty_dynamic_mac_table_requires_matching_ios_xe_aggregate(tmp_path):
    # Derive zero rows/counts from both measured outputs. A header alone may be truncated.
    empty = fixture("mac-empty-port")
    count = re.sub(r"(?<=:) +[0-9]+$", " 0", fixture("mac-count"), flags=re.MULTILINE)

    class Transport(G67Ios):
        def check_query_status(self, command):
            if command == "show mac address-table count":
                return 0, self.count
            return super().check_query_status(command)

    device = Transport("iolxe-l2", MAC, empty)
    runtime = make_runtime(tmp_path, device)
    change = request(device, op="clear", table="fdb", key="0000.5e00.53e1", changes={})
    device.count = fixture("mac-count")
    assert execute.preview(runtime, "lab-ios", change)["reason_codes"] == ["clear_readback_unreadable"]
    device.count = count
    assert execute.preview(runtime, "lab-ios", change)["reason_codes"] == ["clear_no_entry"]
    assert not device.clears
