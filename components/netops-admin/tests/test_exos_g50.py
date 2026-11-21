import dataclasses
from pathlib import Path

import pytest

from fake_exos import FakeExos
from netops_admin import engine, execute, exos
from netops_admin.errors import Rejected
from test_execute_exos import make_runtime, request, steps

FIXTURES = Path(__file__).parent / "fixtures" / "exos_g50"
FIRMWARE = "33.6.1.14"
FDB_EMPTY = (FIXTURES / "fdb-miss.out").read_text()
FDB_WITH_STATIC = (FIXTURES / "fdb-hit-one.out").read_text()
COUNTERS_EMPTY = (FIXTURES / "stats-wide.out").read_text()
COUNTERS_RESET = COUNTERS_EMPTY.replace("\n6         R ", "\n3         A ")
# real d-exos LLDP list (front ports 1, 3, 4, 5 and mgmt have neighbors); the derived variant keeps only the mgmt rows
LLDP_REAL = (FIXTURES / "lldp-d-exos.out").read_text()
LLDP_MGMT_ONLY = "\n".join(line for line in LLDP_REAL.splitlines() if not line[:1].isdigit()) + "\n"


class G50Exos(FakeExos):
    def __init__(self, read, write, before, after, firmware, lldp=LLDP_REAL):
        super().__init__()
        self.lldp_text = lldp
        self.firmware = firmware
        self.read = read
        self.write = write
        self.before = before
        self.after = after
        self.clears = []
        self.checks = []

    def check_query(self, command):
        self.checks.append(command)
        assert command == self.read
        return self.after if self.clears else self.before

    def apply(self, commands, spec):
        assert commands == [self.write]
        self.clears.extend(commands)
        return 1


@pytest.mark.parametrize("table,key,read,write,before,after", [
    ("port-counters", "3", "show ports 3 statistics no-refresh wide", "clear counters ports 3",
     (FIXTURES / "stats-wide-active.out").read_text(), COUNTERS_RESET),
    ("fdb", "00:00:5e:00:53:01", "show fdb 00:00:5e:00:53:01", "clear fdb 00:00:5e:00:53:01",
     FDB_WITH_STATIC, "\n".join(line for line in FDB_WITH_STATIC.splitlines() if " d m " not in line)),
    ("fdb", "port:5", "show fdb ports 5", "clear fdb ports 5",
     (FIXTURES / "fdb-port-active.out").read_text(), FDB_EMPTY),
    ("fdb", "vlan:host03", "show fdb vlan host03", "clear fdb vlan host03",
     (FIXTURES / "fdb-vlan.out").read_text(), FDB_EMPTY),
    ("iparp", "192.0.2.2", "show iparp 192.0.2.2 vr VR-Default", "clear iparp 192.0.2.2 vr VR-Default",
     (FIXTURES / "arp-hit.out").read_text(), (FIXTURES / "arp-miss-vr.out").read_text()),
])
def test_preview_confirmed_apply_and_readback(tmp_path, table, key, read, write, before, after):
    # these fixtures name ports 1, 3, 4 and 5, which have LLDP neighbors on d-exos today; see the protection tests
    device = G50Exos(read, write, before, after, FIRMWARE, lldp=LLDP_MGMT_ONLY)
    runtime = make_runtime(tmp_path, device, firmware=FIRMWARE)
    change = request(op="clear", table=table, key=key, changes={})
    preview = execute.preview(runtime, "sw", change)
    assert preview["result"] == "ready"
    assert preview["commands"] == [write]
    assert preview["inverse_commands"] == 0
    assert preview["safeguard_seconds"] is None
    assert preview["return_mechanism"] == "irreversible"
    assert preview["firmware_support"]["status"] == "tested"
    assert device.clears == [] and runtime.store.records() == []
    with pytest.raises(Rejected) as refused:
        execute.apply(runtime, "sw", change)
    assert refused.value.reason_codes == ["clear_preview_required"]
    with pytest.raises(Rejected) as refused:
        execute.apply(runtime, "sw", change, expected_plan_sha256="0" * 64)
    assert refused.value.reason_codes == ["plan_changed"]
    assert device.clears == []

    snapshot = device.snapshot()
    approved = preview["plan_sha256"]
    record = execute.apply(runtime, "sw", change, expected_plan_sha256=approved)
    assert record["result"] == "confirmed"
    assert record["readback"] == preview["predicted"]["after"]
    assert "postcheck_passed" in steps(record)
    assert "safeguard" not in record and record["plan"]["inverse"] == []
    assert device.snapshot() == snapshot and device.saves == 0 and not device.timers
    assert execute.apply(runtime, "sw", change, expected_plan_sha256=approved)["change_id"] == record["change_id"]
    assert device.clears == [write]
    for undo in (execute.preview_undo, execute.undo):
        with pytest.raises(Rejected) as refused:
            undo(runtime, record["change_id"], "verify irreversible operation")
        assert refused.value.reason_codes == ["undo_not_applicable"]
    assert device.clears == [write]


@pytest.mark.parametrize("table,key,read,fixture,code", [
    ("port-counters", "999", "show ports 999 statistics no-refresh wide", "stats-error.out", "clear_readback_unreadable"),
    ("fdb", "00:00:5e:00:53:02", "show fdb 00:00:5e:00:53:02", "fdb-hit.out", "clear_ambiguous_entry"),
    ("fdb", "00:00:5e:00:53:01", "show fdb 00:00:5e:00:53:01", "fdb-static.out", "clear_no_entry"),
    ("iparp", "192.0.2.210", "show iparp 192.0.2.210 vr VR-Default", "arp-miss-vr.out", "clear_no_entry"),
    ("iparp", "192.0.2.60", "show iparp 192.0.2.60 vr VR-Default", "arp-static.out", "clear_no_entry"),
    ("neighbor-discovery", "2001:db8::210", "show neighbor-discovery cache ipv6 2001:db8::210 vr VR-Default",
     "nd-miss.out", "clear_readback_unreadable"),
    ("neighbor-discovery", "2001:db8::210", "show neighbor-discovery cache ipv6 2001:db8::210 vr VR-Default",
     "nd.out", "clear_no_entry"),
    ("neighbor-discovery", "2001:db8:1::60", "show neighbor-discovery cache ipv6 2001:db8:1::60 vr VR-Default",
     "nd-static.out", "clear_no_entry"),
])
def test_real_refusal_is_read_only(tmp_path, table, key, read, fixture, code):
    device = G50Exos(read, None, (FIXTURES / fixture).read_text(), None, FIRMWARE, lldp=LLDP_MGMT_ONLY)
    runtime = make_runtime(tmp_path, device, firmware=FIRMWARE)
    change = request(op="clear", table=table, key=key, changes={})
    preview = execute.preview(runtime, "sw", change)
    assert preview["result"] == "rejected" and code in preview["reason_codes"]
    assert device.clears == [] and runtime.store.records() == []


def test_unverified_clear_is_not_retried_and_recovery_never_writes(tmp_path):
    read, write = "show ports 6 statistics no-refresh wide", "clear counters ports 6"
    device = G50Exos(read, write, COUNTERS_EMPTY, COUNTERS_EMPTY.rsplit("\n", 3)[0], "31.7.3.37")
    runtime = make_runtime(tmp_path, device, firmware=device.firmware)
    change = request(op="clear", table="port-counters", key="6", changes={})
    preview = execute.preview(runtime, "sw", change)
    assert preview["result"] == "ready" and preview["firmware_support"]["status"] == "untested"
    record = execute.apply(runtime, "sw", change, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "unknown" and runtime.store.blocked("sw")
    record.update(status="running", steps=record["steps"][:-1])
    runtime.store.save(record)
    assert execute.recover(runtime, "sw")[0]["result"] == "unknown"
    assert device.clears == [write] and device.saves == 0


def test_nd_plan_refuses_an_address_with_both_learned_and_static_entries(tmp_path):
    table, key = "neighbor-discovery", "2001:db8:1::60"
    change = request(op="clear", table=table, key=key, changes={})
    target = exos.clear_target(table, key, change.changes)
    before = exos.clear_observation(table, target, (FIXTURES / "nd-static.out").read_text())
    before["entries"].append(dict(before["entries"][0], dynamic=True, vlan="g50test-other", port="7"))
    fake = FakeExos()
    device = make_runtime(tmp_path, fake, firmware=FIRMWARE).config.devices["sw"]
    with pytest.raises(Rejected) as refused:
        engine.build_clear_plan(device, fake.snapshot(), change, target, before)
    assert refused.value.reason_codes == ["clear_ambiguous_entry"]


@pytest.mark.parametrize("table,key,changes", [
    ("port-counters", "7,8", {}), ("port-counters", "all", {}), ("fdb", "port:6-7", {}),
    ("fdb", "vlan:all", {}), ("fdb", "vlan:test\nclear fdb", {}),
    ("iparp", "192.0.2.1/32", {}), ("iparp", "192.0.2.1", {"vr": "all"}),
    ("neighbor-discovery", "fe80::1%6", {}),
])
def test_clear_has_no_wildcards_or_unbounded_scope(tmp_path, table, key, changes):
    device = G50Exos(None, None, None, None, FIRMWARE)
    runtime = make_runtime(tmp_path, device, firmware=FIRMWARE)
    preview = execute.preview(runtime, "sw", request(op="clear", table=table, key=key, changes=changes))
    assert preview["result"] == "rejected"
    assert device.checks == [] and device.clears == []


# --- 501-rv finding 1: a clear on an active target is learned again before the readback -----------------------------

ARP_A = (FIXTURES / "arp-g50-a.out").read_text()
# derived: the address of host A answered by another MAC (00:00:5e:00:53:a5) after the clear
ARP_A_OTHER_MAC = ARP_A.replace("00:00:5e:00:53:a4", "00:00:5e:00:53:a5")


@pytest.mark.parametrize("table,key,read,before,after,lldp", [
    ("fdb", "00:00:5e:00:53:a4", "show fdb 00:00:5e:00:53:a4", "fdb-g50-a.out", "fdb-g50-a.out", LLDP_REAL),
    ("fdb", "port:6", "show fdb ports 6", "fdb-g50-port6.out", "fdb-g50-port6.out", LLDP_REAL),
    ("iparp", "192.0.2.10", "show iparp 192.0.2.10 vr VR-Default", "arp-g50-a.out", "arp-g50-a.out", LLDP_REAL),
    ("iparp", "192.0.2.10", "show iparp 192.0.2.10 vr VR-Default", "arp-g50-a.out", ARP_A_OTHER_MAC, LLDP_REAL),
    ("neighbor-discovery", "2001:db8:3950::10", "show neighbor-discovery cache ipv6 2001:db8:3950::10 vr VR-Default",
     "nd-g50-a.out", "nd-g50-a.out", LLDP_REAL),
    ("fdb", "00:00:5e:00:53:01", "show fdb 00:00:5e:00:53:01", "fdb-hit-one.out", "fdb-hit-one.out", LLDP_MGMT_ONLY),
], ids=["fdb-mac", "fdb-port", "arp", "arp-other-mac", "nd", "fdb-mac-with-static"])
def test_relearned_target_is_confirmed_and_does_not_block(tmp_path, table, key, read, before, after, lldp):
    text = lambda name: name if "\n" in name else (FIXTURES / name).read_text()
    write = "clear " + read[len("show "):]
    device = G50Exos(read, write, text(before), text(after), FIRMWARE, lldp=lldp)
    runtime = make_runtime(tmp_path, device, firmware=FIRMWARE)
    change = request(op="clear", table=table, key=key, changes={})
    preview = execute.preview(runtime, "sw", change)
    assert preview["result"] == "ready"
    record = execute.apply(runtime, "sw", change, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", record.get("reason")
    assert runtime.store.blocked("sw") is None
    assert "relearned" in steps(record) and "postcheck_passed" in steps(record)
    entries = record["readback"]["entries"]
    assert entries and all(entry.get("relearned") is (True if entry["dynamic"] else None) for entry in entries)
    statics = [entry for entry in preview["predicted"]["before"]["entries"] if not entry["dynamic"]]
    assert [entry for entry in entries if not entry["dynamic"]] == statics
    assert device.clears == [write]
    # the device is not blocked: a next request is previewed normally
    again = request(op="clear", table=table, key=key, changes={}, request_id="req-0002-after-relearn")
    assert execute.preview(runtime, "sw", again)["result"] == "ready"


def test_static_entry_lost_after_the_clear_stays_unknown(tmp_path):
    read = "show fdb 00:00:5e:00:53:01"
    device = G50Exos(read, "clear fdb 00:00:5e:00:53:01", FDB_WITH_STATIC, FDB_EMPTY, FIRMWARE, lldp=LLDP_MGMT_ONLY)
    runtime = make_runtime(tmp_path, device, firmware=FIRMWARE)
    change = request(op="clear", table="fdb", key="00:00:5e:00:53:01", changes={})
    preview = execute.preview(runtime, "sw", change)
    record = execute.apply(runtime, "sw", change, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "unknown" and record["reason"] == "clear readback mismatch"


@pytest.mark.parametrize("table,key,read,fixture", [
    ("iparp", "192.0.2.10", "show iparp 192.0.2.10 vr VR-Default", "arp-g50-a.out"),
    ("neighbor-discovery", "2001:db8:3950::10", "show neighbor-discovery cache ipv6 2001:db8:3950::10 vr VR-Default",
     "nd-g50-a.out"),
])
def test_pending_neighbor_after_clear_is_incomplete(tmp_path, table, key, read, fixture):
    before = (FIXTURES / fixture).read_text()
    # DERIVED: put the captured neighbor into the pending state, without its resolved MAC.
    after = before.replace("00:00:5e:00:53:a4", "Incomplete").replace("Pending Entries  :           0",
                                                                          "Pending Entries  :           1")
    write = "clear " + read[len("show "):]
    device = G50Exos(read, write, before, after, FIRMWARE)
    runtime = make_runtime(tmp_path, device, firmware=FIRMWARE)
    change = request(op="clear", table=table, key=key, changes={})
    preview = execute.preview(runtime, "sw", change)
    assert preview["result"] == "ready" and device.clears == []
    record = execute.apply(runtime, "sw", change, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed" and "relearned" not in steps(record)
    [entry] = record["readback"]["entries"]
    assert entry["relearned"] is False and entry["status"] == "incomplete"
    assert device.clears == [write]


def _counters(port, link, values):
    """derived from stats-wide-active.out: the measured layout with other values"""
    template = (FIXTURES / "stats-wide-active.out").read_text()
    row = next(line for line in template.splitlines() if line.startswith("3 "))
    fields = [port, link, *map(str, values)]
    widths = [9, 5] + [20] * 8
    new = " ".join(field.ljust(width) if index < 2 else field.rjust(width)
                   for index, (field, width) in enumerate(zip(fields, widths)))
    return template.replace(row, new)


ACTIVE = (FIXTURES / "stats-wide-active.out").read_text()


@pytest.mark.parametrize("before,after,result", [
    # multicast/broadcast counters were 0 and count a few control frames (ND, LLDP) after the clear
    (ACTIVE, _counters("3", "A", [12, 1430, 15, 1650, 1, 3, 0, 2]), "confirmed"),
    # small counters of a quiet port grow slightly within the tolerance
    (_counters("3", "A", [35, 3060, 20, 1900, 0, 0, 0, 0]), _counters("3", "A", [40, 3600, 22, 2100, 0, 1, 0, 1]),
     "confirmed"),
    # not cleared: a large counter did not fall
    (ACTIVE, ACTIVE, "unknown"),
    # a counter that was 0 grew beyond the tolerance
    (ACTIVE, _counters("3", "A", [12, 1430, 15, 1650, 0, 65, 0, 0]), "unknown"),
], ids=["control-frames", "quiet-port-grows", "not-cleared", "beyond-tolerance"])
def test_counter_readback_tolerates_control_traffic(tmp_path, before, after, result):
    read, write = "show ports 3 statistics no-refresh wide", "clear counters ports 3"
    device = G50Exos(read, write, before, after, FIRMWARE, lldp=LLDP_MGMT_ONLY)
    runtime = make_runtime(tmp_path, device, firmware=FIRMWARE)
    change = request(op="clear", table="port-counters", key="3", changes={})
    preview = execute.preview(runtime, "sw", change)
    assert preview["result"] == "ready"
    record = execute.apply(runtime, "sw", change, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == result
    assert (runtime.store.blocked("sw") is None) is (result == "confirmed")


# --- 501-rv: clear_protected_target --------------------------------------------------------------------------------

FDB_MGMT = (FIXTURES / "fdb-g50-a.out").read_text().replace("g50test(3950)", "   Mgmt(4095)")
ARP_VR_MGMT = ARP_A.replace("VR-Default", "VR-Mgmt   ")
POLICY = {"version": 1, "platform": "exos"}


@pytest.mark.parametrize("table,key,changes,read,before,protected,policy,lldp", [
    # protected port of the device configuration
    ("port-counters", "3", {}, "show ports 3 statistics no-refresh wide", ACTIVE, {"ports": ["3"]}, None,
     LLDP_MGMT_ONLY),
    # management VLAN as the scope and as the VLAN of a learned row
    ("fdb", "vlan:host03", {}, "show fdb vlan host03", "fdb-vlan.out", {}, {"management_vlans": ["host03"]},
     LLDP_MGMT_ONLY),
    ("fdb", "00:00:5e:00:53:01", {}, "show fdb 00:00:5e:00:53:01", "fdb-hit-one.out", {},
     {"management_vlans": ["host02"]}, LLDP_MGMT_ONLY),
    # the built-in Mgmt VLAN and the system VR VR-Mgmt without any policy
    ("fdb", "vlan:Mgmt", {}, "show fdb vlan Mgmt", FDB_MGMT, {}, None, LLDP_REAL),
    ("iparp", "192.0.2.10", {"vr": "VR-Mgmt"}, "show iparp 192.0.2.10 vr VR-Mgmt", ARP_VR_MGMT, {}, None, LLDP_REAL),
    # port 3 is an untagged member of DATA in the running configuration, DATA is a management VLAN
    ("port-counters", "3", {}, "show ports 3 statistics no-refresh wide", ACTIVE, {}, {"management_vlans": ["DATA"]},
     LLDP_MGMT_ONLY),
    # the port_vlans allowlist puts a management VLAN on port 6
    ("fdb", "port:6", {}, "show fdb ports 6", "fdb-g50-port6.out", {},
     {"management_vlans": ["mgmt-net"], "port_vlans": {"6": {"tagged": ["mgmt-net"], "untagged": ["Default"]}}},
     LLDP_REAL),
    # uplinks: the port of the scope or of a learned row has an LLDP neighbor (real d-exos list)
    ("fdb", "port:5", {}, "show fdb ports 5", "fdb-port-active.out", {}, None, LLDP_REAL),
    ("port-counters", "3", {}, "show ports 3 statistics no-refresh wide", ACTIVE, {}, None, LLDP_REAL),
    ("fdb", "vlan:host03", {}, "show fdb vlan host03", "fdb-vlan.out", {}, None, LLDP_REAL),
    ("iparp", "192.0.2.2", {}, "show iparp 192.0.2.2 vr VR-Default", "arp-hit.out", {}, None, LLDP_REAL),
], ids=["protected-port", "management-vlan-scope", "management-vlan-row", "mgmt-vlan", "vr-mgmt",
        "management-vlan-member", "port-vlans-policy", "lldp-port-scope", "lldp-counters", "lldp-vlan-row",
        "lldp-arp-row"])
def test_clear_protected_target(tmp_path, table, key, changes, read, before, protected, policy, lldp):
    text = before if "\n" in before else (FIXTURES / before).read_text()
    device = G50Exos(read, None, text, None, FIRMWARE, lldp=lldp)
    runtime = make_runtime(tmp_path, device, firmware=FIRMWARE)
    target = dataclasses.replace(runtime.config.devices["sw"], protected=protected,
                                 audit_policy=dict(POLICY, **policy) if policy else None)
    runtime.config = dataclasses.replace(runtime.config, devices={"sw": target})
    preview = execute.preview(runtime, "sw", request(op="clear", table=table, key=key, changes=changes))
    assert preview["result"] == "rejected"
    assert preview["reason_codes"] == ["clear_protected_target"], preview["reasons"]
    assert device.clears == [] and runtime.store.records() == []


def test_unreadable_lldp_list_refuses_the_clear(tmp_path):
    truncated = LLDP_REAL.split("NOTE:")[0]
    device = G50Exos("show fdb ports 6", None, (FIXTURES / "fdb-g50-port6.out").read_text(), None, FIRMWARE,
                     lldp=truncated)
    runtime = make_runtime(tmp_path, device, firmware=FIRMWARE)
    preview = execute.preview(runtime, "sw", request(op="clear", table="fdb", key="port:6", changes={}))
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["port_usage_unreadable"]
    assert device.clears == []


def test_lldp_list_with_mgmt_rows_is_read():
    # EXOS-VM 33.6.1.14 lists neighbors of the management port as `mgmt`
    assert exos.lldp_ports(LLDP_REAL) == {"1", "3", "4", "5", "mgmt"}


# --- 501-rv: the preview of a VLAN scope names the count of learned entries ------------------------------------------

def test_vlan_preview_counts_the_learned_entries(tmp_path):
    device = G50Exos("show fdb vlan host03", None, (FIXTURES / "fdb-vlan.out").read_text(), None, FIRMWARE,
                     lldp=LLDP_MGMT_ONLY)
    runtime = make_runtime(tmp_path, device, firmware=FIRMWARE)
    preview = execute.preview(runtime, "sw", request(op="clear", table="fdb", key="vlan:host03", changes={}))
    assert preview["result"] == "ready"
    assert "fdb vlan:host03: 6 learned (dynamic) entries will be cleared, 0 other entries stay" in preview["prechecks"]
