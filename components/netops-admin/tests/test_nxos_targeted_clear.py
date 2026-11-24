"""Targeted NX-OS clear of counters, MAC and ARP/ND entries.

The reads use anonymised Nexus 9300v captures from NX-OS 9.3(12) (see fixtures/nxos_nxos_targeted_clear/PROVENANCE.md).
The answers after a clear that the lab produced live are the real empty tables; the ones that need a changed value
(counters after the clear, an entry learned again) substitute only that value of the captured text."""
import dataclasses
import re
from pathlib import Path

import pytest

from fake_nxos import FakeNxos
from netops_admin import execute, nxos_clear
from netops_admin.errors import Rejected
from test_nxos import FIRMWARE, make_runtime, request, steps

FIXTURES = Path(__file__).parent / "fixtures" / "nxos_nxos_targeted_clear"


def captured(name):
    return (FIXTURES / name).read_text()


def lab(case):
    return captured("nexus9300v__" + case + ".txt")


HOST_MAC = "0000.5e00.5301"
HOST_IP = "192.0.2.101"
COUNTERS = lab("show-interface-eth1-2")
# derived: the captured port with every counter at 0 and a clearing time instead of "never"
COUNTERS_CLEARED = re.sub(r"\d+ (input|output) packets  \d+ bytes", r"0 \1 packets  0 bytes",
                          re.sub(r"\d+ (unicast|multicast|broadcast) packets", r"0 \1 packets", COUNTERS)
                          ).replace("counters never", "counters 00:00:04")
CDP = (FIXTURES.parent / "nxos_nxos_switchport_admin" / "nexus9300v__cdp.txt").read_text()


class G105Nxos(FakeNxos):
    def __init__(self, read, write, before, after):
        super().__init__()
        self.read, self.write, self.before, self.after = read, write, before, after
        self.clears = []
        self.on_clear = None

    def check_query(self, command):
        if command == self.read:
            self.check_queries.append(command)
            return self.after if self.clears else self.before
        return super().check_query(command)

    session_vrf = "management"

    def with_interactive_reader(self, spec, callback):
        def read(command):
            return super(G105Nxos, self).with_interactive_reader(spec, lambda inner: inner(command)).replace(
                "management", self.session_vrf) if command.startswith("show sockets") else self.query(command)

        return callback(read)

    def query(self, command):
        if command == "show cdp neighbors":
            return CDP
        svi = re.fullmatch(r"show interface vlan ([0-9]+)", command)
        if svi:
            return (FIXTURES.parent / "nxos_nxos_routing_admin" / "svi-up.txt").read_text().replace(
                "Vlan20 is", "Vlan%s is" % svi.group(1))
        return super().query(command)

    def apply(self, steps, spec):
        assert steps == [self.write]
        assert self.line_guard is None or self.line_guard()
        self.clears.extend(steps)
        if self.write.startswith("clear counters "):
            self.advance(5)
        if self.on_clear is not None:
            self.on_clear(self)
        return 1


def runtime_for(tmp_path, device, protected=None, firmware=FIRMWARE):
    runtime = make_runtime(tmp_path, device, firmware=firmware)
    if protected:
        name = "lab-nxos"
        runtime.config.devices[name] = dataclasses.replace(runtime.config.devices[name], protected=protected)
    return runtime


def clear_request(table, key, **changes):
    return request(op="clear", table=table, key=key, changes=changes)


# ---- the request: one explicit object, never a whole table ----

@pytest.mark.parametrize("table,key,changes,read,write", [
    ("port-counters", "Eth1/2", {}, "show interface Ethernet1/2", "clear counters interface Ethernet1/2"),
    ("port-counters", "ethernet1/48", {}, "show interface Ethernet1/48", "clear counters interface Ethernet1/48"),
    ("mac-address-table", "00:00:5E:00:53:01", {}, "show mac address-table address 0000.5e00.5301",
     "clear mac address-table dynamic address 0000.5e00.5301"),
    ("mac-address-table", "interface:Eth1/2", {}, "show mac address-table interface Ethernet1/2",
     "clear mac address-table dynamic interface Ethernet1/2"),
    ("ip-arp", "192.0.2.101", {}, "show ip arp 192.0.2.101 vrf default", "clear ip arp 192.0.2.101 vrf default"),
    ("ip-arp", "192.0.2.101", {"vrf": "blue"}, "show ip arp 192.0.2.101 vrf blue",
     "clear ip arp 192.0.2.101 vrf blue"),
    ("ipv6-neighbor", "2001:db8:20::101", {"interface": "Vlan20"}, "show ipv6 neighbor 2001:db8:20::101 vrf default",
     "clear ipv6 neighbor 2001:db8:20::101 Vlan20 vrf default"),
    ("ipv6-neighbor", "2001:DB8:20::101", {"vrf": "blue"}, "show ipv6 neighbor 2001:db8:20::101 vrf blue",
     "clear ipv6 neighbor 2001:db8:20::101 vrf blue"),
])
def test_the_verified_selectors_are_rendered_with_one_object(table, key, changes, read, write):
    target = nxos_clear.target(table, key, changes)
    assert (target.read, target.write) == (read, write)


@pytest.mark.parametrize("table,key,changes", [
    ("port-counters", "all", {}),
    ("port-counters", "Ethernet1/1-4", {}),
    ("port-counters", "Ethernet1/2,Ethernet1/3", {}),
    ("port-counters", "port-channel10", {}),
    ("port-counters", "mgmt0", {}),
    ("port-counters", "Vlan20", {}),
    ("port-counters", "Ethernet1/2", {"snmp": "yes"}),
    ("mac-address-table", "all", {}),
    ("mac-address-table", "vlan:20", {}),
    ("mac-address-table", "interface:port-channel10", {}),
    ("mac-address-table", "interface:Ethernet1/2,Ethernet1/3", {}),
    ("mac-address-table", "ffff.ffff.ffff", {}),
    ("mac-address-table", "0100.5e00.0001", {}),
    ("mac-address-table", HOST_MAC, {"vlan": "20"}),
    ("ip-arp", "0.0.0.0", {}),
    ("ip-arp", "224.0.0.5", {}),
    ("ip-arp", "192.0.2.0/24", {}),
    ("ip-arp", "all", {}),
    ("ip-arp", HOST_IP, {"vrf": "all"}),
    ("ip-arp", HOST_IP, {"vrf": "ALL"}),
    ("ip-arp", HOST_IP, {"vrf": "default; clear ip arp"}),
    ("ip-arp", HOST_IP, {"interface": "Vlan20"}),
    ("ip-arp", "2001:db8::1", {}),
    ("ipv6-neighbor", "2001:db8::1", {"vrf": "all"}),
    ("ipv6-neighbor", "ff02::1", {}),
    ("ipv6-neighbor", "::", {}),
    ("ipv6-neighbor", "fe80::1%Vlan20", {}),
    ("ipv6-neighbor", "2001:db8::1", {"interface": "port-channel1"}),
    ("ipv6-neighbor", "192.0.2.1", {}),
])
def test_a_clear_without_one_explicit_object_is_refused_before_the_device_is_contacted(tmp_path, table, key, changes):
    device = G105Nxos("-", "-", "", "")
    runtime = runtime_for(tmp_path, device)
    preview = execute.preview(runtime, "lab-nxos", clear_request(table, key, **changes))
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["clear_invalid_target"], preview
    assert device.clears == [] and device.queries == [] and device.check_queries == []
    assert runtime.store.records() == []


def test_a_table_without_clear_is_refused_as_unsupported(tmp_path):
    device = G105Nxos("-", "-", "", "")
    runtime = runtime_for(tmp_path, device)
    change = clear_request("vlan", "10")
    with pytest.raises(Rejected) as refused:
        execute.apply(runtime, "lab-nxos", change, expected_plan_sha256="0" * 64)
    assert refused.value.reason_codes == ["action_unsupported"]
    assert device.clears == []


# ---- preview, confirmed apply, readback ----

CASES = [
    ("port-counters", "Ethernet1/2", {}, "show interface Ethernet1/2", "clear counters interface Ethernet1/2",
     COUNTERS, COUNTERS_CLEARED),
    ("mac-address-table", HOST_MAC, {}, "show mac address-table address " + HOST_MAC,
     "clear mac address-table dynamic address " + HOST_MAC, lab("mac-address-hit"), lab("mac-address-miss")),
    ("mac-address-table", "interface:Ethernet1/2", {}, "show mac address-table interface Ethernet1/2",
     "clear mac address-table dynamic interface Ethernet1/2", lab("mac-interface-hit"),
     lab("mac-interface-empty")),
    ("ip-arp", HOST_IP, {}, "show ip arp %s vrf default" % HOST_IP, "clear ip arp %s vrf default" % HOST_IP,
     lab("arp-hit"), lab("arp-miss")),
    ("ipv6-neighbor", "2001:db8:20::101", {"interface": "Vlan20"},
     "show ipv6 neighbor 2001:db8:20::101 vrf default",
     "clear ipv6 neighbor 2001:db8:20::101 Vlan20 vrf default", captured("doc__nd-hit.txt"),
     lab("nd-miss")),
]


@pytest.mark.parametrize("table,key,changes,read,write,before,after", CASES)
def test_preview_confirmed_apply_readback_and_no_undo(tmp_path, table, key, changes, read, write, before, after):
    if table == "ipv6-neighbor":
        # one ND address of the documented layout holds two rows (global and link-local); the clear names one
        before = before.replace("Total number of entries: 2", "Total number of entries: 1").split("fe80::")[0]
    device = G105Nxos(read, write, before, after)
    runtime = runtime_for(tmp_path, device)
    change = clear_request(table, key, **changes)
    preview = execute.preview(runtime, "lab-nxos", change)
    assert preview["result"] == "ready", preview
    assert preview["commands"] == [write] and preview["inverse_commands"] == 0
    assert preview["safeguard_seconds"] is None and preview["return_mechanism"] == "irreversible"
    assert preview["firmware_support"]["status"] == "tested"
    assert device.clears == [] and runtime.store.records() == []
    with pytest.raises(Rejected) as refused:
        execute.apply(runtime, "lab-nxos", change)
    assert refused.value.reason_codes == ["clear_preview_required"]
    with pytest.raises(Rejected) as refused:
        execute.apply(runtime, "lab-nxos", change, expected_plan_sha256="0" * 64)
    assert refused.value.reason_codes == ["plan_changed"]
    assert device.clears == []

    snapshot = nxos_clear.config_digest(device.running())
    record = execute.apply(runtime, "lab-nxos", change, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", record
    assert "postcheck_passed" in steps(record) and "safeguard" not in record
    assert record["plan"]["inverse"] == [] and record["plan"]["safeguard_id"] is None
    # the configuration is untouched: nothing is saved and no timer or checkpoint exists
    assert nxos_clear.config_digest(device.running()) == snapshot
    assert device.saves == 0 and not device.schedules and not device.checkpoints
    assert execute.apply(runtime, "lab-nxos", change, expected_plan_sha256=preview["plan_sha256"])["change_id"] \
        == record["change_id"]
    assert device.clears == [write]
    for undo in (execute.preview_undo, execute.undo):
        with pytest.raises(Rejected) as refused:
            undo(runtime, record["change_id"], "verify irreversible operation")
        assert refused.value.reason_codes == ["undo_not_applicable"]
    assert device.clears == [write]


def test_the_preview_names_what_stays(tmp_path):
    device = G105Nxos("show mac address-table interface Ethernet1/2", "clear mac address-table dynamic interface "
                      "Ethernet1/2", lab("mac-interface-hit"), lab("mac-interface-empty"))
    preview = execute.preview(runtime_for(tmp_path, device), "lab-nxos",
                              clear_request("mac-address-table", "interface:Ethernet1/2"))
    assert any("1 learned (dynamic) entries will be cleared, 0 other entries stay" in line
               for line in preview["prechecks"])


def test_counters_that_moved_between_preview_and_apply_do_not_change_the_plan(tmp_path):
    read, write = "show interface Ethernet1/2", "clear counters interface Ethernet1/2"
    device = G105Nxos(read, write, COUNTERS, COUNTERS_CLEARED)
    runtime = runtime_for(tmp_path, device)
    change = clear_request("port-counters", "Ethernet1/2")
    preview = execute.preview(runtime, "lab-nxos", change)
    device.before = COUNTERS.replace("11258 unicast", "11999 unicast").replace('counters never', "counters 1d00h")
    assert execute.apply(runtime, "lab-nxos", change, expected_plan_sha256=preview["plan_sha256"])[
        "result"] == "confirmed"


def test_the_age_of_an_arp_entry_does_not_change_the_plan(tmp_path):
    read, write = "show ip arp %s vrf default" % HOST_IP, "clear ip arp %s vrf default" % HOST_IP
    device = G105Nxos(read, write, lab("arp-hit"), lab("arp-miss"))
    runtime = runtime_for(tmp_path, device)
    change = clear_request("ip-arp", HOST_IP)
    preview = execute.preview(runtime, "lab-nxos", change)
    device.before = lab("arp-hit").replace("00:14:03", "00:14:33")
    assert execute.apply(runtime, "lab-nxos", change, expected_plan_sha256=preview["plan_sha256"])[
        "result"] == "confirmed"


# ---- an entry learned again, and a clear that did nothing ----

def test_an_arp_entry_learned_again_is_reported_with_its_new_age(tmp_path):
    read, write = "show ip arp %s vrf default" % HOST_IP, "clear ip arp %s vrf default" % HOST_IP
    device = G105Nxos(read, write, lab("arp-hit"), lab("arp-hit").replace("00:14:03", "00:00:02"))
    runtime = runtime_for(tmp_path, device)
    change = clear_request("ip-arp", HOST_IP)
    approved = execute.preview(runtime, "lab-nxos", change)["plan_sha256"]
    record = execute.apply(runtime, "lab-nxos", change, expected_plan_sha256=approved)
    assert record["result"] == "confirmed" and "relearned" in steps(record)
    [entry] = record["readback"]["entries"]
    assert entry["relearned"] is True and entry["age"] == 2


def test_an_arp_entry_that_is_not_younger_means_the_clear_did_nothing(tmp_path):
    read, write = "show ip arp %s vrf default" % HOST_IP, "clear ip arp %s vrf default" % HOST_IP
    device = G105Nxos(read, write, lab("arp-hit"), lab("arp-hit"))
    runtime = runtime_for(tmp_path, device)
    change = clear_request("ip-arp", HOST_IP)
    approved = execute.preview(runtime, "lab-nxos", change)["plan_sha256"]
    record = execute.apply(runtime, "lab-nxos", change, expected_plan_sha256=approved)
    assert record["result"] == "unknown" and "postcheck_failed" in steps(record)


def test_counters_that_did_not_fall_are_not_a_success(tmp_path):
    read, write = "show interface Ethernet1/2", "clear counters interface Ethernet1/2"
    device = G105Nxos(read, write, COUNTERS, COUNTERS)
    runtime = runtime_for(tmp_path, device)
    change = clear_request("port-counters", "Ethernet1/2")
    approved = execute.preview(runtime, "lab-nxos", change)["plan_sha256"]
    record = execute.apply(runtime, "lab-nxos", change, expected_plan_sha256=approved)
    assert record["result"] == "unknown" and "postcheck_failed" in steps(record)


def test_wave6_mac_unchanged_is_not_relearned(tmp_path):
    table = "mac-address-table"
    target = nxos_clear.target(table, HOST_MAC, {})
    before = lab("mac-address-hit")
    device = G105Nxos(target.read, target.write, before, before)
    runtime = runtime_for(tmp_path, device)
    change = clear_request(table, HOST_MAC)
    approved = execute.preview(runtime, "lab-nxos", change)["plan_sha256"]
    record = execute.apply(runtime, "lab-nxos", change, expected_plan_sha256=approved)
    assert record["result"] == "unknown" and "postcheck_failed" in steps(record)
    assert not record["readback"]["entries"][0]["relearned"]


def test_wave6_mac_with_a_new_age_is_relearned(tmp_path):
    table = "mac-address-table"
    target = nxos_clear.target(table, HOST_MAC, {})
    after = lab("mac-address-hit")
    before = after.replace("dynamic  0", "dynamic  15")
    device = G105Nxos(target.read, target.write, before, after)
    device.on_clear = lambda switch: switch.advance(2)
    runtime = runtime_for(tmp_path, device)
    change = clear_request(table, HOST_MAC)
    approved = execute.preview(runtime, "lab-nxos", change)["plan_sha256"]
    record = execute.apply(runtime, "lab-nxos", change, expected_plan_sha256=approved)
    assert record["result"] == "confirmed"
    assert record["readback"]["entries"][0]["relearned"]


@pytest.mark.parametrize(("after_age", "same_values"), [("00:10:10", False), ("00:00:01", True)])
def test_wave6_counter_clear_needs_recent_time_and_changed_nonzero_values(tmp_path, after_age, same_values):
    before = re.sub(r"\d+(?= (?:unicast|multicast|broadcast|input|output) packets| bytes)", "1", COUNTERS)
    before = before.replace("counters never", "counters 00:10:00")
    after = (before.replace("00:10:00", after_age) if same_values else
             COUNTERS_CLEARED.replace("00:00:04", after_age))
    target = nxos_clear.target("port-counters", "Ethernet1/2", {})
    device = G105Nxos(target.read, target.write, before, after)
    runtime = runtime_for(tmp_path, device)
    change = clear_request("port-counters", "Ethernet1/2")
    approved = execute.preview(runtime, "lab-nxos", change)["plan_sha256"]
    record = execute.apply(runtime, "lab-nxos", change, expected_plan_sha256=approved)
    assert record["result"] == "unknown" and "postcheck_failed" in steps(record)


def test_wave6_clear_arp_respects_inventory_svi(tmp_path):
    from enrollment_helpers import certify

    table = "ip-arp"
    target = nxos_clear.target(table, HOST_IP, {})
    device = G105Nxos(target.read, target.write, lab("arp-hit"), lab("arp-miss"))
    runtime = runtime_for(tmp_path, device, {"interface": ["vLaN20"]})
    certify(runtime, device, "lab-nxos")
    preview = execute.preview(runtime, "lab-nxos", clear_request(table, HOST_IP))
    assert preview["reason_codes"] == ["clear_protected_target"], preview
    assert device.clears == []


def test_a_mac_entry_of_another_host_that_disappeared_is_not_a_success(tmp_path):
    # the selected port keeps its static entry in the readback; the second host of the same scope must stay
    before = lab("mac-interface-hit") + "*   20     0000.5e00.5309   static   -         F      F    Eth1/2\n"
    device = G105Nxos("show mac address-table interface Ethernet1/2",
                      "clear mac address-table dynamic interface Ethernet1/2", before, lab("mac-interface-empty"))
    runtime = runtime_for(tmp_path, device)
    change = clear_request("mac-address-table", "interface:Ethernet1/2")
    approved = execute.preview(runtime, "lab-nxos", change)["plan_sha256"]
    record = execute.apply(runtime, "lab-nxos", change, expected_plan_sha256=approved)
    assert record["result"] == "unknown"


def test_a_configuration_change_during_the_clear_is_reported(tmp_path):
    read, write = "show ip arp %s vrf default" % HOST_IP, "clear ip arp %s vrf default" % HOST_IP
    device = G105Nxos(read, write, lab("arp-hit"), lab("arp-miss"))
    device.on_clear = lambda dev: dev.body.append("ntp server 192.0.2.99")
    runtime = runtime_for(tmp_path, device)
    change = clear_request("ip-arp", HOST_IP)
    approved = execute.preview(runtime, "lab-nxos", change)["plan_sha256"]
    record = execute.apply(runtime, "lab-nxos", change, expected_plan_sha256=approved)
    assert record["result"] == "unknown"
    assert "configuration differs" in [step.get("detail") for step in record["steps"]]


def test_the_command_is_not_repeated_after_an_unverified_apply(tmp_path):
    read, write = "show ip arp %s vrf default" % HOST_IP, "clear ip arp %s vrf default" % HOST_IP
    device = G105Nxos(read, write, lab("arp-hit"), lab("arp-miss").replace("Total number of entries: 0", "Total number of entries: 3"))
    runtime = runtime_for(tmp_path, device)
    change = clear_request("ip-arp", HOST_IP)
    approved = execute.preview(runtime, "lab-nxos", change)["plan_sha256"]
    first = execute.apply(runtime, "lab-nxos", change, expected_plan_sha256=approved)
    assert first["result"] == "unknown"
    assert execute.apply(runtime, "lab-nxos", change, expected_plan_sha256=approved)["change_id"] == first["change_id"]
    assert device.clears == [write]


# ---- refusals read nothing but the targets ----

@pytest.mark.parametrize("table,key,changes,fixture,code", [
    ("mac-address-table", "0000.5e00.5399", {}, "nexus9300v__mac-address-miss.txt", "clear_no_entry"),
    ("ip-arp", "192.0.2.200", {}, "nexus9300v__arp-miss.txt", "clear_no_entry"),
    ("ipv6-neighbor", "2001:db8::1", {}, "nexus9300v__nd-miss.txt", "clear_no_entry"),
    ("port-counters", "Ethernet1/2", {}, "nexus9300v__arp-hit.txt", "clear_readback_unreadable"),
    ("ip-arp", HOST_IP, {"vrf": "nonexist"}, "nexus9300v__arp-bad-vrf.txt", "clear_readback_unreadable"),
    ("ip-arp", HOST_IP, {}, "nexus9300v__mac-address-hit.txt", "clear_readback_unreadable"),
    ("mac-address-table", HOST_MAC, {}, "nexus9300v__arp-hit.txt", "clear_readback_unreadable"),
    # derived: the same MAC in two VLANs on a free port (the captured one is on the uplink)
    ("mac-address-table", "0000.5e00.5307", {}, "two-vlans-free-port", "clear_ambiguous_entry"),
])
def test_real_refusal_is_read_only(tmp_path, table, key, changes, fixture, code):
    if fixture == "two-vlans-free-port":
        text = lab("mac-address-two-vlans").replace("Eth1/1", "Eth1/9")
    else:
        text = captured(fixture)
    device = G105Nxos(nxos_clear.target(table, key, changes).read, "-", text, text)
    runtime = runtime_for(tmp_path, device)
    preview = execute.preview(runtime, "lab-nxos", clear_request(table, key, **changes))
    assert preview["result"] == "rejected" and code in preview["reason_codes"], preview
    assert device.clears == [] and runtime.store.records() == [] and device.saves == 0


@pytest.mark.parametrize("cut", ["header", "total", "row"])
def test_an_incomplete_arp_answer_is_never_complete(tmp_path, cut):
    text = lab("arp-all")
    text = {"header": text.replace("Address         Age", "Addr            Age"),
            "total": text.replace("Total number of entries: 6", "Total number of entries: 7"),
            "row": text.replace("203.0.113.1     00:00:09  0000.5e00.5306  mgmt0", "203.0.113.1     00:00")}[cut]
    target = nxos_clear.target("ip-arp", HOST_IP, {})
    with pytest.raises(Rejected) as refused:
        nxos_clear.observation("ip-arp", target, text)
    assert refused.value.reason_codes == ["clear_readback_unreadable"]


def test_a_mac_answer_with_a_foreign_row_or_without_its_header_is_unreadable():
    target = nxos_clear.target("mac-address-table", "interface:Ethernet1/2", {})
    for text in (lab("mac-interface-trunk"), lab("mac-interface-hit").replace("VLAN     MAC Address", "VLAN     MAC"),
                 lab("mac-interface-hit") + "*   20     0000.5e00.5309   dynamic"):
        with pytest.raises(Rejected) as refused:
            nxos_clear.observation("mac-address-table", target, text)
        assert refused.value.reason_codes == ["clear_readback_unreadable"]


def test_a_counter_answer_without_a_clearing_line_or_a_direction_is_unreadable():
    target = nxos_clear.target("port-counters", "Ethernet1/2", {})
    for text in (COUNTERS.replace('Last clearing of "show interface" counters never', ""),
                 COUNTERS.split("  TX")[0], COUNTERS.replace("  RX\n", ""),
                 COUNTERS.replace("Ethernet1/2 is up", "Ethernet1/3 is up")):
        with pytest.raises(Rejected) as refused:
            nxos_clear.observation("port-counters", target, text)
        assert refused.value.reason_codes == ["clear_readback_unreadable"]


# ---- protections ----

def test_the_management_vrf_and_the_management_interface_are_never_cleared(tmp_path):
    device = G105Nxos("show ip arp 203.0.113.1 vrf management", "-", lab("arp-mgmt"), lab("arp-mgmt"))
    runtime = runtime_for(tmp_path, device)
    preview = execute.preview(runtime, "lab-nxos", clear_request("ip-arp", "203.0.113.1", vrf="management"))
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["clear_protected_target"]
    # the same entry read in the default VRF (derived) still sits on mgmt0
    device = G105Nxos("show ip arp 203.0.113.1 vrf default", "-", lab("arp-mgmt"), lab("arp-mgmt"))
    preview = execute.preview(runtime_for(tmp_path / "b", device), "lab-nxos", clear_request("ip-arp", "203.0.113.1"))
    assert preview["reason_codes"] == ["clear_protected_target"]
    assert device.clears == []


def test_an_uplink_and_a_port_with_a_neighbor_are_not_cleared(tmp_path):
    # the captured table of the trunk port (Eth1/1 is a trunk in show interface trunk)
    device = G105Nxos("show mac address-table interface Ethernet1/1", "-", lab("mac-interface-trunk"), "")
    preview = execute.preview(runtime_for(tmp_path, device), "lab-nxos",
                              clear_request("mac-address-table", "interface:Ethernet1/1"))
    assert preview["reason_codes"] == ["clear_protected_target"]
    for extra in ("lldp_extra", "trunk_extra"):
        device = G105Nxos("show mac address-table interface Ethernet1/9", "-",
                          lab("mac-interface-hit").replace("Eth1/2", "Eth1/9"), "")
        setattr(device, extra, ["Eth1/9"])
        preview = execute.preview(runtime_for(tmp_path / extra, device), "lab-nxos",
                                  clear_request("mac-address-table", "interface:Ethernet1/9"))
        assert preview["reason_codes"] == ["clear_protected_target"], extra
        assert device.clears == []


def test_a_cdp_neighbor_port_is_not_cleared(tmp_path):
    local = "Eth1/9"
    device = G105Nxos("show interface Ethernet1/9", "-", COUNTERS.replace("Ethernet1/2", "Ethernet1/9"), "")
    original = device.query
    device.query = lambda command: CDP.replace("mgmt0", local) if command == "show cdp neighbors" else original(command)
    preview = execute.preview(runtime_for(tmp_path, device), "lab-nxos", clear_request("port-counters", "Ethernet1/9"))
    assert preview["reason_codes"] == ["clear_protected_target"]


@pytest.mark.parametrize("protected,table,key,changes,read_text", [
    ({"interface": ["Ethernet1/2"]}, "port-counters", "Ethernet1/2", {}, COUNTERS),
    ({"interface": ["ethernet1/2"]}, "mac-address-table", "interface:Ethernet1/2", {}, lab("mac-interface-hit")),
    ({"ports": ["Eth1/2"]}, "mac-address-table", HOST_MAC, {}, lab("mac-address-hit")),
    ({"vlan": ["20"]}, "mac-address-table", HOST_MAC, {}, lab("mac-address-hit")),
    ({"vlan": ["20"]}, "ip-arp", HOST_IP, {}, lab("arp-hit")),
    ({"ip-arp": [HOST_IP]}, "ip-arp", HOST_IP, {}, lab("arp-hit")),
])
def test_protected_objects_of_the_inventory_are_not_cleared(tmp_path, protected, table, key, changes, read_text):
    device = G105Nxos(nxos_clear.target(table, key, changes).read, "-", read_text, read_text)
    preview = execute.preview(runtime_for(tmp_path, device, protected), "lab-nxos", clear_request(table, key, **changes))
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["clear_protected_target"], preview
    assert device.clears == []


def test_a_port_channel_peer_link_or_overlay_entry_is_not_cleared(tmp_path):
    for port, flags in (("Po10", "*"), ("nve1", "*"), ("Eth1/9", "+")):
        text = lab("mac-address-hit").replace("*   20", "%s   20" % flags).replace("Eth1/2", port)
        device = G105Nxos(nxos_clear.target("mac-address-table", HOST_MAC, {}).read, "-", text, text)
        preview = execute.preview(runtime_for(tmp_path / port, device), "lab-nxos",
                                  clear_request("mac-address-table", HOST_MAC))
        assert preview["reason_codes"] == ["clear_protected_target"], (port, flags)


def test_an_svi_that_carries_the_admin_session_is_not_cleared(tmp_path):
    # the fake switch reports its SSH session from the 192.0.2.36 peer; an SVI network that holds the peer carries it
    device = G105Nxos("show ip arp 203.0.113.5 vrf default", "-", "", "")
    text = lab("arp-hit").replace(HOST_IP, "203.0.113.5").replace("Vlan20", "Vlan10")
    device.before = device.after = text
    device.body = [line.replace("203.0.113.5/24", "192.0.2.5/24") for line in device.body]
    device.session_vrf = "default"
    preview = execute.preview(runtime_for(tmp_path, device), "lab-nxos", clear_request("ip-arp", "203.0.113.5"))
    assert preview["result"] == "rejected", preview
    assert preview["reason_codes"] in (["port_management_interface"], ["clear_protected_target"]), preview
    assert device.clears == []


def test_an_unreadable_check_account_refuses_the_clear(tmp_path):
    device = G105Nxos(nxos_clear.target("ip-arp", HOST_IP, {}).read, "-", "", "")
    device.check_unreadable = True
    preview = execute.preview(runtime_for(tmp_path, device), "lab-nxos", clear_request("ip-arp", HOST_IP))
    assert preview["reason_codes"] == ["clear_readback_unreadable"]
    assert device.clears == []


def test_a_clear_does_not_need_the_scheduler_or_a_saved_configuration(tmp_path):
    read, write = "show ip arp %s vrf default" % HOST_IP, "clear ip arp %s vrf default" % HOST_IP
    device = G105Nxos(read, write, lab("arp-hit"), lab("arp-miss"))
    device.scheduler_enabled = False
    device.body.append("ntp server 192.0.2.98")       # an unsaved change of someone else
    device.config_sessions = ["foreign-session"]
    runtime = runtime_for(tmp_path, device)
    change = clear_request("ip-arp", HOST_IP)
    approved = execute.preview(runtime, "lab-nxos", change)
    assert approved["result"] == "ready"
    assert execute.apply(runtime, "lab-nxos", change, expected_plan_sha256=approved["plan_sha256"])[
        "result"] == "confirmed"


def test_an_untested_version_is_a_warning_and_never_a_block(tmp_path):
    from netops_admin import engine
    read, write = "show ip arp %s vrf default" % HOST_IP, "clear ip arp %s vrf default" % HOST_IP
    device = G105Nxos(read, write, lab("arp-hit"), lab("arp-miss"))
    runtime = runtime_for(tmp_path, device)
    change = clear_request("ip-arp", HOST_IP)
    target = nxos_clear.target(change.table, change.key, change.changes)
    before = nxos_clear.observation(change.table, target, lab("arp-hit"))
    plan = engine.build_clear_plan(runtime.config.devices["lab-nxos"], device.running(), change, target, before,
                                   firmware="10.2(5)")
    assert plan["firmware"] == "10.2(5)" and plan["commands"] == [write]
    assert plan["firmware_support"]["status"] == "untested"
    assert plan["firmware_support"]["tested_versions"] == ["9.3(12)"]
    tested_plan = engine.build_clear_plan(runtime.config.devices["lab-nxos"], device.running(), change, target,
                                          before, firmware=FIRMWARE)
    assert tested_plan["firmware_support"]["status"] == "tested"
    assert plan["plan_sha256"] != tested_plan["plan_sha256"]       # the warning is bound into the approved plan


def test_a_switch_without_the_lldp_feature_has_no_lldp_neighbors(tmp_path):
    # With LLDP disabled on Nexus 9300v, `show lldp neighbors` returns a syntax error.
    read, write = "show interface Ethernet1/2", "clear counters interface Ethernet1/2"
    device = G105Nxos(read, write, COUNTERS, COUNTERS_CLEARED)
    feature = device.query("show feature")
    assert "lldp" in feature
    original = device.query

    def query(command):
        if command == "show feature":
            return re.sub(r"(lldp\s+1\s+)enabled ", r"\1disabled", feature)
        if command == "show lldp neighbors":
            raise AssertionError("the LLDP list of a switch without the feature is not read")
        return original(command)

    device.query = query
    preview = execute.preview(runtime_for(tmp_path, device), "lab-nxos", clear_request("port-counters", "Ethernet1/2"))
    assert preview["result"] == "ready", preview


def test_an_unknown_lldp_feature_state_refuses_the_clear(tmp_path):
    device = G105Nxos("show interface Ethernet1/2", "-", COUNTERS, COUNTERS_CLEARED)
    original = device.query
    device.query = lambda command: "" if command == "show feature" else original(command)
    preview = execute.preview(runtime_for(tmp_path, device), "lab-nxos", clear_request("port-counters", "Ethernet1/2"))
    assert preview["result"] == "rejected" and device.clears == []


def test_the_safeguard_of_another_operation_does_not_block_a_clear(tmp_path):
    # Other Admin operations can leave timed safeguards on the same Nexus 9300v.
    read, write = "show ip arp %s vrf default" % HOST_IP, "clear ip arp %s vrf default" % HOST_IP
    device = G105Nxos(read, write, lab("arp-hit"), lab("arp-miss"))
    device.files = {"netops-48e8f155cbf8-pred.cfg"}
    runtime = runtime_for(tmp_path, device)
    change = clear_request("ip-arp", HOST_IP)
    preview = execute.preview(runtime, "lab-nxos", change)
    assert preview["result"] == "ready", preview
    assert execute.apply(runtime, "lab-nxos", change, expected_plan_sha256=preview["plan_sha256"])[
        "result"] == "confirmed"
    # a configuration change of a safeguard-less kind still sees it: the configuration change path is untouched
    other = FakeNxos()
    other.files = {"netops-48e8f155cbf8-pred.cfg"}
    assert any("48e8f155cbf8" in name for name in execute.exec_nxos.leftovers(other))


def _slow_clear(monkeypatch, device, seconds):
    """The clear session and the readback take `seconds` more than the preparation (a jump of the wall clock)."""
    offset, original = [0], execute.time.time
    monkeypatch.setattr(execute.time, "time", lambda: original() + offset[0])
    device.on_clear = lambda dev: offset.__setitem__(0, seconds)


def test_a_young_arp_entry_is_judged_by_the_elapsed_time_not_by_its_absolute_age(tmp_path, monkeypatch):
    # NX-OS refreshes a cleared ARP entry at once: an entry 3 s old before the clear is 5 s old a little later,
    # although the clear worked. The readback compares with the age an untouched entry would have by now.
    read, write = "show ip arp %s vrf default" % HOST_IP, "clear ip arp %s vrf default" % HOST_IP
    before = lab("arp-hit").replace("00:14:03", "00:00:03")
    device = G105Nxos(read, write, before, before.replace("00:00:03", "00:00:05"))
    runtime = runtime_for(tmp_path, device)
    change = clear_request("ip-arp", HOST_IP)
    approved = execute.preview(runtime, "lab-nxos", change)["plan_sha256"]
    _slow_clear(monkeypatch, device, 30)
    record = execute.apply(runtime, "lab-nxos", change, expected_plan_sha256=approved)
    assert record["result"] == "confirmed" and "relearned" in steps(record)


def test_an_untouched_arp_entry_is_never_taken_for_a_cleared_one(tmp_path, monkeypatch):
    read, write = "show ip arp %s vrf default" % HOST_IP, "clear ip arp %s vrf default" % HOST_IP
    before = lab("arp-hit").replace("00:14:03", "00:00:03")
    device = G105Nxos(read, write, before, before.replace("00:00:03", "00:00:35"))   # 3 s + the 32 s that passed
    runtime = runtime_for(tmp_path, device)
    change = clear_request("ip-arp", HOST_IP)
    approved = execute.preview(runtime, "lab-nxos", change)["plan_sha256"]
    _slow_clear(monkeypatch, device, 32)
    record = execute.apply(runtime, "lab-nxos", change, expected_plan_sha256=approved)
    assert record["result"] == "unknown" and "postcheck_failed" in steps(record)


def test_an_arp_entry_younger_than_a_second_is_read_with_its_fractional_age(tmp_path):
    # On Nexus 9300v, right after `clear ip arp` the refreshed entry shows its age as 0.965201 (seconds)
    assert nxos_clear._seconds("0.333114") == 0 and nxos_clear._seconds("00:14:03") == 843
    read, write = "show ip arp %s vrf default" % HOST_IP, "clear ip arp %s vrf default" % HOST_IP
    device = G105Nxos(read, write, lab("arp-hit"), lab("arp-hit").replace("00:14:03", "0.965201"))
    runtime = runtime_for(tmp_path, device)
    change = clear_request("ip-arp", HOST_IP)
    approved = execute.preview(runtime, "lab-nxos", change)["plan_sha256"]
    record = execute.apply(runtime, "lab-nxos", change, expected_plan_sha256=approved)
    assert record["result"] == "confirmed" and "relearned" in steps(record)
    [entry] = record["readback"]["entries"]
    assert entry["age"] == 0 and entry["relearned"] is True


@pytest.mark.parametrize("failing", ["show interface trunk", "show cdp neighbors", "show feature", "show version"])
def test_a_failed_or_timed_out_preflight_read_has_its_own_reason_code(tmp_path, failing):
    from netops_admin.access import AccessError
    device = G105Nxos("show interface Ethernet1/2", "-", COUNTERS, COUNTERS_CLEARED)
    original = device.query

    def query(command):
        if command == failing:
            raise AccessError("query failed: ssh to 192.0.2.55 did not finish within 60.0 seconds")
        return original(command)

    device.query = query
    preview = execute.preview(runtime_for(tmp_path, device), "lab-nxos", clear_request("port-counters", "Ethernet1/2"))
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["clear_readback_unreadable"], preview
    assert device.clears == [] and runtime_for(tmp_path / "x", device).store.records() == []
