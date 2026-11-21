"""1.0.12 G130: targeted EOS clear of port counters, one MAC, one ARP/ND entry and a BGP soft refresh.

The reads are captured outputs of cEOSLab 4.36.1F (b04-eos-a and d-ceos, anonymised; fixtures/eos_g130/PROVENANCE.md). The
answers after a clear are the real ones that the lab gave. A state that the lab did not produce (a failed clear, an entry
learned again with an old age, a session reset, a second VLAN, a port-channel member) substitutes only the named value of
a captured text; every such test says so."""
import copy
import dataclasses
import json
import re
from pathlib import Path

import pytest

from fake_eos import FIXTURES as EOS_FIXTURES, FakeEos
from netops_admin import eos_clear, execute
from netops_admin.access import AccessError
from netops_admin.errors import Rejected
from test_eos import FIRMWARE, make_runtime, request, steps

FIXTURES = Path(__file__).parent / "fixtures" / "eos_g130"
G125 = Path(__file__).parent / "fixtures" / "eos_g125"
TARGET = "lab-ceos"


def captured(name):
    return (FIXTURES / ("b04-a__" + name + ".txt")).read_text()


def swap(text, old, new, count=1):
    assert text.count(old) >= count, (old, text[:200])
    return text.replace(old, new)


PORT = "Ethernet5"
MAC = "0000.5e00.5302"
VLAN = "3931"
IP = "198.51.100.11"
IP6 = "2001:db8:1::11"
PEER = "192.0.2.2"

COUNTERS_BEFORE = captured("show-interfaces-ethernet5-before")
COUNTERS_AFTER = captured("show-interfaces-ethernet5-after-clear")
MAC_BEFORE, MAC_AFTER, MAC_RELEARNED = (captured("show-mac-json-" + name) for name in ("before", "after-clear", "relearned"))
ARP_BEFORE, ARP_AFTER, ARP_RELEARNED = (captured("show-ip-arp-json-" + name) for name in ("before", "after-clear", "relearned"))
ND_BEFORE, ND_AFTER = captured("show-ipv6-neighbors-json-before"), captured("show-ipv6-neighbors-json-after-clear")
BGP_BEFORE, BGP_IN, BGP_OUT = (captured("show-bgp-neighbor-json-" + name) for name in ("before", "after-soft-in", "after-soft-out"))
LLDP = captured("show-lldp-neighbors-json")
SWITCHPORT = captured("show-interfaces-ethernet5-switchport")


class G130Eos(FakeEos):
    """The measured cEOS with the lab objects of the clear: Ethernet5 an access port of VLAN 3931 whose SVI is in a VRF."""

    def __init__(self, read, write, before, after, *, address=None):
        super().__init__()
        self.read, self.write, self.before, self.after = read, write, before, after
        self.clears, self.on_clear = [], None
        self.line_guard = None
        self.queries = []
        self.late_reads = 0   # reads after the clear that still show the state before it (a counter that follows late)
        self.lldp = LLDP
        self.answers = {}
        self.channel = None
        self.vrf_of_svi = "G130"
        start = self.lines.index("interface Ethernet5")
        end = start + 1
        while self.lines[end].startswith(" "):
            end += 1
        self.lines[start:end] = ["interface Ethernet5", "   switchport access vlan 3931"]
        at = self.lines.index("end")
        self.lines[at:at] = ["vlan 3931", "   name G130-EP", "!", "interface Vlan3931", "   vrf G130",
                             "   ip address 203.0.113.131/24", "!"]
        self.saved = list(self.lines)

    def _read(self, command):
        if command in self.answers:
            answer = self.answers[command]
            if isinstance(answer, Exception):
                raise answer
            return answer
        return None

    def check_query_status(self, command):
        self.check_queries.append(command)
        if self.check_unreadable:
            raise AccessError("check account unavailable")
        answer = self._read(command)
        if answer is not None:
            return answer if isinstance(answer, tuple) else (0, answer)
        if command == self.read:
            if self.clears and self.late_reads:
                self.late_reads -= 1
                return 0, self.before
            return 0, self.after if self.clears else self.before
        if command == "show interfaces Ethernet5 status | json":
            data = json.loads((G125 / "ethernet-member-status.json").read_text())
            row = data["interfaceStatuses"].pop("Ethernet12")
            row["vlanInformation"] = ({"vlanId": 3931, "interfaceMode": "bridged", "interfaceForwardingModel": "bridged"}
                                      if self.channel is None else
                                      {"vlanExplanation": "in Po%s" % self.channel, "interfaceForwardingModel": "dataLink"})
            data["interfaceStatuses"]["Ethernet5"] = row
            return 0, json.dumps(data)
        if command == "show port-channel dense | json":
            data = json.loads((G125 / "channel-dense-passive.json").read_text())
            row = data["portChannels"].pop("Port-Channel900")
            row["ports"] = {"Ethernet5": dict(next(iter(row["ports"].values())), intf="Ethernet5")}
            data["portChannels"]["Port-Channel%s" % self.channel] = row
            return 0, json.dumps(data)
        return self.query_status(command)

    def query(self, command):
        self.queries.append(command)
        answer = self._read(command)
        if answer is not None:
            return answer
        if command == "show lldp neighbors | json":
            return self.lldp
        if command == "show interfaces Ethernet5 switchport":
            return SWITCHPORT
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


FRESH = iter(range(10 ** 6))


def runtime_for(tmp_path, device, protected=None):
    # every runtime has its own state: a repeated request id and the hourly budget of refusals belong to one state
    runtime = make_runtime(tmp_path / ("state%d" % next(FRESH)), device)
    if protected:
        runtime.config.devices[TARGET] = dataclasses.replace(runtime.config.devices[TARGET], protected=protected)
    return runtime


def clear_request(table, key, **changes):
    return request(op="clear", table=table, key=key, changes=changes)


# ---- the request: one explicit object, never a whole table ----

@pytest.mark.parametrize("table,key,changes,read,write", [
    ("port-counters", "Ethernet5", {}, "show interfaces Ethernet5", "clear counters Ethernet5"),
    ("port-counters", "et5", {}, "show interfaces Ethernet5", "clear counters Ethernet5"),
    ("port-counters", "Ethernet1/2/3", {}, "show interfaces Ethernet1/2/3", "clear counters Ethernet1/2/3"),
    ("mac-address-table", "00:00:5E:00:53:02", {}, "show mac address-table address 0000.5e00.5302 | json", None),
    ("mac-address-table", "0000.5e00.5302", {"vlan": "3931"},
     "show mac address-table address 0000.5e00.5302 | json", None),
    ("ip-arp", IP, {}, "show ip arp vrf default %s | json" % IP, "clear arp " + IP),
    ("ip-arp", IP, {"vrf": "blue"}, "show ip arp vrf blue %s | json" % IP, "clear arp vrf blue " + IP),
    ("ipv6-neighbor", "2001:DB8:1::11", {"interface": "Vlan3931"}, "show ipv6 neighbors vrf default %s | json" % IP6, None),
    ("ipv6-neighbor", IP6, {"vrf": "blue"}, "show ipv6 neighbors vrf blue %s | json" % IP6, None),
    ("bgp-refresh", PEER, {"direction": "in"}, "show ip bgp neighbors %s | json" % PEER, "clear ip bgp %s soft in" % PEER),
    ("bgp-refresh", PEER, {"direction": "out"}, "show ip bgp neighbors %s | json" % PEER, "clear ip bgp %s soft out" % PEER),
])
def test_the_verified_selectors_are_rendered_with_one_object(table, key, changes, read, write):
    target = eos_clear.target(table, key, changes)
    assert (target.read, target.write) == (read, write)


@pytest.mark.parametrize("table,key,changes", [
    ("port-counters", "all", {}),
    ("port-counters", "Ethernet1-4", {}),
    ("port-counters", "Ethernet1,Ethernet2", {}),
    ("port-counters", "Ethernet5.10", {}),
    ("port-counters", "Port-Channel10", {}),
    ("port-counters", "Management0", {}),
    ("port-counters", "Vlan3931", {}),
    ("port-counters", "Ethernet5", {"session": "yes"}),
    ("mac-address-table", "all", {}),
    ("mac-address-table", "interface:Ethernet5", {}),
    ("mac-address-table", "ffff.ffff.ffff", {}),
    ("mac-address-table", "0100.5e00.0001", {}),
    ("mac-address-table", "0000.0000.0000", {}),
    ("mac-address-table", MAC, {"vlan": "0"}),
    ("mac-address-table", MAC, {"vlan": "4095"}),
    ("mac-address-table", MAC, {"vlan": "3931; clear mac"}),
    ("mac-address-table", MAC, {"interface": "Ethernet5"}),
    ("ip-arp", "0.0.0.0", {}),
    ("ip-arp", "224.0.0.5", {}),
    ("ip-arp", "255.255.255.255", {}),
    ("ip-arp", "127.0.0.1", {}),
    ("ip-arp", "198.51.100.0/24", {}),
    ("ip-arp", "all", {}),
    ("ip-arp", IP, {"vrf": "all"}),
    ("ip-arp", IP, {"vrf": "ALL"}),
    ("ip-arp", IP, {"vrf": "blue; clear arp"}),
    ("ip-arp", IP, {"interface": "Vlan3931"}),
    ("ip-arp", IP6, {}),
    ("ipv6-neighbor", IP6, {"vrf": "all"}),
    ("ipv6-neighbor", "ff02::1", {}),
    ("ipv6-neighbor", "::", {}),
    ("ipv6-neighbor", "::1", {}),
    ("ipv6-neighbor", "fe80::1%Vlan3931", {}),
    ("ipv6-neighbor", IP6, {"interface": "Management0"}),
    ("ipv6-neighbor", IP6, {"interface": "Loopback0"}),
    ("ipv6-neighbor", IP, {}),
    ("bgp-refresh", PEER, {}),
    ("bgp-refresh", PEER, {"direction": "both"}),
    ("bgp-refresh", PEER, {"direction": "in", "vrf": "blue"}),
    ("bgp-refresh", "*", {"direction": "in"}),
    ("bgp-refresh", "0.0.0.0", {"direction": "in"}),
    ("bgp-refresh", "2001:db8::2", {"direction": "in"}),
    ("bgp-refresh", "peer-group", {"direction": "out"}),
])
def test_a_clear_without_one_explicit_object_is_refused_before_the_device_is_contacted(tmp_path, table, key, changes):
    device = G130Eos("-", "-", "", "")
    runtime = runtime_for(tmp_path, device)
    preview = execute.preview(runtime, TARGET, clear_request(table, key, **changes))
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["clear_invalid_target"], preview
    assert device.clears == [] and device.queries == [] and device.check_queries == []
    assert runtime.store.records() == []


def test_a_table_without_clear_and_a_clear_with_endpoint_impact_are_unsupported(tmp_path):
    device = G130Eos("-", "-", "", "")
    runtime = runtime_for(tmp_path, device)
    for change in (clear_request("vlan", "10"), request(op="clear", table="port-counters", key=PORT, changes={},
                                                            endpoint_impact=PORT)):
        with pytest.raises(Rejected) as refused:
            execute.apply(runtime, TARGET, change, expected_plan_sha256="0" * 64)
        assert refused.value.reason_codes == ["action_unsupported"]
    assert device.clears == [] and device.queries == []


# ---- preview, confirmed apply, readback ----

CASES = {
    "counters": ("port-counters", PORT, {}, "show interfaces Ethernet5", "clear counters Ethernet5",
                 COUNTERS_BEFORE, COUNTERS_AFTER),
    "mac": ("mac-address-table", MAC, {}, "show mac address-table address %s | json" % MAC,
            "clear mac address-table dynamic vlan %s address %s" % (VLAN, MAC), MAC_BEFORE, MAC_AFTER),
    "arp": ("ip-arp", IP, {}, "show ip arp vrf default %s | json" % IP, "clear arp " + IP, ARP_BEFORE, ARP_AFTER),
    "nd": ("ipv6-neighbor", IP6, {}, "show ipv6 neighbors vrf default %s | json" % IP6,
           "clear ipv6 neighbors Vlan3931 " + IP6, ND_BEFORE, ND_AFTER),
    "bgp-in": ("bgp-refresh", PEER, {"direction": "in"}, "show ip bgp neighbors %s | json" % PEER,
               "clear ip bgp %s soft in" % PEER, BGP_BEFORE, BGP_IN),
    "bgp-out": ("bgp-refresh", PEER, {"direction": "out"}, "show ip bgp neighbors %s | json" % PEER,
                "clear ip bgp %s soft out" % PEER, BGP_BEFORE, BGP_OUT),
}


def case_device(case):
    table, key, changes, read, write, before, after = CASES[case]
    device = G130Eos(read, write, before, after)
    if table == "bgp-refresh":
        # the BGP neighbor is directly connected in the lab (a /30 on Vlan3930); make the lab address
        # of the fixture (anonymised to 192.0.2.0/24) connected on an SVI of the default VRF
        at = device.lines.index("end")
        device.lines[at:at] = ["interface Vlan3930", "   ip address 192.0.2.1/30", "!"]
        device.saved = list(device.lines)
    return device, clear_request(table, key, **changes), write


@pytest.mark.parametrize("case", sorted(CASES))
def test_preview_confirmed_apply_readback_and_no_undo(tmp_path, case):
    device, change, write = case_device(case)
    runtime = runtime_for(tmp_path, device)
    baseline = list(device.lines)
    preview = execute.preview(runtime, TARGET, change)
    assert preview["result"] == "ready", preview
    assert preview["commands"] == [write] and preview["inverse_commands"] == 0
    assert preview["safeguard_seconds"] is None and preview["return_mechanism"] == "irreversible"
    assert preview["firmware_support"]["status"] == "tested"
    assert device.clears == [] and runtime.store.records() == []
    with pytest.raises(Rejected) as refused:
        execute.apply(runtime, TARGET, change)
    assert refused.value.reason_codes == ["clear_preview_required"] and device.clears == []
    with pytest.raises(Rejected) as refused:
        execute.apply(runtime, TARGET, change, expected_plan_sha256="0" * 64)
    assert refused.value.reason_codes == ["plan_changed"] and device.clears == []
    result = execute.apply(runtime, TARGET, change, expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "confirmed", result
    assert device.clears == [write] and device.lines == baseline and device.saves == 0
    record = runtime.store.operation(result["change_id"])
    assert record["kind"] == "eos-clear" and steps(record)[-1] == "postcheck_passed"
    assert record["readback"] is not None
    for undo in (execute.preview_undo, execute.undo):
        with pytest.raises(Rejected) as refused:
            undo(runtime, result["change_id"], "verify irreversible operation")
        assert refused.value.reason_codes == ["undo_not_applicable"]
    assert execute.apply(runtime, TARGET, change, expected_plan_sha256=preview["plan_sha256"])["change_id"] \
        == result["change_id"]
    assert device.clears == [write]


def test_a_cleared_port_reports_the_new_clearing_time_in_its_readback(tmp_path):
    device, change, _ = case_device("counters")
    runtime = runtime_for(tmp_path, device)
    preview = execute.preview(runtime, TARGET, change)
    result = execute.apply(runtime, TARGET, change, expected_plan_sha256=preview["plan_sha256"])
    record = runtime.store.operation(result["change_id"])
    assert record["readback"]["clearing"] == 2 and record["plan"]["predicted"]["before"]["clearing"] is None
    assert record["readback"]["counters"]["in_packets"] == 0 and record["plan"]["predicted"]["before"][
        "counters"]["in_packets"] == 103


# ---- what is not an effect: the same value before and after, or a stale one, is not confirmed ----

def failed(tmp_path, case, after, expect_step="postcheck_failed", reason="clear readback mismatch"):
    device, change, write = case_device(case)
    device.after = after
    runtime = runtime_for(tmp_path, device)
    preview = execute.preview(runtime, TARGET, change)
    result = execute.apply(runtime, TARGET, change, expected_plan_sha256=preview["plan_sha256"])
    record = runtime.store.operation(result["change_id"])
    assert result["result"] == "unknown" and expect_step in steps(record), (result, steps(record))
    assert reason in json.dumps(result) or reason in json.dumps(record["steps"])
    assert device.clears == [write]
    return record


def test_unchanged_counters_and_a_stale_clearing_time_are_not_a_clear(tmp_path):
    failed(tmp_path, "counters", COUNTERS_BEFORE)
    # derived: the captured read after the clear, with a clearing time that is older than the command
    failed(tmp_path, "counters", swap(COUNTERS_AFTER, "counters 0:00:02 ago", "counters 0:09:02 ago"))
    # derived: counters that kept growing after the clear
    failed(tmp_path, "counters", swap(COUNTERS_AFTER, "0 packets input, 0 bytes", "50000 packets input, 9999999 bytes"))
    # derived: the clearing time is there, the counters were not reset
    failed(tmp_path, "counters", swap(COUNTERS_BEFORE, "counters never", "counters 0:00:02 ago"))


def test_an_incomplete_or_foreign_counter_answer_is_unverified_never_confirmed(tmp_path):
    for text in (COUNTERS_AFTER.replace('Last clearing of "show interface" counters 0:00:02 ago\n', ""),
                 COUNTERS_AFTER.replace("0:00:02 ago", "2 seconds ago"),
                 COUNTERS_AFTER.replace("Ethernet5 is up", "Ethernet6 is up"),
                 COUNTERS_AFTER.replace("     1 packets output, 122 bytes\n", ""),
                 "% Invalid input\n", "", COUNTERS_AFTER + COUNTERS_AFTER):
        failed(tmp_path, "counters", text, "postcheck_failed", "clear readback unavailable")


def test_a_mac_that_is_still_there_with_its_old_learning_time_is_not_a_clear(tmp_path):
    failed(tmp_path, "mac", MAC_BEFORE)
    # derived: another MAC of the VLAN appeared in the answer of a filter for one address
    other = json.loads(MAC_AFTER)
    other["unicastTable"]["tableEntries"].append(json.loads(MAC_BEFORE)["unicastTable"]["tableEntries"][0]
                                                 | {"macAddress": "00:00:5e:00:53:03"})
    failed(tmp_path, "mac", json.dumps(other), "postcheck_failed", "clear readback unavailable")


def test_a_mac_learned_again_by_live_traffic_is_confirmed_and_marked(tmp_path):
    device, change, write = case_device("mac")
    device.after = MAC_RELEARNED
    runtime = runtime_for(tmp_path, device)
    preview = execute.preview(runtime, TARGET, change)
    result = execute.apply(runtime, TARGET, change, expected_plan_sha256=preview["plan_sha256"])
    record = runtime.store.operation(result["change_id"])
    assert result["result"] == "confirmed" and "relearned" in steps(record)
    assert record["readback"]["entries"][0]["relearned"] is True


def test_a_mac_of_another_vlan_stays_and_the_vlan_selects_the_entry(tmp_path):
    # derived: the captured entry plus a second entry of the same MAC in VLAN 3932 on the same port (what the lab never held)
    first = json.loads(MAC_BEFORE)["unicastTable"]["tableEntries"][0]
    second = dict(first, vlanId=3932)
    both = json.loads(MAC_BEFORE)
    both["unicastTable"]["tableEntries"].append(second)
    only_first, only_second = json.loads(MAC_AFTER), json.loads(MAC_AFTER)
    only_first["unicastTable"]["tableEntries"].append(first)
    only_second["unicastTable"]["tableEntries"].append(second)
    device = G130Eos("show mac address-table address %s | json" % MAC,
                     "clear mac address-table dynamic vlan 3932 address " + MAC, json.dumps(both), json.dumps(only_first))
    runtime = runtime_for(tmp_path, device)
    ambiguous = execute.preview(runtime, TARGET, clear_request("mac-address-table", MAC))
    assert ambiguous["result"] == "rejected" and ambiguous["reason_codes"] == ["clear_ambiguous_entry"]
    change = clear_request("mac-address-table", MAC, vlan="3932")
    preview = execute.preview(runtime, TARGET, change)
    assert preview["result"] == "ready" and preview["commands"] == [device.write], preview
    result = execute.apply(runtime, TARGET, change, expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "confirmed", result
    # the other VLAN lost its entry as well: not the clear that was approved
    device.clears.clear()
    device.after = json.dumps(only_second)
    device.write = "clear mac address-table dynamic vlan 3931 address " + MAC
    change = request(op="clear", table="mac-address-table", key=MAC, changes={"vlan": "3931"},
                     request_id="req-0002-example")
    preview = execute.preview(runtime, TARGET, change)
    assert preview["commands"] == [device.write], preview
    device.after = MAC_AFTER
    result = execute.apply(runtime, TARGET, change, expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "unknown" and "clear readback mismatch" in json.dumps(result)


def test_other_vlan_dynamic_mac_movement_does_not_hide_a_proven_clear(tmp_path):
    # Derived from the captured MAC table: the selected row disappears while the same dynamic MAC moves in another VLAN.
    before = json.loads(MAC_BEFORE)
    selected, = before["unicastTable"]["tableEntries"]
    other = dict(selected, vlanId=int(VLAN) + 1)
    before["unicastTable"]["tableEntries"].append(other)
    after = json.loads(MAC_AFTER)
    after["unicastTable"]["tableEntries"].append(dict(other, interface="Ethernet6"))
    device, _, _ = case_device("mac")
    device.before, device.after = json.dumps(before), json.dumps(after)
    change = clear_request("mac-address-table", MAC, vlan=VLAN)
    runtime = runtime_for(tmp_path, device)
    plan = execute.preview(runtime, TARGET, change)
    assert plan["result"] == "ready", plan
    result = execute.apply(runtime, TARGET, change, expected_plan_sha256=plan["plan_sha256"])
    assert result["result"] == "confirmed", result


def test_an_arp_entry_that_stays_with_its_old_age_is_not_a_clear_but_a_new_one_is(tmp_path):
    failed(tmp_path, "arp", ARP_BEFORE)
    # derived: the same entry, its age grown by the elapsed time (the clear did nothing)
    failed(tmp_path, "arp", swap(ARP_BEFORE, "16953012", "16953020"))
    device, change, _ = case_device("arp")
    device.after = ARP_RELEARNED
    runtime = runtime_for(tmp_path, device)
    preview = execute.preview(runtime, TARGET, change)
    result = execute.apply(runtime, TARGET, change, expected_plan_sha256=preview["plan_sha256"])
    record = runtime.store.operation(result["change_id"])
    assert result["result"] == "confirmed" and "relearned" in steps(record)
    assert record["readback"]["entries"][0]["relearned"] is True


@pytest.mark.parametrize("case", ["bgp-in", "bgp-out"])
def test_an_unchanged_bgp_exchange_or_a_reset_session_is_not_a_soft_refresh(tmp_path, case):
    failed(tmp_path, case, BGP_BEFORE)
    # derived: the refresh counter grew but the session was reset (a hard clear), not a soft refresh
    reset = json.loads(BGP_IN if case == "bgp-in" else BGP_OUT)
    reset["vrfs"]["default"]["peerList"][0]["establishedTransitions"] = 2
    failed(tmp_path, case, json.dumps(reset))
    # derived: the session is not Established after the refresh
    down = json.loads(BGP_IN if case == "bgp-in" else BGP_OUT)
    down["vrfs"]["default"]["peerList"][0]["state"] = "Idle"
    failed(tmp_path, case, json.dumps(down))
    failed(tmp_path, case, json.dumps({"vrfs": {"default": {"peerList": []}}}))


def test_a_soft_out_is_not_proven_by_the_counter_of_a_soft_in(tmp_path):
    failed(tmp_path, "bgp-out", BGP_IN)


def test_a_stale_soft_out_event_and_an_ordinary_update_do_not_prove_clear(tmp_path):
    # Derived from the recorded soft-out with no new begin-of-refresh marker and the same lastEvent.
    after = json.loads(BGP_OUT)
    stats = after["vrfs"]["default"]["peerList"][0]["outMessageStats"]
    stats["updates"] += 1
    device, change, _ = case_device("bgp-out")
    device.before, device.after = BGP_OUT, json.dumps(after)
    runtime = runtime_for(tmp_path, device)
    plan = execute.preview(runtime, TARGET, change)
    assert plan["result"] == "ready", plan
    result = execute.apply(runtime, TARGET, change, expected_plan_sha256=plan["plan_sha256"])
    assert result["result"] == "unknown", result


# ---- scopes that are refused with their own code, nothing is sent ----

def refused_preview(tmp_path, case, *, protected=None, code, edit=None, answers=None, device=None):
    device, change, _ = case_device(case) if device is None else device
    if edit is not None:
        edit(device)
    device.answers.update(answers or {})
    runtime = runtime_for(tmp_path, device, protected)
    preview = execute.preview(runtime, TARGET, change)
    assert preview["result"] == "rejected" and preview["reason_codes"] == [code], preview
    with pytest.raises(Rejected) as refused:
        execute.apply(runtime, TARGET, change, expected_plan_sha256="0" * 64)
    assert device.clears == [] and runtime.store.records() == []
    return preview


@pytest.mark.parametrize("case,empty", [("mac", MAC_AFTER), ("arp", ARP_AFTER), ("nd", ND_AFTER)])
def test_a_scope_without_a_learned_entry_is_refused(tmp_path, case, empty):
    refused_preview(tmp_path, case, code="clear_no_entry", edit=lambda device: setattr(device, "before", empty))


def test_a_static_entry_is_not_cleared(tmp_path):
    refused_preview(tmp_path, "arp", code="clear_no_entry",
                    edit=lambda device: setattr(device, "before", captured("show-ip-arp-json-static").replace("198.51.100.250", IP)))
    refused_preview(tmp_path, "nd", code="clear_no_entry",
                    edit=lambda device: setattr(device, "before", captured("show-ipv6-neighbors-json-static").replace(
                        "2001:db8:1::250", IP6)))


def test_an_ipv6_neighbor_on_another_interface_than_named_is_refused(tmp_path):
    device, _, write = case_device("nd")
    change = clear_request("ipv6-neighbor", IP6, interface="Ethernet6")
    refused_preview(tmp_path, "nd", code="clear_invalid_target", device=(device, change, write))


def test_a_vrf_or_a_port_that_does_not_exist_is_an_invalid_target(tmp_path):
    table, key, changes, read, write, before, after = CASES["arp"]
    device = G130Eos("show ip arp vrf nosuch %s | json" % IP, "-", "", "")
    device.answers[device.read] = (1, captured("show-ip-arp-vrf-absent"))
    refused_preview(tmp_path, "arp", code="clear_invalid_target",
                    device=(device, clear_request("ip-arp", IP, vrf="nosuch"), write))
    device = G130Eos("show interfaces Ethernet99", "-", "", "")
    device.answers[device.read] = (1, captured("show-interfaces-invalid"))
    refused_preview(tmp_path, "counters", code="clear_invalid_target",
                    device=(device, clear_request("port-counters", "Ethernet99"), "-"))


def test_a_bgp_neighbor_that_is_absent_down_or_without_route_refresh_is_refused(tmp_path):
    refused_preview(tmp_path, "bgp-in", code="clear_no_entry",
                    edit=lambda device: setattr(device, "before", captured("show-bgp-neighbor-json-absent")))
    down = json.loads(BGP_BEFORE)
    down["vrfs"]["default"]["peerList"][0]["state"] = "Active"
    refused_preview(tmp_path, "bgp-out", code="clear_no_entry", edit=lambda device: setattr(device, "before", json.dumps(down)))
    # derived: the capability that the soft in needs is not negotiated; soft out needs no such capability
    plain = json.loads(BGP_BEFORE)
    plain["vrfs"]["default"]["peerList"][0]["neighborCapabilities"]["routeRefreshCap"]["enabled"] = False
    refused_preview(tmp_path, "bgp-in", code="clear_invalid_target", edit=lambda device: setattr(device, "before", json.dumps(plain)))
    device, change, _ = case_device("bgp-out")
    device.before = json.dumps(plain)
    assert execute.preview(runtime_for(tmp_path, device), TARGET, change)["result"] == "ready"


# ---- protections ----

@pytest.mark.parametrize("case,protected", [
    ("counters", {"interface": ["Ethernet5"]}),
    ("counters", {"ports": ["ethernet5"]}),
    ("counters", {"vlan": ["3931"]}),
    ("counters", {"port-counters": ["Ethernet5"]}),
    ("mac", {"interface": ["Ethernet5"]}),
    ("mac", {"vlan": ["3931"]}),
    ("mac", {"interface": ["Vlan3931"]}),
    ("mac", {"mac-address-table": [MAC]}),
    ("arp", {"interface": ["Vlan3931"]}),
    ("arp", {"interface": ["Ethernet5"]}),
    ("arp", {"vlan": ["3931"]}),
    ("arp", {"ip-arp": [IP]}),
    ("nd", {"interface": ["Vlan3931"]}),
    ("nd", {"vlan": ["3931"]}),
    ("nd", {"ipv6-neighbor": [IP6]}),
    ("bgp-in", {"bgp-refresh": [PEER]}),
    ("bgp-out", {"interface": ["Vlan3930"]}),
])
def test_protected_objects_are_refused_for_every_kind_of_interface(tmp_path, case, protected):
    refused_preview(tmp_path, case, protected=protected, code="clear_protected_target")


def test_the_management_vrf_and_the_management_interface_are_refused(tmp_path):
    for vrf in ("Management", "management"):
        device = G130Eos("-", "-", "", "")
        runtime = runtime_for(tmp_path, device)
        for table, key in (("ip-arp", IP), ("ipv6-neighbor", IP6)):
            preview = execute.preview(runtime, TARGET, clear_request(table, key, vrf=vrf))
            assert preview["result"] == "rejected" and preview["reason_codes"] == ["clear_protected_target"], preview
        assert device.queries == [] and device.check_queries == [] and device.clears == []
    # derived: the entry sits on the management interface of the switch
    refused_preview(tmp_path, "arp", code="clear_protected_target",
                    edit=lambda device: setattr(device, "before", swap(ARP_BEFORE, "Vlan3931, Ethernet5", "Management0")))
    # derived: the entry sits on a routed port, which is not an SVI
    refused_preview(tmp_path, "arp", code="clear_protected_target",
                    edit=lambda device: setattr(device, "before", swap(ARP_BEFORE, "Vlan3931, Ethernet5", "Ethernet5")))


def test_an_svi_of_the_management_path_is_refused_and_another_vrf_is_not(tmp_path):
    # the lab switch has its management interface in the default VRF: an SVI of the default VRF may carry the SSH session
    def default_vrf(device):
        device.lines.remove("   vrf G130")
        device.saved = list(device.lines)
    for case in ("counters", "mac", "arp", "nd"):
        refused_preview(tmp_path, case, code="clear_protected_target", edit=default_vrf)


@pytest.mark.parametrize("case", ["counters", "mac", "arp", "nd"])
def test_an_uplink_or_a_channel_member_is_refused(tmp_path, case):
    lldp = json.loads(LLDP)
    lldp["lldpNeighbors"].append({"port": "Ethernet5", "neighborDevice": "host09", "neighborPort": "Ethernet9", "ttl": 120})
    refused_preview(tmp_path, case, code="clear_protected_target",
                    edit=lambda device: setattr(device, "lldp", json.dumps(lldp)))
    refused_preview(tmp_path, case, code="clear_protected_target", answers={
        "show interfaces Ethernet5 switchport": (G125 / "peer-switchport.txt").read_text().replace("Name: Po200", "Name: Et5")})
    refused_preview(tmp_path, case, code="clear_protected_target", answers={
        "show interfaces Ethernet5 switchport": swap(SWITCHPORT, "Switchport: Enabled", "Switchport: Disabled")})

    def member(device):
        device.channel = "104"
    refused_preview(tmp_path, case, code="clear_protected_target", edit=member)


def test_a_mac_entry_on_a_port_channel_or_an_overlay_is_refused(tmp_path):
    for port in ("Port-Channel104", "Vxlan1", "Cpu"):
        refused_preview(tmp_path, "mac", code="clear_protected_target",
                        edit=lambda device, port=port: setattr(device, "before", swap(MAC_BEFORE, '"Ethernet5"', '"%s"' % port)))


def test_a_read_that_fails_or_times_out_before_the_clear_refuses_it_with_its_own_code(tmp_path):
    for case in ("counters", "mac", "arp", "nd"):
        refused_preview(tmp_path, case, code="clear_readback_unreadable",
                        answers={"show lldp neighbors | json": AccessError("exit status 1")})
        refused_preview(tmp_path, case, code="clear_readback_unreadable",
                        answers={"show lldp neighbors | json": "not json"})
        refused_preview(tmp_path, case, code="clear_readback_unreadable",
                        answers={"show interfaces Ethernet5 switchport": "unexpected\n"})
    for case in ("counters", "mac", "arp", "nd", "bgp-in"):
        device, change, _ = case_device(case)
        device.check_unreadable = True
        refused_preview(tmp_path, case, code="clear_readback_unreadable", device=(device, change, ""))
        device, change, _ = case_device(case)
        device.before = "\n> read\n% unexpected\n"
        refused_preview(tmp_path, case, code="clear_readback_unreadable", device=(device, change, ""))


def test_a_write_account_without_privilege_15_cannot_clear(tmp_path):
    device, change, _ = case_device("counters")
    device.privilege = 1
    refused_preview(tmp_path, "counters", code="write_account_privilege", device=(device, change, ""))


def test_a_switch_that_another_session_holds_is_no_obstacle_for_a_clear(tmp_path):
    # a clear writes no configuration: open sessions, a pending commit timer and unsaved changes do not concern it
    device, change, write = case_device("counters")
    device.timer = {"name": "netops-foreign", "expire": device.epoch + 600, "checkpoint": list(device.lines)}
    device.sessions["netops-foreign"] = {"state": "pending"}
    device.saved = []
    runtime = runtime_for(tmp_path, device)
    assert execute.preview(runtime, TARGET, change)["result"] == "ready"


# ---- the configuration must stay as it was, the plan binds what the approval saw ----

def test_a_configuration_that_changed_during_the_clear_is_a_foreign_change(tmp_path):
    device, change, write = case_device("arp")
    device.on_clear = lambda dev: dev.lines.insert(dev.lines.index("end"), "hostname other")
    runtime = runtime_for(tmp_path, device)
    preview = execute.preview(runtime, TARGET, change)
    result = execute.apply(runtime, TARGET, change, expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "unknown" and "foreign change" in json.dumps(result)


def test_the_hash_of_the_preview_binds_the_target_and_not_the_moving_counters(tmp_path):
    device, change, _ = case_device("counters")
    runtime = runtime_for(tmp_path, device)
    first = execute.preview(runtime, TARGET, change)["plan_sha256"]
    device.before = swap(COUNTERS_BEFORE, "103 packets input, 8682 bytes", "190 packets input, 9999 bytes")
    assert execute.preview(runtime, TARGET, change)["plan_sha256"] == first
    # the hash of an ARP preview does not survive another entry
    device, change, _ = case_device("arp")
    runtime = runtime_for(tmp_path, device)
    first = execute.preview(runtime, TARGET, change)["plan_sha256"]
    device.before = swap(ARP_BEFORE, "0000.5e00.5302", "0000.5e00.5399")
    with pytest.raises(Rejected) as refused:
        execute.apply(runtime, TARGET, change, expected_plan_sha256=first)
    assert refused.value.reason_codes == ["plan_changed"] and device.clears == []


def test_the_target_of_the_plan_is_stable_between_two_previews_of_the_same_state(tmp_path):
    for case in sorted(CASES):
        device, change, _ = case_device(case)
        runtime = runtime_for(tmp_path / case, device)
        assert execute.preview(runtime, TARGET, change)["plan_sha256"] == execute.preview(runtime, TARGET, change)["plan_sha256"]


def test_the_eos_tables_are_registered_as_clear_tables():
    from netops_admin import engine
    assert engine.CLEAR_TABLES["eos"] == eos_clear.TABLES
    assert set(eos_clear.TABLES) == {"port-counters", "mac-address-table", "ip-arp", "ipv6-neighbor", "bgp-refresh"}
    assert execute.CLEAR_KINDS["eos"] == "eos-clear" in execute.IRREVERSIBLE_KINDS or "eos-clear" in execute.IRREVERSIBLE_KINDS


@pytest.mark.parametrize("case", ["bgp-in", "bgp-out"])
def test_a_bgp_counter_that_follows_the_refresh_late_is_read_again(tmp_path, case):
    # measured live on 4.36.1F: the first read right after soft out still showed the old begin-of-refresh counter
    device, change, write = case_device(case)
    device.late_reads = 2
    runtime = runtime_for(tmp_path, device)
    preview = execute.preview(runtime, TARGET, change)
    result = execute.apply(runtime, TARGET, change, expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "confirmed", result
    # a counter that never moves is still not a refresh, after the whole wait
    device, change, write = case_device(case)
    device.late_reads = 100
    runtime = runtime_for(tmp_path, device)
    preview = execute.preview(runtime, TARGET, change)
    result = execute.apply(runtime, TARGET, change, expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "unknown" and "clear readback mismatch" in json.dumps(result)
    assert device.check_queries.count(device.read) <= 2 + eos_clear.BGP_READBACK_ATTEMPTS + 2


def test_a_switch_that_runs_no_bgp_has_no_neighbor_to_refresh(tmp_path):
    # measured on d-ceos (BGP not configured): the JSON read answers with exit status 1 and errors ["BGP inactive"]
    device, change, write = case_device("bgp-in")
    device.answers[device.read] = (1, (FIXTURES / "d-ceos__show-bgp-neighbor-json-inactive.txt").read_text())
    refused_preview(tmp_path, "bgp-in", code="clear_no_entry", device=(device, change, write))


def test_an_untested_eos_version_is_only_a_warning_of_the_preview(tmp_path):
    # G00-1: the version outside the tested list never blocks the clear; the plan carries the warning
    device, change, write = case_device("counters")
    device.firmware = "4.40.0F"
    device.lines = [line.replace("4.36.1F", "4.40.0F") for line in device.lines]
    runtime = make_runtime(tmp_path / "untested", device, firmware="4.40.0F")
    preview = execute.preview(runtime, TARGET, change)
    assert preview["result"] == "ready" and preview["firmware_support"]["status"] == "untested", preview
    assert preview["firmware_support"]["device_version"] == "4.40.0F"
    result = execute.apply(runtime, TARGET, change, expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "confirmed" and device.clears == [write]
