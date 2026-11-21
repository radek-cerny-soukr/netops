"""1.0.12 G146 (Junos ELS, vJunos-switch 26.2R1.7): targeted clear of port counters (J34), one learned MAC (J35), one
ARP or IPv6 neighbor entry (J36) and a BGP route refresh of one peer (J37).

Parsers run on anonymised outputs measured on d-vjunos (fixtures/junos_g146, PROVENANCE.md names the DERIVED ones:
the IPv6 neighbor row and the BGP neighbor, which the lab cannot produce); preview, apply and readback run through
execute.preview/execute.apply against FakeJunos, whose clear answers follow the measurement."""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from conftest import request_bytes
from fake_junos import FIRMWARE, FakeJunos

from netops_admin import engine, execute, junos_clear
from netops_admin.access import AccessError
from netops_admin.errors import Rejected
from netops_admin.request import parse_request
from test_junos import NAME, make_runtime, steps

FIXTURES = Path(__file__).parent / "fixtures" / "junos_g146"
COUNTER = iter(range(1, 10000))


def fx(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


NEVER, CLEARED, ACTIVE = fx("counters-never.txt"), fx("counters-cleared.txt"), fx("counters-active.txt")
FDB_ENTRY, ARP_HIT, ND_STALE, BGP = fx("fdb-entry.txt"), fx("arp-hit.txt"), fx("nd-stale.txt"), fx("bgp-established.txt")
MAC, IP, IP6, PEER = "00:00:5e:00:53:01", "192.0.2.102", "2001:db8:20::10", "192.0.2.141"
# the real ge-0/0/3 pair; the preview of ge-0/0/3 reads the first, the readback the second
PORT = "ge-0/0/3"


def request(table, key, changes=None, **fields):
    fields.setdefault("request_id", "g146-unit-%04d" % next(COUNTER))
    return parse_request(request_bytes(op="clear", table=table, key=key, changes=changes or {}, **fields))


def read_of(table, key, mode=None):
    return junos_clear.clear_target(table, key, {"mode": mode} if mode else {}).read


class G146Junos(FakeJunos):
    """The reads of the clear target come from `reads` (a text or a callable); the clear command changes them through
    `effect`."""

    def __init__(self):
        super().__init__()
        self.reads = {}
        self.clears = []
        self.effect = None
        self.fail_check = False

    def check_query(self, command):
        if command in self.reads:
            self.check_queries.append(command)
            if self.fail_check:
                raise AccessError("check account unavailable")
            value = self.reads[command]
            return value() if callable(value) else value
        return super().check_query(command)

    def apply(self, steps, spec):
        if len(steps) == 1 and steps[0].startswith("clear "):
            self.clears.append(steps[0])
            if self.effect is not None:
                self.effect(steps[0])
            return 1
        return super().apply(steps, spec)


def device_for(table, key, before, after=None, mode=None):
    device = G146Junos()
    command = read_of(table, key, mode)
    device.reads[command] = lambda: after if device.clears and after is not None else before
    return device


def run(tmp_path, device, table, key, mode=None, **kw):
    runtime = make_runtime(tmp_path, device, **kw)
    change = request(table, key, {"mode": mode} if mode else {})
    return runtime, change, execute.preview(runtime, NAME, change)


def confirmed(tmp_path, device, table, key, mode=None, **kw):
    runtime, change, preview = run(tmp_path, device, table, key, mode, **kw)
    assert preview["result"] == "ready", preview
    configuration = device.snapshot()
    record = execute.apply(runtime, NAME, change, expected_plan_sha256=preview["plan_sha256"])
    assert device.snapshot() == configuration and not device.timer
    return runtime, change, preview, record


# ---- parsers on measured outputs ----

def test_counters_before_and_after_the_real_clear():
    before = junos_clear.counters_observation(NEVER, PORT)
    after = junos_clear.counters_observation(CLEARED, PORT)
    assert before == {"port": PORT, "admin": "enabled", "link": "down", "cleared": junos_clear.NOT_CLEARED,
                      "counters": {"input_bytes": 0, "output_bytes": 323, "input_packets": 0, "output_packets": 1}}
    assert after["cleared"] == "2026-11-19 19:51:47" and set(after["counters"].values()) == {0}
    active = junos_clear.counters_observation(ACTIVE, "ge-0/0/1")
    assert active["link"] == "up" and active["counters"]["output_packets"] == 54320


@pytest.mark.parametrize("text,port,code", [
    ("\nerror: device ge-0/0/99 not found\n", "ge-0/0/99", "port_missing"),
    (NEVER.split("  Traffic statistics:")[0], PORT, "clear_readback_unreadable"),      # cut before the counters
    (NEVER.replace("Statistics last cleared: Never", "Statistics last cleared: sometime"), PORT, "clear_readback_unreadable"),
    (NEVER.replace("Output packets:                    1", "Output packets:"), PORT, "clear_readback_unreadable"),
    (NEVER, "ge-0/0/1", "clear_readback_unreadable"),                                  # another port answered
    ("", PORT, "clear_readback_unreadable"),
    (NEVER + "---(more)---", PORT, "clear_readback_unreadable"),
])
def test_unrecognised_counters_are_refused(text, port, code):
    with pytest.raises(Rejected) as refused:
        junos_clear.counters_observation(text, port)
    assert refused.value.reason_codes == [code]


def test_fdb_entry_miss_and_ambiguity():
    one = junos_clear.fdb_observation(FDB_ENTRY, MAC)
    assert one["entries"] == [{"vlan": "D20", "interface": "ge-0/0/1.0", "dynamic": True,
                               "learned": "2026-11-18 18:16:37"}]
    assert junos_clear.fdb_observation(fx("fdb-miss.txt"), MAC) == {"mac": MAC, "entries": []}
    two = junos_clear.fdb_observation(FDB_ENTRY + FDB_ENTRY.replace("D20", "D10").replace("ID: 20", "ID: 10"), MAC)
    assert [entry["vlan"] for entry in two["entries"]] == ["D10", "D20"]
    static = junos_clear.fdb_observation(FDB_ENTRY.replace("MAC flags: D ", "MAC flags: S "), MAC)
    assert static["entries"][0]["dynamic"] is False
    for text in (FDB_ENTRY.replace(MAC, "00:00:5e:00:53:09", 1), FDB_ENTRY.split("MAC flags")[0],
                 "error: syntax error\n", FDB_ENTRY + "---(more)---"):
        with pytest.raises(Rejected) as refused:
            junos_clear.fdb_observation(text, MAC)
        assert refused.value.reason_codes == ["clear_readback_unreadable"]


def test_arp_row_miss_and_the_unfiltered_table():
    one = junos_clear.arp_observation(ARP_HIT, IP)
    assert one["entries"] == [{"mac": MAC, "interface": "irb.20", "port": "ge-0/0/1.0", "dynamic": True, "tte": 46}]
    assert junos_clear.arp_observation(fx("arp-miss.txt"), IP) == {"ip": IP, "entries": []}
    assert "deleted" in fx("clear-arp-answer.txt")
    with pytest.raises(Rejected):
        junos_clear.arp_observation(fx("arp-table.txt"), IP)             # more addresses than the selected one
    with pytest.raises(Rejected):
        junos_clear.arp_observation(ARP_HIT + "Total entries: 4\n", IP)  # the summary does not match the rows
    with pytest.raises(Rejected):
        junos_clear.arp_observation(ARP_HIT.replace("TTE", "XXX"), IP)


def test_nd_row_miss_and_unknown_rows():
    one = junos_clear.nd_observation(ND_STALE, IP6)
    assert one["entries"][0]["state"] == "stale" and one["entries"][0]["interface"] == "irb.20"
    assert junos_clear.nd_observation(fx("nd-empty.txt"), IP6) == {"ip": IP6, "entries": []}
    for text in (ND_STALE.replace("stale", "weird"), ND_STALE.splitlines()[1] + "\n", ND_STALE.replace("Secure", "Sec")):
        with pytest.raises(Rejected) as refused:
            junos_clear.nd_observation(text, IP6)
        assert refused.value.reason_codes == ["clear_readback_unreadable"]


def test_bgp_neighbor_and_not_running():
    state = junos_clear.bgp_observation(BGP, PEER)
    assert state == {"peer": PEER, "state": "Established", "flaps": 0, "refresh_capable": True, "advertised": 3,
                     "output_updates": 3, "output_refreshes": 0}
    assert junos_clear.bgp_observation(fx("bgp-not-running.txt"), PEER) is None
    for text in (BGP.replace("Number of flaps: 0\n", ""), BGP.replace("Routing-Instance: master", "Routing-Instance: x"),
                 BGP.replace("192.0.2.141+179", "192.0.2.150+179"), "error: syntax error\n"):
        with pytest.raises(Rejected):
            junos_clear.bgp_observation(text, PEER)


# ---- targets ----

def test_commands_are_the_measured_ones():
    target = junos_clear.clear_target
    assert target("port-counters", "ge-0/0/3", {}).write == "clear interfaces statistics ge-0/0/3"
    assert target("fdb", "00:00:5E:00:53:01", {}).write == "clear ethernet-switching table 00:00:5e:00:53:01"
    assert target("arp", IP, {}).write == "clear arp hostname " + IP
    assert target("neighbor-discovery", "2001:DB8:20::10", {}).write == "clear ipv6 neighbors host " + IP6
    assert target("bgp-neighbor-refresh", PEER, {"mode": "soft"}).write == "clear bgp neighbor %s soft" % PEER
    assert target("bgp-neighbor-refresh", PEER, {"mode": "soft-inbound"}).write.endswith("soft-inbound")


def test_an_unknown_clear_table_is_not_a_junos_clear(tmp_path):
    device = G146Junos()
    runtime = make_runtime(tmp_path, device)
    with pytest.raises(Rejected) as refused:
        execute.preview(runtime, NAME, request("mac-table", MAC))
    assert refused.value.reason_codes == ["action_unsupported"] and device.clears == []


@pytest.mark.parametrize("table,key,changes", [
    ("port-counters", "all", {}), ("port-counters", "ge-0/0/3.0", {}), ("port-counters", "ge-0/0/*", {}),
    ("port-counters", "fxp0", {}), ("port-counters", "ge-0/0/3", {"snmp": "1"}),
    ("fdb", "all", {}), ("fdb", "01:00:5e:90:10:01", {}), ("fdb", "00:00:5e:00:53", {}), ("fdb", "vlan:D20", {}),
    ("arp", "all", {}), ("arp", "192.0.2.0/24", {}), ("arp", "224.0.0.5", {}), ("arp", "2001:db8::1", {}),
    ("arp", IP, {"vpn": "x"}), ("arp", "0.0.0.0", {}),
    ("neighbor-discovery", "all", {}), ("neighbor-discovery", IP, {}), ("neighbor-discovery", "ff02::1", {}),
    ("neighbor-discovery", "fe80::1%ge-0/0/1", {}), ("neighbor-discovery", "fe80::1%fxp0", {}),
    ("bgp-neighbor-refresh", PEER, {}), ("bgp-neighbor-refresh", "all", {"mode": "soft"}),
    ("bgp-neighbor-refresh", PEER, {"mode": "hard"}), ("bgp-neighbor-refresh", PEER, {"mode": "soft", "as": "1"}),
])
def test_scope_beyond_one_object_is_refused_before_the_device_is_read(tmp_path, table, key, changes):
    # (table `mac-table` is no table of this clear: execute refuses it as action_unsupported, see the next test)
    with pytest.raises(Rejected) as refused:
        junos_clear.clear_target(table, key, changes)
    assert refused.value.reason_codes == ["clear_invalid_target"]
    device = G146Junos()
    runtime = make_runtime(tmp_path, device)
    change = request(table, key, changes)
    answer = execute.preview(runtime, NAME, change)
    assert answer["result"] == "rejected" and "clear_invalid_target" in answer["reason_codes"]
    assert device.clears == [] and device.check_queries == [] and runtime.store.records() == []


# ---- J34: counters ----

def test_counters_preview_apply_readback_without_undo(tmp_path):
    device = device_for("port-counters", PORT, NEVER, CLEARED)
    runtime, change, preview = run(tmp_path, device, "port-counters", PORT)
    assert preview["result"] == "ready" and preview["commands"] == ["clear interfaces statistics ge-0/0/3"]
    assert preview["return_mechanism"] == "irreversible" and preview["safeguard_seconds"] is None
    assert preview["inverse_commands"] == 0 and preview["firmware_support"]["status"] == "tested"
    assert device.clears == [] and runtime.store.records() == []
    with pytest.raises(Rejected) as refused:
        execute.apply(runtime, NAME, change)
    assert refused.value.reason_codes == ["clear_preview_required"]
    with pytest.raises(Rejected) as refused:
        execute.apply(runtime, NAME, change, expected_plan_sha256="0" * 64)
    assert refused.value.reason_codes == ["plan_changed"]
    assert device.clears == []
    configuration = device.snapshot()
    record = execute.apply(runtime, NAME, change, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed" and "postcheck_passed" in steps(record)
    assert record["readback"]["cleared"] == "2026-11-19 19:51:47" and "safeguard" not in record
    assert record["kind"] == "junos-clear" and device.clears == ["clear interfaces statistics ge-0/0/3"]
    assert device.snapshot() == configuration and not device.timer
    assert execute.apply(runtime, NAME, change, expected_plan_sha256=preview["plan_sha256"])["change_id"] == record["change_id"]
    assert device.clears == ["clear interfaces statistics ge-0/0/3"]
    for undo in (execute.preview_undo, execute.undo):
        with pytest.raises(Rejected) as refused:
            undo(runtime, record["change_id"], "verify irreversible operation")
        assert refused.value.reason_codes == ["undo_not_applicable"]


def test_counters_that_moved_since_the_preview_do_not_change_the_plan_hash(tmp_path):
    device = device_for("port-counters", PORT, NEVER)
    runtime, _change, first = run(tmp_path, device, "port-counters", PORT)
    device.reads[read_of("port-counters", PORT)] = NEVER.replace("Output packets:                    1", "Output packets:                    9")
    second = execute.preview(runtime, NAME, request("port-counters", PORT))
    assert first["plan_sha256"] == second["plan_sha256"]
    device.reads[read_of("port-counters", PORT)] = NEVER.replace("Physical link is Down", "Physical link is Up")
    assert execute.preview(runtime, NAME, request("port-counters", PORT))["plan_sha256"] != first["plan_sha256"]


def test_a_clear_that_changed_nothing_is_not_reported_as_success(tmp_path):
    # the state after the command equals the state before: same "last cleared", same counters (nothing was reset)
    device = device_for("port-counters", "ge-0/0/1", ACTIVE, ACTIVE)
    runtime, change, preview = run(tmp_path, device, "port-counters", "ge-0/0/1")
    record = execute.apply(runtime, NAME, change, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "unknown" and "clear readback mismatch" in record["reason"]
    assert runtime.store.blocked(NAME) is not None


def test_counters_that_fell_but_without_a_new_clear_time_are_not_proof(tmp_path):
    device = device_for("port-counters", PORT, NEVER, CLEARED.replace("Statistics last cleared: 2026-11-19 19:51:47 UTC (00:00:01 ago)",
                                                                     "Statistics last cleared: Never"))
    runtime, change, preview = run(tmp_path, device, "port-counters", PORT)
    assert execute.apply(runtime, NAME, change, expected_plan_sha256=preview["plan_sha256"])["result"] == "unknown"


def test_counters_busy_after_the_clear_stay_within_the_tolerance(tmp_path):
    busy = CLEARED.replace("Input  packets:                    0                    0 pps",
                           "Input  packets:                   12                    0 pps", 1).replace("link is Down", "link is Up")
    device = device_for("port-counters", "ge-0/0/1", ACTIVE, busy.replace(PORT, "ge-0/0/1"))
    _runtime, _change, _preview, record = confirmed(tmp_path, device, "port-counters", "ge-0/0/1")
    assert record["result"] == "confirmed" and record["readback"]["counters"]["input_packets"] == 12


def test_a_missing_port_is_refused_with_its_own_code(tmp_path):
    device = device_for("port-counters", "ge-0/0/99", fx("counters-not-found.txt"))
    _runtime, _change, preview = run(tmp_path, device, "port-counters", "ge-0/0/99")
    assert preview["result"] == "rejected" and "port_missing" in preview["reason_codes"] and device.clears == []


# ---- J35: one learned MAC ----

def test_fdb_entry_cleared_and_other_entries_are_not_touched(tmp_path):
    device = device_for("fdb", MAC, FDB_ENTRY, fx("fdb-miss.txt"))
    _runtime, _change, preview, record = confirmed(tmp_path, device, "fdb", MAC)
    assert preview["commands"] == ["clear ethernet-switching table " + MAC]
    assert record["result"] == "confirmed" and record["readback"] == {"mac": MAC, "entries": []}
    assert device.clears == ["clear ethernet-switching table " + MAC]
    assert preview["predicted"]["after"] == {"mac": MAC, "entries": []}


def test_fdb_entry_learned_again_is_proven_by_its_later_time_only(tmp_path):
    later = FDB_ENTRY.replace("2026-11-18 18:16:37", "2026-11-19 20:01:02")
    device = device_for("fdb", MAC, FDB_ENTRY, later)
    runtime, _change, _preview, record = confirmed(tmp_path, device, "fdb", MAC)
    assert record["result"] == "confirmed" and "relearned" in steps(record)
    assert record["readback"]["entries"][0]["relearned"] is True
    # the same entry (same learning time) after the command: the clear did nothing
    device = device_for("fdb", MAC, FDB_ENTRY, FDB_ENTRY)
    runtime, change, preview = run(tmp_path / "b", device, "fdb", MAC)
    assert execute.apply(runtime, NAME, change, expected_plan_sha256=preview["plan_sha256"])["result"] == "unknown"


@pytest.mark.parametrize("before,code", [
    (fx("fdb-miss.txt"), "clear_no_entry"),
    (FDB_ENTRY.replace("MAC flags: D ", "MAC flags: S "), "clear_no_entry"),
    (FDB_ENTRY + FDB_ENTRY.replace("D20", "D10").replace("ID: 20", "ID: 10"), "clear_ambiguous_entry"),
    (FDB_ENTRY.replace("ge-0/0/1.0", "ge-0/0/0.0"), "clear_protected_target"),                  # LLDP uplink
    (FDB_ENTRY.replace("ge-0/0/1.0", "ae0.0"), "clear_protected_target"),
    (FDB_ENTRY.replace("ge-0/0/1.0", "fxp0.0"), "clear_protected_target"),
    ("MAC address: " + MAC + "\n  VLAN name: D20, VLAN ID: 20\n", "clear_readback_unreadable"),
])
def test_fdb_refusals_never_send_the_command(tmp_path, before, code):
    device = device_for("fdb", MAC, before)
    runtime, _change, preview = run(tmp_path, device, "fdb", MAC)
    assert preview["result"] == "rejected" and code in preview["reason_codes"], preview
    assert device.clears == [] and runtime.store.records() == []


def test_fdb_in_a_protected_vlan_or_on_a_protected_port_is_refused(tmp_path):
    for protected in ({"vlan": ["D20"]}, {"interface": ["ge-0/0/1"]}):
        device = device_for("fdb", MAC, FDB_ENTRY)
        _runtime, _change, preview = run(tmp_path / next(iter(protected)), device, "fdb", MAC, protected=protected)
        assert preview["result"] == "rejected" and "clear_protected_target" in preview["reason_codes"]
        assert device.clears == []


# ---- J36: ARP and IPv6 neighbor ----

def test_arp_entry_deleted(tmp_path):
    device = device_for("arp", IP, ARP_HIT, fx("arp-miss.txt"))
    _runtime, _change, preview, record = confirmed(tmp_path, device, "arp", IP)
    assert preview["commands"] == ["clear arp hostname " + IP] and record["result"] == "confirmed"
    assert record["readback"] == {"ip": IP, "entries": []}


def test_arp_entry_with_decreasing_tte_is_not_proof_of_clear(tmp_path):
    older = ARP_HIT.replace("   46    none", "   40    none")      # the entry is still the old one (TTE only falls)
    device = device_for("arp", IP, ARP_HIT, older)
    runtime, change, preview = run(tmp_path / "b", device, "arp", IP)
    record = execute.apply(runtime, NAME, change, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "unknown" and "mismatch" in record["reason"]


@pytest.mark.parametrize("before,code", [
    (fx("arp-miss.txt"), "clear_no_entry"),
    (ARP_HIT.replace("none", "permanent"), "clear_no_entry"),
    (ARP_HIT.replace("irb.20 [ge-0/0/1.0]", "fxp0.0"), "clear_protected_target"),
    (ARP_HIT.replace("irb.20 [ge-0/0/1.0]", "irb.20 [ge-0/0/0.0]"), "clear_protected_target"),   # behind the uplink
    (ARP_HIT + ARP_HIT.splitlines()[1].replace("irb.20", "irb.10") + "\n", "clear_ambiguous_entry"),   # one host twice
    (fx("arp-table.txt"), "clear_readback_unreadable"),
])
def test_arp_refusals_never_send_the_command(tmp_path, before, code):
    device = device_for("arp", IP, before)
    runtime, _change, preview = run(tmp_path, device, "arp", IP)
    assert preview["result"] == "rejected" and code in preview["reason_codes"], preview
    assert device.clears == [] and runtime.store.records() == []


def test_arp_on_the_path_of_the_ssh_session_is_refused(tmp_path):
    device = device_for("arp", IP, ARP_HIT)
    device.ssh_paths = [("192.0.2.56", "203.0.113.81")]      # the session reaches the switch through irb.20
    _runtime, _change, preview = run(tmp_path, device, "arp", IP)
    assert preview["result"] == "rejected" and device.clears == []


def test_nd_entry_cleared_and_reachable_entry_refused(tmp_path):
    device = device_for("neighbor-discovery", IP6, ND_STALE, fx("nd-empty.txt"))
    _runtime, _change, preview, record = confirmed(tmp_path, device, "neighbor-discovery", IP6)
    assert preview["commands"] == ["clear ipv6 neighbors host " + IP6] and record["result"] == "confirmed"
    device = device_for("neighbor-discovery", IP6, ND_STALE.replace("stale", "reachable"))
    _runtime, _change, preview = run(tmp_path / "b", device, "neighbor-discovery", IP6)
    assert preview["result"] == "rejected" and "clear_no_entry" in preview["reason_codes"]
    assert "reachable" in " ".join(preview["reasons"]) and device.clears == []


def test_nd_entry_that_stays_in_the_same_state_is_not_success(tmp_path):
    device = device_for("neighbor-discovery", IP6, ND_STALE, ND_STALE)
    runtime, change, preview = run(tmp_path, device, "neighbor-discovery", IP6)
    assert execute.apply(runtime, NAME, change, expected_plan_sha256=preview["plan_sha256"])["result"] == "unknown"


# ---- J37: BGP refresh ----

def _bgp(updates=3, refreshes=0, flaps=0, state="Established"):
    return (BGP.replace("Updates 3       Refreshes 0", "Updates %d       Refreshes %d" % (updates, refreshes))
            .replace("Number of flaps: 0", "Number of flaps: %d" % flaps).replace("State: Established", "State: " + state))


def test_bgp_inbound_refresh_proven_by_the_refresh_counter(tmp_path):
    mode = "soft-inbound"
    device = device_for("bgp-neighbor-refresh", PEER, BGP, _bgp(refreshes=1), mode)
    _runtime, _change, preview, record = confirmed(tmp_path, device, "bgp-neighbor-refresh", PEER, mode)
    assert preview["commands"] == ["clear bgp neighbor %s %s" % (PEER, mode)] and record["result"] == "confirmed"
    assert record["readback"]["state"] == "Established" and device.clears == [preview["commands"][0]]


@pytest.mark.parametrize("mode,after", [
    ("soft-inbound", _bgp(updates=9)),                  # only the other counter rose: no proof of a refresh
    ("soft", _bgp(refreshes=2)),
    ("soft-inbound", _bgp(refreshes=1, flaps=1)),       # the session was reset: not a soft clear
    ("soft-inbound", _bgp(refreshes=1, state="Active")),
], ids=["other-counter", "wrong-counter", "session-reset", "not-established"])
def test_bgp_effect_not_proven_is_unknown(tmp_path, mode, after):
    device = device_for("bgp-neighbor-refresh", PEER, BGP, after, mode)
    runtime, change, preview = run(tmp_path, device, "bgp-neighbor-refresh", PEER, mode)
    assert preview["result"] == "ready"
    assert execute.apply(runtime, NAME, change, expected_plan_sha256=preview["plan_sha256"])["result"] == "unknown"


@pytest.mark.parametrize("before,mode", [
    (fx("bgp-not-running.txt"), "soft"),                                  # the lab switch: BGP without licence
    (_bgp(state="Active"), "soft"),
    (BGP.replace("Peer supports Refresh capability (2)\n", ""), "soft-inbound"),
    (BGP.replace("Advertised prefixes:          3", "Advertised prefixes:          0"), "soft"),
], ids=["not-running", "active", "no-refresh-capability", "nothing-advertised"])
def test_bgp_refusals_never_send_the_command(tmp_path, before, mode):
    device = device_for("bgp-neighbor-refresh", PEER, before, None, mode)
    runtime, _change, preview = run(tmp_path, device, "bgp-neighbor-refresh", PEER, mode)
    assert preview["result"] == "rejected" and "clear_no_entry" in preview["reason_codes"], preview
    assert device.clears == [] and runtime.store.records() == []


# ---- accounts, firmware, unreadable reads, recovery ----

def test_write_account_without_the_clear_permission_is_refused(tmp_path):
    device = device_for("port-counters", PORT, NEVER, CLEARED)
    device.permissions_missing = ("clear",)
    _runtime, _change, preview = run(tmp_path, device, "port-counters", PORT)
    assert preview["result"] == "rejected" and "write_account_privilege" in preview["reason_codes"]
    assert device.clears == []


def test_clear_needs_no_configuration_mode_and_ignores_a_foreign_commit_confirmed(tmp_path):
    device = device_for("port-counters", PORT, NEVER, CLEARED)
    device.foreign_editor = True                      # someone else is in configuration mode: irrelevant for a clear
    _runtime, _change, preview, record = confirmed(tmp_path, device, "port-counters", PORT)
    assert record["result"] == "confirmed" and device.applied_blocks == []


def test_an_untested_release_is_a_warning_never_a_block(tmp_path):
    device = device_for("port-counters", PORT, NEVER, CLEARED)
    device.firmware = "26.9R1.1"
    device.lines = [line.replace("26.2R1.7", "26.9R1.1") if line.startswith("set version ") else line for line in device.lines]
    runtime, change, preview = run(tmp_path, device, "port-counters", PORT, firmware="26.9R1.1")
    assert preview["result"] == "ready", preview["reasons"]
    assert preview["firmware_support"]["status"] == "untested"
    record = execute.apply(runtime, NAME, change, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed" and record["plan"]["firmware_support"]["status"] == "untested"


def test_unreadable_check_account_is_a_clear_readback_error_not_a_generic_refusal(tmp_path):
    device = device_for("port-counters", PORT, NEVER, CLEARED)
    device.fail_check = True
    _runtime, _change, preview = run(tmp_path, device, "port-counters", PORT)
    assert preview["result"] == "rejected" and "clear_readback_unreadable" in preview["reason_codes"]


def test_lldp_or_terse_not_readable_fails_closed(tmp_path):
    device = device_for("port-counters", PORT, NEVER, CLEARED)
    original = device.query

    def broken(command):
        if command == "show lldp neighbors":
            return "garbage that is no LLDP neighbor list\n"
        return original(command)

    device.query = broken
    runtime, _change, preview = run(tmp_path, device, "port-counters", PORT)
    assert preview["result"] == "rejected" and "clear_readback_unreadable" in preview["reason_codes"]
    assert device.clears == [] and runtime.store.records() == []


def test_the_uplink_and_the_only_port_with_a_link_are_protected_for_counters(tmp_path):
    device = device_for("port-counters", "ge-0/0/0", NEVER.replace(PORT, "ge-0/0/0"))
    _runtime, _change, preview = run(tmp_path, device, "port-counters", "ge-0/0/0")
    assert preview["result"] == "rejected" and "clear_protected_target" in preview["reasons"][0] or "clear_protected_target" in preview["reason_codes"]
    device = device_for("port-counters", "ge-0/0/1", ACTIVE)
    device.up_ports = {"ge-0/0/1"}
    _runtime, _change, preview = run(tmp_path / "b", device, "port-counters", "ge-0/0/1")
    assert preview["result"] == "rejected" and "clear_protected_target" in preview["reason_codes"]
    assert device.clears == []


def test_interrupted_clear_is_settled_by_recovery_without_a_second_command(tmp_path):
    device = device_for("port-counters", PORT, NEVER, CLEARED)

    def crash(_command):
        raise KeyboardInterrupt()

    device.effect = crash
    runtime, change, preview = run(tmp_path, device, "port-counters", PORT)
    with pytest.raises(KeyboardInterrupt):
        execute.apply(runtime, NAME, change, expected_plan_sha256=preview["plan_sha256"])
    device.effect = None
    settled = execute.recover(runtime, NAME)
    assert [item["result"] for item in settled] == ["unknown"]
    assert device.clears == ["clear interfaces statistics ge-0/0/3"]


def test_plan_of_a_clear_is_a_valid_plan_document(tmp_path):
    device = device_for("fdb", MAC, FDB_ENTRY, fx("fdb-miss.txt"))
    _runtime, _change, _preview, record = confirmed(tmp_path, device, "fdb", MAC)
    plan = engine._read_plan(record["plan"])
    assert plan["op"] == "clear" and plan["platform"] == "junos" and plan["inverse"] == [] and plan["safeguard_id"] is None
    tampered = dict(record["plan"], table="mac-table")
    with pytest.raises(Rejected):
        engine._read_plan(tampered)


def test_the_documented_commands_have_no_scope_wider_than_one_object():
    for table, key, changes in (("port-counters", PORT, {}), ("fdb", MAC, {}), ("arp", IP, {}),
                                ("neighbor-discovery", IP6, {}), ("bgp-neighbor-refresh", PEER, {"mode": "soft"})):
        command = junos_clear.clear_target(table, key, changes).write
        assert not re.search(r"\b(all|statistics all|instance|vlan-name|logical-system)\b", command), command


@pytest.mark.parametrize('table,key,before,interface', [
    ('arp', IP, ARP_HIT, 'irb.20'),
    ('arp', IP, ARP_HIT, 'ge-0/0/1.0'),
    ('neighbor-discovery', IP6, ND_STALE, 'irb.20'),
    ('fdb', MAC, FDB_ENTRY, 'ge-0/0/1.0'),
    ('fdb', MAC, FDB_ENTRY, 'irb.20'),
])
def test_g146_clear_protects_logical_interfaces(tmp_path, table, key, before, interface):
    target = device_for(table, key, before)
    runtime, _, refused = run(tmp_path, target, table, key, protected={'interface': [interface]})
    assert refused.get('reason_codes') == ['clear_protected_target'], refused
    assert not target.clears and not runtime.store.records()


@pytest.mark.parametrize('table,key,before,after,mode', [
    ('arp', IP, ARP_HIT, ARP_HIT.replace('   46    none', ' 1198    none'), None),
    ('neighbor-discovery', IP6, ND_STALE, ND_STALE.replace('stale', 'reachable'), None),
    ('bgp-neighbor-refresh', PEER, BGP, _bgp(updates=6), 'soft'),
])
def test_g146_background_protocol_activity_is_not_proof_of_clear(tmp_path, table, key, before, after, mode):
    target = device_for(table, key, before, after, mode)
    _, _, preview, record = confirmed(tmp_path, target, table, key, mode)
    assert record['result'] == 'unknown' and target.clears == preview['commands']
