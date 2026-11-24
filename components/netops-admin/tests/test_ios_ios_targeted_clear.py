"""Scoped IOS clear requests through the Admin executor with GNS3 replies."""
from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest
from fake_ios import FakeIos
from test_access import Shell, device_access
from test_ios import make_runtime, request

from netops_admin import execute
from netops_admin.errors import Rejected

FIXTURES = Path(__file__).parent / "fixtures" / "ios_ios_targeted_clear"
COUNTERS = "show interfaces GigabitEthernet0/2"
MAC = "show mac address-table dynamic"
ARP = "show ip arp vrf blue"
ND = "show ipv6 neighbors vrf blue"
COUNTERS_CLEAR = "clear counters GigabitEthernet0/2"


def fixture(name):
    return (FIXTURES / (name + ".out")).read_text()


def without_row(text, marker):
    """Derived readback when the switch has evicted the row, including its updated footer."""
    rows = [line for line in text.splitlines() if marker not in line]
    assert len(rows) == len(text.splitlines()) - 1
    if "Total Mac Addresses" in rows[-1]:
        label, count = rows[-1].rsplit(" ", 1)
        rows[-1] = f"{label} {int(count) - 1}"
    return "\n".join(rows) + "\n"


class G67Ios(FakeIos):
    def __init__(self, node, read, before, after=None, command=None):
        super().__init__(node)
        self.read = read
        self.before = before
        self.after = after
        self.command = command
        self.clears = []
        self.reads = 0
        self.next_before = None
        self.query_override["show interfaces GigabitEthernet0/3 switchport"] = fixture("switchport")

    def check_query_status(self, command):
        assert command == self.read
        self.reads += 1
        if self.clears:
            return 0, self.after
        if self.next_before is not None and self.reads >= 3:
            return 0, self.next_before
        return 0, self.before

    def apply(self, steps, spec):
        assert self.command
        # Responses of the fake SSH channel. Real DeviceAccess handles the echo, prompt and confirmation.
        counters = self.command.startswith("clear counters ")
        if counters:
            shell = Shell([b"\r\nfixture-router#", self.command.encode() + b'\r\nClear "show interface" counters on this interface [confirm]',
                           b"\r\nfixture-router#"])
        else:
            shell = Shell([b"\r\nfixture-router#", self.command.encode() + b"\r\nfixture-router#"])
        self.last_answers = ()
        transport = device_access(shell)
        accepted = transport.apply(steps, type(spec)(b"\nfixture-router", spec.ends, spec.continuation, spec.error))
        assert shell.sent == ([self.command, ""] if counters else [self.command])
        self.clears.append(self.command)
        return accepted


def emulate_non_iol_xe(device):
    """Keep the IOS XE transport fixtures while testing generic XE clear behavior."""
    version = device.query("show version")
    device.query_override["show version"] = version.replace("X86_64BI_LINUX-ADVENTERPRISEK9-M", "CAT9K_IOSXE")


@pytest.mark.parametrize("node,table,key,changes,read,command,name,after_name,removed", [
    ("iosv", "port-counters", "Gi0/2", {}, COUNTERS, COUNTERS_CLEAR, "counters-before", "counters-after", None),
    ("iosvl2", "fdb", "00:00:5e:00:53:03", {}, MAC, "clear mac address-table dynamic address 0000.5e00.5303",
     "mac-before", "mac-after-interface", "0000.5e00.5303"),
    ("iosvl2", "fdb", "port:Gi0/3", {}, MAC, "clear mac address-table dynamic interface GigabitEthernet0/3",
     "mac-before", "mac-after-interface", "0000.5e00.5303"),
    ("iolxe", "iparp", "192.0.2.1", {"vrf": "blue"}, ARP, "clear arp-cache vrf blue 192.0.2.1",
     "arp-before", None, "192.0.2.1 "),
    ("iolxe", "neighbor-discovery", "2001:db8:1::1", {"vrf": "blue"}, ND,
     "clear ipv6 neighbors vrf blue 2001:db8:1::1", "nd-before", None, "2001:db8:1::1 "),
])
def test_preview_confirmed_apply_readback_and_no_undo(tmp_path, node, table, key, changes, read, command, name,
                                                      after_name, removed):
    before = fixture(name)
    after = fixture(after_name) if after_name else without_row(before, removed)
    device = G67Ios(node, read, before, after, command)
    if table == "neighbor-discovery":
        emulate_non_iol_xe(device)
    runtime = make_runtime(tmp_path, device)
    change = request(device, op="clear", table=table, key=key, changes=changes,
                     **({"endpoint_impact": key} if node == "iolxe" else {}))
    snapshot = device.snapshot()
    preview = execute.preview(runtime, "lab-ios", change)
    assert preview["result"] == "ready", preview.get("reasons")
    assert preview["commands"] == [command]
    assert preview["return_mechanism"] == "irreversible"
    assert preview["inverse_commands"] == 0
    assert preview["safeguard_seconds"] is None
    assert preview["firmware_support"]["status"] == ("untested" if table == "neighbor-discovery" else "tested")
    assert device.clears == [] and runtime.store.records() == []
    with pytest.raises(Rejected) as refused:
        execute.apply(runtime, "lab-ios", change)
    assert refused.value.reason_codes == ["clear_preview_required"]
    assert not device.clears
    result = execute.apply(runtime, "lab-ios", change, expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "confirmed", result["steps"]
    assert result["readback"]
    if removed:
        assert result["readback"]["entries"] == []
        assert result["readback"]["other_entries"] == preview["predicted"]["before"]["other_entries"]
    assert device.snapshot() == snapshot and device.timer is None and device.saves == 0
    assert execute.apply(runtime, "lab-ios", change, expected_plan_sha256=preview["plan_sha256"])["change_id"] == result["change_id"]
    for undo in (execute.preview_undo, execute.undo):
        with pytest.raises(Rejected) as refused:
            undo(runtime, result["change_id"], "verify runtime return")
        assert refused.value.reason_codes == ["undo_not_applicable"]
    assert device.clears == [command]


@pytest.mark.parametrize("after_age,expected", [("00:00:04", "unknown"), ("00:00:02", "confirmed")])
def test_classic_ios_repeated_clear_requires_fresh_reset_evidence(tmp_path, after_age, expected):
    recent = fixture("counters-after")
    device = G67Ios("iosv", COUNTERS, recent, recent.replace("00:00:04", after_age), COUNTERS_CLEAR)
    runtime = make_runtime(tmp_path, device)
    change = request(device, op="clear", table="port-counters", key=device.port, changes={})
    preview = execute.preview(runtime, "lab-ios", change)
    result = execute.apply(runtime, "lab-ios", change, expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == expected
    assert device.clears == [COUNTERS_CLEAR] and device.saves == 0


@pytest.mark.parametrize("table,key,changes", [
    ("port-counters", "all", {}),
    ("port-counters", "Gi0/2 | show version", {}),
    ("fdb", "dynamic", {}),
    ("fdb", "port:", {}),
    ("iparp", "*", {"vrf": "blue"}),
    ("iparp", "192.0.2.1", {"vrf": "blue\nclear arp-cache"}),
    ("neighbor-discovery", "2001:db8::1", {}),
])
def test_invalid_scope_refused_before_transport(tmp_path, table, key, changes):
    device = G67Ios("iosv", None, "")
    runtime = make_runtime(tmp_path, device)
    runtime.access_factory = lambda _device: pytest.fail("invalid selector should never contact the device")
    preview = execute.preview(runtime, "lab-ios", request(device, op="clear", table=table, key=key, changes=changes))
    assert preview["result"] == "rejected"
    assert preview["reason_codes"] == ["clear_invalid_target"]


@pytest.mark.parametrize("cut", [True, False])
def test_refused_or_truncated_read_is_unverified(tmp_path, cut):
    before = fixture("counters-before").split("packets output")[0] if cut else fixture("counters-refused")
    device = G67Ios("iosv", COUNTERS, before)
    runtime = make_runtime(tmp_path, device)
    change = request(device, op="clear", table="port-counters", key=device.port, changes={})
    preview = execute.preview(runtime, "lab-ios", change)
    assert preview["reason_codes"] == ["clear_readback_unreadable"]
    assert not device.clears


def test_trunk_and_incomplete_mac_table_are_refused(tmp_path):
    device = G67Ios("iosvl2", MAC, fixture("mac-before"))
    runtime = make_runtime(tmp_path, device)
    key = "port:Gi0/2"
    change = request(device, op="clear", table="fdb", key=key, changes={})
    assert execute.preview(runtime, "lab-ios", change)["reason_codes"] == ["clear_protected_target"]
    device.before = "\n".join(device.before.splitlines()[:-1]) + "\n"
    assert execute.preview(runtime, "lab-ios", change)["reason_codes"] == ["clear_readback_unreadable"]
    assert not device.clears


def test_mac_moving_between_preflight_and_write_is_refused(tmp_path):
    device = G67Ios("iosvl2", MAC, fixture("mac-before"))
    runtime = make_runtime(tmp_path, device)
    change = request(device, op="clear", table="fdb", key="0000.5e00.5303", changes={})
    preview = execute.preview(runtime, "lab-ios", change)
    assert preview["result"] == "ready", preview.get("reasons")
    device.next_before = device.before.replace("Gi0/3", "Gi0/2")
    result = execute.apply(runtime, "lab-ios", change, expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "rejected" and result["reason_codes"] == ["clear_scope_unverified"]
    assert not device.clears


def test_untested_version_warns_without_refusing(tmp_path):
    device = G67Ios("iosv", COUNTERS, fixture("counters-before"))
    original = device.firmware
    device.firmware = "15.9(3)M13"
    device.query_override["show version"] = device.query("show version").replace(original, device.firmware)
    runtime = make_runtime(tmp_path, device)
    change = request(device, op="clear", table="port-counters", key=device.port, changes={})
    preview = execute.preview(runtime, "lab-ios", change)
    assert preview["result"] == "ready", preview.get("reasons")
    assert preview["firmware_support"]["status"] == "untested"


def test_classic_ios_arp_refresh_keeps_existing_confirmation_behavior(tmp_path):
    # DERIVED: replay the measured refresh with the classic IOS fixture's data interface.
    before = fixture("arp-before").replace("Ethernet0/2", "GigabitEthernet0/3")
    after = fixture("arp-after").replace("Ethernet0/2", "GigabitEthernet0/3")
    device = G67Ios("iosv", ARP, before, after, "clear arp-cache vrf blue 192.0.2.1")
    runtime = make_runtime(tmp_path, device)
    change = request(device, op="clear", table="iparp", key="192.0.2.1", changes={"vrf": "blue"},
                     endpoint_impact="192.0.2.1")
    preview = execute.preview(runtime, "lab-ios", change)
    assert preview["result"] == "ready", preview.get("reasons")
    result = execute.apply(runtime, "lab-ios", change, expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "confirmed"
    assert result["readback"]["refreshed"] and result["readback"]["entries"][0]["age"] == 0
    assert result["readback"]["other_entries"] == preview["predicted"]["before"]["other_entries"]


def test_neighbor_that_remains_in_cache_does_not_confirm_or_retry(tmp_path):
    device = G67Ios("iolxe", ND, fixture("nd-before"), fixture("nd-after"),
                    "clear ipv6 neighbors vrf blue 2001:db8:1::1")
    emulate_non_iol_xe(device)
    runtime = make_runtime(tmp_path, device)
    change = request(device, op="clear", table="neighbor-discovery", key="2001:db8:1::1", changes={"vrf": "blue"},
                     endpoint_impact="2001:db8:1::1")
    preview = execute.preview(runtime, "lab-ios", change)
    assert preview["result"] == "ready", preview.get("reasons")
    assert preview["firmware_support"]["status"] == "untested"
    result = execute.apply(runtime, "lab-ios", change, expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "unknown" and result["reason"] == "clear readback mismatch"
    assert not runtime.store.blocked("lab-ios")
    assert execute.recover(runtime, "lab-ios") == []
    assert device.clears == ["clear ipv6 neighbors vrf blue 2001:db8:1::1"]


def test_default_nd_preview_requires_both_port_and_address(tmp_path):
    device = G67Ios("iosv", "show ipv6 neighbors", fixture("nd-global-before"))
    runtime = make_runtime(tmp_path, device)
    change = request(device, op="clear", table="neighbor-discovery", key="2001:db8:2::7",
                     changes={"interface": "Gi0/1.10"})
    preview = execute.preview(runtime, "lab-ios", change)
    assert preview["result"] == "ready", preview.get("reasons")
    assert preview["commands"] == ["clear ipv6 neighbors GigabitEthernet0/1.10 2001:db8:2::7"]
    assert not device.clears


def test_port_clear_refuses_a_protected_mac_in_other_notation(tmp_path):
    device = G67Ios("iosvl2", MAC, fixture("mac-before"))
    runtime = make_runtime(tmp_path, device)
    configured = runtime.config.devices["lab-ios"]
    runtime.config.devices["lab-ios"] = dataclasses.replace(configured, protected={"fdb": ["00:00:5e:00:53:03"]})
    change = request(device, op="clear", table="fdb", key="port:Gi0/3", changes={})
    preview = execute.preview(runtime, "lab-ios", change)
    assert preview["reason_codes"] == ["clear_protected_target"]
    assert not device.clears
