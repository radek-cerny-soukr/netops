"""G83 through the Admin executor with measured IOS XE DHCP answers."""
from dataclasses import replace
from pathlib import Path
import re

import pytest

from fake_ios import FakeIos
from test_ios import make_runtime, steps
from test_ios_g65 import req

from netops_admin import engine, execute
from netops_admin.access import AccessError
from netops_admin.errors import Rejected

FIXTURES = Path(__file__).parent / "fixtures" / "ios_g83"
HOST = "NETOPS-G83-HOST"
POOL = "NETOPS-G83-POOL"
PORT = "Ethernet0/2"
HELPER = PORT + ":192.0.2.10"
EXCLUSION = "192.0.2.20"
POOL_COMMAND = "show running-config | section ^ip dhcp pool %s$|^end$"
EXCLUSION_COMMAND = "show running-config | include ^ip dhcp excluded-address 192[.]0[.]2[.]20$|^end$"
RELAY_COMMAND = "show running-config interface " + PORT
IP_INTERFACE = "show ip interface " + PORT


def fixture(name):
    return (FIXTURES / (name + ".txt")).read_text()


def captured_lines(name):
    return [re.sub(r" +", " ", line) if not line.startswith(" ") else " " + " ".join(line.split())
            for line in fixture(name).splitlines()[:-1]]


class DhcpXe(FakeIos):
    def __init__(self):
        super().__init__("iolxe")
        # Separate the synthetic management address in the C45 baseline from the G83 pool.
        self.lines = [self.management_address(line) for line in self.lines]
        self.lines = self.state_with(relay=True, phase="before")
        self.saved = list(self.lines)
        self.replays = []

    @staticmethod
    def management_address(text):
        return text.replace("192.0.2.57", "203.0.113.57")

    def state_with(self, add=(), *, update=None, relay=False, phase="after"):
        lines = list(self.lines)
        for name in add:
            lines[-1:-1] = [*captured_lines(name), "!"]
        if update is not None:
            pool = captured_lines(update)
            start, end = self._block(pool[0])
            lines[start:end] = pool
        if relay:
            start, end = self._block("interface " + PORT)
            body = fixture("relay-" + phase).split("interface " + PORT + "\n", 1)[1].splitlines()[:-1]
            lines[start + 1:end] = body
        return lines

    def query(self, command):
        if command in self.query_override:
            return super().query(command)
        if command == RELAY_COMMAND:
            return fixture("relay-" + self.relay_phase())
        if command == EXCLUSION_COMMAND:
            found = captured_lines("exclusion-created")[0] in self.lines
            return fixture("exclusion-created" if found else "pool-absent")
        if command == "show ip dhcp pool " + POOL:
            return fixture("pool-operational")
        for name, captures in ((HOST, ("host-hardware", "host-client")), (POOL, ("pool-created", "pool-updated"))):
            if command == POOL_COMMAND % name:
                if "ip dhcp pool " + name not in self.lines:
                    return fixture("pool-absent")
                start, end = self._block("ip dhcp pool " + name)
                return next(fixture(variant) for variant in captures if self.lines[start:end] == captured_lines(variant))
        return self.management_address(super().query(command))

    def relay_phase(self):
        return "after" if "ip helper-address 192.0.2.10" in self.interface(PORT) else "before"

    def check_query(self, command):
        if command == IP_INTERFACE and command not in (self.check_override or {}):
            self.check_queries.append(command)
            return fixture("ip-interface-" + self.relay_phase())
        return super().check_query(command)

    def apply(self, commands, spec):
        if commands[0] != "configure terminal":
            return super().apply(commands, spec)
        expected, state = self.replays.pop(0)
        assert commands == ["configure terminal", *expected, "end"]
        self.applied_blocks.append(list(commands))
        self.lines = list(state)
        return len(commands)


HOST_CHANGE = {"host": "192.0.2.41 255.255.255.0", "hardware-address": "0000.5e00.5301"}
POOL_CHANGE = {"network": "192.0.2.0/24", "default-router": "192.0.2.1 192.0.2.2",
               "dns-server": "192.0.2.3 192.0.2.4"}


@pytest.mark.parametrize("table,key,changes,capture,return_commands,impact", [
    ("dhcp-reservation", HOST, HOST_CHANGE, "host-hardware", ["no ip dhcp pool " + HOST], None),
    ("dhcp-pool", POOL, POOL_CHANGE, "pool-created", ["no ip dhcp pool " + POOL], None),
    ("dhcp-exclusion", EXCLUSION, {}, "exclusion-created", ["no ip dhcp excluded-address " + EXCLUSION], None),
    ("dhcp-relay", HELPER, {}, None, ["interface " + PORT, "no ip helper-address 192.0.2.10"], HELPER),
])
def test_preview_hash_apply_readback_and_undo(tmp_path, table, key, changes, capture, return_commands, impact):
    device = DhcpXe()
    runtime = make_runtime(tmp_path, device)
    before = device.snapshot()
    if capture is None:
        commands = ["interface " + PORT, "ip helper-address 192.0.2.10"]
        after = device.state_with(relay=True)
    else:
        commands = [line.strip() for line in captured_lines(capture)]
        after = device.state_with(add=(capture,))
    device.replays.extend(((commands, after), (return_commands, device.lines)))
    request = req(table, "create", key, changes, **({"endpoint_impact": impact} if impact else {}))

    preview = execute.preview(runtime, "lab-ios", request)
    assert preview["result"] == "ready", preview
    assert preview["firmware_support"]["status"] == "tested"
    assert preview["commands"] == ["configure terminal", *commands, "end"]
    assert not device.applied_blocks and device.snapshot() == before
    with pytest.raises(Rejected) as declined:
        execute.apply(runtime, "lab-ios", request)
    assert declined.value.reason_codes == ["plan_changed"] and not device.applied_blocks
    record = execute.apply(runtime, "lab-ios", request, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", (record["reason"], steps(record))
    assert "check_identity_passed" in steps(record)
    assert engine.verify(record["plan"], device.snapshot().encode())["result"] == "match"

    undo = execute.preview_undo(runtime, record["change_id"], "restore original state")
    assert undo["result"] == "ready" and undo["commands"] == ["configure terminal", *return_commands, "end"]
    returned = execute.undo(runtime, record["change_id"], "restore original state")
    assert returned["result"] == "confirmed", (returned["reason"], steps(returned))
    assert device.snapshot() == before and device.saved == device.lines
    assert device.timer is None and not device.replays


@pytest.mark.parametrize("table,key,old,new,changes,commands,inverse", [
    ("dhcp-reservation", HOST, "host-hardware", "host-client",
     {"host": "192.0.2.42 255.255.255.0", "hardware-address": None, "client-identifier": "0102.0000.5318.32"},
     ["no hardware-address", "host 192.0.2.42 255.255.255.0", "client-identifier 0102.0000.5318.32"],
     ["no client-identifier", "host 192.0.2.41 255.255.255.0", "hardware-address 0000.5e00.5301"]),
    ("dhcp-pool", POOL, "pool-created", "pool-updated",
     {"network": "192.0.2.0/25", "default-router": "192.0.2.2", "dns-server": None},
     ["no network 192.0.2.0 255.255.255.0", "no dns-server",
      "network 192.0.2.0 255.255.255.128", "default-router 192.0.2.2"],
     ["no network 192.0.2.0 255.255.255.128", "network 192.0.2.0 255.255.255.0",
      "default-router 192.0.2.1 192.0.2.2", "dns-server 192.0.2.3 192.0.2.4"]),
])
def test_update_and_restore_measured_pool(tmp_path, table, key, old, new, changes, commands, inverse):
    device = DhcpXe()
    device.lines = device.state_with(add=(old,))
    device.saved = list(device.lines)
    before = device.snapshot()
    after = device.state_with(update=new)
    mode = "ip dhcp pool " + key
    device.replays.extend((([mode, *commands], after), ([mode, *inverse], device.lines)))
    runtime = make_runtime(tmp_path, device)
    request = req(table, "update", key, changes)
    preview = execute.preview(runtime, "lab-ios", request)
    assert preview["result"] == "ready" and not device.applied_blocks, preview
    record = execute.apply(runtime, "lab-ios", request, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", (record["reason"], steps(record))
    assert engine.verify(record["plan"], device.snapshot().encode())["result"] == "match"
    returned = execute.undo(runtime, record["change_id"], "restore the prior options")
    assert returned["result"] == "confirmed", (returned["reason"], steps(returned))
    assert device.snapshot() == before and not device.replays


@pytest.mark.parametrize("op", ("create", "delete"))
def test_first_or_only_helper_on_active_routed_interface_requires_impact(tmp_path, op):
    device = DhcpXe()
    if op == "delete":
        device.lines = device.state_with(relay=True)
        device.saved = list(device.lines)
    runtime = make_runtime(tmp_path, device)
    rejected = execute.preview(runtime, "lab-ios", req("dhcp-relay", op, HELPER))
    assert rejected["reason_codes"] == ["endpoint_impact_required"], rejected
    accepted = execute.preview(runtime, "lab-ios", req("dhcp-relay", op, HELPER, endpoint_impact=HELPER))
    assert accepted["result"] == "ready" and not device.applied_blocks, accepted


def test_existing_pool_with_active_leases_requires_impact(tmp_path):
    device = DhcpXe()
    device.lines = device.state_with(add=("pool-created",))
    device.saved = list(device.lines)
    device.query_override["show ip dhcp pool " + POOL] = re.sub(
        r"(?m)^( Leased addresses\s+: )0$", r"\g<1>1", fixture("pool-operational"))
    runtime = make_runtime(tmp_path, device)
    changes = {"dns-server": "192.0.2.4"}
    result = execute.preview(runtime, "lab-ios", req("dhcp-pool", "update", POOL, changes))
    assert result["reason_codes"] == ["endpoint_impact_required"] and not device.applied_blocks
    preview = execute.preview(runtime, "lab-ios", req("dhcp-pool", "update", POOL, changes, endpoint_impact=POOL))
    assert preview["result"] == "ready", preview


@pytest.mark.parametrize("interface", ("Vlan183", "Port-channel183", "Loopback183"))
def test_protected_logical_interfaces_refuse_helper_before_any_write(tmp_path, interface):
    device = DhcpXe()
    device.lines[-1:-1] = ["interface " + interface, " ip address 203.0.113.183 255.255.255.255", "!"]
    device.saved = list(device.lines)
    runtime = make_runtime(tmp_path, device)
    runtime.config.devices["lab-ios"] = replace(runtime.config.devices["lab-ios"],
                                               protected={"interface": [interface.lower()]})
    key = interface + ":192.0.2.10"
    result = execute.preview(runtime, "lab-ios", req("dhcp-relay", "create", key, endpoint_impact=key))
    assert result["reason_codes"] == ["port_protected"] and not device.applied_blocks, result


@pytest.mark.parametrize("response", ["running-denied", "l2-running-denied", "pool-created"])
def test_refused_and_truncated_config_reads_are_not_absence(tmp_path, response):
    device = DhcpXe()
    answer = fixture(response)
    if response == "pool-created":
        answer = answer.removesuffix("end\n")
    device.query_override[POOL_COMMAND % POOL] = answer
    result = execute.preview(make_runtime(tmp_path, device), "lab-ios", req("dhcp-pool", "create", POOL, POOL_CHANGE))
    assert result["reason_codes"] == ["ios_dhcp_readback_unreadable"] and not device.applied_blocks, result


@pytest.mark.parametrize("response", [
    fixture("ip-interface-before").split("  Directed broadcast forwarding")[0],
    fixture("ip-interface-after"),
])
def test_incomplete_or_conflicting_operational_relay_is_refused(tmp_path, response):
    device = DhcpXe()
    device.check_override = {IP_INTERFACE: response}
    result = execute.preview(make_runtime(tmp_path, device), "lab-ios",
                             req("dhcp-relay", "create", HELPER, endpoint_impact=HELPER))
    assert result["reason_codes"] == ["ios_dhcp_readback_unreadable"] and not device.applied_blocks, result


def test_preflight_timeout_has_a_distinct_reason(tmp_path):
    device = DhcpXe()
    runtime = make_runtime(tmp_path, device)

    def timeout(_, command):
        if command == "show privilege":
            raise AccessError("read timed out")

    device.on_query = timeout
    result = execute.preview(runtime, "lab-ios", req("dhcp-exclusion", "create", EXCLUSION))
    assert result["reason_codes"] == ["ios_dhcp_read_timeout"] and not device.applied_blocks, result


def test_newer_firmware_warns_and_keeps_the_same_dhcp_profile():
    device = DhcpXe()
    plan = engine.build_plan("iosxe", device.snapshot().encode(), req("dhcp-pool", "create", POOL, POOL_CHANGE),
                             firmware="17.18.3")
    assert plan["firmware_support"]["status"] == "untested"
    assert plan["predicted"]["after"]["network"] == "192.0.2.0 255.255.255.0"


@pytest.mark.parametrize("operation", ["create", "delete"])
def test_each_helper_change_on_active_interface_needs_impact(tmp_path, operation):
    device = DhcpXe()
    helpers = ["192.0.2.11"] + (["192.0.2.10"] if operation == "delete" else [])
    _, last = device._block("interface " + PORT)
    device.lines[last:last] = [" ip helper-address " + address for address in helpers]
    device.saved = list(device.lines)
    report = "Helper address is " + "\n                    ".join(helpers)
    device.check_override = {
        IP_INTERFACE: fixture("ip-interface-before").replace("Helper address is not set", report),
    }
    runtime = make_runtime(tmp_path, device)
    denied = execute.preview(runtime, "lab-ios", req("dhcp-relay", operation, HELPER))
    assert denied["reason_codes"] == ["endpoint_impact_required"], denied
    approved = execute.preview(runtime, "lab-ios", req("dhcp-relay", operation, HELPER, endpoint_impact=HELPER))
    assert approved["result"] == "ready", approved
    assert not device.applied_blocks
