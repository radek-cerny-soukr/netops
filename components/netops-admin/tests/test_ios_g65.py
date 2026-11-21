"""G65 preview/apply/undo over measured Cisco IOS DHCP responses."""
from pathlib import Path
import re

import pytest

from conftest import request_bytes
from fake_ios import FakeIos
from test_ios import make_runtime, steps
from netops_admin import engine, exec_ios, execute, ios
from netops_admin.access import AccessError
from netops_admin.errors import Rejected
from netops_admin.request import parse_request

FIXTURES = Path(__file__).parent / "fixtures" / "ios_g65"
POOL = "NETOPS-G65-POOL"
HOST = "NETOPS-G65-HOST"
PORT = "GigabitEthernet0/2"
RELAY = PORT + ":192.0.2.10"
NETWORK = "192.0.2.0 255.255.255.0"
HARDWARE = "0000.5e00.5301"
CLIENT = "0102.0000.0000.42"


def fixture(name):
    return (FIXTURES / (name + ".txt")).read_text()


def req(table, op, key, changes=None, **fields):
    return parse_request(request_bytes(table=table, op=op, key=key, changes=changes or {}, **fields))


def cleaned(lines):
    return [re.sub(r" +", " ", line.strip()) if not line.startswith(" ") else
            " " + re.sub(r" +", " ", line.strip()) for line in lines]


def pool(name, variant="ios-pools"):
    section = next(lines.splitlines() for lines in fixture(variant).split("ip dhcp pool ")[1:]
                   if lines.splitlines()[0] == name)
    return ["ip dhcp pool " + section[0], *cleaned(section[1:])]


RANGE = " ".join(fixture("ios-exclusions").splitlines()[1].split())


class DhcpIos(FakeIos):
    def __init__(self):
        super().__init__("iosv")
        # The two capture sets used 192.0.2 for different subnets. Move only the
        # old fixture's synthetic management address to keep them distinct.
        self.lines = [line.replace("192.0.2.51", "203.0.113.51") for line in self.lines]
        self.set_relay("before")
        self.saved = list(self.lines)
        self.replays = []

    def set_relay(self, phase):
        start, end = self._block("interface " + PORT)
        lines = fixture("ios-interface-" + phase).split("interface " + PORT + "\n")[1].splitlines()
        self.lines[start + 1:end] = cleaned(lines[:-1])

    def query(self, command):
        if command in self.query_override:
            return super().query(command)
        if command == "show ip dhcp pool " + POOL:
            return fixture("ios-dhcp-pool")
        if command.startswith("show running-config | section ^ip dhcp pool "):
            name = command.split("pool ")[1].split("$", 1)[0]
            header = "ip dhcp pool " + name
            if header in self.lines:
                start, end = self._block(header)
                return "\n".join(self.lines[start:end]) + "\nend\n"
            return fixture("ios-pool-check-before")
        if command.startswith("show running-config | include ^ip dhcp excluded-address "):
            line = command.split("^")[1].split("$")[0].replace("[.]", ".")
            if line in self.lines:
                return line + "\nend\n"
            return fixture("ios-excl-check-before")
        if command == "show running-config interface " + PORT:
            phase = "after" if "ip helper-address 192.0.2.10" in self.interface(PORT) else "before"
            return fixture("ios-interface-" + phase)
        return super().query(command).replace("192.0.2.51", "203.0.113.51")

    def check_query(self, command):
        if command == "show ip interface " + PORT and command not in (self.check_override or {}):
            self.check_queries.append(command)
            phase = "after" if "ip helper-address 192.0.2.10" in self.interface(PORT) else "before"
            return fixture("ios-relay-" + phase)
        return super().check_query(command)

    def apply(self, commands, spec):
        if commands[0] != "configure terminal":
            return super().apply(commands, spec)
        expected, config = self.replays.pop(0)
        assert commands == ["configure terminal", *expected, "end"]
        self.applied_blocks.append(commands)
        self.lines = list(config)
        return len(commands)


def dhcp_state(device, *, additions=(), relay=False):
    original = list(device.lines)
    if relay:
        device.set_relay("after")
    state = device.lines[:-1] + list(additions) + ["end"]
    device.lines = original
    return state


@pytest.mark.parametrize("table,key,changes,positive,inverse,capture,relay", [
    ("dhcp-pool", POOL, {"network": "192.0.2.0/24", "default-router": "192.0.2.1 192.0.2.2",
                        "dns-server": "192.0.2.3 192.0.2.4"}, pool(POOL),
     ["no ip dhcp pool " + POOL], pool(POOL), False),
    ("dhcp-reservation", HOST, {"host": "192.0.2.41 255.255.255.0", "hardware-address": HARDWARE},
     pool(HOST), ["no ip dhcp pool " + HOST], pool(HOST), False),
    ("dhcp-exclusion", "192.0.2.20-192.0.2.29", {}, [RANGE], ["no " + RANGE], [RANGE], False),
    ("dhcp-relay", RELAY, {}, ["interface " + PORT, "ip helper-address 192.0.2.10"],
     ["interface " + PORT, "no ip helper-address 192.0.2.10"], [], True),
])
def test_create_and_confirmed_undo(tmp_path, table, key, changes, positive, inverse, capture, relay):
    device = DhcpIos()
    runtime = make_runtime(tmp_path, device)
    before = device.snapshot()
    after = dhcp_state(device, additions=capture, relay=relay)
    positive = [line.strip() for line in positive]
    device.replays.extend([(positive, after), (inverse, device.lines)])
    request = req(table, "create", key, changes)
    preview = execute.preview(runtime, "lab-ios", request)
    assert preview["result"] == "ready", preview
    assert device.snapshot() == before and not device.applied_blocks
    assert preview["commands"] == ["configure terminal", *positive, "end"]
    record = execute.apply(runtime, "lab-ios", request, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", (record["reason"], steps(record))
    assert "check_identity_passed" in steps(record)
    assert engine.verify(record["plan"], device.snapshot().encode())["result"] == "match"
    rollback = execute.preview_undo(runtime, record["change_id"], "return G65 test object")
    assert rollback["result"] == "ready" and rollback["commands"] == ["configure terminal", *inverse, "end"]
    returned = execute.undo(runtime, record["change_id"], "return G65 test object")
    assert returned["result"] == "confirmed", (returned["reason"], steps(returned))
    assert device.snapshot() == before
    assert device.timer is None and device.saved == device.lines and not device.replays


def test_update_switches_id_and_host_then_restores_measured_hardware_binding(tmp_path):
    device = DhcpIos()
    before = dhcp_state(device, additions=pool(HOST))
    after = dhcp_state(device, additions=pool(HOST, "ios-pools-updated"))
    device.lines, device.saved = before, list(before)
    device.replays.extend([
        (["ip dhcp pool " + HOST, "no hardware-address", "host 192.0.2.42 255.255.255.0",
          "client-identifier " + CLIENT], after),
        (["ip dhcp pool " + HOST, "no client-identifier", "host 192.0.2.41 255.255.255.0",
          "hardware-address " + HARDWARE], before),
    ])
    runtime = make_runtime(tmp_path, device)
    request = req("dhcp-reservation", "update", HOST,
                  {"host": "192.0.2.42 255.255.255.0", "client-identifier": CLIENT, "hardware-address": None})
    preview = execute.preview(runtime, "lab-ios", request)
    assert preview["result"] == "ready" and not device.applied_blocks
    changed = execute.apply(runtime, "lab-ios", request, expected_plan_sha256=preview["plan_sha256"])
    assert changed["result"] == "confirmed", (changed["reason"], steps(changed))
    assert changed["plan"]["predicted"]["after"]["client-identifier"] == CLIENT
    returned = execute.undo(runtime, changed["change_id"], "return to hardware address")
    assert returned["result"] == "confirmed", (returned["reason"], steps(returned))
    assert device.lines == before


def test_pool_changes_network_only_after_removing_the_old_subnet(tmp_path):
    device = DhcpIos()
    before = dhcp_state(device, additions=pool(POOL))
    after = dhcp_state(device, additions=pool(POOL, "ios-pool-narrowed"))
    device.lines, device.saved = before, list(before)
    narrower = "192.0.2.0 255.255.255.128"
    commands = [
        "ip dhcp pool " + POOL, "no network " + NETWORK, "no dns-server",
        "network " + narrower, "default-router 192.0.2.2",
    ]
    inverse = [
        "ip dhcp pool " + POOL, "no network " + narrower, "network " + NETWORK,
        "default-router 192.0.2.1 192.0.2.2", "dns-server 192.0.2.3 192.0.2.4",
    ]
    device.replays.extend([(commands, after), (inverse, before)])
    runtime = make_runtime(tmp_path, device)
    request = req("dhcp-pool", "update", POOL,
                  {"network": "192.0.2.0/25", "default-router": "192.0.2.2", "dns-server": None})

    preview = execute.preview(runtime, "lab-ios", request)
    assert preview["result"] == "ready"
    assert preview["commands"] == ["configure terminal", *commands, "end"]
    assert not device.applied_blocks
    record = execute.apply(runtime, "lab-ios", request, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", (record["reason"], steps(record))
    returned = execute.undo(runtime, record["change_id"], "restore /24 DHCP network")
    assert returned["result"] == "confirmed", (returned["reason"], steps(returned))
    assert device.lines == before


@pytest.mark.parametrize("answer", [fixture("ios-ro-config-refused"), ""])
def test_refused_or_missing_end_is_not_absence(tmp_path, answer):
    device = DhcpIos()
    device.query_override["show running-config | section ^ip dhcp pool " + POOL + "$|^end$"] = answer
    runtime = make_runtime(tmp_path, device)
    preview = execute.preview(runtime, "lab-ios", req("dhcp-pool", "create", POOL, {"network": NETWORK}))
    assert preview["result"] == "rejected"
    assert preview["reason_codes"] == ["ios_dhcp_readback_unreadable"]
    assert not device.applied_blocks


def test_timeout_is_distinguished_from_refusal(tmp_path):
    device = DhcpIos()
    def timeout(_, command):
        if command.startswith("show running-config | section"):
            raise AccessError("query timed out")
    device.on_query = timeout
    command = "show running-config | section ^ip dhcp pool " + POOL + "$|^end$"
    device.query_override[command] = "end\n"
    runtime = make_runtime(tmp_path, device)
    preview = execute.preview(runtime, "lab-ios", req("dhcp-pool", "create", POOL, {"network": NETWORK}))
    assert preview["reason_codes"] == ["ios_dhcp_read_timeout"]
    assert not device.applied_blocks


def test_readback_mismatch_returns_the_checkpoint_without_confirming(tmp_path):
    device = DhcpIos()
    before = device.snapshot()
    device.replays.append((["ip dhcp pool " + POOL, "network " + NETWORK],
                           dhcp_state(device, additions=pool(POOL)[:2])))
    device.query_override["show running-config | section ^ip dhcp pool " + POOL + "$|^end$"] = fixture(
        "ios-pool-check-before")
    runtime = make_runtime(tmp_path, device)
    request = req("dhcp-pool", "create", POOL, {"network": NETWORK})
    preview = execute.preview(runtime, "lab-ios", request)
    assert preview["result"] == "ready"
    result = execute.apply(runtime, "lab-ios", request, expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "reverted", (result["reason"], steps(result))
    assert "check_identity_failed" in steps(result)
    assert "configure confirm" not in device.sent_lines
    assert device.snapshot() == before and device.saved == device.lines and device.timer is None
    assert device.saved_while_pending == 0


def test_empty_and_wrong_kind_pools_are_never_overwritten(tmp_path):
    device = DhcpIos()
    device.lines = dhcp_state(device, additions=pool("NETOPS-G65-EMPTY") + pool(HOST))
    device.saved = list(device.lines)
    runtime = make_runtime(tmp_path, device)
    for key in ("NETOPS-G65-EMPTY", HOST):
        preview = execute.preview(runtime, "lab-ios", req("dhcp-pool", "create", key, {"network": NETWORK}))
        assert preview["result"] == "rejected"
    assert not device.applied_blocks


def test_management_scope_protected_even_when_valid_dhcp(tmp_path):
    device = DhcpIos()
    runtime = make_runtime(tmp_path, device)
    for request in (req("dhcp-relay", "create", "GigabitEthernet0/0:192.0.2.10"),
                    req("dhcp-exclusion", "create", "203.0.113.51"),
                    req("dhcp-pool", "create", POOL, {"network": "203.0.113.0/24"})):
        result = execute.preview(runtime, "lab-ios", request)
        assert result["reason_codes"] == ["port_management_interface"], result
    assert not device.applied_blocks


def test_unrelated_exclusions_and_helpers_are_in_the_rest_digest():
    device = DhcpIos()
    before = device.snapshot().encode()
    request = req("dhcp-relay", "create", RELAY)
    plan = engine.build_plan("ios", before, request, firmware=device.firmware)
    actual = ios.snapshot_after(before.decode(), plan)
    assert engine.verify(plan, actual.encode())["result"] == "match"
    with_other_helper = actual.replace(" ip helper-address", " ip helper-address 192.0.2.11\n ip helper-address", 1)
    assert engine.verify(plan, with_other_helper.encode())["rest_matches"] is False
    assert exec_ios.observe(device, plan) is None


def test_review_3_dhcp_write_requires_a_preview_hash(tmp_path):
    device = DhcpIos()
    rules = pool(POOL)[:2]
    device.replays.append(([line.strip() for line in rules], dhcp_state(device, additions=rules)))
    runtime = make_runtime(tmp_path, device)
    change = req(ios.DHCP_POOL, "create", POOL, {"network": NETWORK})
    assert execute.preview(runtime, "lab-ios", change)["result"] == "ready"
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab-ios", change)
    assert caught.value.reason_codes == ["plan_changed"]
    assert not device.applied_blocks


def test_review_7_leased_pool_requires_impact(tmp_path):
    device = DhcpIos()
    device.lines = dhcp_state(device, additions=pool(POOL))
    device.saved = list(device.lines)
    device.query_override["show ip dhcp pool " + POOL] = re.sub(
        r"(?m)^( Leased addresses\s+: )0$", r"\g<1>1", fixture("ios-dhcp-pool"))
    runtime = make_runtime(tmp_path, device)
    changes = {"dns-server": "192.0.2.4"}
    refused = execute.preview(runtime, "lab-ios", req(ios.DHCP_POOL, "update", POOL, changes))
    assert refused["reason_codes"] == ["endpoint_impact_required"]
    accepted = execute.preview(runtime, "lab-ios", req(ios.DHCP_POOL, "update", POOL, changes, endpoint_impact=POOL))
    assert accepted["result"] == "ready" and "Explicit DHCP impact accepted for " + POOL in accepted["prechecks"]
    assert not device.applied_blocks


def test_review_7_last_helper_on_active_svi_requires_impact(tmp_path):
    device = DhcpIos()
    svi = "Vlan165"
    key = svi + ":192.0.2.10"
    device.lines[-1:-1] = ["interface " + svi, " ip address 198.51.100.1 255.255.255.0",
                            " ip helper-address 192.0.2.10", "!"]
    device.saved = list(device.lines)
    device.check_override = {"show ip interface " + svi: fixture("ios-relay-after").replace(PORT, svi)}
    device.query_override["show running-config interface " + svi] = (
        fixture("ios-interface-after").replace(PORT, svi).replace(" vrf forwarding blue\n", ""))
    runtime = make_runtime(tmp_path, device)
    refused = execute.preview(runtime, "lab-ios", req(ios.DHCP_RELAY, "delete", key))
    assert refused["reason_codes"] == ["endpoint_impact_required"]
    accepted = execute.preview(runtime, "lab-ios", req(ios.DHCP_RELAY, "delete", key, endpoint_impact=key))
    assert accepted["result"] == "ready" and "Explicit DHCP impact accepted for " + key in accepted["prechecks"]
    assert not device.applied_blocks
