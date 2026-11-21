"""Admin address and group changes against measured FortiOS CLI readbacks."""
from __future__ import annotations

import json
from pathlib import Path
import re

import pytest
from fake_020 import FortiOS767
from fake_fortios import FakeFortiOS, quoted
from test_execute import make_runtime, request

from netops_admin import engine, execute, fortios, profiles
from netops_admin.errors import Rejected
from netops_core import prompt
from netops_core.fortios import tokenize

ADDRESS, GROUP = fortios.ADDRESS_TABLES
FIRMWARE = "7.6.8 build3744"
FIXTURES = Path(__file__).parent / "fixtures" / "fortios_7_6_8_g21"
INTERFACE_ADDRESS = "n439-v address"
INTERFACE_CAPTURE = FIXTURES.with_name("fortios_7_6_8_net") / "show-firewall-address-n439-v-address__auto-created-by-role-lan.txt"

CASES = {
    "mask": {"subnet": "192.0.2.80/32"},
    "fqdn": {"type": "fqdn", "fqdn": "www.example.invalid"},
    "wildcard": {"type": "fqdn", "fqdn": "*.example.invalid"},
    "range": {"type": "iprange", "start-ip": "192.0.2.90", "end-ip": "192.0.2.99"},
    "mac": {"type": "mac", "macaddr": ["00:00:5e:00:53:07", "00:00:5e:00:53:08"]},
    "geo": {"type": "geography", "country": "CZ"},
    "interface": {"type": "interface-subnet", "interface": "dmz"},
}


def fixture(name):
    return prompt.cleaned((FIXTURES / f"{name}.txt").read_text(), "fortios")


def key(suffix):
    return f"netops-g21-{suffix}"


def show(table, name, state):
    lines = [f"config {table}", f"    edit {quoted(name)}"]
    for field, value in state.items():
        if field in ("macaddr", "member"):
            value = " ".join(quoted(item) for item in tokenize(value))
        elif field in ("comment", "country", "fqdn", "interface"):
            value = quoted(value)
        lines.append(f"        set {field} {value}")
    return "\n".join([*lines, "    next", "end", ""])


class FortiOSG21(FakeFortiOS):
    firmware = ("7.6.8", "3744")

    def __init__(self, *, omit_empty_groups=True):
        super().__init__()
        self.groups = {}
        self.readbacks = {}
        self.omit_empty_groups = omit_empty_groups

    def _run(self, lines, automatic=False):
        if lines[0] == f"config {GROUP}":
            return FortiOS767._run(self, lines, automatic)
        result = super()._run(lines, automatic)
        if lines[0] == f"config {ADDRESS}" and self.addresses.get(key("interface"), {}).get("interface") == "dmz":
            # Measured device behavior. The subnet is materialized from the interface, never written by Admin.
            self.addresses[key("interface")]["subnet"] = "192.0.2.0 255.255.255.0"
        if lines[0] == f"config {ADDRESS}":
            for state in self.addresses.values():
                if state.get("type") == "ipmask":
                    state.pop("type")
        return result

    def snapshot(self):
        original = super().snapshot()
        prefix, _, rest = original.partition(f"config {ADDRESS}\n")
        _, _, suffix = rest.partition("end\n")
        addresses = "".join(show(ADDRESS, name, state).split("\n", 1)[1].removesuffix("end\n")
                            for name, state in self.addresses.items())
        groups = "".join(show(GROUP, name, state).split("\n", 1)[1].removesuffix("end\n")
                         for name, state in self.groups.items())
        interface = fixture("interface-config").split("\n", 1)[1].removesuffix("end\n")
        suffix = suffix.replace("config system interface\n", "config system interface\n" + interface)
        group_section = f"config {GROUP}\n{groups}end\n" if groups or not self.omit_empty_groups else ""
        return f"{prefix}config {ADDRESS}\n{addresses}end\n{group_section}{suffix}"

    def seed(self, table, suffix, capture):
        target = self.addresses if table == ADDRESS else self.groups
        target[key(suffix)] = fortios.shown_object(fixture(capture), table, key(suffix))

    def check_query(self, command):
        self._fire()
        match = re.fullmatch(r'show (firewall address|firewall addrgrp) "([^"]+)"', command)
        if not match:
            return super().check_query(command)
        table, name = match.groups()
        target = self.addresses if table == ADDRESS else self.groups
        state = target.get(name)
        if self.check_unreadable:
            raise RuntimeError("check account unavailable")
        if state is None:
            return fixture("address-absent" if table == ADDRESS else "group-absent")
        # Replay measured output for the independently simulated state, including its per-member quoting.
        view = {field: value for field, value in state.items() if field != "uuid"}
        for capture in self.readbacks.get(name, ()):
            text = fixture(capture)
            measured = fortios.parse_snapshot(text).sub[table].entries[name]
            measured = {field: attr.value() if field != "member" else list(attr.values)
                        for field, attr in measured.attrs.items() if field != "uuid"}
            expected = dict(view)
            if "member" in expected and "member" in measured:
                expected["member"] = sorted(tokenize(expected["member"]))
                measured["member"].sort()
            if expected == measured:
                return text
        return show(table, name, state)


def ask(table, suffix, op, changes):
    return request(table=table, key=key(suffix), op=op, changes=changes, request_id=f"g21-{suffix}-{op}")


def apply_preview(rt, device, req):
    before = device.snapshot()
    written = list(device.applied_blocks)
    preview = execute.preview(rt, "lab", req)
    assert preview["result"] == "ready", preview
    assert device.snapshot() == before and device.applied_blocks == written
    record = execute.apply(rt, "lab", req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", record
    assert engine.verify(record["plan"], device.snapshot().encode())["result"] == "match"
    return record, before


def undo(rt, device, record):
    preview = execute.preview_undo(rt, record["change_id"], "Restore G21 baseline", issue=True)
    assert preview["result"] == "ready", preview
    restored = execute.undo(rt, record["change_id"], "Restore G21 baseline", preview["plan_sha256"])
    assert restored["result"] == "confirmed", restored
    assert engine.verify(record["plan"], device.snapshot().encode(), expect="before")["result"] == "match"
    assert not device.stitches and not device.actions and not device.triggers


@pytest.mark.parametrize("suffix", CASES)
def test_create_and_undo_address_via_admin_and_real_readback(tmp_path, suffix):
    device = FortiOSG21()
    capture = suffix + "-created"
    expected = fortios.shown_object(fixture(capture), ADDRESS, key(suffix))
    device.readbacks[key(suffix)] = (capture,)
    rt = make_runtime(tmp_path, device)
    record, before = apply_preview(rt, device, ask(ADDRESS, suffix, "create", CASES[suffix]))
    assert engine.observed_state(record["plan"], expected) == record["plan"]["predicted"]["after"]
    assert device.check_query(f'show {ADDRESS} "{key(suffix)}"') == fixture(capture)
    undo(rt, device, record)
    assert device.snapshot() == before


@pytest.mark.parametrize("suffix", ["range", "mac", "fqdn", "wildcard", "geo", "interface"])
def test_delete_and_undo_recreate_address_values(tmp_path, suffix):
    device = FortiOSG21()
    capture = suffix + "-created"
    device.seed(ADDRESS, suffix, capture)
    device.readbacks[key(suffix)] = (capture,)
    rt = make_runtime(tmp_path, device)
    record, _ = apply_preview(rt, device, ask(ADDRESS, suffix, "delete", {}))
    assert record["plan"]["inverse_identity_changes"] == ["uuid"]
    assert key(suffix) not in device.addresses
    undo(rt, device, record)
    assert device.check_query(f'show {ADDRESS} "{key(suffix)}"') == fixture(capture)


def test_update_range_and_undo_uses_real_before_and_after(tmp_path):
    device = FortiOSG21()
    device.seed(ADDRESS, "range", "range-created")
    device.readbacks[key("range")] = ("range-created", "range-updated")
    rt = make_runtime(tmp_path, device)
    update = ask(ADDRESS, "range", "update", {"start-ip": "192.0.2.100", "end-ip": "192.0.2.110"})
    record, before = apply_preview(rt, device, update)
    assert device.check_query(f'show {ADDRESS} "{key("range")}"') == fixture("range-updated")
    undo(rt, device, record)
    assert device.snapshot() == before


@pytest.mark.parametrize("op", ["create", "update", "delete"])
def test_group_lifecycle_and_undo_with_real_readbacks(tmp_path, op):
    device = FortiOSG21()
    for suffix in ("mask", "fqdn", "range"):
        device.seed(ADDRESS, suffix, suffix + "-created")
    if op != "create":
        device.seed(GROUP, "group", "group-created")
    device.readbacks[key("group")] = ("group-created", "group-updated")
    rt = make_runtime(tmp_path, device)
    changes = {
        "create": {"member": [key("mask"), key("range")], "comment": "G21 group"},
        "update": {"member": [key("mask"), key("fqdn")], "comment": "G21 updated"},
        "delete": {},
    }[op]
    record, _ = apply_preview(rt, device, ask(GROUP, "group", op, changes))
    readback = fixture({"create": "group-created", "update": "group-updated", "delete": "group-absent"}[op])
    assert device.check_query(f'show {GROUP} "{key("group")}"') == readback
    observed = fortios.shown_object(readback, GROUP, key("group"))
    assert engine.observed_state(record["plan"], observed) == record["plan"]["predicted"]["after"]
    undo(rt, device, record)


def test_group_digest_treats_explicit_and_omitted_empty_sections_equally(tmp_path):
    device = FortiOSG21(omit_empty_groups=False)
    rt = make_runtime(tmp_path, device)
    req = ask(ADDRESS, "mask", "create", CASES["mask"])
    assert f"config {GROUP}\nend\n" in device.snapshot()
    record, _ = apply_preview(rt, device, req)
    device.omit_empty_groups = True
    omitted = device.snapshot()
    assert f"config {GROUP}\n" not in omitted
    assert engine.verify(record["plan"], omitted.encode())["rest_matches"]
    assert fortios.load(omitted, FIRMWARE).rest_digest(ADDRESS, key("mask")) == record["plan"]["rest_sha256"]


def test_group_delete_preview_refuses_oversized_cli_inverse(tmp_path):
    device = FortiOSG21()
    device.seed(ADDRESS, "mask", "mask-created")
    device.seed(GROUP, "group", "group-created")
    members = [f"netops-g21-{i:014d}" for i in range(40)]
    for name in members:
        device.addresses[name] = {"subnet": device.addresses[key("mask")]["subnet"]}
    device.groups[key("group")]["member"] = " ".join(members)
    rt = make_runtime(tmp_path, device)
    preview = execute.preview(rt, "lab", ask(GROUP, "group", "delete", {}))
    assert preview["result"] == "rejected", preview
    assert preview["reason_codes"] == ["safeguard_script_limit"]
    assert "inverse exceeds the safeguard script limit" in preview["reasons"][0]
    assert not device.applied_blocks


@pytest.mark.parametrize("op", ["create", "update", "delete"])
def test_group_preserves_measured_interface_address_name(tmp_path, op):
    device = FortiOSG21(omit_empty_groups=False)
    device.addresses[INTERFACE_ADDRESS] = fortios.shown_object(INTERFACE_CAPTURE.read_text(), ADDRESS, INTERFACE_ADDRESS)
    device.seed(ADDRESS, "mask", "mask-created")
    if op != "create":
        device.seed(GROUP, "group", "group-created")
        device.groups[key("group")]["member"] = quoted(INTERFACE_ADDRESS)
    rt = make_runtime(tmp_path, device)
    changes = {"create": {"member": [INTERFACE_ADDRESS, key("mask")]}, "update": {"comment": "G21 updated"},
               "delete": {}}[op]
    record, _ = apply_preview(rt, device, ask(GROUP, "group", op, changes))
    plan = record["plan"]
    if op == "create":
        assert f'set member "{INTERFACE_ADDRESS}" "{key("mask")}"' in [line.strip() for line in plan["commands"]]
    elif op == "update":
        assert all(not line.lstrip().startswith("set member") for line in plan["commands"])
    else:
        assert f'set member "{INTERFACE_ADDRESS}"' in [line.strip() for line in plan["inverse"]]
    undo(rt, device, record)


def test_referenced_nested_group_and_address_are_refused_before_writes(tmp_path):
    device = FortiOSG21()
    device.seed(ADDRESS, "mac", "mac-created")
    device.seed(GROUP, "child", "child-created")
    device.seed(GROUP, "parent", "parent-created")
    rt = make_runtime(tmp_path, device)
    for table, suffix in ((ADDRESS, "mac"), (GROUP, "child")):
        with pytest.raises(Rejected, match="referenced"):
            execute.apply(rt, "lab", ask(table, suffix, "delete", {}))
    assert fortios.cli_error(fixture("mac-delete-referenced")) == "Command fail"
    assert not device.applied_blocks


@pytest.mark.parametrize("changes, reason", [
    ({"type": "fqdn", "subnet": "192.0.2.80/32"}, "does not accept subnet"),
    ({"type": "iprange", "end-ip": "192.0.2.99"}, "needs start-ip"),
    ({"type": "iprange", "start-ip": "192.0.2.99", "end-ip": "192.0.2.90"}, "start-ip must"),
    ({"type": "mac", "macaddr": ["not-a-mac"]}, "needs MAC addresses"),
    ({"type": "interface-subnet", "interface": "missing"}, "has no static IPv4 subnet"),
])
def test_invalid_address_is_refused_before_writes(tmp_path, changes, reason):
    device = FortiOSG21()
    rt = make_runtime(tmp_path, device)
    with pytest.raises(Rejected, match=reason):
        execute.apply(rt, "lab", ask(ADDRESS, "invalid", "create", changes))
    assert not device.applied_blocks


def test_protected_and_already_bound_interfaces_are_refused(tmp_path):
    device = FortiOSG21()
    req = ask(ADDRESS, "other", "create", CASES["interface"])
    rt = make_runtime(tmp_path, device, protected={"system interface": ["dmz"]})
    with pytest.raises(Rejected, match="protected"):
        execute.apply(rt, "lab", req)
    device.seed(ADDRESS, "interface", "interface-created")
    with pytest.raises(Rejected, match="already has"):
        execute.apply(rt, "lab", req)
    assert not device.applied_blocks


def test_a_truncated_independent_readback_returns_the_change(tmp_path):
    device = FortiOSG21()
    original_check = device.check_query
    before = device.snapshot()

    def truncated(command):
        answer = original_check(command)
        if key("fqdn") in device.addresses and command == f'show {ADDRESS} "{key("fqdn")}"':
            return fixture("fqdn-created").split("    next", 1)[0]
        return answer

    device.check_query = truncated
    rt = make_runtime(tmp_path, device)
    record = execute.apply(rt, "lab", ask(ADDRESS, "fqdn", "create", CASES["fqdn"]))
    assert record["result"] == "reverted", record
    assert device.snapshot() == before


def test_webhook_inverse_contains_typed_mac_subtable():
    device = FortiOSG21()
    device.seed(ADDRESS, "mac", "mac-created")
    snapshot = device.snapshot().replace("7.6.8-FW-build3744", "8.0.2-FW-build0251")
    plan = engine.build_plan("fortios", snapshot.encode(), ask(ADDRESS, "mac", "delete", {}))
    profile = profiles.find_profile("fortios", ADDRESS, plan["firmware"])
    inverse = fortios.rest_inverse(profile, "delete", key("mac"), plan["inverse"], "192.0.2.1")
    assert plan["firmware_support"]["status"] == "untested"
    assert inverse["method"] == "post"
    assert json.loads(inverse["body"]) == {
        "name": key("mac"), "type": "mac",
        "macaddr": [{"macaddr": address} for address in CASES["mac"]["macaddr"]],
    }
