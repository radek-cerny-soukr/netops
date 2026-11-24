"""Full Admin operations over fixture-backed Junos CLI, including the RO account and undo."""

from dataclasses import replace
import json
from pathlib import Path
import re

import pytest

from enrollment_helpers import certify
from fake_junos import FakeJunos
from test_junos import NAME, make_runtime, request, steps

from netops_admin import exec_junos, execute
from netops_admin.access import AccessError
from netops_admin.errors import Rejected
from approved_apply import approved_apply

FIXTURES = Path(__file__).parent / "fixtures" / "junos_junos_static_routing"
V4, V6 = "198.51.100.0/24", "2001:db8:139:1::/64"
# RFC 2544 benchmarking prefix for a client network outside every connected subnet: the anonymised baseline already
# uses all three documentation /24s as connected subnets (written as a prefix: no full non-documentation address)
REMOTE_NET = "198.18.0."
IRB = "irb.3920"
VLAN = "netops-junos-static-routing-test"
VLAN_2 = "netops-junos-static-routing-other"
VRRP = "irb.3920:139"
ROUTE = r"routing-options (?:rib inet6[.]0 )?static route"
VRRP_PATH = r"interfaces irb unit [0-9]+ family inet address \S+ vrrp-group [0-9]+"
EDIT = re.compile(rf"(?:{ROUTE} \S+|{VRRP_PATH}|interfaces irb unit [0-9]+|vlans \S+ l3-interface)(?: .*)?")
SINGLE = re.compile(rf"(?:{ROUTE} \S+ preference|{VRRP_PATH} priority|vlans \S+ l3-interface) \S+")


def fixture(name):
    return (FIXTURES / name).read_text()


def field(value):
    return [{"data": str(value)}]


class FakeL3(FakeJunos):
    def __init__(self):
        super().__init__()
        self.ssh_paths = [("192.0.2.56", "192.0.2.81")]
        self.lines.extend((f"set vlans {VLAN} vlan-id 3920", f"set vlans {VLAN_2} vlan-id 3921"))
        self.check_fault = None

    def _line(self, line, session):
        action, _, path = line.partition(" ")
        if action in ("set", "delete") and EDIT.fullmatch(path):
            candidate = self._candidate(session)
            if action == "delete":
                target = "set " + path
                candidate[:] = [row for row in candidate if row != target and not row.startswith(target + " ")]
            else:
                if SINGLE.fullmatch(path):
                    target = "set " + path.rsplit(" ", 1)[0] + " "
                    candidate[:] = [row for row in candidate if not row.startswith(target)]
                if line not in candidate:
                    candidate.append(line)
            return ""
        return super()._line(line, session)

    def query(self, command):
        if command == "show interfaces terse | no-more":
            return super().query("show interfaces terse")
        if command.startswith("show route ") and command.endswith(" | no-more"):
            return super().query(command.removesuffix(" | no-more"))
        return super().query(command)

    def check_query(self, command):
        assert "configuration" not in command
        if self.check_fault and (answer := self.check_fault(command)) is not None:
            return answer
        match = re.fullmatch(r"show route table (inet6?[.]0) (\S+) exact( hidden)? \| display json \| no-more",
                             command)
        if match:
            self.check_queries.append(command)
            return self._route_report(*match.groups())
        match = re.fullmatch(r"show interfaces (irb[.][0-9]+) terse \| display json \| no-more", command)
        if match:
            self.check_queries.append(command)
            return self._irb_report(match[1])
        match = re.fullmatch(r"show vlans (\S+) extensive \| display json \| no-more", command)
        if match and match[1] in (VLAN, VLAN_2):
            self.check_queries.append(command)
            return self._vlan_report(match[1])
        if command == "show vrrp detail | no-more":
            self.check_queries.append(command)
            return self._vrrp_report()
        return super().check_query(command)

    def _route_report(self, rib, key, hidden):
        empty = fixture("route6-empty.json" if rib == "inet6.0" else "route4-empty.json")
        if hidden:
            return empty
        records = {}
        for line in self.lines:
            if match := re.fullmatch(rf"set {ROUTE} {re.escape(key)} (next-hop|preference) (\S+)", line):
                records[match[1]] = match[2]
        if "next-hop" not in records:
            return empty
        report = json.loads(fixture("route-present.json"))
        table, = report["route-information"][0]["route-table"]
        table["table-name"] = field(rib)
        route, = table["rt"]
        route["rt-destination"] = field(key)
        entry, = route["rt-entry"]
        entry["preference"] = field(records.get("preference", "5"))
        entry["nh"][0]["to"] = field(records["next-hop"])
        return json.dumps(report)

    def _irb_report(self, key):
        source = [match.groups() for line in self.lines if (match := re.fullmatch(
            rf"set interfaces irb unit {key[4:]} family (inet6?) address (\S+)", line))]
        empty = fixture("irb-empty.json")
        if not source:
            return empty
        report = json.loads(fixture("irb-present.json"))
        root, = report["interface-information"]
        first, = root["logical-interface"]
        first["name"] = field(key)
        first["address-family"] = [{"address-family-name": field(family),
                                    "interface-address": [{"ifa-local": field(address)}]}
                                   for family, address in source]
        return json.dumps(report)

    def _vlan_report(self, name):
        report = json.loads(fixture("vlan-present.json"))
        root, = report["l2ng-l2ald-vlan-instance-information"]
        first = root["l2ng-l2ald-vlan-instance-group"][0]
        first["l2ng-l2rtb-vlan-name"] = field(name)
        binding = "l2ng-l2rtb-vlan-l3-interface"
        matches = [row.split()[-1] for row in self.lines if row.startswith(f"set vlans {name} l3-interface ")]
        if matches:
            first[binding] = field(matches[0])
        else:
            first.pop(binding, None)
        root["l2ng-l2ald-vlan-instance-group"] = [first]
        return json.dumps(report)

    def _vrrp_report(self):
        records = {}
        for line in self.lines:
            match = re.fullmatch(rf"set {VRRP_PATH} (.+)", line)
            if match:
                name, _, value = match[1].partition(" ")
                records[name] = value
        if not records:
            return fixture("vrrp-empty.txt")
        text = fixture("vrrp-configured.txt")
        return (text.replace("198.51.100.2", records["virtual-address"])
                .replace("Priority: 120,", "Priority: " + records.get("priority", "100") + ",")
                .replace("Preempt: no,", "Preempt: " + ("no" if "no-preempt" in records else "yes") + ","))


def apply(runtime, fake, table, key, op, attrs, label, **fields):
    req = request(table=table, key=key, op=op, changes=attrs, request_id="junos-static-routing-test-" + label, **fields)
    before, history = fake.snapshot(), fake.history[:]
    plan = execute.preview(runtime, NAME, req)
    assert plan["result"] == "ready", plan
    assert fake.snapshot() == before and fake.history == history
    record = execute.apply(runtime, NAME, req, expected_plan_sha256=plan["plan_sha256"])
    assert record["result"] == "confirmed", record
    assert steps(record).index("check_identity_passed") < steps(record).index("confirm_start")
    return record


def undo(runtime, record):
    reason = "Restore exactly the previous configuration"
    preview = execute.preview_undo(runtime, record["change_id"], reason, issue=True)
    assert preview["result"] == "ready", preview
    reverted = execute.undo(runtime, record["change_id"], reason, expected_plan_sha256=preview["plan_sha256"])
    assert reverted["result"] == "confirmed", reverted
    assert steps(reverted).index("check_identity_passed") < steps(reverted).index("confirm_start")


@pytest.mark.parametrize(("key", "first", "second"), [
    (V4, "192.0.2.1", "192.0.2.2"),
    (V6, "2001:db8:139::1", "2001:db8:139::2"),
])
def test_route_create_update_delete_and_restore(tmp_path, key, first, second):
    fake = FakeL3()
    runtime = make_runtime(tmp_path, fake)
    baseline = set(fake.lines)
    created = apply(runtime, fake, "static-route", key, "create", {"next-hop": first, "preference": 5}, "route1")
    saved = set(fake.lines)
    updated = apply(runtime, fake, "static-route", key, "update", {"next-hop": second, "preference": 11}, "route2")
    changed = set(fake.lines)
    deleted = apply(runtime, fake, "static-route", key, "delete", {}, "route3")
    assert set(fake.lines) == baseline
    undo(runtime, deleted)
    assert set(fake.lines) == changed
    undo(runtime, updated)
    assert set(fake.lines) == saved
    undo(runtime, created)
    assert set(fake.lines) == baseline and not fake.pending()


def test_irb_change_preserves_both_existing_vlans(tmp_path):
    fake = FakeL3()
    runtime = make_runtime(tmp_path, fake)
    baseline = set(fake.lines)
    created = apply(runtime, fake, "irb", IRB, "create",
                    {"ipv4-address": "198.51.100.1/24", "ipv6-address": "2001:db8:139::1/64", "vlan": VLAN}, "irb1")
    configured = set(fake.lines)
    updated = apply(runtime, fake, "irb", IRB, "update",
                    {"ipv4-address": "198.51.100.3/24", "ipv6-address": None, "vlan": VLAN_2}, "irb2")
    assert f"set vlans {VLAN} vlan-id 3920" in fake.lines and f"set vlans {VLAN_2} l3-interface {IRB}" in fake.lines
    undo(runtime, updated)
    assert set(fake.lines) == configured
    undo(runtime, created)
    assert set(fake.lines) == baseline and not fake.pending()


@pytest.mark.parametrize(("key", "change", "reason"), [
    ("0.0.0.0/0", {"preference": 31}, "endpoint_impact_required"),
    ("192.0.2.0/24", {"next-hop": "192.0.2.1"}, "junos_l3_management_path"),
    (V4, {"next-hop": "2001:db8::1"}, "junos_l3_scope"),
])
def test_route_refusals_before_any_write(tmp_path, key, change, reason):
    fake = FakeL3()
    runtime = make_runtime(tmp_path, fake)
    before, history = fake.snapshot(), fake.history[:]
    op = "update" if key == "0.0.0.0/0" else "create"
    preview = execute.preview(runtime, NAME, request(table="static-route", key=key, op=op, changes=change))
    assert preview["reason_codes"] == [reason], preview
    assert fake.snapshot() == before and fake.history == history


def test_route_protects_check_address_even_when_translated(tmp_path):
    fake = FakeL3()
    runtime = make_runtime(tmp_path, fake)
    runtime.config.devices[NAME] = replace(runtime.config.devices[NAME], check_address="198.51.100.77")
    certify(runtime, fake, NAME)
    req = request(table="static-route", key=V4, op="create", changes={"next-hop": "192.0.2.1"})
    result = execute.preview(runtime, NAME, req)
    assert result["reason_codes"] == ["junos_l3_management_path"]


def test_irb_refuses_protected_vlan_on_either_side(tmp_path):
    fake = FakeL3()
    fake.lines.extend((f"set vlans {VLAN} l3-interface {IRB}",
                       "set interfaces irb unit 3920 family inet address 198.51.100.1/24"))
    runtime = make_runtime(tmp_path, fake, protected={"vlan": ["3920"]})
    req = request(table="irb", key=IRB, changes={"vlan": VLAN_2})
    result = execute.preview(runtime, NAME, req)
    assert result["reason_codes"] == ["port_protected"]


@pytest.mark.parametrize(("failure", "code"), [
    ("truncated", "junos_l3_read_unavailable"),
    ("timeout", "junos_l3_read_timeout"),
])
def test_incomplete_operational_route_can_never_prove_absence(tmp_path, failure, code):
    fake = FakeL3()
    runtime = make_runtime(tmp_path, fake)

    def fail(command):
        if " exact hidden " not in command:
            return None
        if failure == "timeout":
            raise AccessError("query failed: the connection timed out")
        return fixture("route4-empty.json")[:-5]

    fake.check_fault = fail
    before = fake.history[:]
    req = request(table="static-route", key=V4, op="create", changes={"next-hop": "192.0.2.1"})
    result = execute.preview(runtime, NAME, req)
    assert result["reason_codes"] == [code], result
    assert fake.history == before and not fake.pending()


def test_failed_post_commit_readback_reverts_without_confirmation(tmp_path):
    fake = FakeL3()
    runtime = make_runtime(tmp_path, fake)
    before = set(fake.lines)
    fake.check_fault = lambda command: (fixture("route4-empty.json")[:-5]
                                       if "show route table" in command and fake.pending() else None)
    req = request(table="static-route", key=V4, op="create", changes={"next-hop": "192.0.2.1"})
    preview = execute.preview(runtime, NAME, req)
    record = execute.apply(runtime, NAME, req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "reverted" and "confirm_start" not in steps(record)
    assert set(fake.lines) == before and not fake.pending()


def test_vrrp_priority_and_preempt_are_restored(tmp_path):
    fake = FakeL3()
    fake.lines.extend((f"set vlans {VLAN} l3-interface {IRB}",
                       "set interfaces irb unit 3920 family inet address 198.51.100.1/24"))
    runtime = make_runtime(tmp_path, fake)
    baseline = set(fake.lines)
    created = apply(runtime, fake, "vrrp", VRRP, "create",
                    {"virtual-address": "198.51.100.2", "priority": 120, "preempt": "disabled"}, "vrrp1")
    configured = set(fake.lines)
    updated = apply(runtime, fake, "vrrp", VRRP, "update", {"priority": 121, "preempt": "enabled"}, "vrrp2")
    undo(runtime, updated)
    assert set(fake.lines) == configured
    undo(runtime, created)
    assert set(fake.lines) == baseline and not fake.pending()


def test_vrrp_unavailable_is_refused_before_commit(tmp_path):
    fake = FakeL3()
    fake.lines.append("set interfaces irb unit 3920 family inet address 198.51.100.1/24")
    runtime = make_runtime(tmp_path, fake)
    fake.check_fault = lambda command: fixture("vrrp-target-error.txt") if command == "show vrrp detail | no-more" else None
    request_vrrp = request(table="vrrp", key=VRRP, op="create", changes={"virtual-address": "198.51.100.2"})
    with pytest.raises(Rejected) as caught:
        approved_apply(runtime, NAME, request_vrrp)
    assert caught.value.reason_codes == ["junos_vrrp_unsupported"]
    assert not fake.pending()


def test_untested_firmware_remains_available_with_warning(tmp_path):
    fake = FakeL3()
    fake.firmware = "27.1R1.1"
    fake.lines[0] = "set version " + fake.firmware
    runtime = make_runtime(tmp_path, fake, firmware=fake.firmware)
    req = request(table="static-route", key=V4, op="create", changes={"next-hop": "192.0.2.1"})
    preview = execute.preview(runtime, NAME, req)
    assert preview["result"] == "ready" and preview["firmware_support"]["status"] == "untested"


def test_default_route_requires_a_bound_preview_and_proven_management_return(tmp_path):
    fake = FakeL3()
    runtime = make_runtime(tmp_path, fake)
    key = "0.0.0.0/0"
    req = request(table="static-route", key=key, changes={"preference": 31}, endpoint_impact=key)
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, NAME, req)
    assert caught.value.reason_codes == ["plan_changed"]
    preview = execute.preview(runtime, NAME, req)
    assert preview["result"] == "ready", preview
    fake.ssh_paths = [("192.0.2.56", REMOTE_NET + "81")]
    refused = execute.preview(runtime, NAME, req)
    assert refused["reason_codes"] == ["junos_l3_management_path"], refused


def test_irb_with_the_management_address_cannot_be_deleted(tmp_path):
    fake = FakeL3()
    fake.lines.extend((f"set vlans {VLAN} l3-interface {IRB}",
                       "set interfaces irb unit 3920 family inet address 192.0.2.56/24"))
    runtime = make_runtime(tmp_path, fake)
    before, history = fake.snapshot(), fake.history[:]
    req = request(table="irb", key=IRB, op="delete", changes={})
    outcome = execute.preview(runtime, NAME, req)
    assert outcome["reason_codes"] == ["junos_l3_management_path"], outcome
    assert fake.snapshot() == before and fake.history == history


def test_new_irb_cannot_divert_the_ssh_return_route(tmp_path):
    fake = FakeL3()
    fake.ssh_paths = [("192.0.2.56", "203.0.113.81")]
    runtime = make_runtime(tmp_path, fake)
    req = request(table="irb", key=IRB, op="create", changes={"ipv4-address": "203.0.113.1/24", "vlan": VLAN})
    result = execute.preview(runtime, NAME, req)
    assert result["reason_codes"] == ["junos_l3_management_path"], result

def test_vrrp_readback_retries_while_the_control_process_starts(tmp_path, monkeypatch):
    fake = FakeL3()
    fake.lines.append("set interfaces irb unit 3920 family inet address 198.51.100.1/24")
    runtime = make_runtime(tmp_path, fake)
    attempts = 0

    def read_while_starting(command):
        nonlocal attempts
        if "show vrrp detail" in command and fake.pending():
            attempts += 1
            if attempts < 3:
                return fixture("vrrp-empty.txt")
        return None

    monkeypatch.setattr(exec_junos, "sleep", lambda _: None)
    fake.check_fault = read_while_starting
    apply(runtime, fake, "vrrp", VRRP, "create",
          {"virtual-address": "198.51.100.2", "priority": 120, "preempt": "disabled"}, "vrrp-starting")
    assert attempts == 3 and not fake.pending()

def test_ipv6_route_warns_when_only_ipv4_had_a_successful_live_run(tmp_path):
    fake = FakeL3()
    runtime = make_runtime(tmp_path, fake)
    req = request(table="static-route", key=V6, op="create", changes={"next-hop": "2001:db8:139::1"})
    preview = execute.preview(runtime, NAME, req)
    assert preview["result"] == "ready" and preview["firmware_support"]["status"] == "untested"


def test_hostname_route_protects_resolved_addresses_of_both_accounts(tmp_path):
    fake = FakeL3()
    runtime = make_runtime(tmp_path, fake)
    runtime.config.devices[NAME] = replace(runtime.config.devices[NAME],
                                           address="admin.example", check_address="check.example")
    fake.resolve_addresses = lambda address: {
        "admin.example": {"192.0.2.56"}, "check.example": {"198.51.100.77", "2001:db8::1"},
    }[address]
    certify(runtime, fake, NAME)
    req = request(table="static-route", key=V4, op="create", changes={"next-hop": "192.0.2.1"})
    result = execute.preview(runtime, NAME, req)
    assert result["reason_codes"] == ["junos_l3_management_path"], result
