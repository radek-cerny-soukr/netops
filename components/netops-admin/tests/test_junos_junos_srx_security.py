"""JUNOS-SRX-SECURITY SRX zones, global address book, security policies and NAT through Admin and the Junos transport boundary.

There is no SRX in the lab: the configuration is derived from the Juniper documentation and the zone readback uses the
documented `show security zones <zone>` output (tests/fixtures/junos_junos_srx_security/PROVENANCE.md).
"""

from __future__ import annotations

from functools import partial
import itertools
import re
from pathlib import Path

import pytest
from conftest import request_bytes
from fake_junos import BASELINE, FIRMWARE, FakeJunos
from test_junos import NAME, make_runtime as _make_runtime, steps

from netops_admin import exec_junos, execute, junos, junos_srx
from netops_admin.engine import build_plan, verify
from netops_admin.errors import Rejected
from netops_admin.request import parse_request

make_runtime = partial(_make_runtime, simulate_unmeasured_profiles=True)


FIXTURES = Path(__file__).parent / "fixtures" / "junos_junos_srx_security"
IDS = itertools.count(1)
POLICY_KEY = "trust@DMZ@permit-http"
MAIL_KEY = "trust@DMZ@permit-mail-trust-DMZ"


def fixture(name):
    return (FIXTURES / name).read_text()


BASE = fixture("srx-base-set.txt")


def request(table, key, changes, op="create", **fields):
    return parse_request(request_bytes(table=table, key=key, changes=changes, op=op,
                                       request_id=f"junos-srx-security-unit-{next(IDS):04}", **fields))


def plan(req, extra=BASE, firmware=FIRMWARE, **kwargs):
    return build_plan("junos", (BASELINE + extra).encode(), req, firmware=firmware, **kwargs)


class SrxLab(FakeJunos):
    """A candidate that takes `security` statements and answers the documented zone and capability reads."""

    def __init__(self, config=BASE, *, srx=True, management=("198.51.100.65", "198.51.100.73")):
        super().__init__()
        self.lines.extend(config.splitlines())
        self.srx = srx
        self.ssh_paths = [management]
        self.zone_override = None
        self.management_ingress = "ge-0/0/6.0"
        self.ignore_nat_insert = False

    def _line(self, line, session):
        words = line.split()
        if words[:1] in (["set"], ["delete"]) and words[1:2] == ["security"]:
            assert self.srx, "a switch would have refused the security hierarchy"
            candidate = self._candidate(session)
            statement = "set " + line.split(" ", 1)[1]
            if words[0] == "delete":
                candidate[:] = [item for item in candidate if item != statement and not item.startswith(statement + " ")]
            else:
                parent = statement.rsplit(" ", 1)[0]
                candidate[:] = [item for item in candidate if item != parent]
                if statement not in candidate:
                    candidate.append(statement)
            return ""
        if words[:2] == ["insert", "security"]:
            kind = "rule" if words[2] == "nat" else "policy"
            if kind == "rule" and self.ignore_nat_insert:
                return ""
            moving_path, _, anchor = line.removeprefix("insert ").partition(f" before {kind} ")
            root, _, name = moving_path.rpartition(f" {kind} ")
            old = f"set {root} {kind} {name} "
            new = f"set {root} {kind} {anchor} "
            candidate = self._candidate(session)
            moving = [item for item in candidate if item.startswith(old)]
            candidate[:] = [item for item in candidate if not item.startswith(old)]
            at = next(i for i, item in enumerate(candidate) if item.startswith(new))
            candidate[at:at] = moving
            return ""
        return super()._line(line, session)

    def query(self, command):
        if command == "show security zones | no-more":
            return "" if self.srx else fixture("ex9214-show-security-zones-refused.txt")
        if command == "show interfaces terse | no-more":
            return ("Interface               Admin Link Proto    Local                 Remote\n"
                    "fxp0.0                  up    up   inet     192.0.2.56/24\n"
                    "ge-0/0/6.0              up    up   inet     198.51.100.65/27\n"
                    "lo0.0                   up    up   inet     192.0.2.60/32\n")
        if command.startswith("show security flow session "):
            local, peer = self.ssh_paths[0]
            return (fixture("show-security-flow-ssh.txt").replace("192.0.2.60", local)
                    .replace("198.51.100.73", peer).replace("ge-0/0/6.0", self.management_ingress))
        match = re.fullmatch(r"show configuration (security .+) \| display set \| no-more", command)
        if match:
            path = "set " + match.group(1)
            return "".join(item + "\n" for item in self.lines if item == path or item.startswith(path + " "))
        return super().query(command)

    def check_query(self, command):
        match = re.fullmatch(r"show security zones (\S+)", command)
        if match:
            self.check_queries.append(command)
            if self.zone_override is not None:
                return self.zone_override
            zone = match.group(1)
            ports = sorted(item.split()[-1] for item in self.lines
                           if re.fullmatch(r"set security zones security-zone %s interfaces \S+" % zone, item))
            text = fixture("show-security-zones-abc.txt").splitlines()
            head = [row.replace("abc", zone) for row in text[:4]]
            return "\n".join(head + ["   Interfaces bound: %d" % len(ports), "   Interfaces:"]
                             + ["     " + port for port in ports]) + "\n"
        return super().check_query(command)


def run(tmp_path, req, *, lab=None, undo=True):
    target = lab or SrxLab()
    runtime = make_runtime(tmp_path, target)
    baseline = target.snapshot()
    preview = execute.preview(runtime, NAME, req)
    assert preview["result"] == "ready", preview
    assert target.snapshot() == baseline, "the preview writes nothing"
    assert all(not any(line.startswith("commit") for line in block) for block in target.applied_blocks)
    record = execute.apply(runtime, NAME, req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", (record.get("reason"), record.get("steps"))
    assert "check_identity_passed" in steps(record)
    changed = target.snapshot()
    assert changed != baseline
    if undo:
        back = execute.undo(runtime, record["change_id"], "restore the approved test object")
        assert back["result"] == "confirmed", (back.get("reason"), back.get("steps"))
        assert sorted(target.snapshot().splitlines()) == sorted(baseline.splitlines())
    return record, target, changed


# ---- the plan adapter on the documented configuration ----

def test_snapshot_reads_the_documented_objects():
    snapshot = junos.load(BASELINE + BASE, FIRMWARE)
    zones = snapshot.entries("security-zone")
    assert zones["trust"].attributes == {"interfaces": "ge-0/0/6.0", "host-inbound-services": "ping ssh"}
    assert zones["untrust"].attributes == {} and not zones["untrust"].unsupported
    assert zones["DMZ"].attributes["interfaces"] == "ge-0/0/5.0" and not zones["DMZ"].unsupported
    assert snapshot.entries("address-book-address")["PC-Trust"].attributes == {"prefix": "198.51.100.2/32"}
    assert snapshot.entries("address-book-set")["DMZ-address-set-http"].attributes == {
        "addresses": "Server-HTTP-1 Server-HTTP-2"}
    assert snapshot.entries("security-policy")[MAIL_KEY].attributes == {
        "source-addresses": "PC-Trust", "destination-addresses": "Server-SMTP", "applications": "junos-smtp",
        "action": "permit"}
    assert snapshot.entries("nat-source-rule")["rs1@r1"].attributes == {
        "from-zone": "trust", "to-zone": "untrust", "source-address": "198.51.100.0/27", "translation": "interface"}
    assert snapshot.entries("nat-destination-pool")["dst-nat-pool-1"].attributes == {"address": "198.51.100.34/32"}
    assert snapshot.entries("nat-destination-rule")["rs-dst@r1"].attributes == {
        "from-zone": "untrust", "destination-address": "203.0.113.200/32", "pool": "dst-nat-pool-1"}


def test_policy_with_log_or_identity_is_outside_the_profile():
    extra = BASE + ("set security policies from-zone trust to-zone DMZ policy permit-http then log session-init\n")
    snapshot = junos.load(BASELINE + extra, FIRMWARE)
    assert snapshot.entries("security-policy")[POLICY_KEY].unsupported
    with pytest.raises(Rejected, match="outside the profile"):
        plan(request("security-policy", POLICY_KEY, {"action": "deny"}, op="update", endpoint_impact=POLICY_KEY), extra)


@pytest.mark.parametrize("table, key, changes, expected", [
    ("security-zone", "partner", {"interfaces": "ge-0/0/7.0", "host-inbound-services": "ping"},
     ["set security zones security-zone partner", "set security zones security-zone partner interfaces ge-0/0/7.0",
      "set security zones security-zone partner host-inbound-traffic system-services ping"]),
    ("address-book-address", "Web-2", {"prefix": "198.51.100.41"},
     ["set security address-book global address Web-2 198.51.100.41/32"]),
    ("address-book-set", "Web-set", {"addresses": "Server-HTTP-2 Server-HTTP-1"},
     ["set security address-book global address-set Web-set address Server-HTTP-1",
      "set security address-book global address-set Web-set address Server-HTTP-2"]),
    ("security-policy", "DMZ@trust@back", {"source-addresses": "Server-SMTP", "destination-addresses": "any",
                                           "applications": "junos-smtp", "action": "deny"},
     ["set security policies from-zone DMZ to-zone trust policy back match source-address Server-SMTP",
      "set security policies from-zone DMZ to-zone trust policy back match destination-address any",
      "set security policies from-zone DMZ to-zone trust policy back match application junos-smtp",
      "set security policies from-zone DMZ to-zone trust policy back then deny"]),
    ("nat-source-rule", "rs2@r1", {"from-zone": "DMZ", "to-zone": "untrust", "source-address": "198.51.100.32/27",
                                   "translation": "interface"},
     ["set security nat source rule-set rs2 from zone DMZ", "set security nat source rule-set rs2 to zone untrust",
      "set security nat source rule-set rs2 rule r1 match source-address 198.51.100.32/27",
      "set security nat source rule-set rs2 rule r1 then source-nat interface"]),
    ("nat-destination-pool", "pool-2", {"address": "198.51.100.35"},
     ["set security nat destination pool pool-2 address 198.51.100.35/32"]),
    ("nat-destination-rule", "rs-dst@r2", {"from-zone": "untrust", "destination-address": "203.0.113.201",
                                           "pool": "dst-nat-pool-1"},
     ["set security nat destination rule-set rs-dst rule r2 match destination-address 203.0.113.201/32",
      "set security nat destination rule-set rs-dst rule r2 then destination-nat pool dst-nat-pool-1"]),
])
def test_create_shows_the_exact_commands_and_the_inverse_is_a_delete(table, key, changes, expected):
    if table == "security-policy":
        key = "DMZ@trust@back"
    change = plan(request(table, key, changes))
    commands = [line for line in change["commands"] if line.startswith("set security")]
    assert commands == expected or sorted(commands) == sorted(expected)
    assert all(line.startswith("delete security") for line in change["inverse"] if "security" in line)
    predicted = junos.snapshot_after(BASELINE + BASE, change)
    assert verify(change, predicted.encode())["result"] == "match"


def test_changing_existing_boundary_objects_needs_endpoint_impact():
    cases = [("security-zone", "trust", {"host-inbound-services": "ping"}),
             ("security-policy", POLICY_KEY, {"action": "deny"}),
             ("nat-source-rule", "rs1@r1", {"source-address": "198.51.100.0/28"}),
             ("nat-destination-rule", "rs-dst@r1", {"destination-address": "203.0.113.202"}),
             ("address-book-address", "Server-SMTP", {"prefix": "198.51.100.37"}),
             ("address-book-set", "DMZ-address-set-http", {"addresses": "Server-HTTP-1"}),
             ("nat-destination-pool", "dst-nat-pool-1", {"address": "198.51.100.41"})]
    for table, key, changes in cases:
        with pytest.raises(Rejected) as exc:
            plan(request(table, key, changes, op="update"))
        assert exc.value.reason_codes == ["endpoint_impact_required"], (table, exc.value.reasons)
        approved = plan(request(table, key, changes, op="update", endpoint_impact=key))
        assert approved["endpoint_impact"] == key
        assert any("security boundary" in text for text in approved["prechecks"])
    # an unreferenced address or set and an unused pool change without it
    free = BASE + "set security address-book global address Spare 198.51.100.169/32\n"
    plan(request("address-book-address", "Spare", {"prefix": "198.51.100.170"}, op="update"), free)


def test_update_renders_only_what_changes_and_keeps_other_statements():
    change = plan(request("security-policy", POLICY_KEY, {"action": "deny", "applications": "junos-https"},
                          op="update", endpoint_impact=POLICY_KEY))
    base = "security policies from-zone trust to-zone DMZ policy permit-http"
    assert [line for line in change["commands"] if " security " in " " + line + " "] == [
        f"delete {base} match application junos-http", f"set {base} match application junos-https",
        f"delete {base} then permit", f"set {base} then deny"]
    assert f"set {base} then permit" in change["inverse"]
    zone = plan(request("security-zone", "DMZ", {"interfaces": "ge-0/0/5.0 ge-0/0/7.0"}, op="update",
                        endpoint_impact="DMZ"))
    assert [line for line in zone["commands"] if " security " in " " + line + " "] == [
        "set security zones security-zone DMZ interfaces ge-0/0/7.0"]
    assert 'description "servers"' not in " ".join(zone["commands"] + zone["inverse"])


def test_zone_delete_keeps_description_check_and_dependencies():
    with pytest.raises(Rejected, match="cannot be restored|used by policies"):
        plan(request("security-zone", "DMZ", {}, op="delete", endpoint_impact="DMZ"))
    with pytest.raises(Rejected) as exc:
        plan(request("security-zone", "trust", {}, op="delete", endpoint_impact="trust"))
    assert exc.value.reason_codes == ["junos_srx_dependency"]


@pytest.mark.parametrize("table, key, changes, code", [
    ("security-zone", "partner", {"interfaces": "ge-0/0/6.0"}, "junos_srx_dependency"),      # already in trust
    ("security-zone", "partner", {"interfaces": "ge-0/0/9.0"}, "junos_srx_dependency"),      # no logical unit
    ("security-zone", "partner", {"interfaces": "fxp0.0"}, "port_management_interface"),
    ("address-book-set", "x", {"addresses": "Missing"}, "junos_srx_dependency"),
    ("address-book-address", "DMZ-address-set-http", {"prefix": "192.0.2.1"}, "junos_srx_dependency"),
    ("security-policy", "trust@DMZ@new", {"source-addresses": "Missing", "destination-addresses": "any",
                                          "applications": "any", "action": "permit"}, "junos_srx_dependency"),
    ("security-policy", "trust@nowhere@new", {"source-addresses": "any", "destination-addresses": "any",
                                              "applications": "any", "action": "permit"}, "junos_srx_dependency"),
    ("security-policy", "trust@DMZ@new", {"source-addresses": "any", "destination-addresses": "any",
                                          "applications": "undefined-app", "action": "permit"},
     "junos_srx_dependency"),
    ("nat-source-rule", "rs1@r2", {"from-zone": "trust", "to-zone": "DMZ", "source-address": "192.0.2.128/25",
                                   "translation": "interface"}, "junos_srx_scope"),            # shared rule-set zones
    ("nat-destination-rule", "rs-dst@r2", {"from-zone": "untrust", "destination-address": "203.0.113.5",
                                           "pool": "no-pool"}, "junos_srx_dependency"),
])
def test_dependencies_and_scope_are_refused_before_a_write(table, key, changes, code):
    with pytest.raises(Rejected) as exc:
        plan(request(table, key, changes))
    assert exc.value.reason_codes == [code], exc.value.reasons


def test_referenced_objects_cannot_be_deleted():
    for table, key in (("address-book-address", "Server-HTTP-1"), ("address-book-address", "PC-Trust"),
                       ("address-book-set", "DMZ-address-set-http"), ("nat-destination-pool", "dst-nat-pool-1")):
        with pytest.raises(Rejected) as exc:
            plan(request(table, key, {}, op="delete", endpoint_impact=key))
        assert exc.value.reason_codes == ["junos_srx_dependency"], (table, key)


def test_protected_inventory_names_are_refused():
    with pytest.raises(Rejected) as exc:
        plan(request("security-zone", "partner", {"interfaces": "ge-0/0/7.0"}),
             protected={"interface": ["ge-0/0/7"]})
    assert exc.value.reason_codes == ["port_protected"]
    with pytest.raises(Rejected) as exc:
        plan(request("security-policy", POLICY_KEY, {"action": "deny"}, op="update", endpoint_impact=POLICY_KEY),
             protected={"security-policy": ["permit-http"]})
    assert exc.value.reason_codes == ["port_protected"]


def test_inherited_security_configuration_is_refused():
    extra = BASE + "set groups g1 security zones security-zone trust interfaces ge-0/0/7.0\n"
    with pytest.raises(Rejected) as exc:
        plan(request("security-zone", "partner", {"interfaces": "ge-0/0/7.0"}), extra)
    assert exc.value.reason_codes == ["junos_srx_scope"]


def test_profile_firmware_warning_never_blocks():
    text = (BASELINE.replace(FIRMWARE, "27.1R1.2") + BASE)
    change = build_plan("junos", text.encode(), request("address-book-address", "Web-3", {"prefix": "198.51.100.42"}),
                        firmware="27.1R1.2")
    assert change["firmware_support"]["status"] == "untested"


# ---- end to end through the runtime: preview writes nothing, apply needs the hash, readback, undo ----

@pytest.mark.parametrize("table, key, changes, extra", [
    ("security-zone", "trust", {"interfaces": "ge-0/0/6.0 ge-0/0/7.0", "host-inbound-services": "ping ssh https"},
     {"endpoint_impact": "trust", "op": "update"}),
    ("security-zone", "partner", {"interfaces": "ge-0/0/7.0", "host-inbound-services": "ping"}, {}),
    ("address-book-address", "Web-2", {"prefix": "198.51.100.41"}, {}),
    ("address-book-set", "Web-set", {"addresses": "Server-HTTP-1 PC-Trust"}, {}),
    ("security-policy", "trust@DMZ@extra", {"source-addresses": "PC-Trust", "destination-addresses": "any",
                                            "applications": "junos-https", "action": "permit"}, {}),
    ("security-policy", POLICY_KEY, {"action": "reject"}, {"endpoint_impact": POLICY_KEY, "op": "update"}),
    ("nat-source-rule", "rs2@r1", {"from-zone": "DMZ", "to-zone": "untrust", "source-address": "198.51.100.32/27",
                                   "translation": "off"}, {}),
    ("nat-source-rule", "rs1@r1", {"translation": "off", "destination-address": "203.0.113.0/24"},
     {"endpoint_impact": "rs1@r1", "op": "update"}),
    ("nat-destination-pool", "pool-2", {"address": "198.51.100.35"}, {}),
    ("nat-destination-rule", "rs-dst@r2", {"from-zone": "untrust", "destination-address": "203.0.113.201",
                                           "pool": "dst-nat-pool-1"}, {}),
    ("nat-destination-rule", "rs-dst@r1", {}, {"endpoint_impact": "rs-dst@r1", "op": "delete"}),
    ("nat-source-rule", "rs1@r1", {}, {"endpoint_impact": "rs1@r1", "op": "delete"}),
])
def test_preview_apply_readback_and_undo(tmp_path, table, key, changes, extra):
    op = extra.pop("op", "create")
    record, target, changed = run(tmp_path, request(table, key, changes, op=op, **extra))
    if op == "delete" and table == "nat-source-rule":
        assert not any(line.startswith("set security nat source rule-set rs1") for line in changed.splitlines())
    assert any(line.startswith(("set security", "delete security")) for line in record["plan"]["commands"])


def test_deleting_a_policy_and_undo_restore_the_evaluation_order(tmp_path):
    req = request("security-policy", MAIL_KEY, {}, op="delete", endpoint_impact=MAIL_KEY)
    record, target, changed = run(tmp_path, req, undo=False)
    assert "policy permit-mail-trust-DMZ" not in changed
    runtime = make_runtime(tmp_path, target)
    back = execute.undo(runtime, record["change_id"], "restore the policy order")
    assert back["result"] == "confirmed"
    names = [line.split()[8] for line in target.snapshot().splitlines()
             if line.startswith("set security policies from-zone trust to-zone DMZ") and " match source-address" in line]
    assert names == ["permit-mail-trust-DMZ", "permit-http"]
    assert any(line.startswith("insert security policies from-zone trust to-zone DMZ policy permit-mail-trust-DMZ "
                               "before policy permit-http") for line in back["plan"]["commands"])


def test_apply_without_the_approved_hash_is_refused(tmp_path):
    target = SrxLab()
    runtime = make_runtime(tmp_path, target)
    req = request("address-book-address", "Web-2", {"prefix": "198.51.100.41"})
    before = target.snapshot()
    with pytest.raises(Rejected) as exc:
        execute.apply(runtime, NAME, req)
    assert exc.value.reason_codes == ["plan_changed"]
    assert target.snapshot() == before and not target.applied_blocks


def test_a_switch_without_the_security_hierarchy_is_refused_before_any_write(tmp_path):
    target = SrxLab(srx=False)
    runtime = make_runtime(tmp_path, target)
    before = target.snapshot()
    for table, key, changes in (("security-zone", "partner", {"interfaces": "ge-0/0/7.0"}),
                                ("address-book-address", "Web-2", {"prefix": "198.51.100.41"}),
                                ("nat-source-rule", "rs2@r1", {"from-zone": "trust", "to-zone": "untrust",
                                                               "source-address": "192.0.2.128/25", "translation": "off"})):
        result = execute.preview(runtime, NAME, request(table, key, changes))
        assert result["result"] == "rejected" and result["reason_codes"] == ["junos_srx_unsupported"], result
    assert target.snapshot() == before
    assert all(not any(line.startswith(("commit", "set security")) for line in block)
               for block in target.applied_blocks)


def test_zone_changes_that_cut_the_management_connection_are_refused(tmp_path):
    cases = [{"host-inbound-services": "ping"}, {"interfaces": None, "host-inbound-services": "ping ssh"}]
    target = SrxLab()
    runtime = make_runtime(tmp_path, target)
    for changes in cases:
        result = execute.preview(runtime, NAME, request("security-zone", "trust", changes, op="update",
                                                         endpoint_impact="trust"))
        assert result["reason_codes"] == ["junos_srx_management"], result
    gone = execute.preview(runtime, NAME, request("security-zone", "trust", {}, op="delete", endpoint_impact="trust"))
    assert gone["result"] == "rejected"
    # another zone is not the management zone
    ok = execute.preview(runtime, NAME, request("security-zone", "DMZ", {"host-inbound-services": "ping https"},
                                                 op="update", endpoint_impact="DMZ"))
    assert ok["result"] == "ready", ok


@pytest.mark.parametrize("reply", [
    "Security zone: partner\n   Interfaces bound: 1\n",                      # incomplete: no interface list
    fixture("show-security-zones-abc.txt")[:-12],                            # truncated
    "error: permission denied\n",
    fixture("show-security-zones-abc.txt"),                                  # another zone and interface
], ids=["no-list", "truncated", "denied", "other-zone"])
def test_zone_readback_that_is_incomplete_or_differs_never_commits_as_confirmed(tmp_path, reply):
    target = SrxLab()
    target.zone_override = reply
    runtime = make_runtime(tmp_path, target)
    req = request("security-zone", "partner", {"interfaces": "ge-0/0/7.0"})
    preview = execute.preview(runtime, NAME, req)
    if preview["result"] == "rejected":
        assert preview["reason_codes"] == ["junos_srx_readback_unreadable"]
        assert all(not any(line.startswith("commit") for line in block) for block in target.applied_blocks)
        return
    record = execute.apply(runtime, NAME, req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] != "confirmed"


def test_check_account_that_cannot_answer_is_unreadable_not_ok(tmp_path):
    target = SrxLab()
    target.check_unreadable = True
    runtime = make_runtime(tmp_path, target)
    req = request("security-zone", "partner", {"interfaces": "ge-0/0/7.0"})
    result = execute.preview(runtime, NAME, req)
    assert result["result"] == "rejected"
    assert all(not any(line.startswith("commit") for line in block) for block in target.applied_blocks)


def test_srx_tables_are_listed_by_the_doctor_and_reason_codes_are_declared():
    assert set(junos_srx.TABLES) == {"security-zone", "address-book-address", "address-book-set", "security-policy",
                                     "nat-source-rule", "nat-destination-pool", "nat-destination-rule"}
    assert exec_junos.exec_junos_srx.capability is not None


@pytest.mark.parametrize('table,ruleset,kind,match,action', [
    ('nat-source-rule', 'rs1', 'source', 'source-address 198.51.100.0/24', 'source-nat off'),
    ('nat-destination-rule', 'rs-dst', 'destination', 'destination-address 203.0.113.0/24',
     'destination-nat pool dst-nat-pool-1'),
])
@pytest.mark.parametrize('ignore_insert', [False, True])
def test_junos_srx_security_nat_undo_checks_the_original_rule_order(tmp_path, table, ruleset, kind, match, action, ignore_insert):
    path = f'security nat {kind} rule-set {ruleset}'
    target = SrxLab(BASE + f'set {path} rule broad match {match}\nset {path} rule broad then {action}\n')
    key = ruleset + '@r1'
    req = request(table, key, {}, op='delete', endpoint_impact=key)
    record, _, _ = run(tmp_path, req, lab=target, undo=False)
    runtime = make_runtime(tmp_path, target)
    target.ignore_nat_insert = ignore_insert
    back = execute.undo(runtime, record['change_id'], 'restore the NAT rule order')
    if ignore_insert:
        assert back['result'] != 'confirmed'
        assert list(junos.load(target.snapshot(), None).entries(table)) == [ruleset + '@broad']
    else:
        assert back['result'] == 'confirmed', back
        assert f'insert {path} rule r1 before rule broad' in back['plan']['commands']
        assert list(junos.load(target.snapshot(), None).entries(table)) == [key, ruleset + '@broad']


@pytest.mark.parametrize('table', ['security-zone', 'security-policy'])
def test_junos_srx_security_protects_the_ssh_ingress_zone_when_ssh_terminates_on_a_loopback(tmp_path, table):
    target = SrxLab(BASE + 'set interfaces lo0 unit 0 family inet address 192.0.2.60/32\n',
                    management=('192.0.2.60', '198.51.100.73'))
    runtime = make_runtime(tmp_path, target)
    if table == 'security-zone':
        req = request(table, 'trust', {'host-inbound-services': 'ping'}, op='update', endpoint_impact='trust')
    else:
        req = request(table, 'trust@junos-host@deny-ssh', {'source-addresses': 'any', 'destination-addresses': 'any',
                                                         'applications': 'junos-ssh', 'action': 'deny'})
    result = execute.preview(runtime, NAME, req)
    assert result.get('reason_codes') == ['junos_srx_management'], result
    assert not runtime.store.records()
