"""JUNOS-FIREWALL-FILTERS Junos firewall filters, terms, counters and interface bindings through Admin and the Junos transport."""

from __future__ import annotations

import itertools
import json
import re
from pathlib import Path

import pytest
from conftest import request_bytes
from fake_junos import BASELINE, FIRMWARE, FakeJunos
from test_junos import NAME, make_runtime, steps

from netops_admin import execute, junos
from netops_admin.engine import build_plan, verify
from netops_admin.errors import Rejected
from netops_admin.request import parse_request

FIXTURES = Path(__file__).parent / "fixtures" / "junos_junos_firewall_filters"
ROUTING = Path(__file__).parent / "fixtures" / "junos_26_2R1_7" / "junos-system-services"
INTERFACE = "irb.3921"
FILTER4, FILTER6, OUTPUT = "NETOPS-JUNOS-FIREWALL-FILTERS-IN", "NETOPS-JUNOS-FIREWALL-FILTERS-V6", "NETOPS-JUNOS-FIREWALL-FILTERS-OUT"
KEY4, KEY6, BIND4, BIND6 = FILTER4 + "@inet", FILTER6 + "@inet6", INTERFACE + "@inet", INTERFACE + "@inet6"
TERMS4 = "t-src,192.0.2.0/24,c-src,accept t-deny,198.51.100.0/24,-,discard t-rest,-,c-rest,accept"
TERMS4_REORDERED = "t-deny,198.51.100.0/24,-,discard t-src,192.0.2.0/24,c-src,accept t-rest,-,c-rest,accept"
TERMS6 = "t6-src,2001:db8:2::/48,c6-src,accept t6-deny,2001:db8:3::/48,-,reject t6-rest,-,c6-rest,accept"
TERMS_OUT = "t-out,192.0.2.0/24,c-out,accept t-out-rest,-,-,discard"
IDS = itertools.count(1)
VLAN_CONFIG = f"set vlans netops-junos-firewall-filters-test vlan-id 3921\nset vlans netops-junos-firewall-filters-test l3-interface {INTERFACE}\n"
COMPARE = "show | compare rollback 0 | no-more"


def fixture(name):
    return (FIXTURES / name).read_text()


def request(table, key, changes, op="create", **fields):
    return parse_request(request_bytes(table=table, key=key, changes=changes, op=op,
                                       request_id=f"junos-firewall-filters-unit-{next(IDS):04}", **fields))


def plan(req, snapshot=BASELINE, firmware=FIRMWARE, **kwargs):
    return build_plan("junos", snapshot.encode(), req, firmware=firmware, **kwargs)


def config(*names):
    return VLAN_CONFIG + fixture("cfg-irb.txt") + "".join(fixture(name) for name in names)


def reports(lines):
    """The binding report of the check account for the configured filters, from the measured shape."""
    document = json.loads(fixture("ro-filters-nofilter.json"))
    for item in document["interface-filter-information"][0]["logical-interface"][0]["filter-information"]:
        if "filter-family" not in item:
            continue
        family = item["filter-family"][0]["data"]
        for direction in ("input", "output"):
            prefix = f"set interfaces irb unit 3921 family {family} filter {direction} "
            names = [row[len(prefix):] for row in lines if row.startswith(prefix)]
            if names:
                item["filter-" + direction] = [{"data": names[0]}]
    return json.dumps(document, indent=4) + "\n"


class FilterLab(FakeJunos):
    """Apply firewall and filter-binding edits to the candidate and answer the reads of the measured shapes."""

    def __init__(self, text=""):
        super().__init__()
        self.lines.extend(text.splitlines())
        self.ssh_paths = [("192.0.2.56", "192.0.2.40")]
        self.management_hop = "fxp0.0"

    def _line(self, line, session):
        if line == COMPARE:
            return self._compare(self._candidate(session))
        if line in ("show | compare", "show | compare | no-more") and session["mode"] != "oper" and len(
                self._candidate(session)) - len(self.lines) > 8:
            raise AssertionError("a filter diff longer than one screen must use the unpaged compare")
        verb, _, path = line.partition(" ")
        if verb in ("set", "delete") and (path.startswith("firewall ") or re.match(
                r"interfaces irb unit [0-9]+ family inet6? filter ", path)):
            candidate = self._candidate(session)
            statement = "set " + path
            if verb == "delete":
                candidate[:] = [item for item in candidate if item != statement and not item.startswith(statement + " ")]
            else:
                match = re.match(r"(set interfaces irb unit [0-9]+ family inet6? filter (?:input|output)) ", statement)
                if match:
                    candidate[:] = [item for item in candidate if not item.startswith(match[1] + " ")]
                if statement not in candidate:
                    candidate.append(statement)
            return ""
        if verb == "insert":
            moving, _, anchor = path.partition(" before term ")
            root = moving.rsplit(" term ", 1)[0]
            moving, anchor = "set " + moving + " ", "set " + root + " term " + anchor + " "
            candidate = self._candidate(session)
            block = [item for item in candidate if item.startswith(moving)]
            candidate[:] = [item for item in candidate if not item.startswith(moving)]
            at = next(index for index, item in enumerate(candidate) if item.startswith(anchor))
            candidate[at:at] = block
            return ""
        return super()._line(line, session)

    def query(self, command):
        if command == "show interfaces terse | no-more":
            return ("Interface               Admin Link Proto    Local                 Remote\n"
                    "fxp0.0                  up    up   inet     192.0.2.56/24\n")
        if command == "show route 192.0.2.40 active-path | display json | no-more":
            text = (ROUTING / "management-route.json").read_text()
            return text.replace('"Direct"', '"Direct"') if self.management_hop == "fxp0.0" else text.replace(
                "fxp0.0", self.management_hop)
        if command.startswith("show configuration ") and command.endswith(" | display set | no-more"):
            path = command[len("show configuration "):-len(" | display set | no-more")]
            return "".join(item + "\n" for item in self.lines
                           if item == "set " + path or item.startswith("set " + path + " "))
        return super().query(command)

    def check_query(self, command):
        if self.check_override is not None and command in self.check_override:
            return super().check_query(command)
        if command == f"show interfaces filters {INTERFACE} | display json | no-more":
            self.check_queries.append(command)
            return reports(self.lines)
        return super().check_query(command)


def run_and_undo(runtime, target, req):
    baseline = target.snapshot()
    preview = execute.preview(runtime, NAME, req)
    assert preview["result"] == "ready", preview
    assert target.snapshot() == baseline
    assert all(not any(line.startswith("commit") for line in block) for block in target.applied_blocks)
    record = execute.apply(runtime, NAME, req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", (record.get("reason"), record.get("steps"))
    assert "check_identity_passed" in steps(record)
    undo = execute.undo(runtime, record["change_id"], "restore the approved test object")
    assert undo["result"] == "confirmed", (undo.get("reason"), undo.get("steps"))
    assert target.snapshot() == baseline and not target.pending()
    return record, preview


def test_measured_reports_match_the_simulated_binding_report():
    def same(lines, name):
        assert json.loads(reports(lines)) == json.loads(fixture(name))

    same(fixture("cfg-irb.txt").splitlines(), "ro-filters-nofilter.json")
    inet = fixture("cfg-binding-inet.txt").splitlines()
    same(inet, "ro-filters-inet.json")
    same(inet + ["set interfaces irb unit 3921 family inet filter output " + OUTPUT], "ro-filters-inet-in-out.json")
    same(inet + fixture("cfg-binding-inet6.txt").splitlines(), "ro-filters-inet-inet6.json")


def test_inet_filter_is_previewed_applied_read_back_and_returned(tmp_path):
    target = FilterLab(config())
    runtime = make_runtime(tmp_path, target)
    record, preview = run_and_undo(runtime, target, request("firewall-filter", KEY4, {"terms": TERMS4}))
    assert record["plan"]["predicted"] == {"before": None, "after": {"terms": TERMS4}}
    commands = [line for line in preview["commands"] if line.startswith("set firewall")]
    assert commands[0] == f"set firewall family inet filter {FILTER4} term t-src from source-address 192.0.2.0/24"
    assert f"set firewall family inet filter {FILTER4} term t-rest then count c-rest" in commands
    assert COMPARE in preview["commands"] and "show | compare" not in preview["commands"]
    assert record["plan"]["inverse"] == [f"delete firewall family inet filter {FILTER4}"] or (
        f"delete firewall family inet filter {FILTER4}" in record["plan"]["inverse"])


def test_last_source_only_term_is_announced_as_implicit_discard():
    change = plan(request("firewall-filter", KEY4, {"terms": "t-src,192.0.2.0/24,c-src,accept"}), BASELINE + config())
    assert any("implicit" in text for text in change["prechecks"])
    assert not any("implicit" in text for text in plan(request("firewall-filter", KEY4, {"terms": TERMS4}),
                                                       BASELINE + config())["prechecks"])


def test_ipv6_filter_and_binding_use_operational_binding_readback(tmp_path):
    target = FilterLab(config("cfg-filter-inet6.txt"))
    runtime = make_runtime(tmp_path, target)
    req = request("filter-binding", BIND6, {"input": FILTER6}, endpoint_impact=BIND6)
    record, _preview = run_and_undo(runtime, target, req)
    assert record["plan"]["predicted"]["after"] == {"input": FILTER6}
    assert f"set interfaces irb unit 3921 family inet6 filter input {FILTER6}" in record["plan"]["commands"]
    assert f"delete interfaces irb unit 3921 family inet6 filter input" in " ".join(record["plan"]["inverse"])
    assert f"show interfaces filters {INTERFACE} | display json | no-more" in target.check_queries
    target = FilterLab(config())
    run_and_undo(make_runtime(tmp_path / "second", target), target, request("firewall-filter", KEY6, {"terms": TERMS6}))


def test_binding_update_changes_one_direction_and_keeps_the_other(tmp_path):
    target = FilterLab(config("cfg-filter-inet.txt", "cfg-binding-inet.txt") + "".join(
        f"set firewall family inet filter {OUTPUT} term {name}\n" for name in ("t-out then accept",)))
    runtime = make_runtime(tmp_path, target)
    req = request("filter-binding", BIND4, {"output": OUTPUT}, op="update", endpoint_impact=BIND4)
    record, _preview = run_and_undo(runtime, target, req)
    assert record["plan"]["predicted"]["before"] == {"input": FILTER4}
    assert record["plan"]["predicted"]["after"] == {"input": FILTER4, "output": OUTPUT}
    assert record["plan"]["commands"][3:4] == [f"set interfaces irb unit 3921 family inet filter output {OUTPUT}"]


def test_term_order_change_uses_insert_and_the_inverse_restores_the_order(tmp_path):
    target = FilterLab(config("cfg-filter-inet.txt", "cfg-binding-inet.txt"))
    runtime = make_runtime(tmp_path, target)
    req = request("firewall-filter", KEY4, {"terms": TERMS4_REORDERED}, op="update", endpoint_impact=KEY4)
    record, _preview = run_and_undo(runtime, target, req)
    path = f"firewall family inet filter {FILTER4}"
    assert f"insert {path} term t-deny before term t-src" in record["plan"]["commands"]
    assert not any(line.startswith("delete") for line in record["plan"]["commands"])
    assert f"insert {path} term t-src before term t-deny" in record["plan"]["inverse"]
    changed = plan(req, BASELINE + config("cfg-filter-inet.txt", "cfg-binding-inet.txt"))
    after = junos.snapshot_after(BASELINE + config("cfg-filter-inet.txt", "cfg-binding-inet.txt"), changed)
    assert verify(changed, after.encode())["result"] == "match"
    measured = fixture("cfg-filter-inet-reordered.txt").splitlines()
    assert [row.split()[7] for row in measured if " from " in row or " then count" in row][:2] == ["t-deny", "t-src"]


def test_changing_a_term_rewrites_that_term_in_its_place():
    text = BASELINE + config("cfg-filter-inet.txt", "cfg-binding-inet.txt")
    changed = plan(request("firewall-filter", KEY4, {"terms": TERMS4.replace("c-src,accept", "c-src,discard")}, op="update",
                           endpoint_impact=KEY4), text)
    path = f"firewall family inet filter {FILTER4}"
    assert changed["commands"][3:] and f"delete {path} term t-src" in changed["commands"]
    assert f"insert {path} term t-src before term t-deny" in changed["commands"]
    assert verify(changed, junos.snapshot_after(text, changed).encode())["result"] == "match"


@pytest.mark.parametrize("table,key,changes,op,extra,fields,code", [
    ("filter-binding", "fxp0.0@inet", {"input": FILTER4}, "create", ["cfg-filter-inet.txt"], {"endpoint_impact": "fxp0.0@inet"},
     "port_protected"),
    ("filter-binding", "lo0.0@inet", {"input": FILTER4}, "create", ["cfg-filter-inet.txt"], {"endpoint_impact": "lo0.0@inet"},
     "port_protected"),
    ("firewall-filter", KEY4, {}, "delete", ["cfg-filter-inet.txt", "cfg-binding-inet.txt"], {},
     "junos_filter_dependency"),
    ("firewall-filter", KEY4, {"terms": TERMS4_REORDERED}, "update", ["cfg-filter-inet.txt", "cfg-binding-inet.txt"], {},
     "endpoint_impact_required"),
    ("filter-binding", BIND4, {"input": FILTER4}, "create", ["cfg-filter-inet.txt"], {}, "endpoint_impact_required"),
    ("filter-binding", BIND4, {"input": "NETOPS-JUNOS-FIREWALL-FILTERS-NONE"}, "create", ["cfg-filter-inet.txt"],
     {"endpoint_impact": BIND4}, "junos_filter_dependency"),
    ("filter-binding", "irb.3922@inet", {"input": FILTER4}, "create", ["cfg-filter-inet.txt"],
     {"endpoint_impact": "irb.3922@inet"}, "junos_filter_dependency"),
    ("filter-binding", INTERFACE + "@inet6", {"input": FILTER4}, "create", ["cfg-filter-inet.txt"],
     {"endpoint_impact": INTERFACE + "@inet6"}, "junos_filter_dependency"),
], ids=["management-interface", "re-protection-lo0", "delete-bound-filter", "update-bound-filter-needs-impact",
        "bind-needs-impact", "missing-filter", "unit-without-family", "filter-of-another-family"])
def test_refusals_are_static_and_name_a_reason(table, key, changes, op, extra, fields, code):
    with pytest.raises(Rejected) as exc:
        plan(request(table, key, changes, op=op, **fields), BASELINE + config(*extra))
    assert exc.value.reason_codes == [code]


def test_protected_interface_and_filter_from_the_inventory():
    text = BASELINE + config("cfg-filter-inet.txt")
    bind = request("filter-binding", BIND4, {"input": FILTER4}, endpoint_impact=BIND4)
    with pytest.raises(Rejected) as exc:
        plan(bind, text, protected={"interface": [INTERFACE]})
    assert exc.value.reason_codes == ["port_protected"]
    with pytest.raises(Rejected) as exc:
        plan(bind, text, protected={"interface": ["irb"]})
    assert exc.value.reason_codes == ["port_protected"]
    with pytest.raises(Rejected, match="protected"):
        plan(request("firewall-filter", KEY4, {"terms": TERMS4}), text, protected={"firewall-filter": [KEY4]})


@pytest.mark.parametrize("terms", [
    "t-src,2001:db8:2::/48,c,accept", "t-src,192.0.2.0/24,c,accept t-src,-,-,discard", "t-src,192.0.2.1/24,c,accept",
    "t-src,192.0.2.0/24,c,permit", "t-src,-,-", "", "t-src,192.0.2.0/24,a-counter-name-longer-than-24,accept"],
    ids=["v6-in-inet", "duplicate-term", "host-bits", "unknown-action", "short-term", "empty", "long-counter"])
def test_invalid_terms_are_refused(terms):
    with pytest.raises(Rejected):
        plan(request("firewall-filter", KEY4, {"terms": terms}), BASELINE + config())


def test_filters_outside_the_profile_and_inherited_configuration_are_not_edited():
    existing = BASELINE + config() + fixture("cfg-firewall-existing.txt")
    with pytest.raises(Rejected, match="outside the profile"):
        plan(request("firewall-filter", "junos-security-test@inet", {"terms": "t-all,-,-,accept"}, op="update"), existing)
    inherited = BASELINE + config() + "set groups G firewall family inet filter X term t then accept\n"
    with pytest.raises(Rejected) as exc:
        plan(request("firewall-filter", KEY4, {"terms": TERMS4}), inherited)
    assert exc.value.reason_codes == ["junos_filter_scope"]


BINDING_QUERY = f"show interfaces filters {INTERFACE} | display json | no-more"


@pytest.mark.parametrize("answer", ["truncated", "denied", "other-interface"])
def test_incomplete_binding_readback_refuses_the_preview_without_commit(tmp_path, answer):
    target = FilterLab(config("cfg-filter-inet.txt"))
    text = fixture("ro-filters-nofilter.json")
    replies = {"truncated": text[:-30], "denied": "error: permission denied\n",
               "other-interface": text.replace(INTERFACE, "irb.3922")}
    target.check_override = {BINDING_QUERY: replies[answer]}
    runtime = make_runtime(tmp_path, target)
    req = request("filter-binding", BIND4, {"input": FILTER4}, endpoint_impact=BIND4)
    preview = execute.preview(runtime, NAME, req)
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["junos_filter_readback_unreadable"]
    assert all(not any(line.startswith("commit") for line in block) for block in target.applied_blocks)


def test_binding_that_the_device_does_not_report_after_commit_is_reverted(tmp_path):
    class Stale(FilterLab):
        def check_query(self, command):
            if command == BINDING_QUERY and any("filter input" in line for line in self.lines):
                self.check_queries.append(command)
                return fixture("ro-filters-nofilter.json")
            return super().check_query(command)

    target = Stale(config("cfg-filter-inet.txt"))
    runtime = make_runtime(tmp_path, target)
    req = request("filter-binding", BIND4, {"input": FILTER4}, endpoint_impact=BIND4)
    preview = execute.preview(runtime, NAME, req)
    assert preview["result"] == "ready", preview
    record = execute.apply(runtime, NAME, req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "reverted", (record["result"], record.get("reason"), steps(record))
    assert "confirm_start" not in steps(record) and not target.pending()
    assert target.snapshot() == FilterLab(config("cfg-filter-inet.txt")).snapshot()


def test_unreadable_configuration_after_commit_is_not_a_success(tmp_path):
    class Truncated(FilterLab):
        def query(self, command):
            answer = super().query(command)
            if command.startswith("show configuration firewall family inet filter"):
                return answer.rstrip("\n")
            return answer

    target = Truncated(config())
    runtime = make_runtime(tmp_path, target)
    req = request("firewall-filter", KEY4, {"terms": TERMS4})
    preview = execute.preview(runtime, NAME, req)
    assert preview["result"] == "ready"
    record = execute.apply(runtime, NAME, req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "reverted", (record["result"], record.get("reason"), steps(record))
    assert "confirm_start" not in steps(record) and not target.pending()
    assert target.snapshot() == FilterLab(config()).snapshot()


@pytest.mark.parametrize("hop", [INTERFACE])
def test_management_return_path_through_the_filtered_interface_is_refused(tmp_path, hop):
    target = FilterLab(config("cfg-filter-inet.txt"))
    target.management_hop = hop
    runtime = make_runtime(tmp_path, target)
    req = request("filter-binding", BIND4, {"input": FILTER4}, endpoint_impact=BIND4)
    preview = execute.preview(runtime, NAME, req)
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["junos_filter_management"]
    assert all(not any(line.startswith("commit") for line in block) for block in target.applied_blocks)


def test_management_session_on_the_filtered_interface_is_refused(tmp_path):
    class LocalOnIrb(FilterLab):
        def query(self, command):
            answer = super().query(command)
            if command == "show interfaces terse | no-more":
                return answer + "irb.3921                up    up   inet     192.0.2.56/24\n"
            return answer

    target = LocalOnIrb(config("cfg-filter-inet.txt"))
    runtime = make_runtime(tmp_path, target)
    req = request("filter-binding", BIND4, {"input": FILTER4}, endpoint_impact=BIND4)
    assert execute.preview(runtime, NAME, req)["reason_codes"] == ["junos_filter_management"]


def test_unreadable_management_evidence_refuses_with_a_filter_reason(tmp_path):
    class Refusing(FilterLab):
        def query(self, command):
            if command.startswith("show route 192.0.2.40 "):
                return "error: permission denied\n"
            return super().query(command)

    target = Refusing(config("cfg-filter-inet.txt"))
    runtime = make_runtime(tmp_path, target)
    req = request("filter-binding", BIND4, {"input": FILTER4}, endpoint_impact=BIND4)
    assert execute.preview(runtime, NAME, req)["reason_codes"] == ["junos_filter_readback_unreadable"]


def test_untested_firmware_is_a_warning_not_a_block():
    text = (BASELINE + config()).replace(FIRMWARE, "27.1R1.2")
    change = plan(request("firewall-filter", KEY4, {"terms": TERMS4}), text, "27.1R1.2")
    assert change["firmware_support"]["status"] == "untested"
    assert verify(change, junos.snapshot_after(text, change).encode())["result"] == "match"


def test_unbound_filter_without_interfaces_needs_no_management_preflight(tmp_path):
    target = FilterLab(config("cfg-filter-inet.txt"))
    runtime = make_runtime(tmp_path, target)
    req = request("firewall-filter", KEY4, {"terms": TERMS4_REORDERED}, op="update")
    record, _preview = run_and_undo(runtime, target, req)
    assert "endpoint_impact" not in record["plan"]


@pytest.mark.parametrize('table,key,changes,impact', [
    ('firewall-filter', KEY4, {'terms': TERMS4}, None),
    ('filter-binding', BIND4, {'input': FILTER4}, BIND4),
])
def test_junos_firewall_filters_apply_requires_the_preview_hash(tmp_path, table, key, changes, impact):
    target = FilterLab(config('cfg-filter-inet.txt') if impact else config())
    runtime = make_runtime(tmp_path, target)
    req = request(table, key, changes, **({'endpoint_impact': impact} if impact else {}))
    baseline = target.snapshot()
    assert execute.preview(runtime, NAME, req)['result'] == 'ready'
    with pytest.raises(Rejected) as exc:
        execute.apply(runtime, NAME, req)
    assert exc.value.reason_codes == ['plan_changed']
    assert target.snapshot() == baseline and not runtime.store.records()


@pytest.mark.parametrize('op,changes', [('update', {'output': None}), ('delete', {})])
def test_junos_firewall_filters_removing_an_applied_filter_requires_impact(tmp_path, op, changes):
    target = FilterLab(config('cfg-filter-inet.txt')
                       + 'set firewall family inet filter ACCESS-OUT term allow then accept\n'
                       + fixture('cfg-binding-inet.txt')
                       + 'set interfaces irb unit 3921 family inet filter output ACCESS-OUT\n')
    runtime = make_runtime(tmp_path, target)
    denied = execute.preview(runtime, NAME, request('filter-binding', BIND4, changes, op=op))
    assert denied['reason_codes'] == ['endpoint_impact_required'], denied
    record, _ = run_and_undo(runtime, target, request('filter-binding', BIND4, changes, op=op, endpoint_impact=BIND4))
    assert any(command.endswith('filter output') for command in record['plan']['commands'])


@pytest.mark.parametrize('interface,guarded', [(INTERFACE, [INTERFACE]), ('lo0.0', []), ('fxp0.0', [])])
def test_junos_firewall_filters_cannot_edit_a_filter_on_a_protected_interface(tmp_path, interface, guarded):
    port, unit = interface.split('.')
    target = FilterLab(config('cfg-filter-inet.txt', 'cfg-binding-inet.txt').replace(
        'interfaces irb unit 3921 family inet filter', f'interfaces {port} unit {unit} family inet filter'))
    runtime = make_runtime(tmp_path, target, protected={'interface': guarded})
    for table, key, changes in (
        ('firewall-filter', KEY4, {'terms': TERMS4_REORDERED}),
        ('filter-binding', interface + '@inet', {}),
    ):
        op = 'update' if table == 'firewall-filter' else 'delete'
        result = execute.preview(runtime, NAME, request(table, key, changes, op=op, endpoint_impact=key))
        assert result.get('reason_codes') == ['port_protected'], result
    assert not runtime.store.records()
