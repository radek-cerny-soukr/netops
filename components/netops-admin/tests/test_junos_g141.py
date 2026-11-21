"""G141 routing profiles through Admin and the Junos transport boundary."""

from __future__ import annotations

import itertools
import json
import re
from pathlib import Path

import pytest
from conftest import request_bytes
from fake_junos import BASELINE, FIRMWARE, FakeJunos
from test_junos import NAME, make_runtime, steps

from netops_admin import exec_junos, execute, junos
from netops_admin.engine import build_plan, verify
from netops_admin.errors import Rejected
from netops_admin.request import parse_request

FIXTURES = Path(__file__).parent / "fixtures" / "junos_26_2R1_7" / "g141"
INTERFACE = "irb.3920"
PREFIX_LIST = "NETOPS-G141-PREFIXES"
POLICY = "NETOPS-G141-POLICY"
AREA = "0.0.0.7"
PREFIXES = "203.0.113.1/32 203.0.113.2/32"
TERMS = f"match:{PREFIX_LIST}:accept default:-:reject"
IDS = itertools.count(1)


def fixture(name):
    return (FIXTURES / name).read_text()


def request(table, key, changes, op="create", **fields):
    return parse_request(request_bytes(table=table, key=key, changes=changes, op=op,
                                       request_id=f"g141-unit-{next(IDS):04}", **fields))


def plan(req, snapshot=BASELINE, firmware=FIRMWARE, **kwargs):
    return build_plan("junos", snapshot.encode(), req, firmware=firmware, **kwargs)


class RoutingLab(FakeJunos):
    """Apply CLI edits to a candidate and replay measured answers over the simulated transport."""

    def __init__(self, config=""):
        super().__init__()
        self.lines.extend(config.splitlines())
        self.ssh_paths = [("192.0.2.56", "192.0.2.40")]
        self.management_protocol = "Direct"

    def _line(self, line, session):
        if line.split()[:2] in (["set", "policy-options"], ["delete", "policy-options"]) or re.match(
                r"^(?:set|delete) protocols (?:ospf3?|bgp) ", line):
            candidate = self._candidate(session)
            verb, path = line.split(" ", 1)
            statement = "set " + path
            if verb == "delete":
                candidate[:] = [item for item in candidate if item != statement and not item.startswith(statement + " ")]
            elif statement not in candidate:
                candidate.append(statement)
            return ""
        if line.startswith("insert policy-options "):
            old, new = line.removeprefix("insert ").split(" before term ")
            root = old.rsplit(" term ", 1)[0]
            new = "set " + root + " term " + new + " "
            old = "set " + old + " "
            candidate = self._candidate(session)
            moving = [item for item in candidate if item.startswith(old)]
            candidate[:] = [item for item in candidate if not item.startswith(old)]
            at = next(i for i, item in enumerate(candidate) if item.startswith(new))
            candidate[at:at] = moving
            return ""
        return super()._line(line, session)

    def query(self, command):
        if command == "show interfaces terse | no-more":
            return ("Interface               Admin Link Proto    Local                 Remote\n"
                    "fxp0.0                  up    up   inet     192.0.2.56/24\n")
        if command == f"show interfaces {INTERFACE} terse | no-more":
            return ("Interface               Admin Link Proto    Local                 Remote\n"
                    "irb.3920                up    down inet     203.0.113.1/32\n"
                    "                                   inet6    2001:db8:141::1/128\n")
        if command == "show route 192.0.2.40 active-path | display json | no-more":
            return fixture("management-route.json").replace('"Direct"', f'"{self.management_protocol}"')
        if command.startswith("show configuration ") and command.endswith(" | no-more"):
            _, path = command.split("show configuration ", 1)
            path, *pipes = path.split(" | ")
            answers = [item for item in self.lines if item == "set " + path or item.startswith("set " + path + " ")]
            if pipes[1].startswith("match "):
                pattern = pipes[1].removeprefix('match "').removesuffix('"')
                answers = [item for item in answers if re.search(pattern, item)]
            return "".join(row + "\n" for row in answers)
        return super().query(command)

    def check_query(self, command):
        if self.check_override is not None and command in self.check_override:
            return super().check_query(command)
        if command == f"show ospf3 interface {INTERFACE} detail | display json | no-more":
            self.check_queries.append(command)
            configured = any(row.startswith(f"set protocols ospf3 area {AREA} interface {INTERFACE}") for row in self.lines)
            return fixture("ospf3-after.json" if configured else "ospf3-before.json")
        if command == "show ospf3 neighbor | display json | no-more":
            self.check_queries.append(command)
            return fixture("ospf3-neighbors-after.json")
        policy_rows = [row for row in self.lines if row.startswith(f"set policy-options policy-statement {POLICY} ")]
        if command == "show policy | display json | no-more":
            self.check_queries.append(command)
            return fixture("policies-after.json" if policy_rows else "policies-before.json")
        if command == f"show policy {POLICY} | display json | no-more":
            self.check_queries.append(command)
            data = json.loads(fixture("policy-after.json"))
            policy = data["policy-information"][0]["policy"][0]
            order = list(dict.fromkeys(row.split()[5] for row in policy_rows))
            known = {row["name"][0]["data"]: row for row in policy["term"]}
            policy["term"] = [known[name] for name in order]
            return json.dumps(data)
        if command == "show bgp group transit | no-more":
            self.check_queries.append(command)
            return fixture("bgp-group-vendor.txt")
        if command == "show bgp neighbor 192.0.2.141 | no-more":
            self.check_queries.append(command)
            base = fixture("bgp-neighbor-vendor.txt")
            result = [row for row in base.splitlines() if "Import:" not in row]
            result = [row.replace("Established", "Active") for row in result]
            for direction in ("import", "export"):
                for parent in ("set protocols bgp group transit neighbor 192.0.2.141",
                               "set protocols bgp group transit"):
                    prefix = f"{parent} {direction} "
                    policies = [row[len(prefix):] for row in self.lines if row.startswith(prefix)]
                    if policies:
                        result.append(f"  {direction.title()}: [ {policies[0]} ]")
                        break
            return "\n".join(result) + "\n"
        return super().check_query(command)


def _run_and_undo(runtime, target, req):
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
    assert target.snapshot() == baseline
    return record


def test_ospf3_preview_confirm_operational_readback_and_undo(tmp_path):
    target = RoutingLab(fixture("set-interface-after.txt"))
    runtime = make_runtime(tmp_path, target)
    req = request("ospf3-interface", INTERFACE, {"area": AREA, "metric": 18, "passive": "yes"})
    record = _run_and_undo(runtime, target, req)
    assert record["plan"]["predicted"]["after"] == {"area": AREA, "metric": "18", "passive": "yes"}
    assert "show ospf3 neighbor | display json | no-more" in target.check_queries


def test_policy_order_only_edit_uses_insert_and_restores_the_exact_order(tmp_path):
    target = RoutingLab(fixture("set-policy-after.txt"))
    runtime = make_runtime(tmp_path, target)
    req = request("route-policy", POLICY, {"terms": " ".join(reversed(TERMS.split()))}, op="update")
    record = _run_and_undo(runtime, target, req)
    assert record["plan"]["predicted"]["before"] == {"terms": TERMS}
    assert f"insert policy-options policy-statement {POLICY} term default before term match" in record["plan"]["commands"]
    assert f"insert policy-options policy-statement {POLICY} term match before term default" in record["plan"]["inverse"]


@pytest.mark.parametrize("reply", [fixture("ospf3-after.json")[:-20], "error: permission denied\n"],
                         ids=["truncated", "denied"])
def test_ospf_incomplete_or_denied_readback_refuses_without_commit(tmp_path, reply):
    target = RoutingLab(fixture("set-interface-after.txt"))
    target.check_override = {f"show ospf3 interface {INTERFACE} detail | display json | no-more": reply}
    runtime = make_runtime(tmp_path, target)
    req = request("ospf3-interface", INTERFACE, {"area": AREA, "metric": 18, "passive": "yes"})
    preview = execute.preview(runtime, NAME, req)
    assert preview["result"] == "rejected"
    assert preview["reason_codes"] == ["junos_routing_readback_unreadable"]
    assert all(not any(line.startswith("commit") for line in block) for block in target.applied_blocks)


def test_routing_management_route_blocks_preview(tmp_path):
    target = RoutingLab(fixture("set-interface-after.txt"))
    target.management_protocol = "OSPF3"
    runtime = make_runtime(tmp_path, target)
    req = request("ospf3-interface", INTERFACE, {"area": AREA, "metric": 18, "passive": "yes"})
    assert execute.preview(runtime, NAME, req)["reason_codes"] == ["junos_routing_management"]


def test_passive_ospfv2_empty_operational_output_is_not_a_success():
    target = RoutingLab(fixture("set-ospf-after.txt"))
    target.check_override = {f"show ospf interface {INTERFACE} detail | display json | no-more": fixture("ospf-after.json")}
    with pytest.raises(Rejected) as exc:
        exec_junos.observe(target, {"table": "ospf-interface", "key": INTERFACE, "firmware": FIRMWARE}, operational=True)
    assert exc.value.reason_codes == ["junos_routing_readback_unreadable"]


def test_profile_firmware_warning_and_metric_only_edit():
    text = BASELINE.replace(FIRMWARE, "27.1R1.2") + fixture("set-ospf-after.txt")
    req = request("ospf3-interface", INTERFACE, {"metric": 19}, op="update")
    change = plan(req, text, "27.1R1.2")
    assert change["firmware_support"]["status"] == "untested"
    prefix = f"set protocols ospf3 area {AREA} interface {INTERFACE}"
    assert [line for line in change["commands"] if line.startswith(prefix)] == [prefix + " metric 19"]
    predicted = junos.snapshot_after(text, change)
    assert verify(change, predicted.encode())["result"] == "match"


def test_prefix_list_replacement_keeps_other_objects_and_rejects_mixed_families():
    prefix_config = "".join(row for row in fixture("set-policy-after.txt").splitlines(keepends=True)
                            if row.startswith("set policy-options prefix-list "))
    text = BASELINE + prefix_config
    req = request("prefix-list", PREFIX_LIST, {"prefixes": "203.0.113.2/32 203.0.113.3/32"}, op="update")
    change = plan(req, text)
    assert f"delete policy-options prefix-list {PREFIX_LIST} 203.0.113.1/32" in change["commands"]
    assert f"set policy-options prefix-list {PREFIX_LIST} 203.0.113.1/32" in change["inverse"]
    with pytest.raises(Rejected, match="one address family"):
        plan(request("prefix-list", PREFIX_LIST, {"prefixes": "203.0.113.1/32 2001:db8::1/128"}))
    with pytest.raises(Rejected) as exc:
        plan(req, BASELINE + fixture("set-policy-after.txt"))
    assert exc.value.reason_codes == ["junos_routing_dependency"]


def test_policy_readback_checks_expanded_prefixes_and_requires_a_source_list(tmp_path):
    text = BASELINE + fixture("set-policy-after.txt")
    missing = request("route-policy", "NETOPS-G141-MISSING", {"terms": "match:missing:accept"})
    with pytest.raises(Rejected) as exc:
        plan(missing, text)
    assert exc.value.reason_codes == ["junos_routing_dependency"]
    target = RoutingLab(fixture("set-policy-after.txt"))
    target.check_override = {
        f"show policy {POLICY} | display json | no-more": fixture("policy-after.json").replace(
            "203.0.113.2/32", "203.0.113.9/32")
    }
    runtime = make_runtime(tmp_path, target)
    req = request("route-policy", POLICY, {"terms": " ".join(reversed(TERMS.split()))}, op="update")
    assert execute.preview(runtime, NAME, req)["reason_codes"] == ["junos_routing_readback_unreadable"]


def test_bgp_existing_policy_needs_explicit_impact_and_preserves_other_statements():
    group = "transit"
    address = "192.0.2.141"
    key = f"{group}@{address}"
    family = f"set protocols bgp group {group} family inet unicast\n"
    text = (BASELINE + fixture("set-policy-after.txt") + f"set protocols bgp group {group} type external\n"
            + f"set protocols bgp group {group} peer-as 64512\n" + family
            + f"set protocols bgp group {group} neighbor {address}\n")
    settings = {"import": POLICY, "export": POLICY}
    with pytest.raises(Rejected) as exc:
        plan(request("bgp-neighbor", key, settings, op="update"), text)
    assert exc.value.reason_codes == ["endpoint_impact_required"]
    approved = plan(request("bgp-neighbor", key, settings, op="update", endpoint_impact=key), text)
    assert approved["endpoint_impact"] == key
    predicted = junos.snapshot_after(text, approved)
    assert family in predicted
    assert verify(approved, predicted.encode())["result"] == "match"
    assert f"set protocols bgp group {group} neighbor {address}" in approved["inverse"]
    with pytest.raises(Rejected) as exc:
        plan(request("bgp-group", group, {}, op="delete"), text)
    assert exc.value.reason_codes == ["junos_routing_scope"]


def test_bgp_operational_neighbor_from_vendor_example_and_truncated_output():
    class Transport:
        def check_query(self, command):
            assert command == "show bgp neighbor 192.0.2.141 | no-more"
            return self.answer

    from netops_admin.exec_junos_routing import _bgp_neighbor

    access = Transport()
    access.answer = fixture("bgp-neighbor-vendor.txt")
    assert _bgp_neighbor(access, "192.0.2.141", "transit") == (
        {"peer-as": "64512", "import": POLICY}, "Established")
    access.answer = access.answer.rsplit("]", 1)[0]
    with pytest.raises(ValueError, match="invalid BGP policy list"):
        _bgp_neighbor(access, "192.0.2.141", "transit")



def test_bgp_group_import_verified_by_inheriting_peer_and_restored(tmp_path):
    target = RoutingLab(fixture("set-policy-after.txt") +
                        "set protocols bgp group transit type external\n"
                        "set protocols bgp group transit peer-as 64512\n"
                        "set protocols bgp group transit neighbor 192.0.2.141\n")
    runtime = make_runtime(tmp_path, target)
    req = request("bgp-group", "transit", {"import": POLICY}, op="update", endpoint_impact="transit")
    _run_and_undo(runtime, target, req)
    assert "show bgp group transit | no-more" in target.check_queries
    assert "show bgp neighbor 192.0.2.141 | no-more" in target.check_queries


@pytest.mark.parametrize("direction", ["import", "export"])
@pytest.mark.parametrize("stale", [False, True], ids=["current", "stale"])
def test_bgp_group_policy_removal_checks_every_inheriting_peer(tmp_path, direction, stale):
    policy_row = f"set protocols bgp group transit {direction} {POLICY}"
    second_peer = "show bgp neighbor 192.0.2.142 | no-more"

    class TwoPeerLab(RoutingLab):
        def check_query(self, command):
            if command == second_peer:
                self.check_queries.append(command)
                output = super().check_query("show bgp neighbor 192.0.2.141 | no-more")
                output = output.replace("192.0.2.141", "192.0.2.142")
                if stale and policy_row not in self.lines:
                    output += f"  {direction.title()}: [ {POLICY} ]\n"
                return output
            return super().check_query(command)

    target = TwoPeerLab(fixture("set-policy-after.txt") +
                        "set protocols bgp group transit type external\n"
                        "set protocols bgp group transit peer-as 64512\n"
                        "set protocols bgp group transit neighbor 192.0.2.141\n"
                        "set protocols bgp group transit neighbor 192.0.2.142\n" + policy_row + "\n")
    runtime = make_runtime(tmp_path, target)
    baseline = target.snapshot()
    req = request("bgp-group", "transit", {direction: None}, op="update", endpoint_impact="transit")
    preview = execute.preview(runtime, NAME, req)
    assert preview["result"] == "ready", preview
    target.check_queries.clear()

    record = execute.apply(runtime, NAME, req, expected_plan_sha256=preview["plan_sha256"])

    assert record["result"] == ("reverted" if stale else "confirmed"), record.get("reason")
    if stale:
        assert "confirm_start" not in steps(record)
        assert "check_identity_failed" in steps(record)
    else:
        assert target.check_queries.count(second_peer) >= 2
        assert policy_row not in target.lines
        assert execute.undo(runtime, record["change_id"], "Restore the approved test policy")["result"] == "confirmed"
    assert target.snapshot() == baseline and not target.pending()


def test_bgp_neighbor_import_export_preview_confirm_and_undo(tmp_path):
    target = RoutingLab(fixture("set-policy-after.txt") +
                        "set protocols bgp group transit type external\n"
                        "set protocols bgp group transit peer-as 64512\n"
                        "set protocols bgp group transit neighbor 192.0.2.141\n")
    runtime = make_runtime(tmp_path, target)
    key = "transit@192.0.2.141"
    req = request("bgp-neighbor", key, {"import": POLICY, "export": POLICY}, op="update", endpoint_impact=key)
    _run_and_undo(runtime, target, req)
    assert "show bgp neighbor 192.0.2.141 | no-more" in target.check_queries


def test_empty_existing_area_and_implicit_bgp_group_cannot_be_pruned():
    ospf = request("ospf-interface", INTERFACE, {"area": AREA, "passive": "yes"})
    area = BASELINE + f"set protocols ospf area {AREA}\n"
    peer = request("bgp-neighbor", "transit@192.0.2.141", {}, op="delete")
    group = BASELINE + "set protocols bgp group transit neighbor 192.0.2.141\n"
    for req, text in ((ospf, area), (peer, group)):
        with pytest.raises(Rejected) as exc:
            plan(req, text)
        assert exc.value.reason_codes == ["junos_routing_scope"]


def test_management_query_refusal_has_a_readback_reason(tmp_path):
    class RefusingLab(RoutingLab):
        def query(self, command):
            if command.startswith("show route 192.0.2.40 "):
                return "error: permission denied\n"
            return super().query(command)

    target = RefusingLab(fixture("set-interface-after.txt"))
    runtime = make_runtime(tmp_path, target)
    req = request("ospf3-interface", INTERFACE, {"area": AREA, "metric": 18, "passive": "yes"})
    result = execute.preview(runtime, NAME, req)
    assert result["reason_codes"] == ["junos_routing_readback_unreadable"]
