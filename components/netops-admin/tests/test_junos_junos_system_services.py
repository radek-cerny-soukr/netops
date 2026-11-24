"""JUNOS-SYSTEM-SERVICES routing profiles through Admin and the Junos transport boundary."""

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

FIXTURES = Path(__file__).parent / "fixtures" / "junos_26_2R1_7" / "junos-system-services"
INTERFACE = "irb.3920"
PREFIX_LIST = "NETOPS-JUNOS-SYSTEM-SERVICES-PREFIXES"
POLICY = "NETOPS-JUNOS-SYSTEM-SERVICES-POLICY"
AREA = "0.0.0.7"
PREFIXES = "203.0.113.1/32 203.0.113.2/32"
TERMS = f"match:{PREFIX_LIST}:accept default:-:reject"
IDS = itertools.count(1)


def fixture(name):
    return (FIXTURES / name).read_text()


def request(table, key, changes, op="create", **fields):
    return parse_request(request_bytes(table=table, key=key, changes=changes, op=op,
                                       request_id=f"junos-system-services-unit-{next(IDS):04}", **fields))


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
    missing = request("route-policy", "NETOPS-JUNOS-SYSTEM-SERVICES-MISSING", {"terms": "match:missing:accept"})
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
    runtime = make_runtime(tmp_path, target, simulate_unmeasured_profiles=True)
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
    runtime = make_runtime(tmp_path, target, simulate_unmeasured_profiles=True)
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
    runtime = make_runtime(tmp_path, target, simulate_unmeasured_profiles=True)
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


# ---- 1.0.13: the license warning of a completed BGP commit (measured on vJunos-switch 26.2R1.7) ----

LICENSE_COMMIT = fixture("commit-confirmed-10__bgp-license-warning.txt")
LICENSE_ROWS = LICENSE_COMMIT.split("commit confirmed will be automatically rolled back", 1)[0]
OTHER_WARNING = "warning: statement has no contents; ignored"


class LicensedRoutingLab(RoutingLab):
    """vJunos-switch without a BGP license: a commit that changes BGP and leaves it configured answers the measured
    warning block above "commit complete"; the check account reads the measured summary and group answers."""

    def __init__(self, config="", rows=LICENSE_ROWS):
        super().__init__(config)
        self.rows = rows

    def _commit(self, candidate, minutes, comment):
        def bgp(lines):
            return [line for line in lines if line.startswith("set protocols bgp ")]

        changed = bgp(candidate) != bgp(self.lines)
        answer = super()._commit(candidate, minutes, comment)
        if "commit complete" in answer and changed and bgp(candidate):
            return self.rows + answer
        return answer

    def check_query(self, command):
        if command == "show bgp group summary | no-more":
            self.check_queries.append(command)
            if not any(line.startswith("set protocols bgp ") for line in self.lines):
                return fixture("show-bgp-group-summary__license-not-running.txt")
        if command == "show bgp group measurement-bgp | no-more":
            self.check_queries.append(command)
            return fixture("show-bgp-group__license-empty.txt")
        if command == "show bgp group transit | no-more":
            self.check_queries.append(command)
            return fixture("show-bgp-group__license-empty.txt").rstrip("\n") + "\n" + fixture("bgp-group-vendor.txt")
        return super().check_query(command)


def test_cli_error_accepts_the_measured_license_warning_only_on_a_completed_commit():
    echo = 'commit confirmed 10 comment "netops-change" \n'
    assert junos.cli_error(echo + LICENSE_COMMIT) is None
    assert junos.cli_error(echo + LICENSE_COMMIT.replace("commit complete\n", "")) == "warning: requires 'BGP' license"
    other = LICENSE_COMMIT.replace("warning: requires 'BGP' license", OTHER_WARNING)
    assert junos.cli_error(echo + other) == OTHER_WARNING
    assert junos.cli_error(echo + LICENSE_ROWS + "    " + OTHER_WARNING + "\n" + LICENSE_COMMIT.split("\n", 3)[3]) \
        == OTHER_WARNING
    assert junos.cli_error("set protocols bgp group transit type external \n" + LICENSE_ROWS) \
        == "warning: requires 'BGP' license"


# r3: a warning is a warning in either case; the captured check-account row starts with "Warning:" (capital W)
CAPITAL_WARNING = fixture("show-bgp-group__license-empty.txt").strip()


def test_cli_error_refuses_a_capitalised_warning_on_commit_and_set():
    echo = 'commit confirmed 10 comment "netops-change" \n'
    tail = LICENSE_COMMIT.split("\n", 3)[3]
    assert junos.cli_error(echo + LICENSE_ROWS + "    " + CAPITAL_WARNING + "\n" + tail) == CAPITAL_WARNING
    capital_license = LICENSE_COMMIT.replace("warning: requires", "Warning: requires")
    assert junos.cli_error(echo + capital_license) == "Warning: requires 'BGP' license"
    assert junos.cli_error("set protocols bgp group transit type external \n" + CAPITAL_WARNING + "\n") \
        == CAPITAL_WARNING


def _transit_lab(cls=None, **kwargs):
    return (cls or LicensedRoutingLab)(fixture("set-policy-after.txt") +
                                       "set protocols bgp group transit type external\n"
                                       "set protocols bgp group transit peer-as 64512\n"
                                       "set protocols bgp group transit neighbor 192.0.2.141\n", **kwargs)


def _transit_import_apply(runtime):
    req = request("bgp-group", "transit", {"import": POLICY}, op="update", endpoint_impact="transit")
    preview = execute.preview(runtime, NAME, req)
    assert preview["result"] == "ready", preview
    return execute.apply(runtime, NAME, req, expected_plan_sha256=preview["plan_sha256"])


def test_bgp_commit_with_the_license_and_a_capitalised_warning_fails_and_returns(tmp_path):
    target = _transit_lab(rows=LICENSE_ROWS + "    " + CAPITAL_WARNING + "\n")
    runtime = make_runtime(tmp_path, target, simulate_unmeasured_profiles=True)
    baseline = target.snapshot()
    record = _transit_import_apply(runtime)
    assert (record["result"], record["reason"]) == ("reverted", "change failed"), steps(record)
    assert "change_failed" in steps(record)
    assert target.snapshot() == baseline and not target.pending()


def test_bgp_set_answered_with_a_capitalised_warning_fails_and_returns(tmp_path):
    class WarningSetLab(LicensedRoutingLab):
        def _line(self, line, session):
            answer = super()._line(line, session)
            if line.startswith("set protocols bgp group transit import "):
                return CAPITAL_WARNING
            return answer

    target = _transit_lab(WarningSetLab)
    runtime = make_runtime(tmp_path, target, simulate_unmeasured_profiles=True)
    baseline = target.snapshot()
    record = _transit_import_apply(runtime)
    assert (record["result"], record["reason"]) == ("reverted", "change failed"), steps(record)
    assert "change_failed" in steps(record)
    assert target.snapshot() == baseline and not target.pending()


@pytest.mark.parametrize("warning", [OTHER_WARNING, CAPITAL_WARNING], ids=["lower", "capital"])
def test_a_warning_on_the_final_confirmation_commit_is_never_confirmed(tmp_path, warning):
    """The own netops-<id>-ok commit completes with a warning: the transport refuses the line and the history shows
    the own confirmation without a pending rollback; the refusal must not be lost (the change is not confirmed)."""
    class WarningConfirmationLab(LicensedRoutingLab):
        def _commit(self, candidate, minutes, comment):
            answer = super()._commit(candidate, minutes, comment)
            if minutes is None and comment.endswith("-ok"):
                return LICENSE_ROWS.replace("warning: requires 'BGP' license", warning) + answer
            return answer

    target = _transit_lab(WarningConfirmationLab)
    runtime = make_runtime(tmp_path, target, simulate_unmeasured_profiles=True)
    record = _transit_import_apply(runtime)
    assert "confirm_start" in steps(record)
    assert any((item["comment"] or "").endswith("-ok") for item in target.history)
    assert record["result"] != "confirmed", steps(record)
    assert "confirm_unverified" in steps(record)


def test_bgp_commit_with_license_warning_is_confirmed_read_back_and_undone(tmp_path):
    target = LicensedRoutingLab(fixture("set-policy-after.txt") +
                                "set protocols bgp group transit type external\n"
                                "set protocols bgp group transit peer-as 64512\n"
                                "set protocols bgp group transit neighbor 192.0.2.141\n")
    runtime = make_runtime(tmp_path, target, simulate_unmeasured_profiles=True)
    req = request("bgp-group", "transit", {"import": POLICY}, op="update", endpoint_impact="transit")
    _run_and_undo(runtime, target, req)
    assert "show bgp group transit | no-more" in target.check_queries


def test_bgp_commit_with_another_warning_still_fails_and_returns(tmp_path):
    target = LicensedRoutingLab(fixture("set-policy-after.txt") +
                                "set protocols bgp group transit type external\n"
                                "set protocols bgp group transit peer-as 64512\n"
                                "set protocols bgp group transit neighbor 192.0.2.141\n",
                                rows=LICENSE_ROWS.replace("warning: requires 'BGP' license", OTHER_WARNING))
    runtime = make_runtime(tmp_path, target, simulate_unmeasured_profiles=True)
    baseline = target.snapshot()
    req = request("bgp-group", "transit", {"import": POLICY}, op="update", endpoint_impact="transit")
    preview = execute.preview(runtime, NAME, req)
    record = execute.apply(runtime, NAME, req, expected_plan_sha256=preview["plan_sha256"])
    assert (record["result"], record["reason"]) == ("reverted", "change failed"), steps(record)
    assert "change_failed" in steps(record)
    assert target.snapshot() == baseline


def test_new_group_with_license_warning_and_empty_group_display_is_returned(tmp_path):
    """The live result: the commit passes, the check account sees only the license warning for the new group without
    neighbours, so the check identity fails closed and the change is returned."""
    target = LicensedRoutingLab(fixture("set-policy-after.txt"))
    runtime = make_runtime(tmp_path, target, simulate_unmeasured_profiles=True)
    baseline = target.snapshot()
    req = request("bgp-group", "measurement-bgp", {"type": "external", "peer-as": 64512})
    preview = execute.preview(runtime, NAME, req)
    assert preview["result"] == "ready", preview
    record = execute.apply(runtime, NAME, req, expected_plan_sha256=preview["plan_sha256"])
    assert (record["result"], record["reason"]) == ("reverted", "check identity unavailable"), steps(record)
    assert {"change_applied", "postcheck_passed", "check_identity_failed"} <= set(steps(record))
    assert "show bgp group measurement-bgp | no-more" in target.check_queries
    assert target.snapshot() == baseline


# ---- 1.0.13 r2: BGP with the lab local AS (measured on vJunos-switch 26.2R1.7, profiles enabled) ----

GROUP = "measurement-bgp"
FIRST_PEER, SECOND_PEER = "192.0.2.57", "192.0.2.58"
NOT_RUNNING = fixture("show-bgp-group-summary__license-not-running.txt")


class MeasuredBgpLab(LicensedRoutingLab):
    """vJunos-switch with `routing-options autonomous-system` and still without a BGP license: the check account's
    answers are the measured ones for the state of the simulated configuration (no BGP, a group without neighbours,
    a group with the first neighbour, a neighbour that overrides the group's peer AS)."""

    def _line(self, line, session):
        # a batch reads its exclusive candidate and compares it with the active configuration (as in the batch
        # simulation of test_junos_junos_interface_recovery.py)
        if line == junos.BATCH_BASELINE:
            return "\n".join(self._candidate(session))
        if line == junos.BATCH_COMPARE:
            return self._compare(self._candidate(session))
        return super()._line(line, session)

    def _bgp(self):
        return [row for row in self.lines if row.startswith("set protocols bgp ")]

    def _peers(self):
        prefix = f"set protocols bgp group {GROUP} neighbor "
        return {row[len(prefix):].split()[0]: row for row in self._bgp() if row.startswith(prefix)}

    def check_query(self, command):
        answers = {
            "show bgp summary | no-more": "show-bgp-summary__as-one-peer.txt",
            "show bgp group summary | no-more": "show-bgp-group-summary__as-one-group.txt",
            f"show bgp neighbor {FIRST_PEER} | no-more": "show-bgp-neighbor__as-first-peer.txt",
            f"show bgp neighbor {SECOND_PEER} | no-more": "show-bgp-neighbor__as-second-peer.txt",
        }
        peers = self._peers()
        if command == f"show bgp group {GROUP} | no-more":
            self.check_queries.append(command)
            if not self._bgp():
                return NOT_RUNNING
            if not peers:
                return fixture("show-bgp-group__license-empty.txt")
            override = any(row.endswith(" peer-as 64513") for row in peers.values())
            return fixture("show-bgp-group__as-peer-as-override.txt" if override else "show-bgp-group__as-one-peer.txt")
        if command in answers:
            self.check_queries.append(command)
            if not self._bgp():
                return NOT_RUNNING
            if command.startswith("show bgp neighbor ") and command.split()[3] not in peers or \
                    not command.startswith("show bgp neighbor ") and set(peers) != {FIRST_PEER}:
                raise AssertionError("no measured answer for %r in this state" % command)
            return fixture(answers[command])
        return super().check_query(command)


def _bgp_batch(neighbour_as):
    return parse_request(request_bytes(
        table="batch", op="update", key="batch", request_id=f"junos-system-services-unit-{next(IDS):04}",
        changes=[{"table": "bgp-group", "op": "create", "key": GROUP,
                  "changes": {"type": "external", "peer-as": 64512}},
                 {"table": "bgp-neighbor", "op": "create", "key": f"{GROUP}@{FIRST_PEER}",
                  "changes": {"peer-as": neighbour_as}}]))


def _approved_undo(runtime, record):
    reason = "restore the BGP measurement baseline"
    preview = execute.preview_undo(runtime, record["change_id"], reason, issue=True)
    assert preview["result"] == "ready", preview
    undo = execute.undo(runtime, record["change_id"], reason, expected_plan_sha256=preview["plan_sha256"])
    assert undo["result"] == "confirmed", (undo.get("reason"), undo.get("steps"))
    return undo


def test_measured_bgp_group_and_neighbor_batch_is_confirmed_read_back_and_undone(tmp_path):
    """The live run: group and its first neighbour in one batch, confirmed after the check account read the group and
    the neighbour, then undone as one operation to the configuration before."""
    target = MeasuredBgpLab(fixture("set-policy-after.txt"))
    runtime = make_runtime(tmp_path, target)
    baseline = target.snapshot()
    req = _bgp_batch(64512)
    preview = execute.preview(runtime, NAME, req)
    assert preview["result"] == "ready", preview
    record = execute.apply(runtime, NAME, req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", (record.get("reason"), record.get("steps"))
    assert {"batch_step_verified", "check_identity_passed"} <= set(steps(record))
    assert f"show bgp group {GROUP} | no-more" in target.check_queries
    assert f"show bgp neighbor {FIRST_PEER} | no-more" in target.check_queries
    _approved_undo(runtime, record)
    assert target.snapshot() == baseline


def test_measured_bgp_neighbor_on_the_admin_group_is_confirmed_and_undone(tmp_path):
    """The live run: a second neighbour with its own peer AS added on the group the Admin batch created."""
    target = MeasuredBgpLab(fixture("set-policy-after.txt"))
    runtime = make_runtime(tmp_path, target)
    batch = _bgp_batch(64512)
    created = execute.apply(runtime, NAME, batch, expected_plan_sha256=execute.preview(runtime, NAME, batch)["plan_sha256"])
    assert created["result"] == "confirmed", created
    with_group = target.snapshot()
    req = request("bgp-neighbor", f"{GROUP}@{SECOND_PEER}", {"peer-as": 64513})
    preview = execute.preview(runtime, NAME, req)
    assert preview["result"] == "ready", preview
    record = execute.apply(runtime, NAME, req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", (record.get("reason"), record.get("steps"))
    assert "check_identity_passed" in steps(record)
    assert f"show bgp neighbor {SECOND_PEER} | no-more" in target.check_queries
    _approved_undo(runtime, record)
    assert target.snapshot() == with_group


@pytest.mark.parametrize("change", ["group-alone", "neighbour-overrides-peer-as"])
def test_measured_bgp_group_the_check_account_cannot_confirm_is_returned(tmp_path, change):
    """Live with the local AS: a group without neighbours still shows only the license warning, and a group whose only
    neighbour has another peer AS shows that AS in the group display; both fail the check closed and are returned."""
    target = MeasuredBgpLab(fixture("set-policy-after.txt"))
    runtime = make_runtime(tmp_path, target)
    baseline = target.snapshot()
    req = (request("bgp-group", GROUP, {"type": "external", "peer-as": 64512}) if change == "group-alone"
           else _bgp_batch(64513))
    preview = execute.preview(runtime, NAME, req)
    assert preview["result"] == "ready", preview
    read = len(target.check_queries)
    record = execute.apply(runtime, NAME, req, expected_plan_sha256=preview["plan_sha256"])
    assert (record["result"], record["reason"]) == ("reverted", "check identity unavailable"), steps(record)
    assert f"show bgp group {GROUP} | no-more" in target.check_queries[read:]
    assert f"show bgp neighbor {FIRST_PEER} | no-more" not in target.check_queries[read:]
    assert target.snapshot() == baseline


# r3: the lab's local AS is not published; the measured BGP answers carry the documentation AS (RFC 5398)
LOCAL_AS = re.compile(r"(?:Local AS:|Local: unspecified AS) (\d+)$", re.MULTILINE)
MEASURED_WITH_LOCAL_AS = ("show-bgp-group__as-one-peer.txt", "show-bgp-group__as-peer-as-override.txt",
                          "show-bgp-neighbor__as-first-peer.txt", "show-bgp-neighbor__as-second-peer.txt")


def test_measured_bgp_answers_and_provenance_carry_the_documentation_local_as():
    seen = {name: LOCAL_AS.findall(fixture(name)) for name in MEASURED_WITH_LOCAL_AS}
    assert all(len(found) == 1 for found in seen.values()), seen
    numbers = {found[0] for found in seen.values()}
    assert numbers == {"64500"} and 64496 <= int(numbers.pop()) <= 64511, seen
    provenance = fixture("PROVENANCE.md")
    assert "documentation AS\n64500 (RFC 5398)" in provenance or "documentation AS 64500 (RFC 5398)" in provenance
    assert not re.search(r"autonomous-system \d", provenance)
