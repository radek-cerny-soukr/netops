"""JUNOS-DYNAMIC-ROUTING execution against a fake Junos transport with measured CLI answers."""
from pathlib import Path
import re

import pytest

from fake_junos import FakeJunos
from netops_admin import engine, exec_junos_g140, execute
from netops_admin.access import AccessError
from netops_admin.errors import Rejected
from test_junos import FIRMWARE, NAME, make_runtime, request, steps


PATH = Path(__file__).parent / "fixtures" / "junos_junos_dynamic_routing"
PORT = "ge-0/0/8"
STP = "ge-0/0/9"
KEY = "ae40"
LACP = "show lacp interfaces ae40"
TERSE = "show interfaces ae40 terse"
BRIDGE = "show spanning-tree bridge detail"
DETAIL = "show spanning-tree interface ge-0/0/9 detail"
COUNT = "set chassis aggregated-devices ethernet device-count"
EDGE = "set protocols rstp interface ge-0/0/9 edge"


def measured(name):
    return (PATH / (name + ".txt")).read_text()


def scope(name):
    return set(measured("enabled-" + name).splitlines())


LAG_CONFIG = scope("ae-config") | scope("lag-count") | scope("member-config")
RSTP_CONFIG = scope("stp-config")
STP_BRIDGE = set(line for line in RSTP_CONFIG if " interface " not in line)
STP_PORT = RSTP_CONFIG - STP_BRIDGE
WRITABLE = LAG_CONFIG | RSTP_CONFIG | {
    "set protocols rstp",
    "set interfaces ae40", "set interfaces ae40 aggregated-ether-options lacp passive",
    "set protocols rstp bridge-priority 8k", "set protocols rstp interface ge-0/0/9 cost 23456",
    COUNT + " 42",
}


class G140Transport(FakeJunos):
    broken = None
    bundled = False

    def _line(self, line, session):
        if line == "show | compare rollback 0 | no-more":
            return self._compare(self._candidate(session))
        if line == "show | compare":
            raise AssertionError("A JUNOS-DYNAMIC-ROUTING candidate diff must disable pagination")
        if line.startswith(("set chassis ", "delete chassis ")):
            return self._edit(line, self._candidate(session))
        return super()._line(line, session)

    def _edit(self, line, candidate):
        verb, _, path = line.partition(" ")
        stored = "set " + path
        if verb == "delete" and any(item == stored or item.startswith(stored + " ") for item in WRITABLE):
            deleted = stored in candidate
            candidate[:] = [item for item in candidate if item != stored and not item.startswith(stored + " ")]
            # Measured: the last RSTP interface leaf leaves a bare interface stanza.
            if deleted and re.fullmatch(r"set protocols rstp interface \S+ (?:edge|cost)", stored):
                path = stored.rsplit(" ", 1)[0]
                if not any(item.startswith(path + " ") for item in candidate):
                    candidate.append(path)
            return ""
        match = re.fullmatch(r"(set protocols rstp bridge-priority) ([0-9]+)", stored)
        if match:
            stored = "%s %dk" % (match[1], int(match[2]) // 1024)
        if verb == "set" and stored in WRITABLE:
            for prefix in (COUNT, "set protocols rstp bridge-priority", "set protocols rstp interface %s cost" % STP):
                if stored.startswith(prefix + " "):
                    candidate[:] = [item for item in candidate if not item.startswith(prefix + " ")]
            if stored.startswith("set interfaces ae40 "):
                candidate[:] = [item for item in candidate if item != "set interfaces ae40"]
            if stored.startswith("set protocols rstp "):
                candidate[:] = [item for item in candidate if item != "set protocols rstp"]
            if stored not in candidate:
                candidate.append(stored)
            return ""
        return super()._edit(line, candidate)

    def query(self, command):
        if command == "show interfaces terse" and any(line.startswith("set interfaces ae40 ") for line in self.lines):
            return super().query(command) + "ae40                    up    down\n"
        return super().query(command)

    def check_query(self, command):
        if command not in (LACP, TERSE, BRIDGE, DETAIL):
            return super().check_query(command)
        self.check_queries.append(command)
        lines = set(self.lines)
        if command in (LACP, TERSE):
            name = "lag" if command == LACP else "ae"
            stage = "enabled" if any(line.startswith("set interfaces ae40 ") for line in lines) else "before"
            text = measured(stage + "-" + name)
            if command == LACP and stage == "enabled":
                if not scope("member-config") <= lines:
                    return ""
                if "set interfaces ae40 aggregated-ether-options lacp passive" in lines:
                    text = text.replace("Fast    Active", "Fast   Passive")
                if self.bundled:
                    text = text.replace("Port disabled     No periodic           Detached",
                                        "      Current   Fast periodic Collecting distributing")
                if self.broken == "lacp":
                    text = "\n".join(text.splitlines()[:-1])
            return text
        if command == BRIDGE:
            if not any(line.startswith("set protocols rstp ") for line in lines):
                return measured("before-stp-bridge")
            priority = "8192" if "set protocols rstp bridge-priority 8k" in lines else (
                "4096" if "set protocols rstp bridge-priority 4k" in lines else "32768")
            return measured("enabled-stp-bridge").replace("4096.", priority + ".")
        if not STP_PORT & lines:
            return "" if STP_BRIDGE & lines else measured("before-stp-port")
        detail = measured("enabled-stp-port")
        if EDGE not in lines:
            detail = detail.replace("/EDGE", "")
        if "set protocols rstp interface ge-0/0/9 cost 23456" in lines:
            detail = detail.replace("12345", "23456")
        if self.broken == "stp":
            return "\n".join(detail.splitlines()[:-2])
        return detail


def lag(op="create", changes=None, **fields):
    return request(table="lag", op=op, key=KEY, changes=changes if changes is not None else
                   {"lacp-mode": "active", "members": [PORT]}, **fields)


def ready(runtime, req):
    result = execute.preview(runtime, NAME, req)
    assert result["result"] == "ready", result
    return result


def apply(runtime, req, preview):
    return execute.apply(runtime, NAME, req, expected_plan_sha256=preview["plan_sha256"])


def undo(runtime, result):
    preview = execute.preview_undo(runtime, result["change_id"], "restore JUNOS-DYNAMIC-ROUTING switch configuration", issue=True)
    assert preview["result"] == "ready", preview
    return execute.undo(runtime, result["change_id"], "restore JUNOS-DYNAMIC-ROUTING switch configuration",
                        expected_plan_sha256=preview["plan_sha256"])


@pytest.mark.parametrize("kind", ["lag", "port", "bridge"])
def test_preview_confirm_readback_and_exact_undo(tmp_path, kind):
    target = G140Transport()
    runtime = make_runtime(tmp_path, target)
    if kind == "lag":
        req = lag()
        configuration = LAG_CONFIG
    elif kind == "port":
        req = request(table="rstp-interface", key=STP, changes={"edge": "enabled", "cost": 12345})
        configuration = STP_PORT
    else:
        target.lines.extend(sorted(STP_PORT))
        req = request(table="rstp", key="rstp", endpoint_impact="rstp",
                      changes={"bridge-priority": 4096, "bpdu-block-on-edge": "enabled"})
        configuration = STP_BRIDGE
    before = target.lines[:]
    history = target.history[:]
    preview = ready(runtime, req)
    assert target.lines == before and target.history == history and not target.pending()
    record = apply(runtime, req, preview)
    assert record["result"] == "confirmed", record.get("reason")
    assert set(target.lines) - set(before) == configuration
    assert steps(record).index("check_identity_passed") < steps(record).index("confirm_start")
    returned = undo(runtime, record)
    assert returned["result"] == "confirmed", returned.get("reason")
    assert target.lines == before and not target.pending()
    assert "show configuration | display set" not in target.check_queries


@pytest.mark.parametrize("broken", ["lacp", "stp"])
def test_incomplete_operational_readback_restores_configuration(tmp_path, broken):
    target = G140Transport()
    runtime = make_runtime(tmp_path, target)
    req = lag() if broken == "lacp" else request(table="rstp-interface", key=STP, changes={"edge": "enabled"})
    preview = ready(runtime, req)
    target.broken = broken
    before = target.lines[:]
    record = apply(runtime, req, preview)
    assert record["result"] == "reverted", record.get("reason")
    assert "confirm_start" not in steps(record) and "check_identity_failed" in steps(record)
    assert target.lines == before and not target.pending()


def test_preexisting_lag_mode_changes_and_collecting_demands_impact(tmp_path):
    target = G140Transport()
    target.lines.extend(sorted(LAG_CONFIG))
    target.bundled = True
    runtime = make_runtime(tmp_path, target)
    before = target.lines[:]
    refused = execute.preview(runtime, NAME, lag("update", {"lacp-mode": "passive"}))
    assert refused["reason_codes"] == ["port_learned_mac"], refused
    req = lag("update", {"lacp-mode": "passive"}, endpoint_impact=KEY)
    record = apply(runtime, req, ready(runtime, req))
    assert record["result"] == "confirmed", record.get("reason")
    assert undo(runtime, record)["result"] == "confirmed"
    assert set(target.lines) == set(before)


@pytest.mark.parametrize("case,code", [
    ("lldp", "port_lldp_neighbor"), ("protected", "port_protected"),
    ("management", "port_management_interface"), ("foreign", "port_lag_member"),
])
def test_membership_refuses_protected_paths(tmp_path, case, code):
    target = G140Transport()
    protected = {}
    if case == "lldp":
        target.lldp_extra = [PORT]
    elif case == "protected":
        protected = {"interface": [PORT]}
    elif case == "management":
        target.up_ports = {PORT}
    elif case == "foreign":
        target.lines.append("set interfaces ge-0/0/8 ether-options 802.3ad ae6")
    runtime = make_runtime(tmp_path, target, protected=protected)
    before, history = target.lines[:], target.history[:]
    refused = execute.preview(runtime, NAME, lag(endpoint_impact=KEY))
    assert refused["reason_codes"] == [code], refused
    assert target.lines == before and target.history == history


def test_bridge_priority_demands_explicit_impact(tmp_path):
    target = G140Transport()
    runtime = make_runtime(tmp_path, target)
    req = request(table="rstp", key="rstp", changes={"bridge-priority": 4096})
    refused = execute.preview(runtime, NAME, req)
    assert refused["reason_codes"] == ["junos_rstp_impact_required"]


@pytest.mark.parametrize("changes", [{"bpdu-block-on-edge": "enabled"}, {"bridge-priority": 4096}])
def test_global_rstp_respects_logical_alias_of_protected_edge(tmp_path, changes):
    target = G140Transport()
    target.lines.extend(sorted(STP_PORT))
    runtime = make_runtime(tmp_path, target, protected={"interface": (f"{STP}.0",)})
    before = target.snapshot()
    req = request(table="rstp", key="rstp", endpoint_impact="rstp", changes=changes)

    refused = execute.preview(runtime, NAME, req)

    assert refused["result"] == "rejected"
    assert refused["reason_codes"] == ["port_protected"]
    assert target.snapshot() == before
    assert all(not any(line.startswith("commit") for line in block) for block in target.applied_blocks)


def test_apply_requires_approved_preview(tmp_path):
    target = G140Transport()
    runtime = make_runtime(tmp_path, target)
    with pytest.raises(Rejected) as refused:
        execute.apply(runtime, NAME, lag())
    assert refused.value.reason_codes == ["plan_changed"]
    assert not target.pending()


def test_capacity_is_only_raised_and_an_untested_release_warns():
    target = G140Transport()
    target.lines.append(COUNT + " 42")
    raw = target.snapshot().replace(FIRMWARE, "25.4R1.1").encode()
    plan = engine.build_plan("junos", raw, lag())
    assert plan["firmware_support"]["status"] == "untested"
    assert plan["junos_lag_capacity"] == {"before": "42", "after": "42"}
    assert all("device-count" not in line for line in plan["commands"])


def test_lacp_truncated_partner_is_rejected():
    output = measured("enabled-lag")
    with pytest.raises(Rejected):
        exec_junos_g140.lacp("\n".join(line for line in output.splitlines() if "Partner" not in line), KEY)



def test_removing_last_member_preserves_existing_aggregate_and_undo(tmp_path):
    target = G140Transport()
    target.lines.extend(sorted(LAG_CONFIG))
    runtime = make_runtime(tmp_path, target)
    before = set(target.lines)
    req = lag("update", {"members": []})
    record = apply(runtime, req, ready(runtime, req))
    assert record["result"] == "confirmed", record.get("reason")
    assert set(target.lines) == before - scope("member-config")
    assert undo(runtime, record)["result"] == "confirmed"
    assert set(target.lines) == before


def test_undo_preserves_preexisting_empty_aggregate(tmp_path):
    target = G140Transport()
    bare = "set interfaces ae40"
    target.lines.append(bare)
    runtime = make_runtime(tmp_path, target)
    before = set(target.lines)
    req = lag("update", {"lacp-mode": "active"})
    record = apply(runtime, req, ready(runtime, req))
    assert record["result"] == "confirmed", record.get("reason")
    assert bare not in target.lines
    assert undo(runtime, record)["result"] == "confirmed"
    assert set(target.lines) == before


def test_deleting_lag_preserves_capacity_and_undo_restores_object(tmp_path):
    target = G140Transport()
    target.lines.extend(sorted(LAG_CONFIG))
    runtime = make_runtime(tmp_path, target)
    before = set(target.lines)
    req = lag("delete", {})
    record = apply(runtime, req, ready(runtime, req))
    assert record["result"] == "confirmed", record.get("reason")
    assert set(target.lines) == before - (LAG_CONFIG - scope("lag-count"))
    assert undo(runtime, record)["result"] == "confirmed"
    assert set(target.lines) == before



def test_removing_first_rstp_port_restores_existing_empty_global_stanza(tmp_path):
    target = G140Transport()
    target.lines.append("set protocols rstp")
    runtime = make_runtime(tmp_path, target)
    before = set(target.lines)
    req = request(table="rstp-interface", key=STP, changes={"edge": "enabled", "cost": 12345})
    record = apply(runtime, req, ready(runtime, req))
    assert record["result"] == "confirmed"
    assert "set protocols rstp" not in target.lines
    assert undo(runtime, record)["result"] == "confirmed"
    assert set(target.lines) == before



def test_lag_cannot_add_default_management_vlan_to_an_unused_port(tmp_path):
    target = G140Transport()
    target.lines.extend(["set vlans default l3-interface irb.20",
                         "set interfaces irb unit 20 family inet address 192.0.2.56/24"])
    runtime = make_runtime(tmp_path, target)
    refused = execute.preview(runtime, NAME, lag(endpoint_impact=KEY))
    assert refused["reason_codes"] == ["port_management_interface"], refused


def test_preflight_distinguishes_transport_timeout(tmp_path):
    class TimedOutTransport(G140Transport):
        def query(self, command):
            if command == "show interfaces terse":
                raise AccessError("query failed: connection timed out")
            return super().query(command)

    runtime = make_runtime(tmp_path, TimedOutTransport())
    refused = execute.preview(runtime, NAME, lag())
    assert refused["reason_codes"] == ["junos_link_read_timeout"], refused
