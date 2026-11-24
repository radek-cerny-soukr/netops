"""EOS-DYNAMIC-ROUTING preview, timed apply, RO readback and undo against measured cEOS output."""
from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path

import pytest

from fake_eos import FakeEos
from test_eos import make_runtime, request, steps

from netops_admin import eos_routing, execute
from netops_admin.access import AccessError
from netops_admin.errors import Rejected

FIXTURES = Path(__file__).parent / "fixtures" / "eos_eos_dynamic_routing"
TARGET = "lab-ceos"
LOOPBACK = "Loopback126"
PREFIX = "192.0.2.0/24"
AREA = "198.51.100.126"
LIST = "NETOPS-EOS-DYNAMIC-ROUTING-P"
MAP = "NETOPS-EOS-DYNAMIC-ROUTING-M"


def raw(name):
    return (FIXTURES / name).read_text()


class MeasuredRoutingEos(FakeEos):
    def __init__(self):
        super().__init__()
        interface, address, *_ = raw("d-config.txt").splitlines()
        self.lines[self.lines.index("end"):self.lines.index("end")] = [interface, address, "!"]
        self.saved = list(self.lines)
        self.operational_error = None
        self.ssh_source = "198.51.100.36"
        self.rib_interface = "Management0"
        self.rib_kind = "connected"
        self.commands_before_commit = []
        self.refuse_candidate = False

    def read_block(self, header):
        start, end = self._block(header)
        return [line.strip() for line in self.lines[start + 1:end]]

    def insert_block(self, header, lines=()):
        at = self.lines.index("end")
        self.lines[at:at] = [header, *("   " + line for line in lines), "!"]

    def replace_line(self, header, stem, text):
        start, end = self._block(header)
        old = [child for child in self.lines[start + 1:end] if not child.strip().startswith(stem)]
        self.lines[start + 1:end] = old + (["   " + text] if text else [])

    def _line(self, line, mode):
        current = mode[0]
        if current.startswith("session:") and line.startswith("commit timer "):
            label = current.split(":", 1)[1]
            pending = self.sessions[label].pop("candidate", [])
            before = list(self.lines)
            self.commands_before_commit.append((pending, before))
            if self.refuse_candidate:
                self.sessions[label]["candidate"] = pending
                return "% Invalid input"
            answer = super()._line(line, mode)
            if not answer:
                context = None
                for command in pending:
                    context = self.write_routing(command, context)
                assert context is None
            return answer
        if current.startswith("session:") and line != "abort":
            self.sessions[current.split(":", 1)[1]].setdefault("candidate", []).append(line)
            return ""
        return super()._line(line, mode)

    def write_routing(self, line, context):
        if line == "exit":
            return None
        command = line.removeprefix("no ")
        negated = command != line
        if command.startswith(("router ospf ", "route-map ", "interface ")):
            if negated:
                start, end = self._block(command)
                del self.lines[start:end + 1]
                return None
            if command not in self.lines:
                self.insert_block(command, ["max-lsa 12000"] if command.startswith("router ospf ") else [])
            return command
        if command.startswith("ip prefix-list "):
            if negated:
                start = next(i for i, existing in enumerate(self.lines) if existing.startswith(command + " "))
                del self.lines[start:start + 2]
            else:
                assert not any(existing.startswith(" ".join(command.split()[:5]) + " ") for existing in self.lines)
                self.insert_block(command)
            return context
        assert context is not None, line
        if command.startswith("network "):
            stem = " ".join(command.split()[:3]) + " "
        elif re.fullmatch(r"(?:(?:no|default) )?passive-interface \S+", line):
            interface = line.split()[-1]
            start, end = self._block(context)
            owned = {f"passive-interface {interface}", f"no passive-interface {interface}"}
            self.lines[start + 1:end] = [child for child in self.lines[start + 1:end] if child.strip() not in owned]
            if not line.startswith("default "):
                self.lines.insert(self._block(context)[1], "   " + line)
            return context
        elif command.startswith("ip ospf cost"):
            stem = "ip ospf cost"
        elif command.startswith("router-id "):
            stem = "router-id "
        elif command.startswith("match ip address prefix-list "):
            stem = "match ip address prefix-list "
        else:
            raise AssertionError(line)
        self.replace_line(context, stem, None if negated else command)
        return context

    def check_query(self, command):
        if command.startswith("show ip route vrf default "):
            self.check_queries.append(command)
            ans = json.loads(raw("d-management-route.json"))
            vrf = ans["vrfs"]["default"]
            route = next(iter(vrf["routes"].values()))
            route.update(routeType=self.rib_kind, vias=[{"interface": self.rib_interface}])
            vrf["routes"] = {"198.51.100.32/27": route}
            return json.dumps(ans)
        if not command.startswith(("show route-map ", "show ip prefix-list ", "show ip ospf")):
            return super().check_query(command)
        self.check_queries.append(command)
        if isinstance(self.operational_error, Exception):
            raise self.operational_error
        if self.operational_error is not None:
            return self.operational_error
        if command == f"show ip prefix-list {LIST} | json":
            value = json.loads(raw("d-prefix.json"))
            rows = []
            for line in self.lines:
                if line.startswith(f"ip prefix-list {LIST} seq "):
                    _, _, _, _, seq, action, prefix = line.split()
                    row = value["ipPrefixLists"][LIST]["ipPrefixEntries"][0]
                    rows.append({**row, "seqno": int(seq), "filterType": action, "prefix": prefix})
            if not rows:
                return raw("d-prefix-absent.json")
            value["ipPrefixLists"][LIST]["ipPrefixEntries"] = rows
            return json.dumps(value)
        if command == f"show route-map {MAP} | json":
            value = json.loads(raw("d-map.json"))
            entries = {}
            for line in self.lines:
                if line.startswith(f"route-map {MAP} "):
                    _, _, action, seq = line.split()
                    row = value["routeMaps"][MAP]["entries"]["10"]
                    lists = [rule.split()[-1] for rule in self.read_block(line)]
                    entries[seq] = {**row, "filterType": action,
                                    "matchRules": {"prefixList": lists[0]} if lists else {}}
            if not entries:
                return raw("d-map-absent.json")
            value["routeMaps"][MAP]["entries"] = entries
            return json.dumps(value)
        assert command in ("show ip ospf | json", f"show ip ospf interface {LOOPBACK} | json")
        header = "router ospf 126"
        if command == "show ip ospf | json":
            value = json.loads(raw("d-ospf-process.json"))
            processes = value["vrfs"]["default"]["instList"]
            if header in self.lines:
                processes["126"]["routerId"] = next(line[10:] for line in self.read_block(header)
                                                     if line.startswith("router-id "))
            else:
                del processes["126"]
            return json.dumps(value)
        if header not in self.lines:
            return raw("d-ospf-interface-absent.json")
        value = json.loads(raw("d-ospf-interface.json"))
        interfaces = value["vrfs"]["default"]["instList"]["126"]["interfaces"]
        area = next((line.split()[-1] for line in self.read_block(header) if line.startswith(f"network {PREFIX} ")), None)
        if area is None:
            interfaces.clear()
        else:
            cost = next((int(line.split()[-1]) for line in self.interface(LOOPBACK) if line.startswith("ip ospf cost ")), 10)
            passive = f"passive-interface {LOOPBACK}" in self.read_block(header)
            interfaces[LOOPBACK].update(area=area, cost=cost, passive=passive)
        return json.dumps(value)


def change(table, op, key, changes, tag):
    return request(table=table, op=op, key=key, changes=changes, request_id=f"eos-dynamic-routing-{tag}")


def confirmed(runtime, cli, req):
    original = list(cli.lines)
    writes = len(cli.applied_blocks)
    plan = execute.preview(runtime, TARGET, req)
    assert plan["result"] == "ready", plan
    assert len(cli.applied_blocks) == writes and cli.lines == original
    result = execute.apply(runtime, TARGET, req, expected_plan_sha256=plan["plan_sha256"])
    assert result["result"] == "confirmed", result
    assert "check_identity_passed" in steps(result)
    label = result["safeguard"]["name"]
    candidate = cli.applied_blocks[writes]
    assert candidate[0] == f"configure session {label}" and candidate[-1].startswith("commit timer ")
    assert candidate[1:-1] == plan["commands"]
    assert len([block for block in cli.applied_blocks[writes:] if block[:1] == ["configure terminal"]]) == 0
    assert cli.lines == cli.saved and not cli.sessions and cli.timer is None
    return result


def undo(runtime, cli, record):
    before = list(cli.lines)
    why = "verify the EOS-DYNAMIC-ROUTING return"
    plan = execute.preview_undo(runtime, record["change_id"], why, issue=True)
    assert plan["result"] == "ready", plan
    assert cli.lines == before
    result = execute.undo(runtime, record["change_id"], why, expected_plan_sha256=plan["plan_sha256"])
    assert result["result"] == "confirmed", result
    assert "check_identity_passed" in steps(result)
    assert cli.lines == cli.saved and not cli.sessions and cli.timer is None


def test_ospf_process_network_and_interface_roundtrip(tmp_path):
    cli = MeasuredRoutingEos()
    original = list(cli.lines)
    runtime = make_runtime(tmp_path, cli)
    process = confirmed(runtime, cli, change(eos_routing.OSPF_PROCESS, "create", "126",
                                             {"router-id": "192.0.2.126"}, "process"))
    network = confirmed(runtime, cli, change(eos_routing.OSPF_NETWORK, "create", f"126:{PREFIX}",
                                             {"area": AREA}, "network"))
    middle = list(cli.lines)
    interface = confirmed(runtime, cli, change(eos_routing.OSPF_INTERFACE, "update", f"126:{LOOPBACK}",
                                               {"cost": 126, "passive": "enabled"}, "interface"))
    assert "ip ospf cost 126" in cli.interface(LOOPBACK)
    assert f"passive-interface {LOOPBACK}" in cli.read_block("router ospf 126")
    undo(runtime, cli, interface)
    candidate, _ = cli.commands_before_commit[-1]
    assert f"default passive-interface {LOOPBACK}" in candidate
    assert cli.lines == middle
    undo(runtime, cli, network)
    undo(runtime, cli, process)
    assert cli.lines == original
    assert f"show ip ospf interface {LOOPBACK} | json" in cli.check_queries


def test_ospf_undo_restores_an_explicitly_active_interface(tmp_path):
    cli = MeasuredRoutingEos()
    header, *children = raw("d-ospf-explicit-active.txt").splitlines()
    cli.insert_block(header, [line.strip() for line in children])
    cli.saved = list(cli.lines)
    runtime = make_runtime(tmp_path, cli)
    result = confirmed(runtime, cli, change(eos_routing.OSPF_INTERFACE, "update", f"126:{LOOPBACK}",
                                            {"passive": "enabled"}, "active"))
    undo(runtime, cli, result)
    assert f"no passive-interface {LOOPBACK}" in cli.read_block("router ospf 126")


def test_prefix_and_policy_roundtrip(tmp_path):
    cli = MeasuredRoutingEos()
    original = list(cli.lines)
    runtime = make_runtime(tmp_path, cli)
    prefix = confirmed(runtime, cli, change(eos_routing.PREFIX_LIST, "create", LIST,
                                            {"rules": f"10 permit {PREFIX}"}, "prefix"))
    policy = confirmed(runtime, cli, change(eos_routing.ROUTE_MAP, "create", f"{MAP}:10",
                                            {"action": "permit", "prefix-list": LIST}, "map"))
    updated = confirmed(runtime, cli, change(eos_routing.PREFIX_LIST, "update", LIST,
                                             {"rules": f"10 permit {PREFIX}, 20 deny 198.51.100.128/25"}, "prefix-update"))
    candidate, _ = cli.commands_before_commit[-1]
    assert candidate == [f"ip prefix-list {LIST} seq 20 deny 198.51.100.128/25"]
    undo(runtime, cli, updated)
    undo(runtime, cli, policy)
    undo(runtime, cli, prefix)
    assert cli.lines == original
    assert {f"show ip prefix-list {LIST} | json", f"show route-map {MAP} | json"} <= set(cli.check_queries)


@pytest.mark.parametrize(("answer", "code"), [
    ('{"ipPrefixLists":', "eos_routing_readback_unreadable"),
    ("% Invalid input at line 1\n", "eos_routing_readback_unreadable"),
    (AccessError("query timed out"), "eos_routing_read_timeout"),
])
def test_incomplete_refused_and_timeout_fail_before_write(tmp_path, answer, code):
    cli = MeasuredRoutingEos()
    cli.operational_error = answer
    runtime = make_runtime(tmp_path, cli)
    req = change(eos_routing.PREFIX_LIST, "create", LIST, {"rules": f"10 permit {PREFIX}"}, "refused")
    plan = execute.preview(runtime, TARGET, req)
    assert plan["result"] == "rejected" and plan["reason_codes"] == [code], plan
    assert not cli.applied_blocks


def test_route_to_ssh_source_blocks_ospf(tmp_path):
    cli = MeasuredRoutingEos()
    cli.insert_block("router ospf 126", ["router-id 192.0.2.126", "max-lsa 12000"])
    cli.saved = list(cli.lines)
    cli.rib_interface = LOOPBACK
    runtime = make_runtime(tmp_path, cli)
    req = change(eos_routing.OSPF_NETWORK, "create", f"126:{PREFIX}", {"area": AREA}, "management")
    plan = execute.preview(runtime, TARGET, req)
    assert plan["result"] == "rejected" and plan["reason_codes"] == ["port_management_interface"], plan
    assert not cli.applied_blocks


@pytest.mark.parametrize("table,op,target,changes", [
    (eos_routing.OSPF_INTERFACE, "update", "Vlan100", {"passive": "enabled"}),
    (eos_routing.OSPF_NETWORK, "update", "198.51.100.128/25", {"area": "0"}),
])
@pytest.mark.parametrize("source,code", [
    ("audit_policy", "port_management_vlan"),
    ("vlan", "port_management_vlan"),
    ("interface", "port_protected"),
])
def test_ospf_protects_configured_management_svi(tmp_path, table, op, target, changes, source, code):
    cli = MeasuredRoutingEos()
    cli.insert_block("vlan 100")
    cli.insert_block("interface Vlan100", ["ip address 198.51.100.129/25"])
    cli.insert_block("router ospf 126", ["router-id 192.0.2.126", "network 198.51.100.128/25 area 1"])
    cli.saved = list(cli.lines)
    protected = {} if source == "audit_policy" else {source: ("100" if source == "vlan" else "vlan100",)}
    runtime = make_runtime(tmp_path, cli, protected=protected)
    if source == "audit_policy":
        runtime.config.devices[TARGET] = replace(runtime.config.devices[TARGET], audit_policy={"management_vlans": [100]})
    req = change(table, op, f"126:{target}", changes, "protected-svi")
    plan = execute.preview(runtime, TARGET, req)
    assert plan["result"] == "rejected" and plan["reason_codes"] == [code], plan
    assert not cli.applied_blocks


def test_bound_policy_cannot_be_changed_indirectly(tmp_path):
    cli = MeasuredRoutingEos()
    cli.insert_block(f"ip prefix-list {LIST} seq 10 permit {PREFIX}")
    cli.insert_block(f"route-map {MAP} permit 10", [f"match ip address prefix-list {LIST}"])
    cli.insert_block("router bgp 65126", [f"neighbor 192.0.2.2 route-map {MAP} in"])
    cli.saved = list(cli.lines)
    runtime = make_runtime(tmp_path, cli)
    req = change(eos_routing.PREFIX_LIST, "update", LIST, {"rules": f"10 deny {PREFIX}"}, "bound")
    plan = execute.preview(runtime, TARGET, req)
    assert plan["result"] == "rejected" and plan["reason_codes"] == ["eos_routing_policy_in_use"], plan
    assert not cli.applied_blocks


def test_rejected_candidate_is_aborted_without_commit(tmp_path):
    cli = MeasuredRoutingEos()
    cli.refuse_candidate = True
    runtime = make_runtime(tmp_path, cli)
    original = list(cli.lines)
    req = change(eos_routing.PREFIX_LIST, "create", LIST, {"rules": f"10 permit {PREFIX}"}, "candidate")
    plan = execute.preview(runtime, TARGET, req)
    with pytest.raises(Rejected) as refused:
        execute.apply(runtime, TARGET, req)
    assert refused.value.reason_codes == ["plan_changed"]
    result = execute.apply(runtime, TARGET, req, expected_plan_sha256=plan["plan_sha256"])
    assert result["result"] == "reverted", result
    assert cli.lines == cli.saved == original and cli.saves == 0 and not cli.sessions and cli.timer is None


def test_failed_snapshot_after_candidate_abort_blocks_without_saving(tmp_path):
    class RoutingWire(MeasuredRoutingEos):
        def snapshot(self):
            if self.commands_before_commit and not self.sessions:
                raise AccessError("synthetic private EOS candidate diagnostic")
            return super().snapshot()

    cli = RoutingWire()
    cli.refuse_candidate = True
    runtime = make_runtime(tmp_path, cli)
    original = list(cli.lines)
    req = change(eos_routing.PREFIX_LIST, "create", LIST, {"rules": f"10 permit {PREFIX}"}, "candidate-disconnect")
    plan = execute.preview(runtime, TARGET, req)
    assert plan["result"] == "ready"

    record = execute.apply(runtime, TARGET, req, expected_plan_sha256=plan["plan_sha256"])

    assert (record["result"], record["reason"]) == ("unknown", "configuration session unverified")
    assert runtime.store.blocked(TARGET)["change_id"] == record["change_id"]
    assert cli.applied_blocks[-1] == [f'configure session {record["safeguard"]["name"]} abort']
    assert len(cli.commands_before_commit) == 1 and cli.lines == cli.saved == original
    assert not cli.sessions and cli.timer is None and cli.saves == 0
    assert "synthetic private EOS candidate diagnostic" not in repr(runtime.store.records())


def test_incomplete_postcheck_expires_and_restores_baseline(tmp_path):
    cli = MeasuredRoutingEos()
    original = list(cli.lines)
    runtime = make_runtime(tmp_path, cli)
    req = change(eos_routing.PREFIX_LIST, "create", LIST, {"rules": f"10 permit {PREFIX}"}, "bad-postcheck")
    plan = execute.preview(runtime, TARGET, req)
    assert plan["result"] == "ready"
    cli.on_apply = lambda device, lines: setattr(device, "operational_error", "{") if (
        lines[-1].startswith("commit timer ")) else None
    result = execute.apply(runtime, TARGET, req, expected_plan_sha256=plan["plan_sha256"])
    assert result["result"] == "reverted" and "check_identity_failed" in steps(result), result
    assert cli.lines == cli.saved == original and not cli.sessions and cli.timer is None
    assert cli.saved_while_pending == 0


def test_other_firmware_warns_without_blocking(tmp_path):
    cli = MeasuredRoutingEos()
    cli.firmware = "4.36.2F"
    cli.lines = [line.replace("EOS-4.36.1F", "EOS-4.36.2F") for line in cli.lines]
    cli.saved = list(cli.lines)
    runtime = make_runtime(tmp_path, cli, firmware=cli.firmware)
    req = change(eos_routing.PREFIX_LIST, "create", LIST, {"rules": f"10 permit {PREFIX}"}, "firmware")
    plan = execute.preview(runtime, TARGET, req)
    assert plan["result"] == "ready" and plan["firmware_support"]["status"] == "untested", plan
    assert not cli.applied_blocks


class MeasuredBgpEos(MeasuredRoutingEos):
    AS = "65126"
    PEER = "198.51.100.6"
    KEY = f"{AS}:{PEER}"
    ROUTER = f"router bgp {AS}"
    IN_MAP = "I597-BGP-IN"
    OUT_MAP = "I597-BGP-OUT"
    no_router = "bgp-without-router.json"

    def __init__(self):
        super().__init__()
        self.insert_block("vlan 3930")
        self.insert_block("interface Vlan3930", ["ip address 198.51.100.5/30"])
        self.insert_block(f"route-map {self.IN_MAP} deny 10")
        self.insert_block(f"route-map {self.OUT_MAP} deny 10")
        self.saved = list(self.lines)

    def write_routing(self, line, context):
        if line == self.ROUTER:
            if line not in self.lines:
                self.insert_block(line)
            return line
        if line == f"no {self.ROUTER}":
            start, end = self._block(self.ROUTER)
            del self.lines[start:end + 1]
            return None
        stem = f"neighbor {self.PEER}"
        command = line.removeprefix("no ")
        if command.startswith(stem):
            assert context == self.ROUTER
            if command == stem:
                self.replace_line(context, stem + " ", None)
            elif command.startswith(stem + " remote-as "):
                self.replace_line(context, stem + " remote-as ", command)
            else:
                assert command.startswith(stem + " route-map ")
                direction = command.split()[-1]
                start, end = self._block(context)
                self.lines[start + 1:end] = [
                    row for row in self.lines[start + 1:end]
                    if not (row.lstrip().startswith(stem + " route-map ") and row.split()[-1] == direction)
                ]
                if line == command:
                    self.lines.insert(self._block(context)[1], "   " + line)
            return context
        return super().write_routing(line, context)

    def check_query(self, command):
        if command != f"show ip bgp neighbors {self.PEER} | json":
            return super().check_query(command)
        self.check_queries.append(command)
        if self.ROUTER not in self.lines:
            return raw(self.no_router)
        children = self.read_block(self.ROUTER)
        stem = f"neighbor {self.PEER}"
        remote = next((line.split()[-1] for line in children if line.startswith(stem + " remote-as ")), "")
        if not remote:
            return raw("bgp-router-without-neighbors.json")
        maps = {side: line.split()[-2] for line in children for side in ("in", "out")
                if line.startswith(stem + " route-map ") and line.endswith(" " + side)}
        # measured: a neighbor without a route map has no routeMap* keys at all
        data = json.loads(raw("duo-bgp-neighbor.json" if maps else "bgp-neighbor-without-route-maps.json"))
        row, = data["vrfs"]["default"]["peerList"]
        row["asn"] = remote
        for field, side in (("routeMapInbound", "in"), ("routeMapOutbound", "out")):
            if side in maps:
                row[field], row[field + "Defined"] = maps[side], True
            else:
                row.pop(field, None)
                row.pop(field + "Defined", None)
        return json.dumps(data)


@pytest.mark.parametrize("existing_router", (False, True))
def test_bgp_peer_route_maps_and_exact_return(tmp_path, existing_router):
    from netops_admin import eos_bgp

    cli = MeasuredBgpEos()
    if existing_router:
        cli.insert_block(cli.ROUTER, ["neighbor 198.51.100.7 remote-as 65128"])
        cli.saved = list(cli.lines)
    start = list(cli.lines)
    runtime = make_runtime(tmp_path, cli)
    initial = {"remote-as": 65127, "route-map-in": cli.IN_MAP, "route-map-out": cli.OUT_MAP}
    created = confirmed(runtime, cli, change(eos_bgp.TABLE, "create", cli.KEY, initial, "bgp-peer"))
    update = {"route-map-in": cli.OUT_MAP, "route-map-out": None}
    denied = execute.preview(runtime, TARGET, change(eos_bgp.TABLE, "update", cli.KEY, update, "bgp-denial"))
    assert denied["result"] == "rejected" and denied["reason_codes"] == ["endpoint_impact_required"], denied
    patched = confirmed(runtime, cli, request(table=eos_bgp.TABLE, op="update", key=cli.KEY, changes=update,
                                             endpoint_impact=cli.KEY, request_id="eos-dynamic-routing-bgp-update"))
    undo(runtime, cli, patched)
    undo(runtime, cli, created)
    assert cli.lines == cli.saved == start
    assert f"show ip bgp neighbors {cli.PEER} | json" in cli.check_queries


def test_bgp_creation_undo_refuses_to_remove_new_router_settings(tmp_path):
    from netops_admin import eos_bgp

    cli = MeasuredBgpEos()
    runtime = make_runtime(tmp_path, cli)
    created = confirmed(runtime, cli, change(eos_bgp.TABLE, "create", cli.KEY, {"remote-as": 65127}, "bgp-parent"))
    cli.replace_line(cli.ROUTER, "router-id ", "router-id 192.0.2.126")
    cli.saved = list(cli.lines)
    denied = execute.preview_undo(runtime, created["change_id"], "Preserve the new router settings", issue=True)
    assert denied["result"] == "rejected" and denied["reason_codes"] == ["eos_routing_unsupported"], denied


@pytest.mark.parametrize("no_router", ("bgp-without-router.json", "bgp-inactive.json"))
def test_bgp_neighbor_without_route_maps_under_a_new_process_is_confirmed_and_undone(tmp_path, no_router):
    from netops_admin import eos_bgp

    cli = MeasuredBgpEos()
    cli.no_router = no_router
    start = list(cli.lines)
    runtime = make_runtime(tmp_path, cli)
    created = confirmed(runtime, cli, change(eos_bgp.TABLE, "create", cli.KEY, {"remote-as": 65127}, "bgp-plain"))
    assert created["plan"]["commands"][:2] == [cli.ROUTER, f"neighbor {cli.PEER} remote-as 65127"], created["plan"]
    undo(runtime, cli, created)
    assert cli.lines == cli.saved == start


@pytest.mark.parametrize("name, state", (
    ("bgp-neighbor-without-route-maps.json", {"remote-as": "65127"}),
    ("duo-bgp-neighbor.json", {"remote-as": "65127", "route-map-in": "I597-BGP-IN", "route-map-out": "I597-BGP-OUT"}),
    ("bgp-router-without-neighbors.json", None),
    ("bgp-without-router.json", None),
    ("bgp-inactive.json", None),
))
def test_bgp_measured_neighbor_answers(name, state):
    from netops_admin import eos_bgp

    assert eos_bgp.observe(json.loads(raw(name)), MeasuredBgpEos.KEY) == state


def test_bgp_refuses_other_errors_and_a_map_without_its_definition():
    from netops_admin import eos_bgp

    with pytest.raises(KeyError):
        eos_bgp.observe({"errors": ["Unexpected error"]}, MeasuredBgpEos.KEY)
    data = json.loads(raw("bgp-neighbor-without-route-maps.json"))
    data["vrfs"]["default"]["peerList"][0]["routeMapInbound"] = "I597-BGP-IN"
    with pytest.raises(ValueError):
        eos_bgp.observe(data, MeasuredBgpEos.KEY)


def test_bgp_refuses_unverified_route_map():
    from netops_admin import eos_bgp

    data = json.loads(raw("duo-bgp-neighbor.json"))
    data["vrfs"]["default"]["peerList"][0]["routeMapInboundDefined"] = False
    with pytest.raises(ValueError):
        eos_bgp.observe(data, MeasuredBgpEos.KEY)
