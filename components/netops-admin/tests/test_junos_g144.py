"""G144 (J29, J30): Junos DHCP pools, host reservations and relay groups through Admin and the Junos transport."""

from __future__ import annotations

import itertools
import re
from pathlib import Path

import pytest
from conftest import request_bytes
from fake_junos import BASELINE, FIRMWARE, FakeJunos
from test_junos import NAME, make_runtime, steps

from netops_admin import exec_junos, execute, junos, junos_dhcp
from netops_admin.engine import build_plan
from netops_admin.errors import Rejected
from netops_admin.request import parse_request

FIXTURES = Path(__file__).parent / "fixtures" / "junos_g144"
POOL = "NETOPS-G144-POOL"
NETWORK = "198.51.100.0/24"
HOST = f"{POOL}@NETOPS-G144-H1"
SERVERS = "NETOPS-G144-SG"
GROUP = "NETOPS-G144-RG"
IRB = "irb.3922"
IDS = itertools.count(1)
POOL_ROWS = f"set access address-assignment pool {POOL} family inet network {NETWORK}\n"
HOST_ROWS = (f"set access address-assignment pool {POOL} family inet host NETOPS-G144-H1 hardware-address 00:00:5e:00:53:44\n"
             f"set access address-assignment pool {POOL} family inet host NETOPS-G144-H1 ip-address 198.51.100.10\n")
IRB_ROWS = (f"set interfaces irb unit 3922 family inet address 198.51.100.1/24\n"
            f"set vlans netops-g144-test vlan-id 3922\nset vlans netops-g144-test l3-interface {IRB}\n")
SERVER_ROWS = f"set forwarding-options dhcp-relay server-group {SERVERS} 198.51.100.250\n"
GROUP_ROWS = (f"set forwarding-options dhcp-relay group {GROUP} active-server-group {SERVERS}\n"
              f"set forwarding-options dhcp-relay group {GROUP} interface {IRB}\n")
LEAF = re.compile(r"(set access address-assignment pool \S+ family inet (?:network|host \S+ (?:hardware-address|ip-address))"
                  r"|set forwarding-options dhcp-relay group \S+ active-server-group) ")


def fixture(name):
    return (FIXTURES / name).read_text()


def request(table, key, changes, op="create", **fields):
    return parse_request(request_bytes(table=table, key=key, changes=changes, op=op,
                                       request_id=f"g144-unit-{next(IDS):04}", **fields))


def plan(req, snapshot, **kwargs):
    return build_plan("junos", snapshot.encode(), req, firmware=FIRMWARE, **kwargs)


class DhcpLab(FakeJunos):
    """Candidate edits of the DHCP stanzas and the scoped configuration reads measured on d-vjunos."""

    def __init__(self, config=""):
        super().__init__()
        self.lines.extend((IRB_ROWS + config).splitlines())
        self.reads = []
        self.read_override = None
        self.read_override_from = 0

    def _line(self, line, session):
        words = line.split()
        if words[:1] in (["set"], ["delete"]) and (words[1:2] == ["access"] or words[1:3] == ["forwarding-options",
                                                                                              "dhcp-relay"]):
            candidate = self._candidate(session)
            statement = "set " + line.split(" ", 1)[1]
            if words[0] == "delete":
                kept = [item for item in candidate if item != statement and not item.startswith(statement + " ")]
                if len(kept) == len(candidate):
                    return "warning: statement not found"
                candidate[:] = kept
                return ""
            statement = re.sub(r"hardware-address (\S+)$", lambda match: "hardware-address " + match[1].lower(), statement)
            leaf = LEAF.match(statement)
            if leaf:
                candidate[:] = [item for item in candidate if not item.startswith(leaf[1] + " ")]
            if statement not in candidate:
                candidate.append(statement)
            return ""
        return super()._line(line, session)

    def query(self, command):
        match = re.fullmatch(r"show configuration (access address-assignment pool \S+|forwarding-options dhcp-relay)"
                             r" \| display set \| no-more", command)
        if match:
            self.reads.append(command)
            if self.read_override is not None and len(self.reads) >= self.read_override_from:
                return self.read_override
            path = "set " + match[1]
            return "".join(item + "\n" for item in self.lines if item == path or item.startswith(path + " ")) or "\n"
        return super().query(command)


def _run_and_undo(runtime, target, req):
    baseline = sorted(target.snapshot().splitlines())
    preview = execute.preview(runtime, NAME, req)
    assert preview["result"] == "ready", preview
    assert sorted(target.snapshot().splitlines()) == baseline
    assert all(not any(line.startswith("commit") for line in block) for block in target.applied_blocks)
    record = execute.apply(runtime, NAME, req, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", (record.get("reason"), record.get("steps"))
    assert "check_identity_passed" in steps(record)
    undo = execute.undo(runtime, record["change_id"], "restore the approved test object")
    assert undo["result"] == "confirmed", (undo.get("reason"), undo.get("steps"))
    assert sorted(target.snapshot().splitlines()) == baseline
    return record


# ---- the parser on the measured outputs of the device ----

def _scoped(name, extra=""):
    return junos.load("set version %s\n%s%s" % (FIRMWARE, fixture(name), extra), None)


def test_measured_pool_output_gives_pool_and_reservation():
    snapshot = _scoped("pool-present.txt")
    pools, hosts = snapshot.entries("dhcp-pool"), snapshot.entries("dhcp-reservation")
    assert {key: entry.attributes for key, entry in pools.items()} == {"NETOPS-G144-PROBE": {"network": NETWORK}}
    assert {key: entry.attributes for key, entry in hosts.items()} == {
        "NETOPS-G144-PROBE@NETOPS-G144-H1": {"hardware-address": "00:00:5e:00:53:44", "ip-address": "198.51.100.10"}}
    assert not any(entry.unsupported for entry in (*pools.values(), *hosts.values()))


def test_measured_relay_output_gives_server_and_group():
    snapshot = _scoped("relay-present.txt")
    assert {key: entry.attributes for key, entry in snapshot.entries("dhcp-relay-server").items()} == {
        "NETOPS-G144-SG": {"servers": "198.51.100.250"}}
    assert {key: entry.attributes for key, entry in snapshot.entries("dhcp-relay-group").items()} == {
        "NETOPS-G144-RG": {"active-server-group": "NETOPS-G144-SG", "interface": IRB}}


def test_server_addresses_are_a_sorted_set_like_the_device_shows_them():
    snapshot = _scoped("server-group-sorted.txt")
    entries = snapshot.entries("dhcp-relay-server")
    assert entries["NETOPS-G144-SG"].attributes == {"servers": "198.51.100.100 198.51.100.200"}
    request_state = junos_dhcp.canonical_changes("dhcp-relay-server", {"servers": "198.51.100.200 198.51.100.100"})
    assert request_state == {"servers": "198.51.100.100 198.51.100.200"}


def test_unknown_statements_are_outside_the_profile():
    rows = (POOL_ROWS + f"set access address-assignment pool {POOL} family inet range r1 low 198.51.100.20\n"
            + f"set forwarding-options dhcp-relay group {GROUP} overrides always-write-giaddr\n"
            + f"set forwarding-options dhcp-relay group {GROUP} interface {IRB} trust\n"
            + f"set forwarding-options dhcp-relay server-group {SERVERS} 2001:db8::1\n")
    snapshot = junos.load("set version %s\n%s" % (FIRMWARE, rows), None)
    assert snapshot.entries("dhcp-pool")[POOL].unsupported
    assert snapshot.entries("dhcp-relay-group")[GROUP].unsupported
    assert snapshot.entries("dhcp-relay-server")[SERVERS].unsupported


# ---- Admin: preview, confirmed apply, readback and undo ----

def test_pool_with_reservation_preview_confirm_readback_and_undo(tmp_path):
    target = DhcpLab()
    runtime = make_runtime(tmp_path, target)
    record = _run_and_undo(runtime, target, request("dhcp-pool", POOL, {"network": NETWORK}))
    assert any(command == f"set access address-assignment pool {POOL} family inet network {NETWORK}"
               for command in record["plan"]["commands"])
    assert target.reads, "the object is read back from the scoped configuration"
    target = DhcpLab(POOL_ROWS)
    runtime = make_runtime(tmp_path / "two", target)
    record = _run_and_undo(runtime, target, request(
        "dhcp-reservation", HOST, {"hardware-address": "00:00:5E:00:53:44", "ip-address": "198.51.100.10"}))
    # an upper case MAC is written and read back as Junos shows it
    assert record["plan"]["predicted"]["after"]["hardware-address"] == "00:00:5e:00:53:44"


def test_reservation_update_and_delete_restore_the_exact_object(tmp_path):
    target = DhcpLab(POOL_ROWS + HOST_ROWS)
    runtime = make_runtime(tmp_path, target)
    record = _run_and_undo(runtime, target, request("dhcp-reservation", HOST, {"ip-address": "198.51.100.11"}, op="update"))
    assert record["plan"]["predicted"]["before"]["ip-address"] == "198.51.100.10"
    assert "set access address-assignment pool %s family inet host NETOPS-G144-H1 ip-address 198.51.100.11" % POOL \
        in record["plan"]["commands"]
    target = DhcpLab(POOL_ROWS + HOST_ROWS)
    runtime = make_runtime(tmp_path / "delete", target)
    _run_and_undo(runtime, target, request("dhcp-reservation", HOST, {}, op="delete"))


def test_pool_network_update_and_empty_pool_delete(tmp_path):
    target = DhcpLab(POOL_ROWS)
    runtime = make_runtime(tmp_path, target)
    _run_and_undo(runtime, target, request("dhcp-pool", POOL, {"network": "198.51.100.0/25"}, op="update"))
    target = DhcpLab(POOL_ROWS)
    runtime = make_runtime(tmp_path / "delete", target)
    _run_and_undo(runtime, target, request("dhcp-pool", POOL, {}, op="delete"))


def test_relay_server_group_and_relay_group_lifecycle(tmp_path):
    target = DhcpLab()
    runtime = make_runtime(tmp_path, target)
    record = _run_and_undo(runtime, target, request("dhcp-relay-server", SERVERS, {"servers": "198.51.100.251 198.51.100.250"}))
    assert record["plan"]["predicted"]["after"] == {"servers": "198.51.100.250 198.51.100.251"}
    target = DhcpLab(SERVER_ROWS)
    runtime = make_runtime(tmp_path / "group", target)
    record = _run_and_undo(runtime, target, request("dhcp-relay-group", GROUP, {"active-server-group": SERVERS,
                                                                                "interface": IRB}, endpoint_impact=GROUP))
    assert f"set forwarding-options dhcp-relay group {GROUP} interface {IRB}" in record["plan"]["commands"]
    target = DhcpLab(SERVER_ROWS + GROUP_ROWS)
    runtime = make_runtime(tmp_path / "update", target)
    target.lines.append("set interfaces irb unit 3923 family inet address 203.0.113.1/24")
    record = _run_and_undo(runtime, target, request("dhcp-relay-group", GROUP, {"interface": "irb.3923"}, op="update", endpoint_impact=GROUP))
    assert f"delete forwarding-options dhcp-relay group {GROUP} interface {IRB}" in record["plan"]["commands"]
    target = DhcpLab(SERVER_ROWS + GROUP_ROWS)
    runtime = make_runtime(tmp_path / "delete", target)
    _run_and_undo(runtime, target, request("dhcp-relay-group", GROUP, {}, op="delete", endpoint_impact=GROUP))


def test_server_group_update_adds_before_it_removes(tmp_path):
    target = DhcpLab(SERVER_ROWS + GROUP_ROWS)
    runtime = make_runtime(tmp_path, target)
    record = _run_and_undo(runtime, target, request("dhcp-relay-server", SERVERS, {"servers": "198.51.100.251"}, op="update",
                                                    endpoint_impact=SERVERS))
    commands = [command for command in record["plan"]["commands"] if "server-group" in command]
    assert commands == [f"set forwarding-options dhcp-relay server-group {SERVERS} 198.51.100.251",
                        f"delete forwarding-options dhcp-relay server-group {SERVERS} 198.51.100.250"]


# ---- refusals before any write ----

def _refused(config, table, key, changes, op="create", code=None, **kwargs):
    target = DhcpLab(config)
    runtime = make_runtime(kwargs.pop("tmp_path"), target, **kwargs)
    result = execute.preview(runtime, NAME, request(table, key, changes, op=op))
    assert result["result"] == "rejected", result
    if code:
        assert result["reason_codes"] == [code], result
    assert all(not any(line.startswith("commit") for line in block) for block in target.applied_blocks)
    return result


@pytest.mark.parametrize("config,table,key,changes,op,code", [
    (POOL_ROWS, "dhcp-reservation", HOST, {"hardware-address": "00:00:5e:00:53:45", "ip-address": "203.0.113.10"},
     "create", "junos_dhcp_scope"),     # outside the pool network (device: "Address is outside the network")
    (POOL_ROWS, "dhcp-reservation", HOST, {"hardware-address": "00:00:5e:00:53:45", "ip-address": "198.51.100.0"},
     "create", "junos_dhcp_scope"),
    (POOL_ROWS + HOST_ROWS, "dhcp-reservation", f"{POOL}@NETOPS-G144-H2",
     {"hardware-address": "00:00:5e:00:53:44", "ip-address": "198.51.100.11"}, "create", "junos_dhcp_scope"),
    (POOL_ROWS + HOST_ROWS, "dhcp-reservation", f"{POOL}@NETOPS-G144-H2",
     {"hardware-address": "00:00:5e:00:53:46", "ip-address": "198.51.100.10"}, "create", "junos_dhcp_scope"),
    ("", "dhcp-reservation", HOST, {"hardware-address": "00:00:5e:00:53:44", "ip-address": "198.51.100.10"},
     "create", "junos_dhcp_dependency"),
    (POOL_ROWS + HOST_ROWS, "dhcp-pool", POOL, {}, "delete", "junos_dhcp_dependency"),
    (POOL_ROWS + HOST_ROWS, "dhcp-pool", POOL, {"network": "203.0.113.0/24"}, "update", "junos_dhcp_dependency"),
    (POOL_ROWS, "dhcp-pool", "NETOPS-G144-OTHER", {"network": "198.51.100.0/25"}, "create", "junos_dhcp_scope"),
    (POOL_ROWS, "dhcp-pool", "NETOPS-G144-OTHER", {"network": "203.0.113.5/24"}, "create", "junos_dhcp_scope"),
    ("", "dhcp-pool", POOL, {"network": "198.51.100.0/31"}, "create", "junos_dhcp_scope"),
    (SERVER_ROWS + GROUP_ROWS, "dhcp-relay-server", SERVERS, {}, "delete", "junos_dhcp_dependency"),
    ("", "dhcp-relay-group", GROUP, {"active-server-group": SERVERS, "interface": IRB}, "create",
     "junos_dhcp_dependency"),
    (SERVER_ROWS, "dhcp-relay-group", GROUP, {"active-server-group": SERVERS, "interface": "irb.3999"}, "create",
     "junos_dhcp_dependency"),
    (SERVER_ROWS + GROUP_ROWS, "dhcp-relay-group", "NETOPS-G144-RG2", {"active-server-group": SERVERS,
                                                                       "interface": IRB}, "create", "junos_dhcp_scope"),
    ("", "dhcp-relay-server", SERVERS, {"servers": "224.0.0.5"}, "create", "junos_dhcp_scope"),
    ("", "dhcp-relay-server", SERVERS, {"servers": "2001:db8::1"}, "create", None),
    (POOL_ROWS, "dhcp-reservation", HOST, {"hardware-address": "01:00:5e:90:10:01", "ip-address": "198.51.100.10"},
     "create", "junos_dhcp_scope"),
], ids=["outside-network", "network-address", "duplicate-mac", "duplicate-ip", "pool-missing", "pool-has-hosts",
        "network-excludes-host", "overlap", "host-bits", "prefix", "server-group-used", "server-group-missing",
        "irb-missing", "interface-in-use", "multicast-server", "ipv6-server", "multicast-mac"])
def test_unsafe_requests_are_refused_before_any_write(tmp_path, config, table, key, changes, op, code):
    _refused(config, table, key, changes, op, code, tmp_path=tmp_path)


def test_object_with_statements_outside_the_profile_is_left_untouched(tmp_path):
    config = POOL_ROWS + f"set access address-assignment pool {POOL} family inet range r1 low 198.51.100.20\n"
    result = _refused(config, "dhcp-pool", POOL, {"network": "198.51.100.0/25"}, "update", tmp_path=tmp_path)
    assert "outside the profile" in " ".join(result["reasons"])
    # reservations of such a pool stay editable: only its network statement is needed
    target = DhcpLab(config)
    runtime = make_runtime(tmp_path / "ok", target)
    assert execute.preview(runtime, NAME, request(
        "dhcp-reservation", HOST, {"hardware-address": "00:00:5e:00:53:44", "ip-address": "198.51.100.10"}))["result"] == "ready"


@pytest.mark.parametrize("extra", [
    f"deactivate access address-assignment pool {POOL}\n",
    "set groups g1 forwarding-options dhcp-relay server-group X 198.51.100.1\n",
    "deactivate forwarding-options dhcp-relay\n",
], ids=["inactive-pool", "group-config", "inactive-relay"])
def test_inactive_or_inherited_dhcp_configuration_is_refused(tmp_path, extra):
    _refused(POOL_ROWS + extra, "dhcp-reservation", HOST,
             {"hardware-address": "00:00:5e:00:53:44", "ip-address": "198.51.100.10"}, "create", "junos_dhcp_scope",
             tmp_path=tmp_path)


def test_protected_relay_interface_and_object_are_refused(tmp_path):
    _refused(SERVER_ROWS, "dhcp-relay-group", GROUP, {"active-server-group": SERVERS, "interface": IRB}, "create",
             "port_protected", tmp_path=tmp_path, protected={"interface": [IRB]})
    result = _refused("", "dhcp-pool", POOL, {"network": NETWORK}, "create", None,
                      tmp_path=tmp_path / "pool", protected={"dhcp-pool": [POOL]})
    assert "protected" in " ".join(result["reasons"])


# ---- the readback is exact or refuses ----

TRUNCATED = fixture("pool-present.txt")[:-20]
DENIED = "error: permission denied\n"
INACTIVE = POOL_ROWS + f"deactivate access address-assignment pool {POOL} family inet network\n"


@pytest.mark.parametrize("reply", [TRUNCATED, DENIED, INACTIVE], ids=["truncated", "denied", "inactive"])
@pytest.mark.parametrize("when", ["before", "after"])
def test_incomplete_or_unrecognised_readback_is_not_a_success(tmp_path, reply, when):
    target = DhcpLab()
    baseline = sorted(target.snapshot().splitlines())
    runtime = make_runtime(tmp_path, target)
    req = request("dhcp-pool", POOL, {"network": NETWORK})
    preview = execute.preview(runtime, NAME, req)
    assert preview["result"] == "ready"
    # reads: 1 object before the change, then the readback after the commit; the preview made none
    target.read_override_from = len(target.reads) + (1 if when == "before" else 2)
    target.read_override = reply
    try:
        record = execute.apply(runtime, NAME, req, expected_plan_sha256=preview["plan_sha256"])
    except Rejected as exc:
        assert when == "before" and exc.reason_codes == ["junos_dhcp_readback_unreadable"], exc.reasons
        assert all(not any(line.startswith("commit") for line in block) for block in target.applied_blocks)
        return
    # the change was committed, its readback is not exact: Admin returns the device to the configuration before it
    assert when == "after" and record["result"] == "reverted", (record["result"], record.get("reason"))
    assert sorted(target.snapshot().splitlines()) == baseline


def test_read_timeout_has_its_own_reason_code():
    class Slow(DhcpLab):
        def query(self, command):
            if command.startswith("show configuration access"):
                raise TimeoutError("read timed out")
            return super().query(command)

    with pytest.raises(Rejected) as exc:
        exec_junos.observe(Slow(), {"table": "dhcp-pool", "key": POOL, "firmware": FIRMWARE})
    assert exc.value.reason_codes == ["junos_dhcp_read_timeout"]


def test_observe_reads_the_scoped_object_and_reports_a_missing_one_as_none():
    target = DhcpLab()
    base = {"firmware": FIRMWARE}
    assert exec_junos.observe(target, {"table": "dhcp-pool", "key": POOL, **base}) is None
    target.read_override = fixture("absent.txt")
    assert exec_junos.observe(target, {"table": "dhcp-relay-group", "key": GROUP, **base}) is None
    target.read_override = fixture("pool-present.txt")
    assert exec_junos.observe(target, {"table": "dhcp-pool", "key": "NETOPS-G144-PROBE", **base}) == {"network": NETWORK}
    assert exec_junos.observe(target, {"table": "dhcp-reservation", "key": "NETOPS-G144-PROBE@NETOPS-G144-H1", **base}) \
        == {"hardware-address": "00:00:5e:00:53:44", "ip-address": "198.51.100.10"}
    assert exec_junos.observe(target, {"table": "dhcp-reservation", "key": "NETOPS-G144-PROBE@MISSING", **base}) is None
    target.read_override = fixture("relay-present.txt")
    assert exec_junos.observe(target, {"table": "dhcp-relay-server", "key": "NETOPS-G144-SG", **base}) \
        == {"servers": "198.51.100.250"}


@pytest.mark.parametrize('table,key,changes,config', [
    ('dhcp-pool', POOL, {'network': NETWORK}, ''),
    ('dhcp-reservation', HOST, {'hardware-address': '00:00:5e:00:53:44', 'ip-address': '198.51.100.10'}, POOL_ROWS),
    ('dhcp-relay-server', SERVERS, {'servers': '198.51.100.250'}, ''),
    ('dhcp-relay-group', GROUP, {'active-server-group': SERVERS, 'interface': IRB}, SERVER_ROWS),
])
def test_g144_apply_requires_the_preview_hash(tmp_path, table, key, changes, config):
    target = DhcpLab(config)
    runtime = make_runtime(tmp_path, target)
    req = request(table, key, changes, **({'endpoint_impact': key} if table == 'dhcp-relay-group' else {}))
    baseline = target.snapshot()
    with pytest.raises(Rejected) as exc:
        execute.apply(runtime, NAME, req)
    assert exc.value.reason_codes == ['plan_changed']
    assert target.snapshot() == baseline and not runtime.store.records()


@pytest.mark.parametrize('table,key,op,changes,config', [
    ('dhcp-pool', POOL, 'update', {'network': '198.51.100.0/25'}, fixture('pool-present.txt').replace('NETOPS-G144-PROBE', POOL)),
    ('dhcp-reservation', HOST, 'update', {'ip-address': '198.51.100.11'}, fixture('pool-present.txt').replace('NETOPS-G144-PROBE', POOL)),
    ('dhcp-relay-server', SERVERS, 'update', {'servers': '198.51.100.251'}, fixture('relay-present.txt')),
    ('dhcp-relay-group', GROUP, 'delete', {}, fixture('relay-present.txt')),
])
def test_g144_active_dhcp_changes_require_impact(tmp_path, table, key, op, changes, config):
    if table in ('dhcp-pool', 'dhcp-reservation'):
        config += f'set system services dhcp-local-server group LOCAL interface {IRB}\n'
    target = DhcpLab(config)
    runtime = make_runtime(tmp_path, target)
    refused = execute.preview(runtime, NAME, request(table, key, changes, op=op))
    assert refused.get('reason_codes') == ['endpoint_impact_required'], refused
    _run_and_undo(runtime, target, request(table, key, changes, op=op, endpoint_impact=key))


@pytest.mark.parametrize('op,changes', [('delete', {}), ('update', {'interface': 'irb.3923'})])
def test_g144_cannot_remove_a_relay_from_a_protected_irb(tmp_path, op, changes):
    target = DhcpLab(fixture('relay-present.txt'))
    target.lines.append('set interfaces irb unit 3923 family inet address 203.0.113.1/24')
    runtime = make_runtime(tmp_path, target, protected={'interface': [IRB]})
    refused = execute.preview(runtime, NAME, request('dhcp-relay-group', GROUP, changes, op=op, endpoint_impact=GROUP))
    assert refused.get('reason_codes') == ['port_protected'], refused
    assert not runtime.store.records()
