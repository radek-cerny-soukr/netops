"""1.0.13: every apply of a shipped FortiOS registry table needs the approved preview's plan_sha256.

The registry of the FortiOS tables added in 1.0.13 (fortios_tables) gives each table the reason code of a missing hash
(TableHooks.preview_code); the common check of every apply (execute._plan_required) keeps that code, while the other
FortiOS tables keep their own code or plan_changed. The cases run through the shipped registry and the shipped
profiles: every table the registry holds with every operation its profile allows, refused before the request journal,
the audit and any device session.
"""
from __future__ import annotations

from dataclasses import replace

import pytest
from fake_fortios_a1 import DNS, RANGE, SERVER, SYSLOG, VLAN, FakeFortiOSA1
from fake_fortios_a2 import GROUP, ONETIME, RECURRING
from fake_fortios_a3 import ADDRESS6, GROUP6, ROUTE6, FakeFortiOSA3
from test_fortios_a3_ipv6 import runtime_for as a3_runtime_for  # noqa: F401 (fixture of the A3 simulator)
from test_fortios_tables_registry import ask, audit_events, runtime_for, ssh_sessions  # noqa: F401 (fixture)

from netops_admin import execute, fortios_tables, profiles
from netops_admin.errors import Rejected

SERVICE, OBJECT = "fortios_service_preview_required", "fortios_object_preview_required"
POLICY = "firewall policy"
# (table, op) -> (key, changes, endpoint_impact, reason code of a missing hash)
CASES = {
    (SERVER, "create"): ("9", {"interface": VLAN, "status": "disable", "netmask": "255.255.255.0",
                               "default-gateway": "192.0.2.1"}, None, SERVICE),
    (SERVER, "update"): ("7", {"lease-time": 3600}, None, SERVICE),
    (SERVER, "delete"): ("7", {}, None, SERVICE),
    (RANGE, "create"): ("7:2", {"start-ip": "192.0.2.160", "end-ip": "192.0.2.170"}, None, SERVICE),
    (RANGE, "update"): ("7:1", {"end-ip": "192.0.2.150"}, "7:1", SERVICE),
    (RANGE, "delete"): ("7:1", {}, None, SERVICE),
    (DNS, "update"): ("-", {"secondary": "198.51.100.55"}, "-", SERVICE),
    (SYSLOG, "update"): ("-", {"facility": "local5"}, None, SERVICE),
    (GROUP, "create"): ("hash-web", {"member": ["HTTP", "HTTPS"], "comment": "hash check"}, None, OBJECT),
    (GROUP, "update"): ("hash-web", {"comment": "changed"}, None, OBJECT),
    (GROUP, "delete"): ("hash-web", {}, None, OBJECT),
    (RECURRING, "create"): ("hash-office", {"day": ["monday"], "start": "08:00", "end": "17:00"}, None, OBJECT),
    (RECURRING, "update"): ("hash-office", {"end": "18:00"}, None, OBJECT),
    (RECURRING, "delete"): ("hash-office", {}, None, OBJECT),
    (ONETIME, "create"): ("hash-window", {"start": "10:00 2026/12/01", "end": "11:00 2026/12/01"}, None, OBJECT),
    (ONETIME, "update"): ("hash-window", {"expiration-days": "0"}, None, OBJECT),
    (ONETIME, "delete"): ("hash-window", {}, None, OBJECT),
    (ADDRESS6, "create"): ("hash-net6", {"ip6": "2001:db8:a3::/64", "comment": "hash check"}, None, OBJECT),
    (ADDRESS6, "update"): ("hash-net6", {"comment": "changed"}, None, OBJECT),
    (ADDRESS6, "delete"): ("hash-net6", {}, None, OBJECT),
    (GROUP6, "create"): ("hash-grp6", {"member": ["hash-net6"]}, None, OBJECT),
    (GROUP6, "update"): ("hash-grp6", {"comment": "changed"}, None, OBJECT),
    (GROUP6, "delete"): ("hash-grp6", {}, None, OBJECT),
    (ROUTE6, "create"): ("63", {"dst": "2001:db8:a3::/48", "blackhole": "enable", "status": "disable"}, None, OBJECT),
    (ROUTE6, "update"): ("63", {"comment": "changed"}, None, OBJECT),
    (ROUTE6, "delete"): ("63", {}, None, OBJECT),
}


@pytest.fixture
def shipped():
    """The shipped registry (fortios_tab_* modules) and the shipped profiles."""
    fortios_tables.reset()
    yield profiles.load_profiles()
    fortios_tables.reset()


def wired(runtime_for, tmp_path):
    runtime = runtime_for(tmp_path, FakeFortiOSA1(syslog=True))
    current = runtime.config.devices["lab"]
    runtime.config = replace(runtime.config, devices={"lab": replace(current, opt_in=tuple(current.opt_in) + (POLICY,))})
    return runtime


def refused_without_a_session(runtime, tmp_path, request_):
    before = runtime.lab.device.snapshot()
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", request_)
    assert runtime.lab.device.applied_blocks == [] and runtime.lab.device.snapshot() == before
    assert ssh_sessions(runtime) == [] and audit_events(tmp_path) == []
    return caught.value


def test_the_cases_cover_every_operation_of_every_shipped_registry_table(shipped):
    shipped_operations = {(table, op) for table in fortios_tables.all_tables()
                          for op in shipped[("fortios", table)].ops}
    assert set(CASES) == shipped_operations
    for table in fortios_tables.all_tables():
        assert shipped[("fortios", table)].measured, table  # a shipped table is enabled, the check is the product path


@pytest.mark.parametrize(("table", "op"), sorted(CASES))
def test_apply_without_the_hash_is_refused_with_the_code_of_the_registration(shipped, runtime_for, tmp_path, table,
                                                                              op):
    key, changes, impact, code = CASES[(table, op)]
    assert fortios_tables.hooks(table).preview_code == code
    runtime = wired(runtime_for, tmp_path)
    request_ = ask(table, key, op, changes, **({"endpoint_impact": impact} if impact else {}))
    refusal = refused_without_a_session(runtime, tmp_path, request_)
    assert refusal.reason_codes == [code], refusal.reasons
    assert "requires the approved preview's plan_sha256" in " ".join(refusal.reasons)


@pytest.mark.parametrize(("table", "code"), [(GROUP, SERVICE), (DNS, OBJECT)])
def test_the_code_of_a_missing_hash_follows_the_registration(shipped, runtime_for, tmp_path, monkeypatch, table, code):
    # the common check reads preview_code from the registry entry, it holds no list of tables of its own
    registry = fortios_tables.registry()
    monkeypatch.setitem(registry, table, replace(registry[table], preview_code=code))
    key, changes, impact, _ = CASES[(table, "update")]
    runtime = wired(runtime_for, tmp_path)
    request_ = ask(table, key, "update", changes, **({"endpoint_impact": impact} if impact else {}))
    assert refused_without_a_session(runtime, tmp_path, request_).reason_codes == [code]


@pytest.mark.parametrize(("table", "key", "changes", "code"), [
    ("firewall address", "hash-host", {"subnet": "192.0.2.30/32"}, "plan_changed"),
    (POLICY, "4242", {"name": "hash-policy"}, "fortios_policy_preview_required"),
])
def test_a_fortios_table_outside_the_registry_keeps_its_code(shipped, runtime_for, tmp_path, table, key, changes,
                                                             code):
    assert fortios_tables.hooks(table) is None
    runtime = wired(runtime_for, tmp_path)
    refusal = refused_without_a_session(runtime, tmp_path, ask(table, key, "update", changes))
    assert refusal.reason_codes == [code], refusal.reasons


def test_apply_with_the_hash_of_the_preview_goes_through_for_the_ipv6_tables(a3_runtime_for, tmp_path):
    # the same registry path with the approved preview's plan_sha256 (the A3 simulator, the shipped profiles)
    fortios_tables.reset()
    try:
        runtime = a3_runtime_for(tmp_path, FakeFortiOSA3())
        for table, op in sorted(key for key in CASES if key[0] in (ADDRESS6, GROUP6, ROUTE6) and key[1] == "create"):
            key, changes, impact, code = CASES[(table, op)]
            request_ = ask(table, key, op, changes, **({"endpoint_impact": impact} if impact else {}))
            with pytest.raises(Rejected) as caught:
                execute.apply(runtime, "lab", request_)
            assert caught.value.reason_codes == [code]
            preview = execute.preview(runtime, "lab", request_)
            assert preview["result"] == "ready", preview
            record = execute.apply(runtime, "lab", request_, expected_plan_sha256=preview["plan_sha256"])
            assert record["result"] == "confirmed", record
            assert key in runtime.lab.device.tables[table].objects
    finally:
        fortios_tables.reset()
