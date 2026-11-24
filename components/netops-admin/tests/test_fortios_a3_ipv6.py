"""1.0.13 A3: firewall address6, firewall addrgrp6 and router static6 through the real Admin path.

The shipped profiles and the shipped registration (fortios_tab_ipv6.TABLES) drive execute (preview, apply, undo,
recover) -> exec_fortios -> the production access.DeviceAccess (held OpenSSH sessions, the Fortinet dialog) -> the
OpenSSH test client (fortinet_ssh_fixture) -> the simulated device (fake_fortios_a3, the layout the check account read
on FortiGate-60F 7.6.8, fixtures/fortios_a3). The parser, the Snapshot, the planning, rest_digest, rest_inverse, the
safeguard rendering, the journal and the audit are real; only the device and the clock are simulated.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from fake_fortios_a3 import ADDRESS6, GROUP6, ROUTE6, WAN1_GATEWAY, FakeFortiOSA3, FakeFortiOSA3Webhook
from fortinet_ssh_fixture import BLOB, PUBLIC_KEY, Counter, install_clients
from test_execute import make_runtime
from test_fortios_tables_registry import Wired, approved, ask, undone

from netops_admin import access, engine, execute, fortios, fortios_tab_ipv6, fortios_tables, profiles
from netops_admin.errors import Rejected
from netops_core import hostkey

FIXTURES = Path(__file__).parent / "fixtures" / "fortios_a3"
PREFIX = {"ip6": "2001:db8:a3::/64", "comment": "netops A3 test"}
BLACKHOLE = {"dst": "2001:db8:a3::/48", "blackhole": "enable", "status": "disable", "comment": "netops A3 test"}


@pytest.fixture(autouse=True)
def shipped_registry():
    fortios_tables.reset()
    yield
    fortios_tables.reset()


@pytest.fixture
def runtime_for(monkeypatch, watch_export_status, tmp_path_factory):
    """runtime_for(tmp_path, device): the Admin runtime of the A1-R registry tests (production access.DeviceAccess
    over the OpenSSH test client of fortinet_ssh_fixture, router static6 opted in, wan1 protected, the device and the
    check address as IPv4 literals) with room for the changes of one scenario."""
    def wire(tmp_path, device):
        tmp_path.mkdir(parents=True, exist_ok=True)
        device.uuids = Counter(next(device.uuids))
        if hasattr(device, "keys"):
            device.keys = Counter(next(device.keys))
        runtime = make_runtime(tmp_path, device, opt_in=(ROUTE6,), protected={"system interface": ["wan1"]})
        key = {"host_key": PUBLIC_KEY} if hasattr(runtime.config.devices["lab"], "host_key") else {}
        configured = replace(runtime.config.devices["lab"], host_key_fingerprint=hostkey.fingerprint_of(BLOB),
                             check_address="198.51.100.15", **key)
        export = tmp_path / "export.json"
        export.write_text(json.dumps({"updated_at": time.time(), "pending": 0}))
        watch_export_status(export)
        limits = dict(runtime.config.limits, changes_per_device_per_hour=64, changes_per_day=128,
                      rejections_per_hour=128)
        runtime.config = replace(runtime.config, devices={"lab": configured}, export_status_file=str(export),
                                 limits=limits)
        runtime.notifier = lambda _: "sent"
        from enrollment_helpers import certify
        certify(runtime, device, "lab")
        runtime.access_factory = access.DeviceAccess
        vault = {alias: SimpleNamespace(login=credential.login, kind="password", use=lambda: "fixture-password")
                 for alias, credential in (("rw", device.credential), ("ro", device.check_credential))}
        monkeypatch.setattr(access.vault, "load", lambda *_args, **_kw: SimpleNamespace(credential=vault.__getitem__))
        lab_ = Wired(tmp_path)
        lab_.store(device)
        (tmp_path / "platform").write_text("fortios")
        runtime.sleep = lab_.advance
        runtime.lab = lab_
        install_clients(tmp_path, monkeypatch, tmp_path_factory.getbasetemp() / "fortinet-ssh-pycache")
        return runtime

    return wire


def lab(webhook=False):
    return FakeFortiOSA3Webhook() if webhook else FakeFortiOSA3()


def show(device, table, key=None):
    return "\n".join(device.table_lines(table, key)) + "\n"


def recreated(runtime, record, before):
    """Undo of a delete: the object comes back with its state; FortiOS gives it a new uuid (inverse_identity_changes)."""
    preview = execute.preview_undo(runtime, record["change_id"], "Restore the A3 baseline", issue=True)
    assert preview["result"] == "ready", preview
    restored = execute.undo(runtime, record["change_id"], "Restore the A3 baseline", preview["plan_sha256"])
    assert restored["result"] == "confirmed", restored
    current = runtime.lab.device
    assert engine.verify(record["plan"], current.snapshot().encode(), expect="before")["result"] == "match"
    def without_uuid(text):
        return re.sub(r"set uuid [0-9a-f-]+", "set uuid -", text)
    assert without_uuid(current.snapshot()) == without_uuid(before) and current.snapshot() != before
    assert not current.stitches and not current.actions and not current.triggers
    return restored


def written(runtime):
    return len(runtime.lab.device.applied_blocks)


def refused(runtime, request_, code=None):
    before = written(runtime)
    preview = execute.preview(runtime, "lab", request_)
    assert preview["result"] == "rejected", preview
    if code is not None:
        assert code in preview["reason_codes"], preview
    assert written(runtime) == before
    return preview


# ------------------------------------------------------------------------------------------- registration and profiles

def test_the_a3_tables_are_registered_with_their_profiles():
    assert set(fortios_tab_ipv6.TABLES) == {ADDRESS6, GROUP6, ROUTE6}
    assert {ADDRESS6, GROUP6, ROUTE6} <= set(fortios_tables.all_tables())
    assert {ADDRESS6, GROUP6} <= set(fortios_tables.impact_tables()) and ROUTE6 not in fortios_tables.impact_tables()
    loaded = profiles.load_profiles()
    for table in (ADDRESS6, GROUP6, ROUTE6):
        profile = loaded[("fortios", table)]
        assert profile.versions == ("7.6.8 build3744",) and profile.exact_versions and profile.provisional
        assert not profile.isolated_update
        assert fortios_tables.hooks(table).preview_code == "fortios_object_preview_required"
        # no operation is verified with the webhook safeguard: every change is refused on 8.0.1+
        assert fortios.webhook_refusal(profile, "8.0.2 build0251", "create") is not None
        assert fortios.webhook_refusal(profile, "7.6.8 build3744", "create") is None
    assert fortios.rest_path(ADDRESS6) == "firewall/address6" and fortios.rest_key(GROUP6) == "name"
    assert loaded[("fortios", ADDRESS6)].protected_keys == ("all", "none")


def test_the_simulator_shows_the_tables_as_the_lab_device():
    device = lab()
    for name, table in (("show-firewall-address6.txt", ADDRESS6), ("show-router-static6.txt", ROUTE6),
                        ("show-firewall-addrgrp6.txt", GROUP6)):
        captured = fortios.parse_snapshot((FIXTURES / name).read_text())
        simulated = fortios.parse_snapshot(show(device, table))
        assert sorted(captured.section(table).entries) == sorted(simulated.section(table).entries), name
        for key, entry in captured.section(table).entries.items():
            assert set(entry.attrs) == set(simulated.section(table).entries[key].attrs), (name, key)


def test_the_simulator_shows_created_objects_as_the_lab_device(runtime_for, tmp_path):
    """The objects the live run created through Admin on the FortiGate-60F 7.6.8 (show of the check account, uuid
    values replaced in the fixtures) and the same creates on the simulator print the same lines."""
    runtime = runtime_for(tmp_path, lab())
    approved(runtime, ask(ADDRESS6, "netops-a3-net", "create", PREFIX))
    approved(runtime, ask(ADDRESS6, "netops-a3-net2", "create",
                          {"type": "iprange", "start-ip": "2001:db8:a3::10", "end-ip": "2001:db8:a3::20"}))
    approved(runtime, ask(GROUP6, "netops-a3-grp", "create", {"member": ["netops-a3-net"]}))
    device = runtime.lab.device
    for table, key, name in ((ADDRESS6, "netops-a3-net", "show-firewall-address6-created.txt"),
                             (ADDRESS6, "netops-a3-net2", "show-firewall-address6-iprange.txt"),
                             (GROUP6, "netops-a3-grp", "show-firewall-addrgrp6-created.txt")):
        def without_uuid(text):
            return re.sub(r"set uuid [0-9a-f-]+", "set uuid -", text)
        assert without_uuid(show(device, table, key)) == without_uuid((FIXTURES / name).read_text()), name
    # the full configuration shows exclude disable (fixed in the profile) and no other managed attribute
    full = fortios.parse_snapshot((FIXTURES / "show-full-configuration-firewall-addrgrp6-created.txt").read_text())
    entry = full.section(GROUP6).entries["netops-a3-grp"]
    assert entry.value("exclude") == profiles.load_profiles()[("fortios", GROUP6)].fixed["exclude"]


# ------------------------------------------------------------------------------------------- the live scenario

def test_address6_group6_and_blackhole_route_are_applied_read_back_and_undone(runtime_for, tmp_path):
    runtime = runtime_for(tmp_path, lab())
    address, before_address = approved(runtime, ask(ADDRESS6, "netops-a3-net", "create", PREFIX))
    assert runtime.lab.device.tables[ADDRESS6].objects["netops-a3-net"]["attrs"]["ip6"] == "2001:db8:a3::/64"
    group, before_group = approved(runtime, ask(GROUP6, "netops-a3-grp", "create", {"member": ["netops-a3-net"]}))
    route, before_route = approved(runtime, ask(ROUTE6, "63", "create", BLACKHOLE))
    shown = show(runtime.lab.device, ROUTE6, "63")
    assert "set device" not in shown and "set gateway" not in shown and "set blackhole enable" in shown
    # the shape the check account read on the FortiGate-60F 7.6.8 after the same create (set vrf 0 included)
    assert shown == (FIXTURES / "show-router-static6-blackhole.txt").read_text()
    updated, before_update = approved(runtime, ask(ADDRESS6, "netops-a3-net", "update", {"comment": "netops A3 two"}))
    undone(runtime, updated, before_update)
    undone(runtime, route, before_route)
    undone(runtime, group, before_group)
    undone(runtime, address, before_address)
    assert "netops-a3-net" not in runtime.lab.device.tables[ADDRESS6].objects


def test_address6_range_and_fqdn_are_created_and_undone(runtime_for, tmp_path):
    runtime = runtime_for(tmp_path, lab())
    rng, before = approved(runtime, ask(ADDRESS6, "netops-a3-range", "create",
                                        {"type": "iprange", "start-ip": "2001:db8:a3::10", "end-ip": "2001:db8:a3::20"}))
    assert rng["plan"]["commands"][2].strip() == "set type iprange"
    undone(runtime, rng, before)
    fqdn, before = approved(runtime, ask(ADDRESS6, "netops-a3-fqdn", "create",
                                         {"type": "fqdn", "fqdn": "a3.example.invalid"}))
    undone(runtime, fqdn, before)


def test_group_update_and_delete_with_undo(runtime_for, tmp_path):
    runtime = runtime_for(tmp_path, lab())
    approved(runtime, ask(ADDRESS6, "netops-a3-a", "create", {"ip6": "2001:db8:a3:a::/64"}))
    approved(runtime, ask(ADDRESS6, "netops-a3-b", "create", {"ip6": "2001:db8:a3:b::/64"}))
    approved(runtime, ask(GROUP6, "netops-a3-grp", "create", {"member": ["netops-a3-a"]}))
    grown, before = approved(runtime, ask(GROUP6, "netops-a3-grp", "update", {"member": ["netops-a3-a", "netops-a3-b"]}))
    undone(runtime, grown, before)
    deleted, before = approved(runtime, ask(GROUP6, "netops-a3-grp", "delete", {}))
    assert "netops-a3-grp" not in runtime.lab.device.tables[GROUP6].objects
    recreated(runtime, deleted, before)
    assert runtime.lab.device.tables[GROUP6].objects["netops-a3-grp"]["attrs"]["member"] == "netops-a3-a"


def test_route_update_and_delete_with_undo(runtime_for, tmp_path):
    runtime = runtime_for(tmp_path, lab())
    approved(runtime, ask(ROUTE6, "63", "create", BLACKHOLE))
    changed, before = approved(runtime, ask(ROUTE6, "63", "update", {"distance": 20, "comment": "netops A3 two"}))
    undone(runtime, changed, before)
    deleted, before = approved(runtime, ask(ROUTE6, "63", "delete", {}))
    undone(runtime, deleted, before)
    assert "63" in runtime.lab.device.tables[ROUTE6].objects


# ------------------------------------------------------------------------------------------- apply needs the preview

@pytest.mark.parametrize(("table", "key", "changes"), [
    (ADDRESS6, "netops-a3-net", PREFIX),
    (GROUP6, "netops-a3-grp", {"member": ["all"]}),
    (ROUTE6, "63", BLACKHOLE),
])
def test_apply_without_the_approved_preview_is_refused(runtime_for, tmp_path, table, key, changes):
    runtime = runtime_for(tmp_path, lab())
    before = runtime.lab.device.snapshot()
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", ask(table, key, "create", changes))
    assert caught.value.reason_codes == ["fortios_object_preview_required"]
    assert written(runtime) == 0 and runtime.lab.device.snapshot() == before


# ------------------------------------------------------------------------------------------- policy use and references

def group_in_policy(device, status="enable"):
    device.tables[ADDRESS6].objects["netops-a3-a"] = {"attrs": {"uuid": device._uuid(), "ip6": "2001:db8:a3:a::/64"},
                                                     "children": {}}
    device.tables[ADDRESS6].objects["netops-a3-b"] = {"attrs": {"uuid": device._uuid(), "ip6": "2001:db8:a3:b::/64"},
                                                     "children": {}}
    device.tables[GROUP6].objects["netops-a3-grp"] = {"attrs": {"uuid": device._uuid(), "member": '"netops-a3-a"'},
                                                      "children": {}}
    device.policies["63"] = {"name": "netops-a3", "srcintf": "port1", "dstintf": "port2", "srcaddr6": "netops-a3-grp",
                             "dstaddr6": "all", "schedule": "always", "service": "ALL"}
    if status != "enable":
        device.policies["63"]["status"] = status
    return device


def test_an_object_of_an_active_policy_changes_only_with_endpoint_impact(runtime_for, tmp_path):
    runtime = runtime_for(tmp_path, group_in_policy(lab()))
    for table, key, changes in ((GROUP6, "netops-a3-grp", {"member": ["netops-a3-a", "netops-a3-b"]}),
                                (ADDRESS6, "netops-a3-a", {"ip6": "2001:db8:a3:c::/64"})):
        refused(runtime, ask(table, key, "update", changes), "fortios_policy_impact_required")
        record, before = approved(runtime, ask(table, key, "update", changes, endpoint_impact=key))
        assert record["plan"]["endpoint_impact"] == key
        undone(runtime, record, before)
    # a comment changes no traffic
    approved(runtime, ask(GROUP6, "netops-a3-grp", "update", {"comment": "netops A3"}))


def test_an_object_of_a_disabled_policy_changes_without_endpoint_impact(runtime_for, tmp_path):
    runtime = runtime_for(tmp_path, group_in_policy(lab(), status="disable"))
    record, before = approved(runtime, ask(ADDRESS6, "netops-a3-a", "update", {"ip6": "2001:db8:a3:c::/64"}))
    undone(runtime, record, before)


def test_an_object_of_a_protected_policy_is_never_changed(runtime_for, tmp_path):
    runtime = runtime_for(tmp_path, group_in_policy(lab()))
    device = replace(runtime.config.devices["lab"], protected={"system interface": ["wan1"], "firewall policy": ["63"]})
    runtime.config = replace(runtime.config, devices={"lab": device})
    preview = refused(runtime, ask(ADDRESS6, "netops-a3-a", "update", {"ip6": "2001:db8:a3:c::/64"},
                                   endpoint_impact="netops-a3-a"))
    assert "protected firewall policies 63" in " ".join(preview["reasons"])


def test_a_referenced_object_is_not_deleted(runtime_for, tmp_path):
    runtime = runtime_for(tmp_path, group_in_policy(lab(), status="disable"))
    refused(runtime, ask(ADDRESS6, "netops-a3-a", "delete", {}), "fortios_object_referenced")
    refused(runtime, ask(GROUP6, "netops-a3-grp", "delete", {}), "fortios_object_referenced")


@pytest.mark.parametrize(("table", "key", "changes", "reason"), [
    (ADDRESS6, "netops-a3-x", {"type": "iprange", "start-ip": "2001:db8::20", "end-ip": "2001:db8::10"},
     "start-ip must be less than or equal to end-ip"),
    (ADDRESS6, "netops-a3-x", {"type": "iprange", "start-ip": "2001:db8::10"}, "needs end-ip"),
    (ADDRESS6, "netops-a3-x", {"type": "fqdn", "fqdn": "a3.example.invalid", "ip6": "2001:db8::/64"},
     "does not take ip6"),
    (ADDRESS6, "netops-a3-x", {"comment": "no prefix"}, "needs ip6"),
    (GROUP6, "netops-a3-x", {"member": ["missing-object"]}, "names a member"),
    (GROUP6, "netops-a3-x", {"member": ["netops-a3-x"]}, "include itself"),
])
def test_invalid_objects_are_refused_before_any_write(runtime_for, tmp_path, table, key, changes, reason):
    runtime = runtime_for(tmp_path, lab())
    preview = refused(runtime, ask(table, key, "create", changes))
    assert reason in " ".join(preview["reasons"]), preview


def test_a_group_cycle_through_another_group_is_refused(runtime_for, tmp_path):
    runtime = runtime_for(tmp_path, group_in_policy(lab(), status="disable"))
    approved(runtime, ask(GROUP6, "netops-a3-outer", "create", {"member": ["netops-a3-grp"]}))
    preview = refused(runtime, ask(GROUP6, "netops-a3-grp", "update", {"member": ["netops-a3-outer"]}))
    assert "include itself" in " ".join(preview["reasons"])


def test_the_protected_keys_of_address6_are_refused(runtime_for, tmp_path):
    runtime = runtime_for(tmp_path, lab())
    refused(runtime, ask(ADDRESS6, "none", "update", {"comment": "x"}))
    refused(runtime, ask(ADDRESS6, "all", "delete", {}))


# ------------------------------------------------------------------------------------------- router static6 (design A 3)

@pytest.mark.parametrize(("key", "changes", "impact"), [
    ("64", {**BLACKHOLE, "dst": "::/0"}, False),
    ("64", {**BLACKHOLE, "dst": "::/0"}, True),
    ("64", {"dst": "2001:db8:a3::/48", "device": "wan1", "gateway": WAN1_GATEWAY}, False),
    ("64", {"dst": "2001:db8:1::/48", "device": "port1"}, False),
    ("64", {**BLACKHOLE, "device": "port1"}, False),
    ("64", {"dst": "2001:db8:a3::/48", "status": "disable"}, False),
    ("64", {"dst": "2001:db8:a3::/48", "device": "missing0"}, False),
])
def test_route6_rules_refuse_before_any_write(runtime_for, tmp_path, key, changes, impact):
    runtime = runtime_for(tmp_path, lab())
    refused(runtime, ask(ROUTE6, key, "create", changes, **({"endpoint_impact": key} if impact else {})),
            None if impact else "fortios_route6_protected")


def test_the_default_route_through_the_management_path_stays_protected_itself(runtime_for, tmp_path):
    runtime = runtime_for(tmp_path, lab())
    refused(runtime, ask(ROUTE6, "1", "update", {"comment": "x"}), "fortios_route6_protected")
    refused(runtime, ask(ROUTE6, "1", "delete", {}))  # also: show omits dst ::/0, the inverse could not recreate it
    # and it does not refuse the other routes, which all overlap ::/0 (the rule of router static)
    record, before = approved(runtime, ask(ROUTE6, "63", "create", {"dst": "2001:db8:a3::/48", "device": "port1",
                                                                   "status": "disable"}))
    undone(runtime, record, before)


def test_a_route_through_a_protected_interface_other_than_default_refuses_overlaps(runtime_for, tmp_path):
    device = lab()
    device.tables[ROUTE6].objects["2"] = {"attrs": {"dst": "2001:db8:a3::/56", "device": "wan1",
                                                    "gateway": WAN1_GATEWAY}, "children": {}}
    runtime = runtime_for(tmp_path, device)
    refused(runtime, ask(ROUTE6, "63", "create", BLACKHOLE), "fortios_route6_protected")


def test_a_route_with_a_dns_or_ipv6_management_address_is_refused_in_preview_apply_and_undo(runtime_for, tmp_path):
    runtime = runtime_for(tmp_path, lab())
    record, _before = approved(runtime, ask(ROUTE6, "63", "create", BLACKHOLE))
    configured = runtime.config.devices["lab"]
    for check_address in ("fw-check.example.invalid", "2001:db8::15"):
        runtime.config = replace(runtime.config, devices={"lab": replace(configured, check_address=check_address)})
        refused(runtime, ask(ROUTE6, "64", "create", BLACKHOLE), "fortios_route6_protected")
        preview = execute.preview_undo(runtime, record["change_id"], "Restore the A3 baseline", issue=True)
        assert preview["result"] == "rejected" and preview["reason_codes"] == ["fortios_route6_protected"], preview
    runtime.config = replace(runtime.config, devices={"lab": configured})


# ------------------------------------------------------------------------------------------- failures and safeguard

def test_a_line_the_device_refuses_is_change_failed_and_returned(runtime_for, tmp_path):
    runtime = runtime_for(tmp_path, lab())
    request_ = ask(ADDRESS6, "netops-a3-net", "create", PREFIX)
    preview = execute.preview(runtime, "lab", request_)
    # the device refuses the set of the prefix inside edit (Command fail -651); Admin aborts the edit
    (tmp_path / "refuse-line").write_text("set ip6 2001:db8:a3::/64")
    record = execute.apply(runtime, "lab", request_, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "reverted", record["steps"]
    assert "change_failed" in [step["step"] for step in record["steps"]]
    assert "netops-a3-net" not in runtime.lab.device.tables[ADDRESS6].objects
    assert not runtime.lab.device.stitches


def test_a_different_readback_is_a_mismatch_and_the_safeguard_returns_the_change(runtime_for, tmp_path):
    device = lab()
    device.check_after_write = {'show firewall address6 "netops-a3-net"':
                                'config firewall address6\n    edit "netops-a3-net"\n        set ip6 2001:db8:a4::/64\n'
                                '    next\nend\n'}
    runtime = runtime_for(tmp_path, device)
    request_ = ask(ADDRESS6, "netops-a3-net", "create", PREFIX)
    preview = execute.preview(runtime, "lab", request_)
    record = execute.apply(runtime, "lab", request_, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "reverted", record
    assert "netops-a3-net" not in runtime.lab.device.tables[ADDRESS6].objects


def test_an_incomplete_readback_is_not_confirmed(runtime_for, tmp_path):
    device = lab()
    device.check_after_write = {'show router static6 "63"': "config router static6\n    edit 63\n        set dst 2001:"}
    runtime = runtime_for(tmp_path, device)
    request_ = ask(ROUTE6, "63", "create", BLACKHOLE)
    preview = execute.preview(runtime, "lab", request_)
    record = execute.apply(runtime, "lab", request_, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "reverted", record
    assert "63" not in runtime.lab.device.tables[ROUTE6].objects


def test_a_blackhole_route_in_another_vrf_is_a_mismatch(runtime_for, tmp_path):
    # FortiOS 7.6.8 shows a blackhole route with "set vrf 0" (profile fixed); any other VRF is outside the profile
    device = lab()
    shown = (FIXTURES / "show-router-static6-blackhole.txt").read_text()
    device.check_after_write = {'show router static6 "63"': shown.replace("set vrf 0", "set vrf 5")}
    runtime = runtime_for(tmp_path, device)
    request_ = ask(ROUTE6, "63", "create", BLACKHOLE)
    preview = execute.preview(runtime, "lab", request_)
    record = execute.apply(runtime, "lab", request_, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "reverted", record["steps"]
    assert "63" not in runtime.lab.device.tables[ROUTE6].objects


def test_a_lost_check_account_after_the_write_lets_the_safeguard_return_the_change(runtime_for, tmp_path):
    device = lab()
    runtime = runtime_for(tmp_path, device)
    request_ = ask(GROUP6, "netops-a3-grp", "create", {"member": ["all"]})
    preview = execute.preview(runtime, "lab", request_)
    current = runtime.lab.device
    current.check_after_write = {'show firewall addrgrp6 "netops-a3-grp"': "Command fail. Return code -37\n"}
    runtime.lab.store(current)
    record = execute.apply(runtime, "lab", request_, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "reverted", record
    assert "netops-a3-grp" not in runtime.lab.device.tables[GROUP6].objects


class Interrupted(BaseException):
    pass


def test_an_interrupted_apply_is_settled_by_admin_recover(runtime_for, tmp_path, monkeypatch):
    runtime = runtime_for(tmp_path, lab())
    request_ = ask(ROUTE6, "63", "create", BLACKHOLE)
    preview = execute.preview(runtime, "lab", request_)
    adapter = execute._adapter("fortios")
    observe = adapter.observe

    def interrupt_after_write(handle, plan):
        if runtime.store.running("lab"):
            raise Interrupted()
        return observe(handle, plan)

    with monkeypatch.context() as patch:
        patch.setattr(adapter, "observe", interrupt_after_write)
        with pytest.raises(Interrupted):
            execute.apply(runtime, "lab", request_, expected_plan_sha256=preview["plan_sha256"])
    assert "63" in runtime.lab.device.tables[ROUTE6].objects
    settled, = execute.recover(runtime, "lab")
    assert settled["result"] == "reverted", settled["steps"]
    assert "63" not in runtime.lab.device.tables[ROUTE6].objects


# ------------------------------------------------------------------------------------------- FortiOS 8.0.2

@pytest.mark.parametrize(("table", "key", "op", "changes"), [
    (ADDRESS6, "netops-a3-net", "create", PREFIX),
    (ADDRESS6, "none", "update", {"comment": "x"}),
    (GROUP6, "netops-a3-grp", "create", {"member": ["all"]}),
    (ROUTE6, "63", "create", BLACKHOLE),
])
def test_8_0_2_refuses_every_a3_change_before_any_write(runtime_for, tmp_path, table, key, op, changes):
    runtime = runtime_for(tmp_path, lab(webhook=True))
    request_ = ask(table, key, op, changes)
    preview = execute.preview(runtime, "lab", request_)
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["safeguard_no_rest_inverse"], preview
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", request_, expected_plan_sha256="0" * 64)
    assert caught.value.reason_codes == ["safeguard_no_rest_inverse"]
    device = runtime.lab.device
    assert device.applied_blocks == [] and not device.api_users and not device.webhooks


def test_an_untested_build_is_planned_with_the_untested_warning():
    loaded = profiles.load_profiles()
    for table in (ADDRESS6, GROUP6, ROUTE6):
        support = profiles.firmware_support(loaded[("fortios", table)], "7.6.9 build3800")
        assert support["status"] == "untested", support


def test_the_stored_plan_verifies_the_device_after_the_write(runtime_for, tmp_path):
    runtime = runtime_for(tmp_path, lab())
    record, before = approved(runtime, ask(ADDRESS6, "netops-a3-net", "create", PREFIX))
    assert engine.verify(record["plan"], before.encode(), expect="before")["result"] == "match"
    assert json.dumps(record).count("2001:db8:a3::/64") >= 1


# ------------------------------------------------------------------------------------------- A3-r2 (review)

DEFAULT_PREFIX = "netops-a3r2-any"
LOCAL_IN = "firewall local-in-policy6"


def fixture_object(name, table, key):
    """The attributes of one object of a captured show (FortiGate-60F 7.6.8, fixtures/fortios_a3/PROVENANCE.md)."""
    entry = fortios.parse_snapshot((FIXTURES / name).read_text()).section(table).entries[key]
    return {attribute: entry.value(attribute) for attribute in entry.attrs}


ALL_IPV6 = "at ::/0 (all IPv6 addresses)"


def at_default_prefix(device):
    """The object the check account read on the FortiGate-60F 7.6.8 after it was saved at ::/0 (interactive
    confirmation, outside Admin): show prints its uuid and comment only (no type, no ip6)."""
    shown = fixture_object("show-firewall-address6-default-prefix.txt", ADDRESS6, DEFAULT_PREFIX)
    assert set(shown) == {"uuid", "comment"}
    device.tables[ADDRESS6].objects[DEFAULT_PREFIX] = {"attrs": shown, "children": {}}
    assert show(device, ADDRESS6, DEFAULT_PREFIX) == (FIXTURES / "show-firewall-address6-default-prefix.txt").read_text()
    full = fortios.parse_snapshot((FIXTURES / "show-full-configuration-firewall-address6-default-prefix.txt")
                                  .read_text()).section(ADDRESS6).entries[DEFAULT_PREFIX]
    assert (full.value("type"), full.value("ip6")) == ("ipprefix", "::/0")
    return device


def test_r2_a_create_naming_ip6_at_the_default_keeps_it_up_to_the_hook_and_is_refused(runtime_for, tmp_path):
    """Review finding 1: a create naming ip6 ::/0 keeps the value up to the hook (the predicted state omits it as
    show does). FortiOS 7.6.8 answers next of such an entry with "The IPv6 address is set to ::/0 which means all IPv6
    addresses." and no prompt (live run of this task), so the create is refused before any write."""
    runtime = runtime_for(tmp_path, lab())
    for changes in ({"ip6": "::/0", "comment": "netops A3 r2 test"}, {"type": "ipprefix", "ip6": "0::0/0"}):
        preview = refused(runtime, ask(ADDRESS6, DEFAULT_PREFIX, "create", changes))
        assert ALL_IPV6 in " ".join(preview["reasons"]) and "needs ip6" not in " ".join(preview["reasons"]), preview
    # no ip6 at all is still a missing prefix
    preview = refused(runtime, ask(ADDRESS6, DEFAULT_PREFIX, "create", {"comment": "netops A3 r2 test"}))
    assert "needs ip6" in " ".join(preview["reasons"]), preview


def test_r2_the_delete_of_an_address6_at_the_default_prefix_is_refused_by_its_undo_plan(runtime_for, tmp_path):
    """Review finding 1: the stored state of the captured object (uuid and comment only) is restored with type
    ipprefix and ip6 ::/0 named; the A2 check of the undo plan finds that recreation cannot be written and refuses the
    delete before any write (a delete that could not be undone)."""
    runtime = runtime_for(tmp_path, at_default_prefix(lab()))
    preview = refused(runtime, ask(ADDRESS6, DEFAULT_PREFIX, "delete", {}))
    reasons = " ".join(preview["reasons"])
    assert "undo cannot be planned" in reasons and ALL_IPV6 in reasons, preview
    assert DEFAULT_PREFIX in runtime.lab.device.tables[ADDRESS6].objects


@pytest.mark.parametrize("changes", [{"comment": "netops A3 r2 two"}, {"ip6": "2001:db8:a3:8::/64"}])
def test_r2_an_update_of_an_address6_at_the_default_prefix_is_refused(runtime_for, tmp_path, changes):
    """A comment change leaves the object at ::/0 (FortiOS asks again on next); a new prefix cannot be undone (its
    undo returns the object to ::/0): both are refused before any write."""
    runtime = runtime_for(tmp_path, at_default_prefix(lab()))
    preview = refused(runtime, ask(ADDRESS6, DEFAULT_PREFIX, "update", changes))
    assert ALL_IPV6 in " ".join(preview["reasons"]), preview


def test_r2_an_update_to_the_default_prefix_is_refused(runtime_for, tmp_path):
    runtime = runtime_for(tmp_path, lab())
    approved(runtime, ask(ADDRESS6, "netops-a3-net", "create", PREFIX))
    preview = refused(runtime, ask(ADDRESS6, "netops-a3-net", "update", {"ip6": "::/0"}))
    assert ALL_IPV6 in " ".join(preview["reasons"]), preview


def test_r2_an_fqdn_without_a_restorable_value_is_not_deleted(runtime_for, tmp_path):
    """The A2 check of the undo plan refuses a delete whose recreation cannot be planned (an FQDN has no default)."""
    device = lab()
    device.tables[ADDRESS6].objects["netops-a3r2-fqdn"] = {"attrs": {"uuid": device._uuid(), "type": "fqdn"},
                                                          "children": {}}
    runtime = runtime_for(tmp_path, device)
    preview = refused(runtime, ask(ADDRESS6, "netops-a3r2-fqdn", "delete", {}))
    assert "undo cannot be planned" in " ".join(preview["reasons"]), preview


def local_in(device, name, status=None):
    """The local-in-policy6 the check account read on the FortiGate-60F 7.6.8 in the live run of this task
    (fixtures/fortios_a3), naming the group ``name`` in srcaddr; status None = as captured (disabled), "enable" = an
    active accept rule (show omits status enable)."""
    lines = (FIXTURES / "show-firewall-local-in-policy6.txt").read_text().splitlines()
    lines = [line.replace('"netops-a3r2-outer"', '"%s"' % name) for line in lines]
    if status == "enable":
        lines = [line for line in lines if line.strip() != "set status disable"]
    device.snapshot_extra = lines
    return device


def management_group(device, nested=False):
    """spravci-v6 is a member of sprava-v6 (directly, or through the nested group sprava-v6-inner)."""
    device.tables[ADDRESS6].objects["spravci-v6"] = {"attrs": {"uuid": device._uuid(), "ip6": "2001:db8:a3:5::/64"},
                                                    "children": {}}
    device.tables[ADDRESS6].objects["jini-v6"] = {"attrs": {"uuid": device._uuid(), "ip6": "2001:db8:a3:6::/64"},
                                                 "children": {}}
    if nested:
        device.tables[GROUP6].objects["sprava-v6-inner"] = {"attrs": {"uuid": device._uuid(),
                                                                      "member": '"spravci-v6"'}, "children": {}}
    device.tables[GROUP6].objects["sprava-v6"] = {
        "attrs": {"uuid": device._uuid(), "member": '"sprava-v6-inner"' if nested else '"spravci-v6"'},
        "children": {}}
    return device


@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("status", ["enable", None])
def test_r2_a_member_of_a_group_a_local_in_policy6_uses_is_not_changed(runtime_for, tmp_path, nested, status):
    """Review finding 2: an active accept rule of firewall local-in-policy6 names the group sprava-v6 (with
    spravci-v6 as a member, directly or through a nested group): a change of the member or of the nested group's
    members is refused before any write, with or without endpoint_impact (Admin does not evaluate local-in policies);
    so is it for a disabled rule (the live scenario); a comment changes no match and passes."""
    runtime = runtime_for(tmp_path, local_in(management_group(lab(), nested), "sprava-v6", status))
    snapshot = fortios.parse_snapshot(runtime.lab.device.snapshot())
    assert snapshot.section(LOCAL_IN).entries, "the local-in-policy6 is part of the snapshot"
    for impact in (False, True):
        extra = {"endpoint_impact": "spravci-v6"} if impact else {}
        preview = refused(runtime, ask(ADDRESS6, "spravci-v6", "update", {"ip6": "2001:db8:a3:7::/64"}, **extra))
        assert "referenced outside IPv6 policies" in " ".join(preview["reasons"]), preview
        assert LOCAL_IN in " ".join(preview["reasons"]), preview
    group = "sprava-v6-inner" if nested else "sprava-v6"
    preview = refused(runtime, ask(GROUP6, group, "update", {"member": ["spravci-v6", "jini-v6"]}))
    assert LOCAL_IN in " ".join(preview["reasons"]), preview
    approved(runtime, ask(ADDRESS6, "spravci-v6", "update", {"comment": "netops A3 r2"}))


def test_r2_a_group_outside_any_local_in_policy6_still_changes(runtime_for, tmp_path):
    """The local-in rule names another group: the member of sprava-v6 changes (no policy uses it)."""
    runtime = runtime_for(tmp_path, local_in(management_group(lab()), "all"))
    record, before = approved(runtime, ask(ADDRESS6, "spravci-v6", "update", {"ip6": "2001:db8:a3:7::/64"}))
    undone(runtime, record, before)


# ------------------------------------------------------------------------------------------- A2 compatibility

@pytest.mark.parametrize("table", [ADDRESS6, GROUP6])
def test_r2_undo_of_a_create_verifies_the_uuid_read_back(runtime_for, tmp_path, table):
    """address6/addrgrp6 print a uuid: the undo of a create deletes only the object with the uuid the check account
    read after the create; the same name and attributes with a new uuid are refused before any write."""
    runtime = runtime_for(tmp_path, lab())
    key, changes = (("netops-a3-net", PREFIX) if table == ADDRESS6 else ("netops-a3-grp", {"member": ["all"]}))
    created, _before = approved(runtime, ask(table, key, "create", changes))
    device = runtime.lab.device
    assert created["fortios_object_uuid"] == device.tables[table].objects[key]["attrs"]["uuid"]
    device.tables[table].objects[key]["attrs"]["uuid"] = device._uuid()
    runtime.lab.store(device)
    before, written_before = runtime.lab.device.snapshot(), written(runtime)
    preview = execute.preview_undo(runtime, created["change_id"], "Restore the A3 baseline")
    assert preview["result"] == "rejected" and "identity" in " ".join(preview["reasons"]), preview
    with pytest.raises(Rejected, match="identity") as caught:
        execute.undo(runtime, created["change_id"], "Restore the A3 baseline")
    assert (preview["reason_codes"], caught.value.reason_codes) == (
        ["undo_identity_mismatch"], ["undo_identity_mismatch"],
    )
    assert runtime.lab.device.snapshot() == before and written(runtime) == written_before


def test_r2_router_static6_undo_compares_key_and_attributes(runtime_for, tmp_path):
    """router static6 has no uuid: an unchanged route under the key of the create is undone; a route changed under
    the same key is refused before any write."""
    runtime = runtime_for(tmp_path, lab())
    created, before = approved(runtime, ask(ROUTE6, "63", "create", BLACKHOLE))
    assert "fortios_object_uuid" not in created
    undone(runtime, created, before)
    created, _before = approved(runtime, ask(ROUTE6, "63", "create", BLACKHOLE))
    device = runtime.lab.device
    device.tables[ROUTE6].objects["63"]["attrs"]["distance"] = "20"
    runtime.lab.store(device)
    current, written_before = runtime.lab.device.snapshot(), written(runtime)
    preview = execute.preview_undo(runtime, created["change_id"], "Restore the A3 baseline")
    assert preview["result"] == "rejected", preview
    assert runtime.lab.device.snapshot() == current and written(runtime) == written_before


def test_r2_a_route6_whose_recreation_cannot_be_planned_is_not_deleted(runtime_for, tmp_path):
    """Before any write the opposite operation is planned with the defaults show omits: a route at dst ::/0 (omitted
    by show) cannot be recreated, its delete is refused."""
    device = lab()
    device.tables[ROUTE6].objects["5"] = {"attrs": {"device": "port1", "status": "disable"}, "children": {}}
    runtime = runtime_for(tmp_path, device)
    refused(runtime, ask(ROUTE6, "5", "delete", {}))
