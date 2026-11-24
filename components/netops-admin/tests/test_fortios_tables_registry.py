"""1.0.13 A1-R: the registry of the FortiOS tables added in 1.0.13 (fortios_tables) and its shared checks.

The registry ships empty (the groups A1-S, A2 and A3 fill it); these tests register framework test tables with test
profiles (not shipped) and drive them through the real path: execute (preview, apply, undo) -> exec_fortios -> the
production access.DeviceAccess (OpenSSH sessions held per account, the Fortinet dialog) -> the OpenSSH test client
(fortinet_ssh_fixture, as in test_fortinet_ssh_operation) -> the simulated device (fake_fortios_tables, the DHCP
server layout of fixtures/fortios_7_6_8_dhcp_dns) kept in <tmp>/device between the sessions. The parser, the
Snapshot, the planning, rest_digest, rest_inverse, the safeguard rendering, the journal and the audit are real.
"""
from __future__ import annotations

import hashlib
import itertools
import json
import pickle
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import request_bytes
from fake_fortios_tables import FakeFortiOSTables, FakeFortiOSTablesWebhook, Table
from fortinet_ssh_fixture import BLOB, PUBLIC_KEY, Counter, install_clients
from test_execute import make_runtime, request

from netops_admin import (access, engine, execute, fortios, fortios_tab_ipv6, fortios_tab_policy, fortios_tab_services,
                          fortios_tables, profiles, readiness)
from netops_admin.errors import Rejected, SnapshotRejected
from netops_admin.fortios_tables import TableHooks
from netops_admin.request import parse_request
from netops_core import hostkey, prompt

FIXTURES = Path(__file__).parent / "fixtures" / "fortios_7_6_8_dhcp_dns"
CANARY = Path(__file__).resolve().parents[2] / "netops-auditor" / "tests" / "fixtures" / "secret_canary.conf"
DNS, SYSLOG, SERVER, RANGE = "system dns", "log syslogd setting", "system dhcp server", "system dhcp server/ip-range"
GROUP, ROUTE6 = "firewall service group", "router static6"
TESTED = "7.6.8 build3744"
REQUESTS = itertools.count(1)


def attribute(kind, default=None, required=False, update=True, unset=False, **extra):
    data = {"type": kind, "default": default, "required_on_create": required, "update": update, "unset": unset,
            "referenced_update": True, **extra}
    if kind == "text":
        data.setdefault("max_length", 63)
    return data


def profile(table, attributes, ops=("create", "update", "delete"), key=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,78}$", **extra):
    return {"platform": "fortios", "table": table, "versions": [TESTED], "ops": list(ops), "key_pattern": key,
            "protected_keys": [], "attributes": attributes, "fixed": {}, "volatile": [], "reserved_values": {},
            "inverse_identity_changes": {}, "rollback_evidence": "A1-R framework test profile, not shipped",
            "exact_versions": True, "provisional": True, **extra}


SWITCH = r"^(enable|disable)$"
PROFILES = {
    DNS: profile(DNS, {"primary": attribute("ipv4-address", "0.0.0.0"), "secondary": attribute("ipv4-address", "0.0.0.0"),
                       "protocol": attribute("text", "cleartext", pattern="^cleartext$")},
                 ops=("update",), key="^-$", implicit_keys=True),
    SYSLOG: profile(SYSLOG, {"status": attribute("text", "disable", pattern=SWITCH, undo_to_default=True),
                             "server": attribute("text", unset=True)}, ops=("update",), key="^-$", implicit_keys=True),
    SERVER: profile(SERVER, {"status": attribute("text", "enable", pattern=SWITCH, undo_to_default=True),
                             "interface": attribute("text", update=False),
                             "default-gateway": attribute("ipv4-address"), "netmask": attribute("ipv4-address"),
                             "dns-service": attribute("text", "local"), "timezone-option": attribute("text", "disable")},
                    ops=("update",), key=r"^[1-9][0-9]{0,9}$", table_scoped_key=True),
    RANGE: profile(RANGE, {"start-ip": attribute("ipv4-address", required=True),
                           "end-ip": attribute("ipv4-address", required=True)},
                   key=r"^[1-9][0-9]{0,9}:[1-9][0-9]{0,9}$", table_scoped_key=True),
    GROUP: profile(GROUP, {"member": attribute("name-list", required=True), "comment": attribute("text", unset=True)}),
    ROUTE6: profile(ROUTE6, {"dst": attribute("ipv6-network", required=True), "device": attribute("text"),
                             "blackhole": attribute("text", "disable", pattern=SWITCH)},
                    key=r"^[1-9][0-9]{0,9}$", table_scoped_key=True),
}
DHCP_EXCLUDED = ("ddns-*", "options", "vci-*", "tftp-server", "filename")
SERVICE = dict(preview_code="fortios_service_preview_required", readback_code="fortios_service_readback_unreadable")


def hooks(**changed):
    """The framework test registration: A1 services (singletons, DHCP server with its ranges), an A2 object with a
    REST inverse and policy use, an A3 object."""
    tables = {
        "fortios_tab_services": {
            DNS: TableHooks(DNS, kind="singleton", impact=True, rest_permission="sysgrp",
                            excluded=("ssl-certificate", "dns-over-tls", "server-hostname", "fqdn-*", "source-ip"),
                            **SERVICE),
            SYSLOG: TableHooks(SYSLOG, kind="singleton", impact=True, rest_permission="loggrp",
                               excluded=("certificate", "enc-algorithm"), **SERVICE),
            SERVER: TableHooks(SERVER, rest_path="system.dhcp/server", rest_key="id", rest_permission="netgrp",
                               child_sections=("ip-range", "reserved-address"), impact=True, excluded=DHCP_EXCLUDED,
                               **SERVICE),
            RANGE: TableHooks(RANGE, kind="nested", parent=(SERVER, "ip-range"), rest_path="system.dhcp/server",
                              rest_key="id", rest_permission="netgrp", impact=True, excluded=DHCP_EXCLUDED, **SERVICE),
        },
        "fortios_tab_policy": {
            GROUP: TableHooks(GROUP, rest_path="firewall.service/group", rest_key="name",
                              rest_verified=frozenset(("create", "delete")), policy_attributes=("service",)),
        },
        "fortios_tab_ipv6": {ROUTE6: TableHooks(ROUTE6)},
    }
    for table, item in changed.items():
        for module in tables.values():
            if table in module:
                module[table] = item
    return tables


@pytest.fixture
def registered(monkeypatch):
    """Install the test tables in the three group modules and their test profiles next to the shipped ones."""
    def install(tables=None, extra_profiles=()):
        loaded = dict(shipped)
        for data in (*PROFILES.values(), *extra_profiles):
            parsed = profiles.parse_profile(data)
            loaded[(parsed.platform, parsed.table)] = parsed
        for module in (profiles, execute, readiness):
            monkeypatch.setattr(module, "load_profiles", lambda: dict(loaded))
        for name, module in (("fortios_tab_services", fortios_tab_services), ("fortios_tab_policy", fortios_tab_policy),
                             ("fortios_tab_ipv6", fortios_tab_ipv6)):
            monkeypatch.setattr(module, "TABLES", (tables or hooks())[name])
        fortios_tables.reset()

    shipped = profiles.load_profiles()
    install()
    yield install
    fortios_tables.reset()


def device_tables():
    """The device: system dns and syslogd as FortiOS shows them (defaults omitted), the DHCP server 3 of the lab capture
    with one address range, no service group and no IPv6 route (show omits both tables, as the stored show of 7.6.8)."""
    server = {"dns-service": "default", "default-gateway": "192.0.2.1", "netmask": "255.255.255.0",
              "interface": "quarantine", "timezone-option": "default"}
    tables = {
        DNS: Table("singleton", defaults={"protocol": "cleartext", "primary": "0.0.0.0", "secondary": "0.0.0.0"}),
        SYSLOG: Table("singleton", defaults={"status": "disable"}, quoted_names=("server",)),
        SERVER: Table(defaults={"status": "enable", "dns-service": "local", "timezone-option": "disable"},
                      quoted_names=("interface",), children=("ip-range", "reserved-address"), numeric_keys=True,
                      order=("start-ip", "end-ip")),
        GROUP: Table(quoted_names=("member", "comment")),
        ROUTE6: Table(quoted_names=("device",), numeric_keys=True, order=("dst", "gateway", "device", "blackhole")),
    }
    tables[DNS].attrs.update(primary="192.0.2.53", secondary="192.0.2.54", protocol="cleartext")
    tables[SYSLOG].attrs.update(status="enable", server="192.0.2.80")
    tables[SERVER].objects["3"] = {"attrs": dict(server),
                                   "children": {"ip-range": {"1": {"start-ip": "192.0.2.2", "end-ip": "192.0.2.254"}}}}
    return tables


def lab(webhook=False):
    return (FakeFortiOSTablesWebhook if webhook else FakeFortiOSTables)(device_tables())


class Wired:
    """The simulated device behind the production DeviceAccess: every OpenSSH session of Admin runs the test client of
    fortinet_ssh_fixture, which loads the device from <directory>/device, answers the Fortinet dialog and stores it
    back. ``device`` is the state the sessions left; ``store`` replaces it (a change made outside Admin)."""

    def __init__(self, directory):
        self.directory = directory

    @property
    def device(self):
        return pickle.loads((self.directory / "device").read_bytes())

    def store(self, device):
        (self.directory / "device").write_bytes(pickle.dumps(device))

    def advance(self, seconds):
        current = self.device
        current.advance(seconds)
        self.store(current)


@pytest.fixture
def runtime_for(monkeypatch, watch_export_status, tmp_path_factory):
    """runtime_for(tmp_path, device): an Admin runtime whose access is the production access.DeviceAccess over the
    OpenSSH test client (pattern of test_fortinet_ssh_operation.wired); runtime.lab is the Wired device. One device
    per test (the test client is found through PATH)."""
    def wire(tmp_path, device):
        tmp_path.mkdir(parents=True, exist_ok=True)
        device.uuids = Counter(next(device.uuids))
        if hasattr(device, "keys"):
            device.keys = Counter(next(device.keys))
        runtime = make_runtime(tmp_path, device, opt_in=(DNS, ROUTE6), protected={"system interface": ["wan1"]})
        name = "lab"
        key = {"host_key": PUBLIC_KEY} if hasattr(runtime.config.devices[name], "host_key") else {}
        configured = replace(runtime.config.devices[name], host_key_fingerprint=hostkey.fingerprint_of(BLOB),
                             check_address="198.51.100.15", **key)
        export = tmp_path / "export.json"
        export.write_text(json.dumps({"updated_at": time.time(), "pending": 0}))
        watch_export_status(export)
        runtime.config = replace(runtime.config, devices={name: configured}, export_status_file=str(export))
        runtime.notifier = lambda _: "sent"
        from enrollment_helpers import certify
        certify(runtime, device, name)
        runtime.access_factory = access.DeviceAccess
        vault = {alias: SimpleNamespace(login=credential.login, kind="password", use=lambda: "fixture-password")
                 for alias, credential in (("rw", device.credential), ("ro", device.check_credential))}
        monkeypatch.setattr(access.vault, "load", lambda *_args, **_kw: SimpleNamespace(credential=vault.__getitem__))
        lab = Wired(tmp_path)
        lab.store(device)
        (tmp_path / "platform").write_text("fortios")
        runtime.sleep = lab.advance
        runtime.lab = lab
        install_clients(tmp_path, monkeypatch, tmp_path_factory.getbasetemp() / "fortinet-ssh-pycache")
        return runtime

    return wire


def ssh_sessions(runtime):
    """The OpenSSH sessions the test client served since the last call (login, address)."""
    events = runtime.lab.directory / "events"
    rows = [json.loads(line) for line in events.read_text().splitlines()] if events.exists() else []
    events.unlink(missing_ok=True)
    return [(row[1], row[2]) for row in rows if row[0] == "ssh"]


def ask(table, key, op, changes, **extra):
    return request(table=table, key=key, op=op, changes=changes, request_id="a1r-request-%04d" % next(REQUESTS), **extra)


def approved(runtime, request_):
    current = runtime.lab.device
    before, written = current.snapshot(), list(current.applied_blocks)
    preview = execute.preview(runtime, "lab", request_)
    assert preview["result"] == "ready", preview
    current = runtime.lab.device
    assert current.snapshot() == before and current.applied_blocks == written
    record = execute.apply(runtime, "lab", request_, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", record
    assert engine.verify(record["plan"], runtime.lab.device.snapshot().encode())["result"] == "match"
    return record, before


def undone(runtime, record, before):
    preview = execute.preview_undo(runtime, record["change_id"], "Restore the A1-R baseline", issue=True)
    assert preview["result"] == "ready", preview
    restored = execute.undo(runtime, record["change_id"], "Restore the A1-R baseline", preview["plan_sha256"])
    assert restored["result"] == "confirmed", restored
    current = runtime.lab.device
    assert engine.verify(record["plan"], current.snapshot().encode(), expect="before")["result"] == "match"
    assert current.snapshot() == before
    assert not current.stitches and not current.actions and not current.triggers
    return restored


def audit_events(tmp_path):
    path = tmp_path / "audit" / "audit.jsonl"
    return [] if not path.exists() else [json.loads(line) for line in path.read_text().splitlines()]


# ------------------------------------------------------------------------------------------- the registry itself

def test_the_shipped_registry_lists_the_group_modules_and_tables():
    fortios_tables.reset()
    try:
        assert fortios_tables.MODULES == ("fortios_tab_services", "fortios_tab_policy", "fortios_tab_ipv6")
        services = {DNS, SYSLOG, SERVER, RANGE}
        policy = {GROUP, "firewall schedule recurring", "firewall schedule onetime"}
        ipv6 = {"firewall address6", "firewall addrgrp6", ROUTE6}
        assert fortios_tab_services.TABLES.keys() == services
        assert fortios_tab_policy.TABLES.keys() == policy
        assert fortios_tab_ipv6.TABLES.keys() == ipv6
        expected = services | policy | ipv6
        assert fortios_tables.all_tables() == tuple(sorted(expected))
        assert fortios_tables.impact_tables() == tuple(sorted(expected - {ROUTE6}))
        assert fortios_tables.PLANNED_TABLES == expected
        assert fortios_tables.hooks("firewall address") is None
    finally:
        fortios_tables.reset()


def test_the_registry_refuses_a_double_and_a_fortios_table():
    group = TableHooks(GROUP)
    with pytest.raises(fortios_tables.RegistryError, match="registered twice"):
        fortios_tables.build({"fortios_tab_policy": {GROUP: group}, "fortios_tab_ipv6": {GROUP: group}})
    for table in ("firewall address", "firewall policy", "system interface", fortios.DHCP_TABLE, "router static"):
        with pytest.raises(fortios_tables.RegistryError, match="handled by fortios.py"):
            fortios_tables.build({"fortios_tab_policy": {table: TableHooks(table)}})
    with pytest.raises(fortios_tables.RegistryError, match="singleton"):
        fortios_tables.build({"fortios_tab_services": {DNS: TableHooks(DNS, kind="singleton",
                                                                       rest_verified=frozenset(("update",)))}})
    with pytest.raises(fortios_tables.RegistryError, match="differs"):
        fortios_tables.build({"fortios_tab_policy": {GROUP: TableHooks(ROUTE6)}})


def test_registered_tables_are_known_to_the_shared_code(registered):
    assert fortios_tables.all_tables() == tuple(sorted((DNS, SYSLOG, SERVER, RANGE, GROUP, ROUTE6)))
    assert fortios_tables.impact_tables() == tuple(sorted((DNS, SYSLOG, SERVER, RANGE)))
    assert fortios.NESTED[RANGE] == (SERVER, "ip-range") and fortios.IP_RANGE_TABLE == RANGE
    assert fortios.rest_path(GROUP) == "firewall.service/group" and fortios.rest_key(RANGE) == "id"
    assert fortios.webhook_permissions(SERVER)["netgrp"] == "read-write"
    assert fortios.webhook_permissions(SERVER)["fwgrp"] == "none"
    assert fortios.webhook_permissions("firewall address")["fwgrp"] == "read-write"


def test_a_profile_with_isolated_update_is_refused_for_a_registered_table(registered, runtime_for, tmp_path):
    isolated = dict(PROFILES[DNS], isolated_update=["secondary"])
    with pytest.raises(Rejected, match="isolated_update"):
        fortios_tables.check_profile(profiles.parse_profile(isolated))
    registered(extra_profiles=(isolated,))
    device = lab()
    runtime = runtime_for(tmp_path, device)
    preview = execute.preview(runtime, "lab", ask(DNS, "-", "update", {"secondary": "192.0.2.55"}, endpoint_impact="-"))
    assert preview["result"] == "rejected" and "isolated_update" in " ".join(preview["reasons"])
    assert not runtime.lab.device.applied_blocks


# ------------------------------------------------------------------------------------------- apply needs the preview

@pytest.mark.parametrize(("table", "key", "op", "changes", "code"), [
    (DNS, "-", "update", {"secondary": "192.0.2.55"}, "fortios_service_preview_required"),
    (SYSLOG, "-", "update", {"server": "192.0.2.81"}, "fortios_service_preview_required"),
    (SERVER, "3", "update", {"status": "disable"}, "fortios_service_preview_required"),
    (RANGE, "3:2", "create", {"start-ip": "192.0.2.100", "end-ip": "192.0.2.110"}, "fortios_service_preview_required"),
    (GROUP, "a1r-web", "create", {"member": ["HTTP", "HTTPS"]}, "fortios_object_preview_required"),
    (ROUTE6, "1", "create", {"dst": "2001:db8:a1::/48", "blackhole": "enable"}, "fortios_object_preview_required"),
])
def test_apply_without_the_approved_preview_is_refused_for_every_registered_table(registered, runtime_for, tmp_path, table, key, op,
                                                                                  changes, code):
    device = lab()
    runtime = runtime_for(tmp_path, device)
    extra = {"endpoint_impact": key} if fortios_tables.hooks(table).impact else {}
    before = device.snapshot()
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", ask(table, key, op, changes, **extra))
    assert caught.value.reason_codes == [code], caught.value.reasons
    device = runtime.lab.device
    assert device.applied_blocks == [] and device.snapshot() == before
    assert ssh_sessions(runtime) == []  # refused before any session
    assert audit_events(tmp_path) == []  # no operation was started


def test_the_shared_check_precedes_the_nested_table_check(registered, runtime_for, tmp_path):
    # the DHCP range is a nested table; without the registry it would get the generic plan_changed
    assert RANGE in fortios.NESTED
    device = lab()
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime_for(tmp_path, device), "lab",
                      ask(RANGE, "3:1", "update", {"end-ip": "192.0.2.200"}, endpoint_impact="3:1"))
    assert caught.value.reason_codes == ["fortios_service_preview_required"]


# ------------------------------------------------------------------------------------------- singleton

def test_singleton_update_is_applied_read_back_and_undone(registered, runtime_for, tmp_path):
    device = lab()
    runtime = runtime_for(tmp_path, device)
    record, before = approved(runtime, ask(DNS, "-", "update", {"secondary": "192.0.2.55"}, endpoint_impact="-"))
    plan = record["plan"]
    assert plan["commands"] == ["config system dns", "    set secondary 192.0.2.55", "end"]
    assert plan["inverse"] == ["config system dns", "    set secondary 192.0.2.54", "end"]
    assert plan["predicted"] == {"before": {"primary": "192.0.2.53", "secondary": "192.0.2.54"},
                                 "after": {"primary": "192.0.2.53", "secondary": "192.0.2.55"}}
    assert runtime.lab.device.tables[DNS].attrs["secondary"] == "192.0.2.55"
    # one held session per account for the preview, the apply and the undo (design A 1.11)
    sessions = ssh_sessions(runtime)
    assert sessions and set(sessions) == {("netops-rw", "192.0.2.1"), ("netops-check", "198.51.100.15")}
    undone(runtime, record, before)
    assert runtime.lab.device.tables[DNS].attrs["secondary"] == "192.0.2.54"


def test_singleton_rest_digest_keeps_the_section_without_the_plan_state(registered):
    device = lab()
    names = fortios_tables.state_names(profiles.parse_profile(PROFILES[DNS]), {}, {})
    snapshot = fortios.Snapshot(device.snapshot())
    digest = snapshot.rest_digest(DNS, "-", singleton_names=names)
    device.tables[DNS].attrs["secondary"] = "192.0.2.99"
    assert fortios.Snapshot(device.snapshot()).rest_digest(DNS, "-", singleton_names=names) == digest
    # the section stays in the digest: a snapshot without it is another configuration
    missing = device.snapshot().replace("config system dns\n    set primary 192.0.2.53\n    set secondary 192.0.2.99\nend\n", "")
    assert "config system dns\n" not in missing
    assert fortios.Snapshot(missing).rest_digest(DNS, "-", singleton_names=names) != digest
    # an attribute outside the plan state stays in it as well
    extra = device.snapshot().replace("    set secondary 192.0.2.99\n", "    set secondary 192.0.2.99\n    set cache-notfound-responses enable\n")
    assert fortios.Snapshot(extra).rest_digest(DNS, "-", singleton_names=names) != digest


def test_singleton_rest_digest_of_the_plan_is_verified_after_the_write(registered, runtime_for, tmp_path):
    device = lab()
    runtime = runtime_for(tmp_path, device)
    request_ = ask(DNS, "-", "update", {"primary": "192.0.2.60"}, endpoint_impact="-")
    plan = engine.build_plan("fortios", device.snapshot().encode(), request_, protected={"system interface": ["wan1"]},
                             device="lab")
    names = fortios_tables.state_names(profiles.parse_profile(PROFILES[DNS]), *plan["predicted"].values())
    before = fortios.Snapshot(device.snapshot())
    assert plan["rest_sha256"] == before.rest_digest(DNS, "-", singleton_names=names)
    assert plan["rest_sha256"] != before.rest_digest(DNS, "-")
    record, _ = approved(runtime, request_)
    assert record["plan"]["rest_sha256"] == plan["rest_sha256"]
    after = fortios.Snapshot(runtime.lab.device.snapshot())
    assert after.rest_digest(DNS, "-", singleton_names=names) == plan["rest_sha256"]


def test_a_snapshot_without_the_singleton_section_is_incomplete(registered, runtime_for, tmp_path):
    device = lab()
    del device.tables[SYSLOG]
    plan_request = ask(SYSLOG, "-", "update", {"server": "192.0.2.81"}, endpoint_impact="-")
    with pytest.raises(SnapshotRejected) as caught:
        engine.build_plan("fortios", device.snapshot().encode(), plan_request)
    assert caught.value.category == fortios.SNAPSHOT_INCOMPLETE


def test_an_excluded_attribute_refuses_any_change_by_name_only(registered, runtime_for, tmp_path):
    device = lab()
    device.tables[DNS].attrs["server-hostname"] = "dot.example.invalid"
    runtime = runtime_for(tmp_path, device)
    preview = execute.preview(runtime, "lab", ask(DNS, "-", "update", {"primary": "192.0.2.60"}, endpoint_impact="-"))
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["fortios_service_scope"]
    text = json.dumps(preview)
    assert "server-hostname" in text and "dot.example.invalid" not in text
    assert not runtime.lab.device.applied_blocks


def test_an_excluded_attribute_on_the_parent_refuses_the_range_change(registered, runtime_for, tmp_path):
    device = lab()
    device.tables[SERVER].objects["3"]["attrs"]["ddns-key"] = "ENC c2VjcmV0LWNhbmFyeQ=="
    runtime = runtime_for(tmp_path, device)
    preview = execute.preview(runtime, "lab", ask(RANGE, "3:1", "update", {"end-ip": "192.0.2.200"},
                                                  endpoint_impact="3:1"))
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["fortios_service_scope"]
    text = json.dumps(preview)
    assert "ddns-key" in text and "c2VjcmV0LWNhbmFyeQ" not in text and "ENC" not in text
    preview = execute.preview(runtime, "lab", ask(SERVER, "3", "update", {"status": "disable"}, endpoint_impact="3"))
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["fortios_service_scope"]


def readback_refused(record):
    """The check account read after the write was refused with the readback code of the table."""
    return [step["detail"] for step in record["steps"] if step["step"] == "check_identity_failed"]


def test_an_excluded_attribute_seen_by_the_readback_is_a_mismatch(registered, runtime_for, tmp_path):
    device = lab()
    # only the independent read of the check account differs: the snapshot of the write account stays as the device
    # holds it, so the operation reaches the readback and the readback alone refuses the confirmation
    device.check_after_write = {"show system dns": "config system dns\n    set primary 192.0.2.53\n"
                                                   "    set secondary 192.0.2.55\n    set source-ip 198.51.100.77\nend\n"}
    request_ = ask(DNS, "-", "update", {"secondary": "192.0.2.55"}, endpoint_impact="-")
    runtime = runtime_for(tmp_path, device)
    preview = execute.preview(runtime, "lab", request_)
    assert preview["result"] == "ready", preview
    record = execute.apply(runtime, "lab", request_, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "reverted", record
    assert readback_refused(record) == ["Rejected (fortios_service_readback_unreadable)"]
    assert "final_check_failed" not in [step["step"] for step in record["steps"]]
    assert runtime.lab.device.tables[DNS].attrs["secondary"] == "192.0.2.54"  # the safeguard returned the change
    assert "198.51.100.77" not in json.dumps(record)


# ------------------------------------------------------------------------------------------- r2 finding 1: parent

OPTION = '"tftp.example.invalid"'


def with_options(shown):
    """The check account answer with a DHCP option (an excluded child section) on the parent server."""
    head, separator, tail = shown.rpartition("    next\n")
    return (head + "        config options\n            edit 1\n                set code 66\n"
            "                set type string\n                set value %s\n            next\n        end\n"
            % OPTION + separator + tail)


def server_show(device):
    return "\n".join(device.table_lines(SERVER, "3")) + "\n"


def test_the_range_preview_refuses_excluded_configuration_the_check_account_sees_on_the_parent(registered,
                                                                                             runtime_for, tmp_path):
    device = lab()
    assert "config options" not in device.snapshot()  # the snapshot passes the plan scope check
    device.check_override = {"show system dhcp server 3": with_options(server_show(device))}
    runtime = runtime_for(tmp_path, device)
    preview = execute.preview(runtime, "lab", ask(RANGE, "3:1", "update", {"end-ip": "192.0.2.200"},
                                                  endpoint_impact="3:1"))
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["fortios_service_readback_unreadable"]
    text = json.dumps(preview)
    assert "options" in text and "tftp.example.invalid" not in text
    assert not runtime.lab.device.applied_blocks


def test_the_range_readback_refuses_excluded_configuration_of_the_parent_after_the_write(registered, runtime_for,
                                                                                       tmp_path):
    device = lab()
    expected = lab()  # the range exactly as the plan predicts it; only the parent differs
    expected.tables[SERVER].objects["3"]["children"]["ip-range"]["1"]["end-ip"] = "192.0.2.200"
    device.check_after_write = {"show system dhcp server 3": with_options(server_show(expected))}
    runtime = runtime_for(tmp_path, device)
    request_ = ask(RANGE, "3:1", "update", {"end-ip": "192.0.2.200"}, endpoint_impact="3:1")
    preview = execute.preview(runtime, "lab", request_)
    assert preview["result"] == "ready", preview
    record = execute.apply(runtime, "lab", request_, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "reverted", record
    assert readback_refused(record) == ["Rejected (fortios_service_readback_unreadable)"]
    current = runtime.lab.device
    assert current.tables[SERVER].objects["3"]["children"]["ip-range"]["1"]["end-ip"] == "192.0.2.254"
    assert "tftp.example.invalid" not in json.dumps(record)


# ------------------------------------------------------------------------------------------- r2 finding 2: default

def test_a_change_from_the_default_value_has_a_working_undo(registered, runtime_for, tmp_path):
    # design A 1.5b: secondary 0.0.0.0 is the default of the test profile, which unset does not restore by measurement
    # (undo_to_default false, unset false); the inverse and the undo set it explicitly
    assert profiles.parse_profile(PROFILES[DNS]).attributes["secondary"].undo_to_default is False
    device = lab()
    device.tables[DNS].attrs.pop("secondary")
    assert "secondary" not in device.snapshot()
    runtime = runtime_for(tmp_path, device)
    record, before = approved(runtime, ask(DNS, "-", "update", {"secondary": "192.0.2.55"}, endpoint_impact="-"))
    assert record["plan"]["predicted"]["before"] == {"primary": "192.0.2.53"}
    assert record["plan"]["inverse"] == ["config system dns", "    set secondary 0.0.0.0", "end"]
    restored = undone(runtime, record, before)
    assert restored["plan"]["commands"] == ["config system dns", "    set secondary 0.0.0.0", "end"]
    assert "secondary" not in runtime.lab.device.snapshot()


# ------------------------------------------------------------------------------------------- r2 finding 3: empty table

def test_the_first_object_of_a_table_show_omits_and_the_last_delete(registered, runtime_for, tmp_path):
    stored = (Path(__file__).resolve().parents[3] / "tests" / "v1" / "fixtures" / "fortios_60f_7_6_8_show.conf").read_text()
    assert "\nconfig router static\n" in stored and "\nconfig router static6\n" not in stored
    device = lab()
    assert "config router static6" not in device.snapshot()  # the same shape: no route, no section
    route = {"dst": "2001:db8:a1::/48", "blackhole": "enable"}
    runtime = runtime_for(tmp_path, device)
    record, before = approved(runtime, ask(ROUTE6, "1", "create", route))
    assert record["plan"]["predicted"]["before"] is None
    assert runtime.lab.device.tables[ROUTE6].objects["1"]["attrs"] == route
    assert "fortios_object_uuid" not in record
    undone(runtime, record, before)
    current = runtime.lab.device
    assert "config router static6" not in current.snapshot()
    current.tables[ROUTE6].objects["1"] = {"attrs": dict(route), "children": {}}
    runtime.lab.store(current)
    record, before = approved(runtime, ask(ROUTE6, "1", "delete", {}))
    assert "config router static6" not in runtime.lab.device.snapshot()
    undone(runtime, record, before)  # the undo of the last delete creates the first route again
    snapshot = fortios.Snapshot(before)
    assert snapshot.entries(ROUTE6).keys() == {"1"}


def test_rest_digest_has_no_empty_wrapper_of_a_registered_object_table(registered):
    device = lab()
    empty = fortios.Snapshot(device.snapshot())
    assert empty.entries(ROUTE6) == {} and empty.entries(GROUP) == {}
    device.tables[ROUTE6].print_empty = True
    assert "config router static6\nend\n" in device.snapshot()
    assert fortios.Snapshot(device.snapshot()).rest_digest(ROUTE6, "1") == empty.rest_digest(ROUTE6, "1")
    device.tables[ROUTE6].objects["1"] = {"attrs": {"dst": "2001:db8:a1::/48", "blackhole": "enable"}, "children": {}}
    created = fortios.Snapshot(device.snapshot())
    assert created.rest_digest(ROUTE6, "1") == empty.rest_digest(ROUTE6, "1")
    assert created.rest_digest(ROUTE6, "2") != empty.rest_digest(ROUTE6, "2")


# ------------------------------------------------------------------------------------------- r3 finding 1: default undo

@pytest.mark.parametrize(("table", "name", "definition", "value", "set_default"), [
    # a text whose measured default is the empty string (unset allowed): canonical_value refuses ""
    (SYSLOG, "interface", attribute("text", "", unset=True), "port1", '    set interface ""'),
    # an IPv6 address whose measured default is :: (unset not allowed): the unicast validation refuses ::
    (DNS, "ip6-primary", attribute("ipv6-address", "::"), "2001:db8::53", "    set ip6-primary ::"),
])
def test_the_undo_returns_to_a_default_the_request_validation_refuses(registered, runtime_for, tmp_path, table, name,
                                                                      definition, value, set_default):
    # design A 1.5b: the undo returns to the measured default by an explicit set, as the plan inverse does, without
    # validating the default as a request value
    changed = dict(PROFILES[table], attributes={**PROFILES[table]["attributes"], name: definition})
    registered(extra_profiles=(changed,))
    device = lab()
    device.tables[table].defaults[name] = definition["default"]
    device.tables[table].quoted_names |= {name} if definition["type"] == "text" else set()
    device.tables[table].attrs[name] = definition["default"]
    assert not any(name in line for line in device.table_lines(table))  # show omits the default
    runtime = runtime_for(tmp_path, device)
    record, before = approved(runtime, ask(table, "-", "update", {name: value}, endpoint_impact="-"))
    assert name not in record["plan"]["predicted"]["before"]
    assert record["plan"]["inverse"] == ["config " + table, set_default, "end"]
    restored = undone(runtime, record, before)
    assert restored["plan"]["commands"] == record["plan"]["inverse"]
    assert runtime.lab.device.tables[table].attrs[name] == definition["default"]


# ------------------------------------------------------------------------------------------- r3 finding 2: rest digest

def test_an_empty_registered_section_keeps_the_rest_digest_of_other_tables(registered):
    # the stored show prints an empty router static6 wrapper; a plan for firewall address made before router static6
    # was registered stays valid on the identical snapshot once it is registered (verify and the recovery side)
    device = lab()
    device.tables[ROUTE6].print_empty = True
    raw = device.snapshot().encode()
    assert b"\nconfig router static6\nend\n" in raw
    registered({"fortios_tab_services": {}, "fortios_tab_policy": {}, "fortios_tab_ipv6": {}})
    baseline = engine.build_plan("fortios", raw, parse_request(request_bytes(key="a1r-new-host")))
    digests = {(table, key): fortios.Snapshot(raw.decode()).rest_digest(table, key)
               for table, key in (("firewall address", "a1r-new-host"), (GROUP, "a1r-web"))}
    registered()
    assert fortios.Snapshot(raw.decode()).entries(ROUTE6) == {}
    fresh = engine.build_plan("fortios", raw, parse_request(request_bytes(key="a1r-new-host")))
    assert fresh["rest_sha256"] == baseline["rest_sha256"]
    checked = engine.verify(baseline, raw, expect="before")
    assert checked["result"] == "match", checked
    assert engine.observed_side(baseline, raw) == "before"
    for (table, key), digest in digests.items():
        assert fortios.Snapshot(raw.decode()).rest_digest(table, key) == digest, table
    # the target table itself still compares without its empty wrapper (r2 finding 3)
    shown = fortios.Snapshot(raw.decode()).rest_digest(ROUTE6, "1")
    device.tables[ROUTE6].print_empty = False
    assert fortios.Snapshot(device.snapshot()).rest_digest(ROUTE6, "1") == shown


# ------------------------------------------------------------------------------------------- r2 finding 4: hook

def test_route6_prechecks_run_through_the_table_hook_with_ipv4_management(registered, runtime_for, tmp_path):
    protected = {"system interface": ["wan1"]}
    route = {"dst": "2001:db8:a1::/48", "blackhole": "enable"}
    snapshot = fortios.Snapshot(lab().snapshot())
    # the arguments the hook has (no device address): rule (f) runs in exec_fortios.plan_prechecks
    fortios.route6_prechecks(snapshot, "1", None, route, protected)
    registered(hooks(**{ROUTE6: TableHooks(ROUTE6, prechecks=fortios.route6_hook)}))
    item, parsed = fortios_tables.hooks(ROUTE6), profiles.parse_profile(PROFILES[ROUTE6])
    assert item.prechecks(snapshot, parsed, "create", "1", None, route, protected, None, False) == []
    with pytest.raises(Rejected) as caught:
        item.prechecks(snapshot, parsed, "create", "1", None, {**route, "dst": "::/0"}, protected, None, False)
    assert caught.value.reason_codes == ["fortios_route6_protected"]
    device = lab()
    runtime = runtime_for(tmp_path, device)
    assert fortios.management_ipv4(runtime.config.devices["lab"].address, runtime.config.devices["lab"].check_address)
    record, before = approved(runtime, ask(ROUTE6, "1", "create", route))
    undone(runtime, record, before)
    written = len(runtime.lab.device.applied_blocks)
    for key, state in (("2", {**route, "dst": "::/0"}), ("3", {"dst": "2001:db8:a3::/48", "device": "wan1"})):
        preview = execute.preview(runtime, "lab", ask(ROUTE6, key, "create", state))
        assert preview["result"] == "rejected" and preview["reason_codes"] == ["fortios_route6_protected"], preview
    assert len(runtime.lab.device.applied_blocks) == written


# ------------------------------------------------------------------------------------------- nested ip-range (5c)

def test_first_range_create_and_last_range_delete_with_undo(registered, runtime_for, tmp_path):
    captured = fortios.shown_registered((FIXTURES / "dhcp-server-empty.txt").read_text(), RANGE, "3:1")
    device = lab()
    device.tables[SERVER].objects["3"]["children"]["ip-range"].clear()
    assert "config ip-range" not in device.snapshot()  # FortiOS does not print an empty child section
    runtime = runtime_for(tmp_path, device)
    record, before = approved(runtime, ask(RANGE, "3:1", "create", captured, endpoint_impact="3:1"))
    assert record["plan"]["commands"][:4] == ["config system dhcp server", "edit 3", "config ip-range", "    edit 1"]
    assert record["plan"]["endpoint_impact"] == "3:1"
    created = runtime.lab.device
    assert created.tables[SERVER].objects["3"]["children"]["ip-range"] == {"1": captured}
    assert "fortios_object_uuid" not in record
    changed = runtime.lab.device
    changed.tables[SERVER].objects["3"]["children"]["ip-range"]["1"]["end-ip"] = "192.0.2.200"
    runtime.lab.store(changed)
    preview = execute.preview_undo(runtime, record["change_id"], "Restore the original empty address range")
    assert preview["result"] == "rejected", preview
    assert "the object differs from the state the undo was planned against" in preview["reasons"]
    assert runtime.lab.device.applied_blocks == created.applied_blocks
    runtime.lab.store(created)
    undone(runtime, record, before)
    current = runtime.lab.device
    assert "config ip-range" not in current.snapshot()
    current.tables[SERVER].objects["3"]["children"]["ip-range"]["1"] = captured
    runtime.lab.store(current)
    record, before = approved(runtime, ask(RANGE, "3:1", "delete", {}, endpoint_impact="3:1"))
    assert "config ip-range" not in runtime.lab.device.snapshot()
    undone(runtime, record, before)          # the undo of the last delete creates the first range


def test_range_rest_digest_ignores_an_empty_range_section_only():
    with_range = prompt.cleaned((FIXTURES / "dhcp-server-empty.txt").read_text(), "fortios")
    header = "#config-version=FGT60F-7.6.8-FW-build3744-260420:opmode=1:vdom=0:user=netops-rw\n"
    start = with_range.index("        config ip-range")
    end = with_range.index("        end\n", start) + len("        end\n")
    without = with_range[:start] + with_range[end:]
    empty = with_range[:start] + "        config ip-range\n        end\n" + with_range[end:]
    digest = fortios.Snapshot(header + without).rest_digest(RANGE, "3:1")
    assert fortios.Snapshot(header + empty).rest_digest(RANGE, "3:1") == digest
    assert fortios.Snapshot(header + with_range).rest_digest(RANGE, "3:1") == digest
    assert fortios.Snapshot(header + with_range).rest_digest(RANGE, "3:2") != digest


def test_the_child_sections_of_a_registered_object_stay_out_of_its_state_and_in_the_rest(registered, runtime_for, tmp_path):
    device = lab()
    runtime = runtime_for(tmp_path, device)
    record, before = approved(runtime, ask(SERVER, "3", "update", {"timezone-option": "disable"}, endpoint_impact="3"))
    assert "ip-range" not in json.dumps(record["plan"]["predicted"])
    device = runtime.lab.device
    assert device.tables[SERVER].objects["3"]["children"]["ip-range"]  # the range stays
    snapshot = fortios.Snapshot(device.snapshot())
    digest = snapshot.rest_digest(SERVER, "3")
    device.tables[SERVER].objects["3"]["children"]["ip-range"]["1"]["end-ip"] = "192.0.2.200"
    assert fortios.Snapshot(device.snapshot()).rest_digest(SERVER, "3") != digest
    undone(runtime, record, before)


# ------------------------------------------------------------------------------------------- endpoint_impact

def test_endpoint_impact_names_the_key_in_the_stored_plan_through_undo(registered, runtime_for, tmp_path):
    device = lab()
    runtime = runtime_for(tmp_path, device)
    record, before = approved(runtime, ask(SYSLOG, "-", "update", {"server": "192.0.2.81"}, endpoint_impact="-"))
    assert record["plan"]["endpoint_impact"] == "-"
    assert any("Explicit endpoint impact accepted for log syslogd setting -" in line
               for line in record["plan"]["prechecks"])
    assert engine.verify(record["plan"], runtime.lab.device.snapshot().encode())["result"] == "match"
    undone(runtime, record, before)


def test_endpoint_impact_is_refused_for_a_registered_table_without_impact(registered, runtime_for, tmp_path):
    device = lab()
    preview = execute.preview(runtime_for(tmp_path, device), "lab",
                              ask(GROUP, "a1r-web", "create", {"member": ["HTTP"]}, endpoint_impact="a1r-web"))
    assert preview["result"] == "rejected" and "endpoint_impact is not supported" in " ".join(preview["reasons"])


# ------------------------------------------------------------------------------------------- FortiOS 8.0.2 webhook

@pytest.mark.parametrize("verified", [(), ("create",), ("delete",), ("update",)])
def test_create_without_a_verified_delete_is_refused_before_any_write(registered, runtime_for, tmp_path, verified):
    registered(hooks(**{GROUP: TableHooks(GROUP, rest_path="firewall.service/group", rest_key="name",
                                          rest_verified=frozenset(verified))}))
    device = lab(webhook=True)
    runtime = runtime_for(tmp_path, device)
    request_ = ask(GROUP, "a1r-web", "create", {"member": ["HTTP", "HTTPS"]})
    preview = execute.preview(runtime, "lab", request_)
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["safeguard_no_rest_inverse"]
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", request_, expected_plan_sha256="0" * 64)
    assert caught.value.reason_codes == ["safeguard_no_rest_inverse"]
    device = runtime.lab.device
    assert device.applied_blocks == []
    assert not device.tables[GROUP].objects and not device.api_users and not device.webhooks


def test_a_verified_pair_is_planned_on_8_0_2(registered, runtime_for, tmp_path):
    device = lab(webhook=True)
    runtime = runtime_for(tmp_path, device)
    preview = execute.preview(runtime, "lab", ask(GROUP, "a1r-web", "create", {"member": ["HTTP", "HTTPS"]}))
    assert preview["result"] == "ready", preview
    assert not runtime.lab.device.applied_blocks
    assert any("8.0.2 build0251" in json.dumps(value) for value in preview.values())


def test_singletons_are_refused_on_8_0_2(registered, runtime_for, tmp_path):
    device = lab(webhook=True)
    preview = execute.preview(runtime_for(tmp_path, device), "lab",
                              ask(DNS, "-", "update", {"secondary": "192.0.2.55"}, endpoint_impact="-"))
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["safeguard_no_rest_inverse"]


def test_service_group_of_32_long_members_is_refused_on_8_0_2_before_any_write(registered, runtime_for, tmp_path):
    # design A 14.2: the undo of the create (a delete) returns the group by a POST whose body exceeds 1023 bytes
    members = ["svc-%018d" % number for number in range(32)]
    assert all(len(member) == 22 for member in members)
    device = lab(webhook=True)
    runtime = runtime_for(tmp_path, device)
    request_ = ask(GROUP, "a1r-long", "create", {"member": members})
    preview = execute.preview(runtime, "lab", request_)
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["safeguard_no_rest_inverse"]
    assert "request body limit" in " ".join(preview["reasons"])
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", request_, expected_plan_sha256="0" * 64)
    assert caught.value.reason_codes == ["safeguard_no_rest_inverse"]
    device = runtime.lab.device
    assert device.applied_blocks == [] and not device.tables[GROUP].objects and not device.api_users


def test_the_original_webhook_tables_stay_allowed_on_8_0_2(registered, runtime_for, tmp_path):
    # regression of finding 8: webhook_refusal of the tables 1.0.12 verified does not depend on the operation
    loaded = profiles.load_profiles()
    for table in sorted(fortios.ORIGINAL_REST):
        for op in (None, "create", "update", "delete", "move"):
            assert fortios.webhook_refusal(loaded[("fortios", table)], "8.0.2 build0251", op) is None, (table, op)
    assert fortios.ORIGINAL_REST == frozenset((
        "firewall policy", "firewall address", "firewall addrgrp", "firewall service custom", fortios.DHCP_TABLE,
        fortios.DNS_TABLE, "vpn ipsec phase2-interface", "firewall vip", "firewall ippool"))
    assert fortios.webhook_refusal(loaded[("fortios", "system interface")], "8.0.2 build0251", "update") is not None
    device = lab(webhook=True)
    preview = execute.preview(runtime_for(tmp_path, device), "lab", request(request_id="a1r-original"))
    assert preview["result"] == "ready", preview


def test_doctor_lists_only_the_verified_pairs_on_8_0_2(registered):
    registered(hooks(**{GROUP: TableHooks(GROUP, rest_path="firewall.service/group", rest_key="name",
                                          rest_verified=frozenset(("update",)))}))
    operations = readiness._operations("fortios", "8.0.2 build0251")
    assert operations[GROUP].startswith("update (untested on 8.0.2 build0251)")
    assert "create delete refused on 8.0.2 build0251" in operations[GROUP]
    assert operations[DNS].startswith("refused on 8.0.2 build0251") and operations[ROUTE6].startswith("refused")
    assert readiness._operations("fortios", TESTED)[GROUP] == "create update delete"
    # an incomplete pair (create without delete) leaves no operation: the table is refused, its operations not listed
    registered(hooks(**{GROUP: TableHooks(GROUP, rest_path="firewall.service/group", rest_key="name",
                                          rest_verified=frozenset(("create",)))}))
    refused = readiness._operations("fortios", "8.0.2 build0251")[GROUP]
    assert refused.startswith("refused on 8.0.2 build0251") and "safeguard_no_rest_inverse" in refused
    assert "create" not in refused


# ------------------------------------------------------------------------------------------- secrets unchanged

# snapshot_sha256 and rest_sha256 of the secret canary (ENC values, an SNMP community in plain text) computed on
# dev-1.0.13 46e961f before A1-R: wave A does not change the redaction, the hash or the serialisation (design A 2)
CANARY_DIGESTS = {
    "snapshot_sha256": "8b3742add4aa1b9e17afd3bc80c08b1253d432fd657a8121e0516a94580cf3af",
    "plan_rest_sha256": "fba8b86e3e6d9dcfe9551a5c358e7ee8ac0778d9d2d3c2ac0faf0b51999eac7e",
    ("firewall address", "office-net"): "bd2256223198b80c0a8bcf9d5b25947e4ff0520a746121072cf545b66d744bb0",
    ("system snmp community", "1"): "db93f62b6dd6705c0ad287edb927186c1f5b8f96378eff7b6c0f2f5e9c504f50",
    ("system admin", "auditor"): "356ed3aa9f55537843bb8c64603b7d1aff0f1bdd4f467652efa3f0e97143b303",
    (fortios.DHCP_TABLE, "1:1"): "fba8b86e3e6d9dcfe9551a5c358e7ee8ac0778d9d2d3c2ac0faf0b51999eac7e",
    ("firewall policy", "1"): "b00d58d4eadcf010bf727ca8d02c3ba7e5208aa7eb11fe753bf5ecb10c59fb7e",
}


@pytest.mark.parametrize("with_registry", [False, True])
def test_the_hashes_of_a_configuration_with_secrets_are_unchanged(request, with_registry):
    if with_registry:
        request.getfixturevalue("registered")
    header = "#config-version=FGT60F-7.6.8-FW-build3744-260420:opmode=1:vdom=0:user=netops-rw\n"
    raw = (header + CANARY.read_text()).encode()
    assert b"ENC CANARY-SECRET" in raw and b'set name "CANARY-SECRET-05"' in raw
    plan = engine.build_plan("fortios", raw, parse_request(request_bytes(key="canary-new")))
    assert hashlib.sha256(raw).hexdigest() == plan["snapshot_sha256"] == CANARY_DIGESTS["snapshot_sha256"]
    assert plan["rest_sha256"] == CANARY_DIGESTS["plan_rest_sha256"]
    snapshot = fortios.Snapshot(raw.decode())
    for (table, key), digest in ((item, value) for item, value in CANARY_DIGESTS.items() if isinstance(item, tuple)):
        assert snapshot.rest_digest(table, key) == digest, (table, key)


# ------------------------------------------------------------------------------------------- framework helpers

@pytest.mark.parametrize(("kind", "value", "expected"), [
    ("ipv6-network", "2001:DB8:A1:0::/48", "2001:db8:a1::/48"), ("ipv6-network", "::/0", "::/0"),
    ("ipv6-address", "2001:db8:0:0::1", "2001:db8::1"),
])
def test_ipv6_attribute_types(kind, value, expected):
    parsed = profiles.parse_profile(profile(ROUTE6, {"value": attribute(kind)}))
    assert kind in profiles.ATTRIBUTE_TYPES
    from netops_admin.request import canonical_value
    assert canonical_value(parsed.attributes["value"], value, "fortios") == expected


@pytest.mark.parametrize(("kind", "value"), [
    ("ipv6-network", "2001:db8::1/48"), ("ipv6-network", "2001:db8::"), ("ipv6-network", "192.0.2.0/24"),
    ("ipv6-address", "ff02::1"), ("ipv6-address", "::"), ("ipv6-address", "2001:db8::/64"), ("ipv6-address", 7),
])
def test_ipv6_attribute_types_refuse(kind, value):
    parsed = profiles.parse_profile(profile(ROUTE6, {"value": attribute(kind)}))
    from netops_admin.request import canonical_value
    with pytest.raises(Rejected):
        canonical_value(parsed.attributes["value"], value, "fortios")


def test_opt_in_tables_of_1_0_13():
    from netops_admin import config
    assert {DNS, ROUTE6} <= set(config.OPT_IN_TABLES) and ROUTE6 in config.PATH_TABLES


def test_policy_use_generalizes_group_policy_use():
    device = lab()
    device.policies = {"1": {"dstaddr": "srv-web", "service": "a1r-web"}, "2": {"service": "a1r-web", "status": "disable"},
                       "3": {"service": "HTTP"}}
    snapshot = fortios.Snapshot(device.snapshot())
    assert fortios.policy_use(snapshot, {"A1R-WEB"}, ("service",), {"firewall policy": ["2"]}) == (["2"], ["1"])
    assert fortios.group_policy_use(snapshot, "srv-web", None) == ([], ["1"])


def test_dhcp_server_protected_and_route6_prechecks():
    device = lab()
    device.interfaces = ["port1", "wan1", "quarantine"]
    snapshot = fortios.Snapshot(device.snapshot())
    protected = {"system interface": ["wan1"]}
    fortios.dhcp_server_protected(snapshot, {"interface": "quarantine"}, None, protected)
    for state in ({"interface": "wan1"}, {"interface": "missing"}):
        with pytest.raises(Rejected) as caught:
            fortios.dhcp_server_protected(snapshot, state, None, protected)
        assert caught.value.reason_codes == ["fortios_service_scope"]
    route = {"dst": "2001:db8:a1::/48", "blackhole": "enable"}
    fortios.route6_prechecks(snapshot, "1", None, route, protected, address="192.0.2.1")
    for state, kwargs in (({"dst": "::/0", "blackhole": "enable"}, {}), ({"dst": "2001:db8::/32", "device": "wan1"}, {}),
                          ({"dst": "2001:db8::/32"}, {}), ({**route, "device": "port1"}, {}),
                          (route, {"address": "fw.example.invalid"}), (route, {"check_address": "2001:db8::1"})):
        with pytest.raises(Rejected) as caught:
            fortios.route6_prechecks(snapshot, "1", None, state, protected, **{"address": "192.0.2.1", **kwargs})
        assert caught.value.reason_codes == ["fortios_route6_protected"]
