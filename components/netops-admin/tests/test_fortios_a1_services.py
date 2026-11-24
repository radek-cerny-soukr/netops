"""1.0.13 A1-S: the FortiOS service tables (system dhcp server, system dhcp server/ip-range, system dns, log syslogd
setting) registered in fortios_tab_services, driven through the real path of the registry tests: execute (preview,
apply, undo, recover) -> exec_fortios -> the production access.DeviceAccess over the OpenSSH test client
(fortinet_ssh_fixture) -> the simulated lab FortiGate-60F (fake_fortios_a1, the shapes of fixtures/fortios_a1). The
parser, the Snapshot, the planning, rest_digest, the safeguard rendering, the journal and the audit are real; only the
device and its clock are simulated.
"""
from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from fake_fortios_a1 import DNS, RANGE, SERVER, SYSLOG, VLAN, FakeFortiOSA1, FakeFortiOSA1Webhook
from fake_fortios_tables import Table
from test_fortios_tables_registry import (approved, ask, audit_events, readback_refused, runtime_for,  # noqa: F401
                                          ssh_sessions, undone)

from netops_admin import engine, execute, fortios, fortios_tab_services, fortios_tables, profiles, readiness
from netops_admin.errors import Rejected, SnapshotRejected
from netops_core import prompt

A1 = (SERVER, RANGE, DNS, SYSLOG)
FIXTURES = Path(__file__).parent / "fixtures"
LAB = FIXTURES / "fortios_a1"
EMPTY_SERVER = FIXTURES / "fortios_7_6_8_dhcp_dns" / "dhcp-server-empty.txt"
CONFLICT, IN_USE = "fortios_dhcp_range_conflict", "fortios_dhcp_server_in_use"
SCOPE, IMPACT = "fortios_service_scope", "fortios_service_impact_required"
# the profiles measured end to end on the lab FortiGate-60F (shipped with measured true)
MEASURED_LIVE = (SERVER, RANGE, DNS, SYSLOG)
PREVIEW, READBACK = "fortios_service_preview_required", "fortios_service_readback_unreadable"


@pytest.fixture
def a1(monkeypatch):
    """The shipped registry and profiles; a profile still waiting for its live run is enabled for the test (the
    measured flag only gates the product, the path under test is the same)."""
    fortios_tables.reset()
    loaded = {key: replace(item, measured=True) if key[0] == "fortios" and key[1] in A1 else item
              for key, item in profiles.load_profiles().items()}
    for module in (profiles, execute, readiness):
        monkeypatch.setattr(module, "load_profiles", lambda: dict(loaded))
    yield loaded
    fortios_tables.reset()


def lab(**options):
    return FakeFortiOSA1(**options)


def rejected(runtime, request_, code):
    preview = execute.preview(runtime, "lab", request_)
    assert preview["result"] == "rejected" and preview["reason_codes"] == [code], preview
    return preview


def server(device, sid="7"):
    return device.tables[SERVER].objects[sid]


def captured(device, name):
    """The simulated lab FortiGate with the tables a lab capture of fixtures/fortios_a1 shows replaced by that capture
    (the real output of the check account, parsed by the production parser)."""
    header = "#config-version=FGT60F-7.6.8-FW-build3744-260420:opmode=1:vdom=0:user=x\n"
    parsed = fortios.Snapshot(header + (LAB / name).read_text())
    for table in (SERVER, DNS, SYSLOG):
        for key, entry in (parsed.entries(table) or {}).items():
            attrs = {attr: value.value() for attr, value in entry.attrs.items()}
            if table != SERVER:
                device.tables[table].attrs = attrs
                continue
            section = entry.section("ip-range")
            ranges = {rid: {attr: value.value() for attr, value in node.attrs.items()}
                      for rid, node in ({} if section is None else section.entries).items()}
            device.tables[SERVER].objects[key] = {"attrs": attrs, "children": {"ip-range": ranges} if ranges else {}}
    return device


# ------------------------------------------------------------------------------------------- registration

def test_the_services_register_four_tables_with_their_codes():
    fortios_tables.reset()
    assert set(fortios_tab_services.TABLES) == set(A1) <= fortios_tables.PLANNED_TABLES
    registry = fortios_tables.registry()
    assert {table: registry[table].kind for table in A1} == {
        SERVER: "object", RANGE: "nested", DNS: "singleton", SYSLOG: "singleton"}
    assert all(registry[table].preview_code == PREVIEW and registry[table].readback_code == READBACK
               and registry[table].impact for table in A1)
    assert registry[RANGE].parent == (SERVER, "ip-range") and fortios.NESTED[RANGE] == (SERVER, "ip-range")
    assert registry[SERVER].child_sections == ("ip-range", "reserved-address")
    assert {"ddns-*", "options", "vci-*", "tftp-server", "filename"} == set(registry[SERVER].excluded)
    assert {"ssl-certificate", "dns-over-tls", "server-hostname", "fqdn-*", "source-ip"} == set(registry[DNS].excluded)
    assert {"certificate", "enc-algorithm", "ssl-min-proto-version", "custom-field-name",
            "interface"} == set(registry[SYSLOG].excluded)
    # no REST inverse is verified on 8.0.2 yet (design A 5.1): every A1 table is refused there
    assert not any(registry[table].rest_verified for table in A1)
    assert {registry[table].rest_permission for table in A1} == {"netgrp", "sysgrp", "loggrp"}
    fortios_tables.reset()


def test_the_shipped_profiles_hold_the_measured_shape():
    loaded = profiles.load_profiles()
    dhcp, rng, dns, syslog = (loaded[("fortios", table)] for table in A1)
    for item in (dhcp, rng, dns, syslog):
        assert item.versions == ("7.6.8 build3744",) and item.exact_versions and item.provisional
        assert not item.isolated_update
        fortios_tables.check_profile(item)
    # design A 14.1: timezone-option (shown as default on the lab servers) is a managed attribute
    assert dhcp.attributes["timezone-option"].default == "disable"
    assert dhcp.attributes["timezone-option"].pattern.fullmatch("default")
    assert not dhcp.attributes["timezone-option"].pattern.fullmatch("specify")
    assert dhcp.attributes["status"].default == "enable" and dhcp.create_values == {"status": "disable"}
    assert dhcp.attributes["dns-service"].default == dhcp.attributes["ntp-service"].default == "specify"
    assert dhcp.fixed == {"server-type": "regular"} and not dhcp.attributes["interface"].update
    assert set(rng.attributes) == {"start-ip", "end-ip"}
    assert dns.ops == syslog.ops == ("update",) and dns.implicit_keys and syslog.implicit_keys
    assert dns.attributes["protocol"].pattern.fullmatch("cleartext")
    assert not dns.attributes["protocol"].pattern.fullmatch("dot")
    assert not syslog.attributes["mode"].pattern.fullmatch("reliable")
    # measured live on FortiOS 7.6.8: FortiOS asks to confirm another port on end, Admin never updates port or mode
    assert not syslog.attributes["port"].update and not syslog.attributes["mode"].update
    for item in (dhcp, rng, dns, syslog):
        assert not fortios_tables.excluded_names(fortios_tables.hooks(item.table), item.attributes), item.table


# ------------------------------------------------------------------------------------------- DHCP (live sequence)

def test_new_dhcp_service_on_a_vlan_in_three_steps_and_undo_in_the_opposite_order(a1, runtime_for, tmp_path):
    # design A 4: server status disable -> ip-range -> status enable with impact; undo in the opposite order
    device = lab(server=False)
    runtime = runtime_for(tmp_path, device)
    start = device.snapshot()
    created, before_create = approved(runtime, ask(SERVER, "7", "create", {
        "interface": VLAN, "status": "disable", "netmask": "255.255.255.0", "default-gateway": "192.0.2.1"}))
    assert created["plan"]["commands"][:2] == ["config system dhcp server", '    edit "7"']
    assert created["plan"]["inverse"] == ["config system dhcp server", '    delete "7"', "end"]
    assert "endpoint_impact" not in created["plan"]  # a disabled new server serves no client
    current = runtime.lab.device
    assert server(current)["attrs"]["status"] == "disable" and not server(current)["children"]
    ranged, before_range = approved(runtime, ask(RANGE, "7:1", "create",
                                                 {"start-ip": "192.0.2.100", "end-ip": "192.0.2.150"}))
    assert ranged["plan"]["predicted"] == {"before": None, "after": {"start-ip": "192.0.2.100", "end-ip": "192.0.2.150"}}
    enabled, before_enable = approved(runtime, ask(SERVER, "7", "update", {"status": "enable"}, endpoint_impact="7"))
    assert enabled["plan"]["endpoint_impact"] == "7"
    assert enabled["plan"]["commands"] == ["config system dhcp server", '    edit "7"', '        set status "enable"',
                                           "    next", "end"]
    assert "status" not in enabled["plan"]["predicted"]["after"]  # enable is the default show omits
    assert "ip-range" not in json.dumps(enabled["plan"]["predicted"])
    undone(runtime, enabled, before_enable)
    undone(runtime, ranged, before_range)
    undone(runtime, created, before_create)
    assert runtime.lab.device.snapshot() == start


def test_a_change_of_status_alone_passes_over_the_measured_server_shape(a1, runtime_for, tmp_path):
    # design A 14.1 regression: the lab server 3 as shown (dhcp-server-empty.txt: timezone-option default, one range)
    shown = prompt.cleaned(EMPTY_SERVER.read_text(), "fortios")
    parsed = fortios.Snapshot("#config-version=FGT60F-7.6.8-FW-build3744-260420:opmode=1:vdom=0:user=x\n" + shown)
    entry = parsed.entries(SERVER)["3"]
    device = lab(server=False)
    device.interface_rows["quarantine"] = ("192.0.2.1 255.255.255.0", "static", "up")
    del device.interface_rows[VLAN]
    attrs = {name: attr.value() for name, attr in entry.attrs.items()}
    assert attrs["timezone-option"] == "default"
    ranges = {rid: {name: attr.value() for name, attr in node.attrs.items()}
              for rid, node in entry.section("ip-range").entries.items()}
    device.tables[SERVER].objects["3"] = {"attrs": attrs, "children": {"ip-range": ranges}}
    simulated = fortios.Snapshot(device.snapshot())
    assert simulated.entry_state(simulated.entries(SERVER)["3"]) == parsed.entry_state(entry)
    runtime = runtime_for(tmp_path, device)
    record, before = approved(runtime, ask(SERVER, "3", "update", {"status": "disable"}, endpoint_impact="3"))
    assert record["plan"]["predicted"]["before"]["timezone-option"] == "default"
    assert record["plan"]["predicted"]["after"]["status"] == "disable"
    undone(runtime, record, before)


def test_enabling_or_changing_an_enabled_server_needs_endpoint_impact(a1, runtime_for, tmp_path):
    device = lab()
    runtime = runtime_for(tmp_path, device)
    rejected(runtime, ask(SERVER, "7", "update", {"status": "enable"}), IMPACT)
    record, before = approved(runtime, ask(SERVER, "7", "update", {"status": "enable"}, endpoint_impact="7"))
    for changes in ({"lease-time": 3600}, {"status": "disable"}, {"default-gateway": "192.0.2.254"}):
        rejected(runtime, ask(SERVER, "7", "update", changes), IMPACT)
    rejected(runtime, ask(RANGE, "7:1", "update", {"end-ip": "192.0.2.140"}), IMPACT)
    rejected(runtime, ask(RANGE, "7:2", "create", {"start-ip": "192.0.2.160", "end-ip": "192.0.2.170"}), IMPACT)
    # the undo of the stored plan returns without a new confirmation (the original change carried it)
    undone(runtime, record, before)
    # a disabled server takes a change without impact
    record, before = approved(runtime, ask(SERVER, "7", "update", {"lease-time": 3600}))
    undone(runtime, record, before)


@pytest.mark.parametrize(("start", "end", "fragment"), [
    ("198.51.100.10", "198.51.100.20", "outside the subnet"),
    ("192.0.2.200", "198.51.100.5", "outside the subnet"),
    ("192.0.2.0", "192.0.2.20", "network address"),
    ("192.0.2.240", "192.0.2.255", "broadcast address"),
    ("192.0.2.1", "192.0.2.20", "interface address"),
    ("192.0.2.140", "192.0.2.160", "overlaps range 1 of DHCP server 7"),
    ("192.0.2.30", "192.0.2.20", "start-ip <= end-ip"),
])
def test_a_range_outside_the_subnet_or_overlapping_is_refused(a1, runtime_for, tmp_path, start, end, fragment):
    device = lab()
    runtime = runtime_for(tmp_path, device)
    preview = rejected(runtime, ask(RANGE, "7:2", "create", {"start-ip": start, "end-ip": end}), CONFLICT)
    assert fragment in " ".join(preview["reasons"])
    assert not runtime.lab.device.applied_blocks


def test_a_range_holding_the_gateway_or_a_vip_or_overlapping_another_server_is_refused(a1, runtime_for, tmp_path):
    device = lab()
    server(device)["attrs"]["default-gateway"] = "192.0.2.254"
    device.snapshot_extra = ["config firewall vip", '    edit "a1-vip"', "        set extip 192.0.2.60",
                             "        set mappedip \"198.51.100.60\"", "    next", "end",
                             "config firewall ippool", '    edit "a1-pool"', "        set startip 192.0.2.70",
                             "        set endip 192.0.2.71", "    next", "end"]
    # a second server on the same interface: its ranges count for the overlap check
    device.tables[SERVER].objects["8"] = {"attrs": {"status": "disable", "netmask": "255.255.255.0",
                                                    "default-gateway": "192.0.2.254", "interface": VLAN},
                                          "children": {"ip-range": {"1": {"start-ip": "192.0.2.180",
                                                                          "end-ip": "192.0.2.190"}}}}
    runtime = runtime_for(tmp_path, device)
    for (start, end), fragment in ((("192.0.2.250", "192.0.2.254"), "default gateway"),
                                   (("192.0.2.55", "192.0.2.65"), "VIP a1-vip"),
                                   (("192.0.2.71", "192.0.2.80"), "IP pool a1-pool"),
                                   (("192.0.2.185", "192.0.2.195"), "DHCP server 8")):
        preview = rejected(runtime, ask(RANGE, "7:2", "create", {"start-ip": start, "end-ip": end}), CONFLICT)
        assert fragment in " ".join(preview["reasons"]), preview
    # a gateway moved into an existing range of the server
    preview = rejected(runtime, ask(SERVER, "7", "update", {"default-gateway": "192.0.2.120"}), CONFLICT)
    assert "default gateway" in " ".join(preview["reasons"])


def test_a_netmask_beyond_the_interface_or_one_leaving_the_range_outside_is_refused(a1, runtime_for, tmp_path):
    device = lab()
    runtime = runtime_for(tmp_path, device)
    rejected(runtime, ask(SERVER, "7", "update", {"netmask": "255.255.0.0"}), CONFLICT)
    preview = rejected(runtime, ask(SERVER, "7", "update", {"netmask": "255.255.255.128"}), CONFLICT)
    assert "outside the subnet" in " ".join(preview["reasons"])


def test_a_server_in_use_or_its_last_range_of_an_enabled_server_is_not_deleted(a1, runtime_for, tmp_path):
    device = lab()
    runtime = runtime_for(tmp_path, device)
    preview = rejected(runtime, ask(SERVER, "7", "delete", {}), IN_USE)
    assert "ip-range" in " ".join(preview["reasons"])
    current = runtime.lab.device
    server(current)["attrs"]["status"] = "enable"
    runtime.lab.store(current)
    rejected(runtime, ask(RANGE, "7:1", "delete", {}, endpoint_impact="7:1"), IN_USE)
    current = runtime.lab.device
    server(current)["children"]["ip-range"].clear()
    runtime.lab.store(current)
    preview = rejected(runtime, ask(SERVER, "7", "delete", {}), IN_USE)
    assert "disabled" in " ".join(preview["reasons"])
    # disabled and without ranges: deleted, the undo creates it again
    current = runtime.lab.device
    server(current)["attrs"]["status"] = "disable"
    runtime.lab.store(current)
    record, before = approved(runtime, ask(SERVER, "7", "delete", {}))
    assert "7" not in runtime.lab.device.tables[SERVER].objects
    undone(runtime, record, before)


def test_the_last_range_of_a_disabled_server_is_deleted_and_restored(a1, runtime_for, tmp_path):
    device = lab()
    runtime = runtime_for(tmp_path, device)
    record, before = approved(runtime, ask(RANGE, "7:1", "delete", {}))
    assert "config ip-range" not in runtime.lab.device.snapshot().split('edit "7"')[-1].split("next")[0] or \
        not server(runtime.lab.device)["children"]["ip-range"]
    undone(runtime, record, before)


def test_a_server_on_a_protected_or_unknown_interface_is_refused(a1, runtime_for, tmp_path):
    device = lab()
    runtime = runtime_for(tmp_path, device)
    rejected(runtime, ask(SERVER, "9", "create", {"interface": "wan1", "status": "disable", "netmask": "255.255.255.0",
                                                   "default-gateway": "192.0.2.1"}), SCOPE)
    rejected(runtime, ask(SERVER, "9", "create", {"interface": "missing0", "status": "disable",
                                                   "netmask": "255.255.255.0", "default-gateway": "192.0.2.1"}), SCOPE)


@pytest.mark.parametrize(("op", "changes"), [
    ("delete", {}),
    ("update", {"start-ip": "192.0.2.160", "end-ip": "192.0.2.170"}),
])
def test_a_range_change_whose_undo_would_restore_a_vip_conflict_is_refused(a1, runtime_for, tmp_path, op, changes):
    # review finding 3 over the lab capture dhcp-server-one-range.txt (disabled server 7, range 7:1
    # .100-.150) and a VIP at .120 made by hand: the undo keeps every conflict check, so the apply checks the range its
    # undo would restore as well and refuses before any write; Admin never confirms a change it cannot return
    device = captured(lab(), "dhcp-server-one-range.txt")
    device.snapshot_extra = ["config firewall vip", '    edit "a1-vip"', "        set extip 192.0.2.120",
                             '        set mappedip "198.51.100.120"', "    next", "end"]
    runtime = runtime_for(tmp_path, device)
    preview = rejected(runtime, ask(RANGE, "7:1", op, changes), CONFLICT)
    assert "undo" in " ".join(preview["reasons"]) and "VIP a1-vip" in " ".join(preview["reasons"]), preview
    assert not runtime.lab.device.applied_blocks
    # without the conflict the same change is confirmed and its undo restores the captured range
    current = runtime.lab.device
    current.snapshot_extra = []
    runtime.lab.store(current)
    record, before = approved(runtime, ask(RANGE, "7:1", op, changes))
    undone(runtime, record, before)


# ------------------------------------------------------------------------------------------- DHCP excluded attributes

@pytest.mark.parametrize("excluded", [
    {"ddns-update": "enable", "ddns-key": "ENC c2VjcmV0LWNhbmFyeQ=="},
    {"vci-match": "enable", "vci-string": "c2VjcmV0LWNhbmFyeQ"},
    {"filename": "c2VjcmV0LWNhbmFyeQ.bin"},
])
def test_an_excluded_attribute_refuses_status_range_and_overlap_by_name_only(a1, runtime_for, tmp_path, excluded):
    device = lab()
    server(device)["attrs"].update(excluded)
    # a second server on the same VLAN without excluded attributes (the overlap check reads server 7)
    device.tables[SERVER].objects["8"] = {"attrs": {"status": "disable", "netmask": "255.255.255.0",
                                                    "default-gateway": "192.0.2.1", "interface": VLAN},
                                          "children": {}}
    runtime = runtime_for(tmp_path, device)
    for request_ in (ask(SERVER, "7", "update", {"status": "disable"}, endpoint_impact="7"),
                     ask(RANGE, "7:1", "update", {"end-ip": "192.0.2.140"}, endpoint_impact="7:1"),
                     ask(RANGE, "8:1", "create", {"start-ip": "192.0.2.200", "end-ip": "192.0.2.210"}),
                     ask(SERVER, "8", "update", {"lease-time": 3600})):
        preview = rejected(runtime, request_, SCOPE)
        text = json.dumps(preview)
        assert sorted(excluded)[0] in text
        assert "c2VjcmV0LWNhbmFyeQ" not in text and "ENC" not in text and "predicted" not in preview
    assert not runtime.lab.device.applied_blocks


def test_dhcp_options_of_the_lab_shape_refuse_the_server_by_name(a1, runtime_for, tmp_path):
    device = lab()
    runtime = runtime_for(tmp_path, device)
    current = runtime.lab.device
    current.snapshot_extra = []
    runtime.lab.store(current)
    # the server 2 of the lab matches FortiSwitch by VCI: any change of it is refused
    preview = rejected(runtime, ask(SERVER, "2", "update", {"lease-time": 3600}, endpoint_impact="2"), SCOPE)
    assert "vci-match" in " ".join(preview["reasons"]) and "FortiSwitch" not in json.dumps(preview)


def test_an_excluded_attribute_seen_by_the_readback_is_a_mismatch_and_the_safeguard_returns(a1, runtime_for, tmp_path):
    device = lab()
    expected = lab()
    server(expected)["attrs"]["lease-time"] = "3600"
    server(expected)["attrs"]["ddns-key"] = "ENC c2VjcmV0LWNhbmFyeQ=="
    device.check_after_write = {'show system dhcp server "7"': "\n".join(expected.table_lines(SERVER, "7")) + "\n"}
    runtime = runtime_for(tmp_path, device)
    request_ = ask(SERVER, "7", "update", {"lease-time": 3600})
    preview = execute.preview(runtime, "lab", request_)
    assert preview["result"] == "ready", preview
    record = execute.apply(runtime, "lab", request_, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "reverted", record
    assert readback_refused(record) == ["Rejected (%s)" % READBACK]
    # the inverse sets the measured default explicitly (design A 1.5b); show omits it again
    assert server(runtime.lab.device)["attrs"].get("lease-time", "604800") == "604800"
    assert "lease-time" not in "\n".join(runtime.lab.device.table_lines(SERVER, "7"))
    assert "c2VjcmV0LWNhbmFyeQ" not in json.dumps(record)


# ------------------------------------------------------------------------------------------- system dns

def test_dns_secondary_change_and_undo(a1, runtime_for, tmp_path):
    device = lab()
    runtime = runtime_for(tmp_path, device)
    rejected(runtime, ask(DNS, "-", "update", {"secondary": "198.51.100.55"}), IMPACT)
    record, before = approved(runtime, ask(DNS, "-", "update", {"secondary": "198.51.100.55"}, endpoint_impact="-"))
    assert record["plan"]["commands"] == ["config system dns", "    set secondary 198.51.100.55", "end"]
    assert record["plan"]["inverse"] == ["config system dns", "    set secondary 198.51.100.54", "end"]
    assert set(ssh_sessions(runtime)) == {("netops-rw", "192.0.2.1"), ("netops-check", "198.51.100.15")}
    undone(runtime, record, before)


def test_dns_primary_is_never_emptied(a1, runtime_for, tmp_path):
    runtime = runtime_for(tmp_path, lab())
    rejected(runtime, ask(DNS, "-", "update", {"primary": "0.0.0.0"}, endpoint_impact="-"), SCOPE)


def test_dns_primary_added_beside_a_secondary_alone_is_undone_to_the_default(a1, runtime_for, tmp_path):
    # review finding 2 over the lab capture dns-cleartext.txt without its primary (show omits the default
    # 0.0.0.0): an apply never leaves the FortiGate without a primary, the undo returns exactly the state before
    device = captured(lab(), "dns-cleartext.txt")
    del device.tables[DNS].attrs["primary"]
    runtime = runtime_for(tmp_path, device)
    assert "primary" not in runtime.lab.device.snapshot().split("config system dns")[1].split("end")[0]
    rejected(runtime, ask(DNS, "-", "update", {"secondary": "198.51.100.55"}, endpoint_impact="-"), SCOPE)
    record, before = approved(runtime, ask(DNS, "-", "update", {"primary": "198.51.100.45"}, endpoint_impact="-"))
    assert record["plan"]["predicted"]["before"].get("primary", "0.0.0.0") == "0.0.0.0"
    undone(runtime, record, before)
    assert runtime.lab.device.tables[DNS].attrs.get("primary", "0.0.0.0") == "0.0.0.0"


@pytest.mark.parametrize("shown", [
    {"protocol": "dot", "server-hostname": "dns.example.invalid"},   # the lab before the preparation
    {"protocol": "doh"},                                                 # DoH without host name: protocol alone
    {"dns-over-tls": "enable"},
    {"ssl-certificate": "a1-certificate"},
])
def test_dns_over_tls_or_https_refuses_any_change(a1, runtime_for, tmp_path, shown):
    device = lab()
    device.tables[DNS].attrs.update(shown)
    runtime = runtime_for(tmp_path, device)
    preview = rejected(runtime, ask(DNS, "-", "update", {"primary": "198.51.100.60"}, endpoint_impact="-"), SCOPE)
    assert "dns.example.invalid" not in json.dumps(preview) and "a1-certificate" not in json.dumps(preview)
    assert not runtime.lab.device.applied_blocks


def test_a_snapshot_without_the_dns_section_is_incomplete(a1):
    device = lab()
    del device.tables[DNS]
    with pytest.raises(SnapshotRejected) as caught:
        engine.build_plan("fortios", device.snapshot().encode(),
                          ask(DNS, "-", "update", {"secondary": "198.51.100.55"}, endpoint_impact="-"))
    assert caught.value.category == fortios.SNAPSHOT_INCOMPLETE


# ------------------------------------------------------------------------------------------- log syslogd setting

def syslog_enabled():
    return lab(syslog=True)


def test_syslog_at_its_defaults_is_missing_from_the_whole_show_and_refused(a1, runtime_for, tmp_path):
    # measured on the lab FortiGate-60F 7.6.8: show log syslogd setting prints the empty section, the whole show (the
    # snapshot of Admin) omits it; the shared registry treats a missing singleton as an incomplete snapshot, so every
    # change of a syslogd at its defaults is refused before any write (fail closed, a finding for the framework)
    shown = (LAB / "syslogd-initial.txt").read_text()
    assert shown.strip() == "config log syslogd setting\nend"
    device = lab()
    assert "config log syslogd setting" not in device.snapshot()
    with pytest.raises(SnapshotRejected) as caught:
        engine.build_plan("fortios", device.snapshot().encode(),
                          ask(SYSLOG, "-", "update", {"status": "enable", "server": "192.0.2.80"}))
    assert caught.value.category == fortios.SNAPSHOT_INCOMPLETE
    runtime = runtime_for(tmp_path, device)
    preview = execute.preview(runtime, "lab", ask(SYSLOG, "-", "update", {"status": "enable", "server": "192.0.2.80"}))
    assert preview["result"] == "rejected" and "no log syslogd setting section" in " ".join(preview["reasons"])
    assert not runtime.lab.device.applied_blocks


def test_disabling_the_only_syslog_target_meets_the_audit_gate(a1, runtime_for, tmp_path):
    # the audit gate of Admin (execute.py, shared) refuses a change that brings back fortios.logging.no-syslog-target,
    # even with endpoint_impact: Admin never leaves the device without a syslog target it had
    runtime = runtime_for(tmp_path, syslog_enabled())
    request_ = ask(SYSLOG, "-", "update", {"status": "disable"}, endpoint_impact="-")
    preview = execute.preview(runtime, "lab", request_)
    assert preview["result"] == "rejected", preview
    assert "fortios.logging.no-syslog-target" in " ".join(preview["reasons"])


def test_syslog_facility_change_and_undo(a1, runtime_for, tmp_path):
    runtime = runtime_for(tmp_path, syslog_enabled())
    facility, before_facility = approved(runtime, ask(SYSLOG, "-", "update", {"facility": "local5"}))
    assert facility["plan"]["commands"] == ["config log syslogd setting", '    set facility "local5"', "end"]
    assert facility["plan"]["inverse"] == ["config log syslogd setting", '    set facility "local7"', "end"]
    rejected(runtime, ask(SYSLOG, "-", "update", {"status": "disable"}), IMPACT)
    rejected(runtime, ask(SYSLOG, "-", "update", {"server": "192.0.2.81"}), IMPACT)
    rejected(runtime, ask(SYSLOG, "-", "update", {"server": None}), IMPACT)
    undone(runtime, facility, before_facility)
    assert runtime.lab.device.tables[SYSLOG].attrs.get("facility", "local7") == "local7"


@pytest.mark.parametrize("changes", [{"port": 1514}, {"mode": "legacy-reliable"}])
def test_the_port_or_mode_of_the_active_syslog_is_refused_before_any_write(a1, runtime_for, tmp_path, changes):
    # review finding 1 over the lab capture syslogd-enabled.txt (enabled, one server, port 514 and mode udp
    # by default): another port or transport of the same collector moves the active target. Measured live:
    # on end FortiOS 7.6.8 asks to confirm a port other than the default of the mode (514 udp, 601
    # legacy-reliable), a question the Admin write does not answer (change_failed, device blocked). The profile
    # therefore never updates port or mode, with or without endpoint_impact; the target moves by server with it
    runtime = runtime_for(tmp_path, captured(lab(), "syslogd-enabled.txt"))
    name = next(iter(changes))
    for extra in ({}, {"endpoint_impact": "-"}):
        preview = execute.preview(runtime, "lab", ask(SYSLOG, "-", "update", changes, **extra))
        assert preview["result"] == "rejected", preview
        assert "attribute %s cannot be updated" % name in " ".join(preview["reasons"]), preview
    assert not runtime.lab.device.applied_blocks
    rejected(runtime, ask(SYSLOG, "-", "update", {"server": "192.0.2.81"}), IMPACT)
    record, before = approved(runtime, ask(SYSLOG, "-", "update", {"server": "192.0.2.81"}, endpoint_impact="-"))
    assert record["plan"]["endpoint_impact"] == "-"
    undone(runtime, record, before)


@pytest.mark.parametrize("shown", [
    {"status": "enable", "server": "192.0.2.80", "mode": "reliable", "enc-algorithm": "high"},
    {"status": "enable", "server": "192.0.2.80", "certificate": "a1-certificate"},
    {"status": "enable", "server": "192.0.2.80", "interface-select-method": "specify", "interface": "internal"},
])
def test_syslog_over_tls_or_bound_to_an_interface_refuses_even_a_facility_change(a1, runtime_for, tmp_path, shown):
    device = syslog_enabled()
    device.tables[SYSLOG].attrs.update(shown)
    runtime = runtime_for(tmp_path, device)
    preview = execute.preview(runtime, "lab", ask(SYSLOG, "-", "update", {"facility": "local5"}))
    assert preview["result"] == "rejected", preview
    assert preview.get("reason_codes") in ([SCOPE], None)
    assert "a1-certificate" not in json.dumps(preview)
    assert not runtime.lab.device.applied_blocks


def test_syslog_reliable_mode_is_outside_the_profile(a1, runtime_for, tmp_path):
    runtime = runtime_for(tmp_path, syslog_enabled())
    preview = execute.preview(runtime, "lab", ask(SYSLOG, "-", "update", {"mode": "reliable"}))
    assert preview["result"] == "rejected" and "mode" in " ".join(preview["reasons"])


def test_syslog_source_ip_only_from_an_unprotected_interface(a1, runtime_for, tmp_path):
    device = syslog_enabled()
    device.interface_rows["wan2"] = ("203.0.113.200 255.255.255.0", "static", "up")
    runtime = runtime_for(tmp_path, device)
    rejected(runtime, ask(SYSLOG, "-", "update", {"source-ip": "198.51.100.200"}), SCOPE)
    record, before = approved(runtime, ask(SYSLOG, "-", "update", {"source-ip": "198.51.100.99"}))
    undone(runtime, record, before)


def test_syslog_source_ip_of_a_protected_interface_is_refused(a1, runtime_for, tmp_path):
    device = syslog_enabled()
    device.interface_rows["wan1"] = ("203.0.113.250 255.255.255.0", "static", "up")
    runtime = runtime_for(tmp_path, device)
    rejected(runtime, ask(SYSLOG, "-", "update", {"source-ip": "203.0.113.250"}), SCOPE)


# ------------------------------------------------------------------------------------------- shared guarantees

@pytest.mark.parametrize(("table", "key", "op", "changes", "impact"), [
    (SERVER, "7", "update", {"lease-time": 3600}, None),
    (RANGE, "7:2", "create", {"start-ip": "192.0.2.160", "end-ip": "192.0.2.170"}, None),
    (DNS, "-", "update", {"secondary": "198.51.100.55"}, "-"),
    (SYSLOG, "-", "update", {"facility": "local5"}, None),
])
def test_apply_without_the_approved_preview_is_refused_with_no_session(a1, runtime_for, tmp_path, table, key, op,
                                                                      changes, impact):
    device = lab(syslog=True)
    runtime = runtime_for(tmp_path, device)
    before = device.snapshot()
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", ask(table, key, op, changes,
                                          **({"endpoint_impact": impact} if impact else {})))
    assert caught.value.reason_codes == [PREVIEW]
    assert runtime.lab.device.applied_blocks == [] and runtime.lab.device.snapshot() == before
    assert ssh_sessions(runtime) == [] and audit_events(tmp_path) == []


@pytest.mark.parametrize(("table", "key", "op", "changes", "impact"), [
    (SERVER, "7", "update", {"status": "enable"}, "7"),
    (SERVER, "9", "create", {"interface": VLAN, "status": "disable", "netmask": "255.255.255.0",
                             "default-gateway": "192.0.2.1"}, None),
    (RANGE, "7:2", "create", {"start-ip": "192.0.2.160", "end-ip": "192.0.2.170"}, None),
    (DNS, "-", "update", {"secondary": "198.51.100.55"}, "-"),
    (SYSLOG, "-", "update", {"facility": "local5"}, None),
])
def test_fortios_8_0_2_refuses_every_a1_change_before_any_write(a1, runtime_for, tmp_path, table, key, op, changes,
                                                                 impact):
    device = FakeFortiOSA1Webhook(syslog=True)
    runtime = runtime_for(tmp_path, device)
    request_ = ask(table, key, op, changes, **({"endpoint_impact": impact} if impact else {}))
    preview = execute.preview(runtime, "lab", request_)
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["safeguard_no_rest_inverse"], preview
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", request_, expected_plan_sha256="0" * 64)
    assert caught.value.reason_codes == ["safeguard_no_rest_inverse"]
    current = runtime.lab.device
    assert current.applied_blocks == [] and not current.api_users and not current.webhooks


def test_an_untested_build_runs_with_the_warning(a1, runtime_for, tmp_path):
    device = lab(syslog=True)
    device.firmware = ("7.6.7", "3704")
    runtime = runtime_for(tmp_path, device)
    preview = execute.preview(runtime, "lab", ask(SYSLOG, "-", "update", {"facility": "local5"}))
    assert preview["result"] == "ready", preview
    assert preview["plan"]["firmware_support"]["status"] == "untested" if "plan" in preview else \
        preview["firmware_support"]["status"] == "untested"


def test_the_shipped_profiles_without_a_live_run_are_refused_as_not_measured(runtime_for, tmp_path):
    fortios_tables.reset()
    loaded = profiles.load_profiles()
    pending = [table for table in A1 if not loaded[("fortios", table)].measured]
    runtime = runtime_for(tmp_path, lab(syslog=True))
    assert pending == [table for table in A1 if table not in MEASURED_LIVE]
    for table in pending:
        request_ = {SERVER: ask(SERVER, "7", "update", {"lease-time": 3600}),
                    RANGE: ask(RANGE, "7:2", "create", {"start-ip": "192.0.2.160", "end-ip": "192.0.2.170"}),
                    DNS: ask(DNS, "-", "update", {"secondary": "198.51.100.55"}, endpoint_impact="-"),
                    SYSLOG: ask(SYSLOG, "-", "update", {"facility": "local5"})}[table]
        with pytest.raises(Rejected) as caught:
            execute.preview(runtime, "lab", request_)
        assert "is not measured on a device" in " ".join(caught.value.reasons)
    fortios_tables.reset()


# ------------------------------------------------------------------------------------------- safeguard

class Killed(BaseException):
    """The Admin process ends right after change_applied (SIGKILL in the live run)."""


def test_a_killed_apply_is_returned_by_the_safeguard_and_settled_by_recover(a1, runtime_for, tmp_path, monkeypatch):
    device = lab()
    runtime = runtime_for(tmp_path, device)
    request_ = ask(SERVER, "7", "update", {"status": "enable"}, endpoint_impact="7")
    preview = execute.preview(runtime, "lab", request_)
    assert preview["result"] == "ready", preview
    before = runtime.lab.device.snapshot()
    step = execute._step

    def killed_after_write(runtime_, record, name, detail=None):
        step(runtime_, record, name, detail)
        if name == "change_applied":
            raise Killed()

    with monkeypatch.context() as patch:
        patch.setattr(execute, "_step", killed_after_write)
        with pytest.raises(Killed):
            execute.apply(runtime, "lab", request_, expected_plan_sha256=preview["plan_sha256"])
    assert server(runtime.lab.device)["attrs"].get("status", "enable") == "enable"
    runtime.lab.advance(600)  # the on-device safeguard expires and runs the inverse
    assert server(runtime.lab.device)["attrs"]["status"] == "disable"
    settled = execute.recover(runtime, "lab")
    assert [record["result"] for record in settled] == ["reverted"]
    current = runtime.lab.device
    assert current.snapshot() == before and not current.stitches


def test_a_lost_check_account_after_the_write_is_returned_by_the_safeguard(a1, runtime_for, tmp_path):
    device = syslog_enabled()
    device.check_after_write = {"show log syslogd setting": "Command fail. Return code -37\n"}
    runtime = runtime_for(tmp_path, device)
    request_ = ask(SYSLOG, "-", "update", {"facility": "local5"})
    preview = execute.preview(runtime, "lab", request_)
    record = execute.apply(runtime, "lab", request_, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "reverted", record
    assert runtime.lab.device.tables[SYSLOG].attrs.get("facility", "local7") == "local7"


def refuse_the_syslog_line(fake, lines):
    """The device refuses the second line of the change block, not of the revert (on_apply of the simulated device)."""
    change = bool(lines) and lines[0] == "config log syslogd setting"
    fake.refused_blocks = getattr(fake, "refused_blocks", 0) + change
    fake.fail_at_line = 2 if change and fake.refused_blocks == 1 else None  # the revert block is accepted


def test_a_line_the_device_refuses_ends_in_change_failed(a1, runtime_for, tmp_path):
    device = lab(syslog=True)
    device.on_apply = refuse_the_syslog_line
    runtime = runtime_for(tmp_path, device)
    request_ = ask(SYSLOG, "-", "update", {"facility": "local5"})
    preview = execute.preview(runtime, "lab", request_)
    record = execute.apply(runtime, "lab", request_, expected_plan_sha256=preview["plan_sha256"])
    steps = [(step["step"], step["detail"]) for step in record["steps"]]
    assert ("change_failed", "AccessError after 2 lines") in steps, steps
    # the refused line ends the held Fortinet session, the inverse is not verified in it: the operation is unknown and
    # the device blocked for a person to inspect; the on-device safeguard still returns the change at its expiry
    assert record["result"] == "unknown" and steps[-1][0] == "revert_unverified", steps
    assert runtime.store.blocked("lab") is not None
    runtime.lab.advance(600)
    current = runtime.lab.device
    assert current.tables[SYSLOG].attrs.get("facility", "local7") == "local7"
    assert runtime.lab.device.tables[SYSLOG].attrs.get("facility", "local7") == "local7"


def test_a_singleton_changed_during_the_operation_is_a_mismatch(a1, runtime_for, tmp_path):
    device = syslog_enabled()
    device.check_after_write = {"show log syslogd setting": "config log syslogd setting\n    set status enable\n"
                                                           '    set server "192.0.2.80"\n    set facility local5\n'
                                                           "    set port 1514\nend\n"}
    runtime = runtime_for(tmp_path, device)
    request_ = ask(SYSLOG, "-", "update", {"facility": "local5"})
    preview = execute.preview(runtime, "lab", request_)
    record = execute.apply(runtime, "lab", request_, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "reverted", record


# ------------------------------------------------------------------------------------------- lab captures

def test_the_lab_captures_parse_into_the_profile_state(a1):
    header = "#config-version=FGT60F-7.6.8-FW-build3744-260420:opmode=1:vdom=0:user=x\n"
    for name in ("dhcp-server-created.txt", "dhcp-server-one-range.txt", "dhcp-server-enabled.txt",
                 "syslogd-enabled.txt", "syslogd-facility.txt", "dns-cleartext.txt", "dns-secondary.txt"):
        path = LAB / name
        if not path.exists():
            pytest.fail("missing lab capture %s" % name)
        snapshot = fortios.Snapshot(header + path.read_text())
        table = SERVER if name.startswith("dhcp") else SYSLOG if name.startswith("syslog") else DNS
        entries = snapshot.entries(table)
        assert entries, name
        profile = a1[("fortios", table)]
        for entry in entries.values():
            state, unsupported = snapshot.entry_state(entry)
            assert not unsupported, (name, unsupported)
            assert set(state) <= set(profile.attributes) | set(profile.fixed), (name, sorted(state))
