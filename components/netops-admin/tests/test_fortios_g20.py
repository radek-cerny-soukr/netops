"""G20 (1.0.12): FortiOS DHCP reservations addressed by interface and MAC, and DNS database entries (A and PTR).

The fake device replays the layout measured on the lab FortiGate-60F, FortiOS 7.6.8 build3744 (fixtures/
fortios_7_6_8_g20, see PROVENANCE.md); its renderings are compared with the captures. Requests go through the real
preview/apply/undo path of Admin.
"""
from __future__ import annotations

from pathlib import Path

import itertools

import pytest
from fake_020 import FortiOS767
from fake_fortios import DeviceRefused, quoted
from test_execute import make_runtime, request

from netops_admin import engine, execute, fortios
from netops_admin.errors import Rejected
from netops_core import prompt
from netops_core.fortios import tokenize

FIXTURES = Path(__file__).parent / "fixtures" / "fortios_7_6_8_g20"
DHCP, DNS = fortios.DHCP_TABLE, fortios.DNS_TABLE
INTERFACE = "quarantine"
MAC = "00:00:5e:00:53:01"
ZONE = "netops-g20.test"
ADDRESS = "192.0.2.220"
HOST_IP = "198.51.100.77"


def fixture(name):
    return prompt.cleaned((FIXTURES / f"{name}.txt").read_text(), "fortios")


class FortiOSG20(FortiOS767):
    """A FortiOS 7.6.8 fake with the DHCP server 3 (interface quarantine) and the DNS zone netops-g20.test."""

    firmware = ("7.6.8", "3744")

    def __init__(self):
        super().__init__()
        self.reservations = {}
        self.entries = {}
        self.zone_present = True

    def dhcp(self):
        text = fixture("dhcp-server-empty")
        if not self.reservations:
            return text
        rows = ["        config reserved-address"]
        for rid, attrs in sorted(self.reservations.items(), key=lambda item: int(item[0])):
            rows.append(f"            edit {rid}")
            for name in ("ip", "mac", "description"):
                if name in attrs:
                    rows.append(f"                set {name} " + (quoted(attrs[name]) if name == "description" else attrs[name]))
            rows.append("            next")
        rows.append("        end")
        marker = "        set timezone-option default\n"
        return text.replace(marker, marker + "\n".join(rows) + "\n")

    def dns(self):
        if not self.zone_present:
            return ""
        text = fixture("dns-zone-empty")
        if not self.entries:
            return text
        rows = ["        config dns-entry"]
        for eid, attrs in sorted(self.entries.items(), key=lambda item: int(item[0])):
            rows.append(f"            edit {eid}")
            if attrs.get("status", "enable") != "enable":
                rows.append(f"                set status {attrs['status']}")
            if attrs.get("type", "A") != "A":
                rows.append(f"                set type {attrs['type']}")
            if attrs.get("ttl", "0") != "0":
                rows.append(f"                set ttl {attrs['ttl']}")
            rows.append(f"                set hostname {quoted(attrs['hostname'])}")
            rows.append(f"                set ip {attrs['ip']}")
            rows.append("            next")
        rows.append("        end")
        marker = f'        set domain "{ZONE}"\n'
        return text.replace(marker, marker + "\n".join(rows) + "\n")

    def snapshot(self):
        return super().snapshot() + self.dns()

    def _run(self, lines, automatic=False):
        if lines[0].strip() != "config system dns-database":
            return super()._run(lines, automatic)
        in_entries, key = False, None
        for number, line in enumerate(lines, 1):
            if self.fail_at_line == number and not automatic:
                raise DeviceRefused(number - 1)
            tokens = tokenize(line.strip())
            if tokens[:2] == ["config", "dns-entry"]:
                in_entries = True
            elif in_entries and tokens[0] == "edit":
                key = tokens[1]
                self.entries.setdefault(key, {})
            elif in_entries and tokens[0] == "set":
                self.entries[key][tokens[1]] = " ".join(tokens[2:])
            elif in_entries and tokens[0] == "unset":
                self.entries[key].pop(tokens[1], None)
            elif in_entries and tokens[0] == "delete":
                self.entries.pop(tokens[1], None)
            elif in_entries and tokens[0] == "end":
                in_entries = False
        return len(lines)

    def check_query(self, command):
        self._fire()
        if self.check_unreadable:
            raise RuntimeError("check account unavailable")
        if command == "show system dhcp server 3":
            return self.dhcp()
        if command == f"show system dns-database {ZONE}":
            return self.dns() if self.zone_present else fixture("dns-zone-missing")
        return super().check_query(command)


REQUESTS = itertools.count(1)


def ask(table, key, op, changes, **extra):
    if table == DHCP:
        extra.setdefault("endpoint_impact", key)
    return request(table=table, key=key, op=op, changes=changes, request_id=f"g20-{op}-{next(REQUESTS)}", **extra)


def approved(runtime, device, request_):
    before = device.snapshot()
    written = list(device.applied_blocks)
    preview = execute.preview(runtime, "lab", request_)
    assert preview["result"] == "ready", preview
    assert device.snapshot() == before and device.applied_blocks == written
    record = execute.apply(runtime, "lab", request_, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "confirmed", record
    assert engine.verify(record["plan"], device.snapshot().encode())["result"] == "match"
    return record, before


def undo(runtime, device, record, before):
    preview = execute.preview_undo(runtime, record["change_id"], "Restore the G20 baseline", issue=True)
    assert preview["result"] == "ready", preview
    restored = execute.undo(runtime, record["change_id"], "Restore the G20 baseline", preview["plan_sha256"])
    assert restored["result"] == "confirmed", restored
    assert engine.verify(record["plan"], device.snapshot().encode(), expect="before")["result"] == "match"
    assert device.snapshot() == before
    assert not device.stitches and not device.actions and not device.triggers


# --------------------------------------------------------------------------------------------- the fake is the device

def test_fake_renders_what_the_device_printed():
    device = FortiOSG20()
    assert device.dhcp() == fixture("dhcp-server-empty") and device.dns() == fixture("dns-zone-empty")
    device.reservations["1"] = {"ip": ADDRESS, "mac": MAC, "description": "netops-g20 test"}
    assert device.dhcp() == fixture("dhcp-server-one-reservation")
    device.entries["1"] = {"hostname": "g20-a", "ip": HOST_IP}
    device.entries["2"] = {"type": "PTR", "ttl": "300", "hostname": "g20-a.netops-g20.test", "ip": HOST_IP}
    assert device.dns() == fixture("dns-zone-two-entries")


# --------------------------------------------------------------------------------------------- DHCP: interface + MAC

def test_reservation_is_created_by_interface_and_mac_and_undone(tmp_path):
    device = FortiOSG20()
    runtime = make_runtime(tmp_path, device)
    key = f"{INTERFACE}@{MAC.upper()}"
    record, before = approved(runtime, device, ask(DHCP, key, "create", {"ip": ADDRESS, "description": "netops-g20 test"}))
    plan = record["plan"]
    assert plan["key"] == "3:1" and plan["endpoint_impact"] == "3:1"
    assert plan["commands"][:3] == ["config system dhcp server", "edit 3", "config reserved-address"]
    assert 'set mac %s' % MAC in " ".join(plan["commands"])  # the MAC of the key, in lower case
    assert device.check_query("show system dhcp server 3") == fixture("dhcp-server-one-reservation")
    undo(runtime, device, record, before)
    assert device.dhcp() == fixture("dhcp-server-empty")


def test_reservation_is_updated_and_deleted_by_the_same_key(tmp_path):
    device = FortiOSG20()
    device.reservations["1"] = {"ip": ADDRESS, "mac": MAC, "description": "netops-g20 test"}
    runtime = make_runtime(tmp_path, device)
    key = f"{INTERFACE}@{MAC}"
    record, before = approved(runtime, device, ask(DHCP, key, "update", {"description": "changed"}))
    assert record["plan"]["key"] == "3:1" and device.reservations["1"]["description"] == "changed"
    undo(runtime, device, record, before)
    record, before = approved(runtime, device, ask(DHCP, key, "delete", {}))
    assert device.reservations == {}
    undo(runtime, device, record, before)
    assert device.reservations["1"]["mac"] == MAC


def test_next_free_reservation_id_follows_the_highest_one(tmp_path):
    device = FortiOSG20()
    device.reservations["4"] = {"ip": "192.0.2.221", "mac": "00:00:5e:00:53:09"}
    runtime = make_runtime(tmp_path, device)
    record, _ = approved(runtime, device, ask(DHCP, f"{INTERFACE}@{MAC}", "create", {"ip": ADDRESS}))
    assert record["plan"]["key"] == "3:5"


@pytest.mark.parametrize(("key", "op", "changes", "fragment"), [
    ("nonexistent@" + MAC, "create", {"ip": ADDRESS}, "has no DHCP server"),
    (f"{INTERFACE}@{MAC}", "create", {"ip": ADDRESS, "mac": "00:00:5e:00:53:02"}, "differs from the mac in the key"),
    (f"{INTERFACE}@{MAC}", "update", {"description": "x"}, "names no object with mac"),
    (f"{INTERFACE}@{MAC}", "delete", {}, "names no object with mac"),
])
def test_interface_and_mac_key_refusals_write_nothing(tmp_path, key, op, changes, fragment):
    device = FortiOSG20()
    runtime = make_runtime(tmp_path, device)
    preview = execute.preview(runtime, "lab", ask(DHCP, key, op, changes))
    assert preview["result"] == "rejected" and fragment in " ".join(preview["reasons"])
    assert not device.applied_blocks


def test_a_mac_already_reserved_cannot_be_reserved_again(tmp_path):
    device = FortiOSG20()
    device.reservations["1"] = {"ip": ADDRESS, "mac": MAC}
    runtime = make_runtime(tmp_path, device)
    preview = execute.preview(runtime, "lab", ask(DHCP, f"{INTERFACE}@{MAC}", "create", {"ip": "192.0.2.221"}))
    assert preview["result"] == "rejected" and "already reserved" in " ".join(preview["reasons"])


def test_the_mac_of_a_reservation_addressed_by_mac_cannot_change(tmp_path):
    device = FortiOSG20()
    device.reservations["1"] = {"ip": ADDRESS, "mac": MAC}
    runtime = make_runtime(tmp_path, device)
    preview = execute.preview(runtime, "lab", ask(DHCP, f"{INTERFACE}@{MAC}", "update", {"mac": "00:00:5e:00:53:02"}))
    assert preview["result"] == "rejected" and "numeric key" in " ".join(preview["reasons"])


def test_reservation_needs_endpoint_impact_and_an_approved_preview(tmp_path):
    device = FortiOSG20()
    runtime = make_runtime(tmp_path, device)
    key = f"{INTERFACE}@{MAC}"
    plain = request(table=DHCP, key=key, op="create", changes={"ip": ADDRESS}, request_id="g20-plain")
    preview = execute.preview(runtime, "lab", plain)
    assert preview["result"] == "rejected" and preview["reason_codes"] == ["endpoint_impact_required"]
    named = ask(DHCP, key, "create", {"ip": ADDRESS})
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", named)
    assert caught.value.reason_codes == ["plan_changed"] and not device.applied_blocks


def test_endpoint_impact_must_name_the_request_key(tmp_path):
    with pytest.raises(Rejected, match="explicitly name"):
        ask(DHCP, f"{INTERFACE}@{MAC}", "create", {"ip": ADDRESS}, endpoint_impact="3:1")


def test_numeric_keys_still_work_and_share_the_checks(tmp_path):
    device = FortiOSG20()
    runtime = make_runtime(tmp_path, device)
    record, before = approved(runtime, device, ask(DHCP, "3:1", "create", {"ip": ADDRESS, "mac": MAC}))
    assert record["plan"]["key"] == "3:1"
    undo(runtime, device, record, before)
    preview = execute.preview(runtime, "lab", ask(DHCP, "3:2", "create", {"ip": "198.51.100.5", "mac": MAC}))
    assert preview["result"] == "rejected" and "usable address in the DHCP subnet" in " ".join(preview["reasons"])


# --------------------------------------------------------------------------------------------- DNS entries

def test_a_and_ptr_entries_are_created_and_undone(tmp_path):
    device = FortiOSG20()
    runtime = make_runtime(tmp_path, device)
    first, before_first = approved(runtime, device, ask(DNS, f"{ZONE}@g20-a", "create", {"ip": HOST_IP}))
    assert first["plan"]["key"] == f"{ZONE}:1"
    assert first["plan"]["commands"][:4] == ["config system dns-database", f'edit "{ZONE}"', "config dns-entry",
                                             "    edit 1"]
    second, before_second = approved(runtime, device, ask(DNS, f"{ZONE}@g20-a.netops-g20.test", "create",
                                                          {"type": "PTR", "ip": HOST_IP, "ttl": "300"}))
    assert second["plan"]["key"] == f"{ZONE}:2"
    assert device.check_query(f"show system dns-database {ZONE}") == fixture("dns-zone-two-entries")
    undo(runtime, device, second, before_second)
    undo(runtime, device, first, before_first)
    assert device.check_query(f"show system dns-database {ZONE}") == fixture("dns-zone-empty")


def test_dns_entries_are_updated_and_deleted_and_undone(tmp_path):
    device = FortiOSG20()
    device.entries["1"] = {"hostname": "g20-a", "ip": HOST_IP}
    device.entries["2"] = {"type": "PTR", "ttl": "300", "hostname": "g20-a.netops-g20.test", "ip": HOST_IP}
    runtime = make_runtime(tmp_path, device)
    updated, before_update = approved(runtime, device, ask(DNS, f"{ZONE}:2", "update", {"ttl": None}))
    assert "ttl" not in device.entries["2"]
    undo(runtime, device, updated, before_update)
    assert device.entries["2"]["ttl"] == "300"
    removed, before_delete = approved(runtime, device, ask(DNS, f"{ZONE}@g20-a", "delete", {}))
    assert list(device.entries) == ["2"]
    undo(runtime, device, removed, before_delete)
    assert device.check_query(f"show system dns-database {ZONE}") == fixture("dns-zone-two-entries")


def test_dns_entry_refusals_write_nothing(tmp_path):
    device = FortiOSG20()
    device.entries["1"] = {"hostname": "g20-a", "ip": HOST_IP}
    device.entries["2"] = {"hostname": "g20-a", "ip": "198.51.100.78"}
    device.entries["3"] = {"type": "NS", "hostname": "g20-ns", "ip": HOST_IP}
    runtime = make_runtime(tmp_path, device)
    cases = [
        (ask(DNS, "nozone.test@host", "create", {"ip": HOST_IP}), "does not exist"),
        (ask(DNS, f"{ZONE}@g20-b", "create", {"type": "PTR", "ip": HOST_IP}), "host name with a domain"),
        (ask(DNS, f"{ZONE}@g20-a", "create", {"ip": HOST_IP}), "duplicates entry 1"),
        (ask(DNS, f"{ZONE}@g20-a", "update", {"ttl": "10"}), "several objects with hostname"),
        (ask(DNS, f"{ZONE}@g20-c", "delete", {}), "no object with hostname"),
        (ask(DNS, f"{ZONE}:3", "update", {"ttl": "10"}), "has type NS"),
        (ask(DNS, f"{ZONE}:1", "update", {"type": "PTR"}), "cannot be updated"),
        (ask(DNS, f"{ZONE}@g20-d", "create", {}), "needs"),
        (ask(DNS, f"{ZONE}@g20-d", "create", {"ip": "999.1.1.1"}), "ip"),
    ]
    for request_, fragment in cases:
        preview = execute.preview(runtime, "lab", request_)
        assert preview["result"] == "rejected" and fragment in " ".join(preview["reasons"]), (request_.key, preview)
    assert not device.applied_blocks


def test_dns_entry_apply_needs_the_approved_preview(tmp_path):
    device = FortiOSG20()
    runtime = make_runtime(tmp_path, device)
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", ask(DNS, f"{ZONE}@g20-a", "create", {"ip": HOST_IP}))
    assert caught.value.reason_codes == ["plan_changed"] and not device.applied_blocks


def test_a_zone_that_is_not_in_the_snapshot_is_never_created(tmp_path):
    device = FortiOSG20()
    device.zone_present = False
    runtime = make_runtime(tmp_path, device)
    preview = execute.preview(runtime, "lab", ask(DNS, f"{ZONE}:1", "create", {"hostname": "g20-a", "ip": HOST_IP}))
    assert preview["result"] == "rejected" and "does not exist" in " ".join(preview["reasons"])
    assert not device.applied_blocks


def test_lost_check_account_returns_the_dns_entry_through_the_timed_safeguard(tmp_path):
    device = FortiOSG20()
    before = device.snapshot()

    def fail_after_change(fake, _lines):
        if len(fake.applied_blocks) == 2:
            fake.check_unreadable = True

    device.on_apply = fail_after_change
    runtime = make_runtime(tmp_path, device)
    request_ = ask(DNS, f"{ZONE}@g20-a", "create", {"ip": HOST_IP})
    preview = execute.preview(runtime, "lab", request_)
    record = execute.apply(runtime, "lab", request_, expected_plan_sha256=preview["plan_sha256"])
    assert record["result"] == "reverted"
    assert engine.verify(record["plan"], device.snapshot().encode(), expect="before")["result"] == "match"
    assert device.snapshot() == before


def test_check_account_reads_a_nested_object_and_refuses_a_missing_parent():
    zone = fixture("dns-zone-two-entries")
    assert fortios.shown_object(zone, DNS, f"{ZONE}:2") == {
        "type": "PTR", "ttl": "300", "hostname": "g20-a.netops-g20.test", "ip": HOST_IP}
    assert fortios.shown_object(fixture("dns-zone-empty"), DNS, f"{ZONE}:1") is None
    with pytest.raises(Rejected):
        fortios.shown_object(fixture("dns-zone-missing"), DNS, f"{ZONE}:1")
    reservation = fixture("dhcp-server-one-reservation")
    assert fortios.shown_object(reservation, DHCP, "3:1") == {
        "ip": ADDRESS, "mac": MAC, "description": "netops-g20 test"}
    assert fortios.shown_object(fixture("dhcp-server-empty"), DHCP, "3:1") is None


def test_device_error_texts_are_cli_errors():
    for name in ("dns-entry-without-hostname-error", "dhcp-duplicate-error", "dns-delete-missing-error"):
        assert fortios.cli_error("x\n" + fixture(name)) is not None, name


@pytest.mark.parametrize("inventory_table", ["system interface", "interface"])
def test_reservation_on_the_server_of_a_protected_interface_is_refused(tmp_path, inventory_table):
    device = FortiOSG20()
    runtime = make_runtime(tmp_path, device, protected={inventory_table: [INTERFACE]})
    preview = execute.preview(runtime, "lab", ask(DHCP, f"{INTERFACE}@{MAC}", "create", {"ip": ADDRESS}))
    assert preview["result"] == "rejected" and "protected system interface" in " ".join(preview["reasons"])
    assert not device.applied_blocks


def test_undo_disabling_a_dns_entry_restores_the_omitted_enabled_default(tmp_path):
    device = FortiOSG20()
    zone = fortios.parse_snapshot(fixture("dns-zone-two-entries")).section("system dns-database").entries[ZONE]
    entry_id, entry = next(iter(zone.section("dns-entry").entries.items()))
    key = f"{ZONE}:{entry_id}"
    device.entries[entry_id] = {name: attr.value() for name, attr in entry.attrs.items()}
    runtime = make_runtime(tmp_path, device)
    assert "status" not in fortios.shown_object(device.dns(), DNS, key)
    record, before = approved(runtime, device, ask(DNS, key, "update", {"status": "disable"}))
    assert fortios.shown_object(device.dns(), DNS, key)["status"] == "disable"
    undo(runtime, device, record, before)
    assert "status" not in fortios.shown_object(device.dns(), DNS, key)
