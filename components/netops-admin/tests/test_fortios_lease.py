"""G20 FG-37 (1.0.12): release of ONE FortiOS DHCP lease (`execute dhcp lease-clear <IPv4>`).

The fake replays the layout measured on the lab FortiGate-60F, FortiOS 7.6.8 build3744 (fixtures/fortios_7_6_8_g20,
lease-*.txt, see PROVENANCE.md). Requests go through the real preview/apply path of Admin.
"""
from __future__ import annotations

from pathlib import Path

import itertools

import pytest
from fake_020 import FortiOS767
from test_execute import make_runtime, request

from netops_admin import engine, execute, fortios_lease
from netops_admin.errors import Rejected
from netops_core import prompt

FIXTURES = Path(__file__).parent / "fixtures" / "fortios_7_6_8_g20"
TABLE = fortios_lease.TABLE
TARGET = "192.0.2.211"
KEEP = ("192.0.2.12", "192.0.2.13")
REQUESTS = itertools.count(1)


def fixture(name):
    return prompt.cleaned((FIXTURES / f"{name}.txt").read_text(), "fortios")


def row(ip, mac, host, vci, server, expiry):
    return f"  {ip}\t{mac}\t{host:<20}{vci:<20}{'':<20}{'':<20}{server:<20}{expiry}"


HEADER = "  IP\t\tMAC-Address\t\tHostname            VCI                 SSID                AP                  SERVER-ID           Expiry"
LEASES = [
    {"interface": "_default", "ip": "192.0.2.12", "mac": "00:00:5e:00:53:12", "host": "host-a", "vci": "", "server": "6",
     "expiry": "Wed Nov 25 21:07:19 2026"},
    {"interface": "fortilink", "ip": "192.0.2.13", "mac": "00:00:5e:00:53:13", "host": "SERIAL0000000001",
     "vci": "FortiSwitch-108E", "server": "2", "expiry": "Wed Nov 25 22:03:32 2026"},
    {"interface": "quarantine", "ip": TARGET, "mac": "00:00:5e:00:53:37", "host": "netops-g37-test", "vci": "netops-g37",
     "server": "3", "expiry": "Fri Nov 27 09:05:45 2026"},
]


class FortiOSLease(FortiOS767):
    """A FortiOS 7.6.8 fake that lists and releases DHCP leases."""

    firmware = ("7.6.8", "3744")

    def __init__(self):
        super().__init__()
        self.leases = [dict(lease) for lease in LEASES]
        self.keep_after_clear = False     # a device that accepts the command but leaves the row in the list
        self.during_clear = None          # callable run when the clear arrives
        self.list_override = None

    def lease_list(self, interface=None):
        if self.list_override is not None:
            return self.list_override
        rows = []
        for name in dict.fromkeys(lease["interface"] for lease in self.leases):
            rows.append(name)
            rows.append(HEADER)
            rows.extend(row(item["ip"], item["mac"], item["host"], item["vci"], item["server"], item["expiry"])
                        for item in self.leases if item["interface"] == name)
        return "\n".join(rows) + "\n" if rows else ""

    def check_query(self, command):
        if command == "execute dhcp lease-list":
            self._connect()
            self._fire()
            if self.check_unreadable:
                raise RuntimeError("check account unavailable")
            return self.lease_list()
        return super().check_query(command)

    def _run(self, lines, automatic=False):
        if not lines[0].startswith("execute dhcp lease-clear "):
            return super()._run(lines, automatic)
        assert len(lines) == 1
        address = lines[0].split()[-1]
        if self.during_clear is not None:
            self.during_clear(self)
        if not self.keep_after_clear:
            self.leases = [lease for lease in self.leases if lease["ip"] != address]
        return 1


def ask(key=TARGET, impact=True, changes=None, **extra):
    if impact:
        extra.setdefault("endpoint_impact", key)
    return request(table=TABLE, key=key, op="clear", changes=changes or {}, request_id=f"fg37-clear-{next(REQUESTS)}", **extra)


def preview(runtime, device, request_):
    written = list(device.applied_blocks)
    result = execute.preview(runtime, "lab", request_)
    assert device.applied_blocks == written
    return result


def clear_is_refused_without_writing(tmp_path, key, codes, device=None, **extra):
    device = device or FortiOSLease()
    runtime = make_runtime(tmp_path, device)
    result = execute.preview(runtime, "lab", ask(key, **extra))
    assert result["result"] == "rejected" and result["reason_codes"] == codes, result
    with pytest.raises(Rejected):
        execute.apply(runtime, "lab", ask(key, **extra), expected_plan_sha256="0" * 64)
    assert not device.applied_blocks
    return result


# ------------------------------------------------------------------------------------- the fake is the device

def test_fake_renders_what_the_device_printed():
    device = FortiOSLease()
    assert device.lease_list() == fixture("lease-list-three-interfaces")
    device.leases = [lease for lease in device.leases if lease["ip"] != TARGET]
    assert device.lease_list() == fixture("lease-list-after-clear")
    assert fixture("lease-clear-success") == "" == fixture("lease-clear-no-lease")


def test_the_real_lease_list_is_read_completely():
    seen = fortios_lease.observation(fixture("lease-list-three-interfaces"))["leases"]
    assert [(lease["interface"], lease["ip"], lease["mac"], lease["server_id"]) for lease in seen] == [
        ("_default", "192.0.2.12", "00:00:5e:00:53:12", "6"), ("fortilink", "192.0.2.13", "00:00:5e:00:53:13", "2"),
        ("quarantine", TARGET, "00:00:5e:00:53:37", "3")]
    assert seen[0]["detail"] == "host-a" and seen[2]["detail"] == "netops-g37-test netops-g37"
    assert seen[2]["expiry"] == "Fri Nov 27 09:05:45 2026"
    assert [lease["ip"] for lease in fortios_lease.observation(fixture("lease-list-quarantine-only"))["leases"]] == [TARGET]
    assert fortios_lease.observation("")["leases"] == []


@pytest.mark.parametrize("text", [
    "Unknown action 0\n",
    "quarantine\n  192.0.2.211\t00:00:5e:00:53:37\tx  3  Fri Nov 27 09:05:45 2026\n",            # row without header
    fixture("lease-list-quarantine-only") + "  192.0.2.9\tnot-a-mac\tx   3   Fri Nov 27 09:05:45 2026\n",
    fixture("lease-list-quarantine-only") + "  192.0.2.9\t00:00:5e:00:53:09\tx   3   soon\n",
    fixture("lease-list-quarantine-only") + fixture("lease-list-quarantine-only"),                 # duplicate address
])
def test_an_unrecognised_list_is_unreadable_never_a_success(text):
    with pytest.raises(Rejected) as caught:
        fortios_lease.observation(text)
    assert caught.value.reason_codes == ["clear_readback_unreadable"]


# ------------------------------------------------------------------------------------- the target

@pytest.mark.parametrize("key", [
    "all", "ALL", "All", "192.0.2.211-192.0.2.215", "192.0.2.0/24", "192.0.2.12,192.0.2.13", "192.0.2.211 ", " 192.0.2.211",
    "192.0.2.211\n", "0.0.0.0", "224.0.0.5", "127.0.0.1", "255.255.255.255", "192.0.2.011", "192.0.2", "host-a", "::1",
    "*", "?", "",
])
def test_all_ranges_and_other_spellings_are_refused_before_the_device_is_read(tmp_path, key):
    device = FortiOSLease()
    runtime = make_runtime(tmp_path, device)
    try:
        asked = ask(key)
    except Rejected:
        return                                   # a key the request parser refuses never reaches the device
    result = execute.preview(runtime, "lab", asked)
    assert result["result"] == "rejected" and result["reason_codes"] == ["clear_invalid_target"], result
    assert not device.applied_blocks


def test_an_address_that_holds_no_lease_is_refused(tmp_path):
    result = clear_is_refused_without_writing(tmp_path, "198.51.100.9", ["clear_no_entry"])
    assert "holds no lease" in " ".join(result["reasons"])


def test_a_released_address_cannot_be_released_again(tmp_path):
    device = FortiOSLease()
    device.leases = [lease for lease in device.leases if lease["ip"] != TARGET]
    clear_is_refused_without_writing(tmp_path, TARGET, ["clear_no_entry"], device)


def test_the_target_takes_no_attributes(tmp_path):
    device = FortiOSLease()
    runtime = make_runtime(tmp_path, device)
    result = execute.preview(runtime, "lab", ask(changes={"interface": "quarantine"}))
    assert result["result"] == "rejected" and not device.applied_blocks


def test_endpoint_impact_is_required_and_names_the_address(tmp_path):
    device = FortiOSLease()
    runtime = make_runtime(tmp_path, device)
    for call in (lambda: execute.preview(runtime, "lab", ask(impact=False)),
                 lambda: execute.apply(runtime, "lab", ask(impact=False), expected_plan_sha256="0" * 64)):
        with pytest.raises(Rejected) as caught:
            call()
        assert caught.value.reason_codes == ["endpoint_impact_required"]
    assert not device.applied_blocks
    with pytest.raises(Rejected, match="explicitly name"):
        ask(TARGET, endpoint_impact="192.0.2.12")


@pytest.mark.parametrize("protected_table", ["system interface", "interface"])
def test_a_protected_interface_is_never_released(tmp_path, protected_table):
    device = FortiOSLease()
    runtime = make_runtime(tmp_path, device, protected={protected_table: ["quarantine"]})
    result = execute.preview(runtime, "lab", ask())
    assert result["result"] == "rejected" and result["reason_codes"] == ["clear_protected_target"]
    assert not device.applied_blocks


# ------------------------------------------------------------------------------------- preview and apply

def test_preview_names_interface_and_mac_and_writes_nothing(tmp_path):
    device = FortiOSLease()
    runtime = make_runtime(tmp_path, device)
    result = preview(runtime, device, ask())
    assert result["result"] == "ready" and result["op"] == "clear" and result["table"] == TABLE
    assert result["commands"] == ["execute dhcp lease-clear " + TARGET] and result["inverse_commands"] == 0
    assert result["return_mechanism"] == "irreversible" and result["safeguard_seconds"] is None
    assert result["firmware"] == "7.6.8 build3744" and result["firmware_support"]["status"] == "tested"
    scope = [line for line in result["prechecks"] if "will be released" in line]
    assert scope == ["DHCP lease 192.0.2.211 on interface quarantine, MAC 00:00:5e:00:53:37, DHCP server 3,"
                     " netops-g37-test netops-g37 will be released; 2 other leases stay"]
    leases = result["predicted"]["before"]["leases"]
    assert [lease["ip"] for lease in leases] == list(KEEP) + [TARGET]
    assert [lease["ip"] for lease in result["predicted"]["after"]["leases"]] == list(KEEP)
    assert all("expiry" not in lease for lease in leases)
    assert not device.stitches and not device.actions and not device.triggers


def test_apply_releases_only_the_target_and_reads_it_back(tmp_path):
    device = FortiOSLease()
    runtime = make_runtime(tmp_path, device)
    asked = ask()
    plan_sha = preview(runtime, device, asked)["plan_sha256"]
    before = {key: dict(value) for key, value in ((lease["ip"], lease) for lease in device.leases)}
    config = device.snapshot()
    record = execute.apply(runtime, "lab", asked, expected_plan_sha256=plan_sha)
    assert record["result"] == "confirmed", record
    assert device.applied_blocks == [["execute dhcp lease-clear " + TARGET]]
    assert [lease["ip"] for lease in device.leases] == list(KEEP)
    assert all(device.leases[index] == before[ip] for index, ip in enumerate(KEEP))
    assert record["kind"] == "fortios-clear" and record["plan"]["endpoint_impact"] == TARGET
    assert record["plan"]["inverse"] == [] and record["plan"]["safeguard_id"] is None
    assert record["readback"]["released"] is True and record["readback"]["others_kept"] is True
    assert record["readback"]["added"] == [] and device.snapshot() == config
    assert not device.stitches and not device.actions and not device.triggers


def test_apply_needs_the_approved_preview(tmp_path):
    device = FortiOSLease()
    runtime = make_runtime(tmp_path, device)
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", ask())
    assert caught.value.reason_codes == ["clear_preview_required"] and not device.applied_blocks
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", ask(), expected_plan_sha256="1" * 64)
    assert caught.value.reason_codes == ["plan_changed"] and not device.applied_blocks


def test_a_renewal_does_not_change_the_plan_but_a_moved_lease_does(tmp_path):
    device = FortiOSLease()
    runtime = make_runtime(tmp_path, device)
    asked = ask()
    plan_sha = preview(runtime, device, asked)["plan_sha256"]
    for lease in device.leases:                                           # every client renewed: only expiries moved
        lease["expiry"] = "Thu Nov 26 21:07:19 2026"
    assert preview(runtime, device, ask())["plan_sha256"] == plan_sha
    record = execute.apply(runtime, "lab", asked, expected_plan_sha256=plan_sha)
    assert record["result"] == "confirmed"
    device = FortiOSLease()
    runtime = make_runtime(tmp_path / "again", device)
    asked = ask()
    plan_sha = preview(runtime, device, asked)["plan_sha256"]
    device.leases[2]["mac"] = "00:00:5e:00:53:99"                       # another client holds the address now
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", asked, expected_plan_sha256=plan_sha)
    assert caught.value.reason_codes == ["plan_changed"] and not device.applied_blocks


def test_the_plan_binds_the_address_the_interface_and_the_other_leases(tmp_path):
    other = FortiOSLease()
    other.leases.append({"interface": "fortilink", "ip": "192.0.2.14", "mac": "00:00:5e:00:53:14", "host": "late",
                         "vci": "", "server": "2", "expiry": "Wed Nov 25 23:00:00 2026"})
    hashes = set()
    for number, device in enumerate((FortiOSLease(), other)):
        hashes.add(preview(make_runtime(tmp_path / str(number), device), device, ask())["plan_sha256"])
    assert len(hashes) == 2                                              # a new neighbour is a new plan


def test_a_row_that_stays_in_the_list_is_not_confirmed(tmp_path):
    device = FortiOSLease()
    device.keep_after_clear = True
    runtime = make_runtime(tmp_path, device)
    asked = ask()
    plan_sha = preview(runtime, device, asked)["plan_sha256"]
    record = execute.apply(runtime, "lab", asked, expected_plan_sha256=plan_sha)
    assert record["result"] == "unknown" and "clear readback mismatch" in record["reason"]
    assert record["readback"]["released"] is False and len(device.applied_blocks) == 1


def test_truncated_readback_at_interface_name_is_not_confirmed(tmp_path):
    device = FortiOSLease()
    device.list_override = fixture("lease-list-three-interfaces")
    device.during_clear = lambda dev: setattr(
        dev, "list_override", dev.list_override.partition("\nquarantine\n")[0] + "\nquarantine\n")
    runtime = make_runtime(tmp_path, device)
    asked = ask()
    plan_sha = preview(runtime, device, asked)["plan_sha256"]
    record = execute.apply(runtime, "lab", asked, expected_plan_sha256=plan_sha)
    assert record["result"] == "unknown" and record["reason"] == "clear readback unavailable"
    assert "readback" not in record


def test_a_neighbour_lease_that_vanishes_is_a_mismatch(tmp_path):
    device = FortiOSLease()
    device.during_clear = lambda dev: dev.leases.pop(0)
    runtime = make_runtime(tmp_path, device)
    asked = ask()
    plan_sha = preview(runtime, device, asked)["plan_sha256"]
    record = execute.apply(runtime, "lab", asked, expected_plan_sha256=plan_sha)
    assert record["result"] == "unknown" and record["readback"]["released"] is True
    assert record["readback"]["others_kept"] is False


def test_a_lease_taken_in_the_meantime_is_reported_not_refused(tmp_path):
    device = FortiOSLease()
    newcomer = {"interface": "fortilink", "ip": "192.0.2.14", "mac": "00:00:5e:00:53:14", "host": "late", "vci": "",
                "server": "2", "expiry": "Wed Nov 25 23:00:00 2026"}
    device.during_clear = lambda dev: dev.leases.append(dict(newcomer))
    runtime = make_runtime(tmp_path, device)
    asked = ask()
    plan_sha = preview(runtime, device, asked)["plan_sha256"]
    record = execute.apply(runtime, "lab", asked, expected_plan_sha256=plan_sha)
    assert record["result"] == "confirmed"
    assert [lease["ip"] for lease in record["readback"]["added"]] == ["192.0.2.14"]


def test_an_unreadable_list_refuses_the_preview(tmp_path):
    device = FortiOSLease()
    device.list_override = "Unknown action 0\n"
    runtime = make_runtime(tmp_path, device)
    result = execute.preview(runtime, "lab", ask())
    assert result["result"] == "rejected" and result["reason_codes"] == ["clear_readback_unreadable"]
    assert not device.applied_blocks


def test_an_unreadable_check_account_refuses_the_preview(tmp_path):
    device = FortiOSLease()
    runtime = make_runtime(tmp_path, device)
    device.check_unreadable = True
    result = execute.preview(runtime, "lab", ask())
    assert result["result"] == "rejected" and not device.applied_blocks


def test_a_changed_configuration_during_the_release_is_not_confirmed(tmp_path):
    device = FortiOSLease()
    device.during_clear = lambda dev: dev.addresses.__setitem__("late-host", {"uuid": "x", "subnet": "192.0.2.99 255.255.255.255"})
    runtime = make_runtime(tmp_path, device)
    asked = ask()
    plan_sha = preview(runtime, device, asked)["plan_sha256"]
    record = execute.apply(runtime, "lab", asked, expected_plan_sha256=plan_sha)
    assert record["result"] == "unknown" and "foreign change" in record["reason"]


def test_per_read_certificate_ciphertext_does_not_change_an_approved_lease_plan(tmp_path):
    device = FortiOSLease()
    snapshot = device.snapshot
    reads = itertools.count()

    def fresh_snapshot():
        return (snapshot() + 'config vpn certificate local\n    edit "fixture-cert"\n'
                + f"        set password ENC fixture-{next(reads)}\n    next\nend\n")

    device.snapshot = fresh_snapshot
    runtime = make_runtime(tmp_path, device)
    asked = ask()
    plan_sha = preview(runtime, device, asked)["plan_sha256"]
    record = execute.apply(runtime, "lab", asked, expected_plan_sha256=plan_sha)
    assert record["result"] == "confirmed" and record["readback"]["released"]


def test_a_release_cannot_be_undone(tmp_path):
    device = FortiOSLease()
    runtime = make_runtime(tmp_path, device)
    asked = ask()
    record = execute.apply(runtime, "lab", asked, expected_plan_sha256=preview(runtime, device, asked)["plan_sha256"])
    assert record["result"] == "confirmed"
    with pytest.raises(Rejected) as caught:
        execute.preview_undo(runtime, record["change_id"], "Give the lease back", issue=True)
    assert caught.value.reason_codes == ["undo_not_applicable"]
    with pytest.raises(Rejected) as caught:
        execute.undo(runtime, record["change_id"], "Give the lease back", "0" * 64)
    assert caught.value.reason_codes == ["undo_not_applicable"]
    assert len(device.applied_blocks) == 1


def test_the_apply_is_idempotent_by_request_id(tmp_path):
    device = FortiOSLease()
    runtime = make_runtime(tmp_path, device)
    asked = ask()
    plan_sha = preview(runtime, device, asked)["plan_sha256"]
    first = execute.apply(runtime, "lab", asked, expected_plan_sha256=plan_sha)
    second = execute.apply(runtime, "lab", asked, expected_plan_sha256=plan_sha)
    assert first["result"] == "confirmed" and second["change_id"] == first["change_id"]
    assert len(device.applied_blocks) == 1
