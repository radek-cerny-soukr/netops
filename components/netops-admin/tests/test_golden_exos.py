"""Golden captures from ExtremeXOS switches on physical hardware (X435-8P-4S and
X440-G2-12p-10G4, firmware 33.7.1.6-patch1-11; device identities are generic).

Every test reads the byte-exact output of a real 'show ...' command (stored
in tests/golden/exos/<firmware>/<model>/<command-slug>/<device>__<variant>.conf, metadata in golden_meta.py)
and checks that the production parser in netops_admin.exos / netops_admin.membership / exec_exos
returns the shape of a real device -- without the FakeExos simulator.
"""
from __future__ import annotations

import datetime
import json
import pathlib

import pytest

from netops_admin import exos, membership
from netops_admin.errors import Rejected

GOLDEN_BASE = pathlib.Path(__file__).parent / "golden"
GOLDEN_ROOT = GOLDEN_BASE / "exos" / "33.7.1.6-patch1-11"


def _golden_meta() -> dict:
    import importlib.util

    spec = importlib.util.spec_from_file_location("golden_meta", pathlib.Path(__file__).parent / "golden_meta.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.GOLDEN_META

DEVICES = {
    "X435-8P-4S": GOLDEN_ROOT / "X435-8P-4S",
    "X440-G2-12p-10G4": GOLDEN_ROOT / "X440G2-12p-10G4",
}


def golden(device: str, command_slug: str, variant: str) -> str:
    path = DEVICES[device] / command_slug / f"{device}__{variant}.conf"
    return path.read_text(encoding="utf-8")


def golden_meta(device: str, command_slug: str, variant: str) -> dict:
    key = str((DEVICES[device] / command_slug / f"{device}__{variant}").relative_to(GOLDEN_BASE))
    return _golden_meta()[key]


# ---------------------------------------------------------------------------
# show switch -> exos.switch_field(exos.SYSNAME / exos.SWITCH_TIME, ...)
# used by exec_exos.hostname() and exec_exos.clock()
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("device,expected_name", [("X435-8P-4S", "X435-8P-4S"), ("X440-G2-12p-10G4", "X440-G2-12p-10G4")])
def test_show_switch_sysname(device, expected_name):
    text = golden(device, "show-switch", "normal")
    assert exos.switch_field(exos.SYSNAME, text, "system name") == expected_name


@pytest.mark.parametrize("device", ["X435-8P-4S", "X440-G2-12p-10G4"])
def test_show_switch_clock_matches_capture_time(device):
    text = golden(device, "show-switch", "normal")
    meta = golden_meta(device, "show-switch", "normal")
    raw = exos.switch_field(exos.SWITCH_TIME, text, "clock")
    parsed = datetime.datetime.strptime(raw, exos.SWITCH_CLOCK_FORMAT)
    captured = datetime.datetime.strptime(meta["captured_utc"], "%Y-%m-%dT%H:%M:%SZ")
    # switch clock is kept in UTC on the captured switches; agree to the minute
    assert abs((parsed - captured).total_seconds()) < 90


# ---------------------------------------------------------------------------
# show version -> exos.switch_field(exos.IMAGE_VERSION, ...), used by
# exec_exos.prechecks() to compare with the expected device firmware
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("device", ["X435-8P-4S", "X440-G2-12p-10G4"])
def test_show_version_matches_device_firmware(device):
    text = golden(device, "show-version", "normal")
    assert exos.switch_field(exos.IMAGE_VERSION, text, "software version") == "33.7.1.6"


# ---------------------------------------------------------------------------
# show ports no-refresh -> exos.switch_ports(), used by exec_exos.ports()
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("device,expected_ports", [
    ("X435-8P-4S", [str(n) for n in range(1, 13)]),
    ("X440-G2-12p-10G4", [str(n) for n in range(1, 17)]),
])
def test_show_ports_no_refresh_lists_every_port(device, expected_ports):
    text = golden(device, "show-ports-no-refresh", "normal")
    assert exos.switch_ports(text) == expected_ports


# ---------------------------------------------------------------------------
# show session -> exos.foreign_sessions(), used by exec_exos.foreign_sessions()
# captured with a single (own, "*"-marked) session -> 0 foreign sessions
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("device", ["X435-8P-4S", "X440-G2-12p-10G4"])
def test_show_session_own_session_is_not_foreign(device):
    text = golden(device, "show-session", "normal")
    assert exos.foreign_sessions(text) == 0


# ---------------------------------------------------------------------------
# show vlan <key> -> exos.shown_vlan(), used by exec_exos.observe()
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("device,key,expected", [
    ("X435-8P-4S", "Default", {"tag": "1"}),
    ("X440-G2-12p-10G4", "Default", {"tag": "1"}),
    ("X440-G2-12p-10G4", "Mgmt", {"tag": "4095", "description": "Management VLAN"}),
])
def test_show_vlan_key_existing(device, key, expected):
    text = golden(device, "show-vlan-key",
                  "normal-existing" if key == "Default" else "normal-existing-zero-active-ports")
    assert exos.shown_vlan(text, key) == expected


@pytest.mark.parametrize("device", ["X435-8P-4S", "X440-G2-12p-10G4"])
def test_show_vlan_key_absent_alpha_returns_none(device):
    text = golden(device, "show-vlan-key", "absent-alpha")
    assert exos.shown_vlan(text, "NoSuchVlan") is None


def test_show_vlan_key_absent_numeric_returns_none():
    # captured on the X435-8P-4S only (the message is generic to the firmware, see the golden_meta note)
    text = golden("X435-8P-4S", "show-vlan-key", "absent-numeric")
    assert exos.shown_vlan(text, "9999") is None


# ---------------------------------------------------------------------------
# show ports <key> vlan -> membership.shown(), used by exec_exos.observe()
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("device", ["X435-8P-4S", "X440-G2-12p-10G4"])
def test_show_ports_key_vlan_membership(device):
    text = golden(device, "show-ports-key-vlan", "normal")
    assert membership.shown(text, "1") == {"untagged": "Default", "tagged": ""}


# ---------------------------------------------------------------------------
# show ports <key> information detail -> exos.shown_port(), used by exec_exos.observe()
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("device", ["X435-8P-4S", "X440-G2-12p-10G4"])
def test_show_ports_key_information_detail_no_display_string(device):
    text = golden(device, "show-ports-key-information-detail", "normal-no-display-string")
    assert exos.shown_port(text, "1") == {}


# ---------------------------------------------------------------------------
# show upm timers / show upm profile -> exos.upm_listing_complete(),
# exos.listed_names(), exos.timer_row() -- used by exec_exos.leftovers(),
# install_safeguard(), safeguard_absent(), safeguard_fired()
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("device", ["X435-8P-4S", "X440-G2-12p-10G4"])
def test_show_upm_timers_empty_listing_is_complete(device):
    text = golden(device, "show-upm-timers", "empty")
    assert exos.upm_listing_complete(text, "Timers") is True
    assert exos.listed_names(text) == []
    assert exos.timer_row(text, "netopsabcdeft") is None


@pytest.mark.parametrize("device", ["X435-8P-4S", "X440-G2-12p-10G4"])
def test_show_upm_profile_empty_listing_is_complete(device):
    text = golden(device, "show-upm-profile", "empty")
    assert exos.upm_listing_complete(text, "Profiles") is True
    assert exos.listed_names(text) == []


# ---------------------------------------------------------------------------
# show upm profile <name> -- on a device without any UPM profile EXOS
# rejects the whole command ("Unrecognized command") instead of printing
# empty contents. exos.profile_contents() expects PROFILE_BEGIN/PROFILE_END
# and correctly returns None on such an answer.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("device,variant", [
    ("X435-8P-4S", "rejected-plain-name"),
    ("X435-8P-4S", "rejected-safeguard-shaped-name"),
    ("X440-G2-12p-10G4", "rejected-safeguard-shaped-name"),
])
def test_show_upm_profile_name_rejected_has_no_profile_contents(device, variant):
    text = golden(device, "show-upm-profile-name", variant)
    assert exos.profile_contents(text) is None


# ---------------------------------------------------------------------------
# show configuration (redacted: no 'account'/'sshd2' lines) ->
# exos.Snapshot(), used directly by exec_exos.accounts_check()/prechecks()
# and as the input of membership.states()/model().
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("device", ["X435-8P-4S", "X440-G2-12p-10G4"])
def test_show_configuration_snapshot_parses_vlan_module(device):
    text = golden(device, "show-configuration", "normal-redacted-secrets")
    snapshot = exos.Snapshot(text, "33.7.1.6")
    assert "vlan" in snapshot.configuration.modules
    # neither captured switch has a VLAN made with 'create vlan' -
    # Default/Mgmt are system VLANs that the configuration only adjusts
    assert snapshot.vlans == {}
    assert snapshot.ports == {}
    assert snapshot.port_lists == []


@pytest.mark.parametrize("device,ports", [("X435-8P-4S", 12), ("X440-G2-12p-10G4", 16)])
def test_show_configuration_snapshot_feeds_membership_model_without_inventory(device, ports):
    # Without the 'show ports no-refresh' inventory (snapshot.inventory is None)
    # membership.model() only recognises explicit VLAN additions; on both
    # captured switches every port is untagged in Default, added by one
    # "configure vlan Default add ports N-M untagged" command.
    text = golden(device, "show-configuration", "normal-redacted-secrets")
    snapshot = exos.Snapshot(text, "33.7.1.6")
    _vlans, members, _descriptions = membership.model(snapshot)
    assert len(members) == ports
    assert all(modes["untagged"] == {"Default"} for modes in members.values())


# ---------------------------------------------------------------------------
# Known parser limit shown by the captures (read-only captures, no code
# change): profile_contents() expects 'show upm profile <name>' to return
# the profile body or no marked answer at all - on a real device without
# a profile EXOS answers "%% Unrecognized command", which profile_contents()
# silently accepts as "no contents" (None). That is right for the caller
# (install_safeguard then reports "safeguard profile differs"), but the
# function would return None just as silently on any other CLI error
# (typo, missing permission). This is documented as an observation, not a bug.
# ---------------------------------------------------------------------------
