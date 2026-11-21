"""Catalyst 9800 operational clear through the Admin executor and fake SSH replies."""

import dataclasses
from pathlib import Path

import pytest

from fake_ios import FakeIos
from netops_admin import execute, ios
from netops_admin.access import AccessError
from netops_admin.errors import Rejected
from netops_core.c9800 import CLIENT_SUMMARY, colon_mac
from test_access import Shell, device_access
from test_ios import make_runtime, request

FIXTURES = Path(__file__).resolve().parents[2] / "netops-helper/tests/fixtures/real/c9800_g87"


def captured(name):
    return (FIXTURES / f"{name}.out").read_text()


DOTTED = captured("clients").splitlines()[-1].split()[0]
MAC = colon_mac(DOTTED)
COMMAND = f"wireless client mac-address {DOTTED} deauthenticate"


class CatalystController(FakeIos):
    def __init__(self):
        super().__init__("iolxe")
        # Reuse the measured IOS XE baseline for generic Admin account and snapshot guards.
        # Only the running-config release line is adapted to the documented controller identity.
        self.firmware = "17.3.5b"
        self.lines = ["version 17.3" if line == "version 17.18" else line for line in self.lines]
        self.saved = list(self.lines)
        self.before = captured("clients")
        self.after = captured("clients_alt")
        self.query_override["show version"] = captured("version")
        self.writes = []

    def check_query_status(self, command):
        assert command == CLIENT_SUMMARY
        answer = self.after if self.writes else self.before
        if isinstance(answer, Exception):
            raise answer
        return 0, answer

    def apply(self, steps, spec):
        marker = b"\r\n" + self.hostname.encode("ascii") + b"#"
        shell = Shell([marker, COMMAND.encode("ascii") + marker])
        accepted = device_access(shell).apply(steps, spec)
        assert shell.sent == [COMMAND]
        self.writes.extend(shell.sent)
        return accepted


def change(device, **values):
    return request(device, **{"op": "clear", "table": ios.WIRELESS_CLIENT,
                              "key": MAC, "changes": {}, "endpoint_impact": MAC, **values})


def test_preview_hash_apply_readback_and_no_undo(tmp_path):
    device = CatalystController()
    runtime = make_runtime(tmp_path, device)
    wanted = change(device)
    before = device.snapshot()
    preview = execute.preview(runtime, "lab-ios", wanted)
    assert preview["result"] == "ready", preview
    assert preview["endpoint_impact"] == DOTTED
    assert preview["commands"] == [COMMAND] and preview["return_mechanism"] == "irreversible"
    assert not preview["inverse_commands"] and not device.writes and not runtime.store.records()
    with pytest.raises(Rejected) as rejected:
        execute.apply(runtime, "lab-ios", wanted)
    assert rejected.value.reason_codes == ["clear_preview_required"]
    with pytest.raises(Rejected) as rejected:
        execute.apply(runtime, "lab-ios", wanted, expected_plan_sha256="f" * 64)
    assert rejected.value.reason_codes == ["plan_changed"]
    assert not device.writes
    result = execute.apply(runtime, "lab-ios", wanted, expected_plan_sha256=preview["plan_sha256"])
    assert result["result"] == "confirmed", result["steps"]
    assert result["readback"]["entries"] == [] and result["readback"]["other_entries"]
    assert device.writes == [COMMAND] and device.snapshot() == before and not device.saves
    assert execute.apply(runtime, "lab-ios", wanted, expected_plan_sha256=preview["plan_sha256"])["change_id"] == result["change_id"]
    for undo in (execute.preview_undo, execute.undo):
        with pytest.raises(Rejected) as rejected:
            undo(runtime, result["change_id"], "verify that wireless deauthentication has no inverse")
        assert rejected.value.reason_codes == ["undo_not_applicable"]
    assert device.writes == [COMMAND]


@pytest.mark.parametrize("key", ["all", "*", "ffff.ffff.ffff", "0100.5e00.0001", "0000.0000.0000", MAC + ",aa:bb:cc:dd:ee:ff"])
def test_refuses_bulk_or_group_scope_without_contact(tmp_path, key):
    device = CatalystController()
    runtime = make_runtime(tmp_path, device)
    runtime.access_factory = lambda _: pytest.fail("invalid scope contacted the device")
    with pytest.raises(Rejected) as rejected:
        execute.preview(runtime, "lab-ios", change(device, key=key, endpoint_impact=key))
    assert rejected.value.reason_codes == ["clear_invalid_target"]


def test_refuses_missing_impact_without_contact(tmp_path):
    device = CatalystController()
    runtime = make_runtime(tmp_path, device)
    runtime.access_factory = lambda _: pytest.fail("missing endpoint_impact contacted the device")
    with pytest.raises(Rejected) as rejected:
        execute.preview(runtime, "lab-ios", change(device, endpoint_impact=None))
    assert rejected.value.reason_codes == ["endpoint_impact_required"]


@pytest.mark.parametrize("mode,reason", [
    ("protected", "clear_protected_target"),
    ("foreign-iosxe", "clear_scope_unverified"),
    ("absent", "clear_no_entry"),
    ("truncated", "clear_readback_unreadable"),
    ("refused", "clear_readback_unreadable"),
    ("timeout", "wireless_client_read_timeout"),
])
def test_refuses_unproved_scope(tmp_path, mode, reason):
    device = CatalystController()
    runtime = make_runtime(tmp_path, device)
    if mode == "protected":
        runtime.config.devices["lab-ios"] = dataclasses.replace(
            runtime.config.devices["lab-ios"], protected={ios.WIRELESS_CLIENT: [MAC]},
        )
    elif mode == "foreign-iosxe":
        del device.query_override["show version"]
    elif mode == "absent":
        device.before = captured("clients_alt")
    elif mode == "truncated":
        device.before = "\n".join(device.before.splitlines()[:-1])
    elif mode == "refused":
        device.before = "% Authorization failed\n"
    elif mode == "timeout":
        device.before = AccessError("read timeout")
    result = execute.preview(runtime, "lab-ios", change(device))
    assert result["result"] == "rejected" and result["reason_codes"] == [reason], result
    assert not device.writes


def test_write_ack_without_observed_disconnect_is_unknown(tmp_path):
    device = CatalystController()
    device.after = device.before
    runtime = make_runtime(tmp_path, device)
    wanted = change(device)
    approved = execute.preview(runtime, "lab-ios", wanted)
    result = execute.apply(runtime, "lab-ios", wanted, expected_plan_sha256=approved["plan_sha256"])
    assert result["result"] == "unknown"
    assert device.writes == [COMMAND]
