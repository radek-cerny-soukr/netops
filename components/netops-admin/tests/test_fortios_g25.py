"""G25 through Admin and DeviceAccess with a session-local fake Fortinet transport."""
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import json

import pytest

from fake_fortios import FakeFortiOS
from netops_admin import access, engine, enrollment, exec_fortios, execute
from netops_admin.errors import Rejected
from netops_admin.fortinet_cli import Reply
from netops_core.session import SessionError
from test_execute import make_runtime, request

FIXTURES = Path(__file__).with_name("fixtures") / "fortios_g25"
FILTER = "diagnose sys session filter"
LIST = "diagnose sys session list"
CLEAR = "diagnose sys session clear"
CHECKSUM = "diagnose sys ha checksum show"
KEY = "src:192.0.2.20"
TUPLE = {"dst": "198.51.100.1", "sport": 62531, "dport": 443, "proto": 6}
FIELDS = dict(vd="vd", src="source ip", dst="dest ip", sport="source port", dport="dest port", proto="proto",
              **{"session-state1": "state1"})
SECRET = "g25-private-text"


def fixture(name):
    return (FIXTURES / (name + ".txt")).read_text()


def change(**kwargs):
    fields = dict(table="sessions", op="clear", key=KEY, endpoint_impact=KEY, changes=TUPLE,
                  request_id="fg-g25-case", reason=SECRET, user_request=SECRET)
    return request(**{**fields, **kwargs})


class Wire:
    def __init__(self, device):
        self.device = device
        self.status = fixture("00-status")
        self.listing = fixture("session-active")
        self.write_listing = None
        self.checksum = fixture("checksum")
        self.opens = []
        self.commands = []
        self.clear_effective = True
        self.refuse_clear = False
        self.clears = 0
        self.filters = {}
        self.bad_filter_role = None
        self.list_failure = None
        self.fail_cleanup = False
        self.closed = set()
        self.exits = []

    @contextmanager
    def open(self, _device, credential, **_kwargs):
        role = "ro" if credential.login == self.device.check_credential.login else "rw"
        self.opens.append(role)
        self.filters[role] = {}
        try:
            yield SimpleNamespace(role=role, context=None, _platform="fortios", _last_prompt=b"host01 # ",
                                  run=lambda command, **kw: self.reply(role, command))
        finally:
            self.exits.append(role)

    def dialog(self, shell, command, _seconds, **_kwargs):
        return self.reply(shell.role, command)

    def reply(self, role, command):
        self.commands.append((role, command))
        if role in self.closed:
            raise SessionError("the Fortinet session is closed", code="closed")
        selected = self.filters[role]
        answer, rc = "", 0
        if command == "get system status":
            answer = self.status
        elif command == CHECKSUM:
            answer = self.checksum
        elif command == "show system accprofile":
            assert role == "rw"
            answer = "config system accprofile\nend\n"
        elif command in ("show system admin", "get system admin list"):
            assert role == "rw"
            answer = self.device.query(command)
        elif command == FILTER:
            answer = fixture("filter-initial")
            for selector, value in selected.items():
                if selector == "sport" and role == self.bad_filter_role:
                    value = "65534-65534"
                answer = answer.replace(f"\t{FIELDS[selector]}: any\n", f"\t{FIELDS[selector]}: {value}\n")
        elif command == FILTER + " clear":
            if self.fail_cleanup and self.clears and role == "rw":
                rc, answer = 1, "Command fail. Return code -1\n"
            else:
                selected.clear()
        elif command.startswith(FILTER + " "):
            _, _, _, _, selector, *parts = command.split()
            if selector == "session-state1":
                assert parts == ["00000000", "80000100"]
                shown = "(0 mask:80000100)"
            else:
                shown = "-".join(parts)
            selected[selector] = shown
        elif command == LIST:
            if self.list_failure == "disconnect":
                selected.clear()
                self.closed.add(role)
                raise SessionError("the Fortinet read reached its idle timeout", code="idle_timeout")
            if self.list_failure == "timeout":
                raise SessionError("the Fortinet read timed out", code="timeout")
            if self.list_failure == "refused":
                rc, answer = 1, "Unknown action 0\n"
            elif self.list_failure == "incomplete":
                answer = self.listing.rsplit("total session", 1)[0]
            else:
                answer = self.write_listing if role == "rw" and self.write_listing is not None else self.listing
        elif command.startswith("diagnose netlink interface list | grep "):
            index = int(command.split("index=")[1].split()[0])
            name = {5: "wan2", 30: "port1", 31: "mgmt-vlan"}[index]
            answer = f"if={name} family=00 type=1 index={index} mtu=1500 link=0 master=0\n"
        elif command == LIST + " expectation":
            answer = fixture("expectation-empty")
        else:
            assert command == CLEAR and role == "rw"
            assert selected and selected.get("vd") == "0"
            if self.refuse_clear:
                return Reply(1, f"Command fail. Return code -1\n{SECRET}".encode(), None, False, False)
            self.clears += 1
            if self.clear_effective:
                self.listing = fixture("session-empty")
        return Reply(rc, answer.encode(), None, False, False)


@pytest.fixture
def wired(tmp_path, monkeypatch):
    fake = FakeFortiOS(hostname="host01")
    wire = Wire(fake)
    runtime = make_runtime(tmp_path, fake)
    runtime.access_factory = access.DeviceAccess
    creds = {alias: SimpleNamespace(login=login.login, kind="password", use=lambda: SECRET)
             for alias, login in (("rw", fake.credential), ("ro", fake.check_credential))}
    monkeypatch.setattr(access.vault, "load", lambda *_args, **_kw: SimpleNamespace(credential=creds.__getitem__))
    monkeypatch.setattr(access.session, "fortinet_session", wire.open)
    monkeypatch.setattr(access.fortinet_cli, "dialog", wire.dialog)

    def certify(firmware):
        device = runtime.config.devices["lab"]
        accounts = exec_fortios.accounts_check(fake, device, "config system accprofile\nend\n")
        runtime.store.save_enrollment("lab", {"protocol": enrollment.PROTOCOL, "firmware": firmware,
                                      "binding": enrollment.binding(device, accounts, firmware, runtime.config),
                                      "change_id": "0" * 32})
    certify("7.6.8 build3744")
    return runtime, wire, certify


def preview(runtime, request=None):
    plan = execute.preview(runtime, "lab", request or change())
    assert plan["result"] == "ready", plan
    return plan


def test_preview_apply_readback_cleanup_and_irreversible_undo(wired):
    runtime, wire, _ = wired
    plan = preview(runtime)
    assert plan["firmware_support"]["status"] == "tested"
    assert plan["predicted"]["before"]["entries"][0]["serial"] == "00013100"
    assert plan["predicted"]["after"]["entries"] == []
    assert plan["return_mechanism"] == "irreversible"
    assert wire.opens == ["rw", "ro"] and ("rw", CLEAR) not in wire.commands
    assert not any(wire.filters.values())
    wire.opens.clear()
    wire.commands.clear()

    result = execute.apply(runtime, "lab", change(), expected_plan_sha256=plan["plan_sha256"])
    assert result["result"] == "confirmed", result["steps"]
    assert engine._read_plan(result["plan"])["endpoint_impact"] == KEY
    assert result["readback"] == plan["predicted"]["after"]
    assert wire.opens == ["rw", "ro"] and wire.clears == 1
    rw = [command for role, command in wire.commands if role == "rw"]
    write = rw.index(CLEAR)
    assert rw[write - 4:write] == [FILTER, LIST, LIST + " expectation", FILTER]
    assert rw[write + 1:write + 7] == [FILTER, LIST, LIST + " expectation", FILTER, FILTER + " clear", FILTER]
    assert not any(wire.filters.values())
    assert SECRET not in json.dumps([plan, result])
    with pytest.raises(Rejected) as caught:
        execute.undo(runtime, result["change_id"], "restore fixture")
    assert caught.value.reason_codes == ["undo_not_applicable"]
    assert wire.opens == ["rw", "ro"]


def test_apply_without_hash_and_preview_without_impact_are_refused_before_ssh(wired):
    runtime, wire, _ = wired
    with pytest.raises(Rejected) as missing_hash:
        execute.apply(runtime, "lab", change())
    assert missing_hash.value.reason_codes == ["clear_preview_required"]
    with pytest.raises(Rejected) as missing_impact:
        execute.preview(runtime, "lab", change(endpoint_impact=None))
    assert missing_impact.value.reason_codes == ["endpoint_impact_required"]
    assert not wire.commands


@pytest.mark.parametrize("key,changes", [("all", {}), ("src:0.0.0.0", {}), ("src:192.0.2.20/24", {}),
                                         ("src:192.0.2.20", {"proto": 0}), ("src:192.0.2.20", {"sport": 0}),
                                         ("src:192.0.2.20", {"dst": "198.51.100.1\nend"})])
def test_unsafe_filter_is_refused_before_ssh(wired, key, changes):
    runtime, wire, _ = wired
    result = execute.preview(runtime, "lab", change(key=key, changes=changes, endpoint_impact=key))
    assert result["reason_codes"] == ["clear_invalid_target"]
    assert not wire.commands


@pytest.mark.parametrize("fault,code", [("incomplete", "clear_readback_unreadable"), ("refused", "clear_readback_unreadable"),
                                        ("timeout", "fortios_clear_read_timeout")])
def test_failed_preflight_has_a_reason_and_clears_the_filter(wired, fault, code):
    runtime, wire, _ = wired
    wire.list_failure = fault
    result = execute.preview(runtime, "lab", change())
    assert result["reason_codes"] == [code]
    assert not any(wire.filters.values()) and not wire.clears


def test_disconnected_read_preserves_timeout_and_unverified_cleanup(wired):
    runtime, wire, _ = wired
    wire.list_failure = "disconnect"
    result = execute.preview(runtime, "lab", change())
    assert result["reason_codes"] == ["fortios_clear_read_timeout", "fortios_clear_cleanup_unverified"]
    assert not wire.clears


def test_config_change_between_preview_and_apply_refuses_the_old_hash(wired):
    runtime, wire, _ = wired
    plan = preview(runtime)
    wire.checksum = wire.checksum.replace("02 25 c7", "01 25 c7")
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", change(), expected_plan_sha256=plan["plan_sha256"])
    assert caught.value.reason_codes == ["plan_changed"] and not wire.clears


def test_write_filter_mismatch_refuses_before_clear_and_removes_both_filters(wired):
    runtime, wire, _ = wired
    plan = preview(runtime)
    wire.bad_filter_role = "rw"
    result = execute.apply(runtime, "lab", change(), expected_plan_sha256=plan["plan_sha256"])
    assert result["result"] == "rejected" and result["reason_codes"] == ["clear_scope_unverified"]
    assert not any(wire.filters.values()) and not wire.clears


@pytest.mark.parametrize("effective,cleanup,reason", [(False, True, "clear readback mismatch"),
                                                       (True, False, "the FortiOS session filter reset")])
def test_an_acknowledged_clear_requires_effect_and_cleanup(wired, effective, cleanup, reason):
    runtime, wire, _ = wired
    plan = preview(runtime)
    wire.clear_effective = effective
    wire.fail_cleanup = not cleanup
    result = execute.apply(runtime, "lab", change(), expected_plan_sha256=plan["plan_sha256"])
    assert result["result"] == "unknown" and result["reason"].startswith(reason)
    assert runtime.store.blocked("lab") is not None and wire.clears == 1


def test_refused_clear_is_not_repeated_and_releases_the_filter_and_sessions(wired):
    runtime, wire, _ = wired
    plan = preview(runtime)
    wire.commands.clear()
    wire.exits.clear()
    wire.refuse_clear = True

    record = execute.apply(runtime, "lab", change(), expected_plan_sha256=plan["plan_sha256"])

    assert (record["result"], record["reason"]) == ("unknown", "clear command acceptance unverified")
    assert runtime.store.blocked("lab")["change_id"] == record["change_id"]
    assert execute.recover(runtime, "lab") == []
    assert wire.commands.count(("rw", CLEAR)) == 1 and wire.clears == 0
    assert not any(wire.filters.values()) and sorted(wire.exits) == ["ro", "rw"]
    assert SECRET not in json.dumps(runtime.store.records())
    assert SECRET not in Path(runtime.config.audit_file).read_text()


def test_one_destination_is_supported_on_untested_firmware(wired):
    runtime, wire, certify = wired
    wire.status = wire.status.replace("7.6.8", "7.6.9")
    certify("7.6.9 build3744")
    req = change(key="dst:198.51.100.1", changes={}, endpoint_impact="dst:198.51.100.1")
    plan = preview(runtime, req)
    assert plan["firmware_support"]["status"] == "untested"
    assert plan["predicted"]["before"]["filter"] == {"dst": "198.51.100.1"}
    wire.listing = wire.listing.replace("serial=00013100", "serial=00013101")
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, "lab", req, expected_plan_sha256=plan["plan_sha256"])
    assert caught.value.reason_codes == ["plan_changed"]
    assert not wire.clears and not any(wire.filters.values())


@pytest.mark.parametrize("scenario,code", [
    ("local", "clear_protected_target"), ("other", "clear_scope_unverified"), ("empty", "clear_no_entry"),
])
def test_listed_sessions_must_prove_scope_and_exist(wired, scenario, code):
    runtime, wire, _ = wired
    if scenario == "empty":
        wire.listing = fixture("session-empty")
    elif scenario == "local":
        wire.listing = wire.listing.replace("state=log ", "state=log local ")
    else:
        wire.listing = wire.listing.replace(":62531->", ":62532->")
    result = execute.preview(runtime, "lab", change())
    assert result["reason_codes"] == [code]
    assert not any(wire.filters.values()) and not wire.clears


@pytest.mark.parametrize(("protected", "old", "new"), [
    ({"firewall policy": ["7"]}, "policy_id=5", "policy_id=7"),
    ({"interface": ["mgmt-vlan"]}, "dev=30->5/5->30", "dev=30->5/5->31"),
    ({"system interface": ["mgmt-vlan"]}, "dev=30->5/5->30", "dev=31->5/5->30"),
])
def test_inventory_protection_at_preview_and_immediately_before_clear(wired, protected, old, new):
    runtime, wire, certify = wired
    device = replace(runtime.config.devices["lab"], protected=protected)
    runtime.config = replace(runtime.config, devices={"lab": device})
    certify("7.6.8 build3744")
    original = wire.listing
    wire.listing = original.replace(old, new)
    refused = execute.preview(runtime, "lab", change())
    assert refused["result"] == "rejected" and refused["reason_codes"] == ["clear_protected_target"]
    assert not wire.clears and not any(wire.filters.values())

    wire.listing = original
    approved = preview(runtime)
    wire.write_listing = original.replace(old, new)
    result = execute.apply(runtime, "lab", change(), expected_plan_sha256=approved["plan_sha256"])
    assert result["result"] == "rejected" and result["reason_codes"] == ["clear_protected_target"]
    assert not wire.clears and not any(wire.filters.values())
