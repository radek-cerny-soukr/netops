"""X21 through the Admin MCP entry points and pinned SFTP transport boundary."""
import os
from pathlib import Path
import re
import stat
from subprocess import CompletedProcess
import tempfile

import pytest

from fake_exos import FakeExos
from netops_admin import exos_acl
from netops_admin.config import DEFAULT_LIMITS
from netops_core import sftp
from test_exos_g42 import args, preview_apply, setup, undo
from test_mcp_server import call

ROOT = Path(__file__).parent / "fixtures/exos/g47"
NAME = "netops-g47-capture"
VLAN = "netops-g47"
POLICY = (ROOT / (NAME + ".pol")).read_text()


def capture(name, device="vm"):
    return (ROOT / device / (name + ".txt")).read_text()


class Lab(FakeExos):
    def __init__(self, monkeypatch, fixture):
        super().__init__()
        self.fixture = fixture
        self.vlans[VLAN] = {"tag": "3947"}
        self.binding = None
        self.files = {}
        self.transfers = []
        self.truncated = False
        self.mismatch = False
        self.fail_install_check = False
        self.fail_remove_once = False
        self.device = None
        monkeypatch.setattr(sftp, "_exos_batch", self.transfer)

    def _host_key(self):
        return "pinned transport"

    def transfer(self, host, port, credential, host_key, legacy, command, *, descriptor=None):
        assert host_key == "pinned transport"
        verb, *operands = command.split()
        if verb in ("get", "put"):
            assert stat.S_IMODE(os.fstat(descriptor).st_mode) == 0o600
        if verb != "ls":
            self.transfers.append(verb)
        stdout, stderr, rc = b"", b"", 0
        if verb == "ls":
            name = operands[-1]
            raw_file = self.files.get(name)
            if raw_file is None:
                stderr = capture("sftp-missing", "vm-b").replace(NAME + ".pol", name).encode()
                rc = 1
            else:
                line = capture("list-file", self.fixture).replace(NAME + ".pol", name)
                stdout = re.sub(r"(?m)(^-[^\n]*?\s+)132(\s+Nov)", rf"\g<1>{len(raw_file)}\2", line).encode()
        elif verb == "get":
            os.write(descriptor, self.files[operands[0]])
        elif verb == "put":
            self.files[operands[1]] = os.pread(descriptor, sftp.EXOS_POLICY_MAX_BYTES, 0)
        elif verb == "rename":
            self.files[operands[1]] = self.files.pop(operands[0])
        elif verb == "rm":
            if self.fail_remove_once:
                self.fail_remove_once = False
                rc = 1
            else:
                self.files.pop(operands[0])
        else:
            raise AssertionError(command)
        return CompletedProcess([], rc, stdout, stderr)

    def snapshot(self):
        acl = capture("bound-config").splitlines()[3] + "\n" if self.binding else ""
        return super().snapshot() + "# Module acl configuration.\n" + acl + "# Module next configuration.\n"

    def _command(self, words, automatic):
        if words == ["configure", "access-list", NAME, "vlan", VLAN, "ingress"]:
            self.binding = NAME
        elif words == ["unconfigure", "access-list", "vlan", VLAN, "ingress"]:
            self.binding = None
        else:
            return super()._command(words, automatic)
        self.unsaved = True
        return True

    def query_status(self, command):
        if command.startswith("check policy "):
            name = command.split()[2]
            if name != NAME and self.fail_install_check:
                return 250, capture("absent-file", self.fixture).replace(NAME, name)
            if name + ".pol" in self.files:
                return 0, capture("checked-file", self.fixture)
            return 250, capture("absent-file", self.fixture).replace(NAME, name)
        if command == "show policy":
            return 0, capture("bound-policy" if self.binding else "absent-policy", self.fixture)
        return super().query_status(command)

    def check_query_status(self, command):
        if command.startswith("check policy "):
            return self.query_status(command)
        if command == "show access-list":
            answer = capture("bound-acl-all" if self.binding else "absent-acl", self.fixture)
            if self.truncated:
                answer = "\n".join(capture("bound-acl-all", self.fixture).splitlines()[:2])
            return 0, answer
        if command == f"show access-list vlan {VLAN} ingress detail":
            answer = capture("bound-detail", self.fixture)
            return 0, answer.replace("192.0.2.147", "192.0.2.148") if self.mismatch else answer
        raise AssertionError(command)

    def check_query(self, command):
        if command == f"show vlan {VLAN}":
            return capture("empty-vlan")
        return super().check_query(command)


def file_request(op, changes=None, **fields):
    return args(exos_acl.POLICY, changes or {}, key=NAME, op=op, request_id=f"g47-file-{op}", **fields)


def attachment(op="create", **fields):
    return args(exos_acl.BINDING, {"policy": NAME} if op == "create" else {}, key=f"vlan:{VLAN}",
                op=op, request_id=f"g47-vlan-{op}", **fields)


def runtime_for(monkeypatch, path, fixture="vm", **options):
    path.mkdir(parents=True, exist_ok=True)

    def temporary_descriptor(name, flags):
        # The test sandbox resolves fchmod descriptors to a path under tmp_path.
        fd, _ = tempfile.mkstemp(prefix=name, dir=path)
        os.fchmod(fd, 0o644)
        return fd

    monkeypatch.setattr(sftp.os, "memfd_create", temporary_descriptor)
    device = Lab(monkeypatch, fixture)
    runtime = setup(monkeypatch, path, device, **options)
    device.device = runtime.config.devices["sw"]
    return device, runtime


@pytest.mark.parametrize("fixture", ["vm", "vm-b", "x440"])
def test_acl_lifecycle_mcp(monkeypatch, tmp_path, fixture):
    device, _ = runtime_for(monkeypatch, tmp_path, fixture, limits=dict(DEFAULT_LIMITS, changes_per_device_per_hour=16))
    before = device.snapshot()
    request = file_request("create", {exos_acl.CONTENT: POLICY})
    confirmation = call("admin_apply", request)
    assert confirmation["reason_codes"] == ["plan_changed"]
    assert not device.transfers

    preview = call("admin_preview", request)
    assert preview["result"] == "ready", preview
    assert not device.files and not device.transfers and device.snapshot() == before
    created = call("admin_apply", dict(request, expected_plan_sha256=preview["plan_sha256"]))
    assert created["result"] == "confirmed", created
    assert device.files == {NAME + ".pol": POLICY.encode()}
    assert device.saves == 0 and not device.applied_blocks

    updated_policy = POLICY.replace("192.0.2.147", "192.0.2.148").replace("    if", "\tif")
    _, updated = preview_apply(device, file_request("update", {exos_acl.CONTENT: updated_policy}))
    assert device.files[NAME + ".pol"] == updated_policy.encode()
    undo(device, updated)
    assert device.files == {NAME + ".pol": POLICY.encode()}

    preview, attached = preview_apply(device, attachment())
    assert preview["commands"] == [f"configure access-list {NAME} vlan {VLAN} ingress"]
    assert device.binding == NAME and device.saves == 1
    assert call("admin_preview", file_request("delete"))["reason_codes"] == [exos_acl.UNSAFE]

    _, detached = preview_apply(device, attachment("delete"))
    assert device.binding is None and not device.timers and not device.profiles
    undo(device, detached)
    assert device.binding == NAME
    undo(device, attached)
    assert device.snapshot() == before and not device.timers and not device.profiles

    _, deleted = preview_apply(device, file_request("delete"))
    assert not device.files
    undo(device, deleted)
    assert device.files == {NAME + ".pol": POLICY.encode()}
    undo(device, created)
    assert not device.files and device.snapshot() == before


def test_refuses_partial_answers_unsafe_scope_and_file_drift(monkeypatch, tmp_path):
    device, _ = runtime_for(monkeypatch, tmp_path, protected={"vlan": (VLAN,)})
    request = attachment()
    device.files[NAME + ".pol"] = POLICY.encode()
    assert call("admin_preview", request)["reason_codes"] == [exos_acl.UNSAFE]
    assert not device.applied_blocks
    device, _ = runtime_for(monkeypatch, tmp_path / "second")
    device.files[NAME + ".pol"] = POLICY.encode()
    device.truncated = True
    assert call("admin_preview", request)["reason_codes"] == [exos_acl.UNREADABLE]
    device.truncated = False
    preview = call("admin_preview", request)
    assert preview["result"] == "ready", preview
    device.files[NAME + ".pol"] = POLICY.replace("192.0.2.147", "192.0.2.148").encode()
    assert call("admin_apply", dict(request, expected_plan_sha256=preview["plan_sha256"]))["reason_codes"] == [
        "plan_changed"]
    assert not device.applied_blocks


def test_device_check_failure_drops_stage_and_binding_mismatch_reverts(monkeypatch, tmp_path):
    device, _ = runtime_for(monkeypatch, tmp_path)
    request = file_request("create", {exos_acl.CONTENT: POLICY})
    preview = call("admin_preview", request)
    device.fail_install_check = True
    device.fail_remove_once = True
    result = call("admin_apply", dict(request, expected_plan_sha256=preview["plan_sha256"]))
    assert result["result"] == "reverted" and not device.files, result
    assert "put" in device.transfers and "rm" in device.transfers and "rename" not in device.transfers
    assert device.transfers.count("rm") == 2
    device.fail_install_check = False
    device.files[NAME + ".pol"] = POLICY.encode()
    device.mismatch = True
    bind = attachment()
    preview = call("admin_preview", bind)
    assert preview["result"] == "ready", preview
    result = call("admin_apply", dict(bind, expected_plan_sha256=preview["plan_sha256"]))
    assert result["result"] == "reverted" and device.binding is None, result
    assert not device.profiles and not device.timers


def test_bad_file_rejects_and_new_firmware_warns(monkeypatch, tmp_path):
    firmware = "99.0.0"
    device, _ = runtime_for(monkeypatch, tmp_path, firmware=firmware)
    device.firmware = firmware
    denied = file_request("create", {exos_acl.CONTENT: "send secrets"}, endpoint_impact=None)
    assert call("admin_preview", denied)["reason_codes"] == [exos_acl.INVALID]
    assert "put" not in device.transfers
    preview = call("admin_preview", file_request("create", {exos_acl.CONTENT: POLICY}))
    assert preview["result"] == "ready", preview
    assert preview["firmware_support"]["status"] == "untested"


def test_port_acl_table_from_x440():
    assert exos_acl.active_bindings(capture("x440-port-table", "x440")) == {
        "port:10": ("netops-g47-live", 1, 0),
    }


@pytest.mark.parametrize("request_fields", [file_request("create", {exos_acl.CONTENT: POLICY}), attachment()])
def test_g47_apply_requires_preview_hash(monkeypatch, tmp_path, request_fields):
    device, _ = runtime_for(monkeypatch, tmp_path)
    snapshot = device.snapshot()
    denied = call("admin_apply", request_fields)
    assert denied["result"] == "rejected" and denied["reason_codes"] == ["plan_changed"]
    assert device.snapshot() == snapshot and not device.applied_blocks and not device.transfers


@pytest.mark.parametrize("key", ["port:10", f"vlan:{VLAN}"])
def test_active_acl_target_requires_endpoint_impact(monkeypatch, tmp_path, key):
    device, _ = runtime_for(monkeypatch, tmp_path)
    device.files[NAME + ".pol"] = POLICY.encode()
    baseline = device.snapshot
    device.snapshot = lambda: baseline().replace("# Module ems", f"configure vlan {VLAN} add ports 10 untagged\n# Module ems")
    check = device.check_query

    def active_target(command):
        if command == f"show vlan {VLAN}":
            return capture("empty-vlan").replace("Ports:   0.", "Ports:   1.").replace(
                "active ports=0)", "active ports=1)\n       Untag:  *10")
        if command == "show ports 10 configuration no-refresh":
            return device.query(command).replace(" E       R ", " E       A ")
        return check(command)

    device.check_query = active_target
    fields = args(exos_acl.BINDING, {"policy": NAME}, key=key, op="create")
    denied = call("admin_preview", fields)
    assert denied["result"] == "rejected", denied
    assert denied["reason_codes"] == ["endpoint_impact_required"] and not device.applied_blocks
    allowed = call("admin_preview", dict(fields, endpoint_impact=key))
    assert allowed["result"] == "ready", allowed
    assert not device.applied_blocks
