"""Count starts of the OpenSSH executable through the common Admin entry points."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import pickle
import time
from types import SimpleNamespace

import pytest

from fake_fortiadc_admin import FakeADC, measured
from fake_fortios import FakeFortiOS
from fortinet_ssh_fixture import BLOB, PUBLIC_KEY, Counter, install_clients
from test_execute import make_runtime as fortios_runtime, request as fortios_request
from test_fortiadc_admin_runtime import Stub, make_runtime as adc_runtime, request as adc_request
from netops_admin import access, enrollment, execute, exec_fortiadc, exec_fortios, fortiadc_plan, fortios, readiness
from netops_core import hostkey
from approved_apply import approved_apply, preview_hash


@pytest.fixture(params=["fortios", "fortiadc"])
def wired(request, monkeypatch, tmp_path, tmp_path_factory):
    platform = request.param
    if platform == "fortios":
        fake, name, change = FakeFortiOS(), "lab", fortios_request
        fake.uuids = Counter(next(fake.uuids))
        runtime = fortios_runtime(tmp_path, fake)
        probe = "192.0.2.254/32"
    else:
        fake, name, change = FakeADC(), "adc", adc_request
        fake.pager_at = 4
        runtime = adc_runtime(tmp_path, fake)
        probe = "pool-a:99:rs-new:8081"
    key = ({"host_key": PUBLIC_KEY} if hasattr(runtime.config.devices[name], "host_key") else {})
    device = replace(runtime.config.devices[name], host_key_fingerprint=hostkey.fingerprint_of(BLOB),
                     check_address="198.51.100.15", **key)
    export = tmp_path / "export.json"
    export.write_text(json.dumps({"updated_at": time.time(), "pending": 0}))
    runtime.config = replace(runtime.config, devices={name: device}, export_status_file=str(export))
    runtime.notifier = lambda _: "sent"
    from enrollment_helpers import certify
    certify(runtime, fake, name)
    runtime.access_factory = access.DeviceAccess
    vault = {alias: SimpleNamespace(login=credential.login, kind="password", use=lambda: "fixture-password")
             for alias, credential in (("rw", fake.credential), ("ro", fake.check_credential))}
    monkeypatch.setattr(access.vault, "load", lambda *_args, **_kw: SimpleNamespace(credential=vault.__getitem__))
    state = tmp_path / "device"
    state.write_bytes(pickle.dumps(fake))
    (tmp_path / "platform").write_text(platform)

    def advance(seconds):
        current = pickle.loads(state.read_bytes())
        current.advance(seconds)
        state.write_bytes(pickle.dumps(current))

    if platform == "fortios":
        runtime.sleep = advance
    install_clients(tmp_path, monkeypatch, tmp_path_factory.getbasetemp() / "fortinet-ssh-pycache")
    return runtime, name, change, probe, tmp_path


def count(wired, operation, maximum=2, *, enforce=True):
    runtime, name, _, _, path = wired
    events = path / "events"
    rows = [json.loads(line) for line in events.read_text().splitlines()] if events.exists() else []
    events.unlink(missing_ok=True)
    ssh = [row for row in rows if row[0] == "ssh"]
    scans = [row for row in rows if row[0] == "ssh-keyscan"]
    print(f"{runtime.config.devices[name].platform} {operation}: ssh={len(ssh)} scan={len(scans)}")
    assert all(not Path(row[3]).exists() for row in ssh)
    if enforce:
        assert 0 < len(ssh) <= maximum and not scans
        if maximum == 2:
            assert {row[2] for row in ssh} == {runtime.config.devices[name].address, "198.51.100.15"}
    return len(ssh), len(scans)


def assert_budget(*counts):
    assert all(0 < ssh <= 2 and scans == 0 for ssh, scans in counts)


def test_confirmed_apply_and_undo_reuse_accounts(wired):
    runtime, name, change, _, path = wired
    original = pickle.loads((path / "device").read_bytes()).snapshot().encode()
    preview = execute.preview(runtime, name, change())
    assert preview["result"] == "ready", preview
    p = count(wired, "preview", enforce=False)
    applied = execute.apply(runtime, name, change(), expected_plan_sha256=preview["plan_sha256"])
    assert applied["result"] == "confirmed", applied["steps"]
    assert applied["plan"]["snapshot_sha256"] == hashlib.sha256(original).hexdigest()
    a = count(wired, "apply", enforce=False)
    undone = execute.undo(runtime, applied["change_id"], "restore fixture")
    assert undone["result"] == "confirmed", undone["steps"]
    u = count(wired, "undo", enforce=False)
    assert_budget(p, a, u)


@pytest.mark.parametrize("wired", ["fortiadc"], indirect=True)
def test_preview_with_live_read_only_prompt(wired):
    runtime, name, change, _, path = wired
    # Sanitized fortiadc-kvm netops-read prompt captured in a live acceptance run.
    (path / "check-prompt").write_text("LLLLLLLL-LLL $ ")
    result = execute.preview(runtime, name, change())
    assert result["result"] == "ready", result
    assert result["plan_sha256"]
    assert count(wired, "preview with read-only prompt") == (2, 0)


def test_doctor_reuses_accounts(wired):
    runtime, name, _, _, _ = wired
    report = readiness.doctor(runtime, name)
    assert any(item["check"] == "check account" and item["status"] == "ok" for item in report["checks"]), report
    count(wired, "doctor")


def test_enrollment_reuses_accounts_through_final_readback(wired):
    runtime, name, _, probe, _ = wired
    record = enrollment.run(runtime, name, probe)
    assert (record["result"], record.get("enrollment")) == ("reverted", "valid"), record["steps"]
    count(wired, "enrollment")


class Interrupted(BaseException):
    pass


def test_recover_reuses_one_session_per_record(wired, monkeypatch):
    runtime, name, change, _, _ = wired
    adapter = execute._adapter(runtime.config.devices[name].platform)
    observe = adapter.observe

    def interrupt_after_write(handle, plan):
        if runtime.store.running(name):
            raise Interrupted()
        return observe(handle, plan)

    with monkeypatch.context() as patch:
        patch.setattr(adapter, "observe", interrupt_after_write)
        with pytest.raises(Interrupted):
            approved_apply(runtime, name, change())
    count(wired, "interrupted apply", enforce=False)
    settled, = execute.recover(runtime, name)
    assert settled["result"] == "reverted", settled["steps"]
    count(wired, "recover", maximum=1)


def test_missing_host_key_is_refused_before_ssh(wired):
    runtime, name, change, _, _ = wired
    device = replace(runtime.config.devices[name], host_key=None)
    runtime.config = replace(runtime.config, devices={name: device})
    result = execute.preview(runtime, name, change())
    assert result["result"] == "rejected"
    assert "add host_key" in " ".join(result["reasons"])
    assert count(wired, "missing host key", enforce=False) == (0, 0)


@pytest.mark.parametrize("wired", ["fortiadc"], indirect=True)
@pytest.mark.parametrize("lose_inverse_reply", [False, True])
def test_disconnected_write_is_not_replayed(wired, lose_inverse_reply):
    runtime, name, change, _, path = wired
    approved = preview_hash(runtime, name, change())
    count(wired, "preview")
    (path / "disconnect-after-write").touch()
    result = execute.apply(runtime, name, change(), expected_plan_sha256=approved)
    assert result["result"] == "unknown"
    assert {"step": "change_failed", "detail": "AccessError after 8 lines"} in [
        {field: step[field] for field in ("step", "detail")} for step in result["steps"]
    ]
    assert runtime.store.blocked(name) is not None
    current = pickle.loads((path / "device").read_bytes())
    assert len(current.applied_blocks) == 1 and current.pools["pool-a"][1]["status"] == "disable"
    count(wired, "disconnect after write")
    if lose_inverse_reply:
        pending, = execute.recover(runtime, name)
        assert pending["change_id"] == result["change_id"] and pending["result"] == "unknown"
        assert count(wired, "disconnect after inverse", maximum=1) == (1, 0)
        restored = pickle.loads((path / "device").read_bytes())
        assert len(restored.applied_blocks) == 2 and restored.pools["pool-a"][1]["status"] == "enable"
    (path / "disconnect-after-write").unlink()
    recovered, = execute.recover(runtime, name)
    assert recovered["change_id"] == result["change_id"]
    assert recovered["result"] == "reverted", recovered["steps"]
    assert count(wired, "recover disconnected write", maximum=1) == (1, 0)
    current = pickle.loads((path / "device").read_bytes())
    assert len(current.applied_blocks) == 2 and current.pools["pool-a"][1]["status"] == "enable"
    assert execute.recover(runtime, name) == []


@pytest.mark.parametrize("wired", ["fortiadc"], indirect=True)
def test_interrupted_apply_recovers_when_the_compensation_read_disconnects(wired, monkeypatch):
    runtime, name, change, _, path = wired
    state = path / "device"
    fake = pickle.loads(state.read_bytes())
    fake.status_text = measured("get_system_status.txt").replace("FortiADC-KVM\n", fake.hostname + "\n", 1)
    live = fortiadc_plan.load(exec_fortiadc.snapshot(Stub()), None)
    members = live.entries(fortiadc_plan.TABLE)
    pool = "LAB_POOL_SMTP"
    fake.pools = {pool: {number: {
        "real-server": members[f"{pool}:{number}"].attributes["real-server"],
        "pool_member_service_port": members[f"{pool}:{number}"].attributes["pool-member-service-port"],
        "status": "enable",
    } for number in (1, 2)}}
    fake.real_servers = sorted(live.real_servers())
    fake.virtual_servers = {"LAB_VS_SMTP": {"load-balance-pool": pool}}
    fake.health = {"LAB_VS_SMTP": {1: "UP", 2: "UP"}}
    state.write_bytes(pickle.dumps(fake))
    before = fake.pools
    step = execute._step

    def interrupt_after_write(runtime, record, name, detail=None):
        step(runtime, record, name, detail)
        if name == "change_applied":
            raise Interrupted()

    with monkeypatch.context() as patch:
        patch.setattr(execute, "_step", interrupt_after_write)
        with pytest.raises(Interrupted):
            approved_apply(runtime, name, change(key=f"{pool}:2"))
    running, = runtime.store.running(name)
    disabled = pickle.loads(state.read_bytes())
    assert len(disabled.applied_blocks) == 1 and disabled.pools[pool][2]["status"] == "disable"
    count(wired, "interrupted apply before compensation", enforce=False)

    disconnect = path / "disconnect-on-second-status"
    disconnect.touch()
    settled = execute.recover(runtime, name)
    assert not disconnect.exists()
    assert settled[-1]["result"] == "reverted"
    saved = runtime.store.operation(running["change_id"])
    steps = [entry["step"] for entry in saved["steps"]]
    assert saved["result"] == "reverted" and steps.count("recovery_start") == 2
    assert steps[-5:] == ["compensation_recovery_pending", "recovery_start", "compensation_start",
                          "compensation_applied", "compensation_verified"]
    restored = pickle.loads(state.read_bytes())
    assert restored.pools == before and restored.applied_blocks[1:] == [running["plan"]["inverse"]]
    assert count(wired, "retry after compensation read disconnect", enforce=False) == (2, 0)


@pytest.mark.parametrize("wired", ["fortios"], indirect=True)
def test_password_dialog_and_literal_question_mark_share_write_session(wired):
    runtime, name, _, _, path = wired
    spec = exec_fortios.prompt_spec("fw-lab")
    handle = runtime.access_factory(runtime.config.devices[name])
    command = 'execute api-user generate-key "fixture"'
    with handle.operation():
        assert fortios.api_key(handle.generate_api_key(command, spec)) == "fixturetoken"
        assert handle.apply(["config firewall address", 'edit "srv-web"', 'set comment "literal?"', "next",
                             "end"], spec) == 5
        (path / "no-password-prompt").touch()
        with pytest.raises(access.AccessError, match="did not ask"):
            handle.generate_api_key(command, spec)
        assert "literal?" in handle.snapshot()
    count(wired, "password dialog", maximum=1)


@pytest.mark.parametrize("wired", ["fortios"], indirect=True)
def test_fortios_ipsec_cli_refusal_keeps_the_session_and_reports_the_marker(wired):
    runtime, name, _, _, _ = wired
    handle = runtime.access_factory(runtime.config.devices[name])
    spec = exec_fortios.prompt_spec("fw-lab")
    with handle.operation():
        with pytest.raises(access.AccessError, match="Unknown action 0") as caught:
            handle.apply(['execute vpn ipsec tunnel down "netops-ipsec" "netops-ipsec" 1'], spec)
        assert caught.value.accepted_lines == 0
        assert "config system global" in handle.snapshot()
    assert count(wired, "IPsec CLI refusal", maximum=1) == (1, 0)


@pytest.mark.parametrize("wired", ["fortiadc"], indirect=True)
def test_completed_refusal_can_be_compensated_on_the_same_pty(wired):
    runtime, name, change, _, path = wired
    approved = preview_hash(runtime, name, change())
    count(wired, "preview")
    (path / "refuse-after-write").touch()
    result = execute.apply(runtime, name, change(), expected_plan_sha256=approved)
    assert result["result"] == "reverted" and result["reason"] == "change failed", result["steps"]
    current = pickle.loads((path / "device").read_bytes())
    assert len(current.applied_blocks) == 2
    assert current.applied_blocks[-1][4] == "set status enable"
    count(wired, "compensated refusal")
