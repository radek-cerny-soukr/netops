from __future__ import annotations

import datetime
import os
import shlex
import stat
from types import SimpleNamespace

import pytest
from fake_exos import FakeExos
from fake_fortios import FakeFortiOS
from test_access import Shell, device_access
from test_execute import foreign_comment, make_runtime, request, steps
from test_execute_exos import make_runtime as make_exos_runtime, request as exos_request

from netops_admin import access, audit, exec_exos, execute
from netops_admin.errors import Rejected

LIMIT = execute.EXPIRY_WAIT_LIMIT_SECONDS


class DeviceTime:
    def __init__(self, read_seconds, offset_seconds, fires):
        self.now, self.read_seconds, self.offset, self.fires = 0.0, read_seconds, offset_seconds, fires
        self.base = datetime.datetime(2026, 10, 13, 12, 0, 0)

    def sleep(self, seconds):
        self.now += seconds

    def monotonic(self):
        return self.now

    def clock(self, _access):
        self.now += self.read_seconds
        return self.base + datetime.timedelta(seconds=self.now + self.offset)

    def safeguard_fired(self, _access, _record):
        self.now += self.read_seconds
        return self.fires


def wait_for_expiry(device, target=None):
    runtime = SimpleNamespace(sleep=device.sleep, monotonic=device.monotonic)
    fire_at = device.base + datetime.timedelta(seconds=180)
    execute._wait_for_expiry(runtime, device, target, {"safeguard": {"fire_at": fire_at.strftime(execute.FIRE_AT_FORMAT)}},
                             due=180.0)


def test_the_expiry_wait_returns_once_the_safeguard_has_fired():
    device = DeviceTime(0, 0, True)
    wait_for_expiry(device)
    assert 200 <= device.now <= 210


@pytest.mark.parametrize("read_seconds", [0, 25, 59])
def test_the_expiry_wait_ends_by_its_limit_counting_the_time_of_the_device_reads(read_seconds):
    device = DeviceTime(read_seconds, -3600, False)
    with pytest.raises(Rejected, match="did not expire"):
        wait_for_expiry(device)
    assert LIMIT <= device.now <= LIMIT + max(read_seconds, 1)


@pytest.mark.parametrize("read_seconds", [0, 25])
def test_the_proof_wait_stays_bounded_by_its_monotonic_limit(read_seconds):
    device = DeviceTime(read_seconds, 0, False)
    with pytest.raises(Rejected, match="not seen fired"):
        wait_for_expiry(device)
    assert device.now <= 180 + execute.EXPIRY_GRACE_SECONDS + execute.EXPIRY_WAIT_SLACK_SECONDS + max(read_seconds, 1)


def test_an_answer_that_arrives_after_the_limit_is_not_used():
    device = DeviceTime(0, -3600, True)
    clock = device.clock

    def late(target):
        if device.now >= LIMIT - 5:
            device.now += 30
            return device.base + datetime.timedelta(days=1)
        return clock(target)

    device.clock = late
    with pytest.raises(Rejected, match="did not expire"):
        wait_for_expiry(device)
    assert device.now <= LIMIT + 30


@pytest.mark.parametrize("fires", [False, True])
def test_the_wait_also_ends_when_only_its_pauses_advance_the_time(fires):
    device = DeviceTime(0, -3600 if not fires else 0, fires)
    runtime = SimpleNamespace(sleep=device.sleep, monotonic=lambda: 0.0)
    fire_at = device.base + datetime.timedelta(seconds=180)
    record = {"safeguard": {"fire_at": fire_at.strftime(execute.FIRE_AT_FORMAT)}}
    if fires:
        execute._wait_for_expiry(runtime, device, None, record, due=180.0)
        assert 200 <= device.now <= 210
    else:
        with pytest.raises(Rejected, match="did not expire"):
            execute._wait_for_expiry(runtime, device, None, record, due=180.0)
        assert LIMIT <= device.now <= LIMIT + 1


def test_each_device_read_is_limited_to_the_time_left():
    device = DeviceTime(25, -3600, False)
    target, seen, clock = SimpleNamespace(read_seconds=None), [], device.clock

    def measured(handle):
        seen.append((device.now, handle.read_seconds))
        return clock(handle)

    device.clock = measured
    with pytest.raises(Rejected):
        wait_for_expiry(device, target)
    assert len(seen) > 2 and target.read_seconds is None
    assert all(limit == pytest.approx(max(LIMIT - started, 1)) for started, limit in seen)


def test_device_access_queries_take_the_read_limit(monkeypatch):
    handle = access.DeviceAccess.__new__(access.DeviceAccess)
    handle.device = SimpleNamespace(legacy_ssh=None, address="192.0.2.1", port=22, platform="fortios")
    handle._host_key_lines, handle.credential, timeouts = {"192.0.2.1": "192.0.2.1 ssh-ed25519 AAAA"}, object(), []

    def run_command(*_arguments, timeout_seconds, **_options):
        timeouts.append(timeout_seconds)
        return SimpleNamespace(rc=0, stdout=b"System time: Mon Oct 13 12:00:00 2026\n")

    monkeypatch.setattr(access.ssh, "run_command", run_command)
    handle.query("get system status")
    handle.read_seconds = 7.5
    handle.query("get system status")
    handle.read_seconds = 600.0
    handle.query("get system status")
    assert timeouts == [access.QUERY_TIMEOUT_SECONDS, 7.5, access.QUERY_TIMEOUT_SECONDS]


def audit_event(log):
    return log.event("administrative", device="lab", action="unblock", reason_characters=1, change_id=None)


def mode(path):
    return stat.S_IMODE(os.lstat(path).st_mode)


def test_the_audit_log_is_created_with_mode_0640_and_takes_events(tmp_path):
    path = tmp_path / "audit" / "audit.jsonl"
    log = audit.AuditLog(path)
    log.check_writable()
    audit_event(log)
    assert mode(path) == 0o640 and len(path.read_text().splitlines()) == 1
    path.chmod(0o600)
    audit_event(log)
    assert mode(path) == 0o640 and len(path.read_text().splitlines()) == 2


def test_the_audit_log_is_never_opened_through_a_symbolic_link(tmp_path):
    vault = tmp_path / "vault.json"
    vault.write_text('{"version": 2}\n')
    vault.chmod(0o600)
    link = tmp_path / "audit.jsonl"
    link.symlink_to(vault)
    log = audit.AuditLog(link)
    with pytest.raises(Rejected, match="symbolic link"):
        log.check_writable()
    with pytest.raises(OSError, match="symbolic link"):
        audit_event(log)
    assert mode(vault) == 0o600 and vault.read_text() == '{"version": 2}\n'


def test_a_dangling_link_in_place_of_the_audit_log_creates_nothing(tmp_path):
    link = tmp_path / "audit.jsonl"
    link.symlink_to(tmp_path / "elsewhere.jsonl")
    with pytest.raises(Rejected, match="symbolic link"):
        audit.AuditLog(link).check_writable()
    assert not (tmp_path / "elsewhere.jsonl").exists()


def test_an_audit_log_with_a_second_name_is_refused(tmp_path):
    other = tmp_path / "other.json"
    other.write_text("{}\n")
    other.chmod(0o600)
    path = tmp_path / "audit.jsonl"
    os.link(other, path)
    log = audit.AuditLog(path)
    with pytest.raises(Rejected, match="one name"):
        log.check_writable()
    with pytest.raises(OSError, match="one name"):
        audit_event(log)
    assert mode(other) == 0o600 and other.read_text() == "{}\n"


def test_an_apply_with_a_linked_audit_log_is_rejected_before_any_mutation(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    vault = tmp_path / "vault.json"
    vault.write_text("{}\n")
    vault.chmod(0o600)
    (tmp_path / "audit").mkdir(exist_ok=True)
    (tmp_path / "audit" / "audit.jsonl").symlink_to(vault)
    with pytest.raises(Rejected, match="audit log"):
        execute.apply(runtime, "lab", request())
    assert not device.applied_blocks and mode(vault) == 0o600 and vault.read_text() == "{}\n"


def interrupted_before_the_request_id_was_registered(tmp_path, device, monkeypatch, request_id):
    runtime = make_runtime(tmp_path, device)

    def killed(*_arguments, **_options):
        raise KeyboardInterrupt

    monkeypatch.setattr(runtime.store, "remember_request", killed)
    with pytest.raises(KeyboardInterrupt):
        execute.apply(runtime, "lab", request(request_id=request_id))
    runtime = make_runtime(tmp_path, device)
    assert runtime.store.request(request_id) is None
    assert [record["status"] for record in runtime.store.records() if record["request_id"] == request_id] == ["running"]
    return runtime


def test_a_request_id_reused_for_other_content_is_refused_in_sequence(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    assert execute.apply(runtime, "lab", request(request_id="req-seq-1"))["result"] == "confirmed"
    with pytest.raises(Rejected, match=execute.REUSED_REQUEST):
        execute.apply(runtime, "lab", request(request_id="req-seq-1", key="other-host"))


def test_a_journaled_request_id_stays_used_after_an_interruption_before_its_registration(tmp_path, monkeypatch):
    device = FakeFortiOS()
    runtime = interrupted_before_the_request_id_was_registered(tmp_path, device, monkeypatch, "req-crash-1")
    with pytest.raises(Rejected, match=execute.REUSED_REQUEST):
        execute.apply(runtime, "lab", request(request_id="req-crash-1", key="other-host"))
    settled = execute.recover(runtime, "lab")
    assert [(record["result"], record["reason"]) for record in settled] == [("rejected", "interrupted before any mutation")]
    preview = execute.preview(runtime, "lab", request(request_id="req-crash-1", key="other-host"))
    assert preview["result"] == "rejected" and preview["reasons"] == [execute.REUSED_REQUEST]
    with pytest.raises(Rejected, match=execute.REUSED_REQUEST):
        execute.apply(runtime, "lab", request(request_id="req-crash-1", key="other-host"))
    again = execute.apply(runtime, "lab", request(request_id="req-crash-1"))
    assert again["change_id"] == settled[0]["change_id"] and again["result"] == "rejected"
    assert len([record for record in runtime.store.records() if record["request_id"] == "req-crash-1"]) == 1
    assert "new-host" not in device.addresses and "other-host" not in device.addresses and not device.applied_blocks


def test_a_journaled_request_id_on_another_device_is_refused(tmp_path, monkeypatch):
    device = FakeFortiOS()
    runtime = interrupted_before_the_request_id_was_registered(tmp_path, device, monkeypatch, "req-crash-2")
    record = next(record for record in runtime.store.records() if record["request_id"] == "req-crash-2")
    record["device"] = "elsewhere"
    runtime.store.save(record)
    with pytest.raises(Rejected, match=execute.REUSED_REQUEST):
        execute.apply(runtime, "lab", request(request_id="req-crash-2"))


BANNERS = {
    "none": b"",
    "plain": b"ExtremeXOS (X440G2) Copyright (C) 2026\r\n\r\n",
    "names the switch": b"Authorized access to sw-lab.example.net only\r\n\r\n",
    "names the switch with stars": b"*** sw-lab.example.net: authorized use only ***\r\n\r\n",
}


@pytest.mark.parametrize("dirty", [True, False])
@pytest.mark.parametrize("banner", sorted(BANNERS))
def test_the_unsaved_marker_is_read_from_the_prompt_after_any_login_banner(banner, dirty):
    prompt = (b"* " if dirty else b"") + b"sw-lab.1 # "
    shell = Shell([b"\r\n" + BANNERS[banner] + prompt])
    assert device_access(shell).login_prefix(exec_exos.prompt_spec("sw-lab")) == (b"*" if dirty else b"")


@pytest.mark.parametrize("dirty", [True, False])
def test_the_exos_precheck_refuses_unsaved_changes_behind_a_banner_naming_the_switch(dirty):
    prompt = (b"* " if dirty else b"") + b"sw-lab.1 # "
    handle = device_access(Shell([BANNERS["names the switch"] + prompt]))
    handle.query = lambda command: "Image   : ExtremeXOS version 33.7.1.6 by release-manager\n"
    reasons = exec_exos.prechecks(handle, SimpleNamespace(firmware="33.7.1.6"), "", exec_exos.prompt_spec("sw-lab"))
    assert reasons == (["the switch has unsaved configuration changes of someone else"] if dirty else [])


def test_a_session_still_sends_its_lines_after_a_banner_naming_the_switch():
    shell = Shell([BANNERS["names the switch"] + b"sw-lab.1 # ", b"\r\nsw-lab.2 # "])
    assert device_access(shell).apply(["show vlan"], exec_exos.prompt_spec("sw-lab")) == 1
    assert shell.sent == ["show vlan"]


def killed_in_the_removal(lines_done):
    def crash(fake, lines):
        if lines[0] == "config system automation-stitch" and lines[1].startswith("delete"):
            fake._run(lines[:lines_done])
            raise KeyboardInterrupt

    return crash


@pytest.mark.parametrize("lines_done", [2, 4, 7])
def test_recover_confirms_a_verified_change_whose_stitch_was_already_removed(tmp_path, lines_done):
    device = FakeFortiOS()
    device.on_apply = killed_in_the_removal(lines_done)
    runtime = make_runtime(tmp_path, device)
    with pytest.raises(KeyboardInterrupt):
        execute.apply(runtime, "lab", request())
    assert not device.stitches and (device.triggers or device.actions)
    device.on_apply = None
    settled = execute.recover(make_runtime(tmp_path, device), "lab")
    assert [(record["result"], record["reason"]) for record in settled] == [("confirmed", "confirmed before the interruption")]
    assert device.addresses["new-host"]["comment"] == "new host"
    assert not device.stitches and not device.triggers and not device.actions and not device.fired
    assert runtime.store.blocked("lab") is None


def test_recover_still_waits_for_a_safeguard_whose_removal_had_not_begun(tmp_path):
    device = FakeFortiOS()
    device.on_apply = killed_in_the_removal(0)
    runtime = make_runtime(tmp_path, device)
    with pytest.raises(KeyboardInterrupt):
        execute.apply(runtime, "lab", request())
    device.on_apply = None
    settled = execute.recover(make_runtime(tmp_path, device), "lab")
    assert [(record["result"], record["reason"]) for record in settled] == [("reverted", "interrupted")]
    assert "new-host" not in device.addresses and not device.stitches and not device.triggers and not device.actions


def test_recover_confirms_a_verified_change_whose_exos_timer_was_already_deleted(tmp_path):
    device = FakeExos()

    def crash(fake, lines):
        if lines and isinstance(lines[0], str) and lines[0].startswith("delete upm timer"):
            assert fake._command(shlex.split(lines[0]), False)
            raise KeyboardInterrupt

    device.on_apply = crash
    with pytest.raises(KeyboardInterrupt):
        execute.apply(make_exos_runtime(tmp_path, device), "sw", exos_request())
    assert not device.timers and device.profiles
    device.on_apply = None
    runtime = make_exos_runtime(tmp_path, device)
    settled = execute.recover(runtime, "sw")
    assert [(record["result"], record["reason"]) for record in settled] == [("confirmed", "confirmed before the interruption")]
    assert device.vlans["guest"] == {"tag": "3999", "description": "guest wifi"}
    assert not device.timers and not device.profiles and device.saves == 1
    assert runtime.store.blocked("sw") is None


def during_the_last_snapshot(device, event):
    snapshot, taken = device.snapshot, []

    def taking():
        taken.append(None)
        if len(taken) == 3:
            event(device)
        return snapshot()

    device.snapshot = taking


def test_a_safeguard_that_fires_during_the_last_snapshot_is_reported_as_fired(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    during_the_last_snapshot(device, lambda fake: fake.advance(200))
    record = execute.apply(runtime, "lab", request())
    assert "final_check_failed" in steps(record) and "confirm_start" not in steps(record)
    assert (record["result"], record["reason"]) == ("reverted", "safeguard fired during confirmation")
    assert runtime.store.blocked("lab") is None
    assert "new-host" not in device.addresses
    assert not device.stitches and not device.triggers and not device.actions


def test_a_foreign_change_during_the_last_snapshot_still_blocks(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    during_the_last_snapshot(device, foreign_comment)
    record = execute.apply(runtime, "lab", request())
    assert "final_check_failed" in steps(record)
    assert (record["result"], record["reason"]) == ("reverted", "foreign change")
    assert runtime.store.blocked("lab")["reason"] == "foreign change"
    assert "new-host" not in device.addresses


def test_a_safeguard_that_fires_together_with_a_foreign_change_still_blocks(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)

    def both(fake):
        foreign_comment(fake)
        fake.advance(200)

    during_the_last_snapshot(device, both)
    record = execute.apply(runtime, "lab", request())
    assert (record["result"], record["reason"]) == ("reverted", "foreign change")
    assert runtime.store.blocked("lab")["reason"] == "foreign change"


def test_a_quiet_last_snapshot_is_confirmed(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    during_the_last_snapshot(device, lambda fake: None)
    record = execute.apply(runtime, "lab", request())
    assert (record["result"], record["reason"]) == ("confirmed", None)
    assert device.addresses["new-host"]["comment"] == "new host"


def killed_after_the_change():
    blocks = []

    def crash(fake, lines):
        blocks.append(lines)
        if len(blocks) == 2:
            fake._run(lines)
            raise KeyboardInterrupt

    return crash


def safeguard_deleted_by_hand(fake):
    fake.stitches.clear()
    fake.triggers.clear()
    fake.actions.clear()


def changed_back_by_hand(fake):
    safeguard_deleted_by_hand(fake)
    del fake.addresses["new-host"]


def changed_elsewhere_by_hand(fake):
    safeguard_deleted_by_hand(fake)
    foreign_comment(fake)


NEITHER = ("unknown", "interrupted; state matches neither side")
RECOVERED = {
    "after, not confirmed": (killed_after_the_change, safeguard_deleted_by_hand,
                             ("unknown", "interrupted; device state matches the after side but confirm_start is missing")),
    "before, not confirmed": (killed_after_the_change, changed_back_by_hand, ("reverted", "interrupted")),
    "neither side, not confirmed": (killed_after_the_change, changed_elsewhere_by_hand, NEITHER),
    "after, confirmation started": (lambda: killed_in_the_removal(0), safeguard_deleted_by_hand,
                                    ("confirmed", "confirmed before the interruption")),
    "before, confirmation started": (lambda: killed_in_the_removal(0), changed_back_by_hand, ("reverted", "interrupted")),
    "neither side, confirmation started": (lambda: killed_in_the_removal(0), changed_elsewhere_by_hand, NEITHER),
}


@pytest.mark.parametrize("case", sorted(RECOVERED))
def test_recover_settles_only_a_device_state_that_matches_one_side_and_the_confirmation(tmp_path, case):
    crash, by_hand, expected = RECOVERED[case]
    device = FakeFortiOS()
    device.on_apply = crash()
    with pytest.raises(KeyboardInterrupt):
        execute.apply(make_runtime(tmp_path, device), "lab", request())
    device.on_apply = None
    runtime = make_runtime(tmp_path, device)
    [running] = runtime.store.running("lab")
    assert ("confirm_start" in steps(running)) == case.endswith("confirmation started")
    by_hand(device)
    settled = execute.recover(runtime, "lab")
    assert [(record["result"], record["reason"]) for record in settled] == [expected]
    assert (runtime.store.blocked("lab") is not None) == (expected[0] == "unknown")
