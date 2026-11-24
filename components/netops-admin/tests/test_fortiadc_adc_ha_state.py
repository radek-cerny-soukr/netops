"""FortiADC HA state through Admin preview, apply, readback, undo and recovery."""

import pytest

from approved_member import approved_cli
from fake_fortiadc import HA_FIXTURES
from fake_fortiadc_admin import measured
from netops_admin import cli, config, execute, fortiadc, fortiadc_member, readiness
from netops_admin.access import AccessError
from netops_admin.errors import Rejected
from netops_core import prompt
from test_fortiadc_admin_runtime import make_runtime, request, steps
from test_fortiadc_adc_pool_members import POOL, RS, TARGET, Wire, capture, server_steps

PRIMARY_DOWN = (HA_FIXTURES / "primary-not-sync.txt").read_text()
PRIMARY_SYNC = PRIMARY_DOWN.replace("Config-Sync: Not Sync", "Config-Sync: In Sync")
SECONDARY = (HA_FIXTURES / "secondary.txt").read_text()


def change():
    return request(op="create", table=RS, key=TARGET, changes={"ip": "192.0.2.11", "status": "enable"})


def pair():
    return Wire(
        [server_steps(RS, TARGET, "set ip 192.0.2.11", "set status enable"),
         ["config " + RS, f'delete "{TARGET}"', "end"]],
        before={fortiadc.HA_STATUS: PRIMARY_SYNC},
        after={"show " + RS: capture("real-ip")},
    )


def test_primary_requires_approved_preview_and_verifies_apply_and_undo(tmp_path):
    wire = pair()
    runtime = make_runtime(tmp_path, wire)
    req = change()
    preview = execute.preview(runtime, "adc", req)
    assert preview["result"] == "ready" and "synchronized secondary" in " ".join(preview["prechecks"])
    assert not wire.writes
    with pytest.raises(Rejected) as denied:
        execute.apply(runtime, "adc", req)
    # every apply needs the approved hash: it is refused before the HA role is read (plan_changed), nothing is written
    assert denied.value.reason_codes == ["plan_changed"] and not wire.writes
    applied = execute.apply(runtime, "adc", req, expected_plan_sha256=preview["plan_sha256"])
    assert applied["result"] == "confirmed" and "check_identity_passed" in steps(applied)
    assert wire.checks[-1] == "show " + RS and TARGET in wire.answers["show " + RS]
    returned = execute.undo(runtime, applied["change_id"], "return test")
    assert returned["result"] == "confirmed" and "check_identity_passed" in steps(returned)
    assert len(wire.writes) == 2 and wire.answers == wire.original


@pytest.mark.parametrize(("answer", "code"), [
    (SECONDARY, "fortiadc_ha_secondary"),
    (PRIMARY_DOWN, "fortiadc_ha_not_synchronized"),
    (PRIMARY_SYNC.rsplit("IP Address:", 1)[0], "fortiadc_ha_not_synchronized"),
    ("Command fail. Return code is -284", "fortiadc_ha_unreadable"),
    ("Mode: active-passive\n--More--", "fortiadc_ha_unreadable"),
])
def test_unverified_pair_is_refused_without_writes(tmp_path, answer, code):
    wire = Wire(before={fortiadc.HA_STATUS: answer})
    runtime = make_runtime(tmp_path, wire)
    preview = execute.preview(runtime, "adc", change())
    assert preview["reason_codes"] == [code] and not wire.writes
    check = next(row for row in readiness.doctor(runtime, "adc")["checks"] if row["check"] == "device prechecks")
    assert check["status"] == "refused" and check["reason_codes"] == [code]


def test_failover_at_write_boundary_is_rejected(tmp_path):
    wire = pair()
    runtime = make_runtime(tmp_path, wire)
    req = change()
    preview = execute.preview(runtime, "adc", req)
    query = wire.query
    replies = iter([PRIMARY_SYNC, SECONDARY])
    wire.query = lambda command: next(replies) if command == fortiadc.HA_STATUS else query(command)
    denied = execute.apply(runtime, "adc", req, expected_plan_sha256=preview["plan_sha256"])
    assert denied["reason_codes"] == ["fortiadc_ha_secondary"] and not wire.writes


def test_lost_sync_blocks_confirmation_and_unsafe_recovery(tmp_path):
    wire = pair()
    wire.after[fortiadc.HA_STATUS] = PRIMARY_DOWN
    runtime = make_runtime(tmp_path, wire)
    runtime.sleep = lambda _: None
    req = change()
    preview = execute.preview(runtime, "adc", req)
    applied = execute.apply(runtime, "adc", req, expected_plan_sha256=preview["plan_sha256"])
    assert applied["result"] == "unknown" and "check_identity_passed" not in steps(applied)
    pending, = execute.recover(runtime, "adc")
    assert pending["result"] == "unknown" and len(wire.writes) == 1
    wire.answers[fortiadc.HA_STATUS] = PRIMARY_SYNC
    returned, = execute.recover(runtime, "adc")
    assert returned["result"] == "reverted" and "compensation_verified" in steps(returned)
    assert len(wire.writes) == 2 and wire.answers == wire.original


def test_recovery_access_failure_keeps_adc_compensation_pending(tmp_path):
    wire = pair()
    wire.after[fortiadc.HA_STATUS] = PRIMARY_DOWN
    runtime = make_runtime(tmp_path, wire)
    runtime.sleep = lambda _: None
    wanted = change()
    preview = execute.preview(runtime, "adc", wanted)
    assert preview["result"] == "ready"
    applied = execute.apply(runtime, "adc", wanted, expected_plan_sha256=preview["plan_sha256"])
    assert applied["result"] == "unknown" and len(wire.writes) == 1
    original_access = runtime.access_factory

    def unavailable(_device):
        raise AccessError("synthetic private ADC diagnostic")

    runtime.access_factory = unavailable
    pending, = execute.recover(runtime, "adc")

    assert pending["change_id"] == applied["change_id"] and pending["result"] == "unknown"
    assert steps(pending)[-2:] == ["recovery_start", "recovery_access_failed"]
    assert runtime.store.blocked("adc")["change_id"] == applied["change_id"] and len(wire.writes) == 1
    assert "synthetic private ADC diagnostic" not in repr(runtime.store.records())
    runtime.access_factory = original_access
    wire.answers[fortiadc.HA_STATUS] = PRIMARY_SYNC
    returned, = execute.recover(runtime, "adc")
    assert returned["result"] == "reverted" and "compensation_verified" in steps(returned)
    assert len(wire.writes) == 2 and wire.answers == wire.original


class PairWire(Wire):
    """The write and check accounts can see different configurations."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.check_answers = {}
        self.trace = []

    def query(self, command):
        self.trace.append(("write-read", command))
        return super().query(command)

    def check_query(self, command):
        self.trace.append(("check-read", command))
        self.checks.append(command)
        return self.check_answers.get(command, self.answers[command])

    def apply(self, commands, spec):
        self.trace.append(("write", commands))
        super().apply(commands, spec)


@pytest.mark.parametrize("omitted", ["peer-ip", "peer-serial", "sync-source", "init-done", "both-flags"])
def test_incomplete_primary_cannot_plan_a_write(tmp_path, omitted):
    answer = PRIMARY_SYNC
    if omitted == "peer-ip":
        answer = answer.rsplit("IP Address:", 1)[0] + "IP Address:  \n"
    if omitted == "peer-serial":
        answer = answer.replace("Serial-number: FADVMSTMXXXXXX25", "Serial-number:  ")
    if omitted in ("sync-source", "both-flags"):
        answer = answer.replace("Config-Sync Source: Y\n", "")
    if omitted in ("init-done", "both-flags"):
        answer = answer.replace("Init Done: Yes\n", "")
    wire = PairWire(before={fortiadc.HA_STATUS: answer})
    preview = execute.preview(make_runtime(tmp_path, wire), "adc", change())
    assert preview["result"] == "rejected"
    assert preview["reason_codes"] == ["fortiadc_ha_not_synchronized"]
    assert not wire.writes


@pytest.mark.parametrize("command", ["pool-member", "pool-member-add", "pool-member-remove"])
@pytest.mark.parametrize("scenario", ["sync-lost", "rollback-sync-lost", "stale-check", "synced", "rollback-synced"])
def test_direct_member_postwrite_verification(tmp_path, monkeypatch, capsys, command, scenario):
    listing = fortiadc.show_command(POOL)
    # Targeted captures from a FortiADC, with the same prompt/pager cleanup as the SSH layer.
    def answer(text):
        return prompt.cleaned(fortiadc.PAGER.sub("", text), "fortiadc")

    base = answer(measured("show_load-balance_pool_LAB_POOL_SMTP.txt"))
    added = answer(capture("pool-member-before"))
    if command == "pool-member":
        before, changed = added, added.replace("set status disable", "set status maintain")
        write = fortiadc.render(POOL, "13", "maintain")
        flags = ["--status", "maintain"]
    elif command == "pool-member-add":
        before, changed = base, added
        write = fortiadc_member.render_add(POOL, "13", TARGET, "2525")
        flags = ["--real-server", TARGET, "--service-port", "2525"]
    else:
        before, changed = added, base
        write = fortiadc_member.render_remove(POOL, "13")
        flags = []

    rolled_back = scenario.startswith("rollback")
    lost = scenario.endswith("sync-lost")
    actual = before if rolled_back else changed
    wire = PairWire([write], before={fortiadc.HA_STATUS: PRIMARY_SYNC, listing: before,
                                   "show " + RS: answer(capture("real-ip")),
                                   fortiadc.VS_COMMAND: answer(capture("vs-smtp-baseline"))},
                    after={fortiadc.HA_STATUS: PRIMARY_DOWN if lost else PRIMARY_SYNC, listing: actual})
    if scenario == "stale-check":
        wire.check_answers[listing] = before

    runtime = make_runtime(tmp_path, wire, certified=False)
    monkeypatch.setattr(config, "load_config", lambda _path: runtime.config)
    monkeypatch.setattr(cli, "open_access", lambda _device: wire)
    # Skip wall-clock backoff while still sending each poll through the transport.
    monkeypatch.setattr(fortiadc, "sleep", lambda _seconds: None, raising=False)
    code, result = approved_cli(cli.main, [command, "--config", "unused", "--device", "adc", "--pool", POOL,
                                           "--member", "13", *flags], capsys)
    expected = "unknown" if lost or scenario == "stale-check" else ("rolled_back" if rolled_back else "confirmed")
    assert result["result"] == expected, result
    assert code == fortiadc.EXIT[expected]
    assert wire.writes == [write]
    postwrite = wire.trace[wire.trace.index(("write", write)) + 1:]
    assert postwrite[:2] == [("write-read", listing), ("write-read", fortiadc.HA_STATUS)]
    if lost:
        assert wire.checks == []
        assert "no verified synchronized secondary" in result["reason"]
    else:
        assert wire.checks == [listing]
        if scenario == "stale-check":
            assert "check account" in result["reason"]


class Interrupted(BaseException):
    pass


@pytest.mark.parametrize("scenario", ["sync-lost", "stale-check", "check-disconnected", "synced"])
def test_recover_locally_restored_primary(tmp_path, scenario):
    listing = "show " + RS

    class InterruptedReturn(PairWire):
        check_disconnected = False

        def check_query(self, command):
            if self.check_disconnected:
                self.checks.append(command)
                raise AccessError("synthetic private ADC diagnostic")
            return super().check_query(command)

        def apply(self, commands, spec):
            super().apply(commands, spec)
            if len(self.writes) == 1:
                raise RuntimeError("write reported a failure after applying")
            raise Interrupted()

    wire = InterruptedReturn(
        [server_steps(RS, TARGET, "set ip 192.0.2.11", "set status enable"),
         ["config " + RS, f'delete "{TARGET}"', "end"]],
        before={fortiadc.HA_STATUS: PRIMARY_SYNC},
        after={listing: capture("real-ip")},
    )
    runtime = make_runtime(tmp_path, wire)
    req = change()
    preview = execute.preview(runtime, "adc", req)
    with pytest.raises(Interrupted):
        execute.apply(runtime, "adc", req, expected_plan_sha256=preview["plan_sha256"])
    journal, = runtime.store.running("adc")
    assert journal["plan"]["fortiadc_ha_role"] == "primary" and "change_start" in steps(journal)
    assert wire.answers[listing] == capture("rs-baseline")

    if scenario == "sync-lost":
        wire.answers[fortiadc.HA_STATUS] = PRIMARY_DOWN
    if scenario != "synced":
        wire.check_answers[listing] = capture("real-ip")
    wire.check_disconnected = scenario == "check-disconnected"

    wire.trace.clear()
    wire.checks.clear()
    recovered, = execute.recover(runtime, "adc")
    assert recovered["result"] == ("reverted" if scenario == "synced" else "unknown")
    assert len(wire.writes) == 2
    assert ("write-read", fortiadc.HA_STATUS) in wire.trace
    assert wire.checks == ([] if scenario == "sync-lost" else [listing])
    if scenario != "synced":
        expected_reason = "no verified synchronized secondary" if scenario == "sync-lost" else "check account"
        assert expected_reason in recovered["reason"]
        assert runtime.store.blocked("adc")["change_id"] == recovered["change_id"]
        assert "synthetic private ADC diagnostic" not in repr(runtime.store.records())
        wire.answers[fortiadc.HA_STATUS] = PRIMARY_SYNC
        wire.check_answers.clear()
        wire.check_disconnected = False
        recovered, = execute.recover(runtime, "adc")
        assert recovered["result"] == "reverted" and len(wire.writes) == 2
    assert "compensation_verified" in steps(recovered)
