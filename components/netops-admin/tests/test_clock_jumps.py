from __future__ import annotations

import datetime

import pytest
from fake_exos import FakeExos
from test_enrollment import ready
from test_execute_exos import make_runtime, request, steps

from netops_admin import enrollment, exec_exos, execute, exos

JUMP_AT = 32
SAFEGUARD = 180
CHANGE = "114114" + "0" * 26
OTHER_CHANGE = "abcdef" + "0" * 26
HEADER = (
    "--------------------------------------------------------------------------------\n"
    "UPM               Profile       Flags              Next Execution\n"
    "Timer             Name                             time              \n"
    "--------------------------------------------------------------------------------\n"
)
FOOTER = (
    "--------------------------------------------------------------------------------\n"
    "\n"
    "Number of UPM Timers: 1\n"
    "Flags: e - Profile is enabled, d: Profile is disabled\n"
    "       o -Timer is non-periodic, p - Timer is periodic"
)
MEASURED_X440_PAST_NEXT = ("Current Time: 2026-10-09 16:42:37\n" + HEADER
                           + "t114ht3          t114hp3        eo            2026-10-09 16:40:02\n" + FOOTER)
MEASURED_X440_FIRED = "Current Time: 2026-10-09 16:45:06\n" + HEADER + "t114ht3          t114hp3        e\n" + FOOTER
MEASURED_X435_PAST_NEXT = ("Current Time: 2026-10-09 16:57:56\n" + HEADER
                           + "t114ht6          t114hp6        eo            2026-10-09 16:55:23\n" + FOOTER)
MEASURED_X435_FIRED = "Current Time: 2026-10-09 17:00:26\n" + HEADER + "t114ht6          t114hp6        e\n" + FOOTER
MEASURED = {
    "x440": (MEASURED_X440_PAST_NEXT, MEASURED_X440_FIRED, "t114ht3", "t114hp3"),
    "x435": (MEASURED_X435_PAST_NEXT, MEASURED_X435_FIRED, "t114ht6", "t114hp6"),
}


class Timers:
    def __init__(self, text):
        self.text = text

    def query(self, command):
        assert command == exos.QUERY_TIMERS
        return self.text


def fired(model, text, change_id=CHANGE):
    timer, profile = MEASURED[model][2:]
    names = exos.safeguard_names(CHANGE)
    own = text.replace(timer, names["timer"]).replace(profile, names["profile"])
    return exec_exos.safeguard_fired(Timers(own), {"change_id": change_id})


@pytest.mark.parametrize("model", sorted(MEASURED))
def test_only_a_measured_fired_timer_of_the_operation_proves_the_return(model):
    past_next, after_fire = MEASURED[model][:2]
    assert fired(model, after_fire) is True
    assert fired(model, past_next) is False
    assert fired(model, after_fire, OTHER_CHANGE) is False


@pytest.mark.parametrize("model", sorted(MEASURED))
def test_a_cut_timer_listing_is_no_proof(model):
    past_next, after_fire = MEASURED[model][:2]
    assert fired(model, past_next.split("o            2026")[0]) is False
    assert fired(model, after_fire.split(FOOTER)[0]) is False
    assert fired(model, after_fire.replace("Number of UPM Timers: 1", "Number of UPM Timers: 2")) is False


def jump_with_the_change(device, seconds=None, before_next=None, crash=False, at=JUMP_AT):
    def jump(fake, steps):
        if len(fake.applied_blocks) != 2:
            return
        fake.advance(at)
        if before_next is None:
            fake.clock += datetime.timedelta(seconds=seconds)
        else:
            fake.clock = next(iter(fake.timers.values()))["next"] - datetime.timedelta(seconds=before_next)
        if crash:
            fake._run(steps)
            raise KeyboardInterrupt

    device.on_apply = jump


def fire_after_snapshot(device, number):
    snapshot, taken = device.snapshot, []

    def slow():
        text = snapshot()
        taken.append(text)
        pending = [timer["due"] for timer in device.timers.values() if timer["next"] is not None]
        if len(taken) == number and pending:
            device.advance(max(0, min(pending) - device.uptime))
        return text

    device.snapshot = slow


def moments(device):
    return [moment for _timer, _profile, moment in device.history]


def failing_change(tmp_path, **jump):
    device = FakeExos()
    device.drop_description = True
    jump_with_the_change(device, **jump)
    return device, make_runtime(tmp_path, device)


def test_a_forward_jump_past_the_timer_waits_until_the_timer_has_fired(tmp_path):
    device, runtime = failing_change(tmp_path, seconds=300)
    record = execute.apply(runtime, "sw", request())
    assert record["result"] == "reverted" and record["reason"] == "prediction mismatch"
    assert moments(device) == [SAFEGUARD]
    assert device.uptime >= SAFEGUARD + execute.EXPIRY_GRACE_SECONDS
    assert "guest" not in device.vlans and not device.timers and not device.profiles and device.saves == 1


def test_a_timer_seen_fired_during_its_run_is_given_time_to_finish(tmp_path):
    device, runtime = failing_change(tmp_path, seconds=300, at=JUMP_AT - 1.5)
    device.run_seconds = 1
    record = execute.apply(runtime, "sw", request())
    assert record["result"] == "reverted" and record["reason"] == "prediction mismatch"
    assert moments(device) == [SAFEGUARD]
    assert "guest" not in device.vlans and not device.timers and not device.profiles


def test_a_timer_that_fires_right_after_the_settling_snapshot_is_not_a_failed_return(tmp_path):
    device, runtime = failing_change(tmp_path, seconds=300)
    fire_after_snapshot(device, 3)
    record = execute.apply(runtime, "sw", request())
    assert record["result"] == "reverted" and record["reason"] == "prediction mismatch"
    assert moments(device) == [SAFEGUARD]
    assert "guest" not in device.vlans and not device.timers and not device.profiles


def test_a_timer_not_seen_fired_stays_installed_and_ends_unknown(tmp_path):
    device, runtime = failing_change(tmp_path, seconds=300)
    device.timer_stuck = True
    record = execute.apply(runtime, "sw", request())
    assert record["result"] == "unknown" and record["reason"] == "prediction mismatch"
    assert steps(record)[-1] == "revert_unverified"
    assert runtime.store.blocked("sw")["reason"] == "prediction mismatch"
    assert len(device.timers) == 1 and len(device.profiles) == 1 and "guest" in device.vlans
    limit = SAFEGUARD + execute.EXPIRY_GRACE_SECONDS + execute.EXPIRY_WAIT_SLACK_SECONDS
    assert limit <= device.uptime <= limit + execute.EXPIRY_POLL_SECONDS


def test_a_backward_jump_still_follows_the_device_clock(tmp_path):
    device, runtime = failing_change(tmp_path, seconds=-300)
    record = execute.apply(runtime, "sw", request())
    assert record["result"] == "reverted" and record["reason"] == "prediction mismatch"
    assert moments(device) == [SAFEGUARD + 300]
    assert "guest" not in device.vlans and not device.timers


def test_a_forward_jump_short_of_the_timer_still_follows_the_device_clock(tmp_path):
    device, runtime = failing_change(tmp_path, before_next=10)
    record = execute.apply(runtime, "sw", request())
    assert record["result"] == "reverted" and record["reason"] == "prediction mismatch"
    assert moments(device) == [JUMP_AT + 10]
    assert device.uptime < SAFEGUARD
    assert "guest" not in device.vlans and not device.timers


def test_enrollment_after_a_forward_jump_waits_until_the_timer_has_fired(tmp_path):
    runtime, device, name = ready(tmp_path, "exos")
    jump_with_the_change(device, seconds=300)
    record = enrollment.run(runtime, name, "3998")
    assert record["result"] == "reverted" and record.get("enrollment") == "valid"
    assert moments(device) == [SAFEGUARD]
    assert not device.timers and not device.profiles


def test_recover_after_a_forward_jump_waits_until_the_timer_has_fired(tmp_path):
    device = FakeExos()
    jump_with_the_change(device, seconds=300, crash=True)
    with pytest.raises(KeyboardInterrupt):
        execute.apply(make_runtime(tmp_path, device), "sw", request())
    device.on_apply = None
    settled = execute.recover(make_runtime(tmp_path, device), "sw")
    assert [(record["result"], record["reason"]) for record in settled] == [("reverted", "interrupted")]
    assert moments(device) == [SAFEGUARD]
    assert "guest" not in device.vlans and not device.timers and not device.profiles
