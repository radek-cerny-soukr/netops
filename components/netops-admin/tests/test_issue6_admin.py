from __future__ import annotations

import datetime

from fake_fortios import FakeFortiOS
from test_execute import make_runtime, request
from test_w4_admin_execute import after_check, blind_safeguard, trail

from netops_admin import execute


class DelayedDispatch(FakeFortiOS):
    def __init__(self, delay_seconds):
        super().__init__()
        self.delay = datetime.timedelta(seconds=delay_seconds)

    def _fire(self):
        clock = self.clock
        self.clock = clock - self.delay
        try:
            super()._fire()
        finally:
            self.clock = clock


def test_a_late_dispatched_safeguard_is_kept_until_its_firing_is_proven(tmp_path, monkeypatch):
    device = DelayedDispatch(execute.EXPIRY_GRACE_SECONDS + execute.EXPIRY_WAIT_SLACK_SECONDS + 300)
    runtime = make_runtime(tmp_path, device)
    after_check(monkeypatch, 1, ["first"])
    record = execute.apply(runtime, "lab", request())
    assert (record["result"], record["reason"]) == ("unknown", "prediction mismatch")
    assert trail(record)[-1] == ("safeguard_kept", "firing not proven")
    assert record["differences"]
    assert device.stitches and device.triggers and device.actions
    assert runtime.store.blocked("lab")["reason"] == "prediction mismatch"
    device.advance(3600)
    assert "new-host" not in device.addresses


def test_a_safeguard_already_gone_from_the_device_still_ends_as_revert_failed(tmp_path, monkeypatch):
    device = FakeFortiOS()
    device.on_apply = blind_safeguard
    runtime = make_runtime(tmp_path, device)
    after_check(monkeypatch, 1, ["first"])
    record = execute.apply(runtime, "lab", request())
    assert (record["result"], record["reason"]) == ("revert-failed", "prediction mismatch")
    assert trail(record)[-1] == ("safeguard_removed", None)
