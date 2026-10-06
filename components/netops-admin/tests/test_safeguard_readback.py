from __future__ import annotations

import pytest
from fake_exos import FakeExos
from fake_fortios import FakeFortiOS
from test_execute import make_runtime, request
from test_execute_exos import make_runtime as make_exos_runtime
from test_execute_exos import request as exos_request

from netops_admin import execute

GARBLED = "Unknown action 0\n"
UNPARSABLE = 'config system automation-action\n    edit "netops\n'


class StuckFortiOS(FakeFortiOS):
    def __init__(self, answer=GARBLED):
        super().__init__()
        self.answer = answer
        self.changed = False
        self.removal_attempted = False
        self.on_apply = self._refuse_removal

    def _refuse_removal(self, fake, lines):
        if any(line.strip() == 'edit "new-host"' for line in lines):
            self.changed = True
        elif self.changed and any(line.startswith("delete ") for line in lines):
            self.removal_attempted = True
            raise RuntimeError("session lost during removal")

    def query(self, command):
        if self.removal_attempted and command.startswith("show system automation-"):
            return self.answer
        return super().query(command)


class StuckExos(FakeExos):
    def __init__(self):
        super().__init__()
        self.removal_attempted = False
        self.on_apply = self._refuse_removal

    def _refuse_removal(self, fake, steps):
        if any(isinstance(step, str) and step.startswith("delete upm") for step in steps):
            self.removal_attempted = True
            raise RuntimeError("session lost during removal")

    def query(self, command):
        if self.removal_attempted and command.startswith("show upm"):
            return GARBLED
        return super().query(command)


@pytest.mark.parametrize("answer", [GARBLED, UNPARSABLE])
def test_fortios_unreadable_removal_check_does_not_confirm(tmp_path, answer):
    device = StuckFortiOS(answer)
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, "lab", request())
    assert device.removal_attempted
    assert record["result"] != "confirmed" or not device.stitches
    device.advance(3600)
    if record["result"] == "confirmed":
        assert "new-host" in device.addresses


def test_fortios_normal_removal_confirms_and_keeps_the_change(tmp_path):
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, "lab", request())
    assert record["result"] == "confirmed" and not device.stitches
    device.advance(3600)
    assert "new-host" in device.addresses


def test_exos_unreadable_removal_check_does_not_confirm(tmp_path):
    device = StuckExos()
    runtime = make_exos_runtime(tmp_path, device)
    record = execute.apply(runtime, "sw", exos_request())
    assert device.removal_attempted
    assert record["result"] != "confirmed" or not device.timers
