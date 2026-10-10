from __future__ import annotations

import pytest
from fake_exos import FakeExos
from fake_fortios import FakeFortiOS
from test_execute import make_runtime, request
from test_execute_exos import make_runtime as make_exos_runtime
from test_execute_exos import request as exos_request

from netops_admin import exec_exos, execute, exos

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


class CountOnlyExos(StuckExos):
    def query(self, command):
        if self.removal_attempted and command == exos.QUERY_PROFILES:
            return "Number of UPM Profiles: %d\n" % len(self.profiles)
        if self.removal_attempted and command == exos.QUERY_TIMERS:
            return "Number of UPM Timers: %d\n" % len(self.timers)
        return super().query(command)


class Listing:
    def __init__(self, profiles, timers):
        self.answers = {exos.QUERY_PROFILES: profiles, exos.QUERY_TIMERS: timers}

    def query(self, command):
        return self.answers[command]


CHANGE = "ab12cd" + "0" * 26
MEASURED_CHANGE = "114114" + "0" * 26
COUNT_ONLY = ("Number of UPM Profiles: 1\n", "Number of UPM Timers: 1\n")
MEASURED_X435_PROFILES_EMPTY = (
    "================================================================================\n"
    "UPM Profile          Events                 Flags Ports\n"
    "================================================================================                         \n"
    "================================================================================\n"
    "Number of UPM Profiles: 0\n"
    "Number of UPM Events in Queue for execution: 0\n"
    "Flags: d - disabled, e - enabled\n"
    "Event name: log-message(Log filter name) - Truncated to 20 chars\n"
)
MEASURED_X435_TIMERS_EMPTY = (
    "--------------------------------------------------------------------------------\n"
    "UPM               Profile       Flags              Next Execution\n"
    "Timer             Name                             time              \n"
    "--------------------------------------------------------------------------------                 \n"
    "--------------------------------------------------------------------------------\n"
    "\n"
    "Number of UPM Timers: 0\n"
    "Flags: e - Profile is enabled, d: Profile is disabled\n"
    "       o -Timer is non-periodic, p - Timer is periodic\n"
)
MEASURED_X435_PROFILES_FOUR = (
    "================================================================================\n"
    "UPM Profile          Events                 Flags Ports\n"
    "================================================================================\n"
    "netops114114p        UPM-Timer(netops114114t)  e \n"
    "t114a                UPM-Timer(t114ta)         e \n"
    "t114b                UPM-Timer(t114tb)         e \n"
    "t114c                                          e \n"
    "================================================================================\n"
    "Number of UPM Profiles: 4\n"
    "Number of UPM Events in Queue for execution: 0\n"
    "Flags: d - disabled, e - enabled\n"
    "Event name: log-message(Log filter name) - Truncated to 20 chars\n"
)
MEASURED_X435_TIMERS_FOUR = (
    "Current Time: 2026-10-09 13:16:23\n"
    "--------------------------------------------------------------------------------\n"
    "UPM               Profile       Flags              Next Execution\n"
    "Timer             Name                             time              \n"
    "--------------------------------------------------------------------------------\n"
    "netops114114t    netops114114p  eo            2026-10-09 15:16:22\n"
    "t114ta           t114a          eo            2026-10-09 15:16:20\n"
    "t114tb           t114b          ep            2026-10-09 15:16:21(Every 3600 secs)\n"
    "t114tn                           \n"
    "--------------------------------------------------------------------------------\n"
    "\n"
    "Number of UPM Timers: 4\n"
    "Flags: e - Profile is enabled, d: Profile is disabled\n"
    "       o -Timer is non-periodic, p - Timer is periodic\n"
)
MEASURED_X440_PROFILES_FOUR = MEASURED_X435_PROFILES_FOUR
MEASURED_X440_TIMERS_FOUR = (
    "Current Time: 2026-10-09 13:14:21\n"
    "--------------------------------------------------------------------------------\n"
    "UPM               Profile       Flags              Next Execution\n"
    "Timer             Name                             time              \n"
    "--------------------------------------------------------------------------------\n"
    "netops114114t    netops114114p  eo            2026-10-09 15:14:21\n"
    "t114ta           t114a          eo            2026-10-09 15:14:17\n"
    "t114tb           t114b          ep            2026-10-09 15:14:18(Every 3600 secs)\n"
    "t114tn                           \n"
    "--------------------------------------------------------------------------------\n"
    "\n"
    "Number of UPM Timers: 4\n"
    "Flags: e - Profile is enabled, d: Profile is disabled\n"
    "       o -Timer is non-periodic, p - Timer is periodic\n"
)
MEASURED_FOUR = {"x435": (MEASURED_X435_PROFILES_FOUR, MEASURED_X435_TIMERS_FOUR),
                 "x440": (MEASURED_X440_PROFILES_FOUR, MEASURED_X440_TIMERS_FOUR)}


def absent(profiles, timers, change_id=CHANGE):
    return exec_exos.safeguard_absent(Listing(profiles, timers), {"change_id": change_id})


def without_row(text, name):
    return "".join(line for line in text.splitlines(keepends=True) if not line.startswith(name))


def test_measured_empty_exos_listings_hold_no_safeguard():
    assert exos.upm_listing_complete(MEASURED_X435_PROFILES_EMPTY, "Profiles")
    assert exos.upm_listing_complete(MEASURED_X435_TIMERS_EMPTY, "Timers")
    assert absent(MEASURED_X435_PROFILES_EMPTY, MEASURED_X435_TIMERS_EMPTY) is True


@pytest.mark.parametrize("model", sorted(MEASURED_FOUR))
def test_measured_exos_listings_with_foreign_entries_block_only_the_named_safeguard(model):
    profiles, timers = MEASURED_FOUR[model]
    assert exos.upm_listing_complete(profiles, "Profiles") and exos.upm_listing_complete(timers, "Timers")
    assert absent(profiles, timers) is True
    assert absent(profiles, timers, MEASURED_CHANGE) is False


@pytest.mark.parametrize("model", sorted(MEASURED_FOUR))
def test_a_measured_exos_listing_without_one_of_its_rows_is_incomplete(model):
    profiles, timers = MEASURED_FOUR[model]
    assert absent(without_row(profiles, "t114a "), timers) is False
    assert absent(profiles, without_row(timers, "t114ta ")) is False


def test_an_exos_entry_on_more_than_one_line_keeps_the_listing_complete():
    two_events = MEASURED_X435_PROFILES_FOUR.replace("t114c ", " " * 21 + "Device-Detect\nt114c ")
    assert exos.upm_listing_complete(two_events, "Profiles")


def test_exos_counts_without_rows_are_not_an_absent_safeguard():
    assert absent(*COUNT_ONLY) is False
    assert absent("Number of UPM Profiles: 0\n", "Number of UPM Timers: 0\n") is True


def test_exos_counts_without_rows_after_a_failed_removal_do_not_confirm(tmp_path):
    device = CountOnlyExos()
    record = execute.apply(make_exos_runtime(tmp_path, device), "sw", exos_request())
    assert device.removal_attempted and device.timers
    assert record["result"] != "confirmed"
