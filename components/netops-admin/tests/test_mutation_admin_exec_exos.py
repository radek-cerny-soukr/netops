from types import SimpleNamespace

import pytest

from netops_admin import exec_exos, exos
from netops_admin.errors import Rejected

CHANGE = "ab12cd" + "0" * 26
NAMES = exos.safeguard_names(CHANGE)
FIRE = "2026-10-13 12:00:00"
INVERSE = ["configure vlan users description old"]
MARKER = "A number within the range of 1-4094 is expected."
SEPARATOR = "-" * 80


def profile_answer(lines):
    return "Profile Contents Begin\n" + "\n".join(lines) + "\nProfile Contents Ends\n"


def timers_answer(*rows):
    lines = ["Current Time: 2026-10-13 11:57:00", SEPARATOR, "UPM               Profile       Flags   Next Execution",
             SEPARATOR]
    lines.extend(rows)
    lines.extend([SEPARATOR, "", "Number of UPM Timers: %d" % len(rows)])
    return "\n".join(lines) + "\n"


def vlan_list(*names):
    lines = ["Name            VID  Protocol Addr       Flags                         Proto  Ports  Virtual"]
    lines.extend("%-15s %-4d -------------------------------- ANY 0 /0 VR-Default" % (name, 10 + index)
                 for index, name in enumerate(names))
    lines.append("Total number of VLAN(s) : %d" % len(names))
    return "\n".join(lines) + "\n"


class Switch:
    def __init__(self, answers=None, checks=None, prefix=b"x440.1 # ", failing=False):
        self.answers = answers or {}
        self.checks = checks or {}
        self.prefix = prefix
        self.failing = failing
        self.queries = []
        self.check_queries = []
        self.applied = []
        self.prefix_specs = []

    def query(self, command):
        self.queries.append(command)
        if self.failing:
            raise OSError("fixture query failed")
        return self.answers.get(command, "")

    def check_query(self, command):
        self.check_queries.append(command)
        return self.checks.get(command, "")

    def apply(self, steps, spec):
        self.applied.append((steps, spec))

    def login_prefix(self, spec):
        self.prefix_specs.append(spec)
        return self.prefix


def refusal(call, *args):
    with pytest.raises(Rejected) as caught:
        call(*args)
    return caught.value.reasons


def test_a_switch_answer_without_a_system_name_is_refused_naming_the_field():
    assert refusal(exec_exos.hostname, Switch({exos.QUERY_SWITCH: "SysContact: x\n"}), "") == [
        "the switch does not report its system name"]


def test_a_switch_answer_without_a_clock_is_refused_naming_the_field():
    assert refusal(exec_exos.clock, Switch({exos.QUERY_SWITCH: "SysName: x440\n"})) == [
        "the switch does not report its clock"]


def test_a_version_answer_without_an_image_is_refused_naming_the_field():
    device = SimpleNamespace(firmware="33.7.1.6")
    assert refusal(exec_exos.prechecks, Switch({exos.QUERY_VERSION: "Switch: x440\n"}), device, "", None) == [
        "the switch does not report its software version"]


def test_prechecks_name_the_running_and_configured_firmware_and_foreign_unsaved_changes():
    switch = Switch({exos.QUERY_VERSION: "Image   : ExtremeXOS version 33.6.1.14 by release-manager\n"},
                    prefix=b"* x440.1 # ")
    spec = object()
    reasons = exec_exos.prechecks(switch, SimpleNamespace(firmware="33.7.1.6"), "", spec)
    assert reasons == ["the switch runs 33.6.1.14, not the configured 33.7.1.6",
                       "the switch has unsaved configuration changes of someone else"]
    assert switch.prefix_specs == [spec]


def test_prechecks_pass_a_matching_firmware_with_saved_configuration():
    switch = Switch({exos.QUERY_VERSION: "Image   : ExtremeXOS version 33.7.1.6 by release-manager\n"})
    assert exec_exos.prechecks(switch, SimpleNamespace(firmware="33.7.1.6"), "", "spec") == []
    assert switch.prefix_specs == ["spec"]


def test_differing_switch_accounts_are_refused_with_both_counts(exos_snapshot):
    text = exos_snapshot.decode("utf-8")
    present = exos.accounts(exos.Snapshot(text, "33.7.1.6"))
    device = SimpleNamespace(firmware="33.7.1.6", accounts=("only-one",))
    assert refusal(exec_exos.accounts_check, None, device, text) == [
        "the switch accounts differ from the expected list (%d present, 1 expected)" % len(present)]


def test_the_exos_prompt_ends_on_hash_or_angle_without_a_continuation():
    spec = exec_exos.prompt_spec("x440")
    assert spec.anchor == b"x440."
    assert spec.ends == (b"# ", b"> ")
    assert spec.continuation is None
    assert spec.error is exos.cli_error


def install(timer_rows, profile_lines=None):
    answers = {
        "%s %s" % (exos.QUERY_PROFILES, NAMES["profile"]):
            profile_answer(exos.safeguard_script(INVERSE) if profile_lines is None else profile_lines),
        exos.QUERY_TIMERS: timers_answer(*timer_rows),
    }
    record = {"change_id": CHANGE, "safeguard": {"fire_at": FIRE}}
    problems = exec_exos.install_safeguard(Switch(answers), record, {"inverse": INVERSE},
                                           SimpleNamespace(safeguard_seconds=180), None)
    return problems, record


def row(when, flags="eo", profile=None):
    return "%-17s %-13s %-7s %s" % (NAMES["timer"], profile or NAMES["profile"], flags, when)


def test_a_safeguard_profile_that_differs_is_named_alone():
    problems, _record = install([row(FIRE)], ["configure vlan users description other"])
    assert problems == ["safeguard profile differs from the planned inverse"]


def test_a_missing_safeguard_timer_is_named_alone():
    problems, record = install([])
    assert problems == ["safeguard timer is missing, periodic, unscheduled or bound to another profile"]
    assert record["safeguard"] == {"fire_at": FIRE}


def test_a_timer_within_the_tolerance_is_accepted_and_its_time_recorded():
    problems, record = install([row("2026-10-13 12:00:10")])
    assert problems == []
    assert record["safeguard"] == {"fire_at": "2026-10-13 12:00:10"}


def test_a_timer_beyond_the_tolerance_is_named_and_its_time_recorded():
    problems, record = install([row("2026-10-13 11:59:49")])
    assert problems == ["safeguard timer fires at another time than planned"]
    assert record["safeguard"] == {"fire_at": "2026-10-13 11:59:49"}


def test_a_timer_query_failure_never_means_the_safeguard_fired():
    assert exec_exos.safeguard_fired(Switch(failing=True), {"change_id": CHANGE}) is False


def test_a_timer_still_marked_non_periodic_has_not_fired():
    switch = Switch({exos.QUERY_TIMERS: timers_answer(row("", flags="eo"))})
    assert exec_exos.safeguard_fired(switch, {"change_id": CHANGE}) is False
    switch = Switch({exos.QUERY_TIMERS: timers_answer(row("", flags="e"))})
    assert exec_exos.safeguard_fired(switch, {"change_id": CHANGE}) is True


def observe(show, listing):
    switch = Switch(checks={"show vlan users": show, "show vlan": listing})
    return switch, lambda: exec_exos.observe(switch, {"table": "vlan", "key": "users"})


def test_a_vlan_the_switch_refuses_by_range_is_absent_when_the_list_lacks_it():
    switch, call = observe("show vlan users\n           ^\n%% Invalid input detected\n" + MARKER + "\n",
                           vlan_list("Default", "guest"))
    assert call() is None
    assert switch.check_queries == ["show vlan users", "show vlan"]


def test_a_vlan_the_switch_refuses_by_range_but_lists_cannot_be_established():
    switch, call = observe(MARKER + "\n", vlan_list("Default", "users"))
    with pytest.raises(Rejected) as caught:
        call()
    assert caught.value.reasons == ["the check account cannot establish the VLAN state"]


def test_an_unrecognised_vlan_answer_without_the_range_marker_is_refused_without_the_list():
    switch, call = observe("something else\n", vlan_list("Default"))
    with pytest.raises(Rejected) as caught:
        call()
    assert caught.value.reasons == ["the check account answer about VLAN users is not recognised"]
    assert switch.check_queries == ["show vlan users"]
