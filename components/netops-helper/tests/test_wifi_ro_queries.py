"""Read-only Wi-Fi templates: the wtp_id slot, the fixed `execute log` sequence and what no template may do."""

import pytest

from netops_helper import read_policy
from netops_helper.query_catalog import READ_QUERIES
from netops_helper.query_catalog.model import FORTIOS_WTP, LITERAL, NO_SLOTS, Query, SequenceQuery, Slot
from netops_helper.read_policy import (
    is_read_sequence, render_read_query, render_read_sequence, require_fortinet_sequence,
)

SERIAL = "FAPEXAMPLE0000001"
LOG_SEQUENCE = (
    "execute log filter category event",
    "execute log filter field subtype wireless",
    "execute log filter view-lines {lines}",
    "execute log display",
)


@pytest.mark.parametrize("name,command", [
    ("wifi_vap_status", "get wireless-controller vap-status"),
    ("wifi_neighbors", "get wireless-controller scan"),
    ("wifi_controller_status", "get wireless-controller status"),
    ("wifi_controller_statistics", "get wireless-controller statistics"),
])
def test_fixed_wifi_reads_take_no_parameter(name, command):
    assert render_read_query("fortinet", name, {}, {}) == ("fortinet", command)
    for parameters in ({"id": "x; execute reboot"}, {"wtp_id": SERIAL}):
        with pytest.raises(ValueError):
            render_read_query("fortinet", name, parameters, {"wtp_ids": (SERIAL,)})


@pytest.mark.parametrize("name,command", [
    ("wifi_ap_status", "get wireless-controller wtp-status"),
    ("wifi_rf_analysis", "get wireless-controller rf-analysis"),
])
def test_wtp_id_is_optional_and_only_an_enrolled_or_observed_value(name, command):
    inventory = {"wtp_ids": (SERIAL,)}
    assert render_read_query("fortinet", name, {}, {}) == ("fortinet", command)
    assert render_read_query("fortinet", name, None, inventory) == ("fortinet", command)
    assert render_read_query("fortinet", name, {"wtp_id": SERIAL}, inventory) == ("fortinet", command + " " + SERIAL)
    with pytest.raises(ValueError, match="not enrolled"):
        render_read_query("fortinet", name, {"wtp_id": "FAPEXAMPLE0000009"}, inventory)
    with pytest.raises(ValueError, match="not enrolled"):
        render_read_query("fortinet", name, {"wtp_id": SERIAL}, {})
    with pytest.raises(ValueError):
        render_read_query("fortinet", name, {"wtp_id": SERIAL, "extra": "1"}, inventory)


@pytest.mark.parametrize("value", [
    "", "A B", "A;B", "A\nB", "A|B", "A$(x)", "A`x`", "A&B", "A?", "-FAP", "_FAP", "A" * 36, "FAP/1", "FAP.1", "ÁP1",
    "FAP1 execute reboot",
])
def test_wtp_id_injection_is_refused_even_when_enrolled(value):
    for name in ("wifi_ap_status", "wifi_rf_analysis"):
        with pytest.raises(ValueError, match="invalid typed"):
            render_read_query("fortinet", name, {"wtp_id": value}, {"wtp_ids": (value,)})


def test_events_sequence_is_the_four_reviewed_commands_in_order():
    platform, commands, filters = render_read_sequence("fortinet", "wifi_events", {"lines": "50"}, {})
    assert platform == "fortinet" and filters == {}
    assert commands == (
        "execute log filter category event",
        "execute log filter field subtype wireless",
        "execute log filter view-lines 50",
        "execute log display",
    )
    _, commands, filters = render_read_sequence(
        "fortinet", "wifi_events", {"lines": "200", "mac_literal": "00:00:5e:00:53:37"}, {})
    assert commands[2] == "execute log filter view-lines 200"
    # the MAC is applied by the Helper to the output; it never reaches a device command
    assert filters == {"mac_literal": "00:00:5e:00:53:37"}
    assert not any("00:00:5e" in command for command in commands)
    assert READ_QUERIES["fortinet"]["wifi_events"].commands == LOG_SEQUENCE


@pytest.mark.parametrize("lines", ["1", "9", "10", "99", "100", "199", "200"])
def test_events_limit_accepts_exactly_one_to_two_hundred(lines):
    assert render_read_sequence("fortinet", "wifi_events", {"lines": lines}, {})[1][2].endswith(" " + lines)


@pytest.mark.parametrize("lines", [
    "0", "201", "1000", "-1", "01", "050", "+5", "5.0", "1e2", " 5", "5 ", "5\n", "5;execute log delete", "٥", "five", "",
    "20 execute reboot",
])
def test_events_limit_outside_the_integer_range_is_refused(lines):
    with pytest.raises(ValueError, match="invalid typed wifi_log_lines"):
        render_read_sequence("fortinet", "wifi_events", {"lines": lines}, {})


@pytest.mark.parametrize("parameters", [
    {}, {"mac_literal": "00:00:5e:00:53:37"}, {"lines": "5", "extra": "1"}, {"lines": "5", "start-line": "1"},
    {"lines": "5", "mac_literal": "00:00:5E:00:53:37"}, {"lines": "5", "mac_literal": "00-00-5e-00-53-37"},
    {"lines": "5", "mac_literal": "00:00:5e:00:53:37 "}, {"lines": "5", "mac_literal": "00:00:5e:00:53:3"},
    {"lines": "5", "mac_literal": "*"}, {"lines": "5", "mac_literal": "00:00:5e:00:53:37\nexecute reboot"},
])
def test_events_parameters_outside_the_template_are_refused(parameters):
    with pytest.raises(ValueError):
        render_read_sequence("fortinet", "wifi_events", parameters, {})


def test_a_sequence_query_is_not_a_single_command_and_the_reverse():
    assert is_read_sequence("fortinet", "wifi_events") and not is_read_sequence("fortinet", "wifi_ap_status")
    with pytest.raises(ValueError, match="sequence"):
        render_read_query("fortinet", "wifi_events", {"lines": "5"}, {})
    with pytest.raises(ValueError, match="unknown read sequence"):
        render_read_sequence("fortinet", "wifi_ap_status", {}, {})
    with pytest.raises(ValueError):
        render_read_sequence("linux", "wifi_events", {"lines": "5"}, {})


GOOD = tuple(command.replace("{lines}", "5") for command in LOG_SEQUENCE)


@pytest.mark.parametrize("commands", [
    GOOD[:3], GOOD[1:], GOOD[::-1], (GOOD[0], GOOD[2], GOOD[1], GOOD[3]), GOOD + ("execute reboot",),
    GOOD[:3] + ("execute log delete",), GOOD[:3] + ("execute log display ",), GOOD[:3] + ("execute log roll",),
    GOOD[:3] + ("execute log filter dump",), GOOD[:3] + ("execute shutdown",), GOOD[:3] + ("execute factoryreset",),
    GOOD[:3] + ("execute log display; execute reboot",), GOOD[:3] + ("execute log display\nexecute reboot",),
    ("execute log filter category traffic",) + GOOD[1:], (GOOD[0], "execute log filter field subtype system") + GOOD[2:],
    GOOD[:2] + ("execute log filter view-lines 201", GOOD[3]), GOOD[:2] + ("execute log filter view-lines 0", GOOD[3]),
    GOOD[:2] + ("execute log filter view-lines 5 ", GOOD[3]), GOOD[:2] + ("execute log filter view-lines 5; execute reboot", GOOD[3]),
    GOOD[:2] + ("execute log filter start-line 1", GOOD[3]), GOOD[:2] + ("execute log filter view-lines {lines}", GOOD[3]),
    list(GOOD), "\n".join(GOOD), (), None, ("execute log display",),
])
def test_only_the_exact_reviewed_sequence_may_run(commands):
    with pytest.raises(ValueError, match="outside the reviewed shapes"):
        require_fortinet_sequence(commands)


def test_the_exact_sequence_is_accepted():
    assert require_fortinet_sequence(GOOD) == GOOD


def test_no_other_catalogue_query_can_run_execute_log():
    for platform, queries in READ_QUERIES.items():
        for name, query in queries.items():
            commands = query.commands if isinstance(query, SequenceQuery) else (query.command,)
            if platform == "fortinet" and name == "wifi_events":
                continue
            assert not any(command.startswith("execute log filter") or command == "execute log display"
                           for command in commands), (platform, name)
    # the only FortiOS execute templates are the ones measured and reviewed before
    executes = {
        command for query in READ_QUERIES["fortinet"].values() for command in
        (query.commands if isinstance(query, SequenceQuery) else (query.command,)) if command.startswith("execute ")
    }
    assert executes == {
        "execute ping-options view-settings", "execute traceroute-options view-settings",
        "execute dhcp lease-list {interface}", *LOG_SEQUENCE,
    }


@pytest.mark.parametrize("command", [
    "execute log display", "execute log filter category event", "execute log filter view-lines 5",
    "execute log delete", "execute reboot", "execute log filter field subtype wireless",
])
def test_a_plain_template_cannot_carry_an_execute_log_command(command):
    with pytest.raises(RuntimeError):
        read_policy._validate_query_command("fortinet", command)
    with pytest.raises(RuntimeError, match="reviewed templates"):
        read_policy._validate_query_catalogs({"fortinet": {"x_query": Query(command, NO_SLOTS, "Read x.")}})


def _sequence(commands, platform="fortinet", **changes):
    values = dict(
        command="; ".join(commands), slots={"lines": Slot(LITERAL, "wifi_log_lines")}, description="Read x.",
        commands=commands, filter_slots=frozenset(),
    )
    values.update(changes)
    return {platform: {"x_query": SequenceQuery(**values)}}


@pytest.mark.parametrize("commands", [
    LOG_SEQUENCE[:3], LOG_SEQUENCE + ("execute reboot",), LOG_SEQUENCE[:3] + ("execute log delete",),
    ("execute reboot",), LOG_SEQUENCE[::-1], LOG_SEQUENCE[:2] + ("execute log filter view-lines 200", LOG_SEQUENCE[3]),
])
def test_a_sequence_template_must_be_the_reviewed_shape(commands):
    with pytest.raises(RuntimeError):
        read_policy._validate_query_catalogs(_sequence(commands))


def test_sequences_are_reserved_for_fortios_exec_queries():
    with pytest.raises(RuntimeError, match="reserved for FortiOS"):
        read_policy._validate_query_catalogs(_sequence(LOG_SEQUENCE, platform="fortiadc"))
    with pytest.raises(RuntimeError, match="reserved for FortiOS"):
        read_policy._validate_query_catalogs(_sequence(LOG_SEQUENCE, pty=True))
    with pytest.raises(RuntimeError, match="display form"):
        read_policy._validate_query_catalogs(_sequence(LOG_SEQUENCE, command="execute log display"))
    with pytest.raises(RuntimeError, match="differ"):
        read_policy._validate_query_catalogs(_sequence(LOG_SEQUENCE, slots={}))
    read_policy._validate_query_catalogs(_sequence(LOG_SEQUENCE))


def test_optional_slots_must_be_the_trailing_template_field():
    slots = FORTIOS_WTP
    good = Query("get wireless-controller wtp-status {wtp_id}", slots, "Read x.", optional_slots=frozenset({"wtp_id"}))
    read_policy._validate_query_catalogs({"fortinet": {"x_query": good}})
    for command in ("get wireless-controller wtp-status {wtp_id} extra", "get wireless-controller {wtp_id} wtp-status"):
        with pytest.raises(RuntimeError):
            read_policy._validate_query_catalogs({"fortinet": {"x_query": Query(
                command, slots, "Read x.", optional_slots=frozenset({"wtp_id"}))}})
    with pytest.raises(RuntimeError, match="declared"):
        read_policy._validate_query_catalogs({"fortinet": {"x_query": Query(
            "get wireless-controller scan", NO_SLOTS, "Read x.", optional_slots=frozenset({"wtp_id"}))}})


def test_new_wifi_queries_do_not_raise_the_read_only_account_warning():
    from netops_helper import inventory
    from test_read_only_wifi_warning import _section
    names = (
        "wifi_ap_status", "wifi_vap_status", "wifi_neighbors", "wifi_controller_status",
        "wifi_controller_statistics", "wifi_rf_analysis", "wifi_events",
    )
    for name in names:
        assert inventory.section_warnings("gate", _section(queries=(name,))) == []
    warnings = inventory.section_warnings("gate", _section(queries=names + ("wifi_clients",)))
    assert len(warnings) == 1 and "query wifi_clients " in warnings[0]


def test_volume_flags_follow_the_measured_output_size():
    queries = READ_QUERIES["fortinet"]
    assert [queries[name].high_volume for name in (
        "wifi_vap_status", "wifi_controller_status", "wifi_controller_statistics")] == [False, False, False]
    assert all(queries[name].high_volume for name in (
        "wifi_ap_status", "wifi_neighbors", "wifi_rf_analysis", "wifi_events"))
