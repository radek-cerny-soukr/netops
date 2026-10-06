from __future__ import annotations

import dataclasses

import pytest
from conftest import request_bytes
from fake_exos import FakeExos
from fake_fortios import FakeFortiOS
from netops_auditor import l1_fortios
from test_execute import make_runtime, request
from test_fortios import plan, rejected, replace

from netops_admin import execute, exos, fortios
from netops_admin.engine import build_plan
from netops_admin.errors import Rejected
from netops_admin.profiles import find_profile, load_profiles
from netops_admin.request import canonical_value, parse_request

GROUP = '        set member "grouped-host"'
TRAILING_BACKSLASH = "C:\\temp\\"
COMMENT = '        set comment "unused"'


def with_spaced_member(snapshot, members):
    text = replace(snapshot, '    edit "lab-net"',
                   '    edit "My Host"\n        set subnet 192.0.2.50 255.255.255.255\n    next\n    edit "lab-net"')
    return replace(text, GROUP, "        set member " + members)


@pytest.mark.parametrize("members", ['"My Host" "grouped-host"', '"My Host"'])
def test_group_member_with_whitespace_is_refused(fortios_snapshot, members):
    snapshot = with_spaced_member(fortios_snapshot, members)
    rejected(snapshot, "whitespace", table="firewall addrgrp", op="update", key="servers",
             changes={"member": ["lab-net"]})


def test_group_member_without_whitespace_is_still_planned(fortios_snapshot):
    document = plan(fortios_snapshot, table="firewall addrgrp", op="update", key="servers",
                    changes={"member": ["lab-net"]})
    assert document["predicted"]["before"] == {"member": "grouped-host"}
    assert '        set member "grouped-host"' in document["inverse"]


@pytest.mark.parametrize("stored, value", [
    ('"say \\"hi\\" ok"', 'say "hi" ok'),
    ('"C:\\\\temp\\\\x"', "C:\\temp\\x"),
    ('"C:\\\\temp\\\\"', TRAILING_BACKSLASH),
    ('"Tiskárna v přízemí"', "Tiskárna v přízemí"),
])
def test_inverse_restores_a_comment_with_quotes_backslashes_and_non_ascii(fortios_snapshot, stored, value):
    snapshot = replace(fortios_snapshot, COMMENT, "        set comment " + stored)
    document = plan(snapshot, op="delete", key="spare-host", changes={})
    line = next(line for line in document["inverse"] if line.strip().startswith("set comment "))
    assert line.strip() == "set comment " + stored
    assert l1_fortios.tokenize(line.strip())[2:] == [value]


def test_comment_with_a_line_break_is_refused(fortios_snapshot):
    snapshot = replace(fortios_snapshot, COMMENT, '        set comment "first\nconfig system admin\nlast"')
    rejected(snapshot, "control character", op="delete", key="spare-host", changes={})


def test_safeguard_script_keeps_one_inverse_command_per_line(fortios_snapshot):
    snapshot = replace(fortios_snapshot, COMMENT, '        set comment "say \\"hi\\" ok"')
    document = plan(snapshot, op="delete", key="spare-host", changes={})
    lines = fortios.render_safeguard("0" * 32, document["inverse"], "2026-10-01 12:00:00")
    start = next(index for index, line in enumerate(lines) if line.startswith('set script "'))
    end = next(index for index, line in enumerate(lines) if index >= start and line.endswith('"') and not line.endswith('\\"'))
    assert end - start + 1 == len(document["inverse"])


@pytest.mark.parametrize("description", ['say "hi"', "C:\\temp", "first\nsecond"])
def test_exos_description_that_cannot_be_quoted_is_refused(description):
    profile = find_profile("exos", "vlan", "33.7.1.6")
    with pytest.raises(Rejected) as caught:
        exos.render_create(profile, "guest", {"tag": "3000", "description": description})
    assert any("cannot be written safely" in reason for reason in caught.value.reasons)
    with pytest.raises(Rejected):
        exos.render_update(profile, "guest", {"description": description}, [])


def test_exos_display_string_with_a_space_is_refused():
    profile = find_profile("exos", "ports", "33.7.1.6")
    with pytest.raises(Rejected) as caught:
        exos.render_update(profile, "11", {"display-string": "two words"}, [])
    assert any("cannot be written safely" in reason for reason in caught.value.reasons)


def test_exos_display_string_with_a_space_from_the_snapshot_is_refused():
    snapshot = replace(FakeExos().snapshot().encode("utf-8"), "display-string Zyxel-5p", "display-string Zyxel 5p")
    body = parse_request(request_bytes(table="ports", op="update", key="11", changes={"display-string": "Cam-01"}))
    with pytest.raises(Rejected) as caught:
        build_plan("exos", snapshot, body, firmware="33.7.1.6")
    assert any("cannot be written safely" in reason for reason in caught.value.reasons)


def test_comment_ending_in_a_backslash_is_read_and_its_inverse_survives_the_safeguard_script(fortios_snapshot):
    snapshot = replace(fortios_snapshot, COMMENT, '        set comment "C:\\\\temp\\\\"')
    document = plan(snapshot, op="update", key="spare-host", changes={"comment": "moved"})
    assert document["predicted"]["before"]["comment"] == TRAILING_BACKSLASH
    assert '        set comment "C:\\\\temp\\\\"' in document["inverse"]
    lines = fortios.render_safeguard("0" * 32, document["inverse"], "2026-10-01 12:00:00")
    action = l1_fortios.parse("\n".join(lines)).section("system automation-action")
    script = next(iter(action.entries.values())).value("script")
    assert script == "\n".join(line.strip() for line in document["inverse"])


@pytest.mark.parametrize("op, changes", [("update", {"comment": "moved"}), ("delete", {})])
def test_comment_ending_in_a_backslash_is_changed_and_undo_requests_it_back(tmp_path, op, changes):
    device = FakeFortiOS()
    device.addresses["spare-host"]["comment"] = TRAILING_BACKSLASH
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, "lab", request(op=op, key="spare-host", changes=changes))
    assert (record["result"], record["reason"]) == ("confirmed", None)
    assert device.addresses.get("spare-host", {}).get("comment") != TRAILING_BACKSLASH
    undone = execute.undo(runtime, record["change_id"], "restore example")
    assert (undone["result"], undone["reason"]) == ("confirmed", None)
    assert device.addresses["spare-host"]["comment"] == TRAILING_BACKSLASH


@pytest.mark.parametrize("comment", ['say "hi"', TRAILING_BACKSLASH, 'a \\" b \\\\'])
def test_fortios_comment_with_quotes_and_backslashes_is_requested_written_and_read_back(tmp_path, comment):
    device = FakeFortiOS()
    record = execute.apply(make_runtime(tmp_path, device), "lab",
                           request(op="update", key="spare-host", changes={"comment": comment}))
    assert (record["result"], record["reason"]) == ("confirmed", None)
    assert device.addresses["spare-host"]["comment"] == comment


@pytest.mark.parametrize("comment", ["first\nsecond", "tab\there", "bell\x07", "del\x7f", "Tiskárna"])
def test_fortios_comment_with_a_control_or_non_ascii_character_is_refused_in_the_request(fortios_snapshot, comment):
    rejected(fortios_snapshot, "attribute comment may hold printable ASCII only", op="update", key="spare-host",
             changes={"comment": comment})


def test_fortios_string_that_is_not_text_still_refuses_quotes_and_backslashes():
    attribute = dataclasses.replace(load_profiles()[("fortios", "firewall address")].attributes["comment"], type="word")
    for value in ('say "hi"', TRAILING_BACKSLASH):
        with pytest.raises(Rejected) as caught:
            canonical_value(attribute, value, "fortios")
        assert caught.value.reasons == ["attribute comment may hold printable ASCII only, without quotes or backslashes"]


@pytest.mark.parametrize("description", ['say "hi"', "C:\\temp\\"])
def test_exos_description_with_quotes_or_backslashes_is_refused_in_the_request(exos_snapshot, description):
    body = parse_request(request_bytes(table="vlan", op="update", key="spare", changes={"description": description}))
    with pytest.raises(Rejected) as caught:
        build_plan("exos", exos_snapshot, body, firmware="33.7.1.6")
    assert caught.value.reasons == ["attribute description may hold printable ASCII only, without quotes or backslashes"]


def test_comment_ending_in_a_backslash_is_restored_by_the_safeguard(tmp_path):
    device = FakeFortiOS()
    device.addresses["spare-host"]["comment"] = TRAILING_BACKSLASH
    device.drop_comment = True
    device.addresses["spare-host"]["subnet"] = "192.0.2.21 255.255.255.255"
    record = execute.apply(make_runtime(tmp_path, device), "lab",
                           request(op="update", key="spare-host", changes={"comment": "moved", "subnet": "192.0.2.22/32"}))
    assert (record["result"], record["reason"]) == ("reverted", "prediction mismatch")
    assert device.addresses["spare-host"]["comment"] == TRAILING_BACKSLASH
    assert device.addresses["spare-host"]["subnet"] == "192.0.2.21 255.255.255.255"
