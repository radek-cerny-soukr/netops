import pytest
from conftest import FIXTURES, request_bytes
from test_access import Shell, device_access

from netops_admin import engine, exec_fortios, exos, fortios
from netops_admin.errors import Rejected
from netops_admin.request import parse_request

QUESTION = "who owns this?"


def fortios_plan(text, changes):
    request = parse_request(request_bytes(op="update", key="spare-host", changes=changes))
    return engine.build_plan("fortios", text.encode(), request)


def exos_plan(text, op, changes):
    request = parse_request(request_bytes(table="vlan", op=op, key="spare", changes=changes))
    return engine.build_plan("exos", text.encode(), request, firmware="33.7.1.6")


def sent_by_fortios(lines):
    shell = Shell([b"FortiGate-60F $ "] + [b"\r\nFortiGate-60F (spare-host) $ "] * len(lines))
    device_access(shell).apply(lines, exec_fortios.prompt_spec("FortiGate-60F"))
    return shell.sent


@pytest.mark.parametrize("case", ["new-value", "old-value"])
def test_fortios_question_mark_is_sent_after_ctrl_v_in_the_change_and_in_the_safeguard(case):
    text = (FIXTURES / "fortios_8_0_0.conf").read_text()
    changes = {"comment": QUESTION if case == "new-value" else "reserved"}
    if case == "old-value":
        text = text.replace('set comment "unused"', 'set comment "%s"' % QUESTION)
    document = fortios_plan(text, changes)
    written = document["commands"] if case == "new-value" else document["inverse"]
    assert '        set comment "%s"' % QUESTION in written
    sent = sent_by_fortios(written)
    assert 'set comment "who owns this\x16?"' in [line.strip() for line in sent]
    safeguard = fortios.render_safeguard("a" * 32, document["inverse"], "2026-11-01 03:16:46")
    sent = sent_by_fortios(safeguard)
    assert all("?" not in line.replace("\x16?", "") for line in sent)


def test_fortios_safeguard_readback_of_a_question_mark_matches_the_device_answer():
    inverse = ["config firewall address", '    edit "spare-host"', '        set comment "%s"' % QUESTION,
               "    next", "end"]
    action = ('config system automation-action\n    edit "netops-sg-aaaaaaaaaaaa-a"\n        set action-type cli-script\n'
              '        set script "config firewall address\nedit \\"spare-host\\"\nset comment \\"%s\\"\nnext\nend"\n'
              "    next\nend\n" % QUESTION)
    answers = {"action": action}
    problems = fortios.safeguard_state("a" * 32, answers, inverse, "2026-11-01 03:16:46")
    assert "safeguard script differs from the planned inverse" not in problems


def test_exos_dollar_text_is_written_directly_and_planned():
    text = (FIXTURES / "exos_33_7_1.conf").read_text()
    document = exos_plan(text, "update", {"description": "cost $5 $(x)"})
    assert 'configure vlan spare description "cost $5 $(x)"' in document["commands"]


@pytest.mark.parametrize("old", ["price $(x)", "cost $((1))"])
def test_exos_old_text_with_dollar_parenthesis_is_refused_before_any_write(old):
    text = (FIXTURES / "exos_33_7_1.conf").read_text().replace('description "unused"', 'description "%s"' % old)
    with pytest.raises(Rejected, match=r"\$\(.*timed safeguard"):
        exos_plan(text, "delete", {})


@pytest.mark.parametrize("old", ["price $5", "web $x", "cost ${x}", "web (prod)"])
def test_exos_old_text_that_the_switch_restores_literally_is_planned(old):
    text = (FIXTURES / "exos_33_7_1.conf").read_text().replace('description "unused"', 'description "%s"' % old)
    document = exos_plan(text, "delete", {})
    assert 'configure vlan spare description "%s"' % old in document["inverse"]


def test_direct_exos_safeguard_script_cannot_bypass_the_dollar_parenthesis_check():
    with pytest.raises(Rejected, match=r"\$\("):
        exos.safeguard_script(['configure vlan spare description "price $(x)"'])
