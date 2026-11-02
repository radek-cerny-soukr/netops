"""Ping on the secondary member of a FortiGate-80F HA cluster returns the device's reason.

The fixture holds the bytes one product ping returned from both members of an
HA a-p cluster of FortiGate-80F with FortiOS 8.0.2 build 0251. The secondary
refuses ``execute ping-options interface`` with a parse error, so the option is
never changed there; the primary accepts it and pings. The fake session answers
each sent command with the recorded bytes, so the real diagnostic shell and the
real recipe run unchanged.
"""

from __future__ import annotations

from dataclasses import replace
import json
import pathlib

import pytest

from netops_helper import engine
from netops_helper import fortios_diagnostics as d
from test_error_branches_helper_engine import _OpenSession, _assert_audit, _diagnostic_target, audit_log  # noqa: F401

RECORDED = json.loads(pathlib.Path(__file__).with_name("fixtures").joinpath("fortios_80f_ha_ping.json").read_text())
ADDRESS = "192.0.2.2"
INTERFACE = "ap-mgmt"


class _Replay:
    def __init__(self, member: str) -> None:
        self.member = dict(RECORDED["members"][member])
        self.pending = [self.member["login"].encode("latin-1")]
        self.sent: list[str] = []

    def expect(self, patterns, timeout):
        buffer = self.pending.pop(0)
        position, index = min((buffer.find(p), i) for i, p in enumerate(patterns) if p in buffer)
        return index, buffer[: position + len(patterns[index])]

    def discard(self, seen) -> None:
        pass

    def send(self, line) -> None:
        self.sent.append(line)
        self.pending.append(self.member["responses"][line].encode("latin-1"))

    def interrupt(self) -> None:
        pass


def _run(member: str):
    session = _Replay(member)
    shell = engine._FortiosDiagnosticShell(session)
    return session, shell


def test_the_secondary_refusal_of_the_interface_option_is_reported_with_its_reason() -> None:
    session, shell = _run("secondary")
    with pytest.raises(d.OptionRefused) as refused:
        d.run(shell, "ping", ADDRESS, INTERFACE, 3, 5)
    assert str(refused.value) == (
        "FortiOS refused 'execute ping-options interface' on this HA secondary member, "
        "so ping could not be bound to the enrolled interface and was not run; "
        "the options it had set were restored and verified. Run ping on the HA primary."
    )
    assert "execute ping " + ADDRESS not in session.sent
    assert "execute ping-options interface auto" not in session.sent
    assert session.sent[-1] == "execute ping-options view-settings"
    assert session.sent.count("execute ping-options view-settings") == 2


def test_a_refusal_outside_an_ha_secondary_names_the_session_only() -> None:
    session = _Replay("secondary")
    member = session.member
    member["login"] = member["login"].replace("(Secondary)", "")
    member["responses"] = {key: value.replace("(Secondary)", "") for key, value in member["responses"].items()}
    session.pending = [member["login"].encode("latin-1")]
    shell = engine._FortiosDiagnosticShell(session)
    with pytest.raises(d.OptionRefused) as refused:
        d.run(shell, "ping", ADDRESS, INTERFACE, 3, 5)
    assert str(refused.value) == (
        "FortiOS refused 'execute ping-options interface' on this session, "
        "so ping could not be bound to the enrolled interface and was not run; "
        "the options it had set were restored and verified."
    )


def test_the_primary_still_pings_with_the_same_recipe() -> None:
    session, shell = _run("primary")
    output, timed_out, identity, domain = d.run(shell, "ping", ADDRESS, INTERFACE, 3, 5)
    assert "3 packets transmitted, 3 packets received, 0% packet loss" in output
    assert not timed_out and identity == ("FortiGate-80F", "8.0.2", "0251") and domain == "root"
    assert "execute ping-options interface auto" in session.sent


def test_a_secondary_that_does_not_restore_its_options_stays_a_failed_restoration() -> None:
    session, shell = _run("secondary")
    responses = session.member["responses"] = dict(session.member["responses"])
    responses["execute ping-options repeat-count 5"] = responses["execute ping-options interface ap-mgmt"].replace(
        "interface ap-mgmt", "repeat-count 5").replace("before 'interface'", "before 'repeat-count'")
    with pytest.raises(ValueError, match="^diagnostic state restoration could not be verified$"):
        d.run(shell, "ping", ADDRESS, INTERFACE, 3, 5)


def test_another_refused_option_is_not_reported_as_an_interface_refusal() -> None:
    session, shell = _run("primary")
    responses = session.member["responses"] = dict(session.member["responses"])
    responses["execute ping-options data-size 56"] = RECORDED["members"]["secondary"]["responses"][
        "execute ping-options interface ap-mgmt"].replace("interface ap-mgmt", "data-size 56").replace(
        "before 'interface'", "before 'data-size'").replace("FGT80F0000002222(Secondary)", "FGT80F0000001111(Primary)")
    with pytest.raises(ValueError) as refused:
        d.run(shell, "ping", ADDRESS, INTERFACE, 3, 5)
    assert not isinstance(refused.value, d.OptionRefused)
    assert str(refused.value) == "diagnostic state restoration could not be verified"
    assert "execute ping " + ADDRESS not in session.sent


def test_the_engine_passes_the_reason_to_the_caller(wire, audit_log, monkeypatch) -> None:
    shell = engine._FortiosDiagnosticShell(_Replay("secondary"))
    monkeypatch.setattr(engine.core_session, "Session", _OpenSession)
    monkeypatch.setattr(engine, "_FortiosDiagnosticShell", lambda opened: shell)
    target = _diagnostic_target()
    target = replace(target, read_inventory={**target.read_inventory, "addresses": (ADDRESS,), "interfaces": (INTERFACE,)})
    with pytest.raises(d.OptionRefused, match="^FortiOS refused 'execute ping-options interface' on this HA secondary"):
        engine.fortios_diagnostics(target, "ping", ADDRESS, INTERFACE, 3, 5, 1000)
    _assert_audit(audit_log, "fortios_diagnostics", ["started", "failed"], "OptionRefused")
