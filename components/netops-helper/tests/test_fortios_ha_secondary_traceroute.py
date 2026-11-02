"""Traceroute on the secondary member of a FortiGate-80F HA cluster returns the device's reason.

The fixture holds the bytes one product traceroute returned from both members
of an HA a-p cluster of FortiGate-80F with FortiOS 8.0.2 build 0251. The
secondary accepts ``execute traceroute-options device`` but refuses
``execute traceroute-options source`` with a parse error, so the source option
is never changed there; the primary accepts both and traces. The fake session
answers each sent command with the recorded bytes, so the real diagnostic
shell and the real recipe run unchanged.
"""

from __future__ import annotations

from dataclasses import replace
import json
import pathlib

import pytest

from netops_helper import engine
from netops_helper import fortios_diagnostics as d
from test_error_branches_helper_engine import _OpenSession, _assert_audit, _diagnostic_target, audit_log  # noqa: F401

FIXTURES = pathlib.Path(__file__).with_name("fixtures")
TRACEROUTE = json.loads(FIXTURES.joinpath("fortios_80f_ha_traceroute.json").read_text())
PING = json.loads(FIXTURES.joinpath("fortios_80f_ha_ping.json").read_text())
ADDRESS = "192.0.2.2"
INTERFACE = "ap-mgmt"
SOURCE_REFUSAL = TRACEROUTE["members"]["secondary"]["responses"]["execute traceroute-options source auto"]


class _Replay:
    def __init__(self, recorded: dict, member: str) -> None:
        self.member = dict(recorded["members"][member])
        self.member["responses"] = dict(self.member["responses"])
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


def test_the_secondary_refusal_of_the_source_option_is_reported_with_its_reason() -> None:
    session = _Replay(TRACEROUTE, "secondary")
    shell = engine._FortiosDiagnosticShell(session)
    with pytest.raises(d.OptionRefused) as refused:
        d.run(shell, "traceroute", ADDRESS, INTERFACE, 3, 5)
    assert str(refused.value) == (
        "FortiOS refused 'execute traceroute-options source' on this HA secondary member, "
        "so traceroute could not use the automatic source address and was not run; "
        "the options it had set were restored and verified. Run traceroute on the HA primary."
    )
    assert "execute traceroute " + ADDRESS not in session.sent
    assert session.sent.count("execute traceroute-options source auto") == 1
    assert "execute traceroute-options device auto" in session.sent
    assert session.sent[-1] == "execute traceroute-options view-settings"
    assert session.sent.count("execute traceroute-options view-settings") == 2


def test_the_primary_still_traces_with_the_same_recipe() -> None:
    session = _Replay(TRACEROUTE, "primary")
    shell = engine._FortiosDiagnosticShell(session)
    output, timed_out, identity, domain = d.run(shell, "traceroute", ADDRESS, INTERFACE, 3, 5)
    assert "traceroute to " + ADDRESS in output
    assert not timed_out and identity == ("FortiGate-80F", "8.0.2", "0251") and domain == "root"
    assert session.sent.count("execute traceroute-options source auto") == 2


def test_a_secondary_that_does_not_restore_the_device_stays_a_failed_restoration() -> None:
    session = _Replay(TRACEROUTE, "secondary")
    session.member["responses"]["execute traceroute-options device auto"] = SOURCE_REFUSAL.replace(
        "source auto", "device auto").replace("before 'source'", "before 'device'")
    shell = engine._FortiosDiagnosticShell(session)
    with pytest.raises(ValueError, match="^diagnostic state restoration could not be verified$"):
        d.run(shell, "traceroute", ADDRESS, INTERFACE, 3, 5)


def test_a_refused_ping_source_is_reported_with_its_reason() -> None:
    session = _Replay(PING, "primary")
    session.member["responses"]["execute ping-options source auto"] = SOURCE_REFUSAL.replace(
        "traceroute-options", "ping-options").replace("FGT80F0000002222(Secondary)", "FGT80F0000001111(Primary)")
    shell = engine._FortiosDiagnosticShell(session)
    with pytest.raises(d.OptionRefused) as refused:
        d.run(shell, "ping", ADDRESS, INTERFACE, 3, 5)
    assert str(refused.value) == (
        "FortiOS refused 'execute ping-options source' on this session, "
        "so ping could not use the automatic source address and was not run; "
        "the options it had set were restored and verified."
    )
    assert "execute ping " + ADDRESS not in session.sent
    assert session.sent.count("execute ping-options source auto") == 1
    assert "execute ping-options interface auto" in session.sent
    assert session.sent[-1] == "execute ping-options view-settings"


def test_the_engine_passes_the_traceroute_reason_to_the_caller(wire, audit_log, monkeypatch) -> None:
    shell = engine._FortiosDiagnosticShell(_Replay(TRACEROUTE, "secondary"))
    monkeypatch.setattr(engine.core_session, "Session", _OpenSession)
    monkeypatch.setattr(engine, "_FortiosDiagnosticShell", lambda opened: shell)
    target = _diagnostic_target()
    target = replace(target, read_inventory={**target.read_inventory, "diagnostic_recipes": ("traceroute",),
                                             "addresses": (ADDRESS,), "interfaces": (INTERFACE,)})
    with pytest.raises(d.OptionRefused, match="^FortiOS refused 'execute traceroute-options source' on this HA secondary"):
        engine.fortios_diagnostics(target, "traceroute", ADDRESS, INTERFACE, 3, 5, 1000)
    _assert_audit(audit_log, "fortios_diagnostics", ["started", "failed"], "OptionRefused")
