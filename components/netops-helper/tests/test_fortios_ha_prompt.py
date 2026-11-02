"""The FortiOS diagnostic shell accepts the CLI prompt of an HA cluster member.

A FortiGate-80F HA cluster with FortiOS 8.0.2 build 0251 logs in with the HA
role appended to the hostname without a space. The recorded bytes were
b"FGT80F*1111(Primary) $ " with the serial masked; the tests use a synthetic
hostname in its place. The fake session matches awaited patterns the way
netops_core.session.Session does, so only the network is substituted.
"""

from __future__ import annotations

import pytest

from netops_core.session import SessionError
from netops_helper import engine

HA_PRIMARY = b"FGT80F0000001111(Primary) $ "


class _Session:
    def __init__(self, *chunks: bytes) -> None:
        self.chunks = list(chunks)
        self.awaited: list = []
        self.sent: list = []

    def expect(self, patterns, timeout):
        self.awaited.append(list(patterns))
        buffer = self.chunks.pop(0)
        found = [(buffer.find(pattern), index) for index, pattern in enumerate(patterns) if pattern in buffer]
        if not found:
            raise SessionError("no awaited pattern", len(buffer))
        position, index = min(found)
        return index, buffer[: position + len(patterns[index])]

    def discard(self, seen) -> None:
        pass

    def send(self, text) -> None:
        self.sent.append(text)


@pytest.mark.parametrize("prompt", [
    HA_PRIMARY,
    b"FGT80F0000002222(Secondary) $ ",
    b"FGT80F0000001111(Primary) # ",
    b"FGT-SYNTH (root) # ",
    b"FGT-SYNTH $ ",
])
def test_the_login_prompt_of_a_cluster_member_is_verified(prompt) -> None:
    session = _Session(b"banner\r\n" + prompt, b"get system status\r\nVersion: synthetic\r\n" + prompt)
    shell = engine._FortiosDiagnosticShell(session)
    assert shell.prompt == prompt
    assert shell.command("get system status") == "Version: synthetic"
    assert session.awaited[-1] == [prompt]


@pytest.mark.parametrize("prompt", [
    b"FGT80F*1111(Primary) $ ",
    b"FGT80F0000001111(Master) $ ",
    b"FGT80F0000001111(Slave) $ ",
    b"FGT80F0000001111(primary) $ ",
    b"FGT80F0000001111(Primary)(Secondary) $ ",
    b"FGT80F0000001111(Primary) (root) $ ",
    b"FGT80F0000001111(Primary)$ ",
    b"(Primary) $ ",
    b"random text $ ",
    b"Login incorrect # ",
])
def test_any_other_login_prompt_is_refused(prompt) -> None:
    with pytest.raises(ValueError, match="^the diagnostic session prompt cannot be verified$"):
        engine._FortiosDiagnosticShell(_Session(b"banner\r\n" + prompt))


def test_the_prompt_of_another_hostname_does_not_end_an_answer() -> None:
    session = _Session(HA_PRIMARY, b"get system status\r\nVersion: synthetic\r\nFGT80F0000009999(Primary) $ ")
    shell = engine._FortiosDiagnosticShell(session)
    with pytest.raises(SessionError):
        shell.command("get system status")
    assert not shell.ready


@pytest.mark.parametrize("role", ["P", "S", "M", "I"])
def test_a_fortiadc_cluster_role_before_the_hostname_is_verified(role) -> None:
    prompt = f"({role}) FADC-SYNTH # ".encode()
    context = f"({role}) FADC-SYNTH (ha) # ".encode()
    session = _Session(
        b"banner\r\n" + prompt,
        b"get system status\r\nVersion: synthetic\r\n" + prompt,
        b"config system ha\r\n" + context,
        b"get\r\nmode: synthetic\r\n" + context,
        b"get system status\r\nVersion: again\r\n" + context,
    )
    shell = engine._FortiosDiagnosticShell(session, "fortiadc")
    assert shell.prompt == prompt
    assert shell.command("get system status") == "Version: synthetic"
    assert session.awaited[-1] == [prompt]
    assert shell.navigate("config system ha") == ""
    assert shell.prompt == context
    assert shell.command("get") == "mode: synthetic"
    assert session.awaited[-1] == [context]
    assert shell.command("get system status") == "Version: again"
    assert session.awaited[-1] == [context]


@pytest.mark.parametrize("prompt", [
    b"(P) FADC-SYNTH # ",
    b"(S) FADC-SYNTH # ",
    b"(M) FADC-SYNTH # ",
    b"(I) FADC-SYNTH # ",
])
def test_the_fortiadc_role_prefix_is_refused_for_fortinet(prompt) -> None:
    with pytest.raises(ValueError, match="^the diagnostic session prompt cannot be verified$"):
        engine._FortiosDiagnosticShell(_Session(b"banner\r\n" + prompt))


@pytest.mark.parametrize("prompt", [
    b"(X) FADC-SYNTH # ",
    b"(P)FADC-SYNTH # ",
    b"(p) FADC-SYNTH # ",
    b"(P)(S) FADC-SYNTH # ",
    b"(P) (S) FADC-SYNTH # ",
])
def test_any_other_fortiadc_role_prefix_is_refused(prompt) -> None:
    with pytest.raises(ValueError, match="^the diagnostic session prompt cannot be verified$"):
        engine._FortiosDiagnosticShell(_Session(b"banner\r\n" + prompt), "fortiadc")


def test_a_fortiadc_context_prompt_with_an_unknown_role_is_refused() -> None:
    session = _Session(b"(P) FADC-SYNTH # ", b"config system ha\r\n(X) FADC-SYNTH (ha) # ")
    shell = engine._FortiosDiagnosticShell(session, "fortiadc")
    with pytest.raises(ValueError, match="^the diagnostic context prompt cannot be verified$"):
        shell.navigate("config system ha")
