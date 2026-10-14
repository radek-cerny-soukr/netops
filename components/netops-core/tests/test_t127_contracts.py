import os
import sys
import subprocess
import pytest

from netops_core import ssh
from test_session import PtySpawn, session


def test_capped_reader_keeps_every_block_and_enforces_cumulative_limit():
    payload = b"a" * (ssh.READ_CHUNK * 2) + b"final"
    command = [sys.executable, "-I", "-c", "import os; os.write(1, b'a' * %d + b'final')" % (ssh.READ_CHUNK * 2)]
    answer = ssh._run_capped(command, len(payload), timeout=5, env=dict(os.environ), stdin_bytes=None)
    assert answer.stdout == payload and answer.returncode == 0
    with pytest.raises(ssh.SshError):
        ssh._run_capped(command, len(payload)-1, timeout=5, env=dict(os.environ), stdin_bytes=None)


def test_session_context_propagates_failure_and_closes():
    spawn = PtySpawn()
    handle = session(spawn)
    class ChangeRejected(Exception):
        pass
    with pytest.raises(ChangeRejected):
        with handle:
            raise ChangeRejected("fixture refusal")
    assert not os.path.exists(handle.workspace())


@pytest.mark.parametrize("command", ["show\rfixture", "show\r"])
def test_ssh_argv_refuses_carriage_return_in_a_command(command):
    with pytest.raises(ssh.SshError, match="single line"):
        ssh.argv("192.0.2.10", 22, "fixture", "/fixture/known_hosts",
                 command, identity="/fixture/key")


@pytest.mark.parametrize("buffer,patterns,index,consumed,remainder", [
    (b"okok", (b"ok",), 0, b"ok", b"ok"),
    (b"ba", (b"a", b"b"), 1, b"b", b"a"),
    (b"ab", (b"a", b"ab"), 0, b"a", b"b"),
])
def test_session_expect_selects_earliest_match_and_retains_following_bytes(
    monkeypatch, buffer, patterns, index, consumed, remainder
):
    from netops_core.session import Session
    handle = object.__new__(Session)
    monkeypatch.setattr(handle, "_alive", lambda: None)
    handle._pending = buffer
    assert handle.expect(patterns, 1) == (index, consumed)
    assert handle.expect((remainder,), 1) == (0, remainder)
