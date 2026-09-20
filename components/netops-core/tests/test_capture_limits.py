import os
import subprocess
import sys

import pytest

from netops_core import hostkey as hostkey_module
from netops_core import session as session_module
from netops_core import sftp as sftp_module
from netops_core import ssh as ssh_module
from netops_core.session import Session, SessionError
from netops_core.ssh import STDERR_MAX_BYTES, SshError, run_command

HOST = "192.0.2.10"
PORT = 22
LOGIN = "audit-ro"
COMMAND = "show"
BLOB = "cmVwbGFjZS1tZS1ob3N0LWtleS1tYXRlcmlhbC1B"
HOST_KEY_LINE = "%s ssh-ed25519 %s" % (HOST, BLOB)
HOST_KEY_PIN = "SHA256:9M3h8iWlwyP5wyoVC6j2DSPB/1Cp4FZhaD1HXhhC7m8"
BUDGET = 4096
FLOOD_BYTES = 200_000

FLOOD = "\n".join(
    (
        "import os, sys",
        "open(sys.argv[1], 'w').write(str(os.getpid()))",
        "sys.stdout.buffer.write(b'x' * %d)" % FLOOD_BYTES,
        "sys.stdout.flush()",
    )
)
ENDLESS = "\n".join(
    (
        "import os, sys",
        "open(sys.argv[1], 'w').write(str(os.getpid()))",
        "while True:",
        "    sys.stdout.buffer.write(b'y' * 65536)",
        "    sys.stdout.flush()",
    )
)
QUIET_BUT_SLOW = "\n".join(
    (
        "import os, sys, time",
        "open(sys.argv[1], 'w').write(str(os.getpid()))",
        "time.sleep(30)",
    )
)
LOUD_STDERR = "\n".join(
    (
        "import sys",
        "sys.stdout.buffer.write(b'ok')",
        "sys.stderr.buffer.write(b'e' * %d)" % (STDERR_MAX_BYTES * 4),
        "sys.stdout.flush()",
        "sys.stderr.flush()",
    )
)
SMALL = "\n".join(("import sys", "sys.stdout.buffer.write(b'z' * 1000)", "sys.stdout.flush()"))


class FakeCredential:
    kind = "ssh-key"
    login = LOGIN
    name = "fw-a-ro"

    def use(self):
        return "-----BEGIN OPENSSH PRIVATE KEY-----\nreplace-me\n"


def _program(tmp_path, body, name="child.py"):
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


def _call(tmp_path, body):
    marker = tmp_path / "pid"
    return [sys.executable, str(_program(tmp_path, body)), str(marker)], marker


def _gone(marker):
    pid = int(marker.read_text(encoding="utf-8"))
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False


def _run(call, budget=BUDGET, timeout=20.0, stdin_bytes=None):
    return ssh_module._capped_runner(budget)(
        call, capture_output=True, timeout=timeout, env=None, check=False, input=stdin_bytes
    )


def test_everything_below_the_budget_comes_back_whole(tmp_path):
    call, _ = _call(tmp_path, SMALL)
    result = _run(call, budget=FLOOD_BYTES)
    assert result.returncode == 0
    assert result.stdout == b"z" * 1000
    assert result.stderr == b""


def test_a_flood_is_stopped_at_the_budget_and_the_client_is_killed(tmp_path):
    call, marker = _call(tmp_path, FLOOD)
    with pytest.raises(SshError) as caught:
        _run(call)
    assert "produced more than %d bytes" % BUDGET in str(caught.value)
    assert _gone(marker)


def test_a_stream_that_never_ends_is_stopped_by_the_budget(tmp_path):
    call, marker = _call(tmp_path, ENDLESS)
    with pytest.raises(SshError) as caught:
        _run(call)
    assert "produced more than %d bytes" % BUDGET in str(caught.value)
    assert _gone(marker)


def test_only_a_bounded_head_of_standard_error_is_kept(tmp_path):
    call, _ = _call(tmp_path, LOUD_STDERR)
    result = _run(call, budget=FLOOD_BYTES)
    assert result.returncode == 0
    assert result.stdout == b"ok"
    assert len(result.stderr) == STDERR_MAX_BYTES


def test_a_client_that_outlives_the_timeout_is_killed(tmp_path):
    call, marker = _call(tmp_path, QUIET_BUT_SLOW)
    with pytest.raises(subprocess.TimeoutExpired):
        _run(call, timeout=1.0)
    assert _gone(marker)


def test_a_budget_that_is_not_a_whole_number_is_refused(tmp_path):
    for value in (0, -1, None, "4096", True):
        with pytest.raises(SshError) as caught:
            run_command(
                HOST, PORT, LOGIN, FakeCredential(), HOST_KEY_LINE, COMMAND,
                capture_max_bytes=value,
            )
        assert "capture_max_bytes must be a whole number" in str(caught.value)


def test_run_command_stops_a_flooding_client_before_it_answers(tmp_path, monkeypatch):
    marker = tmp_path / "pid"
    binary = tmp_path / "ssh-stub"
    binary.write_text(
        "#!/bin/sh\nexec %s %s %s\n"
        % (sys.executable, _program(tmp_path, FLOOD), marker),
        encoding="utf-8",
    )
    binary.chmod(0o755)
    monkeypatch.setattr(ssh_module, "SSH_BINARY", str(binary))
    with pytest.raises(SshError) as caught:
        run_command(
            HOST, PORT, LOGIN, FakeCredential(), HOST_KEY_LINE, COMMAND,
            capture_max_bytes=BUDGET, timeout_seconds=20.0,
        )
    assert "produced more than %d bytes" % BUDGET in str(caught.value)
    assert _gone(marker)


def test_sftp_stops_a_flooding_client_before_it_parses(tmp_path, monkeypatch):
    marker = tmp_path / "pid"
    binary = tmp_path / "sftp-stub"
    binary.write_text(
        "#!/bin/sh\nexec %s %s %s\n"
        % (sys.executable, _program(tmp_path, FLOOD), marker),
        encoding="utf-8",
    )
    binary.chmod(0o755)
    monkeypatch.setattr(sftp_module, "SFTP_BINARY", str(binary))
    with pytest.raises(sftp_module.SftpError) as caught:
        sftp_module.stat(
            HOST, PORT, LOGIN, FakeCredential(), HOST_KEY_LINE, "/safe",
            capture_max_bytes=BUDGET, timeout_seconds=20.0,
        )
    assert "produced more than %d bytes" % BUDGET in str(caught.value)
    assert _gone(marker)


def test_scan_stops_a_flooding_keyscan_before_it_answers(tmp_path, monkeypatch):
    marker = tmp_path / "pid"
    binary = tmp_path / "ssh-keyscan-stub"
    binary.write_text(
        "#!/bin/sh\nexec %s %s %s\n"
        % (sys.executable, _program(tmp_path, FLOOD), marker),
        encoding="utf-8",
    )
    binary.chmod(0o755)
    monkeypatch.setattr(hostkey_module, "KEYSCAN_BINARY", str(binary))
    with pytest.raises(hostkey_module.HostKeyError) as caught:
        hostkey_module.scan(HOST, PORT, HOST_KEY_PIN, 20.0, capture_max_bytes=BUDGET)
    assert "produced more than %d bytes" % BUDGET in str(caught.value)
    assert HOST in str(caught.value)
    assert _gone(marker)


def test_a_flooding_keyscan_stays_the_refusal_its_callers_handle(tmp_path, monkeypatch):
    binary = tmp_path / "ssh-keyscan-stub"
    binary.write_text(
        "#!/bin/sh\nexec %s %s %s\n"
        % (sys.executable, _program(tmp_path, FLOOD), tmp_path / "pid"),
        encoding="utf-8",
    )
    binary.chmod(0o755)
    monkeypatch.setattr(hostkey_module, "KEYSCAN_BINARY", str(binary))
    try:
        hostkey_module.scan(HOST, PORT, HOST_KEY_PIN, 20.0, capture_max_bytes=BUDGET)
    except hostkey_module.HostKeyError:
        pass
    except BaseException as error:
        raise AssertionError(
            "scan must refuse with HostKeyError, the only error its callers catch, got %s"
            % type(error).__name__
        ) from None
    else:
        raise AssertionError("a flooding keyscan must be refused")


@pytest.mark.parametrize("budget", (0, -1, None, "4096", True))
def test_a_keyscan_budget_that_is_not_a_whole_number_is_refused_the_same_way(budget):
    with pytest.raises(hostkey_module.HostKeyError) as caught:
        hostkey_module.scan(HOST, PORT, HOST_KEY_PIN, 20.0, capture_max_bytes=budget)
    assert "capture_max_bytes must be a whole number" in str(caught.value)


def test_scan_still_parses_a_normal_small_answer_through_the_capped_default(
    tmp_path, monkeypatch
):
    binary = tmp_path / "ssh-keyscan-stub"
    binary.write_text("#!/bin/sh\necho '%s'\n" % HOST_KEY_LINE, encoding="utf-8")
    binary.chmod(0o755)
    monkeypatch.setattr(hostkey_module, "KEYSCAN_BINARY", str(binary))
    assert hostkey_module.scan(HOST, PORT, HOST_KEY_PIN, 20.0) == HOST_KEY_LINE


def _flooding_spawn(call, env):
    read_end, write_end = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_end)
        try:
            while True:
                os.write(write_end, b"y" * 65536)
        except OSError:
            pass
        finally:
            os._exit(0)
    os.close(write_end)
    return pid, read_end


def test_a_terminal_that_never_matches_is_stopped_by_the_budget():
    handle = Session(
        HOST, PORT, LOGIN, FakeCredential(), HOST_KEY_LINE,
        capture_max_bytes=BUDGET, spawn=_flooding_spawn,
    )
    try:
        with pytest.raises(SessionError) as caught:
            handle.expect([b"NEVER-MATCHES"], 20.0)
        assert "produced more than %d bytes" % BUDGET in str(caught.value)
        assert caught.value.transcript_bytes > BUDGET
    finally:
        handle.close()


def test_the_budget_of_a_terminal_must_be_a_whole_number():
    calls = []

    def refused(call, env):
        calls.append(call)
        raise AssertionError("the session must be refused before anything is started")

    with pytest.raises(Exception) as caught:
        Session(
            HOST, PORT, LOGIN, FakeCredential(), HOST_KEY_LINE,
            capture_max_bytes=0, spawn=refused,
        )
    assert calls == []
    assert "capture_max_bytes must be a whole number" in str(caught.value)


def test_the_transports_agree_on_one_written_down_budget():
    assert ssh_module.CAPTURE_MAX_BYTES == 16 * 1024 * 1024
    assert ssh_module.STDERR_MAX_BYTES == 64 * 1024
    assert session_module.ssh_module.CAPTURE_MAX_BYTES == ssh_module.CAPTURE_MAX_BYTES
