import os
import selectors
import subprocess
import sys
import time
import types

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


DEAF_BUT_ALIVE = "\n".join(
    (
        "import os, sys, time",
        "open(sys.argv[1], 'w').write(str(os.getpid()))",
        "os.close(1)",
        "os.close(2)",
        "time.sleep(5)",
    )
)
LEAVES_A_CHILD = "\n".join(
    (
        "import os, subprocess, sys, time",
        "open(sys.argv[1], 'w').write(str(os.getpid()))",
        "subprocess.Popen([sys.executable, sys.argv[2], sys.argv[3]])",
        "deadline = time.monotonic() + 10",
        "while not os.path.exists(sys.argv[3]) and time.monotonic() < deadline:",
        "    time.sleep(0.01)",
        "sys.exit(0)",
    )
)
OUTLIVES_ITS_PARENT = "\n".join(
    (
        "import os, sys, time",
        "open(sys.argv[1], 'w').write(str(os.getpid()))",
        "time.sleep(30)",
    )
)


def _pid_of(marker, seconds=5.0):
    deadline = time.monotonic() + seconds
    while True:
        try:
            return int(marker.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
        if time.monotonic() >= deadline:
            raise AssertionError("no process wrote its pid into %s" % marker)
        time.sleep(0.02)


def _ended(pid):
    try:
        with open("/proc/%d/stat" % pid, "rb") as handle:
            state = handle.read().rsplit(b")", 1)[1].split()[0]
    except OSError:
        return True
    return state == b"Z"


def _ended_within(pid, seconds=5.0):
    deadline = time.monotonic() + seconds
    while True:
        if _ended(pid):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.02)


class RefusingSelector:
    def register(self, fileobj, events, data=None):
        raise OSError("this process has no descriptor left for a selector")

    def close(self):
        pass


class BreakingSelector:
    def register(self, fileobj, events, data=None):
        pass

    def select(self, timeout=None):
        raise RuntimeError("the reading loop broke")

    def close(self):
        pass


def _with_selector(monkeypatch, factory):
    monkeypatch.setattr(
        ssh_module,
        "selectors",
        types.SimpleNamespace(DefaultSelector=factory, EVENT_READ=selectors.EVENT_READ),
    )


def _remembered(monkeypatch):
    started = []
    real = subprocess.Popen

    def popen(*arguments, **named):
        process = real(*arguments, **named)
        started.append(process)
        return process

    monkeypatch.setattr(
        ssh_module,
        "subprocess",
        types.SimpleNamespace(
            Popen=popen,
            PIPE=subprocess.PIPE,
            DEVNULL=subprocess.DEVNULL,
            TimeoutExpired=subprocess.TimeoutExpired,
            CompletedProcess=subprocess.CompletedProcess,
        ),
    )
    return started


def test_a_client_that_closes_both_streams_and_stays_is_stopped_by_the_timeout(tmp_path):
    call, marker = _call(tmp_path, DEAF_BUT_ALIVE)
    start = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        _run(call, timeout=1.0)
    assert time.monotonic() - start < 4.0
    assert _gone(marker)


def test_run_command_refuses_a_client_that_closes_its_streams_and_stays(tmp_path, monkeypatch):
    marker = tmp_path / "pid"
    binary = tmp_path / "ssh-stub"
    binary.write_text(
        "#!/bin/sh\nexec %s %s %s\n"
        % (sys.executable, _program(tmp_path, DEAF_BUT_ALIVE), marker),
        encoding="utf-8",
    )
    binary.chmod(0o755)
    monkeypatch.setattr(ssh_module, "SSH_BINARY", str(binary))
    start = time.monotonic()
    with pytest.raises(SshError) as caught:
        run_command(
            HOST, PORT, LOGIN, FakeCredential(), HOST_KEY_LINE, COMMAND, timeout_seconds=1.0,
        )
    assert "did not finish within" in str(caught.value)
    assert time.monotonic() - start < 4.0
    assert _gone(marker)


def test_a_selector_that_cannot_be_registered_leaves_no_client_behind(tmp_path, monkeypatch):
    started = _remembered(monkeypatch)
    _with_selector(monkeypatch, RefusingSelector)
    call, _ = _call(tmp_path, QUIET_BUT_SLOW)
    with pytest.raises(OSError):
        _run(call, timeout=20.0)
    assert len(started) == 1
    assert started[0].poll() is not None


def test_an_error_inside_the_reading_loop_leaves_no_client_behind(tmp_path, monkeypatch):
    started = _remembered(monkeypatch)
    _with_selector(monkeypatch, BreakingSelector)
    call, _ = _call(tmp_path, QUIET_BUT_SLOW)
    with pytest.raises(RuntimeError):
        _run(call, timeout=20.0)
    assert len(started) == 1
    assert started[0].poll() is not None


def test_a_client_that_leaves_a_child_behind_has_its_whole_group_stopped(tmp_path):
    parent_marker = tmp_path / "parent-pid"
    child_marker = tmp_path / "child-pid"
    parent = _program(tmp_path, LEAVES_A_CHILD, name="parent.py")
    child = _program(tmp_path, OUTLIVES_ITS_PARENT, name="grandchild.py")
    call = [sys.executable, str(parent), str(parent_marker), str(child), str(child_marker)]
    start = time.monotonic()
    result = _run(call, timeout=20.0)
    assert result.returncode == 0
    assert time.monotonic() - start < 10.0
    assert _ended_within(_pid_of(child_marker))


def test_a_slow_client_with_open_streams_still_stops_at_the_deadline(tmp_path):
    call, marker = _call(tmp_path, QUIET_BUT_SLOW)
    start = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        _run(call, timeout=1.0)
    assert time.monotonic() - start < 4.0
    assert _gone(marker)


LEAVES_A_QUIET_CHILD = "\n".join(
    (
        "import os, subprocess, sys, time",
        "open(sys.argv[1], 'w').write(str(os.getpid()))",
        "subprocess.Popen([sys.executable, sys.argv[2], sys.argv[3]])",
        "deadline = time.monotonic() + 10",
        "while not os.path.exists(sys.argv[3]) and time.monotonic() < deadline:",
        "    time.sleep(0.01)",
        "sys.exit(0)",
    )
)
QUIET_GRANDCHILD = "\n".join(
    (
        "import os, sys, time",
        "open(sys.argv[1], 'w').write(str(os.getpid()))",
        "os.close(1)",
        "os.close(2)",
        "time.sleep(30)",
    )
)


def test_a_finished_client_leaves_no_child_of_its_own_behind(tmp_path, monkeypatch):
    marker = tmp_path / "grandchild-pid"
    parent = _program(tmp_path, LEAVES_A_QUIET_CHILD, name="quiet-parent.py")
    child = _program(tmp_path, QUIET_GRANDCHILD, name="quiet-grandchild.py")
    binary = tmp_path / "ssh-stub"
    binary.write_text(
        "#!/bin/sh\nexec %s %s %s %s %s\n"
        % (sys.executable, parent, tmp_path / "parent-pid", child, marker),
        encoding="utf-8",
    )
    binary.chmod(0o755)
    monkeypatch.setattr(ssh_module, "SSH_BINARY", str(binary))
    result = run_command(
        HOST, PORT, LOGIN, FakeCredential(), HOST_KEY_LINE, COMMAND, timeout_seconds=20.0,
    )
    grandchild = _pid_of(marker)
    assert result.rc == 0
    assert _ended(grandchild)


def _stub(tmp_path, monkeypatch, script, name="ssh-stub"):
    binary = tmp_path / name
    binary.write_text("#!/bin/sh\n" + script + "\n", encoding="utf-8")
    binary.chmod(0o755)
    monkeypatch.setattr(ssh_module, "SSH_BINARY", str(binary))


def _ask(timeout=20.0):
    return run_command(
        HOST, PORT, LOGIN, FakeCredential(), HOST_KEY_LINE, COMMAND, timeout_seconds=timeout,
    )


@pytest.mark.parametrize("held", ("2>&1", ">/dev/null", "2>/dev/null"))
def test_a_process_that_holds_an_inherited_pipe_does_not_change_the_answer(
    tmp_path, monkeypatch, held
):
    marker = tmp_path / "held-pid"
    _stub(
        tmp_path, monkeypatch,
        "sleep 30 %s &\necho $! > %s\necho answer\nexit 0" % (held, marker),
    )
    start = time.monotonic()
    result = _ask(timeout=20.0)
    assert time.monotonic() - start < 10.0
    assert result.rc == 0
    assert result.stdout == b"answer\n"
    assert _ended_within(_pid_of(marker))


def test_a_held_pipe_and_a_plain_answer_in_sequence_both_return_at_once(tmp_path, monkeypatch):
    marker = tmp_path / "held-pid"
    _stub(tmp_path, monkeypatch, "sleep 30 >/dev/null &\necho $! > %s\nprintf 'one\\n'" % marker)
    start = time.monotonic()
    assert _ask().stdout == b"one\n"
    _stub(tmp_path, monkeypatch, "printf 'two\\n'", name="ssh-plain")
    assert _ask().stdout == b"two\n"
    assert time.monotonic() - start < 10.0
    assert _ended_within(_pid_of(marker))


def test_a_client_killed_by_a_signal_through_the_default_runner_is_refused(tmp_path, monkeypatch):
    _stub(tmp_path, monkeypatch, "printf 'config system global\\n    set'\nkill -9 $$")
    with pytest.raises(SshError) as caught:
        _ask()
    assert "was ended by signal 9" in str(caught.value)
    assert caught.value.rc == -9
    _stub(tmp_path, monkeypatch, "printf 'config system global\\nend\\n'", name="ssh-whole")
    assert _ask().stdout == b"config system global\nend\n"

def _mock_capped_io(monkeypatch, batches, reads, exit_descriptor=None):
    from unittest.mock import Mock

    proc = Mock()
    proc.pid = 41
    proc.stdout.fileno.return_value = 101
    proc.stderr.fileno.return_value = 102
    proc.wait.return_value = 0
    selector = Mock()
    selector.select.side_effect = batches
    stopped = Mock()
    swept = Mock()
    mocked_os = types.SimpleNamespace(read=Mock(side_effect=reads), close=Mock())
    monkeypatch.setattr(
        ssh_module, "subprocess",
        types.SimpleNamespace(
            Popen=Mock(return_value=proc), PIPE=subprocess.PIPE, DEVNULL=subprocess.DEVNULL,
            CompletedProcess=subprocess.CompletedProcess, TimeoutExpired=subprocess.TimeoutExpired,
        ),
    )
    monkeypatch.setattr(
        ssh_module, "selectors",
        types.SimpleNamespace(DefaultSelector=Mock(return_value=selector), EVENT_READ=selectors.EVENT_READ),
    )
    monkeypatch.setattr(ssh_module, "os", mocked_os)
    monkeypatch.setattr(ssh_module, "time", types.SimpleNamespace(monotonic=Mock(return_value=0.0)))
    monkeypatch.setattr(ssh_module, "_own_group", Mock(return_value=41))
    monkeypatch.setattr(ssh_module, "_exit_watch", Mock(return_value=exit_descriptor))
    monkeypatch.setattr(ssh_module, "_stopped", stopped)
    monkeypatch.setattr(ssh_module, "_swept", swept)
    return types.SimpleNamespace(
        proc=proc, selector=selector, stopped=stopped, swept=swept, os=mocked_os,
    )


@pytest.mark.parametrize("budget", (5, 6))
def test_one_stream_eof_does_not_skip_the_other_stream_or_its_cap(monkeypatch, budget):
    err = types.SimpleNamespace(fileobj=102, data="err")
    out = types.SimpleNamespace(fileobj=101, data="out")
    mocks = _mock_capped_io(
        monkeypatch, [[(err, 1)], [(out, 1)], [(out, 1)], [(out, 1)]],
        [b"", b"abc", b"def", b""],
    )
    if budget == 5:
        with pytest.raises(SshError, match="more than 5 bytes on stdout"):
            ssh_module._run_capped(["mock-client"], budget, timeout=10.0, env={}, stdin_bytes=None)
        assert mocks.selector.select.call_count == 3
        assert mocks.os.read.call_count == 3
        mocks.proc.wait.assert_not_called()
        mocks.stopped.assert_called_once_with(mocks.proc, 41)
        mocks.swept.assert_not_called()
    else:
        answer = ssh_module._run_capped(["mock-client"], budget, timeout=10.0, env={}, stdin_bytes=None)
        assert (answer.returncode, answer.stdout, answer.stderr) == (0, b"abcdef", b"")
        assert mocks.selector.select.call_count == 4
        assert [call.args[0] for call in mocks.os.read.call_args_list] == [102, 101, 101, 101]
        mocks.proc.wait.assert_called_once_with(timeout=10.0)
        mocks.swept.assert_called_once_with(41)
        mocks.stopped.assert_not_called()
    mocks.selector.close.assert_called_once_with()
    mocks.proc.stdout.close.assert_called_once_with()
    mocks.proc.stderr.close.assert_called_once_with()


def test_run_capped_failure_passes_owned_group_to_stopped(monkeypatch):
    failure = OSError("synthetic selector failure")
    mocks = _mock_capped_io(monkeypatch, failure, [])
    with pytest.raises(OSError) as caught:
        ssh_module._run_capped(["mock-client"], 6, timeout=10.0, env={}, stdin_bytes=None)
    assert caught.value is failure
    mocks.stopped.assert_called_once_with(mocks.proc, 41)
    mocks.swept.assert_not_called()
    mocks.proc.wait.assert_not_called()
    mocks.os.read.assert_not_called()
    mocks.selector.close.assert_called_once_with()
    mocks.proc.stdout.close.assert_called_once_with()
    mocks.proc.stderr.close.assert_called_once_with()


def test_exited_client_drains_only_currently_ready_bytes_without_waiting(monkeypatch):
    exited = types.SimpleNamespace(fileobj=103, data="exit")
    out = types.SimpleNamespace(fileobj=101, data="out")
    mocks = _mock_capped_io(
        monkeypatch, [[(exited, 1)], [(out, 1)], []], [b"answer"], exit_descriptor=103,
    )
    answer = ssh_module._run_capped(["mock-client"], 6, timeout=10.0, env={}, stdin_bytes=None)
    assert (answer.returncode, answer.stdout, answer.stderr) == (0, b"answer", b"")
    assert [call.args for call in mocks.selector.select.call_args_list] == [(10.0,), (0,), (0,)]
    assert [call.args for call in mocks.selector.unregister.call_args_list] == [(103,)]
    mocks.os.close.assert_called_once_with(103)
    mocks.proc.wait.assert_called_once_with(timeout=10.0)
    mocks.swept.assert_called_once_with(41)
    mocks.stopped.assert_not_called()
    mocks.selector.close.assert_called_once_with()


def test_stopped_signals_the_owned_group_and_client_in_term_kill_order(monkeypatch):
    from unittest.mock import Mock

    events = []
    term = ssh_module.signal.SIGTERM
    kill = ssh_module.signal.SIGKILL
    proc = types.SimpleNamespace(
        send_signal=Mock(side_effect=lambda number: events.append(("client", number))),
        wait=Mock(side_effect=[
            subprocess.TimeoutExpired(["mock-client"], ssh_module.TERMINATE_GRACE_SECONDS), 0,
        ]),
    )

    def wait(timeout):
        events.append(("wait", timeout))
        return proc_wait(timeout=timeout)

    proc_wait = proc.wait
    proc.wait = Mock(side_effect=wait)
    mocked_os = types.SimpleNamespace(
        killpg=Mock(side_effect=lambda group, number: events.append(("group", group, number))),
    )
    monkeypatch.setattr(ssh_module, "os", mocked_os)
    ssh_module._stopped(proc, 41)
    assert events == [
        ("group", 41, term), ("client", term), ("wait", ssh_module.TERMINATE_GRACE_SECONDS),
        ("group", 41, kill), ("client", kill), ("wait", ssh_module.KILL_GRACE_SECONDS),
    ]
    assert proc.send_signal.call_count == 2
    assert mocked_os.killpg.call_count == 2
    assert proc_wait.call_count == 2
