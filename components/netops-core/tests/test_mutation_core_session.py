import fcntl
import os
import pty
import signal
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

import pytest

from netops_core import session as session_module
from netops_core import ssh as ssh_module
from netops_core.session import Session, SessionError, argv
from netops_core.ssh import OWNER_NAME, WORKSPACE_PREFIX, SshError

HOST = "192.0.2.10"
PORT = 22
LOGIN = "audit-ro"
BLOB = "cmVwbGFjZS1tZS1ob3N0LWtleS1tYXRlcmlhbC1B"
HOST_KEY_LINE = "%s ssh-ed25519 %s" % (HOST, BLOB)
KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nKANARCI-KLIC-NESMI-UNIKNOUT\n"
MOMENT = datetime(2026, 9, 16, 8, 30, 0, tzinfo=timezone.utc)
CHILD = "\n".join(
    (
        "import signal, sys",
        "signal.alarm(20)",
        "write = sys.stdout.write",
        "write('Please login: ')",
        "sys.stdout.flush()",
        "sys.stdin.readline()",
        "write('password : ')",
        "sys.stdout.flush()",
        "sys.stdin.readline()",
        "write('ruckus> ')",
        "sys.stdout.flush()",
        "sys.stdin.readline()",
    )
)
QUIET = "\n".join(("import sys, time", "sys.stdout.write('noise')", "sys.stdout.flush()", "time.sleep(5)"))
def two_bursts(first, second, rest=1.0, linger=0.0):
    return "\n".join(
        (
            "import sys, time",
            "sys.stdout.write('READY')",
            "sys.stdout.flush()",
            "time.sleep(0.2)",
            "sys.stdout.write(%r)" % first,
            "sys.stdout.flush()",
            "time.sleep(%r)" % rest,
            "sys.stdout.write(%r)" % second,
            "sys.stdout.flush()",
            "time.sleep(%r)" % linger,
        )
    )


class Credential:
    kind = "ssh-key"
    login = LOGIN
    name = "sw-a-ro"

    def use(self):
        return KEY


class Nameless:
    kind = "ssh-key"

    def use(self):
        return KEY


class PtySpawn:
    def __init__(self, script=CHILD):
        self.script = script
        self.pid = None

    def __call__(self, call, env):
        pid, fd = pty.fork()
        if pid == 0:
            try:
                os.execve(sys.executable, [sys.executable, "-I", "-c", self.script], env)
            finally:
                os._exit(127)
        self.pid = pid
        return pid, fd


class Unsent:
    def __getattr__(self, name):
        return getattr(os, name)

    def write(self, fd, data):
        return 0


def opened(spawn=None, **kwargs):
    login = kwargs.pop("login", LOGIN)
    credential = kwargs.pop("credential", Credential())
    return Session(HOST, PORT, login, credential, HOST_KEY_LINE,
                   spawn=PtySpawn() if spawn is None else spawn, **kwargs)


def assert_sentence(error, subject, received=None):
    text = str(error)
    assert text.startswith(subject), text
    if received is not None:
        assert text.endswith(received), text


def ended_within(pid, seconds=5.0):
    deadline = time.monotonic() + seconds
    while True:
        try:
            with open("/proc/%d/stat" % pid, "rb") as handle:
                state = handle.read().rsplit(b")", 1)[1].split()[0]
        except OSError:
            return True
        if state == b"Z":
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.02)


def pid_in(marker, seconds=5.0):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            return int(marker.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            time.sleep(0.02)
    raise AssertionError("no pid in %s" % marker)


def kill_quietly(pid):
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


@pytest.fixture
def private_tmp(tmp_path, monkeypatch):
    directory = tmp_path / "tmp"
    directory.mkdir(mode=0o700)
    monkeypatch.setattr(tempfile, "tempdir", str(directory))
    return directory


@pytest.fixture
def terminal():
    handle = opened()
    yield handle
    handle.close()


@pytest.fixture
def pipe_session():
    read_end, write_end = os.pipe()
    os.set_blocking(write_end, False)
    handle = opened(spawn=lambda call, env: (0, write_end))
    yield handle
    handle.close()
    os.close(read_end)


def test_argv_refuses_an_empty_known_hosts_naming_the_field():
    with pytest.raises(SshError) as caught:
        argv(HOST, PORT, LOGIN, "")
    assert_sentence(caught.value, "known_hosts must be a non-empty string", repr(""))


def test_argv_refuses_an_empty_identity_naming_the_field():
    with pytest.raises(SshError) as caught:
        argv(HOST, PORT, LOGIN, "/w/known_hosts", identity=" ")
    assert_sentence(caught.value, "identity must be a non-empty string", repr(" "))


def test_a_single_text_pattern_is_awaited_as_it_is(terminal):
    assert terminal.expect("login: ", 10.0) == (0, b"Please login: ")


def test_a_single_bytes_pattern_is_awaited_as_it_is(terminal):
    assert terminal.expect(b"login: ", 10.0) == (0, b"Please login: ")


def test_patterns_that_are_not_a_collection_are_refused_naming_their_type(terminal):
    with pytest.raises(SessionError) as caught:
        terminal.expect(5, 1.0)
    assert_sentence(caught.value, "expect waits for text patterns", "int")
    assert caught.value.transcript_bytes == 0


def test_a_pattern_that_is_no_valid_unicode_is_refused(terminal):
    with pytest.raises(SessionError) as caught:
        terminal.expect(["\ud800"], 1.0)
    assert_sentence(caught.value, "a text pattern must be valid ")


def test_a_pattern_of_another_type_is_refused_naming_its_type(terminal):
    with pytest.raises(SessionError) as caught:
        terminal.expect(["login:", 5], 1.0)
    assert_sentence(caught.value, "a pattern must be text or bytes", "int")


@pytest.mark.parametrize("patterns", ([""], [b""], ["ok", b""]))
def test_an_empty_pattern_is_refused(terminal, patterns):
    with pytest.raises(SessionError) as caught:
        terminal.expect(patterns, 1.0)
    assert_sentence(caught.value, "a pattern must not be empty")


@pytest.mark.parametrize("patterns", ([], ()))
def test_no_pattern_at_all_is_refused(terminal, patterns):
    with pytest.raises(SessionError) as caught:
        terminal.expect(patterns, 1.0)
    assert_sentence(caught.value, "expect needs at least one pattern to wait for")


def test_an_explicit_login_wins_over_the_login_of_the_credential():
    handle = opened(login="operator")
    try:
        assert handle.login == "operator"
        assert handle.argv[-1] == "operator@%s" % HOST
    finally:
        handle.close()


def test_without_a_login_the_session_takes_the_login_of_the_credential():
    handle = opened(login=None)
    try:
        assert handle.login == LOGIN
        assert handle.argv[-1] == "%s@%s" % (LOGIN, HOST)
    finally:
        handle.close()


def test_a_credential_without_a_login_and_no_login_is_refused_as_a_login(private_tmp):
    with pytest.raises(SshError) as caught:
        opened(login=None, credential=Nameless())
    assert_sentence(caught.value, "login must be a non-empty string", "None")
    assert os.listdir(private_tmp) == []


def test_a_session_records_what_it_was_opened_with():
    handle = opened(timeout_seconds=7, now=lambda: MOMENT)
    try:
        assert handle.host == HOST
        assert handle.port == PORT
        assert handle.login == LOGIN
        assert handle.timeout_seconds == 7.0
        assert handle.started_at == "2026-09-16T08:30:00Z"
        assert isinstance(handle.argv, list)
        assert handle.argv[0] == ssh_module.SSH_BINARY
        assert handle.seen_bytes == 0
        assert handle.discarded_login_bytes == 0
    finally:
        handle.close()


def test_a_spawn_that_is_not_callable_is_refused_naming_its_type(private_tmp):
    with pytest.raises(SessionError) as caught:
        opened(spawn=5)
    assert_sentence(caught.value, "spawn must be callable", "int")
    assert os.listdir(private_tmp) == []


def test_without_a_spawn_the_session_starts_the_ssh_binary_on_a_terminal(tmp_path, monkeypatch):
    binary = tmp_path / "ssh-stub"
    binary.write_text("#!%s -I\n%s\n" % (sys.executable, CHILD), encoding="utf-8")
    binary.chmod(0o755)
    monkeypatch.setattr(ssh_module, "SSH_BINARY", str(binary))
    handle = Session(HOST, PORT, LOGIN, Credential(), HOST_KEY_LINE)
    try:
        assert handle.expect(["login: "], 10.0) == (0, b"Please login: ")
        handle.send("operator")
        index, consumed = handle.expect(["password : "], 10.0)
        assert index == 0
        assert consumed.endswith(b"password : ")
    finally:
        handle.close()


def test_without_a_spawn_the_client_sees_only_the_prepared_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("W4_KANARCI_PROSTREDI", "nesmi-projit")
    script = "\n".join(
        (
            "import os, sys",
            "sys.stdout.write('ENV %s HOME=%s END' % (os.environ.get('W4_KANARCI_PROSTREDI'), os.environ.get('HOME')))",
            "sys.stdout.flush()",
            "sys.stdin.readline()",
        )
    )
    binary = tmp_path / "ssh-stub"
    binary.write_text("#!%s -I\n%s\n" % (sys.executable, script), encoding="utf-8")
    binary.chmod(0o755)
    monkeypatch.setattr(ssh_module, "SSH_BINARY", str(binary))
    handle = Session(HOST, PORT, LOGIN, Credential(), HOST_KEY_LINE)
    try:
        _, consumed = handle.expect([" END"], 10.0)
        assert consumed == ("ENV None HOME=%s END" % handle.workspace()).encode()
    finally:
        handle.close()


def test_the_workspace_is_named_for_the_sweep_private_and_claimed():
    handle = opened()
    try:
        workspace = handle.workspace()
        assert os.path.basename(workspace).startswith(WORKSPACE_PREFIX)
        assert stat.S_IMODE(os.stat(workspace).st_mode) == 0o700
        descriptor = os.open(os.path.join(workspace, OWNER_NAME), os.O_RDONLY)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(descriptor)
    finally:
        handle.close()
    assert not os.path.exists(workspace)


def test_a_failing_claim_is_a_session_refusal_and_leaves_no_workspace(private_tmp, monkeypatch):
    def claimed(workspace):
        raise OSError("claim refused")

    monkeypatch.setattr(ssh_module, "_claimed", claimed)
    with pytest.raises(SessionError) as caught:
        opened()
    assert_sentence(caught.value, "cannot open the session to %s" % HOST, "(OSError)")
    assert os.listdir(private_tmp) == []


def test_a_spawn_that_fails_is_reported_with_the_device_and_the_error_type(private_tmp):
    def spawn(call, env):
        raise PermissionError("denied")

    with pytest.raises(SessionError) as caught:
        opened(spawn=spawn)
    assert_sentence(caught.value, "cannot open the session to %s" % HOST, "(PermissionError)")
    assert os.listdir(private_tmp) == []


@pytest.mark.parametrize("answer", ((None, "fd"), ("pid", 0), (None, 0)))
def test_a_spawn_answer_without_a_pid_or_a_descriptor_is_refused_naming_it(private_tmp, answer):
    read_end, write_end = os.pipe()
    answer = tuple(write_end if part == 0 else part for part in answer)
    try:
        with pytest.raises(SessionError) as caught:
            opened(spawn=lambda call, env: answer)
        assert_sentence(caught.value, "spawn must answer with a process id and a file descriptor", repr(answer))
        assert os.listdir(private_tmp) == []
    finally:
        for descriptor in (read_end, write_end):
            try:
                os.close(descriptor)
            except OSError:
                pass


def test_discard_counts_every_discarded_byte(terminal):
    assert terminal.discard("abč") == 4
    assert terminal.discard(b"xy") == 2
    assert terminal.discard(bytearray(b"z")) == 1
    assert terminal.discarded_login_bytes == 7


def test_discard_refuses_what_expect_never_returns_naming_its_type(terminal):
    with pytest.raises(SessionError) as caught:
        terminal.discard(5)
    assert_sentence(caught.value, "discard takes the bytes expect returned", "int")


def test_a_closed_session_says_so_naming_the_device():
    handle = opened()
    handle.close()
    with pytest.raises(SessionError) as caught:
        handle.expect(["login: "], 1.0)
    assert_sentence(caught.value, "the session to %s is already closed" % HOST)


def test_after_a_timeout_the_next_expect_starts_from_new_output(terminal):
    with pytest.raises(SessionError) as caught:
        terminal.expect(["never"], 2.0)
    assert caught.value.transcript_bytes == len(b"Please login: ")
    terminal.send("operator")
    index, consumed = terminal.expect(["password : "], 10.0)
    assert index == 0
    assert consumed.endswith(b"password : ")
    assert b"Please login" not in consumed
    assert b"XX" not in consumed


def test_seen_bytes_add_up_over_two_timeouts(terminal):
    with pytest.raises(SessionError) as first:
        terminal.expect(["never"], 2.0)
    terminal.send("operator")
    time.sleep(0.3)
    with pytest.raises(SessionError) as second:
        terminal.expect(["never"], 1.0)
    assert first.value.transcript_bytes > 0
    assert second.value.transcript_bytes > 0
    assert terminal.seen_bytes == first.value.transcript_bytes + second.value.transcript_bytes
    assert_sentence(first.value, "%s did not answer any of the 1 awaited pattern(s)" % HOST,
                    "%d byte(s) seen" % first.value.transcript_bytes)


def test_seen_bytes_add_up_over_a_timeout_and_the_end_of_the_session():
    handle = opened(spawn=PtySpawn(two_bursts("A" * 10, "B" * 20, rest=1.5)))
    try:
        handle.expect(["READY"], 10.0)
        with pytest.raises(SessionError) as first:
            handle.expect(["never"], 1.0)
        with pytest.raises(SessionError) as second:
            handle.expect(["never"], 10.0)
        assert first.value.transcript_bytes == 10
        assert second.value.transcript_bytes == 20
        assert handle.seen_bytes == 30
        assert_sentence(second.value, "the session to %s ended before any of the 1 awaited pattern(s)" % HOST,
                        "20 byte(s) seen")
    finally:
        handle.close()


def test_seen_bytes_add_up_over_a_timeout_and_an_overflow():
    handle = opened(spawn=PtySpawn(two_bursts("A" * 10, "B" * 100, rest=1.5, linger=5.0)), capture_max_bytes=50)
    try:
        handle.expect(["READY"], 10.0)
        with pytest.raises(SessionError) as first:
            handle.expect(["never"], 1.0)
        with pytest.raises(SessionError) as second:
            handle.expect(["never"], 10.0)
        assert first.value.transcript_bytes == 10
        assert second.value.transcript_bytes > 50
        assert handle.seen_bytes == 10 + second.value.transcript_bytes
        assert_sentence(second.value, "the session to %s produced more than 50 bytes" % HOST, "was stopped")
    finally:
        handle.close()


def test_a_quiet_device_times_out_on_time():
    handle = opened(spawn=PtySpawn(QUIET))
    try:
        began = time.monotonic()
        with pytest.raises(SessionError) as caught:
            handle.expect(["never"], 0.6)
        assert time.monotonic() - began < 3.0
        assert_sentence(caught.value, "%s did not answer" % HOST)
    finally:
        handle.close()


def test_send_refuses_something_that_is_not_text_naming_its_type(terminal):
    with pytest.raises(SessionError) as caught:
        terminal.send(5)
    assert_sentence(caught.value, "a session line must be text", "int")
    assert caught.value.transcript_bytes == 0


def test_send_refuses_a_second_line(terminal):
    with pytest.raises(SessionError) as caught:
        terminal.send("show\nreload")
    assert_sentence(caught.value, "a session line must be a single line")


def test_send_never_drops_the_rest_of_a_line_it_could_not_write(pipe_session):
    with pytest.raises(SessionError) as caught:
        pipe_session.send("x" * 200000)
    assert_sentence(caught.value, "cannot write to the session to %s" % HOST, "(BlockingIOError)")


def test_an_interrupt_that_cannot_be_written_is_reported():
    read_end, write_end = os.pipe()
    handle = opened(spawn=lambda call, env: (0, read_end))
    try:
        with pytest.raises(SessionError) as caught:
            handle.interrupt()
        assert_sentence(caught.value, "the terminal interrupt could not be sent")
    finally:
        handle.close()
        os.close(write_end)


def test_an_interrupt_that_is_not_taken_is_reported(terminal, monkeypatch):
    monkeypatch.setattr(session_module, "os", Unsent())
    with pytest.raises(SessionError) as caught:
        terminal.interrupt()
    assert_sentence(caught.value, "the terminal interrupt was not sent")


def test_close_asks_the_client_to_terminate_before_killing_it(tmp_path, monkeypatch):
    monkeypatch.setattr(session_module, "KILL_AFTER_SECONDS", 0.3)
    marker = tmp_path / "terminated"
    script = "\n".join(
        (
            "import os, signal, time",
            "signal.signal(signal.SIGHUP, signal.SIG_IGN)",
            "signal.signal(signal.SIGTERM, lambda *_: (open(%r, 'w').write('TERM'), os._exit(0)))" % str(marker),
            "time.sleep(30)",
        )
    )
    spawn = PtySpawn(script)
    handle = opened(spawn=spawn)
    time.sleep(0.5)
    handle.close()
    assert marker.read_text(encoding="utf-8") == "TERM"


def test_close_kills_and_reaps_a_client_that_ignores_hangup_and_terminate(monkeypatch):
    monkeypatch.setattr(session_module, "KILL_AFTER_SECONDS", 0.3)
    script = "\n".join(
        (
            "import signal, time",
            "signal.signal(signal.SIGHUP, signal.SIG_IGN)",
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)",
            "time.sleep(30)",
        )
    )
    spawn = PtySpawn(script)
    handle = opened(spawn=spawn)
    time.sleep(0.5)
    try:
        handle.close()
        with pytest.raises(ChildProcessError):
            os.waitpid(spawn.pid, os.WNOHANG)
    finally:
        kill_quietly(spawn.pid)


def test_close_sweeps_a_grandchild_the_client_left_behind(tmp_path, monkeypatch):
    monkeypatch.setattr(session_module, "KILL_AFTER_SECONDS", 0.3)
    marker = tmp_path / "grandchild"
    grandchild = "; ".join(
        (
            "import os, signal, time",
            "signal.signal(signal.SIGHUP, signal.SIG_IGN)",
            "open(%r, 'w').write(str(os.getpid()))" % str(marker),
            "time.sleep(30)",
        )
    )
    script = "\n".join(
        (
            "import signal, subprocess, sys, time",
            "signal.signal(signal.SIGHUP, signal.SIG_DFL)",
            "subprocess.Popen([sys.executable, '-I', '-c', %r], stdin=subprocess.DEVNULL,"
            " stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)" % grandchild,
            "time.sleep(30)",
        )
    )
    handle = opened(spawn=PtySpawn(script))
    left = pid_in(marker)
    try:
        handle.close()
        assert ended_within(left, 3.0)
    finally:
        kill_quietly(left)


def test_close_never_signals_a_process_that_is_not_its_child():
    parent = subprocess.Popen(
        ["/bin/sh", "-c", "sleep 30 >/dev/null 2>&1 & echo $!; wait"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
    )
    pid = None
    read_end, write_end = os.pipe()
    try:
        pid = int(parent.stdout.readline().decode().strip())
        handle = opened(spawn=lambda call, env: (pid, write_end))
        handle.close()
        time.sleep(0.2)
        assert not ended_within(pid, 0.2)
        assert parent.poll() is None
    finally:
        if pid is not None:
            kill_quietly(pid)
        parent.kill()
        parent.wait(timeout=5)
        parent.stdout.close()
        os.close(read_end)
