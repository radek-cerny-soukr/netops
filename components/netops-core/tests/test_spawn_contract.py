import gc
import os
import re
import resource
import select
import shutil
import signal
import subprocess
import sys
import threading
import time
import warnings

import pytest

from netops_core import session


def no_fork(*args):
    pytest.fail("this process forked")


class Recorded:
    """Stands in for the client process: records how it was started and reports nothing."""

    started = []

    def __init__(self, args, **options):
        self.args = args
        self.options = options
        self.pid = 73
        Recorded.started.append(self)


def test_spawn_starts_the_fixed_launcher_on_the_terminal_in_a_new_session(monkeypatch):
    Recorded.started = []
    monkeypatch.setattr(session, "_Client", Recorded)
    call = ["owned-program", "arg"]
    env = {"OWNED": "value", b"PATH": b"/owned", "LC_CTYPE": "C"}
    pid, fd = session._spawn(call, env)
    try:
        assert pid == 73
        assert os.isatty(fd)
        (started,) = Recorded.started
        assert started.args == [sys.executable, "-I", "-S", "-B", "-c", session.LAUNCHER, "owned-program", "arg"]
        options = dict(started.options)
        terminal = options.pop("stdin")
        assert options.pop("stdout") == options.pop("stderr") == terminal
        (written,) = options.pop("pass_fds")
        environment = options.pop("env")
        assert options == {"close_fds": True, "start_new_session": True}
        assert environment == {
            b"OWNED": b"value", b"PATH": b"/owned", b"LC_CTYPE": b"C",
            session.LAUNCHER_VARIABLE: b"%d=C" % written,
        }
        for closed in (terminal, written):
            with pytest.raises(OSError):
                os.fstat(closed)
    finally:
        os.close(fd)


def test_spawn_tells_the_launcher_that_lc_ctype_was_not_set(monkeypatch):
    Recorded.started = []
    monkeypatch.setattr(session, "_Client", Recorded)
    pid, fd = session._spawn(["owned-program"], {"PATH": "/owned"})
    os.close(fd)
    (started,) = Recorded.started
    (written,) = started.options["pass_fds"]
    assert started.options["env"] == {b"PATH": b"/owned", session.LAUNCHER_VARIABLE: b"%d" % written}


def test_spawn_refuses_an_empty_call_before_opening_a_pty(monkeypatch):
    monkeypatch.setattr(session.os, "openpty", lambda: pytest.fail("opened a pty"))
    with pytest.raises(ValueError):
        session._spawn([], {})


def test_spawn_propagates_pty_error_without_starting_a_program(monkeypatch):
    failure = OSError("pty unavailable")

    def openpty():
        raise failure

    monkeypatch.setattr(session.os, "openpty", openpty)
    monkeypatch.setattr(session, "_Client", lambda *args, **options: pytest.fail("started after pty error"))
    with pytest.raises(OSError) as refused:
        session._spawn(["owned-program"], {})
    assert refused.value is failure


def open_descriptors():
    return sorted(os.listdir("/proc/self/fd")) if os.path.isdir("/proc/self/fd") else None


def test_spawn_closes_every_descriptor_when_the_launcher_cannot_start(monkeypatch):
    failure = FileNotFoundError("synthetic missing interpreter")

    def client(*args, **options):
        raise failure

    monkeypatch.setattr(session, "_Client", client)
    before = open_descriptors()
    with pytest.raises(OSError) as refused:
        session._spawn(["owned-program"], {})
    assert refused.value is failure
    assert open_descriptors() == before


@pytest.fixture
def launched(monkeypatch):
    """The process ids of the launchers that _spawn starts."""
    pids = []
    class Launched(session._Client):
        def __init__(self, *args, **options):
            super().__init__(*args, **options)
            pids.append(self.pid)
    monkeypatch.setattr(session, "_Client", Launched)
    return pids


def assert_reaped(pids):
    assert pids
    for pid in pids:
        with pytest.raises(ChildProcessError):
            os.waitpid(pid, os.WNOHANG)


@pytest.mark.parametrize("program,env", [
    ("owned-program-missing", {"PATH": "/nonexistent-first:/nonexistent-last"}),
    (b"owned-program-missing", {b"PATH": b"/nonexistent-first:/nonexistent-last"}),
    ("owned-program-missing", {"PATH": ""}),
    ("/nonexistent/owned-program", {"PATH": "/ignored"}),
])
def test_a_program_that_is_not_found_is_the_same_error_and_leaves_nothing(launched, program, env):
    before = open_descriptors()
    with pytest.raises(FileNotFoundError) as refused:
        session._spawn([program, "arg"], env)
    assert os.path.basename(refused.value.filename) == os.path.basename(os.fsdecode(program))
    assert open_descriptors() == before
    assert_reaped(launched)


def test_a_program_that_is_not_executable_is_a_permission_error(launched, tmp_path):
    program = tmp_path / "owned-program"
    program.write_text("#!/bin/sh\n", encoding="utf-8")
    program.chmod(0o644)
    with pytest.raises(PermissionError) as refused:
        session._spawn(["owned-program"], {"PATH": str(tmp_path)})
    assert refused.value.filename == str(program)
    assert_reaped(launched)


@pytest.mark.parametrize("report,kind,number,name", [
    (b"2=/owned/program", FileNotFoundError, 2, "/owned/program"),
    (b"13=relative/\xff", PermissionError, 13, os.fsdecode(b"relative/\xff")),
    (b"1=", PermissionError, 1, None),
])
def test_the_launcher_report_becomes_the_os_error(report, kind, number, name):
    error = session._launch_error(report)
    assert type(error) is kind
    assert (error.errno, error.strerror, error.filename) == (number, os.strerror(number), name)


def run_on_terminal(call, typed=b"", seconds=10, spawn=session._spawn, env=None):
    """Start call on a real pty, type into it and return its output and exit code.

    One deadline bounds reading up to the end of the terminal and waiting for the child. On every
    path the master is closed, whatever is left of the child's process group is killed while the
    finished leader still holds the group id, and the leader is reaped. Reaching the deadline
    before the leader exited or before the terminal ended fails.
    """
    pid, fd = spawn(call, {"PATH": os.defpath} if env is None else env)
    exited = ended = False
    try:
        deadline = time.monotonic() + seconds
        os.write(fd, typed)
        output = b""
        while time.monotonic() < deadline:
            if select.select([fd], [], [], 0.2)[0]:
                try:
                    chunk = os.read(fd, 4096)
                except OSError:
                    chunk = b""
                if not chunk:
                    ended = True
                    break
                output += chunk
        while True:
            exited = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
            if exited or time.monotonic() >= deadline:
                break
            time.sleep(0.05)
    finally:
        os.close(fd)
        try:
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        _, status = os.waitpid(pid, 0)
    assert exited, "the child was still running after %s s: %r" % (seconds, output)
    assert ended, "the terminal stayed open after %s s: %r" % (seconds, output)
    return output, os.waitstatus_to_exitcode(status)


CHILD = "\n".join((
    "import os, sys",
    "terminal = os.open('/dev/tty', os.O_RDWR)",
    "os.close(terminal)",
    "same = os.ttyname(0) == os.ttyname(1) == os.ttyname(2)",
    "print('LEADER', os.getsid(0) == os.getpid() == os.getpgid(0), 'FOREGROUND', os.tcgetpgrp(0) == os.getpid(),"
    " 'TERMINALS', all(os.isatty(n) for n in range(3)) and same)",
    "sys.stdout.flush()",
    "print('READ', input(), 'END')",
))


def test_the_client_leads_a_session_on_its_controlling_terminal_without_a_fork_or_a_warning(monkeypatch):
    for name in ("fork", "forkpty", "execve", "execv", "execvpe"):
        monkeypatch.setattr(session.os, name, no_fork)
    warned = []
    def spawn_beside_a_thread(call, env):
        stop = threading.Event()
        worker = threading.Thread(target=stop.wait)
        worker.start()
        try:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                started = session._spawn(call, env)
                gc.collect()
        finally:
            stop.set()
            worker.join()
        warned.extend("%s: %s" % (warning.category.__name__, warning.message) for warning in caught)
        return started
    output, code = run_on_terminal([sys.executable, "-I", "-c", CHILD], b"typed line\n", spawn=spawn_beside_a_thread)
    assert warned == []
    assert b"LEADER True FOREGROUND True TERMINALS True" in output, output
    assert b"READ typed line END" in output, output
    assert code == 0


def test_a_shell_reads_a_line_from_its_terminal():
    output, code = run_on_terminal(["sh", "-c", "read x; echo \"got $x\""], b"hello\n")
    assert b"got hello" in output, output
    assert code == 0


def test_the_client_gets_exactly_the_given_environment():
    program = shutil.which("env", path=os.defpath)
    assert program, "env not found on %s" % os.defpath
    for env in ({"PATH": os.defpath, "OWNED": "value"}, {"PATH": os.defpath, "LC_CTYPE": "C"}, {}):
        output, code = run_on_terminal([program], env=env)
        assert code == 0, output
        lines = sorted(line for line in output.decode().splitlines() if line)
        assert lines == sorted("%s=%s" % item for item in env.items()), output


def test_the_program_is_searched_only_on_the_path_of_the_client_environment(tmp_path, monkeypatch):
    owned = tmp_path / "owned"
    owned.mkdir()
    program = owned / "owned-program"
    program.write_text("#!/bin/sh\necho \"owned $0 $1\"\n", encoding="utf-8")
    program.chmod(0o755)
    monkeypatch.setenv("PATH", "/parent-path-must-not-be-used")
    output, code = run_on_terminal(["owned-program", "arg"], env={"PATH": "/nonexistent:%s" % owned})
    assert code == 0, output
    assert ("owned %s arg" % program).encode() in output, output


def test_spawned_clients_leave_no_resource_warning():
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        output, code = run_on_terminal(["true"])
        gc.collect()
    assert code == 0, output
    assert [str(warning.message) for warning in caught] == []


def test_run_on_terminal_stops_waiting_at_the_deadline_and_reaps_the_child():
    started = []
    def spawn(call, env):
        started.append(session._spawn(call, env))
        return started[-1]
    begun = time.monotonic()
    with pytest.raises(AssertionError, match="still running"):
        run_on_terminal(["/bin/sh", "-c", "exec sleep 30"], seconds=1, spawn=spawn)
    assert time.monotonic() - begun < 10
    pid, fd = started[0]
    with pytest.raises(ChildProcessError):
        os.waitpid(pid, os.WNOHANG)
    with pytest.raises(OSError):
        os.fstat(fd)


LEADER = "\n".join((
    "import subprocess, sys",
    "holds = sys.argv[1] == 'holds'",
    "child = subprocess.Popen([sys.executable, '-I', '-c', 'import signal, time;"
    " signal.signal(signal.SIGHUP, signal.SIG_IGN); print(\"ready\", flush=True); time.sleep(30)'],"
    " stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=None if holds else subprocess.DEVNULL)",
    "assert child.stdout.readline() == b'ready\\n'",
    "print('GRANDCHILD', child.pid, flush=True)",
))


def running(pid):
    try:
        with open("/proc/%d/stat" % pid, "rb") as status:
            return status.read().rsplit(b")", 1)[1].split()[0] != b"Z"
    except FileNotFoundError:
        return False
    except OSError:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        return True


def assert_stopped(pid):
    deadline = time.monotonic() + 10
    while running(pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not running(pid), "process %d of the group is still running" % pid


def test_run_on_terminal_kills_the_rest_of_the_group_after_the_leader_exited():
    output, code = run_on_terminal([sys.executable, "-I", "-c", LEADER, "leaves"], seconds=10)
    assert code == 0, output
    grandchild = int(re.search(rb"GRANDCHILD (\d+)", output).group(1))
    assert_stopped(grandchild)


def test_run_on_terminal_fails_when_the_terminal_outlives_the_leader_and_kills_the_group():
    with pytest.raises(AssertionError, match="terminal stayed open") as failed:
        run_on_terminal([sys.executable, "-I", "-c", LEADER, "holds"], seconds=5)
    grandchild = int(re.search(r"GRANDCHILD (\d+)", str(failed.value)).group(1))
    assert_stopped(grandchild)


DESCRIPTORS = "\n".join((
    "import os, sys",
    "for number in map(int, sys.argv[1:]):",
    "    try:",
    "        os.fstat(number)",
    "    except OSError:",
    "        held = False",
    "    else:",
    "        held = True",
    "    print('FD', number, 'PROC', os.path.exists('/proc/self/fd/%d' % number), 'HELD', held)",
))


def inheritable(read_end, numbers):
    for number in numbers:
        with pytest.raises(OSError):
            os.fstat(number)
        os.dup2(read_end, number, inheritable=True)
        assert os.get_inheritable(number)


@pytest.fixture
def pipe():
    read_end, write_end = os.pipe()
    numbers = []
    try:
        yield read_end, numbers
    finally:
        for number in numbers + [read_end, write_end]:
            try:
                os.close(number)
            except OSError:
                pass


def assert_not_inherited(numbers):
    output, code = run_on_terminal([sys.executable, "-I", "-c", DESCRIPTORS] + [str(number) for number in numbers])
    assert code == 0, output
    for number in numbers:
        assert ("FD %d PROC False HELD False" % number).encode() in output, output


def test_the_client_gets_no_other_descriptor_of_this_process(pipe):
    read_end, numbers = pipe
    numbers.extend((211, 213))
    inheritable(read_end, numbers)
    assert_not_inherited(numbers)


def test_a_descriptor_above_the_soft_limit_does_not_reach_the_client(pipe):
    read_end, numbers = pipe
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    number = 1024
    assert hard == resource.RLIM_INFINITY or hard > number, (soft, hard)
    try:
        if soft <= number:
            resource.setrlimit(resource.RLIMIT_NOFILE, (number + 1, hard))
        numbers.append(number)
        inheritable(read_end, numbers)
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, hard))
        assert os.sysconf("SC_OPEN_MAX") == 256
        assert_not_inherited(numbers)
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))


def test_a_descriptor_made_while_the_client_starts_does_not_reach_it(monkeypatch, pipe):
    read_end, numbers = pipe
    numbers.extend((311, 313))
    original = subprocess.Popen.__init__
    def made_just_before_the_fork(self, *args, **options):
        inheritable(read_end, numbers)
        original(self, *args, **options)
    monkeypatch.setattr(session._Client, "__init__", made_just_before_the_fork)
    assert_not_inherited(numbers)
    assert all(os.get_inheritable(number) for number in numbers)


def test_the_descriptor_probe_sees_a_descriptor_that_is_not_closed(monkeypatch, pipe):
    read_end, numbers = pipe
    numbers.extend((211, 213))
    inheritable(read_end, numbers)
    original = subprocess.Popen.__init__
    def passing(self, *args, pass_fds=(), **options):
        original(self, *args, pass_fds=tuple(pass_fds) + tuple(numbers), **options)
    monkeypatch.setattr(session._Client, "__init__", passing)
    output, code = run_on_terminal([sys.executable, "-I", "-c", DESCRIPTORS] + [str(number) for number in numbers])
    assert code == 0, output
    proc = "True" if os.path.isdir("/proc/self/fd") else "False"
    for number in numbers:
        assert ("FD %d PROC %s HELD True" % (number, proc)).encode() in output, output
