import fcntl
import os
import pty
import select
import signal
import stat
import subprocess
import sys
import tempfile

import pytest

from netops_core import sftp as sftp_module
from netops_core import ssh as ssh_module
from netops_core.session import Session, SessionError
from netops_core.ssh import WORKSPACE_PREFIX, SshError, run_command

HOST = "192.0.2.10"
PORT = 22
LOGIN = "audit-ro"
COMMAND = "show"
REMOTE_PATH = "/"
HOST_KEY_LINE = "%s ssh-ed25519 cmVwbGFjZS1tZS1ob3N0LWtleS1tYXRlcmlhbC1B" % HOST
PASSWORD = "synthetic-password-0001"
ANSWER = b"config system global\nend\n"
READY = b"terminal ready"
TERMINAL = "import sys; print(%r, flush=True); sys.stdin.buffer.read()" % READY.decode()
OWNER_NAME = ".owner"
SECONDS = 30
SOURCE = os.path.dirname(os.path.dirname(os.path.abspath(ssh_module.__file__)))
CHILD_HEAD = """
import os
import pty
import subprocess
import sys

from netops_core import session, sftp, ssh


class Credential:
    kind = "password"
    login = %r

    def use(self):
        return %r


def runner(call, **kwargs):
    print(kwargs["env"]["HOME"], flush=True)
    sys.stdin.read()
    return subprocess.CompletedProcess(call, 0, b"", b"")


def spawn(call, env):
    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.execve(sys.executable, [sys.executable, "-I", "-c", %r], env)
        finally:
            os._exit(127)
    return pid, fd


""" % (LOGIN, PASSWORD, TERMINAL)
CHILD = CHILD_HEAD + "ssh.run_command(%r, %d, %r, Credential(), %r, %r, run=runner)\n" % (
    HOST, PORT, LOGIN, HOST_KEY_LINE, COMMAND,
)
SFTP_CHILD = CHILD_HEAD + "sftp.stat(%r, %d, %r, Credential(), %r, %r, run=runner)\n" % (
    HOST, PORT, LOGIN, HOST_KEY_LINE, REMOTE_PATH,
)
SESSION_CHILD = CHILD_HEAD + (
    "opened = session.Session(%r, %d, %r, Credential(), %r, spawn=spawn)\n"
    "opened.expect([%r], %d)\n"
    "print(opened.workspace(), flush=True)\n"
    "sys.stdin.read()\n"
    "opened.close()\n"
) % (HOST, PORT, LOGIN, HOST_KEY_LINE, READY, SECONDS)


class Credential:
    kind = "password"
    login = LOGIN

    def use(self):
        return PASSWORD


def _answered(call, **kwargs):
    return subprocess.CompletedProcess(call, 0, ANSWER, b"")


def _spawned(call, env):
    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.execve(sys.executable, [sys.executable, "-I", "-c", TERMINAL], env)
        finally:
            os._exit(127)
    return pid, fd


def _failing(call, *args, **kwargs):
    raise OSError("the client cannot be started")


def _call(run=_answered):
    return run_command(HOST, PORT, LOGIN, Credential(), HOST_KEY_LINE, COMMAND, run=run)


def _listed(run=_answered):
    return sftp_module.stat(HOST, PORT, LOGIN, Credential(), HOST_KEY_LINE, REMOTE_PATH, run=run)


def _opened(spawn=_spawned):
    with Session(HOST, PORT, LOGIN, Credential(), HOST_KEY_LINE, spawn=spawn) as opened:
        return opened.workspace()


def _refused_call():
    with pytest.raises(SshError):
        _call(_failing)


def _refused_listing():
    with pytest.raises(SshError):
        _listed(_failing)


def _refused_session():
    with pytest.raises(SessionError):
        _opened(_failing)


def _misanswered_session():
    with pytest.raises(SessionError):
        _opened(lambda call, env: ("not a pid", "not a descriptor"))


def _private_tempdir(tmp_path, monkeypatch):
    directory = tmp_path / "tmp"
    directory.mkdir(mode=0o700)
    monkeypatch.setattr(tempfile, "tempdir", str(directory))
    return str(directory)


def _started(temporary, program=CHILD):
    child = subprocess.Popen(
        [sys.executable, "-B", "-c", program],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONPATH": SOURCE,
            "TMPDIR": temporary,
        },
    )
    line = b""
    if select.select([child.stdout], [], [], SECONDS)[0]:
        line = child.stdout.readline()
    if not line:
        child.kill()
        _, said = child.communicate()
        raise AssertionError("the call never reached its runner: %r" % said[-500:])
    return child, line.decode().strip()


def _finished(child):
    try:
        return child.communicate(timeout=SECONDS)
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate()


def _left(path, mode=0o700, owner=True):
    os.mkdir(path)
    os.chmod(path, mode)
    for name in ("secret", OWNER_NAME) if owner else ("secret",):
        with open(os.path.join(path, name), "wb") as handle:
            handle.write(b"left behind\n")
    return path


def _contents(path):
    return sorted(os.listdir(path)) if os.path.isdir(path) else None


def _locked(workspace):
    try:
        descriptor = os.open(os.path.join(workspace, OWNER_NAME), os.O_RDONLY)
    except FileNotFoundError:
        return None
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return True
    finally:
        os.close(descriptor)
    return False


def _open_descriptors():
    return sorted(os.listdir("/dev/fd"))


def _descriptors(information):
    found = []
    for name in os.listdir("/dev/fd"):
        try:
            opened = os.fstat(int(name))
        except OSError:
            continue
        if (opened.st_dev, opened.st_ino) == (information.st_dev, information.st_ino):
            found.append(int(name))
    return found


def test_a_workspace_left_by_a_killed_call_is_removed_by_the_next_call(tmp_path, monkeypatch):
    temporary = _private_tempdir(tmp_path, monkeypatch)
    child, workspace = _started(temporary)
    child.kill()
    _finished(child)
    secret = os.path.join(workspace, "secret")

    assert child.returncode == -signal.SIGKILL
    with open(secret, "rb") as handle:
        assert handle.read() == ("%s\n" % PASSWORD).encode()
    assert stat.S_IMODE(os.stat(secret).st_mode) == 0o600

    assert _call().stdout == ANSWER
    assert not os.path.exists(workspace)
    assert os.listdir(temporary) == []


def test_the_workspace_of_a_call_that_is_still_running_is_left_alone(tmp_path, monkeypatch):
    temporary = _private_tempdir(tmp_path, monkeypatch)
    child, workspace = _started(temporary)
    try:
        before = _contents(workspace)
        _call()
        after = _contents(workspace)
    finally:
        _, said = _finished(child)

    assert "secret" in before
    assert after == before
    assert child.returncode == 0, said
    assert os.listdir(temporary) == []


def test_only_an_abandoned_directory_of_this_user_is_removed(tmp_path, monkeypatch):
    temporary = _private_tempdir(tmp_path, monkeypatch)
    elsewhere = _left(str(tmp_path / "elsewhere"))
    link = os.path.join(temporary, WORKSPACE_PREFIX + "link")
    os.symlink(elsewhere, link)
    other_mode = _left(os.path.join(temporary, WORKSPACE_PREFIX + "mode"), mode=0o755)
    unowned = _left(os.path.join(temporary, WORKSPACE_PREFIX + "unowned"), owner=False)
    linked_owner = _left(os.path.join(temporary, WORKSPACE_PREFIX + "linked-owner"), owner=False)
    os.symlink(os.path.join(elsewhere, OWNER_NAME), os.path.join(linked_owner, OWNER_NAME))
    abandoned = _left(os.path.join(temporary, WORKSPACE_PREFIX + "abandoned"))
    kept = {path: _contents(path) for path in (elsewhere, link, other_mode, unowned, linked_owner)}

    _call()

    assert not os.path.exists(abandoned)
    assert os.path.islink(link)
    assert {path: _contents(path) for path in kept} == kept


def test_an_ordinary_call_answers_as_before_and_leaves_nothing_behind(tmp_path, monkeypatch):
    temporary = _private_tempdir(tmp_path, monkeypatch)
    seen = {}

    def run(call, **kwargs):
        environment = kwargs["env"]
        seen["home"] = environment["HOME"]
        seen["names"] = set(os.listdir(environment["HOME"]))
        with open(environment["NETOPS_ASKPASS_FILE"], "rb") as handle:
            seen["secret"] = handle.read()
        return _answered(call, **kwargs)

    result = _call(run)

    assert (result.rc, result.stdout, result.said) == (0, ANSWER, "")
    assert os.path.dirname(seen["home"]) == temporary
    assert os.path.basename(seen["home"]).startswith(WORKSPACE_PREFIX)
    assert {"known_hosts", "secret"} <= seen["names"]
    assert seen["secret"] == ("%s\n" % PASSWORD).encode()
    assert os.listdir(temporary) == []


def test_the_owner_file_is_locked_during_the_call_and_not_inherited(tmp_path, monkeypatch):
    _private_tempdir(tmp_path, monkeypatch)
    seen = {}

    def run(call, **kwargs):
        path = os.path.join(kwargs["env"]["HOME"], OWNER_NAME)
        information = os.lstat(path)
        seen["regular"] = stat.S_ISREG(information.st_mode)
        seen["mode"] = stat.S_IMODE(information.st_mode)
        descriptor = os.open(path, os.O_RDONLY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            seen["locked"] = False
        except BlockingIOError:
            seen["locked"] = True
        finally:
            os.close(descriptor)
        seen["inheritable"] = [os.get_inheritable(fd) for fd in _descriptors(information)]
        return _answered(call, **kwargs)

    _call(run)

    assert seen == {"regular": True, "mode": 0o600, "locked": True, "inheritable": [False]}


def test_the_owner_file_takes_its_name_only_once_it_is_locked(tmp_path, monkeypatch):
    temporary = _private_tempdir(tmp_path, monkeypatch)
    named = []
    real = fcntl.flock

    def flock(descriptor, operation):
        if operation == fcntl.LOCK_EX:
            for name in os.listdir(temporary):
                named.append(OWNER_NAME in os.listdir(os.path.join(temporary, name)))
        return real(descriptor, operation)

    monkeypatch.setattr(fcntl, "flock", flock)
    _call()

    assert named == [False]


TRANSPORTS = (
    pytest.param(SFTP_CHILD, _listed, id="sftp"),
    pytest.param(SESSION_CHILD, _opened, id="session"),
)


@pytest.mark.parametrize("program,following", TRANSPORTS)
def test_the_locked_workspace_of_a_running_transport_is_left_alone(
    tmp_path, monkeypatch, program, following
):
    temporary = _private_tempdir(tmp_path, monkeypatch)
    child, workspace = _started(temporary, program)
    try:
        locked = _locked(workspace)
        before = _contents(workspace)
        following()
        after = _contents(workspace)
    finally:
        _, said = _finished(child)

    assert locked is True
    assert "secret" in before
    assert after == before
    assert child.returncode == 0, said
    assert os.listdir(temporary) == []


@pytest.mark.parametrize("program,following", TRANSPORTS)
def test_a_workspace_left_by_a_killed_transport_is_removed_by_its_next_call(
    tmp_path, monkeypatch, program, following
):
    temporary = _private_tempdir(tmp_path, monkeypatch)
    child, workspace = _started(temporary, program)
    child.kill()
    _finished(child)

    assert child.returncode == -signal.SIGKILL
    with open(os.path.join(workspace, "secret"), "rb") as handle:
        assert handle.read() == ("%s\n" % PASSWORD).encode()

    following()
    assert not os.path.exists(workspace)
    assert os.listdir(temporary) == []


@pytest.mark.parametrize(
    "attempt",
    (
        _call, _refused_call, _listed, _refused_listing,
        _opened, _refused_session, _misanswered_session,
    ),
    ids=lambda attempt: attempt.__name__.lstrip("_"),
)
def test_neither_a_workspace_nor_a_descriptor_outlives_a_call(tmp_path, monkeypatch, attempt):
    temporary = _private_tempdir(tmp_path, monkeypatch)
    before = _open_descriptors()
    attempt()

    assert _open_descriptors() == before
    assert os.listdir(temporary) == []
