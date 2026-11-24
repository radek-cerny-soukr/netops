"""Exercise pinned SSH and SFTP through local clients and failing OS calls."""

import errno
import os
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace

import pytest

from netops_core import sftp, ssh
from test_ssh import HOST, HOST_KEY_LINE, LOGIN, PORT, key_credential


AUTH_FAILURE = b"Permission denied (publickey).\n"
SUCCESS = b"FortiGate-60F # \n"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    marker = tmp_path / "client-pid"

    def install(name, behavior):
        executable = tmp_path / name
        executable.write_text(
            f"#!{sys.executable}\n"
            "import os, sys, time\n"
            "from pathlib import Path\n"
            "assert 'StrictHostKeyChecking=yes' in sys.argv\n"
            f"Path({str(marker)!r}).write_text(str(os.getpid()))\n"
            + behavior
        )
        executable.chmod(0o700)
        return marker

    return install


def _run_ssh(**kwargs):
    return ssh.run_command(HOST, PORT, LOGIN, key_credential(), HOST_KEY_LINE, "show", **kwargs)


def _reaped_pid(marker):
    pid = int(marker.read_text())
    with pytest.raises(ChildProcessError):
        os.waitpid(pid, os.WNOHANG)
    return pid


def test_ssh_returns_the_answer_if_process_group_lookup_fails(client, monkeypatch):
    marker = client("ssh", f"os.write(1, {SUCCESS!r})\n")
    failed = []

    def disappeared(pid):
        failed.append(pid)
        raise ProcessLookupError(errno.ESRCH, "private-CANARY")

    with monkeypatch.context() as fault:
        fault.setattr(os, "getpgid", disappeared)
        result = _run_ssh()

    assert result.rc == 0 and result.stdout == SUCCESS and result.said == ""
    assert failed == [_reaped_pid(marker)]
    assert list(marker.parent.glob(f"{ssh.WORKSPACE_PREFIX}*")) == []


def test_ssh_cleanup_reaps_client_if_direct_signalling_fails(client, monkeypatch):
    marker = client("ssh", "os.write(1, b'private-CANARY\\n')\ntime.sleep(30)\n")
    signalled = []
    send_signal = subprocess.Popen.send_signal

    def unavailable(proc, number):
        if marker.exists() and proc.pid == int(marker.read_text()):
            signalled.append(number)
            if number == signal.SIGTERM:
                raise OSError(errno.ESRCH, "private-CANARY")
        return send_signal(proc, number)

    def stop(chunk):
        raise ssh.OutputLimitError()

    with monkeypatch.context() as fault:
        fault.setattr(subprocess.Popen, "send_signal", unavailable)
        with pytest.raises(ssh.OutputLimitError) as error:
            _run_ssh(stdout_consumer=stop, timeout_seconds=5)

    assert "CANARY" not in str(error.value) and not error.value.said and not error.value.final
    assert signalled == [signal.SIGTERM, signal.SIGKILL]
    _reaped_pid(marker)
    assert list(marker.parent.glob(f"{ssh.WORKSPACE_PREFIX}*")) == []


def test_ssh_drains_the_client_without_a_pidfd(client, monkeypatch):
    marker = client("ssh", f"os.write(1, {SUCCESS!r})\n")
    failed = []

    def unsupported(pid):
        failed.append(pid)
        raise OSError(errno.ENOSYS, "private-CANARY")

    with monkeypatch.context() as fault:
        fault.setattr(ssh, "os", SimpleNamespace(**(vars(os) | {"pidfd_open": unsupported})))
        result = _run_ssh()

    assert result.rc == 0 and result.stdout == SUCCESS and result.said == ""
    assert failed == [_reaped_pid(marker)]
    assert list(marker.parent.glob(f"{ssh.WORKSPACE_PREFIX}*")) == []


@pytest.mark.parametrize("roots", [None, ("/safe",) * 16384], ids=["buffered-flush", "direct-write"])
def test_sftp_preserves_auth_error_when_client_closes_batch_stdin(client, monkeypatch, roots):
    marker = client("sftp", f"os.close(0)\nos.write(2, {AUTH_FAILURE!r})\nsys.exit(255)\n")
    popen = subprocess.Popen
    launched = []

    def wait_for_client_to_close_stdin(argv, **kwargs):
        proc = popen(argv, **kwargs)
        launched.append(proc)
        proc.wait(timeout=5)
        return proc

    with monkeypatch.context() as fault:
        fault.setattr(subprocess, "Popen", wait_for_client_to_close_stdin)
        with pytest.raises(sftp.SftpError) as error:
            sftp.stat(HOST, PORT, LOGIN, key_credential(), HOST_KEY_LINE, "/safe/log", roots=roots)

    assert len(launched) == 1 and launched[0].stdin.closed
    assert launched[0].pid == _reaped_pid(marker)
    assert error.value.rc == 255 and error.value.final == AUTH_FAILURE.decode().strip()
    assert "the device refused the credential" in str(error.value)
    assert "CANARY" not in str(error.value)
    assert list(marker.parent.glob(f"{sftp.WORKSPACE_PREFIX}*")) == []


def test_ssh_runs_and_cleans_up_when_the_temporary_root_cannot_be_listed(client, monkeypatch):
    marker = client("ssh", f"os.write(1, {SUCCESS!r})\n")
    listdir = os.listdir
    failed = []

    def unavailable(path):
        if path == str(marker.parent) and not failed:
            failed.append(path)
            raise OSError(errno.EACCES, "private-CANARY")
        return listdir(path)

    with monkeypatch.context() as fault:
        fault.setattr(os, "listdir", unavailable)
        result = _run_ssh()

    assert failed == [str(marker.parent)]
    assert result.rc == 0 and result.stdout == SUCCESS and result.said == ""
    _reaped_pid(marker)
    assert list(marker.parent.glob(f"{ssh.WORKSPACE_PREFIX}*")) == []


def test_ssh_preserves_stderr_auth_error_if_client_log_is_missing(client):
    marker = client(
        "ssh",
        "assert '-E' in sys.argv and not Path(sys.argv[sys.argv.index('-E') + 1]).exists()\n"
        f"os.write(1, b'private-CANARY\\n')\nos.write(2, {AUTH_FAILURE!r})\nsys.exit(255)\n",
    )

    with pytest.raises(ssh.SshError) as error:
        _run_ssh(separate_client_log=True)

    assert error.value.rc == 255 and error.value.final == AUTH_FAILURE.decode().strip()
    assert error.value.said == AUTH_FAILURE.decode().strip()
    assert "the device refused the credential" in str(error.value)
    assert "CANARY" not in str(error.value)
    _reaped_pid(marker)
    assert list(marker.parent.glob(f"{ssh.WORKSPACE_PREFIX}*")) == []
