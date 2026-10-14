import io
import os
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from netops_helper import proxy


def _cli(monkeypatch, tmp_path, failure):
    stopped = []
    monkeypatch.setattr(proxy.sys, "argv", ["netops-helper-proxy"])
    monkeypatch.setattr(proxy.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(b"request\n")))
    monkeypatch.setattr(proxy.legacy_configuration, "legacy_configuration_detail", lambda path: None)
    monkeypatch.setattr(proxy.Proxy, "_load_runner", lambda self: {"credential": "owned", "host": "runner.example.invalid", "port": 22, "host_key_fingerprint": "owned-pin"})
    monkeypatch.setattr(proxy.Proxy, "_vault", lambda self, names: {})
    monkeypatch.setattr(proxy.Proxy, "_credential", lambda self, vault, name: SimpleNamespace(kind="ssh-key"))
    monkeypatch.setattr(proxy.Proxy, "_session_secrets", lambda *args: ())
    monkeypatch.setattr(proxy, "_private_directory", lambda: str(tmp_path / "owned"))
    monkeypatch.setattr(proxy.hostkey, "scan", lambda *args: "owned-key")
    monkeypatch.setattr(proxy.hostkey, "known_hosts_file", lambda *args: "owned-known-hosts")

    class Controller:
        def __init__(self, *args):
            pass

        def start(self):
            return True

        def forward(self, line):
            raise failure

        def stop(self):
            stopped.append(True)
            return 0

    monkeypatch.setattr(proxy, "_SessionController", Controller)
    return stopped


def test_closed_cli_output_quiets_final_flush_and_stops(monkeypatch, tmp_path):
    stopped = _cli(monkeypatch, tmp_path, BrokenPipeError())
    redirected = []
    monkeypatch.setattr(proxy.os, "open", lambda path, flags: redirected.append((path, flags)) or 91)
    monkeypatch.setattr(proxy.os, "dup2", lambda source, target: redirected.append((source, target)))
    monkeypatch.setattr(proxy.os, "close", lambda fd: redirected.append(("close", fd)))
    monkeypatch.setattr(proxy.sys, "stdout", SimpleNamespace(fileno=lambda: 92))
    assert proxy.main() == 0
    assert stopped == [True]
    assert redirected == [(proxy.os.devnull, proxy.os.O_WRONLY), (91, 92), ("close", 91)]


def test_other_output_errors_remain_visible(monkeypatch, tmp_path):
    failure = OSError("owned output error")
    _cli(monkeypatch, tmp_path, failure)
    with pytest.raises(OSError) as refused:
        proxy.main()
    assert refused.value is failure


def test_cli_shutdown_with_closed_owned_pipe_has_no_traceback(tmp_path):
    script = "\n".join((
        "import io, runpy, sys, pytest",
        "from pathlib import Path",
        "helpers = runpy.run_path(sys.argv[1])",
        "helpers['_cli'](pytest.MonkeyPatch(), Path(sys.argv[2]), BrokenPipeError())",
        "sys.stdout = io.TextIOWrapper(io.BufferedWriter(io.FileIO(1, 'w', closefd=False)))",
        "sys.stdout.write('buffered output')",
        "raise SystemExit(helpers['proxy'].main())",
    ))
    child = subprocess.Popen(
        [sys.executable, "-B", "-c", script, str(Path(__file__).resolve()), str(tmp_path)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={**os.environ, "PYTHONPATH": os.pathsep.join((
            str(Path(__file__).resolve().parents[1] / "src"),
            str(Path(__file__).resolve().parents[2] / "netops-core" / "src"),
        ))},
    )
    child.stdout.close()
    try:
        code = child.wait(timeout=10)
        error = child.stderr.read()
        assert (code, error) == (0, b"")
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        child.stderr.close()


@pytest.mark.parametrize("phase", ["write", "flush"])
def test_background_response_writer_quiets_closed_output(monkeypatch, phase):
    stopped = []
    errors = []
    instance = proxy.Proxy()
    monkeypatch.setattr(instance, "response", lambda line, epoch: b"response\n")
    monkeypatch.setattr(proxy, "_quiet_closed_stdout", lambda: stopped.append(True), raising=False)
    monkeypatch.setattr(threading, "excepthook", lambda args: errors.append(args.exc_value))

    class ClosedOutput:
        def write(self, data):
            if phase == "write":
                raise BrokenPipeError()

        def flush(self):
            if phase == "flush":
                raise BrokenPipeError()

    monkeypatch.setattr(proxy.sys, "stdout", SimpleNamespace(buffer=ClosedOutput()))
    connection = object.__new__(proxy._ServerConnection)
    connection.proxy = instance
    connection.epoch = instance.open_session()
    connection.child = SimpleNamespace(stdout=io.BytesIO(b"response\n"))
    worker = threading.Thread(target=connection._responses)
    worker.start()
    worker.join(timeout=2)
    assert not worker.is_alive()
    assert errors == []
    assert stopped == [True]
    assert not instance.accepting(connection.epoch)
    assert instance.session_reason == "transport_closed"


def test_background_writer_does_not_swallow_other_output_errors(monkeypatch):
    failure = OSError("owned output error")
    instance = proxy.Proxy()
    monkeypatch.setattr(instance, "response", lambda line, epoch: b"response\n")

    class FailedOutput:
        def write(self, data):
            raise failure

    monkeypatch.setattr(proxy.sys, "stdout", SimpleNamespace(buffer=FailedOutput()))
    connection = object.__new__(proxy._ServerConnection)
    connection.proxy = instance
    connection.epoch = instance.open_session()
    connection.child = SimpleNamespace(stdout=io.BytesIO(b"response\n"))
    with pytest.raises(OSError) as refused:
        connection._responses()
    assert refused.value is failure
