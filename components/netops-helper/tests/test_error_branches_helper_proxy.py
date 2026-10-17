"""Error branches of the proxy, each entered by a real failure.

Every test makes the operating system, a socket or a file fail the way it can
fail in production (an unsearchable directory, a /proc file that cannot be
read, a closed pipe, an address that is already bound, a descriptor that is
gone, a removed working directory, a missing ssh binary) and checks what the
proxy does afterwards: the category the client or the operator sees, that
nothing reaches the server, that no secret leaks and that the session state
stays consistent.
"""

from __future__ import annotations

from base64 import b64encode
import errno
import json
import os
from pathlib import Path
import socket
import stat
import sys
import threading

import pytest

from netops_helper import proxy as MODULE
from test_mutation_helper_proxy_messages import _call, _enroll, _proxy

Proxy = MODULE.Proxy
LINUX = sys.platform.startswith("linux")
RUNNER_HOST_KEY = b64encode(b"error-branch-runner-host-key").decode("ascii")
TCP_CALL = ("tcp_probe", {"target": "device-a", "port": 443})
SECRETS = ("selected-secret", "runner-secret", "separate-community")


def _refused(proxy: Proxy, emitted: list, request_id, category: str) -> None:
    assert proxy.request(_call(request_id, *TCP_CALL)) is None
    assert len(emitted) == 1
    answer = emitted[0]
    assert answer["id"] == request_id
    assert answer["error"]["data"] == {"category": category}
    assert request_id not in proxy.pending and request_id not in proxy.response_secrets
    assert not any(secret in json.dumps(answer) for secret in SECRETS)


def _open_descriptors() -> set[str]:
    return set(os.listdir("/proc/self/fd"))


@pytest.mark.skipif(os.geteuid() == 0, reason="root searches a directory without the x bit")
def test_a_vault_behind_an_unsearchable_directory_is_a_permission_refusal(tmp_path, monkeypatch) -> None:
    _enroll(tmp_path, monkeypatch)
    locked = tmp_path / "locked"
    locked.mkdir()
    vault = locked / "vault.json"
    vault.write_bytes(MODULE.VAULT.read_bytes())
    vault.chmod(0o600)
    monkeypatch.setattr(MODULE, "VAULT", vault)
    proxy, emitted = _proxy(monkeypatch)
    locked.chmod(0o600)
    try:
        with pytest.raises(PermissionError):
            vault.lstat()
        _refused(proxy, emitted, 71, MODULE.VaultPermissionError.category)
    finally:
        locked.chmod(0o700)
    emitted.clear()
    assert json.loads(proxy.request(_call(72, *TCP_CALL)))["id"] == 72


def _foreign_owner_only_file() -> Path:
    for candidate in (Path("/opt/netops-test-fixtures/owner-only"), Path("/proc/1/mem")):
        try:
            information = candidate.lstat()
        except OSError:
            continue
        if (stat.S_ISREG(information.st_mode) and stat.S_IMODE(information.st_mode) == 0o600
                and information.st_uid != os.geteuid() and not os.access(candidate, os.R_OK)):
            return candidate
    raise AssertionError("The test environment must provide a stat-able foreign-owned 0600 file")


def test_a_vault_that_can_be_examined_but_not_read_is_a_permission_refusal(tmp_path, monkeypatch) -> None:
    _enroll(tmp_path, monkeypatch)
    monkeypatch.setattr(MODULE, "VAULT", _foreign_owner_only_file())
    proxy, emitted = _proxy(monkeypatch)
    _refused(proxy, emitted, 73, MODULE.VaultPermissionError.category)


def _unreadable_own_file() -> Path | None:
    candidate = Path("/proc/self/mem")
    try:
        information = candidate.lstat()
    except OSError:
        return None
    if not stat.S_ISREG(information.st_mode) or stat.S_IMODE(information.st_mode) not in MODULE.VAULT_MODES:
        return None
    try:
        candidate.read_bytes()
    except PermissionError:
        return None
    except OSError:
        return candidate
    return None


@pytest.mark.skipif(_unreadable_own_file() is None, reason="needs an own 0600 file whose read fails")
def test_a_vault_whose_read_fails_is_missing_authentication_material(tmp_path, monkeypatch) -> None:
    _enroll(tmp_path, monkeypatch)
    monkeypatch.setattr(MODULE, "VAULT", _unreadable_own_file())
    proxy, emitted = _proxy(monkeypatch)
    _refused(proxy, emitted, 74, MODULE.AuthenticationMaterialError.category)


def _runner_file(tmp_path: Path, monkeypatch) -> None:
    _enroll(tmp_path, monkeypatch)
    MODULE.RUNNER.write_text(json.dumps({
        "version": 1, "host": "runner.example.invalid", "port": 22,
        "credential": "runner-account",
        "host_key_fingerprint": MODULE.hostkey.fingerprint_of(RUNNER_HOST_KEY),
    }))


def _main(monkeypatch, capsys) -> tuple[int, str, str]:
    monkeypatch.setattr(sys, "argv", ["netops-helper-proxy"])
    code = MODULE.main()
    captured = capsys.readouterr()
    return code, captured.out, captured.err


@pytest.mark.skipif(_unreadable_own_file() is None, reason="needs an own 0600 file whose read fails")
def test_the_proxy_does_not_start_when_its_vault_read_fails(tmp_path, monkeypatch, capsys) -> None:
    _runner_file(tmp_path, monkeypatch)
    monkeypatch.setattr(MODULE, "VAULT", _unreadable_own_file())
    code, out, err = _main(monkeypatch, capsys)
    assert (code, out) == (2, "")
    assert err == "netops_proxy_transport category=auth_material message=%s\n" % (
        MODULE.AuthenticationMaterialError.public_message
    )


def _fake_keyscan(tmp_path: Path, monkeypatch) -> Path:
    binaries = tmp_path / "bin"
    binaries.mkdir()
    keyscan = binaries / "ssh-keyscan"
    keyscan.write_text(
        "#!%s\nimport sys\nsys.stdout.write('%%s ssh-ed25519 %s\\n' %% sys.argv[-1])\n"
        % (sys.executable, RUNNER_HOST_KEY),
        encoding="utf-8",
    )
    keyscan.chmod(0o755)
    monkeypatch.setenv("PATH", str(binaries))
    return binaries


@pytest.mark.skipif(not LINUX, reason="abstract UNIX socket names")
def test_an_askpass_socket_name_already_in_use_is_closed_and_refused(monkeypatch) -> None:
    taken = "f" * 32
    occupant = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    occupant.bind("\0netops-helper-askpass-" + taken)
    monkeypatch.setattr(MODULE.secrets_module, "token_hex", lambda size: taken)
    before = _open_descriptors()
    try:
        with pytest.raises(OSError) as refused:
            MODULE._AskpassHandoff("askpass-secret")
        assert refused.value.errno == errno.EADDRINUSE
        assert _open_descriptors() == before
    finally:
        occupant.close()


@pytest.mark.skipif(not LINUX, reason="abstract UNIX socket names")
def test_the_proxy_stops_when_the_askpass_socket_cannot_be_bound(tmp_path, monkeypatch, capsys) -> None:
    _runner_file(tmp_path, monkeypatch)
    _fake_keyscan(tmp_path, monkeypatch)
    taken = "e" * 32
    occupant = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    occupant.bind("\0netops-helper-askpass-" + taken)
    monkeypatch.setattr(MODULE.secrets_module, "token_hex", lambda size: taken)
    monkeypatch.setattr(MODULE.tempfile, "tempdir", str(tmp_path))
    try:
        code, out, err = _main(monkeypatch, capsys)
    finally:
        occupant.close()
    assert (code, out) == (2, "")
    assert err == "netops_proxy_transport category=auth_material message=%s\n" % (
        MODULE.AuthenticationMaterialError.public_message
    )
    assert not list(tmp_path.glob("netops-helper-proxy-*"))


def test_the_proxy_stops_when_the_ssh_binary_cannot_be_started(tmp_path, monkeypatch, capsys) -> None:
    _runner_file(tmp_path, monkeypatch)
    binaries = _fake_keyscan(tmp_path, monkeypatch)
    assert not (binaries / "ssh").exists()
    monkeypatch.setattr(MODULE.tempfile, "tempdir", str(tmp_path))
    before = _open_descriptors()
    code, out, err = _main(monkeypatch, capsys)
    assert (code, out) == (2, "")
    assert err == "netops_proxy_transport category=ssh_transport message=The local SSH process could not start.\n"
    assert "runner-secret" not in err
    assert not list(tmp_path.glob("netops-helper-proxy-*"))
    assert _open_descriptors() == before


@pytest.mark.skipif(not LINUX, reason="abstract UNIX socket names")
def test_a_listener_that_fails_while_serving_closes_the_handoff(monkeypatch) -> None:
    failures: list = []
    monkeypatch.setattr(threading, "excepthook", failures.append)
    child = MODULE.subprocess.Popen(["sleep", "30"])
    handoff = MODULE._AskpassHandoff("askpass-secret")
    try:
        os.close(handoff._listener.detach())
        handoff.serve(child)
        assert handoff._closed.wait(5)
        monkeypatch.setenv(MODULE.ASKPASS_SOCKET_ENV, handoff.name)
        assert MODULE._run_askpass() == 1
    finally:
        child.kill()
        child.wait()
    assert handoff._secret == ""
    for _ in range(100):
        if failures:
            break
        threading.Event().wait(0.05)
    assert [type(item.exc_value) for item in failures] == [OSError]
    assert failures[0].exc_value.errno == errno.EBADF


def test_the_askpass_entry_falls_back_to_the_proxy_file_without_a_working_directory(
    tmp_path, monkeypatch,
) -> None:
    gone = tmp_path / "gone"
    gone.mkdir()
    monkeypatch.chdir(gone)
    gone.rmdir()
    with pytest.raises(FileNotFoundError):
        os.getcwd()
    monkeypatch.setattr(sys, "argv", ["netops-helper-proxy"])
    assert MODULE._askpass_program() == Path(MODULE.__file__).resolve()


def test_a_server_request_whose_answer_cannot_be_written_keeps_the_session(monkeypatch, capsys) -> None:
    proxy, emitted = _proxy(monkeypatch)
    reader, writer = os.pipe()
    os.close(reader)
    failures: list = []

    def write(data: bytes) -> None:
        try:
            os.write(writer, data)
        except OSError as exc:
            failures.append(exc.errno)
            raise

    proxy.server_writer = write
    proxy.pending[3] = "tools/list"
    try:
        assert proxy.response(json.dumps({"jsonrpc": "2.0", "id": 30, "method": "ping"}).encode()) == b""
        assert proxy.response(json.dumps({
            "jsonrpc": "2.0", "id": 31, "method": "sampling/createMessage", "params": {},
        }).encode()) == b""
    finally:
        os.close(writer)
    assert failures == [errno.EPIPE, errno.EPIPE]
    assert capsys.readouterr().err == "netops_proxy_refused category=server_request method=sampling/createMessage\n"
    assert proxy.accepting() and proxy.pending == {3: "tools/list"}
    relayed = json.loads(proxy.response(json.dumps({"jsonrpc": "2.0", "id": 3, "result": {"tools": []}}).encode()))
    assert relayed["id"] == 3 and "result" in relayed
    assert emitted == []


def test_a_batch_answer_with_an_unhashable_id_ends_the_session_as_unpaired(monkeypatch, capsys) -> None:
    proxy, emitted = _proxy(monkeypatch)
    proxy.pending[4] = "tools/call"
    batch = [{"jsonrpc": "2.0", "id": [4], "result": {"content": []}}]
    assert proxy.response(json.dumps(batch).encode()) == b""
    assert not proxy.accepting()
    assert capsys.readouterr().err == ""
    assert proxy.finish_session(lambda: None) == "unpaired_response"
    assert [item["id"] for item in emitted] == [4]
    assert emitted[0]["error"]["data"] == {"category": "session_terminated", "reason": "unpaired_response"}
    assert capsys.readouterr().err == (
        "netops_proxy_session category=session_terminated reason=unpaired_response\n"
    )


CLOSES_ITS_INPUT = "import os, time\nos.close(0)\ntime.sleep(30)\n"
ANSWERS_INITIALIZE_THEN_GARBLES = (
    "import json, sys\n"
    "for raw in sys.stdin:\n"
    "    message = json.loads(raw)\n"
    "    if message.get('method') == 'initialize':\n"
    "        sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': message['id'], 'result': {\n"
    "            'protocolVersion': '2025-11-25', 'capabilities': {}, 'serverInfo': {'name': 'fake', 'version': '1'}}}) + chr(10))\n"
    "    elif 'id' in message:\n"
    "        sys.stdout.write('this is not JSON' + chr(10))\n"
    "    sys.stdout.flush()\n"
)
IGNORES_TERMINATION = (
    "import signal, sys, time\n"
    "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
    "sys.stdin.read()\n"
    "time.sleep(60)\n"
)
INITIALIZE = {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
    "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "client", "version": "1"},
}}


def _until(condition, seconds: float = 10.0) -> bool:
    finished = threading.Event()
    for _ in range(int(seconds / 0.02)):
        if condition():
            return True
        finished.wait(0.02)
    return condition()


def _input_closed(pid: int) -> bool:
    return not os.path.exists("/proc/%d/fd/0" % pid)


def _ignores_sigterm(pid: int) -> bool:
    for line in Path("/proc/%d/status" % pid).read_text().splitlines():
        if line.startswith("SigIgn:"):
            return bool(int(line.split()[1], 16) & (1 << (15 - 1)))
    return False


def _connection(proxy: Proxy, script: str) -> MODULE._ServerConnection:
    return MODULE._ServerConnection(proxy, [sys.executable, "-c", script], dict(os.environ), (), None)


def _terminated(emitted: list, request_id, reason: str) -> None:
    assert [item["id"] for item in emitted] == [request_id]
    assert emitted[0]["error"]["data"] == {"category": "session_terminated", "reason": reason}


@pytest.mark.skipif(not LINUX, reason="reads /proc")
def test_a_request_the_server_can_no_longer_receive_ends_the_session(monkeypatch, capsys) -> None:
    proxy, emitted = _proxy(monkeypatch)
    started: list = []

    def spawn():
        connection = _connection(proxy, CLOSES_ITS_INPUT)
        started.append(connection)
        assert _until(lambda: _input_closed(connection.child.pid))
        return connection if connection.start() else None

    controller = MODULE._SessionController(proxy, spawn)
    assert controller.start()
    try:
        assert controller.forward(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode() + b"\n") is False
    finally:
        code = controller.stop()
    _terminated(emitted, 1, "transport_closed")
    assert controller.restartable is False and len(started) == 1
    assert started[0].killed and started[0].child.poll() is not None
    assert code == 0
    assert capsys.readouterr().err == ""


@pytest.mark.skipif(not LINUX, reason="reads /proc")
def test_a_new_session_whose_server_cannot_receive_the_initialize_replay_fails(monkeypatch, capsys) -> None:
    proxy, emitted = _proxy(monkeypatch)
    started: list = []

    def spawn():
        connection = _connection(proxy, ANSWERS_INITIALIZE_THEN_GARBLES if not started else CLOSES_ITS_INPUT)
        started.append(connection)
        if len(started) > 1:
            assert _until(lambda: _input_closed(connection.child.pid))
        return connection if connection.start() else None

    controller = MODULE._SessionController(proxy, spawn)
    assert controller.start()
    try:
        assert controller.forward(json.dumps(INITIALIZE).encode() + b"\n") is True
        assert _until(lambda: proxy.initialize_message is not None and not proxy.pending)
        assert controller.forward(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}).encode() + b"\n")
        assert _until(lambda: not proxy.accepting())
        assert controller.forward(json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}).encode() + b"\n") is False
    finally:
        code = controller.stop()
    assert len(started) == 2 and controller.failed
    assert [item["id"] for item in emitted] == [2, 3]
    assert [item["error"]["data"]["reason"] for item in emitted] == ["server_message", "session_start"]
    captured = capsys.readouterr()
    assert json.loads(captured.out.splitlines()[0])["id"] == 0
    assert captured.err.splitlines() == [
        "netops_proxy_refused category=server_message",
        "netops_proxy_session category=session_terminated reason=server_message",
        "netops_proxy_session category=session_terminated reason=session_start",
    ]
    assert code == 2


@pytest.mark.skipif(not LINUX, reason="reads /proc")
def test_an_ssh_child_that_ignores_its_end_is_killed_and_reported_as_a_timeout(monkeypatch, capsys) -> None:
    proxy = Proxy()
    connection = _connection(proxy, IGNORES_TERMINATION)
    assert connection.start()
    assert _until(lambda: _ignores_sigterm(connection.child.pid))
    code = connection.stop()
    assert code == -9
    assert capsys.readouterr().err == (
        "netops_proxy_transport category=ssh_timeout message=The remote MCP transport timed out.\n"
    )


@pytest.mark.skipif(not LINUX, reason="reads /proc")
def test_a_child_that_ignores_termination_is_killed() -> None:
    child = MODULE.subprocess.Popen(
        [sys.executable, "-c", IGNORES_TERMINATION], stdin=MODULE.subprocess.PIPE,
    )
    try:
        assert _until(lambda: _ignores_sigterm(child.pid))
        MODULE._stop_child(child)
        assert child.returncode == -9
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()
        child.stdin.close()


CLOSES_ITS_OUTPUT = "import os, time\nos.close(1)\ntime.sleep(30)\n"


@pytest.mark.skipif(not LINUX, reason="reads /proc")
def test_an_ssh_child_that_closes_its_output_but_stays_ends_the_session(monkeypatch, capsys) -> None:
    proxy, emitted = _proxy(monkeypatch)
    connection = _connection(proxy, CLOSES_ITS_OUTPUT)
    proxy.pending[6] = "tools/call"
    try:
        assert connection.start()
        assert _until(lambda: not proxy.accepting(), 20)
        assert proxy.session_reason == "transport_closed"
        assert connection.child.poll() is None
        assert proxy.finish_session(connection.kill) == "transport_closed"
    finally:
        if connection.child.poll() is None:
            connection.child.kill()
        connection.child.wait()
    assert connection.killed
    _terminated(emitted, 6, "transport_closed")
    assert capsys.readouterr().err == ""


def test_a_client_that_stops_reading_ends_the_proxy_without_a_traceback(tmp_path) -> None:
    """The ssh child is stopped and nothing is forwarded once the client's end of standard output is gone.

    The exit status is 0 from the session, or 120 when the interpreter cannot flush
    the answer the proxy had buffered for the vanished client (EVIDENCE: HLP-W5-1).
    """
    import test_proxy_contracts as contracts

    _, _, _, runner = contracts._configure(MODULE, tmp_path)
    contracts._write(runner, contracts._runner(MODULE.hostkey.fingerprint_of(contracts.RUNNER_HOST_KEY)))
    binaries = contracts._fake_tools(tmp_path)
    record = tmp_path / "fake-ssh-record.json"
    reader, writer = os.pipe()
    os.close(reader)
    try:
        process = MODULE.subprocess.Popen(
            [sys.executable, "-B", str(contracts.LAUNCHER)], cwd=tmp_path,
            env=contracts._proxy_environment(MODULE, tmp_path, binaries, record),
            stdin=MODULE.subprocess.PIPE, stdout=writer, stderr=MODULE.subprocess.PIPE,
        )
    finally:
        os.close(writer)
    lines = b"this is not JSON\n" + contracts._request(1, "helper_status", {}) + b"\n"
    _, stderr = process.communicate(lines, timeout=60)
    text = stderr.decode(errors="replace")
    assert "Traceback" not in text, text
    assert set(text.splitlines()) <= {
        "Exception ignored while flushing sys.stdout:", "BrokenPipeError: [Errno 32] Broken pipe",
    }, text
    assert json.loads(record.read_text(encoding="utf-8"))["requests"] == []
    assert process.returncode in (0, 120), text
