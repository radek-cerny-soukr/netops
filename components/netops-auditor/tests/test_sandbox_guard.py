"""The sandbox refuses writes outside temporary directories and network access off loopback.
The negative-test driver explicitly runs all five deliberately failing fixture cases.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys
import xml.etree.ElementTree as ET

import pytest

GUARD = sys.modules["netops_sandbox_guard"]
COMPONENT = Path(__file__).resolve().parents[1]
PROBE = Path.home() / ".netops-sandbox-guard-probe"
UNGUARDED_UNLINK = os.unlink
DOCUMENTATION_ADDRESS = "192.0.2.1"



def _refused(call, fragment: str) -> None:
    with pytest.raises(GUARD.SandboxViolation) as caught:
        call()
    assert fragment in str(caught.value)
    assert GUARD.ACTIVE.violations, "the refusal must be recorded"
    GUARD.ACTIVE.violations.clear()


def _remove_probe() -> None:
    if os.path.lexists(PROBE):
        UNGUARDED_UNLINK(PROBE)


def _code_under_test(directory: Path):
    """A module outside tests/: the FIFO exception covers only a test feeding its own pipe."""
    source = directory / "code_under_test.py"
    source.write_text(
        "import os\n"
        "def feed(path):\n"
        "    with open(path, 'wb') as handle:\n"
        "        handle.write(b'x')\n"
        "def raw(descriptor):\n"
        "    os.write(descriptor, b'x')\n",
        encoding="utf-8",
    )
    specification = importlib.util.spec_from_file_location("code_under_test", source)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def test_writes_inside_tmp_path_pass(tmp_path):
    target = tmp_path / "nested" / "state.json"
    target.parent.mkdir()
    target.write_text("{}", encoding="utf-8")
    with open(tmp_path / "log", "a", encoding="utf-8") as handle:
        handle.write("line\n")
    staged = tmp_path / ".state.tmp"
    staged.write_bytes(b"{}")
    os.replace(staged, target)
    shutil.copy2(target, tmp_path / "copy.json")
    descriptor = os.open(tmp_path / "raw", os.O_WRONLY | os.O_CREAT, 0o600)
    os.fchmod(descriptor, 0o600)
    os.close(descriptor)
    with sqlite3.connect(tmp_path / "store.sqlite3") as database:
        database.execute("create table t (v)")
    os.unlink(tmp_path / "raw")
    assert target.read_text(encoding="utf-8") == "{}"


def test_child_redirected_to_the_null_device_is_not_a_write():
    completed = subprocess.run([sys.executable, "-c", "print(1)"], stdout=subprocess.DEVNULL, check=True)
    assert completed.returncode == 0


def test_loopback_server_is_reachable():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        with socket.create_connection(listener.getsockname(), timeout=5):
            accepted, _ = listener.accept()
            accepted.close()


def test_write_into_the_home_directory_is_refused():
    try:
        _refused(lambda: open(PROBE, "w", encoding="utf-8"), str(PROBE))
        _refused(lambda: os.open(PROBE, os.O_WRONLY | os.O_CREAT, 0o600), str(PROBE))
        _refused(lambda: PROBE.write_text("x", encoding="utf-8"), str(PROBE))
        _refused(lambda: os.makedirs(PROBE / "sub"), str(PROBE))
        _refused(lambda: sqlite3.connect(PROBE), str(PROBE))
    finally:
        exists = os.path.lexists(PROBE)
        _remove_probe()
    assert not exists


def test_links_resolve_the_way_the_operation_does(tmp_path):
    link = tmp_path / "escape"
    link.symlink_to(PROBE)
    try:
        _refused(lambda: open(link, "w", encoding="utf-8"), str(link))
        _refused(lambda: os.open(link, os.O_WRONLY | os.O_CREAT, 0o600), str(link))
        with pytest.raises(FileExistsError):
            os.mkdir(link)
        os.unlink(link)
    finally:
        exists = os.path.lexists(PROBE)
        _remove_probe()
    assert not exists and not os.path.lexists(link)


def test_relative_write_into_the_source_tree_is_refused(monkeypatch):
    monkeypatch.chdir(COMPONENT)
    _refused(lambda: open("sandbox-probe.txt", "w", encoding="utf-8"), str(COMPONENT / "sandbox-probe.txt"))
    assert not (COMPONENT / "sandbox-probe.txt").exists()


def test_special_files_are_never_a_target(tmp_path):
    staged = tmp_path / "staged"
    staged.write_text("x", encoding="utf-8")
    _refused(lambda: open(os.devnull, "w", encoding="utf-8"), os.devnull)
    _refused(lambda: os.replace(staged, os.devnull), os.devnull)
    _refused(lambda: shutil.copyfile("/dev/zero", tmp_path / "out"), "/dev/zero")
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    code = _code_under_test(tmp_path)
    probe = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
    try:
        _refused(lambda: code.feed(fifo), str(fifo))
        _refused(lambda: code.raw(probe), str(fifo))
        os.write(probe, b"fed by the test")
        assert os.read(probe, 64) == b"fed by the test"
    finally:
        os.close(probe)
    null = os.open(os.devnull, os.O_WRONLY)
    try:
        _refused(lambda: os.write(null, b"x"), os.devnull)
    finally:
        os.close(null)
    _refused(lambda: os.replace(staged, fifo), str(fifo))
    assert staged.exists()


def test_network_off_loopback_is_refused():
    pytest_socket = pytest.importorskip("pytest_socket")
    with pytest.raises(pytest_socket.SocketConnectBlockedError), pytest.warns(UserWarning, match=DOCUMENTATION_ADDRESS):
        socket.create_connection((DOCUMENTATION_ADDRESS, 9), timeout=1)
    with socket.socket() as probe:
        _refused(lambda: probe.bind(("", 0)), "<wildcard>")
    _refused(lambda: socket.getaddrinfo("example.invalid", 443), "example.invalid")


def test_deliberate_violations_fail_the_test(tmp_path):
    report = tmp_path / "negative-fixtures.xml"
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    completed = subprocess.run(
        [sys.executable, "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider", "-k", "demo",
         "tests/support/sandbox_violations.py", "--junitxml", str(report)],
        cwd=COMPONENT, env=environment, capture_output=True, text=True, timeout=300,
    )
    exists = os.path.lexists(PROBE)
    _remove_probe()
    output = completed.stdout + completed.stderr
    assert completed.returncode == 1, output
    assert "5 failed" in output, output
    assert str(PROBE) in output and os.devnull in output and DOCUMENTATION_ADDRESS in output, output
    assert not exists
    expected = {
        "test_demo_write_into_the_home_directory": ("test sandbox", str(PROBE)),
        "test_demo_swallowed_refusal_still_fails": ("test sandbox", str(PROBE)),
        "test_demo_write_into_the_null_device": ("test sandbox", os.devnull),
        "test_demo_replace_onto_the_null_device": ("test sandbox", os.devnull),
        "test_demo_connection_off_loopback": ("SocketConnectBlockedError", DOCUMENTATION_ADDRESS),
    }
    cases = ET.parse(report).findall(".//testcase")
    assert {case.get("name") for case in cases} == set(expected)
    for case in cases:
        assert case.find("skipped") is None and case.find("error") is None
        failure = case.find("failure")
        assert failure is not None
        detail = "".join(failure.itertext())
        assert all(fragment in detail for fragment in expected[case.get("name")]), detail
