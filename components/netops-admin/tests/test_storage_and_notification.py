import os
import time
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from netops_admin.state import Store
from netops_admin.notify import NtfyNotifier


def test_state_root_is_created_private_under_public_umask(tmp_path):
    old = os.umask(0o022)
    try:
        store = Store(tmp_path / "state")
        assert store.root.stat().st_mode & 0o777 == 0o700
    finally:
        os.umask(old)


def test_notification_has_a_total_deadline_for_a_slow_header(tmp_path):
    class SlowHeader(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            try:
                for byte in b"HTTP/1.1 200 OK\r\n":
                    self.connection.sendall(bytes([byte]))
                    time.sleep(0.08)
            except OSError:
                pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), SlowHeader)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    topic = tmp_path / "topic.env"
    topic.write_text("NTFY_TOPIC=abcdefgh_12345\n")
    sender = NtfyNotifier("http://127.0.0.1:%d" % server.server_address[1], str(topic), 0.4)
    try:
        started = time.monotonic()
        assert sender({"device": "fixture", "result": "confirmed"}) == "failed"
        assert time.monotonic() - started < 1.2
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_next_store_recovers_a_temporary_left_by_a_killed_atomic_writer(tmp_path):
    import subprocess
    import sys
    import signal
    store = Store(tmp_path / "state")
    destination = store.operations / ("a" * 32 + ".json")
    script = """import os,signal
from pathlib import Path
from netops_admin import state
def killed(*args):
    os.kill(os.getpid(), signal.SIGKILL)
state.os.replace = killed
state.write_atomic(Path(%r), {'fixture': True})
""" % str(destination)
    environment = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
    answer = subprocess.run([sys.executable, "-B", "-c", script], env=environment, timeout=5)
    assert answer.returncode == -signal.SIGKILL
    assert list(store.operations.glob(".*.tmp"))
    preserved = store.operations / "unrelated.tmp"
    preserved.write_text("keep")
    Store(store.root)
    assert not list(store.operations.glob(".*.tmp"))
    assert preserved.read_text() == "keep"
    assert not destination.exists()


def test_store_does_not_clean_through_a_symlink_root(tmp_path):
    import pytest
    from netops_admin.errors import StateUnreadable
    outside = tmp_path / "outside"
    outside.mkdir()
    preserved = outside / ".other.json.1234567890abcdef.tmp"
    preserved.write_text("keep")
    alias = tmp_path / "state"
    alias.symlink_to(outside, target_is_directory=True)
    with pytest.raises(StateUnreadable):
        Store(alias)
    assert preserved.read_text() == "keep"


def test_store_start_waits_for_an_active_atomic_writer(tmp_path):
    import subprocess
    import sys
    import json
    store = Store(tmp_path / "state")
    destination = store.operations / ("b" * 32 + ".json")
    script = """import os,time
from pathlib import Path
from netops_admin import state
original=state.os.replace
def delayed(*args):
    print('ready',flush=True)
    time.sleep(0.3)
    return original(*args)
state.os.replace=delayed
state.write_atomic(Path(%r),{'fixture':True})
""" % str(destination)
    environment = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
    child = subprocess.Popen([sys.executable, "-B", "-c", script], stdout=subprocess.PIPE, text=True, env=environment)
    try:
        assert child.stdout.readline().strip() == "ready"
        Store(store.root)
        assert child.wait(timeout=3) == 0
        assert json.loads(destination.read_text()) == {"fixture": True}
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=3)
        child.stdout.close()


def test_malformed_budget_anchor_is_a_typed_refusal(tmp_path):
    import pytest
    from netops_admin.errors import StateUnreadable
    store = Store(tmp_path / "state")
    (store.root / "budget-clock.json").write_text("{broken")
    with pytest.raises(StateUnreadable):
        store.budget_now()


def test_unavailable_boot_identity_is_a_typed_refusal(tmp_path, monkeypatch):
    import pytest
    from netops_admin.errors import StateUnreadable
    store = Store(tmp_path / "state")
    read = type(store.root).read_text
    def unavailable(path, *args, **kwargs):
        if str(path) == "/proc/sys/kernel/random/boot_id":
            raise FileNotFoundError("fixture missing")
        return read(path, *args, **kwargs)
    from netops_admin import state
    monkeypatch.setattr(state.sys, "platform", "linux")
    monkeypatch.setattr(type(store.root), "read_text", unavailable)
    with pytest.raises(StateUnreadable):
        store.budget_now()


def test_notifier_preserves_ca_and_proxy_settings_without_other_environment(tmp_path, monkeypatch):
    import subprocess
    from netops_admin import notify
    topic = tmp_path / "topic.env"
    topic.write_text("NTFY_TOPIC=abcdefgh_12345\n")
    monkeypatch.setenv("SSL_CERT_FILE", "/fixture/ca.pem")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example.invalid")
    monkeypatch.setenv("UNRELATED_SECRET", "fixture-secret")
    seen = []
    def child(command, **kwargs):
        seen.append(kwargs["env"])
        return subprocess.CompletedProcess(command, 0, stdout=b"sent", stderr=b"")
    monkeypatch.setattr(notify.subprocess, "run", child)
    assert notify.NtfyNotifier("https://ntfy.example.invalid", str(topic), 1)({"result": "confirmed"}) == "sent"
    assert seen[0]["SSL_CERT_FILE"] == "/fixture/ca.pem"
    assert seen[0]["HTTPS_PROXY"] == "http://proxy.example.invalid"
    assert "UNRELATED_SECRET" not in seen[0]
