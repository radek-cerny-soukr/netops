from types import SimpleNamespace
import tempfile

import pytest

from netops_core.target_lock import TargetBusy, target_lock
from netops_helper import engine
from netops_helper.auth import EgressPolicy, TargetAuth
from netops_admin import execute
from netops_admin.errors import Rejected
from netops_admin.state import Store

PIN = "SHA256:" + "A" * 43


def isolated(monkeypatch, path):
    monkeypatch.delenv("NETOPS_TARGET_LOCK_DIR", raising=False)
    monkeypatch.setattr(tempfile, "tempdir", str(path))


def test_helper_busy_target_refuses_before_resolution_or_ssh(tmp_path, monkeypatch):
    isolated(monkeypatch, tmp_path)
    auth = TargetAuth(
        alias="helper-alias", host="192.0.2.10", port=22, login="example",
        secret="test-fixture-password", host_key_fingerprint=PIN,
        ssh_platform="fortinet", enabled_queries=("system_status",),
        read_inventory={"diagnostic_recipes": ("ping",), "addresses": ("192.0.2.20",),
                        "interfaces": ("port2",)},
        fortios_output_standard_verified=True,
        egress=EgressPolicy(addresses=("192.0.2.10",), tcp_ports=(22,)),
    )
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    monkeypatch.setattr(engine, "_resolve_target_ipv4",
                        lambda *args: pytest.fail("network resolution reached while target busy"))
    with target_lock(PIN):
        with pytest.raises(TargetBusy, match="busy"):
            engine.fortios_diagnostics(auth, "ping", "192.0.2.20", "port2", 1, 1, 1000)



def test_fortiadc_busy_target_refuses_before_resolution_or_ssh(tmp_path, monkeypatch):
    isolated(monkeypatch, tmp_path)
    auth = TargetAuth(
        alias="adc-alias", host="192.0.2.11", port=22, login="example",
        secret="test-fixture-password", host_key_fingerprint=PIN,
        ssh_platform="fortiadc", enabled_queries=("system_status",),
        read_inventory={"diagnostic_recipes": ("traceroute",), "addresses": ("192.0.2.20",)},
        egress=EgressPolicy(addresses=("192.0.2.11",), tcp_ports=(22,)),
    )
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    monkeypatch.setattr(engine, "_resolve_target_ipv4",
                        lambda *args: pytest.fail("network resolution reached while target busy"))
    with target_lock(PIN):
        with pytest.raises(TargetBusy, match="busy"):
            engine.fortios_diagnostics(auth, "traceroute", "192.0.2.20", "", 3, 1, 1000)

def test_admin_busy_target_refuses_before_snapshot_or_write(tmp_path, monkeypatch):
    isolated(monkeypatch, tmp_path)
    device = SimpleNamespace(name="different-admin-alias", platform="fortios",
                             host_key_fingerprint=PIN)
    runtime = SimpleNamespace(store=Store(tmp_path / "admin"), simulate_unmeasured_profiles=False)
    request = SimpleNamespace(request_id="lock-test", table="firewall address",
                              fingerprint=lambda: "test-fingerprint")
    monkeypatch.setattr(execute, "_target", lambda *args: device)
    monkeypatch.setattr(execute, "_adapter", lambda *args: object())
    monkeypatch.setattr(execute, "_prepared",
                        lambda *args: pytest.fail("device snapshot reached while target busy"))
    with target_lock(PIN):
        with pytest.raises(Rejected, match="busy"):
            execute.preview(runtime, device.name, request)


def test_failed_diagnostic_keeps_pin_lane_and_target_lock(tmp_path, monkeypatch):
    from contextlib import contextmanager
    from netops_helper import fortios_diagnostics as diagnostics

    isolated(monkeypatch, tmp_path)
    auth = TargetAuth(
        alias="diagnostic-alias", host="192.0.2.10", port=22, login="example",
        secret="test-fixture-password", host_key_fingerprint=PIN,
        ssh_platform="fortinet", enabled_queries=("system_status",),
        read_inventory={"diagnostic_recipes": ("ping",), "addresses": ("192.0.2.20",),
                        "interfaces": ("port2",)},
        fortios_output_standard_verified=True,
        egress=EgressPolicy(addresses=("192.0.2.10",), tcp_ports=(22,)),
    )
    sessions = []
    lane = []
    held_lanes = []

    class Session:
        def __init__(self, *args, **kwargs):
            self.args, self.kwargs, self.closed = args, kwargs, False
            sessions.append(self)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

        def close(self):
            self.closed = True

    @contextmanager
    def paced(*args):
        assert not lane
        lane.append(args)
        try:
            yield
        finally:
            lane.pop()

    def run(shell, *args, reconnect, **kwargs):
        assert shell is sessions[0]
        with pytest.raises(ValueError, match="session is still open"):
            with reconnect():
                pytest.fail("a repair session opened while the original session is open")
        held_lanes.append(tuple(lane))
        with pytest.raises(TargetBusy):
            with target_lock(PIN):
                pytest.fail("target lock released during the diagnostic")
        raise RuntimeError("original diagnostic failure")

    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    monkeypatch.setattr(engine, "_resolve_target_ipv4", lambda *args: ("192.0.2.10",))
    monkeypatch.setattr(engine, "host_key_line", lambda *args: "pinned-known-hosts")
    monkeypatch.setattr(engine, "_paced_connection", paced)
    monkeypatch.setattr(engine.core_session, "fortinet_session", Session)
    monkeypatch.setattr(engine, "_FortiosDiagnosticShell", lambda session: session)
    monkeypatch.setattr(diagnostics, "run", run)
    with pytest.raises(ValueError, match="bounded FortiOS diagnostic failed"):
        engine.fortios_diagnostics(auth, "ping", "192.0.2.20", "port2", 1, 1, 1000)
    assert held_lanes == [(("192.0.2.10", 22, "fortinet"),)]
    session, = sessions
    assert session.closed
    device, credential = session.args
    assert (device.address, device.port, device.host_key_fingerprint) == ("192.0.2.10", 22, PIN)
    assert credential.login == "example"
    assert not lane
    with target_lock(PIN):
        pass
