"""One connection queue per device: FortiOS pacing and the cached host key line.

Twenty-six SSH-family connections in a row (one `ssh-keyscan` plus one `ssh`
per query) made a real FortiGate refuse further connections. `engine.py`
answers with two mechanisms exercised here:

- every SSH-family connection to one (address, port) - a keyscan, an `ssh`
  exec, a PTY session, an `sftp` call - goes through that device's one lane,
  which waits `_CONNECTION_SPACING_SECONDS[platform]` seconds since the lane's
  previous connection started before starting the next one;
- the host key line a keyscan returns is cached for
  `_HOST_KEY_CACHE_TTL_SECONDS`, so a query after the first against the same
  device usually needs only the `ssh`/`sftp` connection, not the keyscan too.

`_now`/`_sleep` are swapped for a fake clock throughout, so an asserted wait
of several seconds costs no real time; `sleep` on that fake clock advances it,
the way a real wait would.
"""

from __future__ import annotations

import asyncio
import threading
import time

import pytest

from conftest import (
    EXEC_CLIENT,
    HOST_KEY_PIN,
    KNOWN_HOSTS_LINE,
    LOOPBACK,
    PORT,
    _calls,
    _plain_query,
    _ruckus_wire,
    _target,
    _write_client,
)
import netops_helper.engine as engine


class FakeClock:
    """A monotonic clock that only moves when told to, `sleep` included.

    Real `_sleep` blocks; this one just records the requested duration and
    advances `now` by it, so a test can assert both "did it wait" and "how
    long did it ask to wait" without spending real seconds. Guarded by its
    own lock so several threads can call `sleep`/`monotonic` safely, even
    though the connection lane's own lock already serializes every call that
    matters for one device.
    """

    def __init__(self, start: float = 1_000.0) -> None:
        self._lock = threading.Lock()
        self.now = start
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        with self._lock:
            return self.now

    def sleep(self, seconds: float) -> None:
        with self._lock:
            self.sleeps.append(seconds)
            self.now += seconds


def _install_clock(monkeypatch) -> FakeClock:
    clock = FakeClock()
    monkeypatch.setattr(engine, "_now", clock.monotonic)
    monkeypatch.setattr(engine, "_sleep", clock.sleep)
    return clock


def _warm_host_key_cache(clock: FakeClock, *, host: str = LOOPBACK, port: int = PORT) -> None:
    """Seed the host-key cache directly, bypassing the lane and ssh-keyscan.

    Lets a test measure connection-to-connection spacing without an extra
    keyscan hop ahead of every read; the keyscan path itself is exercised by
    test_host_key_cache_hits_expires_and_forgets_after_a_client_failure.
    """
    engine._HOST_KEY_LINE_CACHE[(host, port, HOST_KEY_PIN)] = (
        clock.now + engine._HOST_KEY_CACHE_TTL_SECONDS, KNOWN_HOSTS_LINE,
    )


def _keyscans(wire) -> list[dict]:
    return [call for call in _calls(wire) if "stdin_isatty" not in call]


def test_two_fortinet_reads_are_spaced_five_seconds_apart(wire, monkeypatch) -> None:
    clock = _install_clock(monkeypatch)
    _warm_host_key_cache(clock)
    query_name, _ = _plain_query("fortinet")
    target = _target("fortinet", query_name)

    first = engine.ssh_read(target, "fortinet", query_name, {}, 0, 16_000)
    assert first["ok"] is True
    assert clock.sleeps == []

    clock.now += 1.5
    second = engine.ssh_read(target, "fortinet", query_name, {}, 0, 16_000)
    assert second["ok"] is True
    assert len(clock.sleeps) == 1
    assert clock.sleeps[0] == pytest.approx(5.0 - 1.5)
    assert _keyscans(wire) == []


def test_extreme_exos_reads_never_wait(wire, monkeypatch) -> None:
    clock = _install_clock(monkeypatch)
    query_name, _ = _plain_query("extreme_exos")
    target = _target("extreme_exos", query_name)

    for _ in range(2):
        result = engine.ssh_read(target, "extreme_exos", query_name, {}, 0, 16_000)
        assert result["ok"] is True
    assert clock.sleeps == []


def test_two_different_fortinet_devices_do_not_wait_on_each_other(wire, monkeypatch) -> None:
    clock = _install_clock(monkeypatch)
    query_name, _ = _plain_query("fortinet")
    first_target = _target("fortinet", query_name, host="127.0.0.2")
    second_target = _target("fortinet", query_name, host="127.0.0.3")
    _warm_host_key_cache(clock, host="127.0.0.2")
    _warm_host_key_cache(clock, host="127.0.0.3")

    assert engine.ssh_read(first_target, "fortinet", query_name, {}, 0, 16_000)["ok"] is True
    assert engine.ssh_read(second_target, "fortinet", query_name, {}, 0, 16_000)["ok"] is True
    assert clock.sleeps == []


def test_three_threads_on_one_fortinet_device_serialize_with_spacing(
    wire, monkeypatch,
) -> None:
    clock = _install_clock(monkeypatch)
    _warm_host_key_cache(clock)
    query_name, _ = _plain_query("fortinet")
    target = _target("fortinet", query_name)

    fake_starts: list[float] = []
    real_windows: list[tuple[float, float]] = []
    recordings_lock = threading.Lock()

    def fake_run_command(*args, **kwargs):
        fake_started = clock.monotonic()
        real_started = time.monotonic()
        time.sleep(0.05)
        real_finished = time.monotonic()
        with recordings_lock:
            fake_starts.append(fake_started)
            real_windows.append((real_started, real_finished))
        return engine.core_ssh.Result(
            rc=0, stdout=b"", said="", started_at="", finished_at="",
        )

    monkeypatch.setattr(engine.core_ssh, "run_command", fake_run_command)

    results: list[dict] = []
    results_lock = threading.Lock()

    def worker() -> None:
        result = engine.ssh_read(target, "fortinet", query_name, {}, 0, 16_000)
        with results_lock:
            results.append(result)

    threads = [threading.Thread(target=worker) for _ in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(results) == 3
    assert all(result["ok"] is True for result in results)

    real_windows.sort()
    assert len(real_windows) == 3
    assert real_windows[0][1] <= real_windows[1][0]
    assert real_windows[1][1] <= real_windows[2][0]

    fake_starts.sort()
    assert len(fake_starts) == 3
    assert fake_starts[1] - fake_starts[0] >= 5.0
    assert fake_starts[2] - fake_starts[1] >= 5.0


def test_host_key_cache_hits_expires_and_forgets_after_a_client_failure(
    wire, monkeypatch,
) -> None:
    clock = _install_clock(monkeypatch)
    target = _target("linux", "hostname")

    assert engine.ssh_read(target, "linux", "hostname", {}, 0, 16_000)["ok"] is True
    assert len(_keyscans(wire)) == 1

    assert engine.ssh_read(target, "linux", "hostname", {}, 0, 16_000)["ok"] is True
    assert len(_keyscans(wire)) == 1

    clock.now += engine._HOST_KEY_CACHE_TTL_SECONDS + 1.0
    assert engine.ssh_read(target, "linux", "hostname", {}, 0, 16_000)["ok"] is True
    assert len(_keyscans(wire)) == 2

    _write_client(
        wire["binaries"], "ssh",
        EXEC_CLIENT.format(log=str(wire["log"]), output="", code=255),
    )
    failed = engine.ssh_read(target, "linux", "hostname", {}, 0, 16_000)
    assert failed["ok"] is False
    assert len(_keyscans(wire)) == 2

    engine.ssh_read(target, "linux", "hostname", {}, 0, 16_000)
    assert len(_keyscans(wire)) == 3


def test_sftp_and_pty_reads_are_paced_through_the_lane(wire, monkeypatch) -> None:
    clock = _install_clock(monkeypatch)

    query_name, _ = _plain_query("fortinet")
    sftp_target = _target(
        "fortinet", query_name, host="127.0.0.4", sftp_roots=("/safe",),
    )
    _warm_host_key_cache(clock, host="127.0.0.4")

    def fake_stat(*args, **kwargs):
        return engine.core_sftp.Entry(
            kind="file", mode=0o600, size=1, modified_ls="Sep 10 02:26",
            name=None, entry_count=None, said="", started_at="", finished_at="",
        )

    monkeypatch.setattr(engine.core_sftp, "stat", fake_stat)

    first = asyncio.run(engine.sftp_stat(sftp_target, "/safe/log"))
    assert first["ok"] is True
    assert clock.sleeps == []

    second = asyncio.run(engine.sftp_stat(sftp_target, "/safe/log"))
    assert second["ok"] is True
    assert len(clock.sleeps) == 1
    assert clock.sleeps[0] == pytest.approx(5.0)

    monkeypatch.setattr(
        engine, "_CONNECTION_SPACING_SECONDS",
        {**engine._CONNECTION_SPACING_SECONDS, "ruckus_unleashed": 5.0},
    )
    _ruckus_wire(wire)
    ruckus_target = _target(
        "ruckus_unleashed", "system_info", legacy_ssh="rsa-sha1", host="127.0.0.5",
    )
    _warm_host_key_cache(clock, host="127.0.0.5")

    before = len(clock.sleeps)
    first_ruckus = engine.ssh_read(
        ruckus_target, "ruckus_unleashed", "system_info", {}, 0, 16_000,
    )
    assert first_ruckus["ok"] is True
    assert len(clock.sleeps) == before

    second_ruckus = engine.ssh_read(
        ruckus_target, "ruckus_unleashed", "system_info", {}, 0, 16_000,
    )
    assert second_ruckus["ok"] is True
    assert len(clock.sleeps) == before + 1
    assert clock.sleeps[-1] == pytest.approx(5.0)


def test_the_first_keyscan_of_a_device_is_paced_like_any_other_connection(
    wire, monkeypatch,
) -> None:
    clock = _install_clock(monkeypatch)
    query_name, _ = _plain_query("fortinet")
    target = _target("fortinet", query_name)

    first = engine.ssh_read(target, "fortinet", query_name, {}, 0, 16_000)
    assert first["ok"] is True
    assert len(_keyscans(wire)) == 1
    assert len(clock.sleeps) == 1
    assert clock.sleeps[0] == pytest.approx(5.0)


def test_the_extreme_exos_preamble_is_paced_like_the_query_itself(wire, monkeypatch) -> None:
    clock = _install_clock(monkeypatch)
    monkeypatch.setattr(
        engine, "_CONNECTION_SPACING_SECONDS",
        {**engine._CONNECTION_SPACING_SECONDS, "extreme_exos": 5.0},
    )
    _warm_host_key_cache(clock)
    query_name, _ = _plain_query("extreme_exos")
    target = _target("extreme_exos", query_name)

    result = engine.ssh_read(target, "extreme_exos", query_name, {}, 0, 16_000)
    assert result["ok"] is True
    assert len(clock.sleeps) == 1
    assert clock.sleeps[0] == pytest.approx(5.0)
