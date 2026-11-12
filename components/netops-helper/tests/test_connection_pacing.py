"""One connection queue per device: Fortinet/FortiADC pacing and the cached host key line.

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

from dataclasses import replace

import pytest

from conftest import (
    EXEC_CLIENT,
    FORTIADC_STATUS,
    FORTIOS_STATUS,
    HOST_KEY_PIN,
    KNOWN_HOSTS_LINE,
    LOOPBACK,
    PORT,
    READ_QUERIES,
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


def _fortios_wire(wire) -> None:
    _write_client(
        wire["binaries"], "ssh",
        EXEC_CLIENT.format(log=str(wire["log"]), output=FORTIOS_STATUS, code=0),
    )


def test_fortinet_and_fortiadc_reads_are_spaced_five_seconds_apart(wire, monkeypatch) -> None:
    clock = _install_clock(monkeypatch)
    _warm_host_key_cache(clock)
    query_name = "system_status"
    _fortios_wire(wire)
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

    adc_host = "127.0.0.7"
    _warm_host_key_cache(clock, host=adc_host)
    _write_client(
        wire["binaries"], "ssh",
        EXEC_CLIENT.format(log=str(wire["log"]), output=FORTIADC_STATUS, code=0),
    )
    adc_target = _target("fortiadc", query_name, host=adc_host)
    sleeps_before_adc = len(clock.sleeps)
    first_adc = engine.ssh_read(adc_target, "fortiadc", query_name, {}, 0, 16_000)
    assert first_adc["ok"] is True
    assert len(clock.sleeps) == sleeps_before_adc

    clock.now += 1.5
    second_adc = engine.ssh_read(adc_target, "fortiadc", query_name, {}, 0, 16_000)
    assert second_adc["ok"] is True
    assert len(clock.sleeps) == sleeps_before_adc + 1
    assert clock.sleeps[-1] == pytest.approx(5.0 - 1.5)


def test_a_fortinet_query_other_than_system_status_takes_a_second_connection_after_five_seconds(
    wire, monkeypatch,
) -> None:
    clock = _install_clock(monkeypatch)
    _warm_host_key_cache(clock)
    _fortios_wire(wire)
    query_name, command = next(
        (name, item.command) for name, item in sorted(READ_QUERIES["fortinet"].items())
        if not item.slots and item.command != engine._IDENTITY_COMMAND
    )
    target = _target("fortinet", query_name)

    result = engine.ssh_read(target, "fortinet", query_name, {}, 0, 16_000)
    assert result["ok"] is True
    assert [call["argv"][-1] for call in _calls(wire)] == [engine._IDENTITY_COMMAND, command]
    assert clock.sleeps == [pytest.approx(5.0)]


def _two_plain_fortinet_queries():
    return [(name, item.command) for name, item in sorted(READ_QUERIES["fortinet"].items())
            if not item.slots and item.command != engine._IDENTITY_COMMAND][:2]


def test_fortinet_identity_is_checked_before_every_fresh_read(wire, monkeypatch) -> None:
    clock = _install_clock(monkeypatch)
    _warm_host_key_cache(clock)
    _fortios_wire(wire)
    (first, first_command), (second, second_command) = _two_plain_fortinet_queries()
    target = replace(_target("fortinet", first), enabled_queries=(first, second, "system_status"))

    for query in (first, second, first, "system_status", second):
        assert engine.ssh_read(target, "fortinet", query, {}, 0, 16_000)["ok"] is True
    assert [call["argv"][-1] for call in _calls(wire)] == [
        engine._IDENTITY_COMMAND, first_command,
        engine._IDENTITY_COMMAND, second_command,
        engine._IDENTITY_COMMAND, first_command,
        engine._IDENTITY_COMMAND,
        engine._IDENTITY_COMMAND, second_command,
    ]
    assert clock.sleeps == [pytest.approx(5.0)] * 8


@pytest.mark.parametrize("changed_status", [FORTIADC_STATUS, "invalid identity\n"])
def test_a_previously_verified_target_is_refused_after_its_identity_changes(monkeypatch, changed_status) -> None:
    target = _target("fortinet", "system_status")
    reads = []
    status = FORTIOS_STATUS

    def device(auth, platform, command, **_):
        reads.append(command)
        return 0, status if command == engine._IDENTITY_COMMAND else "query output"

    monkeypatch.setattr(engine, "read_from_device", device)
    assert engine._verified_read(target, "fortinet", "get system arp") == (0, "query output")
    status = changed_status
    for command in (engine._IDENTITY_COMMAND, "get system arp", "get system arp"):
        with pytest.raises(engine._ProductIdentityError):
            engine._verified_read(target, "fortinet", command)
    assert reads == [engine._IDENTITY_COMMAND, "get system arp"] + [engine._IDENTITY_COMMAND] * 3


def test_a_refused_identity_is_checked_again_before_the_next_query(monkeypatch) -> None:
    target = _target("fortinet", "system_status")
    reads = []

    def device(auth, platform, command, **_):
        reads.append(command)
        return 0, "Version: FortiADC-KVM v7.6.7,build0676,260522 (GA.M)\n"

    monkeypatch.setattr(engine, "read_from_device", device)
    for _ in range(2):
        with pytest.raises(engine._ProductIdentityError):
            engine._verified_read(target, "fortinet", "get system performance status")
    assert reads == [engine._IDENTITY_COMMAND, engine._IDENTITY_COMMAND]


def test_fortiadc_identity_is_probed_before_every_fresh_query(monkeypatch) -> None:
    platform, command = "fortiadc", "get system performance"
    reads = []

    def device(auth, platform, command, **_):
        reads.append(command)
        return 0, FORTIADC_STATUS

    monkeypatch.setattr(engine, "read_from_device", device)
    target = _target(platform, "system_status")
    for _ in range(2):
        engine._verified_read(target, platform, command)
    assert reads == [engine._IDENTITY_COMMAND, command] * 2


def test_the_fortinet_system_status_query_is_one_connection_without_a_wait(
    wire, monkeypatch,
) -> None:
    clock = _install_clock(monkeypatch)
    _warm_host_key_cache(clock)
    _fortios_wire(wire)
    target = _target("fortinet", "system_status")

    result = engine.ssh_read(target, "fortinet", "system_status", {}, 0, 16_000)
    assert result["ok"] is True
    assert [call["argv"][-1] for call in _calls(wire)] == [engine._IDENTITY_COMMAND]
    assert clock.sleeps == []


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
    query_name = "system_status"
    _fortios_wire(wire)
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
    query_name = "system_status"
    target = _target("fortinet", query_name)

    fake_starts: list[float] = []
    windows: list[tuple[float, float]] = []
    entrants = threading.Barrier(3, timeout=30)
    original_lane_for = engine._lane_for

    def lane_for(*args):
        lane = original_lane_for(*args)
        entrants.wait()
        return lane

    monkeypatch.setattr(engine, "_lane_for", lane_for)
    recordings_lock = threading.Lock()

    def fake_run_command(*args, **kwargs):
        fake_started = clock.monotonic()
        clock.sleep(0.05)
        finished = clock.monotonic()
        with recordings_lock:
            fake_starts.append(fake_started)
            windows.append((fake_started, finished))
        return engine.core_ssh.Result(
            rc=0, stdout=FORTIOS_STATUS.encode(), said="", started_at="", finished_at="",
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
        thread.join(30)
        assert not thread.is_alive()

    assert len(results) == 3
    assert all(result["ok"] is True for result in results)

    windows.sort()
    assert len(windows) == 3
    assert windows[0][1] <= windows[1][0]
    assert windows[1][1] <= windows[2][0]

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
    query_name = "system_status"
    _fortios_wire(wire)
    target = _target("fortinet", query_name)

    first = engine.ssh_read(target, "fortinet", query_name, {}, 0, 16_000)
    assert first["ok"] is True
    assert len(_keyscans(wire)) == 1
    assert len(clock.sleeps) == 1
    assert clock.sleeps[0] == pytest.approx(5.0)


def test_a_populated_platform_preamble_is_paced_like_the_query_itself(wire, monkeypatch) -> None:
    clock = _install_clock(monkeypatch)
    monkeypatch.setattr(
        engine, "_CONNECTION_SPACING_SECONDS",
        {**engine._CONNECTION_SPACING_SECONDS, "extreme_exos": 5.0},
    )
    monkeypatch.setattr(engine, "_PLATFORM_PREAMBLE", {"extreme_exos": ("disable cli paging",)})
    _warm_host_key_cache(clock)
    query_name, _ = _plain_query("extreme_exos")
    target = _target("extreme_exos", query_name)

    result = engine.ssh_read(target, "extreme_exos", query_name, {}, 0, 16_000)
    assert result["ok"] is True
    assert len(clock.sleeps) == 3
    assert clock.sleeps == pytest.approx([5.0, 5.0, 5.0])


@pytest.mark.parametrize("duration", [0.04, 6.0])
@pytest.mark.parametrize("second_role", ["read", "locate"])
def test_locate_and_other_process_share_spacing_and_serialization(duration, second_role):
    import multiprocessing
    context = multiprocessing.get_context("fork")
    start = context.Event()
    events = context.Queue()
    shared_clock = context.Value('d', 1000.0)
    def now():
        return shared_clock.value
    def pause(seconds):
        with shared_clock.get_lock():
            shared_clock.value += seconds
    def worker(role):
        from netops_helper import locate
        original_budget = locate.Budget
        locate.Budget = lambda: original_budget(now)
        engine._now = now
        engine._sleep = pause
        engine._resolve_target_ipv4 = lambda auth: (LOOPBACK,)
        engine.host_key_line = lambda *a: KNOWN_HOSTS_LINE
        engine.record = lambda *a, **k: None
        target = replace(_target("fortinet", "system_status"), device_types=("firewall",),
                         enabled_queries=("system_status", "arp_table"))
        def command(*args, **kwargs):
            began = now()
            pause(duration)
            ended = now()
            events.put((role, began, ended))
            output = FORTIOS_STATUS if args[5] == engine._IDENTITY_COMMAND else ""
            return engine.core_ssh.Result(rc=0, stdout=output.encode(), said="", started_at="", finished_at="")
        engine.core_ssh.run_command = command
        assert start.wait(30)
        if role.startswith("locate"):
            result = engine._locate_endpoint_run([target], "192.0.2.10")
            assert result["reads"] >= 2
        else:
            assert engine.ssh_read(target, "fortinet", "system_status", {}, 0, 16000)["ok"]
    processes = [context.Process(target=worker, args=("locate-1",)),
                 context.Process(target=worker, args=(second_role + "-2",))]
    try:
        for process in processes:
            process.start()
        start.set()
        for process in processes:
            process.join(30)
        assert all(process.exitcode == 0 for process in processes)
        count = 4 if second_role == "locate" else 3
        windows = sorted([events.get(timeout=5) for _ in range(count)], key=lambda item: item[1])
        assert len({role for role, _, _ in windows}) == 2
        for previous, current in zip(windows, windows[1:]):
            assert current[1] >= previous[2], "SSH connections overlapped across processes"
            assert current[1] - previous[1] == pytest.approx(max(5.0, duration)), "cross-process start spacing was bypassed"
    finally:
        for process in processes:
            if process.is_alive():
                process.kill()
            process.join()
        events.close()


def test_ssh_lane_refuses_unsafe_directory_and_corrupt_timestamp(tmp_path):
    engine._lane_directory().mkdir(mode=0o755)
    with pytest.raises(ValueError, match="directory is unsafe"):
        with engine._paced_connection(LOOPBACK, PORT, "fortinet"):
            pytest.fail("unsafe lane admitted connection")
    engine._lane_directory().chmod(0o700)
    with engine._paced_connection(LOOPBACK, PORT, "fortinet"):
        pass
    lane, = engine._lane_directory().iterdir()
    lane.write_bytes(b"broken")
    with pytest.raises(ValueError, match="timestamp is invalid"):
        with engine._paced_connection(LOOPBACK, PORT, "fortinet"):
            pytest.fail("corrupt lane admitted connection")
