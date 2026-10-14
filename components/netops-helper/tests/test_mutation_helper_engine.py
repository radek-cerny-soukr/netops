"""Edge contracts of the engine's paging, receive budgets and device reads.

The fakes stand in only for the network (SSH run, PTY session, FTP peer);
every limit under test runs in the real engine code.
"""

from __future__ import annotations

from base64 import b64encode
from dataclasses import replace
import ipaddress
import threading

from netops_core.hostkey import fingerprint_of
import pytest

from netops_helper.auth import EgressPolicy, TargetAuth
import netops_helper.engine as engine


ADDRESS = str(ipaddress.IPv4Address((192 << 24) | (2 << 8) | 30))
OTHER_ADDRESS = str(ipaddress.IPv4Address((192 << 24) | (2 << 8) | 31))
HOST_KEY_BLOB = b64encode(b"mutation-test-host-key").decode("ascii")
PROMPT = b"ruckus#"


def _auth(platform: str = "fortinet") -> TargetAuth:
    return TargetAuth(
        alias="device-m", host=ADDRESS, port=22, login="reader", secret="credential-m",
        host_key_fingerprint=fingerprint_of(HOST_KEY_BLOB), credential_kind="password",
        sftp_roots=("/safe",), read_inventory={}, account_role="read-only",
        fortios_output_standard_verified=True, ssh_platform=platform,
        enabled_queries=("system_status",),
        egress=EgressPolicy(addresses=(ADDRESS,), tcp_ports=(22, 2222), udp_ports=(),
                            tcp_port_ranges=(), allow_icmp=False),
        legacy_ssh=None,
    )


@pytest.fixture(autouse=True)
def _offered_host_key(monkeypatch) -> None:
    def scan(host, port, pin, timeout_seconds, run=None, legacy=None):
        return f"{host} ssh-ed25519 {HOST_KEY_BLOB}"

    monkeypatch.setattr(engine.core_hostkey, "scan", scan)


def test_an_offset_past_the_end_is_refused_and_the_end_is_complete() -> None:
    with pytest.raises(ValueError):
        engine._page_text("abc", 4, 1_000)
    last = engine._page_text("abc", 3, 1_000)
    assert last["returned_bytes"] == 0 and last["complete"] and last["next_offset"] is None


@pytest.mark.parametrize(("lead", "character"), [
    (999, "é"), (999, "ř"), (998, "€"), (999, "€"), (997, "😀"), (999, "😀"),
])
def test_a_page_stops_just_before_a_partial_character(lead, character) -> None:
    text = "a" * lead + character + "b" * 10
    raw = text.encode("utf-8")
    first = engine._page_text(text, 0, 1_000)
    assert first["untrusted_device_output"] == "a" * lead
    assert first["returned_bytes"] == lead
    assert first["next_offset"] == lead and first["complete"] is False
    assert first["total_bytes"] == len(raw)
    second = engine._page_text(text, first["next_offset"], 1_000)
    assert second["untrusted_device_output"] == character + "b" * 10
    assert second["returned_bytes"] == len(raw) - lead
    assert second["next_offset"] is None and second["complete"] is True


def test_pagination_limits_include_their_maximum() -> None:
    assert engine._validate_pagination(8_000_000, 48_000) == (8_000_000, 48_000)
    assert engine._validate_pagination(0, 1_000) == (0, 1_000)
    for offset, max_bytes in ((8_000_001, 1_000), (0, 48_001), (0, 999), (-1, 1_000), (True, 1_000)):
        with pytest.raises(ValueError):
            engine._validate_pagination(offset, max_bytes)


def test_timeouts_include_both_ends_and_refuse_everything_else() -> None:
    assert engine._bounded_timeout(0.2, "timeout", 0.2, 15.0) == 0.2
    assert engine._bounded_timeout(15, "timeout", 0.2, 15.0) == 15
    for value in (100, 0.1, 15.5, "5", float("nan"), float("inf"), True, None):
        with pytest.raises(ValueError):
            engine._bounded_timeout(value, "timeout", 0.2, 15.0)


def test_the_pty_body_drops_echo_blank_lines_and_prompt_only() -> None:
    data = b"\r\n\r\n show sysinfo \r\n\r\nline one\r\nline \xff two\r\n\r\nruckus#"
    assert engine._pty_body(data, "show sysinfo", PROMPT) == "line one\nline � two"
    assert engine._pty_body(b"show sysinfo\r\nfirst\r\n\r\nsecond\r\nruckus#", "show sysinfo", PROMPT) == "first\n\nsecond"
    assert engine._pty_body(b"other\r\nout\r\nruckus#", "show sysinfo", PROMPT) == "other\nout"
    assert engine._pty_body(PROMPT, "show sysinfo", PROMPT) == ""
    assert engine._pty_body(b"\r\n\r\n", "show sysinfo", PROMPT) == ""


class _Result:
    def __init__(self, stdout: bytes) -> None:
        self.rc, self.stdout, self.said = 0, stdout, ""


def test_exec_output_with_invalid_utf8_is_replaced_not_fatal(monkeypatch) -> None:
    monkeypatch.setattr(engine.core_ssh, "run_command",
                        lambda *args, **kwargs: _Result(b"status \xff\xfe ok\n"))
    rc, text = engine._exec_read(_auth(), "fortinet", "get system status")
    assert rc == 0
    assert "�" in text and "ok" in text


class _Session:
    created: list = []
    failure: Exception | None = None

    def __init__(self, host, port, login, credential, known_hosts_line, **options) -> None:
        if _Session.failure is not None:
            raise _Session.failure
        _Session.created.append({"host": host, "port": port, "login": login, **options})
        self.answers = iter([b"Please login:", b"Password:", b"ruckus>", PROMPT,
                             b"show sysinfo\r\nsysinfo marker\r\nruckus#"])
        self.sent: list = []

    def expect(self, patterns, timeout):
        return 0, next(self.answers)

    def discard(self, seen) -> None:
        pass

    def send(self, text) -> None:
        self.sent.append(text)

    def close(self) -> None:
        pass


def test_the_pty_session_logs_in_as_the_enrolled_account_with_a_bound(monkeypatch) -> None:
    _Session.created, _Session.failure = [], None
    monkeypatch.setattr(engine.core_session, "Session", _Session)
    assert engine._pty_read(_auth("ruckus_unleashed"), "ruckus_unleashed", "show sysinfo") == (
        None, "sysinfo marker",
    )
    session = _Session.created[0]
    assert (session["host"], session["port"], session["login"]) == (ADDRESS, 22, "reader")
    assert 0 < session["timeout_seconds"] <= 60


def test_a_failed_pty_session_forgets_the_host_key_of_that_device(monkeypatch) -> None:
    _Session.created, _Session.failure = [], engine.core_session.SessionError("refused")
    monkeypatch.setattr(engine.core_session, "Session", _Session)
    with pytest.raises(engine.core_session.SessionError):
        engine._pty_read(_auth("ruckus_unleashed"), "ruckus_unleashed", "show sysinfo")
    assert not [key for key in engine._HOST_KEY_LINE_CACHE if key[0] == ADDRESS]
    _Session.failure = None


def test_reads_of_two_devices_never_queue_behind_each_other(monkeypatch) -> None:
    _Session.created, _Session.failure = [], None
    entered, release = threading.Event(), threading.Event()

    class Held(_Session):
        def __init__(self, host, port, *args, **options) -> None:
            super().__init__(host, port, *args, **options)
            self.held = (host, port) == (ADDRESS, 22)

        def expect(self, patterns, timeout):
            if self.held:
                self.held = False
                entered.set()
                release.wait(10)
            return super().expect(patterns, timeout)

    monkeypatch.setattr(engine.core_session, "Session", Held)
    base = _auth("ruckus_unleashed")
    first = threading.Thread(target=engine._pty_read, args=(base, "ruckus_unleashed", "show sysinfo"))
    first.start()
    try:
        assert entered.wait(5)
        others = (
            replace(base, port=2222),
            replace(base, host=OTHER_ADDRESS, egress=replace(base.egress, addresses=(OTHER_ADDRESS,))),
        )
        for other in others:
            read = threading.Thread(
                target=engine._pty_read, args=(other, "ruckus_unleashed", "show sysinfo"), daemon=True,
            )
            read.start()
            read.join(5)
            assert not read.is_alive()
    finally:
        release.set()
        first.join(10)


class _Budget:
    def __init__(self) -> None:
        self.data = None

    def call(self, function, *args):
        return function(*args)

    def remaining(self) -> float:
        return 30.0


class _Peer:
    def __init__(self, payload: bytes, budget: _Budget) -> None:
        self.payload, self.budget, self.sizes = bytearray(payload), budget, []

    def recv(self, size: int) -> bytes:
        assert self.budget.data is self
        self.sizes.append(size)
        chunk = bytes(self.payload[:size])
        del self.payload[:size]
        return chunk

    def close(self) -> None:
        pass


class _Client:
    encoding = "utf-8"

    def __init__(self, peer: _Peer) -> None:
        self.peer = peer

    def voidcmd(self, command) -> None:
        pass

    def transfercmd(self, command) -> _Peer:
        return self.peer

    def voidresp(self) -> None:
        pass


def _names(payload: bytes):
    budget = _Budget()
    peer = _Peer(payload, budget)
    return engine._bounded_ftp_names(_Client(peer), "/safe", budget), peer


def test_ftp_names_keep_an_unterminated_last_line_without_its_cr() -> None:
    assert _names(b"a\r\nb\r\nc\r")[0] == (["a", "b", "c"], False)


@pytest.mark.parametrize("terminated", [True, False])
def test_ftp_names_are_truncated_only_beyond_the_name_limit(terminated) -> None:
    limit = engine._FTP_LIST_MAX_NAMES
    tail = b"\n" if terminated else b""
    exact = b"\n".join(b"n%d" % index for index in range(limit)) + tail
    names, truncated = _names(exact)[0]
    assert (len(names), truncated) == (limit, False)
    over = b"\n".join(b"n%d" % index for index in range(limit + 1)) + tail
    names, truncated = _names(over)[0]
    assert (len(names), truncated) == (limit, True)


def test_ftp_listing_accepts_exactly_its_byte_budget() -> None:
    limit = engine._FTP_LIST_MAX_BYTES
    (names, truncated), peer = _names(b"x" * (limit - 1) + b"\n")
    assert len(names) == 1 and truncated is False
    assert max(peer.sizes) <= 65_536


def test_ftp_listing_never_asks_past_its_byte_budget() -> None:
    limit = engine._FTP_LIST_MAX_BYTES
    budget = _Budget()
    peer = _Peer(b"y" * (limit + 200_000), budget)
    with pytest.raises(ValueError):
        engine._bounded_ftp_names(_Client(peer), "/safe", budget)
    assert sum(peer.sizes) <= limit + 1
    assert max(peer.sizes) <= 65_536


class _ControlClient:
    encoding = "utf-8"

    def __init__(self, lines) -> None:
        self.lines = iter(lines)

    def getline(self) -> str:
        return next(self.lines)


def test_ftp_control_replies_fill_their_budget_exactly_then_stop() -> None:
    half = engine._FTP_CONTROL_MAX_BYTES // 2 - 2
    client = _ControlClient(["a" * half, "b" * half, ""])
    engine._install_ftp_control_budget(client)
    assert client.getline() == "a" * half
    assert client.getline() == "b" * half
    with pytest.raises(ValueError):
        client.getline()


def test_cached_output_expires_exactly_at_its_ttl(monkeypatch) -> None:
    now = [1_000.0]
    monkeypatch.setattr(engine, "_SSH_PAGE_CACHE", {})
    monkeypatch.setattr(engine.time, "monotonic", lambda: now[0])
    engine._store_cached_ssh_output(("k",), 7, "out")
    assert engine._load_cached_ssh_output(("k",)) == (7, "out")
    now[0] += engine._SSH_CACHE_TTL_SECONDS
    assert engine._load_cached_ssh_output(("k",)) is None


def test_a_full_cache_evicts_the_oldest_entry(monkeypatch) -> None:
    now = [1_000.0]
    monkeypatch.setattr(engine, "_SSH_PAGE_CACHE", {})
    monkeypatch.setattr(engine.time, "monotonic", lambda: now[0])
    size = engine._SSH_CACHE_MAX_ENTRIES
    for index in range(size):
        now[0] = 1_000.0 + index
        engine._store_cached_ssh_output((f"k{size - 1 - index}",), size - 1 - index, "out")
    now[0] += 1
    engine._store_cached_ssh_output(("new",), 0, "out")
    assert set(engine._SSH_PAGE_CACHE) == {("new",), *((f"k{index}",) for index in range(size - 1))}
