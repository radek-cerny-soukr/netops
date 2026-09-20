import os
import pty
import sys
import tempfile
import time

import pytest

from netops_core import session as session_module
from netops_core.legacy_ssh import LegacySshError
from netops_core.session import TTY_OPTION, Session, SessionError, argv
from netops_core.ssh import CONFIG_FILE, OPTIONS, PASSWORD_OPTIONS

HOST = "192.0.2.10"
PORT = 22
LOGIN = "audit-ro"
BLOB = "cmVwbGFjZS1tZS1ob3N0LWtleS1tYXRlcmlhbC1B"
HOST_KEY_LINE = "%s ssh-ed25519 %s" % (HOST, BLOB)
CANARY_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nKANARCI-KLIC-NESMI-UNIKNOUT\n"
CANARY_PASSWORD = "KANARCI-HESLO-NESMI-UNIKNOUT"
NOISE = "KANARCI-VYPIS-NESMI-UNIKNOUT"
LEGACY_PROFILE = "rsa-sha1"
LEGACY_OPTIONS = ("HostKeyAlgorithms=+ssh-rsa", "PubkeyAcceptedAlgorithms=+ssh-rsa")
CHILD = "\n".join(
    (
        "import sys",
        "write = sys.stdout.write",
        "write('Please login: ')",
        "sys.stdout.flush()",
        "sys.stdin.readline()",
        "write('password : ')",
        "sys.stdout.flush()",
        "sys.stdin.readline()",
        "while True:",
        "    write('ruckus> ')",
        "    sys.stdout.flush()",
        "    line = sys.stdin.readline()",
        "    if not line or line.strip() == 'exit':",
        "        break",
        "    write('you said ' + line.strip() + chr(10))",
        "    sys.stdout.flush()",
    )
)
QUIET = "\n".join(
    ("import sys, time", "sys.stdout.write(%r)" % NOISE, "sys.stdout.flush()", "time.sleep(5)")
)
STUBBORN = "\n".join(
    ("import signal, time", "signal.signal(signal.SIGHUP, signal.SIG_IGN)", "time.sleep(30)")
)


class FakeCredential:
    def __init__(self, kind, secret, login=LOGIN, name="sw-a-ro"):
        self.name = name
        self.kind = kind
        self.login = login
        self._secret = secret
        self.uses = 0

    def use(self):
        self.uses += 1
        return self._secret

    def __repr__(self):
        return "<FakeCredential %s %s>" % (self.name, self.kind)


class PtySpawn:
    def __init__(self, script=CHILD):
        self.script = script
        self.calls = []
        self.pid = None

    def __call__(self, call, env):
        self.calls.append({"argv": list(call), "env": dict(env)})
        pid, fd = pty.fork()
        if pid == 0:
            try:
                os.execve(sys.executable, [sys.executable, "-I", "-c", self.script], env)
            finally:
                os._exit(127)
        self.pid = pid
        return pid, fd

    def argv(self, index=0):
        return self.calls[index]["argv"]

    def env(self, index=0):
        return self.calls[index]["env"]


def key_credential():
    return FakeCredential("ssh-key", CANARY_KEY)


def password_credential():
    return FakeCredential("password", CANARY_PASSWORD)


def session(spawn, credential=None, **kwargs):
    holder = key_credential() if credential is None else credential
    return Session(HOST, PORT, LOGIN, holder, HOST_KEY_LINE, spawn=spawn, **kwargs)


def options_of(line):
    return [line[index] for index in range(len(line)) if line[index - 1] == "-o"]


def test_argv_asks_for_a_terminal_and_carries_every_hardening_option():
    line = argv(HOST, 2222, LOGIN, "/w/known_hosts", identity="/w/identity")
    assert line[0] == "ssh"
    assert line[1:4] == ["-F", CONFIG_FILE, TTY_OPTION]
    assert options_of(line) == list(OPTIONS) + ["UserKnownHostsFile=/w/known_hosts"]
    assert line[-3:] == ["-p", "2222", "%s@%s" % (LOGIN, HOST)]
    assert line[line.index("-i") + 1] == "/w/identity"


def test_argv_without_an_identity_switches_to_the_password_options():
    line = argv(HOST, PORT, LOGIN, "/w/known_hosts")
    assert TTY_OPTION in line
    assert "-i" not in line
    assert options_of(line) == list(PASSWORD_OPTIONS) + ["UserKnownHostsFile=/w/known_hosts"]


def test_argv_appends_the_legacy_options_behind_the_bound_ones():
    line = argv(HOST, PORT, LOGIN, "/w/known_hosts", identity="/w/identity", legacy=LEGACY_PROFILE)
    assert options_of(line) == list(OPTIONS) + list(LEGACY_OPTIONS) + [
        "UserKnownHostsFile=/w/known_hosts"
    ]
    for option in LEGACY_OPTIONS:
        assert line.index(option) > line.index(OPTIONS[-1])


def test_a_session_starts_ssh_with_a_terminal_and_the_pinned_key():
    spawn = PtySpawn()
    handle = session(spawn)
    try:
        line = spawn.argv()
        assert line[1:4] == ["-F", CONFIG_FILE, TTY_OPTION]
        for option in OPTIONS:
            assert line.count(option) == 1
            assert line[line.index(option) - 1] == "-o"
        pointed = [entry for entry in line if entry.startswith("UserKnownHostsFile=")]
        assert len(pointed) == 1
        path = pointed[0].split("=", 1)[1]
        assert os.path.dirname(path) == handle.workspace()
        assert open(path, encoding="utf-8").read() == "%s\n" % HOST_KEY_LINE
        assert line[-1] == "%s@%s" % (LOGIN, HOST)
        assert set(spawn.env()) == {"PATH", "HOME", "LC_ALL"}
        assert spawn.env()["HOME"] == handle.workspace()
    finally:
        handle.close()


def test_a_legacy_profile_reaches_the_session_behind_the_base_options():
    spawn = PtySpawn()
    handle = session(spawn, legacy_ssh=LEGACY_PROFILE)
    try:
        line = spawn.argv()
        assert options_of(line)[: len(OPTIONS)] == list(OPTIONS)
        assert options_of(line)[len(OPTIONS) : len(OPTIONS) + 2] == list(LEGACY_OPTIONS)
    finally:
        handle.close()


def test_a_profile_that_is_not_written_down_is_refused_before_anything_starts():
    spawn = PtySpawn()
    with pytest.raises(LegacySshError) as caught:
        session(spawn, legacy_ssh="ssh-rsa")
    assert spawn.calls == []
    assert "no global switch" in str(caught.value)


def test_the_password_never_reaches_argv_or_the_environment():
    spawn = PtySpawn()
    credential = password_credential()
    handle = session(spawn, credential=credential)
    try:
        for entry in spawn.argv():
            assert CANARY_PASSWORD not in entry
        for value in spawn.env().values():
            assert CANARY_PASSWORD not in value
        assert spawn.env()["SSH_ASKPASS_REQUIRE"] == "force"
        assert os.path.dirname(spawn.env()["NETOPS_ASKPASS_FILE"]) == handle.workspace()
        assert "BatchMode=no" in spawn.argv()
        assert credential.uses == 1
    finally:
        handle.close()


def test_the_private_key_never_reaches_argv_or_the_environment():
    spawn = PtySpawn()
    handle = session(spawn, credential=key_credential())
    try:
        for entry in spawn.argv():
            assert CANARY_KEY not in entry
        for value in spawn.env().values():
            assert CANARY_KEY not in value
    finally:
        handle.close()


def test_expect_and_send_drive_a_real_terminal():
    spawn = PtySpawn()
    with session(spawn) as handle:
        index, seen = handle.expect(["password : ", "Please login: "], 10)
        assert index == 1
        assert seen.endswith(b"Please login: ")
        handle.send(LOGIN)
        index, seen = handle.expect(["Please login: ", "password : "], 10)
        assert index == 1
        assert handle.discard(seen) == len(seen)
        handle.send("replace-me")
        assert handle.expect(["ruckus> "], 10)[0] == 0
        handle.send("show version")
        index, seen = handle.expect(["you said show version"], 10)
        assert index == 0
        assert b"you said show version" in seen
        assert handle.discarded_login_bytes > 0


def test_expect_forgets_what_it_handed_over():
    spawn = PtySpawn()
    with session(spawn) as handle:
        _, first = handle.expect(["Please login: "], 10)
        assert b"Please login: " in first
        handle.send(LOGIN)
        _, second = handle.expect(["password : "], 10)
        assert b"Please login: " not in second


def test_a_timeout_names_the_patterns_and_the_bytes_but_never_the_content():
    spawn = PtySpawn(QUIET)
    handle = session(spawn)
    try:
        with pytest.raises(SessionError) as caught:
            handle.expect(["never-shows", "also-never-shows"], 1.5)
        said = str(caught.value)
        assert "2 awaited pattern(s)" in said
        assert "byte(s) seen" in said
        assert HOST in said
        assert NOISE not in said
        assert NOISE not in repr(caught.value)
        assert caught.value.transcript_bytes >= len(NOISE)
    finally:
        handle.close()


def test_a_session_that_ends_without_the_pattern_says_so_without_the_content():
    spawn = PtySpawn("\n".join(("import sys", "sys.stdout.write(%r)" % NOISE)))
    handle = session(spawn)
    try:
        with pytest.raises(SessionError) as caught:
            handle.expect(["never-shows"], 10)
        assert "ended before any of the 1 awaited pattern(s)" in str(caught.value)
        assert NOISE not in str(caught.value)
        assert caught.value.transcript_bytes >= 0
    finally:
        handle.close()


@pytest.mark.parametrize("line", ("show version\nexecute reboot", "show\r", "show\x00"))
def test_send_refuses_a_line_that_carries_another_one(line):
    spawn = PtySpawn()
    with session(spawn) as handle:
        with pytest.raises(SessionError) as caught:
            handle.send(line)
        assert "must be a single line" in str(caught.value)


@pytest.mark.parametrize("line", (None, 7, b"show"))
def test_send_refuses_something_that_is_not_text(line):
    spawn = PtySpawn()
    with session(spawn) as handle:
        with pytest.raises(SessionError) as caught:
            handle.send(line)
        assert "must be text" in str(caught.value)


@pytest.mark.parametrize("patterns", ((), [""], [None], "", 7))
def test_expect_refuses_patterns_it_cannot_wait_for(patterns):
    spawn = PtySpawn()
    with session(spawn) as handle:
        with pytest.raises(SessionError):
            handle.expect(patterns, 1)


def test_close_removes_the_workspace_even_after_an_error():
    spawn = PtySpawn(QUIET)
    handle = session(spawn)
    workspace = handle.workspace()
    assert os.path.isdir(workspace)
    with pytest.raises(SessionError):
        handle.expect(["never-shows"], 0.5)
    assert os.path.isdir(workspace)
    handle.close()
    assert not os.path.exists(workspace)


def test_close_kills_a_child_that_ignores_the_hangup(monkeypatch):
    monkeypatch.setattr(session_module, "KILL_AFTER_SECONDS", 0.3)
    spawn = PtySpawn(STUBBORN)
    handle = session(spawn)
    pid = spawn.pid
    handle.close()
    with pytest.raises(ChildProcessError):
        os.waitpid(pid, os.WNOHANG)
    assert not os.path.exists(handle.workspace())


def test_close_is_idempotent_and_the_session_refuses_to_talk_afterwards():
    spawn = PtySpawn()
    handle = session(spawn)
    handle.close()
    handle.close()
    for call in (lambda: handle.send("show"), lambda: handle.expect(["ruckus> "], 1)):
        with pytest.raises(SessionError) as caught:
            call()
        assert "already closed" in str(caught.value)


def test_the_context_manager_closes_the_session():
    spawn = PtySpawn()
    with session(spawn) as handle:
        workspace = handle.workspace()
        assert os.path.isdir(workspace)
    assert not os.path.exists(workspace)
    with pytest.raises(SessionError):
        handle.send("show version")


def test_a_spawn_that_fails_leaves_no_workspace(monkeypatch):
    created = []
    original = tempfile.mkdtemp

    def recorded(**kwargs):
        created.append(original(**kwargs))
        return created[-1]

    monkeypatch.setattr(session_module.tempfile, "mkdtemp", recorded)

    def boom(call, env):
        raise OSError("ssh binary not found")

    with pytest.raises(SessionError) as caught:
        session(boom)
    assert "cannot open the session to %s" % HOST in str(caught.value)
    assert created and not os.path.exists(created[0])


@pytest.mark.parametrize("kind", ("api-token", "snmp-community", None))
def test_a_credential_of_another_kind_is_refused_before_anything_starts(kind):
    spawn = PtySpawn()
    with pytest.raises(Exception) as caught:
        session(spawn, credential=FakeCredential(kind, CANARY_PASSWORD))
    assert spawn.calls == []
    assert "password or ssh-key" in str(caught.value)


def _deaf_child(marker):
    return "; ".join(
        (
            "import os, signal, time",
            "signal.signal(signal.SIGHUP, signal.SIG_IGN)",
            "open(%r, 'w').write(str(os.getpid()))" % str(marker),
            "time.sleep(30)",
        )
    )


def _parent_of(child):
    return "\n".join(
        (
            "import signal, subprocess, sys, time",
            "signal.signal(signal.SIGHUP, signal.SIG_IGN)",
            "subprocess.Popen([sys.executable, '-c', %r])" % child,
            "time.sleep(30)",
        )
    )


def _pid_of(marker, seconds=5.0):
    deadline = time.monotonic() + seconds
    while True:
        try:
            return int(marker.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
        if time.monotonic() >= deadline:
            raise AssertionError("no process wrote its pid into %s" % marker)
        time.sleep(0.02)


def _ended_within(pid, seconds=5.0):
    deadline = time.monotonic() + seconds
    while True:
        try:
            with open("/proc/%d/stat" % pid, "rb") as handle:
                state = handle.read().rsplit(b")", 1)[1].split()[0]
        except OSError:
            return True
        if state == b"Z":
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.02)


def test_close_stops_the_whole_terminal_group_not_only_the_client(tmp_path, monkeypatch):
    monkeypatch.setattr(session_module, "KILL_AFTER_SECONDS", 0.3)
    marker = tmp_path / "grandchild-pid"
    spawn = PtySpawn(_parent_of(_deaf_child(marker)))
    handle = session(spawn)
    grandchild = _pid_of(marker)
    handle.close()
    with pytest.raises(ChildProcessError):
        os.waitpid(spawn.pid, os.WNOHANG)
    assert _ended_within(grandchild)
