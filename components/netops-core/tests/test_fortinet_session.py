"""Replay real Fortinet captures in the OpenSSH client's PTY.

FortiOS frames and answers come from the multi-VDOM context-197 capture (its
README records the live source). FortiADC pool/erase bytes come from the Admin
7.6.7 build0676 fixture; the refusal comes from Helper's ADC-STATISTICS capture. The HA
prefix on the ADC replay is derived from the FortiADC CLI Reference examples
linked in vendor-cli-references/fortinet-fortiadc.md. Transport timing, the
false prompt, interruption, and the large repeated answer are test additions.
"""

import base64
import errno
import json
import os
import re
import select
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from netops_core import hostkey, inventory, session, ssh
from test_session import CANARY_KEY, CANARY_PASSWORD, key_credential, password_credential

COMPONENTS = Path(__file__).resolve().parents[2]
HELPER = COMPONENTS / "netops-helper/tests/fixtures"
ADC_POOL = COMPONENTS / "netops-admin/tests/fixtures/fortiadc_767_0676/show_load-balance_pool.txt"
ADC_REFUSAL = HELPER / "real/fortiadc/fortiadc-kvm_7.6.7_adc_statistics_20261117/refusal.out"
FG_CONTEXT = HELPER / "real/fortinet/fortigate60f_7.6.8_multivdom/context-197.json"
KEY_TYPE = b"ssh-ed25519"
BLOB = base64.b64encode(b"\0\0\0\x0b" + KEY_TYPE + b"\0\0\0\x20" + bytes(range(32))).decode()
PUBLIC_KEY = "ssh-ed25519 " + BLOB
PIN = hostkey.fingerprint_of(BLOB)
FAKE = r"""
import os
from pathlib import Path
import sys
import time
import tty

with open(EVENTS, "a") as log:
    log.write(Path(sys.argv[0]).name + "\n")
if Path(sys.argv[0]).name == "ssh-keyscan":
    sys.exit(99)
assert "StrictHostKeyChecking=yes" in sys.argv
assert "GlobalKnownHostsFile=/dev/null" in sys.argv
assert "ControlMaster=no" in sys.argv and "ControlPath=none" in sys.argv
assert sys.argv[1:3] == ["-e", "none"] and "UpdateHostKeys=no" in sys.argv
assert sys.argv[-3:] == ["-p", str(PORT), LOGIN + "@" + ADDRESS]
path = Path(next(arg.split("=", 1)[1] for arg in sys.argv if arg.startswith("UserKnownHostsFile=")))
assert path.read_text() == KEY_LINE + "\n"
assert path.stat().st_mode & 0o777 == 0o600
assert path.parent.stat().st_mode & 0o777 == 0o700
assert all(secret not in str(sys.argv) and secret not in str(os.environ) for secret in SECRETS)
tty.setraw(0)
if LOGIN_FAILURE is not None:
    os.write(1, b"banner claiming Permission denied and Host key verification failed\r\n")
    Path(sys.argv[sys.argv.index("-E") + 1]).write_text(LOGIN_FAILURE + "\n")
    sys.exit(255)
os.write(1, b"login banner\r\n" + START)
for command, actions in STEPS:
    assert sys.stdin.buffer.readline() == command + b"\n"
    os.write(1, ECHOES.get(command, command) + b"\r\r\n")
    for action in actions:
        if action == "page":
            key = os.read(0, 1)
            if key == b"\n":
                key = os.read(0, 1)
            with open(EVENTS, "a") as log:
                log.write("pager=" + key.hex() + "\n")
            assert key == b" "
        elif action == "idle":
            time.sleep(10)
        elif action == "drip":
            while True:
                os.write(1, b"x")
                time.sleep(0.02)
        elif action == "exit":
            sys.exit(1)
        elif isinstance(action, float):
            time.sleep(action)
        else:
            for _ in range(action[0] if isinstance(action, tuple) else 1):
                data = action[1] if isinstance(action, tuple) else action
                while data:
                    data = data[os.write(1, data):]
    last = actions[-1]
    if isinstance(last, bytes) and last.endswith((b"# ", b"$ ")):
        assert sys.stdin.buffer.readline() == b"\n"
        os.write(1, b"\r\r\n" + last)
sys.stdin.buffer.read()
"""


def _device(**changes):
    fields = dict(platform="fortios", address="192.0.2.10", port=2222, legacy_ssh=None,
                  host_key_fingerprint=PIN, host_key=PUBLIC_KEY)
    return SimpleNamespace(**(fields | changes))


@pytest.fixture
def fake_ssh(tmp_path, monkeypatch):
    events = tmp_path / "events"
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))

    def install(start, steps, *, address="192.0.2.10", port=2222, login="audit-ro", login_failure=None, echoes=None):
        host = address if port == 22 else f"[{address}]:{port}"
        values = dict(EVENTS=str(events), KEY_LINE=f"{host} {PUBLIC_KEY}", PORT=port,
                      ADDRESS=address, LOGIN=login, SECRETS=(CANARY_KEY.strip(), CANARY_PASSWORD),
                      START=start, STEPS=steps, LOGIN_FAILURE=login_failure, ECHOES=echoes or {})
        script = f"#!{sys.executable}\n" + "".join(f"{key} = {value!r}\n" for key, value in values.items())
        for name in ("ssh", "ssh-keyscan"):
            client = tmp_path / name
            client.write_text(script + FAKE)
            client.chmod(0o700)
        return lambda: events.read_text().splitlines() if events.exists() else []

    return install


def _fortios_capture(name):
    transcript = json.loads(FG_CONTEXT.read_text())[name].encode()
    frames = list(re.finditer(rb"(?m)^(FortiGate-60F (?:\([^\n]*\) )?[#$] )([^\n]*)", transcript))
    steps = [(here[2], [transcript[here.end() + 1:nxt.start()].replace(b"\n", b"\r\n"), nxt[1]])
             for here, nxt in zip(frames, frames[1:])]
    return frames[0][1], steps


def test_fortios_wrapped_command_echo_is_not_part_of_the_answer(fake_ssh):
    command = b"diagnose switch-controller switch-info port-stats S000SSSS00000001 port5"
    wrapped = command[:-8] + b" \x08" + command[-8:]
    prompt = b"FortiGate-60F # "
    answer = b"Vdom: root\nThe same marker in output stays byte-for-byte: \x08ok\n"
    events = fake_ssh(prompt, [(command, [answer, prompt])], echoes={command: wrapped})

    with session.fortinet_session(_device(), key_credential()) as shell:
        result = shell.run(command.decode())

    assert result.rc == 0
    assert result.stdout == answer
    assert events() == ["ssh"]


@pytest.mark.parametrize(("name", "contexts", "codes"), [
    ("197-34-gdiag-global", ["global", None], [0, 0]),
    ("197-35-diag-root", ["vdom", "root", "root", "root"], [0, 0, 0, 1]),
    ("197-33-diag-noconfig", [None], [1]),
])
def test_fortios_captured_contexts_and_refusals(fake_ssh, name, contexts, codes):
    initial, steps = _fortios_capture(name)
    events = fake_ssh(initial, steps)
    with session.fortinet_session(_device(platform="fortinet"), key_credential()) as shell:
        results = [shell.run(command.decode()) for command, _ in steps]
        workspace = Path(shell.workspace())
    assert [answer.context for answer in results] == contexts
    assert [answer.rc for answer in results] == codes
    assert [answer.stdout for answer in results] == [
        body.replace(b"\r\n", b"\n") if rc == 0 else b"" for (_, (body, _)), rc in zip(steps, codes)
    ]
    assert all(answer.said == "" and answer.stderr == b"" for answer in results)
    assert events() == ["ssh"]
    assert not workspace.exists()


def _adc_pool():
    initial, _, capture = ADC_POOL.read_bytes().partition(b" # ")
    body, _, _ = capture.rpartition(initial + b" # ")
    pages = re.split(rb"--More-- (\r {9}\r)", body)
    steps = [pages[0]]
    for erase, page in zip(pages[1::2], pages[2::2]):
        steps.extend([b"--Mo", b"re-- " + erase[:1], "page", erase[1:3], 0.01, erase[3:] + page])
    return initial + b" # ", body, steps


def test_fortiadc_ha_pager_false_prompt_and_refusal_in_one_process(fake_ssh):
    initial, body, pages = _adc_pool()
    prompt = b"(P) " + initial
    refusal = ADC_REFUSAL.read_bytes().split(b"\n", 1)[1].split(initial)[0]
    events = fake_ssh(prompt, [
        (b"show load-balance pool", [prompt, 0.25, b"\r\n", *pages, prompt]),
        (b"diagnose server-load-balance slb_load extra", [refusal, prompt]),
        (b"get system status", [b"\r\n", prompt]),
    ], address="check.example.invalid", port=22, login="check")
    with session.fortinet_session(_device(platform="fortiadc"), password_credential(),
                                  address="check.example.invalid", port=22, login="check") as shell:
        answer = shell.run("show load-balance pool")
        assert answer.rc == 0
        assert answer.stdout == prompt + b"\n" + re.sub(rb"--More-- \r {9}\r", b"", body)
        assert shell.run("diagnose server-load-balance slb_load extra").refusal == "device_cli_error"
        assert shell.run("get system status").rc == 0
    assert events() == ["ssh", "pager=20", "pager=20"]


def test_fortiadc_read_only_prompt_preserves_prompt_like_output(fake_ssh):
    # Sanitized fortiadc-kvm netops-read prompt captured in a live acceptance run.
    prompt = b"LLLLLLLL-LLL $ "
    body = b"prefix " + prompt + b"\r\n" + prompt + b"suffix\r\n"
    events = fake_ssh(prompt, [(b"get system status", [body, prompt])])
    with session.fortinet_session(_device(platform="fortiadc"), key_credential()) as shell:
        answer = shell.run("get system status")
    assert answer.rc == 0
    assert answer.stdout == body.replace(b"\r\n", b"\n")
    assert events() == ["ssh"]


@pytest.mark.parametrize(("diagnostic", "code"), [
    ("reader@192.0.2.10: Permission denied (password).", "auth"),
    ("Host key verification failed.", "host_key"),
    ("Unable to negotiate with 192.0.2.10: no matching host key type found.", "negotiation"),
    ("Connection closed by 192.0.2.10 port 2222", "disconnected"),
    ("", "disconnected"),
])
def test_login_failure_uses_client_verdict_only(fake_ssh, diagnostic, code):
    events = fake_ssh(b"", [], login_failure=diagnostic)
    with pytest.raises(session.SessionError) as error:
        session.fortinet_session(_device(), key_credential())
    assert error.value.code == code
    assert "192.0.2.10" not in str(error.value)
    assert events() == ["ssh"]


def test_continuation_is_explicit_and_the_next_line_uses_the_same_shell(fake_ssh):
    prompt = b"FortiGate-60F (root) # "
    events = fake_ssh(prompt, [
        (b'set comments "first', [b"> "]),
        (b'second"', [prompt]),
    ])
    with session.fortinet_session(_device(), key_credential()) as shell:
        answer = shell.run('set comments "first')
        assert answer.continuation and answer.rc != 0 and answer.context == "root"
        assert shell.run('second"').rc == 0
    assert events() == ["ssh"]


@pytest.mark.parametrize(("changes", "detail"), [
    ({"host_key": None}, "add host_key"),
    ({"host_key_fingerprint": "SHA256:" + "A" * 43}, "does not match"),
    ({"host_key_fingerprint": "CANARY-invalid-fingerprint"}, "SHA-256"),
    ({"host_key": "ssh-rsa " + BLOB}, "OpenSSH public key"),
    ({"host_key": "CANARY-invalid-key"}, "OpenSSH public key"),
    ({"address": "bad,alternate.example"}, "address"),
])
def test_bad_pin_refuses_before_credentials_or_client(fake_ssh, changes, detail):
    events = fake_ssh(b"FortiGate-60F # ", [])
    credential = key_credential()
    with pytest.raises(hostkey.HostKeyError, match=detail) as error:
        with session.fortinet_session(_device(**changes), credential):
            pytest.fail("accepted an invalid pin")
    assert "CANARY" not in str(error.value)
    assert credential.uses == 0
    assert events() == []


def test_optional_inventory_host_key_is_validated(tmp_path):
    path = tmp_path / "inventory.json"
    target = vars(_device()) | dict(name="fortigate", role="lab", credential=None,
                                    auditor={}, helper=None)
    del target["host_key"]
    path.write_text(json.dumps({"version": 2, "devices": [target]}))
    assert inventory.load(path)[0].host_key is None
    for key in (None, PUBLIC_KEY, "CANARY-private-material"):
        entry = target | {"host_key": key}
        path.write_text(json.dumps({"version": 2, "devices": [entry]}))
        if key == "CANARY-private-material":
            with pytest.raises(inventory.InventoryError) as error:
                inventory.load(path)
            assert error.value.diagnostic == ("inventory.devices[].host_key", "ssh-public-key")
            assert "CANARY" not in str(error.value)
        else:
            assert inventory.load(path)[0].host_key == key


def test_large_output_and_a_long_line_stream_in_bounded_chunks(fake_ssh):
    prompt = b"FortiGate-60F # "
    _, captured = _fortios_capture("197-35-diag-root")
    body = captured[2][1][0]
    long_line = b"x" * 20000
    events = fake_ssh(prompt, [(b"show", [(3200, body), long_line, b"\n", prompt])])
    chunks = []
    with session.fortinet_session(_device(), key_credential(), capture_max_bytes=8 * 1024 * 1024) as shell:
        answer = shell.run("show", stdout_consumer=chunks.append)
        assert answer.stdout == b""
    assert b"".join(chunks) == body.replace(b"\r\n", b"\n") * 3200 + long_line + b"\n"
    assert max(map(len, chunks)) < 65536
    assert events() == ["ssh"]


@pytest.mark.parametrize(("actions", "options", "code"), [
    (["idle"], {"idle_timeout_seconds": 0.22}, "idle_timeout"),
    (["drip"], {"timeout_seconds": 0.28}, "timeout"),
    (["exit"], {}, "disconnected"),
    ([b"x" * 2000], {"capture_max_bytes": 200}, "output_limit"),
    ([b"--More-- "], {"max_pages": 0}, "page_limit"),
])
def test_incomplete_command_closes_the_client_and_withholds_the_transcript(fake_ssh, actions, options, code):
    prompt = b"FortiGate-60F # "
    events = fake_ssh(prompt, [(b"show", [b"private-CANARY\r\n", *actions])])
    with session.fortinet_session(_device(), key_credential()) as shell:
        workspace = Path(shell.workspace())
        with pytest.raises(session.SessionError) as error:
            shell.run("show", **options)
        assert error.value.code == code
        assert "CANARY" not in str(error.value)
        assert not error.value.final
        assert not workspace.exists()
    assert events() == ["ssh"]


@pytest.mark.parametrize("failure", [ValueError("private-CANARY"), KeyboardInterrupt()])
def test_consumer_failure_and_interruption_close_the_session(fake_ssh, failure):
    prompt = b"FortiGate-60F # "
    events = fake_ssh(prompt, [(b"show", [b"private-CANARY\r\n", prompt])])
    def interrupt(chunk):
        raise failure
    with session.fortinet_session(_device(), key_credential()) as shell:
        workspace = Path(shell.workspace())
        expected = KeyboardInterrupt if isinstance(failure, KeyboardInterrupt) else ssh.OutputConsumerError
        with pytest.raises(expected) as error:
            shell.run("show", stdout_consumer=interrupt)
        assert "CANARY" not in str(error.value)
        assert not workspace.exists()
    assert events() == ["ssh"]


def test_login_timeout_discards_banner_and_closes_the_client(fake_ssh, tmp_path):
    events = fake_ssh(b"private-CANARY", [])
    with pytest.raises(session.SessionError) as error:
        # Allow the fixture's Python process to start under parallel test load.
        session.fortinet_session(_device(), key_credential(), connect_timeout_seconds=3)
    assert error.value.code == "timeout"
    assert "CANARY" not in str(error.value) and not error.value.final
    assert events() == ["ssh"]
    assert list(tmp_path.glob("netops-core-*")) == []


@pytest.mark.parametrize(("changes", "options", "code"), [
    ({"platform": "private-CANARY"}, {}, "invalid_platform"),
    ({}, {"capture_max_bytes": 0}, "invalid_limits"),
    ({}, {"connect_timeout_seconds": 0}, "invalid_session"),
    ({"legacy_ssh": "private-CANARY"}, {}, "invalid_session"),
])
def test_invalid_session_options_precede_credential_access(fake_ssh, tmp_path, changes, options, code):
    events = fake_ssh(b"FortiGate-60F # ", [])
    credential = key_credential()

    with pytest.raises(session.SessionError) as error:
        session.fortinet_session(_device(**changes), credential, **options)

    assert error.value.code == code
    assert "CANARY" not in str(error.value) and not error.value.final
    assert credential.uses == 0
    assert events() == []
    assert list(tmp_path.glob(f"{ssh.WORKSPACE_PREFIX}*")) == []


def test_nonblocking_setup_failure_closes_terminal_and_workspace(fake_ssh, tmp_path, monkeypatch):
    initial, steps = _fortios_capture("197-35-diag-root")
    fake_ssh(initial, steps)
    terminals = []
    set_blocking = os.set_blocking

    def unavailable(fd, blocking):
        if not blocking and os.isatty(fd):
            terminals.append(fd)
            raise OSError(errno.EIO, "private-CANARY")
        return set_blocking(fd, blocking)

    with monkeypatch.context() as fault:
        fault.setattr(os, "set_blocking", unavailable)
        with pytest.raises(session.SessionError) as error:
            session.fortinet_session(_device(), key_credential())

    assert error.value.code == "terminal"
    assert "CANARY" not in str(error.value) and not error.value.final
    assert len(terminals) == 1
    with pytest.raises(OSError) as closed:
        os.fstat(terminals[0])
    assert closed.value.errno == errno.EBADF
    assert list(tmp_path.glob(f"{ssh.WORKSPACE_PREFIX}*")) == []


def test_consumer_limit_withholds_output_and_closes_session(fake_ssh):
    _, steps = _fortios_capture("197-35-diag-root")
    command, (body, prompt) = steps[2]
    events = fake_ssh(steps[1][1][-1], [(command, [body, prompt])])
    limit = ssh.OutputLimitError()
    limit.args = ("private-CANARY",)
    delivered = []

    def stop(chunk):
        delivered.append(chunk)
        raise limit

    with session.fortinet_session(_device(), key_credential()) as shell:
        with pytest.raises(ssh.OutputLimitError) as error:
            shell.run(command.decode(), stdout_consumer=stop)
        assert error.value is not limit
        assert "CANARY" not in str(error.value)
        assert not error.value.said and not error.value.final
        assert not Path(shell.workspace()).exists()
        with pytest.raises(session.SessionError, match="already closed"):
            shell.run(command.decode())

    assert delivered == body.replace(b"\r\n", b"\n").splitlines(keepends=True)[:1]
    assert events() == ["ssh"]


@pytest.mark.parametrize(("operation", "error_type", "error_code"), [
    ("select", OSError, "terminal"),
    ("write", OSError, "disconnected"),
    ("write", BlockingIOError, None),
    ("read", BlockingIOError, None),
])
def test_terminal_fault_during_captured_command(fake_ssh, monkeypatch, operation, error_type, error_code):
    _, steps = _fortios_capture("197-35-diag-root")
    command, (body, prompt) = steps[2]
    events = fake_ssh(steps[1][1][-1], [(command, [body, prompt])])

    with session.fortinet_session(_device(), key_credential()) as shell:
        workspace = Path(shell.workspace())
        module = select if operation == "select" else os
        original = getattr(module, operation)
        faults = []

        fd = shell._fd

        def failed(target, *args):
            terminal = [fd] in (target, args[0]) if operation == "select" else target == fd
            if terminal and not faults:
                faults.append(operation)
                number = errno.EAGAIN if error_type is BlockingIOError else errno.EIO
                raise error_type(number, "private-CANARY")
            return original(target, *args)

        with monkeypatch.context() as fault:
            fault.setattr(module, operation, failed)
            if error_code is None:
                result = shell.run(command.decode())
                assert result.rc == 0 and result.stdout == body.replace(b"\r\n", b"\n")
                assert workspace.is_dir()
            else:
                with pytest.raises(session.SessionError) as error:
                    shell.run(command.decode())
                assert error.value.code == error_code
                assert "CANARY" not in str(error.value) and not error.value.final
                assert not workspace.exists()

    assert faults == [operation]
    assert not workspace.exists()
    assert events() == ["ssh"]
