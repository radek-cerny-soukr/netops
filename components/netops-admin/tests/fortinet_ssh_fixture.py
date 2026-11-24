"""OpenSSH test client backed by the existing Fortinet device fixtures.

Configuration bodies and simulated writes come from FakeFortiOS and FakeADC
(verification, FortiADC 7.6.7 build0676). PTY framing and failures are derived
test inputs. The client never connects to a socket.
"""
import base64
import json
import os
import pickle
import re
import sys
import tty
from dataclasses import dataclass
from pathlib import Path

from netops_core import fortios, prompt

BLOB = base64.b64encode(b"\0\0\0\x0bssh-ed25519\0\0\0\x20" + bytes(range(32))).decode()
PUBLIC_KEY = "ssh-ed25519 " + BLOB

# The interactive client emits output and then normally waits for more input.
# Use a shorter quiet interval for these Admin tests. The production session
# still reads the terminal and handles prompt probes, pagination, continuations,
# idle timeouts and deadlines. The netops-core Fortinet session tests use their
# own client and retain the production interval.
TEST_QUIET_SECONDS = 0.005


def install_clients(directory, monkeypatch, pycache):
    """Install the fixture clients in directory and set PATH to that directory.

    Use the shorter Fortinet quiet interval and let client subprocesses share
    a bytecode cache under pytest's base temporary directory.
    """
    from netops_core import session

    directory = Path(directory)
    search_path = [str(Path(__file__).parent)] + [p for p in sys.path if p.startswith("/repo/")]
    for client in ("ssh", "ssh-keyscan"):
        path = directory / client
        path.write_text(f"#!{sys.executable}\n"
                        f"import sys\nsys.dont_write_bytecode = False\nsys.pycache_prefix = {str(pycache)!r}\n"
                        f"sys.path[:0] = {search_path!r}\n"
                        f"from fortinet_ssh_fixture import main\nmain({str(directory)!r})\n")
        path.chmod(0o700)
    monkeypatch.setenv("PATH", str(directory))
    monkeypatch.setattr(session, "FORTINET_QUIET_SECONDS", TEST_QUIET_SECONDS)


@dataclass
class Counter:
    value: int

    def __next__(self):
        value = self.value
        self.value += 1
        return value


def main(directory):
    directory = Path(directory)
    events, state = directory / "events", directory / "device"
    args = sys.argv[1:]
    client = Path(sys.argv[0]).name
    if client == "ssh-keyscan":
        with events.open("a") as out:
            out.write(json.dumps([client, args[-1]]) + "\n")
        print(args[-1], PUBLIC_KEY)
        return
    at = args.index("-p")
    login, address = args[at + 2].split("@")
    assert "StrictHostKeyChecking=yes" in args
    hosts = Path(next(arg.split("=", 1)[1] for arg in args if arg.startswith("UserKnownHostsFile=")))
    assert hosts.read_text() == f"{address} {PUBLIC_KEY}\n"
    with events.open("a") as out:
        out.write(json.dumps([client, login, address, str(hosts)]) + "\n")
    platform = (directory / "platform").read_text()
    device = pickle.loads(state.read_bytes())
    check = login == device.check_credential.login
    check_prompt = directory / "check-prompt"
    check_prompt = check_prompt.read_text() if check and check_prompt.exists() else None
    block, frames = [], []
    quotes = (False, False)
    status_reads = 0

    def handle(line):
        nonlocal quotes, status_reads
        if line == "abort" and block:
            # FortiOS: discards the unfinished edit and returns to the top level (measured on the FortiGate-60F)
            block.clear()
            frames.clear()
            return ""
        refused = directory / "refuse-line"
        if block and refused.exists() and refused.read_text() in line:
            return "Command fail. Return code -651\n"
        if block or line.startswith("config "):
            block.append(line)
            if quotes[0]:
                quotes = fortios._quote_state("\n" + line, *quotes)
            elif line.startswith("config "):
                frames.append(line.split()[-1])
            elif line == "end":
                frames.pop()
                if not frames:
                    current = pickle.loads(state.read_bytes())
                    current.apply(block, __import__("netops_admin.execute", fromlist=["_adapter"])
                                  ._adapter(platform).prompt_spec(current.hostname))
                    state.write_bytes(pickle.dumps(current))
                    block.clear()
                    if (directory / "disconnect-after-write").exists():
                        return None
                    refusal = directory / "refuse-after-write"
                    if refusal.exists():
                        refusal.unlink()
                        return "Command fail. Return code -3\n"
            elif line.startswith('set script "'):
                quotes = fortios._quote_state(line)
            return ""
        current = pickle.loads(state.read_bytes())
        if line == "get system console":
            answer = "output : standard\n"
        elif line == 'execute vpn ipsec tunnel down "netops-ipsec" "netops-ipsec" 1':
            capture = Path(__file__).parent / "fixtures/fortios_7_6_8_firewall_cleanup/execute-refused.txt"
            answer = capture.read_text()
        elif line == "show" and platform == "fortios":
            answer = current.snapshot()
        elif line == "get system status" and platform == "fortiadc":
            status_reads += 1
            disconnect = directory / "disconnect-on-second-status"
            if not check and status_reads == 2 and disconnect.exists():
                disconnect.unlink()
                return None
            answer = (current.check_query if check else current.query)(line)
        elif line.startswith("diagnose ") and not check:
            answer = current.diagnose_query(line)
        elif re.match(r'show system (?:accprofile|admin) "', line):
            answer = current.own_query(line, check=check)
        else:
            answer = (current.check_query if check else current.query)(line)
        state.write_bytes(pickle.dumps(current))
        return answer

    def marker():
        if check_prompt is not None:
            return check_prompt
        return device.hostname + (f" ({frames[-1]})" if frames else "") + " # "

    if len(args) > at + 3:
        answer = handle(args[at + 3])
        sys.stdout.write(answer)
        return
    tty.setraw(0)
    sys.stdout.write(marker())
    sys.stdout.flush()
    for raw in sys.stdin.buffer:
        line = raw.decode().rstrip("\n")
        if not line:
            sys.stdout.write("\r\n" + marker())
            sys.stdout.flush()
            continue
        if line == 'execute api-user generate-key "fixture"':
            if (directory / "no-password-prompt").exists():
                sys.stdout.write("\r\nCommand fail. Return code -3\r\n" + marker())
            else:
                sys.stdout.write("\r\nPlease enter current administrator password: ")
                sys.stdout.flush()
                assert sys.stdin.buffer.readline() == b"fixture-password\n"
                sys.stdout.write("\r\nNew API key: fixturetoken\r\n" + marker())
            sys.stdout.flush()
            continue
        if "?" in line:
            assert "\x16?" in line
        sys.stdout.write(line.replace("\x16", "") + "\r\n")
        answer = handle(line.replace("\x16", ""))
        if answer is None:
            return
        answer = prompt.cleaned(answer, platform)
        # FakeADC also models repeated exec prompts and embedded pager erasures.
        pages = answer.replace("FortiADC-KVM # ", "").split("--More-- \r         \r")
        for page in pages[:-1]:
            sys.stdout.write(page.replace("\n", "\r\n") + "--More-- ")
            sys.stdout.flush()
            assert sys.stdin.buffer.read(1) == b" "
            sys.stdout.write("\r         \r")
        sys.stdout.write(pages[-1].replace("\n", "\r\n") + ("> " if quotes[0] else marker()))
        sys.stdout.flush()
