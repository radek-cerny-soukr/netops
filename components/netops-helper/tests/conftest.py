import json
import os
from pathlib import Path
import stat
import sys

import pytest

COMPONENT = Path(__file__).resolve().parents[1]

for source in (COMPONENT / "src", COMPONENT.parent / "netops-core" / "src"):
    sys.path.insert(0, str(source))

from netops_core.hostkey import fingerprint_of  # noqa: E402
from netops_helper.auth import EgressPolicy, TargetAuth  # noqa: E402
from netops_helper.query_catalog import READ_QUERIES  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_connection_pacing(monkeypatch):
    """Isolate each test's SSH connection lanes and host-key cache.

    `engine._CONNECTION_LANES` and `engine._HOST_KEY_LINE_CACHE` are module-level
    state shared by every call in the process; most tests reuse the same test
    address, port and host key pin, so leftover lane timing or a cached host
    key line from an earlier test would change what the next test observes.
    `_sleep` is also replaced with a no-op by default, so a platform's
    connection spacing never costs real wall-clock time in a test that is not
    specifically exercising it. tests/test_connection_pacing.py overrides
    `_now`/`_sleep` with its own fake clock to observe the pacing itself.
    """
    import netops_helper.engine as engine

    engine._CONNECTION_LANES.clear()
    engine._HOST_KEY_LINE_CACHE.clear()
    monkeypatch.setattr(engine, "_sleep", lambda seconds: None)
    yield
    engine._CONNECTION_LANES.clear()
    engine._HOST_KEY_LINE_CACHE.clear()


LOOPBACK = "127.0.0.1"
PORT = 2222
LOGIN = "reader"
PASSWORD = "wire-test-password"
HOST_KEY_BLOB = "cmVwbGFjZS1tZS1ob3N0LWtleS1tYXRlcmlhbC1B"
HOST_KEY_PIN = fingerprint_of(HOST_KEY_BLOB)
KNOWN_HOSTS_LINE = f"[{LOOPBACK}]:{PORT} ssh-ed25519 {HOST_KEY_BLOB}"
EXEC_OUTPUT = "wire-test output marker"
RUCKUS_BANNER = "Welcome to the Ruckus Unleashed Network Command Line Interface"
RUCKUS_OUTPUT = "Ruckus wire-test sysinfo marker"

EXEC_CLIENT = '''#!/usr/bin/env python3
import json, os, sys

record = {{
    "argv": sys.argv[1:],
    "env": dict(os.environ),
    "stdin_isatty": sys.stdin.isatty(),
}}
askpass = os.environ.get("SSH_ASKPASS")
if askpass:
    import hashlib, subprocess
    answer = subprocess.run([askpass], capture_output=True, env=dict(os.environ)).stdout
    record["askpass_sha256"] = hashlib.sha256(answer.strip()).hexdigest()
    record["askpass_mode"] = oct(os.stat(os.environ["NETOPS_ASKPASS_FILE"]).st_mode & 0o777)
identity = None
if "-i" in sys.argv:
    identity = sys.argv[sys.argv.index("-i") + 1]
    import hashlib
    record["identity_sha256"] = hashlib.sha256(open(identity, "rb").read()).hexdigest()
    record["identity_mode"] = oct(os.stat(identity).st_mode & 0o777)
for item in sys.argv:
    if item.startswith("UserKnownHostsFile="):
        record["known_hosts"] = open(item.split("=", 1)[1]).read()
with open({log!r}, "a") as handle:
    handle.write(json.dumps(record) + "\\n")
sys.stdout.write({output!r})
sys.exit({code})
'''

KEYSCAN_CLIENT = '''#!/usr/bin/env python3
import json, os, sys

with open({log!r}, "a") as handle:
    handle.write(json.dumps({{"argv": sys.argv[1:], "env": dict(os.environ)}}) + "\\n")
name = sys.argv[-1]
port = sys.argv[sys.argv.index("-p") + 1] if "-p" in sys.argv else "22"
label = name if port == "22" else "[%s]:%s" % (name, port)
sys.stdout.write("%s ssh-ed25519 %s\\n" % (label, {blob!r}))
sys.exit(0)
'''

PTY_CLIENT = '''#!/usr/bin/env python3
import json, os, sys

record = {{"argv": sys.argv[1:], "env": dict(os.environ), "stdin_isatty": sys.stdin.isatty()}}
for item in sys.argv:
    if item.startswith("UserKnownHostsFile="):
        record["known_hosts"] = open(item.split("=", 1)[1]).read()
with open({log!r}, "a") as handle:
    handle.write(json.dumps(record) + "\\n")

transcript = open({transcript!r}, "a")


def read_line():
    line = sys.stdin.readline()
    transcript.write(line)
    transcript.flush()
    return line.rstrip("\\n")


sys.stdout.write("Please login: ")
sys.stdout.flush()
read_line()
sys.stdout.write("\\r\\nPassword: ")
sys.stdout.flush()
read_line()
sys.stdout.write("\\r\\n{banner}\\r\\nruckus> ")
sys.stdout.flush()
while True:
    command = read_line()
    if command == "enable":
        sys.stdout.write("\\r\\nruckus# ")
    else:
        sys.stdout.write("\\r\\n{output}\\r\\nruckus# ")
    sys.stdout.flush()
'''


def _write_client(directory: Path, name: str, body: str) -> None:
    path = directory / name
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


@pytest.fixture()
def wire(tmp_path, monkeypatch):
    import netops_helper.engine as engine

    binaries = tmp_path / "bin"
    binaries.mkdir()
    log = tmp_path / "calls.jsonl"
    transcript = tmp_path / "transcript.txt"
    _write_client(
        binaries, "ssh",
        EXEC_CLIENT.format(log=str(log), output=EXEC_OUTPUT + "\n", code=0),
    )
    _write_client(
        binaries, "ssh-keyscan",
        KEYSCAN_CLIENT.format(log=str(log), blob=HOST_KEY_BLOB),
    )
    monkeypatch.setenv("PATH", f"{binaries}:{os.environ['PATH']}")
    monkeypatch.setattr(engine, "record", lambda *args, **kwargs: None)
    engine._SSH_PAGE_CACHE.clear()
    yield {
        "binaries": binaries, "log": log, "transcript": transcript,
        "python": sys.executable,
    }
    engine._SSH_PAGE_CACHE.clear()


def _calls(wire) -> list[dict]:
    if not wire["log"].exists():
        return []
    return [
        json.loads(line)
        for line in wire["log"].read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _target(
    platform: str,
    query_name: str,
    *,
    legacy_ssh: str | None = None,
    credential_kind: str = "password",
    secret: str = PASSWORD,
    host: str = LOOPBACK,
    sftp_roots: tuple[str, ...] = (),
) -> TargetAuth:
    return TargetAuth(
        alias="wire-test",
        host=host,
        port=PORT,
        login=LOGIN,
        secret=secret,
        host_key_fingerprint=HOST_KEY_PIN,
        credential_kind=credential_kind,
        sftp_roots=sftp_roots,
        read_inventory={},
        account_role="read-only",
        fortios_output_standard_verified=True,
        ssh_platform=platform,
        enabled_queries=(query_name,),
        egress=EgressPolicy(addresses=(host,)),
        legacy_ssh=legacy_ssh,
    )


def _plain_query(platform: str) -> tuple[str, str]:
    for name, query in sorted(READ_QUERIES[platform].items()):
        if not query.slots:
            return name, query.command
    raise AssertionError(f"no slot-free query for {platform}")


def _ruckus_wire(wire) -> None:
    _write_client(
        wire["binaries"], "ssh",
        PTY_CLIENT.format(
            log=str(wire["log"]),
            transcript=str(wire["transcript"]),
            banner=RUCKUS_BANNER,
            output=RUCKUS_OUTPUT,
        ),
    )
