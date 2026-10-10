import json
import os
import select
import subprocess
import sys
from pathlib import Path

import netops_auditor

COMPONENT = Path(__file__).resolve().parents[1]
SOURCES = os.pathsep.join(item for item in (
    str(COMPONENT / "src"), os.environ.get("PYTHONPATH", ""), str(COMPONENT.parent / "netops-core" / "src")) if item)
CONFIG = COMPONENT / "tests" / "fixtures" / "fortios_clean.conf"
SERVER_NAME = "NetOps Auditor Read-Only"
SECONDS = 60
INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "identity-probe", "version": "0"},
    },
}
NETWORK_EVENTS = ("socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr", "socket.getnameinfo",
                  "socket.connect", "socket.sendto", "socket.sendmsg")
REFUSE_NETWORK = """
import runpy, sys
def refuse(event, arguments):
    if event in %r:
        sys.stderr.write("refused network access: %%s %%r\\n" %% (event, arguments[:2]))
        sys.stderr.flush()
        raise OSError("network access refused by the test")
sys.addaudithook(refuse)
module = sys.argv[1]
sys.argv = [module]
runpy.run_module(module, run_name="__main__", alter_sys=True)
""" % (NETWORK_EVENTS,)


def _environment(**values):
    environment = {key: value for key, value in os.environ.items() if not key.startswith("NETOPS_AUDITOR_")}
    environment["PYTHONPATH"] = SOURCES
    environment.update(values)
    return environment


def _store(directory):
    store = directory / "store.sqlite"
    done = subprocess.run(
        [sys.executable, "-B", "-m", "netops_auditor", "run", "--platform", "fortios", "--tenant", "t",
         "--device", "d", "--config", str(CONFIG), "--store", str(store)],
        stdin=subprocess.DEVNULL, capture_output=True, timeout=SECONDS, env=_environment(), cwd=str(COMPONENT),
    )
    assert done.returncode == 0, done.stderr.decode("utf-8", "replace")
    return store


def _initialized(environment, *launcher):
    server = subprocess.Popen(
        [sys.executable, "-B", *(launcher or ("-m",)), "netops_auditor.mcp_server"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, cwd=str(COMPONENT),
    )
    try:
        server.stdin.write(json.dumps(INITIALIZE).encode("utf-8") + b"\n")
        server.stdin.flush()
        line = server.stdout.readline() if select.select([server.stdout], [], [], SECONDS)[0] else b""
    finally:
        server.kill()
        _out, log = server.communicate(timeout=SECONDS)
    assert line, "no answer to initialize: %s" % log.decode("utf-8", "replace")[-600:]
    return json.loads(line), log.decode("utf-8", "replace")


def test_initialize_over_stdio_announces_the_auditor_name_and_version(tmp_path):
    environment = _environment(
        NETOPS_AUDITOR_STORE=str(_store(tmp_path)),
        NETOPS_AUDITOR_TENANT="t",
        NETOPS_AUDITOR_CATALOG="fortios",
    )
    answer, _log = _initialized(environment)
    assert answer["id"] == 1
    assert answer["result"]["serverInfo"] == {"name": SERVER_NAME, "version": netops_auditor.__version__}


def test_the_server_starts_without_a_network_lookup_or_connection(tmp_path):
    environment = _environment(
        NETOPS_AUDITOR_STORE=str(_store(tmp_path)),
        NETOPS_AUDITOR_TENANT="t",
        NETOPS_AUDITOR_CATALOG="fortios",
        HOME=str(tmp_path),
        XDG_DATA_HOME=str(tmp_path / "data"),
    )
    for name in [name for name in environment if name.startswith("FASTMCP_")]:
        del environment[name]
    answer, log = _initialized(environment, "-c", REFUSE_NETWORK)
    assert answer["result"]["serverInfo"] == {"name": SERVER_NAME, "version": netops_auditor.__version__}
    assert "refused network access" not in log, log[-2000:]
