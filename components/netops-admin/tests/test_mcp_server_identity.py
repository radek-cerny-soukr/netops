from __future__ import annotations

import ast
import importlib.util
import json
import os
import select
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

import netops_admin

ROOT = Path(__file__).resolve().parents[1]
SOURCES = os.pathsep.join(item for item in (
    str(ROOT / "src"), os.environ.get("PYTHONPATH", ""),
    str(ROOT.parent / "netops-auditor" / "src"), str(ROOT.parent / "netops-core" / "src")) if item)
SECONDS = 60
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


def test_the_mcp_server_announces_the_package_name_and_version():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    tree = ast.parse((ROOT / "src" / "netops_admin" / "mcp_server.py").read_text(encoding="utf-8"))
    servers = [node.value for node in tree.body if isinstance(node, ast.Assign)
               and [target.id for target in node.targets if isinstance(target, ast.Name)] == ["mcp"]]
    assert len(servers) == 1
    call = servers[0]
    assert isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == "FastMCP"
    keywords = {keyword.arg: keyword.value for keyword in call.keywords}
    name = call.args[0] if call.args else keywords.get("name")
    assert isinstance(name, ast.Constant) and name.value == project["name"]
    version = keywords.get("version")
    assert isinstance(version, ast.Name) and version.id == "__version__"
    imported = {(node.module, alias.name, alias.asname) for node in tree.body
                if isinstance(node, ast.ImportFrom) for alias in node.names}
    assert ("netops_admin", "__version__", None) in imported
    rebound = [node for node in ast.walk(tree) if isinstance(node, ast.Name) and node.id == "__version__"
               and isinstance(node.ctx, ast.Store)]
    assert rebound == []
    assert netops_admin.__version__ == project["version"]


def test_the_server_starts_without_a_network_lookup_or_connection(tmp_path):
    if importlib.util.find_spec("fastmcp") is None:
        pytest.skip("fastmcp is not installed")
    config = tmp_path / "admin.json"
    config.write_text(json.dumps({
        "version": 1, "state_dir": str(tmp_path / "state"), "audit_file": str(tmp_path / "state" / "audit.jsonl"),
        "devices": {"fw-lab": {"platform": "fortios", "address": "192.0.2.1", "host_key_fingerprint": "SHA256:" + "A" * 43,
                               "vault": str(tmp_path / "vault.json"), "credential": "rw", "check_credential": "ro"}},
    }), encoding="utf-8")
    environment = {key: value for key, value in os.environ.items() if not key.startswith(("FASTMCP_", "NETOPS_ADMIN_"))}
    environment.update(PYTHONPATH=SOURCES, NETOPS_ADMIN_CONFIG=str(config), HOME=str(tmp_path),
                       XDG_DATA_HOME=str(tmp_path / "data"))
    request = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
               "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                          "clientInfo": {"name": "start-probe", "version": "0"}}}
    server = subprocess.Popen(
        [sys.executable, "-B", "-c", REFUSE_NETWORK, "netops_admin.mcp_server"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, cwd=str(ROOT),
    )
    try:
        server.stdin.write(json.dumps(request).encode("utf-8") + b"\n")
        server.stdin.flush()
        line = server.stdout.readline() if select.select([server.stdout], [], [], SECONDS)[0] else b""
    finally:
        server.kill()
        _out, log = server.communicate(timeout=SECONDS)
    log = log.decode("utf-8", "replace")
    assert line, "no answer to initialize: %s" % log[-600:]
    assert json.loads(line)["result"]["serverInfo"] == {"name": "netops-admin", "version": netops_admin.__version__}
    assert "refused network access" not in log, log[-2000:]
