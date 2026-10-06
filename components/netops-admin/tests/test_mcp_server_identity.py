from __future__ import annotations

import ast
import tomllib
from pathlib import Path

import netops_admin

ROOT = Path(__file__).resolve().parents[1]


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
