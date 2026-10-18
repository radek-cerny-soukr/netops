from __future__ import annotations
import ast
import importlib.util
import json
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[1]
PRODUCT = ROOT.parents[1]

def _load_release_module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tests" / "support" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_proxy_transport_guard_is_not_an_optimized_assert() -> None:
    source = (ROOT / "src/netops_helper/proxy.py").read_text(encoding="utf-8")
    assert not any(isinstance(node, ast.Assert) for node in ast.walk(ast.parse(source)))
    assert "The local SSH process pipes are unavailable." in source

def test_phase1_surface_rejects_forbidden_command_in_added_module(
    tmp_path: Path,
) -> None:
    gate = _load_release_module("check_public_release")
    root = tmp_path / "phase1-tree"
    source_root = root / "src/netops_helper"
    platform_root = source_root / "platforms"
    platform_root.mkdir(parents=True)
    (source_root / "server.py").write_text(
        "class Mcp:\n"
        "    def tool(self):\n"
        "        return lambda function: function\n"
        "mcp = Mcp()\n"
        "@mcp.tool()\n"
        "def helper_status():\n"
        "    return None\n",
        encoding="utf-8",
    )
    policy_path = source_root / "read_policy.py"
    policy_path.write_text(
        "SAFE_QUERY = \"show version\"\n",
        encoding="utf-8",
    )
    assert gate._phase1_surface_errors(root) == []

    added_module = platform_root / "vendor.py"
    added_module.write_text(
        "FORBIDDEN_QUERY = \"show full-configuration\"\n"
        "def config_mode():\n"
        "    return None\n",
        encoding="utf-8",
    )
    errors = gate._phase1_surface_errors(root)
    assert errors == [
        "phase-1 source contains configuration export pattern: "
        "src/netops_helper/platforms/vendor.py: show full-configuration",
        "phase-1 source contains a write implementation: "
        "src/netops_helper/platforms/vendor.py: config_mode",
    ]
    assert "show full-configuration" not in policy_path.read_text(
        encoding="utf-8"
    ).lower()

def test_phase1_surface_rejects_removed_body_read_symbols_and_policy(
    tmp_path: Path,
) -> None:
    gate = _load_release_module("check_public_release")
    root = tmp_path / "removed-body-read"
    source_root = root / "src/netops_helper"
    source_root.mkdir(parents=True)
    (source_root / "server.py").write_text(
        "class Mcp:\n"
        "    def tool(self):\n"
        "        return lambda function: function\n"
        "mcp = Mcp()\n"
        "@mcp.tool()\n"
        "def helper_status():\n"
        "    return None\n",
        encoding="utf-8",
    )
    assert gate._phase1_surface_errors(root) == []

    (source_root / "legacy.py").write_text(
        "from somewhere import https_get as engine_https_get\n"
        "https_endpoints = []\n"
        "def sftp_read_text():\n"
        "    return None\n",
        encoding="utf-8",
    )
    errors = gate._phase1_surface_errors(root)
    assert any(
        "removed body-read surface remains" in error
        and "https_get" in error
        and "engine_https_get" in error
        and "https_endpoints" in error
        and "sftp_read_text" in error
        for error in errors
    )

    (source_root / "legacy.py").unlink()
    config = root / "config"
    config.mkdir()
    (config / "inventory.example.json").write_text(
        json.dumps({
            "version": 2,
            "devices": [{
                "name": "device",
                "helper": {
                    "https_endpoints": [{
                        "path": "/export.conf",
                        "port": 443,
                        "use_basic_auth": False,
                    }],
                },
            }],
        }),
        encoding="utf-8",
    )
    assert "phase-1 example policy contains removed https_endpoints" in (
        gate._phase1_surface_errors(root)
    )

def test_schema_snapshot_gate_is_narrow_and_rejects_missing_controls(tmp_path: Path) -> None:
    gate=_load_release_module("check_public_release")
    root=tmp_path/"schema-snapshot-boundary"
    directory=root/"src/netops_helper";directory.mkdir(parents=True)
    for name in ["server.py","schema_read.py","engine.py","fortios_diagnostics.py"]:
        (directory/name).write_text((ROOT/"src/netops_helper"/name).read_text())
    assert gate._phase1_surface_errors(root)==[]
    engine=directory/"engine.py";original=engine.read_text()
    mutations=[
        original.replace("reader.selectors(auth,library,path,view,vdom,keys)","pass",1),
        original.replace("current_vdom=reader.verify_status(library,status)",'current_vdom="root"',1),
        original.replace("report=reader.snapshot(library,raw,path,view,vdom,keys,auth.secrets,current_vdom=current_vdom)","report=raw",1),
        original.replace('library=reader.binding(auth)','library=None',1),
        original.replace("current_vdom=current_vdom",'current_vdom="root"',1),
        original.replace("current_vdom=reader.verify_status(library,status)",'current_vdom=reader.verify_status(library,status)\n        current_vdom="root"',1),
        original.replace(",current_vdom=current_vdom","",1),
        original.replace('    page=_page_text(cleaned,offset,max_bytes)','    return raw\n    page=_page_text(cleaned,offset,max_bytes)',1),
        original+'\nEXPORTED_COMMAND="show full-configuration"\n',
    ]
    for mutant in mutations:
        assert mutant!=original
        engine.write_text(mutant)
        errors=gate._phase1_surface_errors(root)
        assert any("configuration export pattern" in error for error in errors)
    engine.write_text(original)

def test_release_license_is_mit() -> None:
    assert (PRODUCT / "LICENSE").read_text().startswith("MIT License\n")
    project = (PRODUCT / "pyproject.toml").read_text()
    assert 'license = "MIT"' in project
    assert 'license-files = ["LICENSE"]' in project

def test_runtime_inputs_and_install_metadata_agree() -> None:
    import tomllib
    dependencies = tomllib.loads((PRODUCT / "pyproject.toml").read_text())["project"]["dependencies"]
    runtime = [line.strip() for line in (PRODUCT / "requirements.in").read_text().splitlines() if line.strip() and not line.startswith("#")]
    assert sorted(x for x in dependencies if not x.startswith("netops-core==")) == sorted(runtime)
