from __future__ import annotations
import ast
import importlib.util
import json
from pathlib import Path
import tomllib
import pytest

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

def test_phase1_surface_ignores_catalog_comments_and_docstrings(tmp_path: Path) -> None:
    gate = _load_release_module("check_public_release")
    source = tmp_path / "src/netops_helper"
    source.mkdir(parents=True)
    (source / "server.py").write_text("", encoding="utf-8")
    (source / "descriptions.py").write_text(
        '\u0022\u0022\u0022show running-config\nshow startup-config\u0022\u0022\u0022\n'
        '# show configuration\n'
        'class Description:\n'
        '    ("show full-configuration" " execute backup")\n'
        '    def describe(self):\n'
        '        """backup configuration"""\n'
        '        return "safe"  # show running-config\n'
        'async def describe_async():\n'
        '    """configuration_backup"""\n',
        encoding="utf-8",
    )
    assert gate._phase1_surface_errors(tmp_path) == []
    (source / "vendor.py").write_text('COMMAND = "show running-config"\n', encoding="utf-8")
    assert gate._phase1_surface_errors(tmp_path) == [
        "phase-1 source contains configuration export pattern: "
        "src/netops_helper/vendor.py: show running-config"
    ]
    # The implementation-pattern check must still include comments.
    (source / "vendor.py").write_text("# config_mode\n", encoding="utf-8")
    assert gate._phase1_surface_errors(tmp_path) == [
        "phase-1 source contains a write implementation: src/netops_helper/vendor.py: config_mode"
    ]


@pytest.mark.parametrize("name, pattern, count", [
    ("config_arista_eos_adapter.py", "show running-config", 1),
    ("config_cisco_nxos_adapter.py", "show running-config", 1),
    ("config_cisco_xe_adapter.py", "show running-config", 1),
    ("config_indented.py", "show running-config", 1),
    ("config_cisco_ios_adapter.py", "show running-config", 1),
    ("config_exos_adapter.py", "show configuration", 1),
    ("config_fortiadc.py", "show full-configuration", 2),
    ("config_fortios.py", "show full-configuration", 1),
])
def test_phase1_config_read_allowances_are_exact(tmp_path: Path, name: str, pattern: str, count: int) -> None:
    gate = _load_release_module("check_public_release")
    source = tmp_path / "src/netops_helper"
    source.mkdir(parents=True)
    (source / "server.py").write_text("", encoding="utf-8")
    allowed = source / name
    original = (ROOT / "src/netops_helper" / name).read_text(encoding="utf-8")
    allowed.write_text(original, encoding="utf-8")
    assert gate._phase1_surface_errors(tmp_path) == []
    message = "phase-1 source contains configuration export pattern: "
    allowed.write_text(original + f'\nEXTRA = "{pattern}"\n', encoding="utf-8")
    assert gate._phase1_surface_errors(tmp_path) == [f"{message}src/netops_helper/{name}: {pattern}"]
    # A renamed copy receives no allowance; FortiADC also requires both occurrences.
    allowed.unlink()
    (source / "other.py").write_text(original, encoding="utf-8")
    renamed = [f"{message}src/netops_helper/other.py: {pattern}"]
    if name in {"config_arista_eos_adapter.py", "config_cisco_nxos_adapter.py",
                "config_cisco_ios_adapter.py", "config_cisco_xe_adapter.py"}:
        renamed.append(f"{message}src/netops_helper/other.py: show startup-config")
    if name in {"config_cisco_ios_adapter.py", "config_cisco_xe_adapter.py"}:
        renamed.append(f"{message}src/netops_helper/other.py: show archive config differences")
    assert gate._phase1_surface_errors(tmp_path) == renamed
    (source / "other.py").unlink()
    if count > 1:
        before, _, after = original.rpartition(pattern)
        allowed.write_text(before + "show" + after, encoding="utf-8")
        assert gate._phase1_surface_errors(tmp_path) == [f"{message}src/netops_helper/{name}: {pattern}"]


def test_nxos_startup_diff_allowance_requires_exact_commands(tmp_path: Path) -> None:
    gate = _load_release_module("check_public_release")
    source = tmp_path / "src/netops_helper"
    source.mkdir(parents=True)
    (source / "server.py").write_text("", encoding="utf-8")
    name = "config_cisco_nxos_adapter.py"
    original = (ROOT / "src/netops_helper" / name).read_text(encoding="utf-8")
    adapter = source / name
    mutations = (
        original.replace("show running-config diff'", "show running-config diff extra'"),
        original + '\nEXTRA = "show startup-config"\n',
        original + '\nDIFF_COMMAND = "show running-config diff"\n',
    )
    for mutated in mutations:
        assert mutated != original
        adapter.write_text(mutated, encoding="utf-8")
        assert any("configuration export pattern" in error for error in gate._phase1_surface_errors(tmp_path))


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
        original.replace("report=reader.snapshot(library,raw,path,view,vdom,keys,auth.redaction_secrets,current_vdom=current_vdom)","report=raw",1),
        original.replace('library=reader.binding(auth)','library=None',1),
        original.replace("current_vdom=current_vdom",'current_vdom="root"',1),
        original.replace("current_vdom=reader.verify_status(library,status)",'current_vdom=reader.verify_status(library,status)\n        current_vdom="root"',1),
        original.replace(",current_vdom=current_vdom","",1),
        original.replace('    page=_schema_page(cleaned,offset,max_bytes,auth)','    return raw\n    page=_schema_page(cleaned,offset,max_bytes,auth)',1),
        original+'\nEXPORTED_COMMAND="show full-configuration"\n',
    ]
    for mutant in mutations:
        assert mutant!=original
        engine.write_text(mutant)
        errors=gate._phase1_surface_errors(root)
        assert any("configuration export pattern" in error for error in errors)
    engine.write_text(original)

def test_required_regression_files_exist() -> None:
    required = (
        'tests/_sandbox_guard.py',
        'tests/_test_guard.py',
        'tests/conftest.py',
        'tests/test_apply_egress_rules.py',
        'tests/test_audit_rotation.py',
        'tests/test_check_operator_config.py',
        'tests/test_cli_closed_output.py',
        'tests/test_cli_errors.py',
        'tests/test_connection_pacing.py',
        'tests/test_egress_scripts.py',
        'tests/test_engine_contracts.py',
        'tests/test_engine_safety.py',
        'tests/test_error_branches_helper_engine.py',
        'tests/test_error_branches_helper_proxy.py',
        'tests/test_fortios_diagnostics.py',
        'tests/test_ftp_wire_safety.py',
        'tests/test_malformed_inputs.py',
        'tests/test_mutation_helper_engine.py',
        'tests/test_mutation_helper_proxy_arguments.py',
        'tests/test_mutation_helper_proxy_messages.py',
        'tests/test_mutation_helper_proxy_sanitize.py',
        'tests/test_phase1_surface.py',
        'tests/test_plain_ftp_acknowledgement.py',
        'tests/test_policy_parity.py',
        'tests/test_proxy.py',
        'tests/test_proxy_contracts.py',
        'tests/test_proxy_vault_size.py',
        'tests/test_query_catalog_arista.py',
        'tests/test_query_catalog_cisco.py',
        'tests/test_query_catalog_docs.py',
        'tests/test_query_catalog_extreme.py',
        'tests/test_query_catalog_fortinet.py',
        'tests/test_query_catalog_junos.py',
        'tests/test_query_catalog_ruckus.py',
        'tests/test_redaction_and_marking_contracts.py',
        'tests/test_resource_limits.py',
        'tests/test_runtime_tar_safety.py',
        'tests/test_sandbox_guard.py',
        'tests/test_sanitize.py',
        'tests/test_schema_read.py',
        'tests/test_secret_canaries.py',
        'tests/test_security.py',
        'tests/test_sftp_safety.py',
        'tests/test_ssh_wire_safety.py',
        'tests/test_triage_slb.py',
        'tests/test_vendor_references.py',
    )
    assert [path for path in required if not (ROOT / path).is_file()] == []


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
