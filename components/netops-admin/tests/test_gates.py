from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("admin_check_gates", ROOT / "scripts" / "check_gates.py")
gates = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gates)


@pytest.fixture
def tree(tmp_path) -> Path:
    copy = tmp_path / "netops-admin"
    shutil.copytree(ROOT / "src", copy / "src")
    shutil.copy2(ROOT / "pyproject.toml", copy / "pyproject.toml")
    return copy


def test_shipped_tree_passes():
    assert gates.import_errors() == []
    assert gates.metadata_errors() == []
    assert gates.profile_errors() == []


@pytest.mark.parametrize(("line", "fragment"), [
    ("import socket\n", "imports socket"),
    ("import subprocess\n", "imports subprocess"),
    ("import importlib\n", "imports importlib"),
    ("from netops_core import transport\n", "imports transport from netops_core"),
    ("from netops_auditor import collect\n", "imports collect from netops_auditor"),
    ("from importlib import import_module\n", "imports import_module from importlib"),
    ("value = eval('1')\n", "uses eval"),
    ("value = __import__('os')\n", "uses __import__"),
    ("import re\nre.system = None\n", "calls system"),
])
def test_forbidden_capability_is_reported(tree, line, fragment):
    module = tree / "src" / "netops_admin" / "cli.py"
    module.write_text(module.read_text(encoding="utf-8") + line, encoding="utf-8")
    assert any(fragment in error for error in gates.import_errors(tree)), gates.import_errors(tree)


def test_version_drift_is_reported(tree):
    init = tree / "src" / "netops_admin" / "__init__.py"
    init.write_text('__version__ = "9.9.9"\n', encoding="utf-8")
    assert gates.metadata_errors(tree) == ["package __version__ differs from pyproject version"]


def test_dependency_drift_is_reported(tree):
    pyproject = tree / "pyproject.toml"
    pyproject.write_text(pyproject.read_text(encoding="utf-8").replace("netops-auditor==0.2.8", "netops-auditor"),
                         encoding="utf-8")
    assert gates.metadata_errors(tree) == ["dependencies must be exactly %r" % gates.DEPENDENCIES]


def test_every_gate_passes_on_the_shipped_component():
    assert gates.check(ROOT) == {name: [] for name in gates.GATE_ORDER}


@pytest.fixture
def component(tmp_path) -> Path:
    copy = tmp_path / "netops-admin"
    shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    return copy


def test_private_material_in_a_released_file_is_reported(component):
    address = ".".join(("10", "1", "2", "3"))
    document = component / "docs" / "execution.md"
    document.write_text(document.read_text(encoding="utf-8") + "\nRun it on host %s as mail.example-corp.cz.\n" % address,
                        encoding="utf-8")
    errors = gates.gate_release_content(component)
    assert any(address in error for error in errors)
    assert any("example-corp.cz" in error for error in errors)


def test_sbom_version_drift_is_reported(component):
    sbom = component / "sbom.cdx.json"
    sbom.write_text(sbom.read_text(encoding="utf-8").replace('"version": "0.2.3"', '"version": "0.0.9"', 1),
                    encoding="utf-8")
    assert any("sbom.cdx.json" in error for error in gates.gate_version_metadata(component))


def test_unpinned_mcp_requirement_is_reported(component):
    (component / "requirements-mcp.txt").write_text("fastmcp>=4\n", encoding="utf-8")
    assert any("does not pin" in error for error in gates.gate_version_metadata(component))
