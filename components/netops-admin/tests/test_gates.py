from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("admin_check_gates", ROOT / "tests" / "support" / "check_gates.py")
gates = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gates)

@pytest.fixture
def tree(tmp_path) -> Path:
    copy = tmp_path / "netops-admin"
    shutil.copytree(ROOT / "src", copy / "src")
    shutil.copy2(ROOT / "pyproject.toml", copy / "pyproject.toml")
    return copy

@pytest.mark.parametrize(("line", "fragment"), [
    ("import socket\n", "imports socket"),
    ("import subprocess\n", "imports subprocess"),
    ("import importlib\n", "imports importlib"),
    ("from netops_core import transport\n", "imports transport from netops_core"),
    ("from netops import gateway\n", "imports gateway from netops"),
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

def _new_import_errors(tree, name, line):
    module = tree / "src" / "netops_admin" / name
    before = set(gates.import_errors(tree))
    text = module.read_text(encoding="utf-8") if module.exists() else ""
    module.write_text(text + "\n" + line, encoding="utf-8")
    return sorted(set(gates.import_errors(tree)) - before)

def test_access_may_import_the_core_platforms_module(tree):
    assert _new_import_errors(tree, "access.py", "from netops_core import platforms\n") == []

OTHER_ADMIN_MODULES = sorted(
    ({path.name for path in (ROOT / "src" / "netops_admin").rglob("*.py")} | set(gates.FILE_RULES) | {"unlisted_module.py"})
    - {"access.py"}
)

def test_the_platforms_admission_check_covers_existing_listed_and_unlisted_modules():
    assert {"cli.py", "engine.py", "execute.py", "schema_runtime.py", "unlisted_module.py"} <= set(OTHER_ADMIN_MODULES)
    assert set(gates.FILE_RULES) - {"access.py"} <= set(OTHER_ADMIN_MODULES)
    assert "access.py" not in OTHER_ADMIN_MODULES

@pytest.mark.parametrize("name", OTHER_ADMIN_MODULES)
def test_the_core_platforms_module_is_admitted_only_for_access(tree, name):
    errors = _new_import_errors(tree, name, "from netops_core import platforms\n")
    assert any("imports platforms from netops_core" in error for error in errors), errors

@pytest.mark.parametrize(("line", "fragment"), [
    ("from netops_core import transport\n", "imports transport from netops_core"),
    ("from netops_core import inputs\n", "imports inputs from netops_core"),
    ("import netops_core\n", "imports netops_core"),
    ("import netops_core.platforms\n", "imports netops_core.platforms"),
    ("from netops_core.platforms import version_record\n", "imports version_record from netops_core.platforms"),
])
def test_access_stays_closed_to_the_rest_of_netops_core(tree, line, fragment):
    errors = _new_import_errors(tree, "access.py", line)
    assert any(fragment in error for error in errors), errors

@pytest.fixture
def component(tmp_path) -> Path:
    copy = tmp_path / "netops-admin"
    shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    return copy

def test_private_material_in_a_released_file_is_reported(component):
    address = ".".join(("10", "1", "2", "3"))
    document = component / "README.md"
    document.write_text(document.read_text(encoding="utf-8") + "\nRun it on host %s as mail.example-corp.cz.\n" % address,
                        encoding="utf-8")
    errors = gates._release_text_errors("README.md", document.read_text(encoding="utf-8"), True)
    assert any(address in error for error in errors)
    assert any("example-corp.cz" in error for error in errors)

def test_current_engine_import_and_profile_boundaries():
    assert gates.import_errors(ROOT) == []
    assert gates.profile_errors(ROOT) == []
